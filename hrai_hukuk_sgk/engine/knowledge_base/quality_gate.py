"""Dual-gate Knowledge Base quality & unverified-source quarantine guards (WP-4.2).

Prevents PENDING_REVIEW, UNVERIFIED, REJECTED_CONTENT_MISMATCH, TRANSPORT_ONLY_UNVERIFIED_CONTENT,
UNREACHABLE_NOT_VERIFIED, and tampered records from EVER entering active RAG answers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import (
    CHUNK_KIND_PRECEDENT_UNIT,
    DOC_KIND_AUTONOMOUS_NORM,
    DOC_KIND_JUDICIAL_PRECEDENT,
    VERIFICATION_QUARANTINED_TAMPER,
    VERIFICATION_SUPERSEDED,
    VERIFICATION_VERIFIED,
    LegalSearchChunk,
    canonical_kb_sha256,
    is_valid_kb_sha256,
)

POOL_VERIFIED_ACTIVE = "VERIFIED_ACTIVE_POOL"
POOL_PENDING_ISOLATED = "PENDING_OR_METADATA_ISOLATED_POOL"
POOL_FAILED_QUARANTINED = "FAILED_OR_REJECTED_ISOLATED_POOL"

TRUST_CHAIN_REJECTED_STATUSES: frozenset[str] = frozenset(
    {
        "REJECTED_CONTENT_MISMATCH",
        "REJECTED_INVALID_SOURCE",
        "TRANSPORT_ONLY_UNVERIFIED_CONTENT",
        "UNREACHABLE_NOT_VERIFIED",
        "FAILED",
        "KB_CHUNK_TAMPER_QUARANTINED",
    }
)


@dataclass(frozen=True)
class IngestGateDecision:
    accepted_active: bool
    pool: str
    error_codes: tuple[str, ...]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted_active": self.accepted_active,
            "pool": self.pool,
            "error_codes": list(self.error_codes),
            "reason": self.reason,
        }


def compute_chunk_integrity_sha256(chunk: LegalSearchChunk) -> str:
    """Recompute sealed integrity digest of `chunk` to detect post-ingestion tampering."""
    return canonical_kb_sha256(
        {
            "provision_id": chunk.provision_id,
            "document_version_id": chunk.document_version_id,
            "chunk_kind": chunk.chunk_kind,
            "context_header": chunk.context_header,
            "raw_text": chunk.raw_text,
            "effective_from": chunk.effective_from,
            "effective_to": chunk.effective_to,
            "content_sha256": chunk.content_sha256,
        }
    )


def _is_temporally_valid_status(status: str, chunk: LegalSearchChunk) -> bool:
    if status == VERIFICATION_VERIFIED:
        return True
    # Content-verified SUPERSEDED records MUST declare an explicit end date so temporal gating isolates them cleanly.
    if status == VERIFICATION_SUPERSEDED and chunk.effective_to is not None:
        return True
    return False


def evaluate_chunk_ingest_gate(chunk: LegalSearchChunk) -> IngestGateDecision:
    """Route every candidate chunk deterministically into active, pending-isolated, or failed-quarantined pools."""
    errors: list[str] = []

    if not is_valid_kb_sha256(chunk.content_sha256):
        errors.append("INVALID_CONTENT_SHA256")
    elif compute_chunk_integrity_sha256(chunk) != chunk.chunk_sha256:
        return IngestGateDecision(
            accepted_active=False,
            pool=POOL_FAILED_QUARANTINED,
            error_codes=(VERIFICATION_QUARANTINED_TAMPER,),
            reason=f"Chunk ({chunk.chunk_id}) bütünlük mührü uyuşmuyor; aktif havuza alınamaz.",
        )

    status = str(chunk.verification_status or "").strip().upper()
    if status in TRUST_CHAIN_REJECTED_STATUSES:
        return IngestGateDecision(
            accepted_active=False,
            pool=POOL_FAILED_QUARANTINED,
            error_codes=(status,),
            reason=f"Güven zinciri / doğrulama reddi ({status}) nedeniyle aktif havuz dışında karantinaya alındı.",
        )

    if chunk.document_kind == DOC_KIND_AUTONOMOUS_NORM:
        if chunk.adoption_status != "COMPANY_ADOPTED_COUNSEL_VERIFIED":
            return IngestGateDecision(
                accepted_active=False,
                pool=POOL_PENDING_ISOLATED,
                error_codes=("L5_L6_TEMPLATE_PENDING_COMPANY_ADOPTION",),
                reason=(
                    f"L5/L6 özerk norm ({chunk.provision_id}) kurum kabulü "
                    f"({chunk.adoption_status}) beklemede; bağlayıcı politika havuzuna alınamaz."
                ),
            )

    if not chunk.content_verified:
        errors.append("CONTENT_NOT_VERIFIED")
    if not _is_temporally_valid_status(status, chunk):
        errors.append(f"UNVERIFIED_STATUS_{status or 'EMPTY'}")

    if chunk.document_kind == DOC_KIND_JUDICIAL_PRECEDENT and chunk.chunk_kind != CHUNK_KIND_PRECEDENT_UNIT:
        errors.append("PRECEDENT_CHUNK_KIND_MISMATCH")

    if errors:
        is_failed = any(c.startswith("INVALID_") or c == VERIFICATION_QUARANTINED_TAMPER for c in errors)
        return IngestGateDecision(
            accepted_active=False,
            pool=POOL_FAILED_QUARANTINED if is_failed else POOL_PENDING_ISOLATED,
            error_codes=tuple(errors),
            reason=f"Kayıt ({chunk.chunk_id}) doğrulanmış aktif havuz şartlarını sağlamıyor: {errors}",
        )

    return IngestGateDecision(
        accepted_active=True,
        pool=POOL_VERIFIED_ACTIVE,
        error_codes=(),
        reason="Aktif VERIFIED/SUPERSEDED-bounded hukuki bilgi havuzu kapısından geçti.",
    )


def verify_chunk_runtime_integrity(chunk: LegalSearchChunk) -> tuple[bool, str | None]:
    """Fail-closed query-time verification that chunk payload and seal remain untampered."""
    if compute_chunk_integrity_sha256(chunk) != chunk.chunk_sha256:
        return False, VERIFICATION_QUARANTINED_TAMPER
    if not _is_temporally_valid_status(chunk.verification_status, chunk) or not chunk.content_verified:
        return False, f"NON_VERIFIED_CHUNK_LEAK:{chunk.verification_status}"
    return True, None
