"""Stage 5 EvidenceLinker connecting retrieved chunks to TrustChainEvidenceAdapterProtocol or Audit Logs."""

from __future__ import annotations

import hashlib
from typing import Any

from ..knowledge_base.models import (
    DOC_KIND_JUDICIAL_PRECEDENT,
    TrustChainEvidenceAdapterProtocol,
    canonical_kb_sha256,
)
from ..knowledge_base.quality_gate import verify_chunk_runtime_integrity
from .models import (
    BINDING_REGISTRY_AUDIT_BACKED_NO_TRUST_CHAIN,
    BINDING_TRUST_CHAIN_EVIDENCE_BOUND,
    BINDING_TRUST_CHAIN_INTEGRITY_MISMATCH,
    EvidenceBindingRecord,
    RankedEvidenceItem,
)


class EvidenceLinker:
    """Cryptographic Trust Chain verifier & central audit log linker (fail-closed on integrity mismatches)."""

    def __init__(self, *, trust_chain_adapter: TrustChainEvidenceAdapterProtocol | None = None) -> None:
        self._adapter = trust_chain_adapter

    def link_all_buckets(
        self,
        *,
        normative_bucket: tuple[RankedEvidenceItem, ...],
        interpretation_bucket: tuple[RankedEvidenceItem, ...],
        precedent_bucket: tuple[RankedEvidenceItem, ...],
        autonomous_norm_bucket: tuple[RankedEvidenceItem, ...],
        historical_context_bucket: tuple[RankedEvidenceItem, ...],
    ) -> dict[str, Any]:
        chain_ok = True
        chain_rep: dict[str, Any] = {}
        if self._adapter is not None:
            try:
                chain_ok, chain_rep = self._adapter.verify_integrity(require_raw_content=True)
            except Exception as exc:
                chain_ok = False
                chain_rep = {"valid": False, "error": str(exc)}

        all_bindings: list[EvidenceBindingRecord] = []
        quarantined: list[EvidenceBindingRecord] = []

        def _process_bucket(
            items: tuple[RankedEvidenceItem, ...],
            *,
            bucket_name: str,
        ) -> tuple[RankedEvidenceItem, ...]:
            kept: list[RankedEvidenceItem] = []
            for item in items:
                ok_chunk, err_code = verify_chunk_runtime_integrity(item.chunk)
                if not ok_chunk:
                    bad_rec = EvidenceBindingRecord(
                        chunk_id=item.chunk.chunk_id,
                        provision_id=item.chunk.provision_id,
                        source_id=item.chunk.source_id,
                        document_kind=item.chunk.document_kind,
                        bucket=bucket_name,
                        evidence_binding_status=BINDING_TRUST_CHAIN_INTEGRITY_MISMATCH,
                        evidence_id=item.chunk.evidence_id,
                        record_sha256=None,
                        registry_head_sha256=None,
                        content_sha256=item.chunk.content_sha256,
                        chunk_sha256=item.chunk.chunk_sha256,
                        audit_log_id=item.audit_log_id,
                        source_url=item.source_url,
                        transport_mode="UNKNOWN",
                        live_verified=False,
                        raw_content_verified=False,
                        failure_reason=f"RUNTIME_CHUNK_INTEGRITY_FAILED:{err_code}",
                    )
                    quarantined.append(bad_rec)
                    continue

                binding, passed = self._verify_single_item(
                    item,
                    bucket_name=bucket_name,
                    chain_ok=chain_ok,
                    chain_rep=chain_rep,
                )
                if not passed:
                    quarantined.append(binding)
                    continue

                all_bindings.append(binding)
                updated_item = RankedEvidenceItem(
                    **{
                        **item.__dict__,
                        "rank": len(kept) + 1,
                        "evidence_binding_status": binding.evidence_binding_status,
                    }
                )
                kept.append(updated_item)
            return tuple(kept)

        linked_norm = _process_bucket(normative_bucket, bucket_name="NORMATIVE")
        linked_interp = _process_bucket(interpretation_bucket, bucket_name="INTERPRETATION_BOUNDARY")
        linked_prec = _process_bucket(precedent_bucket, bucket_name="PRECEDENT")
        linked_auto = _process_bucket(autonomous_norm_bucket, bucket_name="AUTONOMOUS_NORM")
        linked_hist = _process_bucket(historical_context_bucket, bucket_name="HISTORICAL_CONTEXT")

        return {
            "normative_bucket": linked_norm,
            "interpretation_bucket": linked_interp,
            "precedent_bucket": linked_prec,
            "autonomous_norm_bucket": linked_auto,
            "historical_context_bucket": linked_hist,
            "evidence_bindings": tuple(all_bindings),
            "quarantined_evidence_mismatches": tuple(quarantined),
        }

    def _verify_single_item(
        self,
        item: RankedEvidenceItem,
        *,
        bucket_name: str,
        chain_ok: bool,
        chain_rep: dict[str, Any],
    ) -> tuple[EvidenceBindingRecord, bool]:
        ch = item.chunk
        ev_id = ch.evidence_id

        # Case 1: Chunk is bound to an explicit Trust Chain `evidence_id`
        if ev_id is not None and self._adapter is not None:
            if not chain_ok:
                return (
                    EvidenceBindingRecord(
                        chunk_id=ch.chunk_id,
                        provision_id=ch.provision_id,
                        source_id=ch.source_id,
                        document_kind=ch.document_kind,
                        bucket=bucket_name,
                        evidence_binding_status=BINDING_TRUST_CHAIN_INTEGRITY_MISMATCH,
                        evidence_id=ev_id,
                        record_sha256=None,
                        registry_head_sha256=chain_rep.get("head_sha256") or chain_rep.get("registry_head_sha256"),
                        content_sha256=ch.content_sha256,
                        chunk_sha256=ch.chunk_sha256,
                        audit_log_id=item.audit_log_id,
                        source_url=item.source_url,
                        transport_mode="UNKNOWN",
                        live_verified=False,
                        raw_content_verified=False,
                        failure_reason="TRUST_CHAIN_VERIFY_INTEGRITY_FAILED",
                    ),
                    False,
                )

            rec = self._adapter.get(ev_id)
            if rec is None:
                return (
                    EvidenceBindingRecord(
                        chunk_id=ch.chunk_id,
                        provision_id=ch.provision_id,
                        source_id=ch.source_id,
                        document_kind=ch.document_kind,
                        bucket=bucket_name,
                        evidence_binding_status=BINDING_TRUST_CHAIN_INTEGRITY_MISMATCH,
                        evidence_id=ev_id,
                        record_sha256=None,
                        registry_head_sha256=chain_rep.get("head_sha256") or chain_rep.get("registry_head_sha256"),
                        content_sha256=ch.content_sha256,
                        chunk_sha256=ch.chunk_sha256,
                        audit_log_id=item.audit_log_id,
                        source_url=item.source_url,
                        transport_mode="UNKNOWN",
                        live_verified=False,
                        raw_content_verified=False,
                        failure_reason="EVIDENCE_ID_NOT_FOUND_IN_REGISTRY",
                    ),
                    False,
                )

            if not getattr(rec, "is_verified_authority", False):
                return (
                    EvidenceBindingRecord(
                        chunk_id=ch.chunk_id,
                        provision_id=ch.provision_id,
                        source_id=ch.source_id,
                        document_kind=ch.document_kind,
                        bucket=bucket_name,
                        evidence_binding_status=BINDING_TRUST_CHAIN_INTEGRITY_MISMATCH,
                        evidence_id=ev_id,
                        record_sha256=getattr(rec, "record_sha256", None),
                        registry_head_sha256=getattr(rec, "registry_head_sha256", None)
                        or chain_rep.get("head_sha256")
                        or chain_rep.get("registry_head_sha256"),
                        content_sha256=ch.content_sha256,
                        chunk_sha256=ch.chunk_sha256,
                        audit_log_id=item.audit_log_id,
                        source_url=item.source_url,
                        transport_mode=str(getattr(rec, "transport_mode", "UNKNOWN")),
                        live_verified=bool(getattr(rec, "live_verified", False)),
                        raw_content_verified=False,
                        failure_reason="TRUST_CHAIN_EVIDENCE_NOT_VERIFIED_AUTHORITY",
                    ),
                    False,
                )

            rec_sha = getattr(rec, "content_sha256", None)
            if rec_sha != ch.content_sha256:
                return (
                    EvidenceBindingRecord(
                        chunk_id=ch.chunk_id,
                        provision_id=ch.provision_id,
                        source_id=ch.source_id,
                        document_kind=ch.document_kind,
                        bucket=bucket_name,
                        evidence_binding_status=BINDING_TRUST_CHAIN_INTEGRITY_MISMATCH,
                        evidence_id=ev_id,
                        record_sha256=getattr(rec, "record_sha256", None),
                        registry_head_sha256=getattr(rec, "registry_head_sha256", None)
                        or chain_rep.get("head_sha256")
                        or chain_rep.get("registry_head_sha256"),
                        content_sha256=ch.content_sha256,
                        chunk_sha256=ch.chunk_sha256,
                        audit_log_id=item.audit_log_id,
                        source_url=item.source_url,
                        transport_mode=str(getattr(rec, "transport_mode", "UNKNOWN")),
                        live_verified=bool(getattr(rec, "live_verified", False)),
                        raw_content_verified=False,
                        failure_reason="TRUST_CHAIN_CONTENT_SHA256_MISMATCH",
                    ),
                    False,
                )

            raw_bytes = self._adapter.get_raw_bytes(ev_id)
            if not isinstance(raw_bytes, (bytes, bytearray)) or len(raw_bytes) == 0:
                return (
                    EvidenceBindingRecord(
                        chunk_id=ch.chunk_id,
                        provision_id=ch.provision_id,
                        source_id=ch.source_id,
                        document_kind=ch.document_kind,
                        bucket=bucket_name,
                        evidence_binding_status=BINDING_TRUST_CHAIN_INTEGRITY_MISMATCH,
                        evidence_id=ev_id,
                        record_sha256=getattr(rec, "record_sha256", None),
                        registry_head_sha256=getattr(rec, "registry_head_sha256", None)
                        or chain_rep.get("head_sha256")
                        or chain_rep.get("registry_head_sha256"),
                        content_sha256=ch.content_sha256,
                        chunk_sha256=ch.chunk_sha256,
                        audit_log_id=item.audit_log_id,
                        source_url=item.source_url,
                        transport_mode=str(getattr(rec, "transport_mode", "UNKNOWN")),
                        live_verified=bool(getattr(rec, "live_verified", False)),
                        raw_content_verified=False,
                        failure_reason="TRUST_CHAIN_RAW_BYTES_MISSING",
                    ),
                    False,
                )

            raw_digest = hashlib.sha256(bytes(raw_bytes)).hexdigest()
            if raw_digest != ch.content_sha256:
                return (
                    EvidenceBindingRecord(
                        chunk_id=ch.chunk_id,
                        provision_id=ch.provision_id,
                        source_id=ch.source_id,
                        document_kind=ch.document_kind,
                        bucket=bucket_name,
                        evidence_binding_status=BINDING_TRUST_CHAIN_INTEGRITY_MISMATCH,
                        evidence_id=ev_id,
                        record_sha256=getattr(rec, "record_sha256", None),
                        registry_head_sha256=getattr(rec, "registry_head_sha256", None)
                        or chain_rep.get("head_sha256")
                        or chain_rep.get("registry_head_sha256"),
                        content_sha256=ch.content_sha256,
                        chunk_sha256=ch.chunk_sha256,
                        audit_log_id=item.audit_log_id,
                        source_url=item.source_url,
                        transport_mode=str(getattr(rec, "transport_mode", "UNKNOWN")),
                        live_verified=bool(getattr(rec, "live_verified", False)),
                        raw_content_verified=False,
                        failure_reason="TRUST_CHAIN_RAW_BYTES_SHA256_MISMATCH",
                    ),
                    False,
                )

            record_sha = getattr(rec, "record_sha256", None) or canonical_kb_sha256(
                {"evidence_id": ev_id, "content_sha256": ch.content_sha256}
            )
            head_sha = (
                getattr(rec, "registry_head_sha256", None)
                or chain_rep.get("registry_head_sha256")
                or chain_rep.get("head_sha256")
            )
            transport_mode = str(getattr(rec, "transport_mode", "VERIFIED_TEST_TRANSPORT"))
            live_verified = bool(getattr(rec, "live_verified", transport_mode == "LIVE_HTTPS"))
            return (
                EvidenceBindingRecord(
                    chunk_id=ch.chunk_id,
                    provision_id=ch.provision_id,
                    source_id=ch.source_id,
                    document_kind=ch.document_kind,
                    bucket=bucket_name,
                    evidence_binding_status=BINDING_TRUST_CHAIN_EVIDENCE_BOUND,
                    evidence_id=ev_id,
                    record_sha256=record_sha,
                    registry_head_sha256=head_sha,
                    content_sha256=ch.content_sha256,
                    chunk_sha256=ch.chunk_sha256,
                    audit_log_id=item.audit_log_id,
                    source_url=item.source_url,
                    transport_mode=transport_mode,
                    live_verified=live_verified,
                    raw_content_verified=True,
                    failure_reason=None,
                ),
                True,
            )

        # Case 2: No TrustChain adapter attached (or registry-audit-only L1–L6 baseline record)
        # Never fabricate synthetic evidence_id!
        if ch.document_kind == DOC_KIND_JUDICIAL_PRECEDENT and not item.source_url:
            return (
                EvidenceBindingRecord(
                    chunk_id=ch.chunk_id,
                    provision_id=ch.provision_id,
                    source_id=ch.source_id,
                    document_kind=ch.document_kind,
                    bucket=bucket_name,
                    evidence_binding_status=BINDING_TRUST_CHAIN_INTEGRITY_MISMATCH,
                    evidence_id=None,
                    record_sha256=None,
                    registry_head_sha256=None,
                    content_sha256=ch.content_sha256,
                    chunk_sha256=ch.chunk_sha256,
                    audit_log_id=item.audit_log_id,
                    source_url=item.source_url,
                    transport_mode="UNKNOWN",
                    live_verified=False,
                    raw_content_verified=False,
                    failure_reason="PRECEDENT_MISSING_OFFICIAL_URL",
                ),
                False,
            )

        return (
            EvidenceBindingRecord(
                chunk_id=ch.chunk_id,
                provision_id=ch.provision_id,
                source_id=ch.source_id,
                document_kind=ch.document_kind,
                bucket=bucket_name,
                evidence_binding_status=BINDING_REGISTRY_AUDIT_BACKED_NO_TRUST_CHAIN,
                evidence_id=None,
                record_sha256=None,
                registry_head_sha256=None,
                content_sha256=ch.content_sha256,
                chunk_sha256=ch.chunk_sha256,
                audit_log_id=item.audit_log_id,
                source_url=item.source_url,
                transport_mode="LOCAL_AUDIT_BACKED_NO_TRUST_CHAIN",
                live_verified=False,
                raw_content_verified=False,
                failure_reason=None,
            ),
            True,
        )
