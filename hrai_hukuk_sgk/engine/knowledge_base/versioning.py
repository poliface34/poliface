"""Append-only bitemporal version management preserving historical legislation states (WP-4.2).

Guarantees:
  - Historical legislation versions are NEVER deleted or overwritten.
  - Overlapping effective-date windows for the same `provision_id` or `source_id` fail closed.
  - Point-in-time queries (`resolve_version_as_of`) strictly return ONLY the version in effect on
    `as_of_date` and place superseded/future versions into separate historical/future lists.
"""

from __future__ import annotations

from datetime import date
import threading
from typing import Any

from .models import (
    KnowledgeBaseError,
    LegalDocumentVersion,
    LegalProvisionNode,
    TrustChainEvidenceAdapterProtocol,
    canonical_kb_sha256,
    is_valid_kb_sha256,
    parse_strict_kb_date,
)


def _windows_overlap(start_a: date, end_a: date | None, start_b: date, end_b: date | None) -> bool:
    eff_end_a = end_a if end_a is not None else date(2999, 12, 31)
    eff_end_b = end_b if end_b is not None else date(2999, 12, 31)
    return start_a <= eff_end_b and start_b <= eff_end_a


class BitemporalVersionManager:
    """Thread-safe, append-only registry tracking statutory document & provision versions over time."""

    def __init__(self, *, trust_chain_adapter: TrustChainEvidenceAdapterProtocol | None = None) -> None:
        self._lock = threading.RLock()
        self._trust_chain = trust_chain_adapter
        self._doc_versions_by_id: dict[str, LegalDocumentVersion] = {}
        self._doc_versions_by_source: dict[str, list[LegalDocumentVersion]] = {}
        self._provisions_by_key: dict[str, LegalProvisionNode] = {}
        self._provision_history: dict[str, list[LegalProvisionNode]] = {}

    def register_document_version(self, doc_ver: LegalDocumentVersion) -> LegalDocumentVersion:
        with self._lock:
            if doc_ver.document_version_id in self._doc_versions_by_id:
                raise KnowledgeBaseError(
                    "DUPLICATE_DOCUMENT_VERSION_ID",
                    f"document_version_id zaten kayıtlıdır (üzerine yazma yasaktır): {doc_ver.document_version_id!r}",
                )
            if not is_valid_kb_sha256(doc_ver.content_sha256):
                raise KnowledgeBaseError(
                    "INVALID_CONTENT_SHA256",
                    f"'{doc_ver.document_version_id}' için geçerli 64 haneli content_sha256 zorunludur.",
                )

            if self._trust_chain is not None and doc_ver.evidence_id is not None:
                rec = self._trust_chain.get(doc_ver.evidence_id)
                if rec is None or not getattr(rec, "is_verified_authority", False):
                    raise KnowledgeBaseError(
                        "TRUST_CHAIN_EVIDENCE_UNVERIFIED",
                        f"'{doc_ver.document_version_id}' için bağlı evidence_id={doc_ver.evidence_id!r} "
                        "Trust Chain defterinde doğrulanmış değil.",
                    )
                if getattr(rec, "content_sha256", None) != doc_ver.content_sha256:
                    raise KnowledgeBaseError(
                        "TRUST_CHAIN_SHA256_MISMATCH",
                        f"'{doc_ver.document_version_id}' content_sha256 değeri Trust Chain kaydıyla uyuşmuyor.",
                    )

            existing = self._doc_versions_by_source.get(doc_ver.source_id, [])
            if existing:
                prior = existing[-1]
                if doc_ver.supersedes_version_id != prior.document_version_id:
                    raise KnowledgeBaseError(
                        "SUPERSEDES_VERSION_CHAIN_MISMATCH",
                        f"'{doc_ver.document_version_id}' supersedes_version_id={doc_ver.supersedes_version_id!r} "
                        f"önceki sürümle ({prior.document_version_id!r}) eşleşmiyor.",
                    )
                new_from = parse_strict_kb_date(doc_ver.effective_from, "effective_from")
                new_to = parse_strict_kb_date(doc_ver.effective_to, "effective_to") if doc_ver.effective_to else None
                for prev in existing:
                    p_from = parse_strict_kb_date(prev.effective_from, "prev.effective_from")
                    p_to = parse_strict_kb_date(prev.effective_to, "prev.effective_to") if prev.effective_to else None
                    if _windows_overlap(new_from, new_to, p_from, p_to):
                        raise KnowledgeBaseError(
                            "OVERLAPPING_EFFECTIVE_WINDOW",
                            f"'{doc_ver.source_id}' için yürürlük penceresi ({doc_ver.effective_from}..{doc_ver.effective_to}) "
                            f"önceki sürümle ({prev.document_version_id}: {prev.effective_from}..{prev.effective_to}) çakışıyor.",
                        )
            elif doc_ver.supersedes_version_id is not None:
                raise KnowledgeBaseError(
                    "INVALID_INITIAL_SUPERSEDES",
                    f"'{doc_ver.source_id}' ilk sürümünde supersedes_version_id boş olmalıdır.",
                )

            self._doc_versions_by_id[doc_ver.document_version_id] = doc_ver
            self._doc_versions_by_source.setdefault(doc_ver.source_id, []).append(doc_ver)
            return doc_ver

    def register_provision_version(self, prov: LegalProvisionNode) -> LegalProvisionNode:
        with self._lock:
            ver_key = f"{prov.provision_id}@{prov.document_version_id}"
            if ver_key in self._provisions_by_key:
                raise KnowledgeBaseError(
                    "DUPLICATE_PROVISION_VERSION",
                    f"'{ver_key}' madde sürümü zaten kayıtlıdır (append-only ihlali).",
                )
            if not is_valid_kb_sha256(prov.content_sha256):
                raise KnowledgeBaseError(
                    "INVALID_CONTENT_SHA256",
                    f"'{ver_key}' için geçerli 64 haneli content_sha256 zorunludur.",
                )

            existing = self._provision_history.get(prov.provision_id, [])
            if existing:
                new_from = parse_strict_kb_date(prov.effective_from, "effective_from")
                new_to = parse_strict_kb_date(prov.effective_to, "effective_to") if prov.effective_to else None
                for prev in existing:
                    p_from = parse_strict_kb_date(prev.effective_from, "prev.effective_from")
                    p_to = parse_strict_kb_date(prev.effective_to, "prev.effective_to") if prev.effective_to else None
                    if _windows_overlap(new_from, new_to, p_from, p_to):
                        raise KnowledgeBaseError(
                            "OVERLAPPING_PROVISION_EFFECTIVE_WINDOW",
                            f"'{prov.provision_id}' sürümü ({prov.effective_from}..{prov.effective_to}) "
                            f"önceki sürümle ({prev.document_version_id}: {prev.effective_from}..{prev.effective_to}) çakışıyor.",
                        )

            self._provisions_by_key[ver_key] = prov
            self._provision_history.setdefault(prov.provision_id, []).append(prov)
            return prov

    def resolve_version_as_of(self, provision_id: str, as_of_date: str) -> dict[str, Any]:
        """Return exact version active on `as_of_date`, separating expired & future versions strictly."""
        target = parse_strict_kb_date(as_of_date, "as_of_date")
        with self._lock:
            versions = list(self._provision_history.get(provision_id, []))
            if not versions:
                return {
                    "found": False,
                    "provision_id": provision_id,
                    "as_of_date": as_of_date,
                    "active_version": None,
                    "historical_versions": [],
                    "future_versions": [],
                    "reason": "PROVISION_NOT_FOUND",
                }

            active: LegalProvisionNode | None = None
            historical: list[dict[str, Any]] = []
            future: list[dict[str, Any]] = []
            for ver in versions:
                v_from = parse_strict_kb_date(ver.effective_from, "effective_from")
                v_to = parse_strict_kb_date(ver.effective_to, "effective_to") if ver.effective_to else None
                if v_from <= target and (v_to is None or target <= v_to):
                    active = ver
                elif v_to is not None and v_to < target:
                    historical.append(ver.to_dict())
                elif target < v_from:
                    future.append(ver.to_dict())

            return {
                "found": active is not None,
                "provision_id": provision_id,
                "as_of_date": as_of_date,
                "total_versions": len(versions),
                "active_version": active.to_dict() if active is not None else None,
                "historical_versions": historical,
                "future_versions": future,
                "is_historical_superseded_on_date": active is None and len(historical) > 0,
            }

    def get_provision_history(self, provision_id: str) -> tuple[LegalProvisionNode, ...]:
        with self._lock:
            return tuple(self._provision_history.get(provision_id, []))

    def verify_integrity(self) -> tuple[bool, dict[str, Any]]:
        errors: list[str] = []
        with self._lock:
            for source_id, doc_list in self._doc_versions_by_source.items():
                for idx, doc_ver in enumerate(doc_list):
                    if not is_valid_kb_sha256(doc_ver.content_sha256):
                        errors.append(f"source={source_id}[{idx}]: geçersiz content_sha256.")
                    if idx == 0 and doc_ver.supersedes_version_id is not None:
                        errors.append(f"source={source_id}[0]: supersedes_version_id None olmalıdır.")
                    if idx > 0 and doc_ver.supersedes_version_id != doc_list[idx - 1].document_version_id:
                        errors.append(f"source={source_id}[{idx}]: kırık supersedes_version_id zinciri.")

            for prov_id, prov_list in self._provision_history.items():
                for idx in range(len(prov_list)):
                    p_a = prov_list[idx]
                    a_from = parse_strict_kb_date(p_a.effective_from, "effective_from")
                    a_to = parse_strict_kb_date(p_a.effective_to, "effective_to") if p_a.effective_to else None
                    for jdx in range(idx + 1, len(prov_list)):
                        p_b = prov_list[jdx]
                        b_from = parse_strict_kb_date(p_b.effective_from, "effective_from")
                        b_to = parse_strict_kb_date(p_b.effective_to, "effective_to") if p_b.effective_to else None
                        if _windows_overlap(a_from, a_to, b_from, b_to):
                            errors.append(f"provision={prov_id}: çakışan yürürlük aralıkları.")

            digest = canonical_kb_sha256(
                {
                    "document_versions": sorted(self._doc_versions_by_id.keys()),
                    "provision_versions": sorted(self._provisions_by_key.keys()),
                }
            )
            return len(errors) == 0, {
                "valid": len(errors) == 0,
                "document_version_count": len(self._doc_versions_by_id),
                "provision_key_count": len(self._provision_history),
                "total_provision_versions": len(self._provisions_by_key),
                "version_catalog_sha256": digest,
                "errors": errors,
            }
