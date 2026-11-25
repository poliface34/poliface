"""Append-only, versioned, SHA-256 hash-chained EvidenceRegistry (hrAI @HukukSGK v1.0.6 WP2.3).

Core invariants:
  - Every verified source document is stored under a unique `evidence_id` (duplicates fail closed).
  - Append-only & immutable: old legislation versions are NEVER deleted or overwritten; new versions
    increment `version_number` monotonically per `source_key` and point to `supersedes_evidence_id`.
  - Unreachable or rejected acquisition results are NEVER admitted as verified legal authority
    (they may only be recorded in the separate `failed_attempts` audit trail).
  - Every record binds `content_sha256`, `metadata_sha256`, version metadata, and
    `previous_record_sha256` into a verifiable SHA-256 hash chain (`verify_integrity()`).
"""

from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import threading
from typing import Any

from .models import (
    GENESIS_CHAIN_HASH,
    STATUS_VERIFIED_LIVE,
    STATUS_VERIFIED_TEST_TRANSPORT,
    AcquisitionResult,
    EvidenceRecord,
    EvidenceRegistryError,
    TrustChainError,
    canonical_sha256,
    is_valid_sha256_hex,
    parse_strict_iso_date,
)


def _clone_record(rec: EvidenceRecord) -> EvidenceRecord:
    return replace(rec, adapter_metadata=copy.deepcopy(rec.adapter_metadata))


class EvidenceRegistry:
    """Thread-safe, append-only registry of SHA-256 verified legal source evidence records."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._ledger: list[EvidenceRecord] = []
        self._by_id: dict[str, EvidenceRecord] = {}
        self._by_source_key: dict[str, list[str]] = {}
        self._raw_content_sha_index: dict[str, bytes] = {}
        self._failed_attempts: list[EvidenceRecord] = []

    @property
    def head_sha256(self) -> str:
        with self._lock:
            return self._ledger[-1].record_sha256 if self._ledger else GENESIS_CHAIN_HASH

    @property
    def record_count(self) -> int:
        with self._lock:
            return len(self._ledger)

    @property
    def failed_attempts(self) -> tuple[EvidenceRecord, ...]:
        with self._lock:
            return tuple(_clone_record(r) for r in self._failed_attempts)

    def record_failed_attempt(self, result: AcquisitionResult) -> EvidenceRecord:
        """Record a failed or unreachable acquisition attempt strictly in the audit trail (never active evidence)."""
        if not isinstance(result, AcquisitionResult):
            raise EvidenceRegistryError("INVALID_ACQUISITION_RESULT", "AcquisitionResult örneği beklenmektedir.")
        if result.ok or result.record.is_verified_authority:
            raise EvidenceRegistryError(
                "EXPECTED_FAILED_ATTEMPT",
                "Başarılı doğrulanmış sonuç failed_attempts defterine değil register() ile kaydedilmelidir.",
            )
        with self._lock:
            stored = _clone_record(result.record)
            self._failed_attempts.append(stored)
            return _clone_record(stored)

    def register(
        self,
        result: AcquisitionResult,
        *,
        store_raw_bytes: bool = True,
        allow_older_effective_version: bool = False,
    ) -> EvidenceRecord:
        """Register a verified AcquisitionResult into the append-only hash-chained EvidenceRegistry."""
        if not isinstance(result, AcquisitionResult):
            raise EvidenceRegistryError("INVALID_ACQUISITION_RESULT", "AcquisitionResult örneği beklenmektedir.")

        rec = _clone_record(result.record)
        if not result.ok or not rec.is_verified_authority:
            with self._lock:
                self._failed_attempts.append(rec)
            raise EvidenceRegistryError(
                "UNREACHABLE_OR_UNVERIFIED_EVIDENCE_REJECTED",
                f"Doğrulanmamış veya erişilemeyen kaynak ({rec.status}) aktif kanıt defterine kaydedilemez: "
                f"codes={list(rec.error_codes)}",
            )

        if not isinstance(result.raw_bytes, (bytes, bytearray)) or len(result.raw_bytes) == 0:
            raise EvidenceRegistryError(
                "MISSING_RAW_CONTENT_BYTES",
                "SHA-256 bütünlük teyidi için ham belge baytları (raw_bytes) zorunludur.",
            )

        raw_bytes = bytes(result.raw_bytes)
        actual_content_sha = hashlib.sha256(raw_bytes).hexdigest()
        if actual_content_sha != rec.content_sha256 or len(raw_bytes) != rec.content_bytes_length:
            raise EvidenceRegistryError(
                "CONTENT_SHA256_VERIFICATION_FAILED",
                f"Kayıt sırasında ham içerik SHA-256 doğrulaması başarısız ({actual_content_sha} != {rec.content_sha256}).",
            )

        recomputed_meta_sha = canonical_sha256(rec.metadata_payload())
        if recomputed_meta_sha != rec.metadata_sha256:
            raise EvidenceRegistryError(
                "METADATA_SHA256_VERIFICATION_FAILED",
                f"Kayıt metadata SHA-256 özeti uyuşmuyor ({recomputed_meta_sha} != {rec.metadata_sha256}).",
            )

        recomputed_rec_sha = canonical_sha256(rec.chain_payload())
        if recomputed_rec_sha != rec.record_sha256:
            raise EvidenceRegistryError(
                "RECORD_SHA256_VERIFICATION_FAILED",
                f"Kayıt record_sha256 özeti uyuşmuyor ({recomputed_rec_sha} != {rec.record_sha256}).",
            )

        with self._lock:
            if rec.evidence_id in self._by_id:
                raise EvidenceRegistryError(
                    "DUPLICATE_EVIDENCE_ID",
                    f"evidence_id zaten kayıtlıdır (yinelenen kimlik yasaktır): {rec.evidence_id!r}",
                )

            existing_ids = self._by_source_key.get(rec.source_key, [])
            version_number = len(existing_ids) + 1
            prior_latest: EvidenceRecord | None = self._by_id[existing_ids[-1]] if existing_ids else None

            if prior_latest is None:
                if rec.supersedes_evidence_id is not None:
                    raise EvidenceRegistryError(
                        "INVALID_SUPERSEDES_FOR_FIRST_VERSION",
                        f"'{rec.source_key}' ilk sürümü için supersedes_evidence_id boş olmalıdır.",
                    )
                supersedes_id: str | None = None
            else:
                if rec.supersedes_evidence_id is not None and rec.supersedes_evidence_id != prior_latest.evidence_id:
                    raise EvidenceRegistryError(
                        "SUPERSEDES_CHAIN_MISMATCH",
                        f"supersedes_evidence_id ({rec.supersedes_evidence_id!r}) mevcut son sürümle "
                        f"({prior_latest.evidence_id!r}) eşleşmiyor.",
                    )
                supersedes_id = prior_latest.evidence_id
                if not allow_older_effective_version:
                    new_eff = parse_strict_iso_date(rec.effective_date, "effective_date")
                    old_eff = parse_strict_iso_date(prior_latest.effective_date, "prior.effective_date")
                    if new_eff < old_eff:
                        raise EvidenceRegistryError(
                            "NON_MONOTONIC_EFFECTIVE_DATE_VERSION",
                            f"Yeni sürüm yürürlük tarihi ({rec.effective_date}) önceki sürümden "
                            f"({prior_latest.effective_date}) eski olamaz.",
                        )

            prev_chain_hash = self._ledger[-1].record_sha256 if self._ledger else GENESIS_CHAIN_HASH

            chained_draft = replace(
                rec,
                version_number=version_number,
                supersedes_evidence_id=supersedes_id,
                previous_record_sha256=prev_chain_hash,
            )
            sealed_record_sha = canonical_sha256(chained_draft.chain_payload())
            sealed_record = replace(chained_draft, record_sha256=sealed_record_sha)

            self._ledger.append(sealed_record)
            self._by_id[sealed_record.evidence_id] = sealed_record
            self._by_source_key.setdefault(sealed_record.source_key, []).append(sealed_record.evidence_id)
            if store_raw_bytes:
                self._raw_content_sha_index[sealed_record.evidence_id] = raw_bytes
            return _clone_record(sealed_record)

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        with self._lock:
            rec = self._by_id.get(evidence_id)
            return _clone_record(rec) if rec is not None else None

    def get_raw_bytes(self, evidence_id: str) -> bytes | None:
        with self._lock:
            return self._raw_content_sha_index.get(evidence_id)

    def get_version_history(self, source_key: str) -> tuple[EvidenceRecord, ...]:
        """Return all immutable versions of `source_key` in chronological version order (oldest -> newest)."""
        with self._lock:
            ids = self._by_source_key.get(source_key, [])
            return tuple(_clone_record(self._by_id[eid]) for eid in ids)

    def get_current(self, source_key: str) -> EvidenceRecord | None:
        """Return the latest registered version of `source_key` without deleting historical versions."""
        with self._lock:
            ids = self._by_source_key.get(source_key, [])
            return _clone_record(self._by_id[ids[-1]]) if ids else None

    def is_superseded(self, evidence_id: str) -> bool:
        with self._lock:
            rec = self._by_id.get(evidence_id)
            if rec is None:
                return False
            ids = self._by_source_key.get(rec.source_key, [])
            return bool(ids) and ids[-1] != evidence_id

    def get_superseding_record(self, evidence_id: str) -> EvidenceRecord | None:
        with self._lock:
            rec = self._by_id.get(evidence_id)
            if rec is None:
                return None
            ids = self._by_source_key.get(rec.source_key, [])
            try:
                idx = ids.index(evidence_id)
            except ValueError:
                return None
            if idx + 1 < len(ids):
                return _clone_record(self._by_id[ids[idx + 1]])
            return None

    def resolve_for_date(self, source_key: str, as_of_date: str) -> tuple[EvidenceRecord | None, dict[str, Any]]:
        """Resolve the exact version of `source_key` in effect on `as_of_date` without conflating old & current versions."""
        target = parse_strict_iso_date(as_of_date, "as_of_date")
        with self._lock:
            versions = self.get_version_history(source_key)
            if not versions:
                return None, {"found": False, "source_key": source_key, "as_of_date": as_of_date, "reason": "NOT_FOUND"}

            eligible: list[EvidenceRecord] = []
            for ver in versions:
                eff = parse_strict_iso_date(ver.effective_date, "effective_date")
                exp = parse_strict_iso_date(ver.expiry_or_repeal_date, "expiry_or_repeal_date") if ver.expiry_or_repeal_date else None
                if eff <= target and (exp is None or target <= exp):
                    eligible.append(ver)

            if not eligible:
                return None, {
                    "found": False,
                    "source_key": source_key,
                    "as_of_date": as_of_date,
                    "total_versions": len(versions),
                    "reason": "NO_VERSION_EFFECTIVE_ON_DATE",
                }

            chosen = eligible[-1]
            latest = versions[-1]
            superseded = chosen.evidence_id != latest.evidence_id
            return chosen, {
                "found": True,
                "source_key": source_key,
                "as_of_date": as_of_date,
                "evidence_id": chosen.evidence_id,
                "version_number": chosen.version_number,
                "total_versions": len(versions),
                "is_current_latest": not superseded,
                "is_superseded_by_later_version": superseded,
                "latest_evidence_id": latest.evidence_id,
            }

    def verify_integrity(self) -> tuple[bool, dict[str, Any]]:
        """Re-verify the entire append-only SHA-256 hash chain, version links, metadata digests, and stored raw bytes."""
        errors: list[str] = []
        with self._lock:
            expected_prev = GENESIS_CHAIN_HASH
            seen_ids: set[str] = set()
            seen_versions: dict[str, list[EvidenceRecord]] = {}

            for idx, rec in enumerate(self._ledger):
                if rec.evidence_id in seen_ids:
                    errors.append(f"ledger[{idx}]: yinelenen evidence_id ({rec.evidence_id}).")
                seen_ids.add(rec.evidence_id)

                if rec.status not in (STATUS_VERIFIED_LIVE, STATUS_VERIFIED_TEST_TRANSPORT):
                    errors.append(f"ledger[{idx}] ({rec.evidence_id}): aktif defterde doğrulanmamış durum ({rec.status}).")
                if not is_valid_sha256_hex(rec.content_sha256):
                    errors.append(f"ledger[{idx}] ({rec.evidence_id}): geçersiz content_sha256.")

                if rec.previous_record_sha256 != expected_prev:
                    errors.append(
                        f"ledger[{idx}] ({rec.evidence_id}): kırık hash zinciri "
                        f"({rec.previous_record_sha256} != {expected_prev})."
                    )

                recomp_meta = canonical_sha256(rec.metadata_payload())
                if recomp_meta != rec.metadata_sha256:
                    errors.append(
                        f"ledger[{idx}] ({rec.evidence_id}): metadata_sha256 uyuşmazlığı "
                        f"({recomp_meta} != {rec.metadata_sha256})."
                    )

                recomp_rec = canonical_sha256(rec.chain_payload())
                if recomp_rec != rec.record_sha256:
                    errors.append(
                        f"ledger[{idx}] ({rec.evidence_id}): record_sha256 uyuşmazlığı "
                        f"({recomp_rec} != {rec.record_sha256})."
                    )

                if rec.evidence_id in self._raw_content_sha_index:
                    raw_b = self._raw_content_sha_index[rec.evidence_id]
                    raw_sha = hashlib.sha256(raw_b).hexdigest()
                    if raw_sha != rec.content_sha256 or len(raw_b) != rec.content_bytes_length:
                        errors.append(
                            f"ledger[{idx}] ({rec.evidence_id}): saklanan ham içerik SHA-256 tahrifatı "
                            f"({raw_sha} != {rec.content_sha256})."
                        )

                src_list = seen_versions.setdefault(rec.source_key, [])
                expected_ver = len(src_list) + 1
                if rec.version_number != expected_ver:
                    errors.append(
                        f"ledger[{idx}] ({rec.evidence_id}): sürüm numarası süreksiz "
                        f"({rec.version_number} != {expected_ver})."
                    )
                expected_sup = src_list[-1].evidence_id if src_list else None
                if rec.supersedes_evidence_id != expected_sup:
                    errors.append(
                        f"ledger[{idx}] ({rec.evidence_id}): supersedes_evidence_id uyuşmazlığı "
                        f"({rec.supersedes_evidence_id!r} != {expected_sup!r})."
                    )
                src_list.append(rec)
                expected_prev = rec.record_sha256

            # Check index consistency against append-only ledger
            if set(self._by_id.keys()) != seen_ids:
                errors.append("_by_id indeksi ile append-only _ledger tutarsız.")
            for skey, recs in seen_versions.items():
                idx_ids = self._by_source_key.get(skey, [])
                if idx_ids != [r.evidence_id for r in recs]:
                    errors.append(f"_by_source_key[{skey!r}] ile _ledger tutarsız.")

            valid = len(errors) == 0
            return valid, {
                "valid": valid,
                "record_count": len(self._ledger),
                "source_key_count": len(seen_versions),
                "failed_attempt_count": len(self._failed_attempts),
                "head_sha256": self._ledger[-1].record_sha256 if self._ledger else GENESIS_CHAIN_HASH,
                "errors": errors,
            }

    def export_snapshot_dict(self) -> dict[str, Any]:
        """Export an auditable JSON-serializable snapshot of the registry and its hash chain."""
        ok, report = self.verify_integrity()
        if not ok:
            raise EvidenceRegistryError(
                "EVIDENCE_REGISTRY_INTEGRITY_FAILED",
                f"Bütünlüğü bozulmuş kanıt defteri dışa aktarılamaz: {report['errors']}",
            )
        with self._lock:
            return {
                "schema_version": "1.0.6-wp2",
                "head_sha256": report["head_sha256"],
                "record_count": len(self._ledger),
                "records": [rec.to_dict() for rec in self._ledger],
                "failed_attempts": [fa.to_dict() for fa in self._failed_attempts],
            }

    @classmethod
    def from_snapshot_dict(cls, snapshot: dict[str, Any]) -> EvidenceRegistry:
        """Rehydrate an EvidenceRegistry from an exported snapshot and fail closed if tampered."""
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("records"), list):
            raise EvidenceRegistryError("INVALID_REGISTRY_SNAPSHOT", "Geçersiz EvidenceRegistry anlık görüntüsü.")
        if snapshot.get("schema_version") != "1.0.6-wp2":
            raise EvidenceRegistryError(
                "UNSUPPORTED_SNAPSHOT_SCHEMA_VERSION",
                f"Desteklenmeyen anlık görüntü şema sürümü: {snapshot.get('schema_version')!r}",
            )
        reg = cls()
        try:
            for raw in snapshot["records"]:
                rec = EvidenceRecord(
                    evidence_id=str(raw["evidence_id"]),
                    source_key=str(raw["source_key"]),
                    adapter_type=str(raw["adapter_type"]),
                    title=str(raw["title"]),
                    source_url=str(raw["source_url"]),
                    final_url=str(raw["final_url"]),
                    redirect_chain=tuple(raw.get("redirect_chain", ())),
                    acquired_at_utc=str(raw["acquired_at_utc"]),
                    publication_date=str(raw["publication_date"]),
                    effective_date=str(raw["effective_date"]),
                    expiry_or_repeal_date=raw.get("expiry_or_repeal_date"),
                    version_number=int(raw["version_number"]),
                    supersedes_evidence_id=raw.get("supersedes_evidence_id"),
                    content_sha256=str(raw["content_sha256"]),
                    content_bytes_length=int(raw["content_bytes_length"]),
                    content_type=str(raw["content_type"]),
                    http_status=raw.get("http_status"),
                    transport_mode=str(raw["transport_mode"]),
                    live_verified=bool(raw["live_verified"]),
                    status=str(raw["status"]),
                    adapter_metadata=dict(raw.get("adapter_metadata", {})),
                    metadata_sha256=str(raw["metadata_sha256"]),
                    record_sha256=str(raw["record_sha256"]),
                    previous_record_sha256=str(raw["previous_record_sha256"]),
                    error_codes=tuple(raw.get("error_codes", ())),
                    errors=tuple(raw.get("errors", ())),
                    legal_boundary_notice=str(raw.get("legal_boundary_notice", "")),
                )
                reg._ledger.append(rec)
                reg._by_id[rec.evidence_id] = rec
                reg._by_source_key.setdefault(rec.source_key, []).append(rec.evidence_id)
        except (KeyError, TypeError, ValueError) as exc:
            raise EvidenceRegistryError("CORRUPT_REGISTRY_SNAPSHOT", f"Bozuk anlık görüntü kaydı: {exc}") from exc

        ok, rep = reg.verify_integrity()
        if (
            not ok
            or snapshot.get("head_sha256") != rep["head_sha256"]
            or snapshot.get("record_count") != len(reg._ledger)
        ):
            raise EvidenceRegistryError(
                "REGISTRY_SNAPSHOT_INTEGRITY_FAILED",
                f"Kanıt defteri anlık görüntüsü bütünlük doğrulamasından geçemedi: {rep['errors']}",
            )
        return reg
