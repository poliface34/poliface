"""Append-only, versioned, SHA-256 hash-chained EvidenceRegistry with Raw Content Store (hrAI @HukukSGK v1.0.6 WP2.3).

Core invariants (including PR #3 Finding 1 remediation):
  - Every verified source document is stored under a unique `evidence_id` (duplicates fail closed).
  - Append-only & immutable: old legislation versions are NEVER deleted or overwritten; new versions
    increment `version_number` monotonically per `source_key` and point to `supersedes_evidence_id`.
  - Raw document bytes are preserved in an explicit `ContentStore` (`InMemoryContentStore` or
    `FileSystemContentStore`) AND exported/rehydrated with SHA-256 verification in snapshots by default
    (`SNAPSHOT_MODE_FULL_WITH_RAW`).
  - `verify_integrity(require_raw_content=True)` (default) FAILS CLOSED if ANY registered record is
    missing its raw bytes or fails raw-byte SHA-256 recomputation — metadata-only snapshots are NEVER
    silently accepted as full verified content archives.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import base64
import copy
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import re
import stat
import threading
from typing import Any

from .models import (
    CONTENT_MATCH_MATCHED,
    GENESIS_CHAIN_HASH,
    SNAPSHOT_MODE_FULL_WITH_RAW,
    SNAPSHOT_MODE_METADATA_ONLY,
    STATUS_VERIFIED_LIVE,
    STATUS_VERIFIED_TEST_TRANSPORT,
    AcquisitionResult,
    EvidenceRecord,
    EvidenceRegistryError,
    canonical_sha256,
    is_valid_sha256_hex,
    parse_strict_iso_date,
)

_SAFE_EVIDENCE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{3,127}$")


def _clone_record(rec: EvidenceRecord) -> EvidenceRecord:
    return replace(
        rec,
        adapter_metadata=copy.deepcopy(rec.adapter_metadata),
        content_verification=copy.deepcopy(rec.content_verification),
    )


class ContentStore(ABC):
    """Abstract integrity-preserving raw document byte archive contract."""

    @abstractmethod
    def put(self, evidence_id: str, raw_bytes: bytes) -> str:
        """Persist `raw_bytes` for `evidence_id` (write-once; refuse silent overwrite) and return SHA-256."""

    @abstractmethod
    def get(self, evidence_id: str) -> bytes | None:
        """Return stored raw bytes for `evidence_id`, or None if absent."""

    @abstractmethod
    def has(self, evidence_id: str) -> bool:
        """Return True iff raw bytes for `evidence_id` exist in the store."""


class InMemoryContentStore(ContentStore):
    """Thread-safe write-once in-memory raw content archive."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._blobs: dict[str, bytes] = {}

    def put(self, evidence_id: str, raw_bytes: bytes) -> str:
        if not isinstance(raw_bytes, (bytes, bytearray)) or len(raw_bytes) == 0:
            raise EvidenceRegistryError("MISSING_RAW_CONTENT_BYTES", "Boş ham belge içeriği saklanamaz.")
        data = bytes(raw_bytes)
        with self._lock:
            if evidence_id in self._blobs:
                raise EvidenceRegistryError(
                    "CONTENT_STORE_OVERWRITE_FORBIDDEN",
                    f"Ham belge deposunda '{evidence_id}' kaydının üzerine yazılamaz.",
                )
            self._blobs[evidence_id] = data
        return hashlib.sha256(data).hexdigest()

    def get(self, evidence_id: str) -> bytes | None:
        with self._lock:
            return self._blobs.get(evidence_id)

    def has(self, evidence_id: str) -> bool:
        with self._lock:
            return evidence_id in self._blobs


class FileSystemContentStore(ContentStore):
    """Write-once filesystem raw content archive with symlink & path-traversal rejection."""

    def __init__(self, root_dir: str | Path) -> None:
        raw_path = Path(root_dir)
        try:
            st = raw_path.lstat()
        except FileNotFoundError:
            raw_path.mkdir(parents=True, exist_ok=True)
        else:
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise EvidenceRegistryError(
                    "INVALID_CONTENT_STORE_DIR",
                    f"Ham belge deposu dizini symlink olamaz ve geçerli bir dizin olmalıdır: {raw_path}",
                )
        self._root = raw_path.resolve()
        self._lock = threading.RLock()

    def _blob_path(self, evidence_id: str) -> Path:
        if not isinstance(evidence_id, str) or not _SAFE_EVIDENCE_ID_RE.fullmatch(evidence_id):
            raise EvidenceRegistryError("INVALID_EVIDENCE_ID", f"Geçersiz evidence_id dosya adı: {evidence_id!r}")
        p = self._root / f"{evidence_id}.bin"
        if p.parent.resolve() != self._root:
            raise EvidenceRegistryError("INVALID_EVIDENCE_ID", f"Yol dışına taşan evidence_id: {evidence_id!r}")
        return p

    def put(self, evidence_id: str, raw_bytes: bytes) -> str:
        if not isinstance(raw_bytes, (bytes, bytearray)) or len(raw_bytes) == 0:
            raise EvidenceRegistryError("MISSING_RAW_CONTENT_BYTES", "Boş ham belge içeriği saklanamaz.")
        data = bytes(raw_bytes)
        target = self._blob_path(evidence_id)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        with self._lock:
            if target.is_symlink():
                raise EvidenceRegistryError(
                    "CONTENT_STORE_SYMLINK_FORBIDDEN",
                    f"Ham belge deposunda symlink üzerine yazılamaz: {target}",
                )
            try:
                fd = os.open(str(target), flags, 0o600)
            except FileExistsError as exc:
                raise EvidenceRegistryError(
                    "CONTENT_STORE_OVERWRITE_FORBIDDEN",
                    f"Ham belge deposunda '{evidence_id}' dosyasının üzerine yazılamaz.",
                ) from exc
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
        return hashlib.sha256(data).hexdigest()

    def get(self, evidence_id: str) -> bytes | None:
        target = self._blob_path(evidence_id)
        with self._lock:
            if target.is_symlink():
                raise EvidenceRegistryError(
                    "CONTENT_STORE_SYMLINK_FORBIDDEN",
                    f"Ham belge deposunda symlink yasaktır: {target}",
                )
            if not target.is_file():
                return None
            return target.read_bytes()

    def has(self, evidence_id: str) -> bool:
        target = self._blob_path(evidence_id)
        with self._lock:
            return not target.is_symlink() and target.is_file()


class EvidenceRegistry:
    """Thread-safe, append-only registry of SHA-256 verified legal source evidence records + raw content archive."""

    def __init__(self, *, content_store: ContentStore | None = None) -> None:
        self._lock = threading.RLock()
        self._ledger: list[EvidenceRecord] = []
        self._by_id: dict[str, EvidenceRecord] = {}
        self._by_source_key: dict[str, list[str]] = {}
        self._content_store: ContentStore = content_store if content_store is not None else InMemoryContentStore()
        self._failed_attempts: list[EvidenceRecord] = []

    @property
    def content_store(self) -> ContentStore:
        return self._content_store

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

    def has_record_sha256(self, record_sha256: str) -> bool:
        """Return True iff `record_sha256` equals GENESIS (on empty registry) or an authentic record in `_ledger`."""
        return self.record_index_by_sha256(record_sha256) is not None

    def record_index_by_sha256(self, record_sha256: str) -> int | None:
        """Return 0-based ledger index for `record_sha256` (-1 for empty GENESIS), or None if not in chain."""
        with self._lock:
            if record_sha256 == GENESIS_CHAIN_HASH:
                return -1 if len(self._ledger) == 0 else None
            for idx, rec in enumerate(self._ledger):
                if rec.record_sha256 == record_sha256:
                    return idx
            return None

    def record_index_by_id(self, evidence_id: str) -> int | None:
        """Return 0-based ledger index for `evidence_id`, or None if absent."""
        with self._lock:
            for idx, rec in enumerate(self._ledger):
                if rec.evidence_id == evidence_id:
                    return idx
            return None

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
        allow_older_effective_version: bool = False,
    ) -> EvidenceRecord:
        """Register a content-verified AcquisitionResult and persist its raw bytes into `content_store`."""
        if not isinstance(result, AcquisitionResult):
            raise EvidenceRegistryError("INVALID_ACQUISITION_RESULT", "AcquisitionResult örneği beklenmektedir.")

        rec = _clone_record(result.record)
        if not result.ok or not rec.is_verified_authority:
            with self._lock:
                self._failed_attempts.append(rec)
            raise EvidenceRegistryError(
                "UNREACHABLE_OR_UNVERIFIED_EVIDENCE_REJECTED",
                f"Doğrulanmamış, içerik-eşleşmesiz veya erişilemeyen kaynak ({rec.status}) aktif kanıt "
                f"defterine kaydedilemez: codes={list(rec.error_codes)}",
            )

        if not isinstance(result.raw_bytes, (bytes, bytearray)) or len(result.raw_bytes) == 0:
            raise EvidenceRegistryError(
                "MISSING_RAW_CONTENT_BYTES",
                "SHA-256 bütünlük teyidi ve ham belge arşivi için raw_bytes zorunludur.",
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

            # Persist raw bytes BEFORE appending to ledger so ledger never holds contentless entries
            stored_sha = self._content_store.put(sealed_record.evidence_id, raw_bytes)
            if stored_sha != sealed_record.content_sha256:
                raise EvidenceRegistryError(
                    "CONTENT_STORE_DIGEST_MISMATCH",
                    f"Ham belge deposu özeti uyuşmuyor ({stored_sha} != {sealed_record.content_sha256}).",
                )

            self._ledger.append(sealed_record)
            self._by_id[sealed_record.evidence_id] = sealed_record
            self._by_source_key.setdefault(sealed_record.source_key, []).append(sealed_record.evidence_id)
            return _clone_record(sealed_record)

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        with self._lock:
            rec = self._by_id.get(evidence_id)
            return _clone_record(rec) if rec is not None else None

    def get_raw_bytes(self, evidence_id: str) -> bytes | None:
        with self._lock:
            return self._content_store.get(evidence_id)

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
                exp = (
                    parse_strict_iso_date(ver.expiry_or_repeal_date, "expiry_or_repeal_date")
                    if ver.expiry_or_repeal_date
                    else None
                )
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

    def verify_integrity(self, *, require_raw_content: bool = True) -> tuple[bool, dict[str, Any]]:
        """Re-verify the entire append-only SHA-256 hash chain, version links, metadata digests, AND raw document bytes.

        When `require_raw_content=True` (default), missing raw bytes for ANY record is a fail-closed integrity error.
        """
        errors: list[str] = []
        raw_verified_count = 0
        raw_missing_ids: list[str] = []

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
                if not rec.content_verified or rec.content_verification.get("content_match_status") != CONTENT_MATCH_MATCHED:
                    errors.append(f"ledger[{idx}] ({rec.evidence_id}): içerik-metadata eşleşmesi doğrulanmamış.")
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

                try:
                    raw_b = self._content_store.get(rec.evidence_id)
                except EvidenceRegistryError as cs_exc:
                    raw_b = None
                    errors.append(f"ledger[{idx}] ({rec.evidence_id}): ham belge deposu hatası: {cs_exc.message}")

                if raw_b is None:
                    raw_missing_ids.append(rec.evidence_id)
                    if require_raw_content:
                        errors.append(
                            f"ledger[{idx}] ({rec.evidence_id}): ham belge baytları eksik "
                            "(RAW_CONTENT_UNAVAILABLE_FOR_VERIFICATION)."
                        )
                else:
                    raw_sha = hashlib.sha256(raw_b).hexdigest()
                    if raw_sha != rec.content_sha256 or len(raw_b) != rec.content_bytes_length:
                        errors.append(
                            f"ledger[{idx}] ({rec.evidence_id}): saklanan ham içerik SHA-256 tahrifatı "
                            f"({raw_sha} != {rec.content_sha256})."
                        )
                    else:
                        raw_verified_count += 1

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

            if set(self._by_id.keys()) != seen_ids:
                errors.append("_by_id indeksi ile append-only _ledger tutarsız.")
            for skey, recs in seen_versions.items():
                idx_ids = self._by_source_key.get(skey, [])
                if idx_ids != [r.evidence_id for r in recs]:
                    errors.append(f"_by_source_key[{skey!r}] ile _ledger tutarsız.")

            valid = len(errors) == 0
            full_content_verified = len(raw_missing_ids) == 0 and raw_verified_count == len(self._ledger)
            return valid, {
                "valid": valid,
                "full_content_archive_verified": valid and full_content_verified,
                "require_raw_content": require_raw_content,
                "record_count": len(self._ledger),
                "raw_content_verified_count": raw_verified_count,
                "raw_content_missing_ids": raw_missing_ids,
                "source_key_count": len(seen_versions),
                "failed_attempt_count": len(self._failed_attempts),
                "head_sha256": self._ledger[-1].record_sha256 if self._ledger else GENESIS_CHAIN_HASH,
                "errors": errors,
            }

    def export_snapshot_dict(self, *, include_raw_content: bool = True) -> dict[str, Any]:
        """Export an auditable JSON-serializable snapshot (with Base64 raw document archive by default)."""
        ok, report = self.verify_integrity(require_raw_content=include_raw_content)
        if not ok:
            raise EvidenceRegistryError(
                "EVIDENCE_REGISTRY_INTEGRITY_FAILED",
                f"Bütünlüğü bozulmuş kanıt defteri dışa aktarılamaz: {report['errors']}",
            )
        with self._lock:
            raw_content_b64: dict[str, str] | None = None
            raw_bundle_sha256: str | None = None
            snapshot_mode = SNAPSHOT_MODE_FULL_WITH_RAW if include_raw_content else SNAPSHOT_MODE_METADATA_ONLY

            if include_raw_content:
                raw_content_b64 = {}
                for rec in self._ledger:
                    blob = self._content_store.get(rec.evidence_id)
                    if blob is None:
                        raise EvidenceRegistryError(
                            "RAW_CONTENT_MISSING_FOR_EXPORT",
                            f"Tam arşiv dışa aktarımı için '{rec.evidence_id}' ham baytları eksik.",
                        )
                    raw_content_b64[rec.evidence_id] = base64.b64encode(blob).decode("ascii")
                raw_bundle_sha256 = canonical_sha256(raw_content_b64)

            return {
                "schema_version": "1.0.6-wp2",
                "snapshot_mode": snapshot_mode,
                "head_sha256": report["head_sha256"],
                "record_count": len(self._ledger),
                "records": [rec.to_dict() for rec in self._ledger],
                "raw_content_b64": raw_content_b64,
                "raw_content_bundle_sha256": raw_bundle_sha256,
                "failed_attempts": [fa.to_dict() for fa in self._failed_attempts],
            }

    @classmethod
    def from_snapshot_dict(
        cls,
        snapshot: dict[str, Any],
        *,
        content_store: ContentStore | None = None,
        require_raw_content: bool = True,
    ) -> EvidenceRegistry:
        """Rehydrate an EvidenceRegistry from an exported snapshot, verifying raw bytes fail-closed by default."""
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("records"), list):
            raise EvidenceRegistryError("INVALID_REGISTRY_SNAPSHOT", "Geçersiz EvidenceRegistry anlık görüntüsü.")
        if snapshot.get("schema_version") != "1.0.6-wp2":
            raise EvidenceRegistryError(
                "UNSUPPORTED_SNAPSHOT_SCHEMA_VERSION",
                f"Desteklenmeyen anlık görüntü şema sürümü: {snapshot.get('schema_version')!r}",
            )

        snap_mode = snapshot.get("snapshot_mode")
        if snap_mode not in (SNAPSHOT_MODE_FULL_WITH_RAW, SNAPSHOT_MODE_METADATA_ONLY):
            raise EvidenceRegistryError(
                "INVALID_SNAPSHOT_MODE",
                f"Geçersiz veya eksik snapshot_mode: {snap_mode!r}",
            )

        if snap_mode == SNAPSHOT_MODE_METADATA_ONLY and require_raw_content and content_store is None:
            raise EvidenceRegistryError(
                "RAW_CONTENT_REQUIRED_FOR_METADATA_ONLY_SNAPSHOT",
                "METADATA_ONLY_UNVERIFIED_CONTENT anlık görüntüsü ham belge deposu (content_store) olmadan "
                "require_raw_content=True modunda tam doğrulanmış arşiv olarak yüklenemez.",
            )

        reg = cls(content_store=content_store)
        raw_map = snapshot.get("raw_content_b64")
        if snap_mode == SNAPSHOT_MODE_FULL_WITH_RAW:
            if not isinstance(raw_map, dict):
                raise EvidenceRegistryError(
                    "RAW_CONTENT_MISSING_OR_CORRUPT_IN_SNAPSHOT",
                    "FULL_WITH_RAW_CONTENT anlık görüntüsünde 'raw_content_b64' sözlüğü zorunludur.",
                )
            exp_bundle = snapshot.get("raw_content_bundle_sha256")
            if exp_bundle != canonical_sha256(raw_map):
                raise EvidenceRegistryError(
                    "RAW_CONTENT_BUNDLE_SHA256_MISMATCH",
                    "Anlık görüntüdeki ham belge paket özeti (raw_content_bundle_sha256) uyuşmuyor.",
                )

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
                    content_verified=bool(raw.get("content_verified", False)),
                    content_verification=copy.deepcopy(dict(raw.get("content_verification", {}))),
                    status=str(raw["status"]),
                    adapter_metadata=copy.deepcopy(dict(raw.get("adapter_metadata", {}))),
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

                if isinstance(raw_map, dict) and rec.evidence_id in raw_map:
                    try:
                        decoded = base64.b64decode(raw_map[rec.evidence_id], validate=True)
                    except Exception as b64_exc:
                        raise EvidenceRegistryError(
                            "RAW_CONTENT_MISSING_OR_CORRUPT_IN_SNAPSHOT",
                            f"'{rec.evidence_id}' için Base64 ham belge içeriği bozuk: {b64_exc}",
                        ) from b64_exc
                    if reg._content_store.has(rec.evidence_id):
                        existing = reg._content_store.get(rec.evidence_id)
                        if existing != decoded:
                            raise EvidenceRegistryError(
                                "RAW_CONTENT_STORE_SNAPSHOT_CONFLICT",
                                f"'{rec.evidence_id}' için content_store baytları anlık görüntüdeki ham içerikle uyuşmuyor.",
                            )
                    else:
                        reg._content_store.put(rec.evidence_id, decoded)
        except EvidenceRegistryError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise EvidenceRegistryError("CORRUPT_REGISTRY_SNAPSHOT", f"Bozuk anlık görüntü kaydı: {exc}") from exc

        if snap_mode == SNAPSHOT_MODE_FULL_WITH_RAW and isinstance(raw_map, dict):
            if set(raw_map.keys()) != set(reg._by_id.keys()):
                raise EvidenceRegistryError(
                    "RAW_CONTENT_MISSING_OR_CORRUPT_IN_SNAPSHOT",
                    "FULL_WITH_RAW_CONTENT anlık görüntüsündeki raw_content_b64 anahtarları kayıt listesiyle birebir örtüşmüyor.",
                )

        ok, rep = reg.verify_integrity(require_raw_content=require_raw_content)
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
