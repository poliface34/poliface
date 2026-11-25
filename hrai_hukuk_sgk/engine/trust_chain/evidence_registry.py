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


def _require_str(raw: dict[str, Any], key: str, *, allow_none: bool = False) -> str | None:
    val = raw.get(key)
    if val is None and allow_none:
        return None
    if not isinstance(val, str):
        raise ValueError(f"'{key}' alanı metin (str) olmalıdır: {val!r}")
    return val


def _require_int(raw: dict[str, Any], key: str, *, allow_none: bool = False) -> int | None:
    val = raw.get(key)
    if val is None and allow_none:
        return None
    if not isinstance(val, int) or isinstance(val, bool):
        raise ValueError(f"'{key}' alanı tam sayı (int) olmalıdır: {val!r}")
    return val


def _require_bool(raw: dict[str, Any], key: str) -> bool:
    val = raw.get(key)
    if not isinstance(val, bool):
        raise ValueError(f"'{key}' alanı mantıksal (bool) olmalıdır: {val!r}")
    return val


def _require_str_tuple(raw: dict[str, Any], key: str) -> tuple[str, ...]:
    val = raw.get(key)
    if not isinstance(val, (list, tuple)) or not all(isinstance(item, str) for item in val):
        raise ValueError(f"'{key}' alanı metin listesi olmalıdır: {val!r}")
    return tuple(val)


def _require_dict(raw: dict[str, Any], key: str) -> dict[str, Any]:
    val = raw.get(key)
    if not isinstance(val, dict):
        raise ValueError(f"'{key}' alanı sözlük (dict) olmalıdır: {val!r}")
    return copy.deepcopy(val)


def _evidence_record_from_dict(raw: Any, *, error_code: str) -> EvidenceRecord:
    """Strictly reconstruct an `EvidenceRecord` from a snapshot dictionary; fail closed on missing or malformed fields."""
    if not isinstance(raw, dict):
        raise EvidenceRegistryError(error_code, f"Kayıt sözlük (dict) biçiminde olmalıdır: {type(raw).__name__}")
    try:
        evidence_id = _require_str(raw, "evidence_id")
        source_key = _require_str(raw, "source_key")
        adapter_type = _require_str(raw, "adapter_type")
        title = _require_str(raw, "title")
        source_url = _require_str(raw, "source_url")
        final_url = _require_str(raw, "final_url")
        redirect_chain = _require_str_tuple(raw, "redirect_chain")
        acquired_at_utc = _require_str(raw, "acquired_at_utc")
        publication_date = _require_str(raw, "publication_date")
        effective_date = _require_str(raw, "effective_date")
        expiry_or_repeal_date = _require_str(raw, "expiry_or_repeal_date", allow_none=True)
        version_number = _require_int(raw, "version_number")
        supersedes_evidence_id = _require_str(raw, "supersedes_evidence_id", allow_none=True)
        content_sha256 = _require_str(raw, "content_sha256")
        content_bytes_length = _require_int(raw, "content_bytes_length")
        content_type = _require_str(raw, "content_type")
        http_status = _require_int(raw, "http_status", allow_none=True)
        transport_mode = _require_str(raw, "transport_mode")
        live_verified = _require_bool(raw, "live_verified")
        content_verified = _require_bool(raw, "content_verified")
        content_verification = _require_dict(raw, "content_verification")
        status = _require_str(raw, "status")
        adapter_metadata = _require_dict(raw, "adapter_metadata")
        metadata_sha256 = _require_str(raw, "metadata_sha256")
        record_sha256 = _require_str(raw, "record_sha256")
        previous_record_sha256 = _require_str(raw, "previous_record_sha256")
        error_codes = _require_str_tuple(raw, "error_codes")
        errors = _require_str_tuple(raw, "errors")
        legal_boundary_notice = _require_str(raw, "legal_boundary_notice")
    except (KeyError, TypeError, ValueError) as exc:
        raise EvidenceRegistryError(error_code, f"Bozuk veya eksik kanıt/denetim kaydı: {exc}") from exc

    assert evidence_id is not None and source_key is not None and adapter_type is not None
    assert title is not None and source_url is not None and final_url is not None
    assert acquired_at_utc is not None and publication_date is not None and effective_date is not None
    assert version_number is not None and content_sha256 is not None and content_bytes_length is not None
    assert content_type is not None and transport_mode is not None and status is not None
    assert metadata_sha256 is not None and record_sha256 is not None and previous_record_sha256 is not None
    assert legal_boundary_notice is not None

    return EvidenceRecord(
        evidence_id=evidence_id,
        source_key=source_key,
        adapter_type=adapter_type,
        title=title,
        source_url=source_url,
        final_url=final_url,
        redirect_chain=redirect_chain,
        acquired_at_utc=acquired_at_utc,
        publication_date=publication_date,
        effective_date=effective_date,
        expiry_or_repeal_date=expiry_or_repeal_date,
        version_number=version_number,
        supersedes_evidence_id=supersedes_evidence_id,
        content_sha256=content_sha256,
        content_bytes_length=content_bytes_length,
        content_type=content_type,
        http_status=http_status,
        transport_mode=transport_mode,
        live_verified=live_verified,
        content_verified=content_verified,
        content_verification=content_verification,
        status=status,
        adapter_metadata=adapter_metadata,
        metadata_sha256=metadata_sha256,
        record_sha256=record_sha256,
        previous_record_sha256=previous_record_sha256,
        error_codes=error_codes,
        errors=errors,
        legal_boundary_notice=legal_boundary_notice,
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
    def failed_attempts_head_sha256(self) -> str:
        with self._lock:
            return self._failed_attempts[-1].record_sha256 if self._failed_attempts else GENESIS_CHAIN_HASH

    @property
    def failed_attempts_sha256(self) -> str:
        with self._lock:
            return canonical_sha256([fa.to_dict() for fa in self._failed_attempts])

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

    def _append_failed_attempt_locked(self, rec: EvidenceRecord) -> EvidenceRecord:
        """Validate and append a non-verified failure record into the append-only `_failed_attempts` hash chain."""
        if rec.is_verified_authority or rec.status in (STATUS_VERIFIED_LIVE, STATUS_VERIFIED_TEST_TRANSPORT):
            raise EvidenceRegistryError(
                "EXPECTED_FAILED_ATTEMPT",
                "Doğrulanmış kayıt failed_attempts denetim listesine eklenemez.",
            )
        if rec.version_number != 0 or not rec.error_codes:
            raise EvidenceRegistryError(
                "INVALID_FAILED_ATTEMPT_RECORD",
                f"Başarısız edinim kaydı version_number=0 ve en az bir error_code içermelidir: {rec.evidence_id!r}",
            )
        recomp_meta = canonical_sha256(rec.metadata_payload())
        if recomp_meta != rec.metadata_sha256:
            raise EvidenceRegistryError(
                "FAILED_ATTEMPT_METADATA_SHA256_MISMATCH",
                f"Başarısız edinim kaydı metadata_sha256 uyuşmuyor ({recomp_meta} != {rec.metadata_sha256}).",
            )
        recomp_rec = canonical_sha256(rec.chain_payload())
        if recomp_rec != rec.record_sha256:
            raise EvidenceRegistryError(
                "FAILED_ATTEMPT_RECORD_SHA256_MISMATCH",
                f"Başarısız edinim kaydı record_sha256 uyuşmuyor ({recomp_rec} != {rec.record_sha256}).",
            )

        prev_fa_hash = self._failed_attempts[-1].record_sha256 if self._failed_attempts else GENESIS_CHAIN_HASH
        chained = replace(rec, previous_record_sha256=prev_fa_hash)
        sealed = replace(chained, record_sha256=canonical_sha256(chained.chain_payload()))
        self._failed_attempts.append(sealed)
        return _clone_record(sealed)

    def record_failed_attempt(self, result: AcquisitionResult) -> EvidenceRecord:
        """Record a failed or unreachable acquisition attempt strictly in the hash-chained audit trail."""
        if not isinstance(result, AcquisitionResult):
            raise EvidenceRegistryError("INVALID_ACQUISITION_RESULT", "AcquisitionResult örneği beklenmektedir.")
        if result.ok or result.record.is_verified_authority:
            raise EvidenceRegistryError(
                "EXPECTED_FAILED_ATTEMPT",
                "Başarılı doğrulanmış sonuç failed_attempts defterine değil register() ile kaydedilmelidir.",
            )
        with self._lock:
            return self._append_failed_attempt_locked(_clone_record(result.record))

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
                self._append_failed_attempt_locked(rec)
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

            expected_fa_prev = GENESIS_CHAIN_HASH
            for fidx, fa in enumerate(self._failed_attempts):
                if fa.is_verified_authority or fa.status in (STATUS_VERIFIED_LIVE, STATUS_VERIFIED_TEST_TRANSPORT):
                    errors.append(
                        f"failed_attempts[{fidx}] ({fa.evidence_id}): doğrulanmış kayıt failed_attempts "
                        "denetim listesinde bulunamaz."
                    )
                if fa.version_number != 0:
                    errors.append(
                        f"failed_attempts[{fidx}] ({fa.evidence_id}): failed_attempt version_number 0 olmalıdır "
                        f"(bulunan: {fa.version_number})."
                    )
                if not fa.error_codes:
                    errors.append(
                        f"failed_attempts[{fidx}] ({fa.evidence_id}): failed_attempt en az bir error_code içermelidir."
                    )
                if fa.previous_record_sha256 != expected_fa_prev:
                    errors.append(
                        f"failed_attempts[{fidx}] ({fa.evidence_id}): kırık failed_attempts hash zinciri "
                        f"({fa.previous_record_sha256} != {expected_fa_prev})."
                    )
                recomp_fa_meta = canonical_sha256(fa.metadata_payload())
                if recomp_fa_meta != fa.metadata_sha256:
                    errors.append(
                        f"failed_attempts[{fidx}] ({fa.evidence_id}): failed_attempt metadata_sha256 uyuşmazlığı "
                        f"({recomp_fa_meta} != {fa.metadata_sha256})."
                    )
                recomp_fa_rec = canonical_sha256(fa.chain_payload())
                if recomp_fa_rec != fa.record_sha256:
                    errors.append(
                        f"failed_attempts[{fidx}] ({fa.evidence_id}): failed_attempt record_sha256 uyuşmazlığı "
                        f"({recomp_fa_rec} != {fa.record_sha256})."
                    )
                expected_fa_prev = fa.record_sha256

            fa_head = self._failed_attempts[-1].record_sha256 if self._failed_attempts else GENESIS_CHAIN_HASH
            fa_digest = canonical_sha256([fa.to_dict() for fa in self._failed_attempts])

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
                "failed_attempts_head_sha256": fa_head,
                "failed_attempts_sha256": fa_digest,
                "head_sha256": self._ledger[-1].record_sha256 if self._ledger else GENESIS_CHAIN_HASH,
                "errors": errors,
            }

    @staticmethod
    def _compute_snapshot_sha256(
        *,
        schema_version: str,
        snapshot_mode: str,
        head_sha256: str,
        record_count: int,
        records: list[dict[str, Any]],
        raw_content_bundle_sha256: str | None,
        failed_attempt_count: int,
        failed_attempts_head_sha256: str,
        failed_attempts_sha256: str,
    ) -> str:
        return canonical_sha256(
            {
                "schema_version": schema_version,
                "snapshot_mode": snapshot_mode,
                "head_sha256": head_sha256,
                "record_count": record_count,
                "records": records,
                "raw_content_bundle_sha256": raw_content_bundle_sha256,
                "failed_attempt_count": failed_attempt_count,
                "failed_attempts_head_sha256": failed_attempts_head_sha256,
                "failed_attempts_sha256": failed_attempts_sha256,
            }
        )

    def export_snapshot_dict(self, *, include_raw_content: bool = True) -> dict[str, Any]:
        """Export an auditable JSON-serializable snapshot (raw archive + failed_attempts audit trail sealed by SHA-256)."""
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

            records_dicts = [rec.to_dict() for rec in self._ledger]
            failed_dicts = [fa.to_dict() for fa in self._failed_attempts]
            failed_attempts_head = report["failed_attempts_head_sha256"]
            failed_attempts_sha = report["failed_attempts_sha256"]
            snapshot_sha = self._compute_snapshot_sha256(
                schema_version="1.0.6-wp2",
                snapshot_mode=snapshot_mode,
                head_sha256=report["head_sha256"],
                record_count=len(records_dicts),
                records=records_dicts,
                raw_content_bundle_sha256=raw_bundle_sha256,
                failed_attempt_count=len(failed_dicts),
                failed_attempts_head_sha256=failed_attempts_head,
                failed_attempts_sha256=failed_attempts_sha,
            )

            return {
                "schema_version": "1.0.6-wp2",
                "snapshot_mode": snapshot_mode,
                "head_sha256": report["head_sha256"],
                "record_count": len(records_dicts),
                "records": records_dicts,
                "raw_content_b64": raw_content_b64,
                "raw_content_bundle_sha256": raw_bundle_sha256,
                "failed_attempt_count": len(failed_dicts),
                "failed_attempts_head_sha256": failed_attempts_head,
                "failed_attempts_sha256": failed_attempts_sha,
                "failed_attempts": failed_dicts,
                "snapshot_sha256": snapshot_sha,
            }

    @classmethod
    def from_snapshot_dict(
        cls,
        snapshot: dict[str, Any],
        *,
        content_store: ContentStore | None = None,
        require_raw_content: bool = True,
    ) -> EvidenceRegistry:
        """Rehydrate an EvidenceRegistry (records, raw archive & failed_attempts audit trail) fail-closed."""
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

        raw_failed_list = snapshot.get("failed_attempts")
        if not isinstance(raw_failed_list, list):
            raise EvidenceRegistryError(
                "FAILED_ATTEMPTS_MISSING_OR_CORRUPT_IN_SNAPSHOT",
                "Anlık görüntüde 'failed_attempts' denetim listesi zorunludur ve liste biçiminde olmalıdır.",
            )

        reg = cls(content_store=content_store)
        raw_map = snapshot.get("raw_content_b64")
        raw_bundle_sha256: str | None = None
        if snap_mode == SNAPSHOT_MODE_FULL_WITH_RAW:
            if not isinstance(raw_map, dict):
                raise EvidenceRegistryError(
                    "RAW_CONTENT_MISSING_OR_CORRUPT_IN_SNAPSHOT",
                    "FULL_WITH_RAW_CONTENT anlık görüntüsünde 'raw_content_b64' sözlüğü zorunludur.",
                )
            exp_bundle = snapshot.get("raw_content_bundle_sha256")
            actual_bundle = canonical_sha256(raw_map)
            if exp_bundle != actual_bundle:
                raise EvidenceRegistryError(
                    "RAW_CONTENT_BUNDLE_SHA256_MISMATCH",
                    "Anlık görüntüdeki ham belge paket özeti (raw_content_bundle_sha256) uyuşmuyor.",
                )
            raw_bundle_sha256 = actual_bundle
        elif snapshot.get("raw_content_bundle_sha256") is not None:
            raise EvidenceRegistryError(
                "RAW_CONTENT_MISSING_OR_CORRUPT_IN_SNAPSHOT",
                "METADATA_ONLY_UNVERIFIED_CONTENT anlık görüntüsünde raw_content_bundle_sha256 null olmalıdır.",
            )

        for raw in snapshot["records"]:
            rec = _evidence_record_from_dict(raw, error_code="CORRUPT_REGISTRY_SNAPSHOT")
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

        for raw_fa in raw_failed_list:
            fa_rec = _evidence_record_from_dict(raw_fa, error_code="CORRUPT_FAILED_ATTEMPT_RECORD")
            reg._failed_attempts.append(fa_rec)

        if snap_mode == SNAPSHOT_MODE_FULL_WITH_RAW and isinstance(raw_map, dict):
            if set(raw_map.keys()) != set(reg._by_id.keys()):
                raise EvidenceRegistryError(
                    "RAW_CONTENT_MISSING_OR_CORRUPT_IN_SNAPSHOT",
                    "FULL_WITH_RAW_CONTENT anlık görüntüsündeki raw_content_b64 anahtarları kayıt listesiyle birebir örtüşmüyor.",
                )

        declared_fa_count = snapshot.get("failed_attempt_count")
        if (
            not isinstance(declared_fa_count, int)
            or isinstance(declared_fa_count, bool)
            or declared_fa_count != len(reg._failed_attempts)
        ):
            raise EvidenceRegistryError(
                "FAILED_ATTEMPTS_INTEGRITY_FAILED",
                f"Anlık görüntüdeki failed_attempt_count ({declared_fa_count!r}) gerçek kayıt sayısıyla "
                f"({len(reg._failed_attempts)}) uyuşmuyor.",
            )

        actual_fa_sha = canonical_sha256([fa.to_dict() for fa in reg._failed_attempts])
        if snapshot.get("failed_attempts_sha256") != actual_fa_sha:
            raise EvidenceRegistryError(
                "FAILED_ATTEMPTS_INTEGRITY_FAILED",
                "Anlık görüntüdeki failed_attempts_sha256 özeti uyuşmuyor.",
            )

        ok, rep = reg.verify_integrity(require_raw_content=require_raw_content)
        expected_snapshot_sha = cls._compute_snapshot_sha256(
            schema_version="1.0.6-wp2",
            snapshot_mode=snap_mode,
            head_sha256=rep["head_sha256"],
            record_count=len(reg._ledger),
            records=[rec.to_dict() for rec in reg._ledger],
            raw_content_bundle_sha256=raw_bundle_sha256,
            failed_attempt_count=len(reg._failed_attempts),
            failed_attempts_head_sha256=rep["failed_attempts_head_sha256"],
            failed_attempts_sha256=rep["failed_attempts_sha256"],
        )
        if (
            not ok
            or snapshot.get("head_sha256") != rep["head_sha256"]
            or snapshot.get("record_count") != len(reg._ledger)
            or snapshot.get("failed_attempts_head_sha256") != rep["failed_attempts_head_sha256"]
            or snapshot.get("snapshot_sha256") != expected_snapshot_sha
        ):
            raise EvidenceRegistryError(
                "REGISTRY_SNAPSHOT_INTEGRITY_FAILED",
                f"Kanıt defteri anlık görüntüsü bütünlük doğrulamasından geçemedi: {rep['errors']}",
            )
        return reg
