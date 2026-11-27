"""WP-4.6 GCP HOLDOUT vault preparation: infrastructure-independent adapters, validators and status.

PREPARATION ONLY. Nothing in this module creates GCP projects, buckets, KMS keys, service accounts or
credentials, and nothing here moves, deletes or rewrites the real HOLDOUT file or Git history.

Status separation that every caller must preserve:

    PREPARATION_COMPLETE  !=  VAULT_PROVISIONED  !=  MIGRATION_VERIFIED

- The repository status file (`governance/holdout_vault_migration_status.json`) records the real
  state: GCP project NOT_CREATED, bucket NOT_PROVISIONED, KMS key NOT_CREATED, region UNDECIDED,
  KVKK review PENDING, migration NOT_STARTED, restore verification NOT_STARTED.
- The HOLDOUT file being absent from a release package or from a working tree is NEVER evidence of
  a completed migration: `derive_migration_state()` ignores file presence entirely.
- Every operation that would need a real GCP connection raises `VaultOperationRefused` with code
  `VAULT_NOT_CONFIGURED` unless a client is explicitly injected (tests inject in-memory mocks that
  operate on synthetic bytes only).
- Every check fails closed: a missing field, an unexpected value, a hash/size/key/location mismatch,
  a missing audit entry, a self-approval or an unverifiable ledger checkpoint refuses the operation.

The real HOLDOUT file is identified only by registry metadata (relative path, SHA-256, Git blob id,
size). This module never opens, reads, hashes or parses it.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any, Protocol

from ..attestation_verifier import canonical_json_bytes, verify_asymmetric_signature
from .holdout_governance import (
    DEFAULT_HOLDOUT_REGISTRY_PATH,
    EVENT_GRANT_REVOKED,
    EVENT_VAULT_READ,
    GOVERNANCE_DIR,
    PROJECT_ROOT,
    HoldoutAccessDenied,
    HoldoutAccessGate,
    HoldoutAccessGrant,
    HoldoutAccessLedger,
    HoldoutLedgerIntegrityError,
    HoldoutVaultRegistry,
    load_holdout_vault_registry,
)
from .models import EvaluationIntegrityError

# ---------------------------------------------------------------------------
# Paths, schemas and pinned historical reference (metadata only)
# ---------------------------------------------------------------------------

DEFAULT_VAULT_MIGRATION_STATUS_PATH = GOVERNANCE_DIR / "holdout_vault_migration_status.json"
DEFAULT_AUDIT_ARCHIVE_MANIFEST_PATH = (
    GOVERNANCE_DIR / "archive" / "HOLDOUT_V1_2_AUDIT_ARCHIVE_MANIFEST_20261127.json"
)
PACKAGE_EXCLUSION_MANIFEST_NAME = "PACKAGE_EXCLUSION_MANIFEST.json"

MIGRATION_STATUS_SCHEMA = "hrai.holdout_vault_migration_status.v1"
PACKAGE_EXCLUSION_SCHEMA = "hrai.release_package_exclusion_manifest.v1"
VAULT_MANIFEST_SCHEMA = "hrai.holdout_vault_migration_manifest.v1"
CHECKPOINT_SCHEMA = "hrai.holdout_ledger_external_checkpoint.v1"

# Historical reference recorded BEFORE this work (archive manifest 2026-11-27 + vault registry).
# These values are pinned; they must never be replaced by a newly computed value.
HISTORICAL_HOLDOUT_VAULT_ID = "HOLDOUT-WP45-V1.2-30-SEALED-20261126"
HISTORICAL_HOLDOUT_FILE_SHA256 = "b809245fa04ee6de2daf4189c115ba03860b1bd54213dfc88b86ce7a1625730f"
HISTORICAL_HOLDOUT_GIT_BLOB_SHA1 = "542fa53d2d86dfebd88207d5231cf876859e6dd2"
HISTORICAL_HOLDOUT_SIZE_BYTES = 78895

# ---------------------------------------------------------------------------
# Status vocabulary
# ---------------------------------------------------------------------------

GCP_PROJECT_NOT_CREATED = "NOT_CREATED"
VAULT_BUCKET_NOT_PROVISIONED = "NOT_PROVISIONED"
KMS_KEY_NOT_CREATED = "NOT_CREATED"
DATA_REGION_UNDECIDED = "UNDECIDED"
KVKK_REVIEW_PENDING = "PENDING"
CUSTODIAN_ROLE_PENDING = "CORPORATE_CLOUD_ADMIN_ROLE_PENDING_NAMED_OWNER"
MIGRATION_NOT_STARTED = "NOT_STARTED"
RESTORE_NOT_STARTED = "NOT_STARTED"
MIGRATION_NOT_VERIFIED = "NOT_VERIFIED"
MIGRATION_VERIFIED = "VERIFIED"
PREPARATION_COMPLETE = "PREPARATION_COMPLETE"
VAULT_PROVISIONED = "VAULT_PROVISIONED"
MIGRATION_VERIFIED_STATE = "MIGRATION_VERIFIED"

# Values that the status file may hold today. "Achieved" values (PROVISIONED, VERIFIED, ...) are
# deliberately absent: recording one requires a reviewed schema change with evidence fields, not a
# JSON edit. The loader therefore rejects any premature success claim.
ALLOWED_STATUS_VALUES: dict[str, frozenset[str]] = {
    "gcp_project": frozenset({GCP_PROJECT_NOT_CREATED}),
    "vault_bucket": frozenset({VAULT_BUCKET_NOT_PROVISIONED}),
    "kms_key": frozenset({KMS_KEY_NOT_CREATED}),
    "data_region": frozenset({DATA_REGION_UNDECIDED}),
    "kvkk_review": frozenset({KVKK_REVIEW_PENDING}),
    "custodian": frozenset({CUSTODIAN_ROLE_PENDING}),
    "vault_migration": frozenset({MIGRATION_NOT_STARTED}),
    "restore_verification": frozenset({RESTORE_NOT_STARTED}),
    "migration_verification": frozenset({MIGRATION_NOT_VERIFIED}),
}
REQUIRED_FALSE_FLAGS: tuple[str, ...] = (
    "holdout_deletion_allowed",
    "git_history_rewrite_allowed",
    "repository_visibility_change_performed",
    "gcp_resources_created_by_this_work",
    "credentials_created_by_this_work",
)

# ---------------------------------------------------------------------------
# Refusal codes
# ---------------------------------------------------------------------------

VAULT_NOT_CONFIGURED = "VAULT_NOT_CONFIGURED"
VAULT_STATUS_INVALID = "VAULT_STATUS_INVALID"
VAULT_REFERENCE_INCONSISTENT = "VAULT_REFERENCE_INCONSISTENT"
VAULT_MANIFEST_INVALID = "VAULT_MANIFEST_INVALID"
VAULT_HASH_MISMATCH = "VAULT_HASH_MISMATCH"
VAULT_BUCKET_POLICY_INVALID = "VAULT_BUCKET_POLICY_INVALID"
VAULT_KMS_KEY_INVALID = "VAULT_KMS_KEY_INVALID"
VAULT_ACCESS_DENIED = "VAULT_ACCESS_DENIED"
VAULT_SEPARATION_OF_DUTIES = "VAULT_SEPARATION_OF_DUTIES_VIOLATION"
VAULT_RESTORE_FAILED = "VAULT_RESTORE_FAILED"
VAULT_AUDIT_LOG_INCOMPLETE = "VAULT_AUDIT_LOG_INCOMPLETE"
VAULT_CHECKPOINT_INVALID = "VAULT_CHECKPOINT_INVALID"
VAULT_DELETION_FORBIDDEN = "VAULT_HOLDOUT_DELETION_FORBIDDEN"
VAULT_HISTORY_REWRITE_FORBIDDEN = "VAULT_GIT_HISTORY_REWRITE_FORBIDDEN"
VAULT_PACKAGE_EXCLUSION_INVALID = "VAULT_PACKAGE_EXCLUSION_INVALID"


class VaultOperationRefused(EvaluationIntegrityError):
    """Raised whenever a vault operation cannot be proven safe (fail-closed)."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _load_json(path: Path, code: str) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise VaultOperationRefused(code, f"{path.name} okunamadı: {exc}") from exc
    if not isinstance(raw, dict):
        raise VaultOperationRefused(code, f"{path.name} JSON nesnesi olmalı.")
    return raw


# ---------------------------------------------------------------------------
# Migration status (repository truth) and derived state
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VaultMigrationStatus:
    statuses: Mapping[str, str]
    flags: Mapping[str, bool]
    package_exclusion: Mapping[str, Any]
    source_path: str
    raw: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)

    def get(self, key: str) -> str:
        return self.statuses[key]

    @property
    def vault_provisioned(self) -> bool:
        return False  # no provisioned value is representable in schema v1

    @property
    def migration_verified(self) -> bool:
        return self.statuses["migration_verification"] == MIGRATION_VERIFIED


def load_vault_migration_status(path: str | Path | None = None) -> VaultMigrationStatus:
    """Strictly load the repository migration status; reject any premature success claim."""
    p = Path(path) if path is not None else DEFAULT_VAULT_MIGRATION_STATUS_PATH
    raw = _load_json(p, VAULT_STATUS_INVALID)
    if raw.get("schema") != MIGRATION_STATUS_SCHEMA:
        raise VaultOperationRefused(VAULT_STATUS_INVALID, f"Durum şeması '{MIGRATION_STATUS_SCHEMA}' olmalı.")
    status = raw.get("status")
    flags = raw.get("safety_flags")
    pkg = raw.get("package_exclusion")
    if not isinstance(status, dict) or not isinstance(flags, dict) or not isinstance(pkg, dict):
        raise VaultOperationRefused(VAULT_STATUS_INVALID, "'status', 'safety_flags', 'package_exclusion' nesne olmalı.")
    statuses: dict[str, str] = {}
    for key, allowed in ALLOWED_STATUS_VALUES.items():
        val = status.get(key)
        if val not in allowed:
            raise VaultOperationRefused(
                VAULT_STATUS_INVALID,
                f"status.{key}='{val}' kabul edilmez (izinli: {sorted(allowed)}). Gerçekleşmemiş bir adım tamamlanmış gösterilemez.",
            )
        statuses[key] = val
    extra = sorted(set(status) - set(ALLOWED_STATUS_VALUES))
    if extra:
        raise VaultOperationRefused(VAULT_STATUS_INVALID, f"Bilinmeyen durum alanları: {extra}.")
    for flag in REQUIRED_FALSE_FLAGS:
        if flags.get(flag) is not False:
            raise VaultOperationRefused(VAULT_STATUS_INVALID, f"safety_flags.{flag} false olmalı.")
    if pkg.get("source") != "holdout_vault_registry.vaults[].file_relpath":
        raise VaultOperationRefused(VAULT_STATUS_INVALID, "package_exclusion.source kayıt defterine bağlı olmalı.")
    if pkg.get("absence_means_migrated") is not False:
        raise VaultOperationRefused(VAULT_STATUS_INVALID, "package_exclusion.absence_means_migrated false olmalı.")
    return VaultMigrationStatus(
        statuses=statuses,
        flags={k: bool(flags[k]) for k in REQUIRED_FALSE_FLAGS},
        package_exclusion=dict(pkg),
        source_path=str(p),
        raw=raw,
    )


def derive_migration_state(status: VaultMigrationStatus, *, local_file_present: bool | None = None) -> str:
    """Migration state comes ONLY from verified vault evidence; local file presence/absence is ignored.

    `local_file_present` is accepted (and deliberately unused) so callers cannot accidentally build
    their own "file missing => migrated" shortcut.
    """
    del local_file_present
    if status.migration_verified and status.statuses["restore_verification"] == MIGRATION_VERIFIED:
        return MIGRATION_VERIFIED
    return MIGRATION_NOT_VERIFIED


def readiness_level(status: VaultMigrationStatus, *, preparation_checks_passed: bool) -> str:
    """Return the highest level actually reached; never collapses the three levels together."""
    if status.migration_verified:
        return MIGRATION_VERIFIED_STATE
    if status.vault_provisioned:
        return VAULT_PROVISIONED
    return PREPARATION_COMPLETE if preparation_checks_passed else "PREPARATION_INCOMPLETE"


@dataclass(frozen=True)
class OperatorApproval:
    """A recorded approval by a named role holder (identity verified outside this module)."""

    approver_id: str
    role: str
    approved_action: str


def _check_two_person_rule(requester_id: str, approvals: Sequence[OperatorApproval], action: str) -> None:
    if not requester_id or not requester_id.strip():
        raise VaultOperationRefused(VAULT_SEPARATION_OF_DUTIES, "Talep eden kimliği zorunludur.")
    relevant = [a for a in approvals if a.approved_action == action]
    ids = [a.approver_id for a in relevant]
    if requester_id in ids:
        raise VaultOperationRefused(VAULT_SEPARATION_OF_DUTIES, "Talep eden kendi talebini onaylayamaz.")
    if len(set(ids)) != len(ids):
        raise VaultOperationRefused(VAULT_SEPARATION_OF_DUTIES, "Aynı onaylayan birden fazla kez sayılamaz.")
    if len(set(ids)) < 2:
        raise VaultOperationRefused(VAULT_SEPARATION_OF_DUTIES, f"'{action}' için iki farklı kişinin onayı gerekir.")
    if len({a.role for a in relevant}) < 2:
        raise VaultOperationRefused(VAULT_SEPARATION_OF_DUTIES, "İki onay farklı rollerden gelmelidir.")


def authorize_holdout_deletion(
    status: VaultMigrationStatus,
    *,
    requester_id: str,
    approvals: Sequence[OperatorApproval] = (),
) -> str:
    """Deletion of the in-repository HOLDOUT file is refused until the vault is VERIFIED.

    Even when all conditions hold this returns only `ELIGIBLE_PENDING_OWNER_DECISION`; the deletion
    itself is a separate, owner-approved repository change and is never performed by code.
    """
    if derive_migration_state(status) != MIGRATION_VERIFIED:
        raise VaultOperationRefused(
            VAULT_DELETION_FORBIDDEN,
            "Harici kasa ve geri yükleme doğrulanmadan HOLDOUT dosyası silinemez (migration NOT_VERIFIED).",
        )
    _check_two_person_rule(requester_id, approvals, "DELETE_IN_REPO_HOLDOUT")
    return "ELIGIBLE_PENDING_OWNER_DECISION"


def authorize_git_history_rewrite(status: VaultMigrationStatus, **_: Any) -> str:
    """Git history rewriting is never authorised by code (separate owner decision + risk report)."""
    if derive_migration_state(status) != MIGRATION_VERIFIED:
        raise VaultOperationRefused(
            VAULT_HISTORY_REWRITE_FORBIDDEN, "Kasa doğrulanmadan Git geçmişi değiştirilemez (migration NOT_VERIFIED)."
        )
    raise VaultOperationRefused(
        VAULT_HISTORY_REWRITE_FORBIDDEN,
        "Git geçmişi yeniden yazımı kod ile yetkilendirilemez; ayrı sahip kararı ve risk değerlendirmesi gerekir.",
    )


# ---------------------------------------------------------------------------
# Historical reference & package exclusion (metadata only; the HOLDOUT file is never read)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HistoricalHoldoutReference:
    vault_id: str
    file_relpath: str
    file_name: str
    file_sha256: str
    git_blob_sha1: str
    size_bytes: int


def load_historical_holdout_reference(
    *,
    registry_path: str | Path | None = None,
    archive_manifest_path: str | Path | None = None,
    vault_id: str = HISTORICAL_HOLDOUT_VAULT_ID,
) -> HistoricalHoldoutReference:
    """Cross-check registry + archive manifest against the pinned historical values (no file read)."""
    registry = load_holdout_vault_registry(registry_path)
    vault = registry.vault(vault_id)
    if vault is None:
        raise VaultOperationRefused(VAULT_REFERENCE_INCONSISTENT, f"{vault_id} kayıt defterinde yok.")
    man_p = Path(archive_manifest_path) if archive_manifest_path is not None else DEFAULT_AUDIT_ARCHIVE_MANIFEST_PATH
    man = _load_json(man_p, VAULT_REFERENCE_INCONSISTENT)
    if man.get("vault_id") != vault_id:
        raise VaultOperationRefused(VAULT_REFERENCE_INCONSISTENT, "Arşiv manifesti farklı bir kasaya ait.")
    file_name = Path(vault.file_relpath).name
    entries = [e for e in man.get("entries", []) if isinstance(e, dict) and e.get("file_name") == file_name]
    if len(entries) != 1:
        raise VaultOperationRefused(VAULT_REFERENCE_INCONSISTENT, "Arşiv manifestinde tek bir kasa dosyası kaydı olmalı.")
    entry = entries[0]
    checks = {
        "registry.file_sha256": (vault.file_sha256, HISTORICAL_HOLDOUT_FILE_SHA256),
        "manifest.sha256": (entry.get("sha256"), HISTORICAL_HOLDOUT_FILE_SHA256),
        "manifest.git_blob_sha1": (entry.get("git_blob_sha1"), HISTORICAL_HOLDOUT_GIT_BLOB_SHA1),
        "manifest.size_bytes": (entry.get("size_bytes"), HISTORICAL_HOLDOUT_SIZE_BYTES),
    }
    if vault_id == HISTORICAL_HOLDOUT_VAULT_ID:
        bad = [k for k, (actual, expected) in checks.items() if actual != expected]
        if bad:
            raise VaultOperationRefused(
                VAULT_REFERENCE_INCONSISTENT, f"Tarihsel referansla tutarsız alanlar: {bad} (SHA-256 ikamesi yasak)."
            )
    if entry.get("sha256") != vault.file_sha256:
        raise VaultOperationRefused(VAULT_REFERENCE_INCONSISTENT, "Manifest ve kayıt defteri SHA-256 değerleri farklı.")
    return HistoricalHoldoutReference(
        vault_id=vault_id,
        file_relpath=vault.file_relpath,
        file_name=file_name,
        file_sha256=vault.file_sha256,
        git_blob_sha1=str(entry.get("git_blob_sha1")),
        size_bytes=int(entry.get("size_bytes")),
    )


def package_exclusion_relpaths(registry: HoldoutVaultRegistry | None = None) -> tuple[str, ...]:
    """Every registered vault file (any status) is excluded from release packages and CI artifacts."""
    reg = registry if registry is not None else load_holdout_vault_registry()
    rels: set[str] = set()
    for v in reg.vaults:
        rel = Path(v.file_relpath)
        if rel.is_absolute() or ".." in rel.parts or not rel.parts:
            raise VaultOperationRefused(VAULT_PACKAGE_EXCLUSION_INVALID, f"Geçersiz kasa yolu: {v.file_relpath!r}.")
        rels.add(rel.as_posix())
    if not rels:
        raise VaultOperationRefused(VAULT_PACKAGE_EXCLUSION_INVALID, "Hariç tutulacak kasa dosyası bulunamadı.")
    return tuple(sorted(rels))


_PACKAGE_SKIP_DIRS = frozenset({"__pycache__", ".pytest_cache", ".git"})
_PACKAGE_SKIP_SUFFIXES = (".pyc", ".pyo")
_PACKAGE_SKIP_NAMES = frozenset({".DS_Store"})


def plan_release_package(project_root: str | Path, excluded_relpaths: Sequence[str]) -> list[str]:
    """Names-only walk of the files a release package would contain (no file content is read)."""
    root = Path(project_root)
    excluded = set(excluded_relpaths)
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _PACKAGE_SKIP_DIRS)
        rel_dir = Path(dirpath).relative_to(root)
        for name in sorted(filenames):
            if name in _PACKAGE_SKIP_NAMES or name.endswith(_PACKAGE_SKIP_SUFFIXES):
                continue
            rel = (rel_dir / name).as_posix()
            if rel not in excluded:
                out.append(rel)
    return sorted(out)


def load_package_exclusion_manifest(project_root: str | Path) -> dict[str, Any] | None:
    """Return the manifest embedded by the release packager, or None when running from the source tree."""
    p = Path(project_root) / PACKAGE_EXCLUSION_MANIFEST_NAME
    if not p.is_file():
        return None
    raw = _load_json(p, VAULT_PACKAGE_EXCLUSION_INVALID)
    if raw.get("schema") != PACKAGE_EXCLUSION_SCHEMA:
        raise VaultOperationRefused(VAULT_PACKAGE_EXCLUSION_INVALID, "Paket hariç tutma manifesti şeması geçersiz.")
    if raw.get("migration_state") != MIGRATION_NOT_VERIFIED or raw.get("absence_means_migrated") is not False:
        raise VaultOperationRefused(
            VAULT_PACKAGE_EXCLUSION_INVALID, "Paket manifesti taşıma tamamlandı iddiası taşıyamaz (NOT_VERIFIED olmalı)."
        )
    return raw


def verify_holdout_git_metadata(
    project_root: str | Path,
    file_relpath: str,
    expected_blob_sha1: str,
    expected_size_bytes: int = HISTORICAL_HOLDOUT_SIZE_BYTES,
) -> dict[str, str]:
    """Verify the committed blob id (Git index) and the on-disk size (stat) via metadata only.

    WP-4.7: runs `git ls-files -s` WITHOUT naming the file (so no Git command is pointed at it and the
    process-wide HOLDOUT guard never sees the path in argv) and filters the index listing in Python.
    `git status` / `git diff` are not used because they may re-hash the working-tree file. The working
    tree copy is checked by `os.stat` size only; this code never opens the file. Returns
    `{"mode": "NO_GIT"}` when no Git work tree is available (e.g. clean package extract).
    """
    root = Path(project_root).resolve()
    git = shutil.which("git")
    if git is None:
        return {"mode": "NO_GIT"}
    try:
        top = subprocess.run(
            [git, "rev-parse", "--show-toplevel"], cwd=root, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"mode": "NO_GIT"}
    if top.returncode != 0 or not top.stdout.strip():
        return {"mode": "NO_GIT"}
    repo_root = Path(top.stdout.strip()).resolve()
    try:
        repo_rel = (root / file_relpath).relative_to(repo_root).as_posix()
    except ValueError:
        return {"mode": "NO_GIT"}
    ls = subprocess.run(
        [git, "ls-files", "-s", "-z"], cwd=repo_root, stdin=subprocess.DEVNULL,
        capture_output=True, timeout=60, check=False,
    )
    if ls.returncode != 0:
        raise VaultOperationRefused(VAULT_REFERENCE_INCONSISTENT, "git ls-files başarısız oldu.")
    blob = None
    for rec in ls.stdout.split(b"\0"):
        meta, sep, name = rec.partition(b"\t")
        if sep and name.decode("utf-8", "replace") == repo_rel:
            parts = meta.split()
            blob = parts[1].decode("ascii") if len(parts) >= 2 else None
            break
    if blob is None:
        raise VaultOperationRefused(VAULT_REFERENCE_INCONSISTENT, "Kasa dosyası Git dizininde izlenmiyor.")
    if blob != expected_blob_sha1:
        raise VaultOperationRefused(
            VAULT_REFERENCE_INCONSISTENT, f"Git blob kimliği tarihsel referansla uyuşmuyor ({blob})."
        )
    try:
        st = os.stat(root / file_relpath)
    except OSError as exc:
        raise VaultOperationRefused(VAULT_REFERENCE_INCONSISTENT, "Kasa dosyası çalışma ağacında yok.") from exc
    if st.st_size != expected_size_bytes:
        raise VaultOperationRefused(VAULT_REFERENCE_INCONSISTENT, "Kasa dosyasının boyutu tarihsel referansla uyuşmuyor.")
    return {"mode": "GIT", "git_blob_sha1": blob, "working_tree": "SIZE_MATCHES_HISTORICAL_REFERENCE"}


# ---------------------------------------------------------------------------
# Injected infrastructure interfaces (implemented later against the real GCP client libraries)
# ---------------------------------------------------------------------------


class ObjectStoreClient(Protocol):
    def get_bucket_metadata(self, bucket: str) -> Mapping[str, Any]: ...

    def upload_file(
        self, bucket: str, object_name: str, local_path: Path, *, kms_key_name: str, metadata: Mapping[str, str]
    ) -> Mapping[str, Any]: ...

    def get_object_metadata(self, bucket: str, object_name: str, generation: str | None = None) -> Mapping[str, Any]: ...

    def download_file(self, bucket: str, object_name: str, generation: str, dest_path: Path) -> None: ...


class KeyManagementClient(Protocol):
    def get_crypto_key(self, key_name: str) -> Mapping[str, Any]: ...


class AuditLogSource(Protocol):
    def list_entries(self, *, bucket: str, object_name: str) -> Sequence[Mapping[str, Any]]: ...


@dataclass(frozen=True)
class GcsVaultConfig:
    """Target configuration. Every field is an institutional decision that has NOT been made yet."""

    project_id: str
    bucket: str
    location: str
    kms_key_name: str
    object_prefix: str = "holdout/"
    min_retention_seconds: int = 0
    require_bucket_lock: bool = True
    allowed_writer_principals: tuple[str, ...] = ()
    allowed_reader_principals: tuple[str, ...] = ()


_KMS_KEY_RE = re.compile(
    r"^projects/(?P<project>[a-z][a-z0-9-]{4,28}[a-z0-9])/locations/(?P<location>[a-z0-9-]+)/"
    r"keyRings/(?P<ring>[A-Za-z0-9_-]{1,63})/cryptoKeys/(?P<key>[A-Za-z0-9_-]{1,63})$"
)
CMEK_ALLOWED_PROTECTION_LEVELS = ("HSM", "SOFTWARE", "EXTERNAL")
SIGNING_ALGORITHM_MAP = {
    "EC_SIGN_ED25519": "ED25519",
    "RSA_SIGN_PSS_3072_SHA256": "RSA-PSS-SHA256",
    "RSA_SIGN_PSS_4096_SHA256": "RSA-PSS-SHA256",
}


def _not_configured(component: str) -> VaultOperationRefused:
    return VaultOperationRefused(
        VAULT_NOT_CONFIGURED,
        f"{component}: GCP projesi oluşturulmadı (NOT_CREATED); gerçek bağlantı yapılandırılmamıştır.",
    )


class CloudKMSKeyProvider:
    """Validates Cloud KMS key *references* (CMEK and checkpoint signing). Never creates keys."""

    def __init__(self, client: KeyManagementClient | None = None) -> None:
        self._client = client

    @staticmethod
    def parse_key_name(key_name: str) -> dict[str, str]:
        m = _KMS_KEY_RE.fullmatch(key_name or "")
        if m is None:
            raise VaultOperationRefused(VAULT_KMS_KEY_INVALID, "KMS anahtar adı projects/*/locations/*/keyRings/*/cryptoKeys/* olmalı.")
        if "/cryptoKeyVersions/" in key_name:
            raise VaultOperationRefused(VAULT_KMS_KEY_INVALID, "CMEK için sürüm değil anahtar adı verilmelidir.")
        return m.groupdict()

    def _get(self, key_name: str) -> Mapping[str, Any]:
        parts = self.parse_key_name(key_name)
        if self._client is None:
            raise _not_configured("CloudKMSKeyProvider")
        meta = self._client.get_crypto_key(key_name)
        if not isinstance(meta, Mapping) or meta.get("name") != key_name:
            raise VaultOperationRefused(VAULT_KMS_KEY_INVALID, "KMS yanıtı istenen anahtarla eşleşmiyor.")
        return {**meta, "_parts": parts}

    def validate_cmek_key(self, key_name: str, *, expected_location: str) -> dict[str, Any]:
        meta = self._get(key_name)
        if meta["_parts"]["location"] != expected_location:
            raise VaultOperationRefused(VAULT_KMS_KEY_INVALID, "KMS anahtar konumu kasa konumuyla aynı olmalı.")
        if meta.get("purpose") != "ENCRYPT_DECRYPT":
            raise VaultOperationRefused(VAULT_KMS_KEY_INVALID, "CMEK anahtarının amacı ENCRYPT_DECRYPT olmalı.")
        if meta.get("primary_state") != "ENABLED":
            raise VaultOperationRefused(VAULT_KMS_KEY_INVALID, "Birincil anahtar sürümü ENABLED değil.")
        if meta.get("protection_level") not in CMEK_ALLOWED_PROTECTION_LEVELS:
            raise VaultOperationRefused(VAULT_KMS_KEY_INVALID, "Geçersiz koruma seviyesi.")
        return {"key_name": key_name, "location": expected_location, "status": "KEY_REFERENCE_VALID"}

    def validate_signing_key(self, key_version_name: str) -> dict[str, Any]:
        base, sep, _ver = (key_version_name or "").partition("/cryptoKeyVersions/")
        if not sep:
            raise VaultOperationRefused(VAULT_KMS_KEY_INVALID, "İmza için anahtar sürümü adı gerekir.")
        self.parse_key_name(base)
        if self._client is None:
            raise _not_configured("CloudKMSKeyProvider")
        meta = self._client.get_crypto_key(key_version_name)
        if meta.get("purpose") != "ASYMMETRIC_SIGN" or meta.get("state") != "ENABLED":
            raise VaultOperationRefused(VAULT_KMS_KEY_INVALID, "İmza anahtarı ASYMMETRIC_SIGN ve ENABLED olmalı.")
        alg = SIGNING_ALGORITHM_MAP.get(str(meta.get("algorithm")))
        if alg is None:
            raise VaultOperationRefused(VAULT_KMS_KEY_INVALID, "Ledger ile uyumsuz imza algoritması.")
        return {"key_version_name": key_version_name, "ledger_algorithm": alg, "status": "SIGNING_KEY_REFERENCE_VALID"}


# ---------------------------------------------------------------------------
# Vault manifest
# ---------------------------------------------------------------------------

VAULT_MANIFEST_ENTRY_KEYS = frozenset({"vault_id", "object_name", "sha256", "size_bytes", "git_blob_sha1", "kms_key_name"})


@dataclass(frozen=True)
class VaultManifestEntry:
    vault_id: str
    object_name: str
    sha256: str
    size_bytes: int
    git_blob_sha1: str
    kms_key_name: str


class VaultManifestValidator:
    """Validates a migration manifest against the pinned historical reference (no substitution)."""

    def __init__(self, reference: HistoricalHoldoutReference) -> None:
        self._ref = reference

    @staticmethod
    def manifest_sha256(manifest: Mapping[str, Any]) -> str:
        body = {k: v for k, v in manifest.items() if k != "manifest_sha256"}
        return _sha256_hex(canonical_json_bytes(body))

    def validate(self, manifest: Mapping[str, Any]) -> tuple[VaultManifestEntry, ...]:
        if not isinstance(manifest, Mapping) or manifest.get("schema") != VAULT_MANIFEST_SCHEMA:
            raise VaultOperationRefused(VAULT_MANIFEST_INVALID, f"Manifest şeması '{VAULT_MANIFEST_SCHEMA}' olmalı.")
        if manifest.get("manifest_sha256") != self.manifest_sha256(manifest):
            raise VaultOperationRefused(VAULT_MANIFEST_INVALID, "manifest_sha256 içerikle uyuşmuyor.")
        raw_entries = manifest.get("entries")
        if not isinstance(raw_entries, list) or len(raw_entries) != 1:
            raise VaultOperationRefused(VAULT_MANIFEST_INVALID, "Manifest tam olarak bir kasa nesnesi içermelidir.")
        out: list[VaultManifestEntry] = []
        for e in raw_entries:
            if not isinstance(e, Mapping) or set(e) != VAULT_MANIFEST_ENTRY_KEYS:
                raise VaultOperationRefused(VAULT_MANIFEST_INVALID, "Manifest girdisi beklenen alanları taşımıyor.")
            if e["vault_id"] != self._ref.vault_id:
                raise VaultOperationRefused(VAULT_MANIFEST_INVALID, "vault_id tarihsel referansla uyuşmuyor.")
            if not _is_sha256(e["sha256"]) or e["sha256"] != self._ref.file_sha256:
                raise VaultOperationRefused(VAULT_HASH_MISMATCH, "Manifest SHA-256 tarihsel referansla uyuşmuyor (ikame yasak).")
            if e["size_bytes"] != self._ref.size_bytes or e["git_blob_sha1"] != self._ref.git_blob_sha1:
                raise VaultOperationRefused(VAULT_HASH_MISMATCH, "Boyut veya Git blob kimliği referansla uyuşmuyor.")
            obj = str(e["object_name"])
            if not obj or obj.startswith("/") or ".." in obj.split("/"):
                raise VaultOperationRefused(VAULT_MANIFEST_INVALID, "Geçersiz nesne adı.")
            CloudKMSKeyProvider.parse_key_name(str(e["kms_key_name"]))
            out.append(VaultManifestEntry(**{k: e[k] for k in VAULT_MANIFEST_ENTRY_KEYS}))
        return tuple(out)


def build_vault_manifest(entries: Sequence[Mapping[str, Any]], *, prepared_by_role: str) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema": VAULT_MANIFEST_SCHEMA,
        "prepared_by_role": prepared_by_role,
        "entries": [dict(e) for e in entries],
    }
    body["manifest_sha256"] = VaultManifestValidator.manifest_sha256(body)
    return body


# ---------------------------------------------------------------------------
# GCS adapter, restore verifier and audit-log validation
# ---------------------------------------------------------------------------


def _file_sha256_and_size(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


@dataclass(frozen=True)
class TransferResult:
    object_name: str
    generation: str
    sha256: str
    size_bytes: int
    status: str  # always UPLOADED_PENDING_RESTORE_VERIFICATION (never VERIFIED)


class GCSHoldoutVaultAdapter:
    """GCS + CMEK vault adapter. Without injected clients and config every operation is NOT_CONFIGURED."""

    def __init__(
        self,
        config: GcsVaultConfig | None = None,
        *,
        store: ObjectStoreClient | None = None,
        kms: CloudKMSKeyProvider | None = None,
        audit: AuditLogSource | None = None,
    ) -> None:
        self._config = config
        self._store = store
        self._kms = kms
        self._audit = audit

    @classmethod
    def from_repository_status(cls, status: VaultMigrationStatus | None = None) -> "GCSHoldoutVaultAdapter":
        """The only adapter the repository can build today: unconfigured (GCP project NOT_CREATED)."""
        st = status or load_vault_migration_status()
        if st.get("gcp_project") == GCP_PROJECT_NOT_CREATED or st.get("data_region") == DATA_REGION_UNDECIDED:
            return cls(None)
        raise VaultOperationRefused(VAULT_STATUS_INVALID, "Beklenmeyen durum.")  # pragma: no cover

    @property
    def configured(self) -> bool:
        return self._config is not None and self._store is not None and self._kms is not None

    def _require(self) -> tuple[GcsVaultConfig, ObjectStoreClient, CloudKMSKeyProvider]:
        if not self.configured:
            raise _not_configured("GCSHoldoutVaultAdapter")
        assert self._config is not None and self._store is not None and self._kms is not None
        if self._config.location in ("", DATA_REGION_UNDECIDED):
            raise VaultOperationRefused(VAULT_NOT_CONFIGURED, "Veri bölgesi UNDECIDED; kasa işlemi yapılamaz.")
        return self._config, self._store, self._kms

    def verify_bucket_policy(self) -> dict[str, Any]:
        cfg, store, kms = self._require()
        meta = store.get_bucket_metadata(cfg.bucket)
        problems: list[str] = []
        if meta.get("location") != cfg.location:
            problems.append("location")
        if meta.get("uniform_bucket_level_access") is not True:
            problems.append("uniform_bucket_level_access")
        if meta.get("public_access_prevention") != "enforced":
            problems.append("public_access_prevention")
        if meta.get("versioning_enabled") is not True:
            problems.append("versioning")
        if meta.get("default_kms_key_name") != cfg.kms_key_name:
            problems.append("default_kms_key_name")
        if int(meta.get("retention_period_seconds") or 0) < max(cfg.min_retention_seconds, 1):
            problems.append("retention_policy")
        if cfg.require_bucket_lock and meta.get("retention_policy_locked") is not True:
            problems.append("bucket_lock")
        if meta.get("all_users_bindings") or meta.get("all_authenticated_users_bindings"):
            problems.append("public_iam_binding")
        if problems:
            raise VaultOperationRefused(VAULT_BUCKET_POLICY_INVALID, f"Kasa politikası eksik/hatalı: {problems}.")
        kms.validate_cmek_key(cfg.kms_key_name, expected_location=cfg.location)
        return {"bucket": cfg.bucket, "status": "BUCKET_POLICY_VALID"}

    def transfer(
        self,
        source_path: str | Path,
        entry: VaultManifestEntry,
        *,
        requester_id: str,
        approvals: Sequence[OperatorApproval],
    ) -> TransferResult:
        """Upload one object after policy, key, hash and two-person checks; verify stored metadata."""
        cfg, store, _kms = self._require()
        _check_two_person_rule(requester_id, approvals, "VAULT_UPLOAD")
        if entry.kms_key_name != cfg.kms_key_name or not entry.object_name.startswith(cfg.object_prefix):
            raise VaultOperationRefused(VAULT_MANIFEST_INVALID, "Manifest girdisi kasa yapılandırmasıyla uyuşmuyor.")
        self.verify_bucket_policy()
        src = Path(source_path)
        if src.is_symlink() or not src.is_file():
            raise VaultOperationRefused(VAULT_HASH_MISMATCH, "Kaynak dosya düzenli bir dosya olmalı.")
        local_sha, local_size = _file_sha256_and_size(src)
        if local_sha != entry.sha256 or local_size != entry.size_bytes:
            raise VaultOperationRefused(VAULT_HASH_MISMATCH, "Kaynak SHA-256/boyut manifestle uyuşmuyor; yükleme yapılmadı.")
        up = store.upload_file(
            cfg.bucket, entry.object_name, src, kms_key_name=cfg.kms_key_name,
            metadata={"sha256": entry.sha256, "vault_id": entry.vault_id, "git_blob_sha1": entry.git_blob_sha1},
        )
        generation = str(up.get("generation") or "")
        if not generation:
            raise VaultOperationRefused(VAULT_HASH_MISMATCH, "Yükleme nesne sürümü (generation) döndürmedi.")
        meta = store.get_object_metadata(cfg.bucket, entry.object_name, generation)
        md = meta.get("metadata") or {}
        if (
            md.get("sha256") != entry.sha256
            or int(meta.get("size") or -1) != entry.size_bytes
            or meta.get("kms_key_name", "").split("/cryptoKeyVersions/")[0] != cfg.kms_key_name
            or str(meta.get("generation")) != generation
        ):
            raise VaultOperationRefused(VAULT_HASH_MISMATCH, "Hedef nesne metadata'sı kaynakla uyuşmuyor.")
        return TransferResult(entry.object_name, generation, entry.sha256, entry.size_bytes, "UPLOADED_PENDING_RESTORE_VERIFICATION")

    def download_generation(self, entry: VaultManifestEntry, generation: str, dest: Path) -> None:
        cfg, store, _kms = self._require()
        store.download_file(cfg.bucket, entry.object_name, generation, dest)

    def verify_audit_trail(self, entry: VaultManifestEntry, *, require_restore_read: bool = True) -> dict[str, Any]:
        """Every data-access log entry must come from an allowed principal; uploads/reads must be present."""
        cfg, _store, _kms = self._require()
        if self._audit is None:
            raise _not_configured("AuditLogSource")
        entries = list(self._audit.list_entries(bucket=cfg.bucket, object_name=entry.object_name))
        writers = set(cfg.allowed_writer_principals)
        readers = set(cfg.allowed_reader_principals)
        unexpected: list[str] = []
        creates = reads = 0
        for e in entries:
            method = str(e.get("method_name"))
            principal = str(e.get("principal"))
            if method == "storage.objects.create":
                creates += 1
                if principal not in writers:
                    unexpected.append(f"{method}:{principal}")
            elif method == "storage.objects.get":
                reads += 1
                if principal not in readers:
                    unexpected.append(f"{method}:{principal}")
            elif method == "storage.objects.delete":
                unexpected.append(f"{method}:{principal}")
        if unexpected:
            raise VaultOperationRefused(VAULT_AUDIT_LOG_INCOMPLETE, f"Yetkisiz veya beklenmeyen erişim kaydı: {unexpected}.")
        if creates < 1 or (require_restore_read and reads < 1):
            raise VaultOperationRefused(VAULT_AUDIT_LOG_INCOMPLETE, "Yükleme/geri yükleme audit kaydı eksik.")
        return {"entries": len(entries), "creates": creates, "reads": reads, "status": "AUDIT_TRAIL_CONSISTENT"}


class VaultRestoreVerifier:
    """Restores one object generation into a temporary directory and compares SHA-256/size (no parsing)."""

    def __init__(self, adapter: GCSHoldoutVaultAdapter, *, project_root: str | Path | None = None) -> None:
        self._adapter = adapter
        self._root = Path(project_root).resolve() if project_root is not None else PROJECT_ROOT

    def verify(self, entry: VaultManifestEntry, generation: str) -> dict[str, Any]:
        if not self._adapter.configured:
            raise _not_configured("VaultRestoreVerifier")
        with tempfile.TemporaryDirectory(prefix="hrai_vault_restore_") as td:
            dest = Path(td) / "restored.bin"
            if str(dest.resolve()).startswith(str(self._root) + os.sep):
                raise VaultOperationRefused(VAULT_RESTORE_FAILED, "Geri yükleme hedefi depo içinde olamaz.")
            self._adapter.download_generation(entry, generation, dest)
            if not dest.is_file():
                raise VaultOperationRefused(VAULT_RESTORE_FAILED, "Geri yüklenen nesne bulunamadı.")
            sha, size = _file_sha256_and_size(dest)
        if sha != entry.sha256 or size != entry.size_bytes:
            raise VaultOperationRefused(VAULT_RESTORE_FAILED, "Geri yüklenen baytlar manifestle uyuşmuyor.")
        return {"object_name": entry.object_name, "generation": generation, "status": "RESTORE_MATCHED_FOR_GENERATION"}


# ---------------------------------------------------------------------------
# Ledger v2 integration: external checkpoint and access grant validation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExternalLedgerCheckpoint:
    ledger_id: str
    seq: int
    head_record_hash: str
    record_count: int
    created_at_utc: str
    signer_key_ref: str
    algorithm: str
    signature_b64: str = ""

    def signing_payload(self) -> dict[str, Any]:
        return {
            "schema": CHECKPOINT_SCHEMA,
            "ledger_id": self.ledger_id,
            "seq": self.seq,
            "head_record_hash": self.head_record_hash,
            "record_count": self.record_count,
            "created_at_utc": self.created_at_utc,
            "signer_key_ref": self.signer_key_ref,
            "algorithm": self.algorithm,
        }


def create_ledger_checkpoint(
    ledger: HoldoutAccessLedger,
    *,
    signer: Callable[[dict[str, Any]], str],
    signer_key_ref: str,
    algorithm: str,
    created_at_utc: str,
) -> ExternalLedgerCheckpoint:
    """Sign the current verified ledger head. `signer` is injected (Cloud KMS asymmetricSign later)."""
    try:
        records = ledger.verify()
    except HoldoutLedgerIntegrityError as exc:
        raise VaultOperationRefused(VAULT_CHECKPOINT_INVALID, str(exc)) from exc
    head = records[-1]
    unsigned = ExternalLedgerCheckpoint(
        ledger_id=head["ledger_id"], seq=head["seq"], head_record_hash=head["record_hash"],
        record_count=len(records), created_at_utc=created_at_utc, signer_key_ref=signer_key_ref, algorithm=algorithm,
    )
    sig = signer(unsigned.signing_payload())
    return ExternalLedgerCheckpoint(**{**unsigned.__dict__, "signature_b64": sig})


def verify_ledger_checkpoint(
    checkpoint: ExternalLedgerCheckpoint,
    ledger: HoldoutAccessLedger,
    *,
    public_key_pem: str,
    previous: ExternalLedgerCheckpoint | None = None,
) -> dict[str, Any]:
    """Signature valid + ledger still contains the checkpointed prefix (append-only) + monotonic seq."""
    ok, why = verify_asymmetric_signature(
        checkpoint.signing_payload(), checkpoint.signature_b64, public_key_pem, checkpoint.algorithm
    )
    if not ok:
        raise VaultOperationRefused(VAULT_CHECKPOINT_INVALID, f"Checkpoint imzası doğrulanamadı ({why}).")
    try:
        records = ledger.verify()
    except HoldoutLedgerIntegrityError as exc:
        raise VaultOperationRefused(VAULT_CHECKPOINT_INVALID, str(exc)) from exc
    if records[0]["ledger_id"] != checkpoint.ledger_id:
        raise VaultOperationRefused(VAULT_CHECKPOINT_INVALID, "Checkpoint farklı bir ledger'a ait.")
    if len(records) < checkpoint.record_count:
        raise VaultOperationRefused(VAULT_CHECKPOINT_INVALID, "Ledger checkpoint'ten kısa (kayıt silinmiş/kesilmiş).")
    anchored = records[checkpoint.record_count - 1]
    if anchored["seq"] != checkpoint.seq or anchored["record_hash"] != checkpoint.head_record_hash:
        raise VaultOperationRefused(VAULT_CHECKPOINT_INVALID, "Ledger checkpoint'teki baş kayıtla uyuşmuyor (yeniden yazım).")
    if previous is not None:
        if previous.ledger_id != checkpoint.ledger_id or checkpoint.seq < previous.seq:
            raise VaultOperationRefused(VAULT_CHECKPOINT_INVALID, "Checkpoint sırası geri gidemez.")
    return {"ledger_id": checkpoint.ledger_id, "seq": checkpoint.seq, "status": "CHECKPOINT_VERIFIED"}


class VaultAccessGrantValidator:
    """Decides whether a Ledger v2 grant may be used to restore an object from the vault."""

    def __init__(self, gate: HoldoutAccessGate) -> None:
        self._gate = gate

    def validate_restore_access(
        self,
        grant: HoldoutAccessGrant,
        *,
        requester_id: str,
        approvals: Sequence[OperatorApproval],
        checkpoint: ExternalLedgerCheckpoint,
        checkpoint_public_key_pem: str,
    ) -> dict[str, Any]:
        if grant.operator_id != requester_id:
            raise VaultOperationRefused(VAULT_ACCESS_DENIED, "Grant başka bir operatöre ait.")
        _check_two_person_rule(requester_id, approvals, "VAULT_RESTORE_READ")
        try:
            led = self._gate._ledger_for_grant(grant)
            registry = self._gate.load_registry()
            self._gate._check_grant_still_valid(led, grant, registry)
            records = led.verify()
        except (HoldoutAccessDenied, HoldoutLedgerIntegrityError) as exc:
            raise VaultOperationRefused(VAULT_ACCESS_DENIED, str(exc)) from exc
        grant_rec = next(r for r in records if r["event_type"] == "ACCESS_GRANTED" and r["grant_id"] == grant.grant_id)
        if grant_rec["custodian_id"] == requester_id:
            raise VaultOperationRefused(VAULT_SEPARATION_OF_DUTIES, "Emanetçi kendi talebine grant veremez.")
        if any(r["grant_id"] == grant.grant_id and r["event_type"] == EVENT_GRANT_REVOKED for r in records):
            raise VaultOperationRefused(VAULT_ACCESS_DENIED, "Grant iptal edilmiş.")
        if any(r["grant_id"] == grant.grant_id and r["event_type"] == EVENT_VAULT_READ for r in records):
            raise VaultOperationRefused(VAULT_ACCESS_DENIED, "Grant ile kasa okuması zaten yapılmış (tek kullanımlık).")
        if grant.access_number > grant.max_authorized_runs:
            raise VaultOperationRefused(VAULT_ACCESS_DENIED, "Erişim sınırı aşılmış.")
        verify_ledger_checkpoint(checkpoint, led, public_key_pem=checkpoint_public_key_pem)
        if checkpoint.seq < grant_rec["seq"]:
            raise VaultOperationRefused(VAULT_CHECKPOINT_INVALID, "Grant kaydı harici checkpoint ile sabitlenmemiş.")
        return {"grant_id": grant.grant_id, "status": "RESTORE_ACCESS_PERMITTED_PENDING_VAULT_READ_RECORD"}

