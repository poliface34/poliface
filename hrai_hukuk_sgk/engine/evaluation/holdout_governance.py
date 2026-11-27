"""WP-4.6 HOLDOUT governance: persistent append-only access ledger and fail-closed access gate.

Design goals (WP-4.6, approved scope):

- HOLDOUT case contents never enter the normal CI / unit-test evaluation flow.
- Every HOLDOUT access is authorised by a registered custodian's detached Ed25519 or
  RSA-PSS-SHA256 signature over an RFC 8785 (JCS) canonical access request.
- Every decision (grant, denial, vault read, run start, run completion) is written to a
  persistent, hash-chained, append-only JSONL ledger that lives OUTSIDE the repository.
- Access limits are enforced atomically: the limit check and the ledger append happen under one
  exclusive file lock, so concurrent requests cannot both pass.
- Everything fails closed: missing ledger, broken chain, unknown vault, consumed vault, unknown or
  revoked custodian, bad signature, expired request, replayed request, CI environment, tuning
  purpose and exceeded limits all raise `HoldoutAccessDenied` before any HOLDOUT byte is parsed.

The registry shipped in the repository declares the WP-4.5 v1.2 30-case HOLDOUT vault as
`CONSUMED_BLINDNESS_COMPROMISED` and enrols no custodian, so no grant can be issued for it.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any
import uuid

from ..attestation_verifier import (
    canonical_json_bytes,
    compute_public_key_fingerprint,
    parse_utc_timestamp,
    verify_asymmetric_signature,
)
from .models import EvaluationIntegrityError, canonical_eval_sha256

PROJECT_ROOT = Path(__file__).resolve().parents[2]
GOVERNANCE_DIR = Path(__file__).resolve().parent / "governance"
DEFAULT_HOLDOUT_REGISTRY_PATH = GOVERNANCE_DIR / "holdout_vault_registry.json"
HOLDOUT_LEDGER_PATH_ENV = "HRAI_HOLDOUT_LEDGER_PATH"

REGISTRY_SCHEMA = "hrai.holdout_vault_registry.v1"
LEDGER_SCHEMA = "hrai.holdout_access_ledger.v1"
REQUEST_SCHEMA = "hrai.holdout_access_request.v1"
GENESIS_PREVIOUS_SHA256 = "0" * 64

VAULT_STATUS_SEALED_AVAILABLE = "SEALED_AVAILABLE"
VAULT_STATUS_CONSUMED = "CONSUMED_BLINDNESS_COMPROMISED"
VALID_VAULT_STATUSES: frozenset[str] = frozenset({VAULT_STATUS_SEALED_AVAILABLE, VAULT_STATUS_CONSUMED})

CUSTODIAN_STATUS_ACTIVE = "ACTIVE"
CUSTODIAN_STATUSES: frozenset[str] = frozenset({"ACTIVE", "SUSPENDED", "REVOKED"})
CUSTODIAN_ALGORITHMS: frozenset[str] = frozenset({"ED25519", "RSA-PSS-SHA256"})

PURPOSE_FINAL_BLIND_VERIFICATION = "FINAL_BLIND_VERIFICATION"
PURPOSE_INDEPENDENT_AUDIT = "INDEPENDENT_AUDIT"
ALLOWED_PURPOSES: frozenset[str] = frozenset({PURPOSE_FINAL_BLIND_VERIFICATION, PURPOSE_INDEPENDENT_AUDIT})
FORBIDDEN_PURPOSE_MARKERS: tuple[str, ...] = ("TUNING", "OPTIMIZ", "CALIBRAT", "DEBUG", "TRAIN", "FIX")
MAX_REQUEST_VALIDITY = timedelta(hours=24)

EVENT_GENESIS = "GENESIS"
EVENT_ACCESS_GRANTED = "ACCESS_GRANTED"
EVENT_ACCESS_DENIED = "ACCESS_DENIED"
EVENT_VAULT_READ = "VAULT_READ"
EVENT_RUN_STARTED = "RUN_STARTED"
EVENT_RUN_COMPLETED = "RUN_COMPLETED"
LEDGER_EVENTS: frozenset[str] = frozenset(
    {
        EVENT_GENESIS,
        EVENT_ACCESS_GRANTED,
        EVENT_ACCESS_DENIED,
        EVENT_VAULT_READ,
        EVENT_RUN_STARTED,
        EVENT_RUN_COMPLETED,
    }
)
LEDGER_RECORD_KEYS: frozenset[str] = frozenset(
    {
        "schema",
        "seq",
        "ledger_id",
        "event_type",
        "recorded_at_utc",
        "vault_id",
        "vault_file_sha256",
        "request_id",
        "nonce",
        "grant_id",
        "operator_id",
        "custodian_id",
        "purpose",
        "decision_code",
        "details",
        "previous_record_sha256",
        "record_sha256",
    }
)

CI_ENVIRONMENT_MARKERS: tuple[str, ...] = (
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "BUILDKITE",
    "JENKINS_URL",
    "TF_BUILD",
    "CIRCLECI",
)

# Decision codes (stable identifiers used in the ledger, exceptions and tests).
DENY_CI_ENVIRONMENT = "HOLDOUT_ACCESS_FORBIDDEN_IN_CI"
DENY_LEDGER_NOT_CONFIGURED = "HOLDOUT_LEDGER_NOT_CONFIGURED"
DENY_LEDGER_MISSING = "HOLDOUT_LEDGER_MISSING"
DENY_LEDGER_INSIDE_REPOSITORY = "HOLDOUT_LEDGER_INSIDE_REPOSITORY"
DENY_LEDGER_INTEGRITY = "HOLDOUT_LEDGER_INTEGRITY_FAILURE"
DENY_REGISTRY_INVALID = "HOLDOUT_REGISTRY_INVALID"
DENY_VAULT_UNKNOWN = "HOLDOUT_VAULT_UNKNOWN"
DENY_VAULT_CONSUMED = "HOLDOUT_VAULT_CONSUMED"
DENY_VAULT_HASH_MISMATCH = "HOLDOUT_VAULT_HASH_MISMATCH"
DENY_PURPOSE_FORBIDDEN = "HOLDOUT_PURPOSE_FORBIDDEN"
DENY_CUSTODIAN_UNKNOWN = "HOLDOUT_CUSTODIAN_UNKNOWN"
DENY_CUSTODIAN_INACTIVE = "HOLDOUT_CUSTODIAN_INACTIVE"
DENY_CUSTODIAN_KEY_MISMATCH = "HOLDOUT_CUSTODIAN_KEY_MISMATCH"
DENY_SIGNATURE_INVALID = "HOLDOUT_REQUEST_SIGNATURE_INVALID"
DENY_REQUEST_TIME_INVALID = "HOLDOUT_REQUEST_TIME_INVALID"
DENY_REQUEST_REPLAY = "HOLDOUT_REQUEST_REPLAY"
DENY_LIMIT_EXCEEDED = "HOLDOUT_ACCESS_LIMIT_EXCEEDED"
DENY_NO_GRANT = "HOLDOUT_ACCESS_DENIED_NO_GRANT"
DENY_GRANT_INVALID = "HOLDOUT_GRANT_INVALID"
DENY_GRANT_ALREADY_USED = "HOLDOUT_GRANT_ALREADY_USED"
DENY_CASE_SET_MISMATCH = "HOLDOUT_CASE_SET_MISMATCH"
DENY_NON_BLIND = "HOLDOUT_NON_BLIND_EVALUATION_FORBIDDEN"
GRANTED = "HOLDOUT_ACCESS_GRANTED"


class HoldoutAccessDenied(EvaluationIntegrityError):
    """Raised when any HOLDOUT access control check fails (fail-closed)."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class HoldoutLedgerIntegrityError(EvaluationIntegrityError):
    """Raised when the persistent HOLDOUT access ledger fails hash-chain or format verification."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _fmt_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file_bytes(path: str | Path) -> str:
    """SHA-256 of raw file bytes (never parses content)."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def compute_holdout_case_set_sha256(cases: Sequence[Any]) -> str:
    """Canonical SHA-256 of a HOLDOUT case set, order-independent (sorted by case_id)."""
    ordered = sorted(cases, key=lambda c: c.case_id)
    return canonical_eval_sha256([c.to_dict() for c in ordered])


def detect_ci_environment(environment: Mapping[str, str] | None = None) -> str | None:
    """Return the name of the first CI marker variable set to a truthy value, else None."""
    env = os.environ if environment is None else environment
    for key in CI_ENVIRONMENT_MARKERS:
        val = str(env.get(key, "") or "").strip().lower()
        if val and val not in {"0", "false", "no", "off"}:
            return key
    return None


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _repository_root(project_root: Path) -> Path:
    """The git work tree containing the project (falls back to the project's parent)."""
    for cand in (project_root, *project_root.parents):
        if (cand / ".git").exists():
            return cand
    return project_root.parent


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HoldoutCustodianRecord:
    custodian_id: str
    custodian_role: str
    identity_verification_ref: str
    key_id: str
    algorithm: str
    public_key_pem: str
    public_key_fingerprint_sha256: str
    valid_from_utc: str
    valid_until_utc: str
    status: str = CUSTODIAN_STATUS_ACTIVE


@dataclass(frozen=True)
class HoldoutVaultRecord:
    vault_id: str
    dataset_version: str
    file_relpath: str
    file_sha256: str
    case_set_sha256: str
    case_count: int
    status: str
    max_authorized_runs: int


@dataclass(frozen=True)
class HoldoutVaultRegistry:
    registry_version: str
    vaults: tuple[HoldoutVaultRecord, ...]
    custodians: tuple[HoldoutCustodianRecord, ...]
    source_path: str
    raw: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)

    def vault(self, vault_id: str) -> HoldoutVaultRecord | None:
        return next((v for v in self.vaults if v.vault_id == vault_id), None)

    def vault_by_file_sha256(self, file_sha256: str) -> HoldoutVaultRecord | None:
        return next((v for v in self.vaults if v.file_sha256 == file_sha256), None)

    def custodian(self, custodian_id: str) -> HoldoutCustodianRecord | None:
        return next((c for c in self.custodians if c.custodian_id == custodian_id), None)


def _req_str(d: Mapping[str, Any], key: str, ctx: str) -> str:
    val = d.get(key)
    if not isinstance(val, str) or not val.strip():
        raise HoldoutAccessDenied(DENY_REGISTRY_INVALID, f"{ctx}: '{key}' zorunlu ve boş olmayan metin olmalı.")
    return val


def _req_sha(d: Mapping[str, Any], key: str, ctx: str) -> str:
    val = _req_str(d, key, ctx)
    if len(val) != 64 or any(ch not in "0123456789abcdef" for ch in val):
        raise HoldoutAccessDenied(DENY_REGISTRY_INVALID, f"{ctx}: '{key}' 64 karakter küçük harf hex SHA-256 olmalı.")
    return val


def load_holdout_vault_registry(path: str | Path | None = None) -> HoldoutVaultRegistry:
    """Strictly load the HOLDOUT vault & custodian registry (fail-closed on any schema deviation)."""
    p = Path(path) if path is not None else DEFAULT_HOLDOUT_REGISTRY_PATH
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HoldoutAccessDenied(DENY_REGISTRY_INVALID, f"Kayıt defteri okunamadı ({p.name}): {exc}") from exc
    if not isinstance(raw, dict) or raw.get("schema") != REGISTRY_SCHEMA:
        raise HoldoutAccessDenied(DENY_REGISTRY_INVALID, f"Kayıt defteri şeması '{REGISTRY_SCHEMA}' olmalı.")
    reg_ver = _req_str(raw, "registry_version", "registry")
    vaults_raw = raw.get("vaults")
    custodians_raw = raw.get("custodians")
    if not isinstance(vaults_raw, list) or not isinstance(custodians_raw, list):
        raise HoldoutAccessDenied(DENY_REGISTRY_INVALID, "'vaults' ve 'custodians' liste olmalı.")

    vaults: list[HoldoutVaultRecord] = []
    seen_vault_ids: set[str] = set()
    for i, v in enumerate(vaults_raw):
        if not isinstance(v, dict):
            raise HoldoutAccessDenied(DENY_REGISTRY_INVALID, f"vaults[{i}] nesne olmalı.")
        ctx = f"vaults[{i}]"
        vid = _req_str(v, "vault_id", ctx)
        if vid in seen_vault_ids:
            raise HoldoutAccessDenied(DENY_REGISTRY_INVALID, f"Yinelenen vault_id: {vid}.")
        seen_vault_ids.add(vid)
        status = _req_str(v, "status", ctx)
        if status not in VALID_VAULT_STATUSES:
            raise HoldoutAccessDenied(DENY_REGISTRY_INVALID, f"{ctx}: geçersiz status '{status}'.")
        max_runs = v.get("max_authorized_runs")
        count = v.get("case_count")
        if not isinstance(max_runs, int) or isinstance(max_runs, bool) or max_runs < 0:
            raise HoldoutAccessDenied(DENY_REGISTRY_INVALID, f"{ctx}: max_authorized_runs >= 0 tamsayı olmalı.")
        if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
            raise HoldoutAccessDenied(DENY_REGISTRY_INVALID, f"{ctx}: case_count > 0 tamsayı olmalı.")
        if status == VAULT_STATUS_CONSUMED and max_runs != 0:
            raise HoldoutAccessDenied(DENY_REGISTRY_INVALID, f"{ctx}: tüketilmiş kasada max_authorized_runs 0 olmalı.")
        vaults.append(
            HoldoutVaultRecord(
                vault_id=vid,
                dataset_version=_req_str(v, "dataset_version", ctx),
                file_relpath=_req_str(v, "file_relpath", ctx),
                file_sha256=_req_sha(v, "file_sha256", ctx),
                case_set_sha256=_req_sha(v, "case_set_sha256", ctx),
                case_count=count,
                status=status,
                max_authorized_runs=max_runs,
            )
        )

    custodians: list[HoldoutCustodianRecord] = []
    seen_cust: set[str] = set()
    for i, c in enumerate(custodians_raw):
        if not isinstance(c, dict):
            raise HoldoutAccessDenied(DENY_REGISTRY_INVALID, f"custodians[{i}] nesne olmalı.")
        ctx = f"custodians[{i}]"
        cid = _req_str(c, "custodian_id", ctx)
        if cid in seen_cust:
            raise HoldoutAccessDenied(DENY_REGISTRY_INVALID, f"Yinelenen custodian_id: {cid}.")
        seen_cust.add(cid)
        alg = _req_str(c, "algorithm", ctx).upper()
        if alg not in CUSTODIAN_ALGORITHMS:
            raise HoldoutAccessDenied(DENY_REGISTRY_INVALID, f"{ctx}: desteklenmeyen algoritma '{alg}'.")
        status = _req_str(c, "status", ctx)
        if status not in CUSTODIAN_STATUSES:
            raise HoldoutAccessDenied(DENY_REGISTRY_INVALID, f"{ctx}: geçersiz status '{status}'.")
        pem = _req_str(c, "public_key_pem", ctx)
        fp = _req_sha(c, "public_key_fingerprint_sha256", ctx)
        if compute_public_key_fingerprint(pem) != fp:
            raise HoldoutAccessDenied(DENY_REGISTRY_INVALID, f"{ctx}: açık anahtar parmak izi uyuşmuyor.")
        custodians.append(
            HoldoutCustodianRecord(
                custodian_id=cid,
                custodian_role=_req_str(c, "custodian_role", ctx),
                identity_verification_ref=_req_str(c, "identity_verification_ref", ctx),
                key_id=_req_str(c, "key_id", ctx),
                algorithm=alg,
                public_key_pem=pem,
                public_key_fingerprint_sha256=fp,
                valid_from_utc=_req_str(c, "valid_from_utc", ctx),
                valid_until_utc=_req_str(c, "valid_until_utc", ctx),
                status=status,
            )
        )
    return HoldoutVaultRegistry(
        registry_version=reg_ver,
        vaults=tuple(vaults),
        custodians=tuple(custodians),
        source_path=str(p),
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Persistent append-only ledger
# ---------------------------------------------------------------------------


@contextmanager
def _exclusive_file_lock(lock_path: Path) -> Iterator[None]:
    """Cross-process exclusive lock (fcntl on POSIX, msvcrt on Windows)."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if os.name == "nt":  # pragma: no cover - exercised on Windows only
            import msvcrt
            import time as _time

            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
            os.lseek(fd, 0, os.SEEK_SET)
            deadline = _time.monotonic() + 60.0
            while True:
                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if _time.monotonic() > deadline:
                        raise
                    _time.sleep(0.05)
            try:
                yield
            finally:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _record_sha256(record_without_hash: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(dict(record_without_hash))).hexdigest()


def _clean_details(details: Mapping[str, Any] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in (details or {}).items():
        out[str(k)] = "" if v is None else str(v)
    return out


class HoldoutAccessLedger:
    """Persistent, hash-chained, append-only JSONL ledger for HOLDOUT access decisions.

    - One canonical (RFC 8785) JSON record per line, newline-terminated.
    - `record_sha256` = SHA-256 over the canonical record without `record_sha256`.
    - `previous_record_sha256` links to the prior record; the first record is GENESIS.
    - Every append re-verifies the whole chain under an exclusive lock and fsyncs the file.
    - No API exists to modify or delete records; any out-of-band edit breaks verification.
    """

    def __init__(self, *, ledger_path: str | Path) -> None:
        if ledger_path is None or not str(ledger_path).strip():
            raise HoldoutAccessDenied(DENY_LEDGER_NOT_CONFIGURED, "Kalıcı HOLDOUT ledger yolu zorunludur.")
        self._path = Path(ledger_path)
        self._lock_path = self._path.with_name(self._path.name + ".lock")

    @property
    def path(self) -> Path:
        return self._path

    @classmethod
    def initialize(
        cls,
        *,
        ledger_path: str | Path,
        ledger_id: str,
        created_by: str,
        recorded_at_utc: str | None = None,
    ) -> "HoldoutAccessLedger":
        """Create a NEW ledger containing only a GENESIS record. Refuses to touch an existing file."""
        if not str(ledger_id or "").strip() or not str(created_by or "").strip():
            raise HoldoutLedgerIntegrityError("Ledger başlatma için ledger_id ve created_by zorunludur.")
        led = cls(ledger_path=ledger_path)
        led._path.parent.mkdir(parents=True, exist_ok=True)
        body = {
            "schema": LEDGER_SCHEMA,
            "seq": 0,
            "ledger_id": ledger_id,
            "event_type": EVENT_GENESIS,
            "recorded_at_utc": recorded_at_utc or _fmt_utc(_utc_now()),
            "vault_id": None,
            "vault_file_sha256": None,
            "request_id": None,
            "nonce": None,
            "grant_id": None,
            "operator_id": created_by,
            "custodian_id": None,
            "purpose": None,
            "decision_code": "LEDGER_INITIALIZED",
            "details": {},
            "previous_record_sha256": GENESIS_PREVIOUS_SHA256,
        }
        record = {**body, "record_sha256": _record_sha256(body)}
        line = canonical_json_bytes(record) + b"\n"
        with _exclusive_file_lock(led._lock_path):
            try:
                fd = os.open(str(led._path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError as exc:
                raise HoldoutLedgerIntegrityError(
                    f"Ledger zaten mevcut; mevcut kayıtların üzerine yazılamaz ({led._path.name})."
                ) from exc
            try:
                os.write(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)
        return led

    def exists(self) -> bool:
        return self._path.is_file()

    def _read_verified(self) -> list[dict[str, Any]]:
        if not self._path.is_file():
            raise HoldoutAccessDenied(DENY_LEDGER_MISSING, f"HOLDOUT ledger bulunamadı: {self._path.name}.")
        data = self._path.read_bytes()
        if not data:
            raise HoldoutLedgerIntegrityError("Ledger boş; GENESIS kaydı yok.")
        if not data.endswith(b"\n"):
            raise HoldoutLedgerIntegrityError("Ledger son satırı tamamlanmamış (kesilmiş yazım veya tahrifat).")
        records: list[dict[str, Any]] = []
        prev = GENESIS_PREVIOUS_SHA256
        ledger_id: str | None = None
        for idx, line in enumerate(data[:-1].split(b"\n")):
            try:
                rec = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise HoldoutLedgerIntegrityError(f"Ledger satır {idx}: geçersiz JSON.") from exc
            if not isinstance(rec, dict) or set(rec.keys()) != LEDGER_RECORD_KEYS:
                raise HoldoutLedgerIntegrityError(f"Ledger satır {idx}: alan kümesi şemayla uyuşmuyor.")
            if canonical_json_bytes(rec) != line:
                raise HoldoutLedgerIntegrityError(f"Ledger satır {idx}: kanonik (RFC 8785) biçimde değil.")
            if rec["schema"] != LEDGER_SCHEMA:
                raise HoldoutLedgerIntegrityError(f"Ledger satır {idx}: şema '{LEDGER_SCHEMA}' olmalı.")
            if rec["seq"] != idx:
                raise HoldoutLedgerIntegrityError(f"Ledger satır {idx}: sıra numarası kopuk (seq={rec['seq']}).")
            if rec["event_type"] not in LEDGER_EVENTS:
                raise HoldoutLedgerIntegrityError(f"Ledger satır {idx}: bilinmeyen olay '{rec['event_type']}'.")
            if (idx == 0) != (rec["event_type"] == EVENT_GENESIS):
                raise HoldoutLedgerIntegrityError(f"Ledger satır {idx}: GENESIS yalnızca ilk kayıt olabilir.")
            if rec["previous_record_sha256"] != prev:
                raise HoldoutLedgerIntegrityError(f"Ledger satır {idx}: önceki kayıt özeti zinciri kopuk.")
            body = {k: v for k, v in rec.items() if k != "record_sha256"}
            if _record_sha256(body) != rec["record_sha256"]:
                raise HoldoutLedgerIntegrityError(f"Ledger satır {idx}: record_sha256 uyuşmuyor (tahrifat).")
            if ledger_id is None:
                ledger_id = rec["ledger_id"]
            elif rec["ledger_id"] != ledger_id:
                raise HoldoutLedgerIntegrityError(f"Ledger satır {idx}: ledger_id değişmiş.")
            if not isinstance(rec["details"], dict):
                raise HoldoutLedgerIntegrityError(f"Ledger satır {idx}: details nesne olmalı.")
            prev = rec["record_sha256"]
            records.append(rec)
        return records

    def verify(self) -> tuple[dict[str, Any], ...]:
        """Verify the full chain (read-only) and return all records."""
        with _exclusive_file_lock(self._lock_path):
            return tuple(self._read_verified())

    def head(self) -> tuple[int, str]:
        recs = self.verify()
        return recs[-1]["seq"], recs[-1]["record_sha256"]

    def _append_locked(
        self,
        records: list[dict[str, Any]],
        *,
        event_type: str,
        decision_code: str,
        recorded_at_utc: str,
        vault_id: str | None = None,
        vault_file_sha256: str | None = None,
        request_id: str | None = None,
        nonce: str | None = None,
        grant_id: str | None = None,
        operator_id: str | None = None,
        custodian_id: str | None = None,
        purpose: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if event_type not in LEDGER_EVENTS or event_type == EVENT_GENESIS:
            raise HoldoutLedgerIntegrityError(f"Eklenemeyen olay türü: {event_type}.")
        last = records[-1]
        body = {
            "schema": LEDGER_SCHEMA,
            "seq": last["seq"] + 1,
            "ledger_id": last["ledger_id"],
            "event_type": event_type,
            "recorded_at_utc": recorded_at_utc,
            "vault_id": vault_id,
            "vault_file_sha256": vault_file_sha256,
            "request_id": request_id,
            "nonce": nonce,
            "grant_id": grant_id,
            "operator_id": operator_id,
            "custodian_id": custodian_id,
            "purpose": purpose,
            "decision_code": decision_code,
            "details": _clean_details(details),
            "previous_record_sha256": last["record_sha256"],
        }
        record = {**body, "record_sha256": _record_sha256(body)}
        line = canonical_json_bytes(record) + b"\n"
        fd = os.open(str(self._path), os.O_WRONLY | os.O_APPEND)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
        records.append(record)
        return record

    def append_event(self, *, event_type: str, decision_code: str, recorded_at_utc: str, **fields: Any) -> dict[str, Any]:
        """Append one audit event after verifying the chain (used for denials)."""
        with _exclusive_file_lock(self._lock_path):
            records = self._read_verified()
            return self._append_locked(
                records,
                event_type=event_type,
                decision_code=decision_code,
                recorded_at_utc=recorded_at_utc,
                **fields,
            )

    def reserve_grant(
        self,
        *,
        vault: HoldoutVaultRecord,
        request: "HoldoutAccessRequest",
        recorded_at_utc: str,
    ) -> tuple[dict[str, Any], int]:
        """Atomically check replay + access limit and append ACCESS_GRANTED (or ACCESS_DENIED)."""
        with _exclusive_file_lock(self._lock_path):
            records = self._read_verified()
            common = dict(
                vault_id=vault.vault_id,
                vault_file_sha256=vault.file_sha256,
                request_id=request.request_id,
                nonce=request.nonce,
                operator_id=request.operator_id,
                custodian_id=request.custodian_id,
                purpose=request.purpose,
            )
            if any(r["request_id"] == request.request_id or r["nonce"] == request.nonce for r in records[1:]):
                self._append_locked(
                    records,
                    event_type=EVENT_ACCESS_DENIED,
                    decision_code=DENY_REQUEST_REPLAY,
                    recorded_at_utc=recorded_at_utc,
                    **{**common, "request_id": f"REPLAY::{request.request_id}", "nonce": f"REPLAY::{request.nonce}"},
                )
                raise HoldoutAccessDenied(DENY_REQUEST_REPLAY, "Aynı request_id veya nonce daha önce kullanıldı.")
            granted_before = sum(
                1
                for r in records
                if r["event_type"] == EVENT_ACCESS_GRANTED and r["vault_file_sha256"] == vault.file_sha256
            )
            if granted_before >= vault.max_authorized_runs:
                self._append_locked(
                    records,
                    event_type=EVENT_ACCESS_DENIED,
                    decision_code=DENY_LIMIT_EXCEEDED,
                    recorded_at_utc=recorded_at_utc,
                    details={"granted_before": granted_before, "max_authorized_runs": vault.max_authorized_runs},
                    **common,
                )
                raise HoldoutAccessDenied(
                    DENY_LIMIT_EXCEEDED,
                    f"Kasa erişim sınırı doldu ({granted_before}/{vault.max_authorized_runs}).",
                )
            grant_id = f"GRANT-{uuid.uuid4().hex[:20].upper()}"
            rec = self._append_locked(
                records,
                event_type=EVENT_ACCESS_GRANTED,
                decision_code=GRANTED,
                recorded_at_utc=recorded_at_utc,
                grant_id=grant_id,
                details={
                    "access_number": granted_before + 1,
                    "max_authorized_runs": vault.max_authorized_runs,
                    "case_set_sha256": vault.case_set_sha256,
                    "dataset_version": vault.dataset_version,
                    "request_signature_sha256": hashlib.sha256(request.signature_b64.encode("ascii")).hexdigest(),
                },
                **common,
            )
            return rec, granted_before + 1

    def claim_grant_event(
        self,
        grant: "HoldoutAccessGrant",
        *,
        event_type: str,
        recorded_at_utc: str,
        details: Mapping[str, Any] | None = None,
        require_prior_event: str | None = None,
    ) -> dict[str, Any]:
        """Atomically verify a grant against the ledger and append a single-use event for it."""
        with _exclusive_file_lock(self._lock_path):
            records = self._read_verified()
            grant_rec = _find_grant_record(records, grant)
            if any(r["grant_id"] == grant.grant_id and r["event_type"] == event_type for r in records):
                raise HoldoutAccessDenied(DENY_GRANT_ALREADY_USED, f"{grant.grant_id} için {event_type} zaten kayıtlı.")
            if require_prior_event is not None and not any(
                r["grant_id"] == grant.grant_id and r["event_type"] == require_prior_event for r in records
            ):
                raise HoldoutAccessDenied(DENY_GRANT_INVALID, f"{event_type} öncesinde {require_prior_event} kaydı yok.")
            return self._append_locked(
                records,
                event_type=event_type,
                decision_code=event_type,
                recorded_at_utc=recorded_at_utc,
                vault_id=grant_rec["vault_id"],
                vault_file_sha256=grant_rec["vault_file_sha256"],
                grant_id=grant.grant_id,
                operator_id=grant_rec["operator_id"],
                custodian_id=grant_rec["custodian_id"],
                purpose=grant_rec["purpose"],
                details=details,
            )


def _find_grant_record(records: Sequence[Mapping[str, Any]], grant: "HoldoutAccessGrant") -> Mapping[str, Any]:
    rec = next(
        (r for r in records if r["event_type"] == EVENT_ACCESS_GRANTED and r["grant_id"] == grant.grant_id),
        None,
    )
    if rec is None:
        raise HoldoutAccessDenied(DENY_GRANT_INVALID, f"{grant.grant_id} ledger'da ACCESS_GRANTED olarak yok.")
    expected = {
        "record_sha256": grant.grant_record_sha256,
        "vault_id": grant.vault_id,
        "vault_file_sha256": grant.vault_file_sha256,
        "ledger_id": grant.ledger_id,
    }
    for k, v in expected.items():
        if rec[k] != v:
            raise HoldoutAccessDenied(DENY_GRANT_INVALID, f"Grant alanı ledger ile uyuşmuyor: {k}.")
    if rec["details"].get("case_set_sha256") != grant.case_set_sha256:
        raise HoldoutAccessDenied(DENY_GRANT_INVALID, "Grant case_set_sha256 ledger ile uyuşmuyor.")
    return rec


# ---------------------------------------------------------------------------
# Requests, grants and the gate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HoldoutAccessRequest:
    request_id: str
    vault_id: str
    vault_file_sha256: str
    purpose: str
    operator_id: str
    custodian_id: str
    key_id: str
    algorithm: str
    requested_at_utc: str
    expires_at_utc: str
    nonce: str
    signature_b64: str = ""

    def signing_payload(self) -> dict[str, Any]:
        return {
            "schema": REQUEST_SCHEMA,
            "request_id": self.request_id,
            "vault_id": self.vault_id,
            "vault_file_sha256": self.vault_file_sha256,
            "purpose": self.purpose,
            "operator_id": self.operator_id,
            "custodian_id": self.custodian_id,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "requested_at_utc": self.requested_at_utc,
            "expires_at_utc": self.expires_at_utc,
            "nonce": self.nonce,
        }


@dataclass(frozen=True)
class HoldoutAccessGrant:
    grant_id: str
    vault_id: str
    vault_file_sha256: str
    case_set_sha256: str
    dataset_version: str
    ledger_path: str
    ledger_id: str
    grant_record_sha256: str
    operator_id: str
    purpose: str
    access_number: int
    max_authorized_runs: int


class HoldoutAccessGate:
    """Fail-closed authorisation gate in front of every HOLDOUT read and evaluation."""

    def __init__(
        self,
        *,
        registry_path: str | Path | None = None,
        ledger_path: str | Path | None = None,
        project_root: str | Path | None = None,
        environment: Mapping[str, str] | None = None,
        clock: Any = None,
    ) -> None:
        self._env = dict(os.environ) if environment is None else dict(environment)
        self._registry_path = Path(registry_path) if registry_path is not None else DEFAULT_HOLDOUT_REGISTRY_PATH
        led = ledger_path if ledger_path is not None else self._env.get(HOLDOUT_LEDGER_PATH_ENV)
        self._ledger_path = Path(led) if led else None
        self._root = Path(project_root).resolve() if project_root is not None else PROJECT_ROOT
        self._clock = clock or _utc_now

    def _now(self) -> datetime:
        return self._clock()

    def _ledger(self, *, record_denials: bool = False) -> HoldoutAccessLedger:
        if self._ledger_path is None:
            raise HoldoutAccessDenied(
                DENY_LEDGER_NOT_CONFIGURED,
                f"Kalıcı ledger yolu verilmedi ({HOLDOUT_LEDGER_PATH_ENV}); bellek içi ledger yasaktır.",
            )
        repo_root = _repository_root(self._root)
        if _is_within(self._ledger_path, repo_root) or _is_within(self._ledger_path, self._root):
            raise HoldoutAccessDenied(
                DENY_LEDGER_INSIDE_REPOSITORY,
                "Ledger depo çalışma ağacı dışında tutulmalıdır (git ile yeniden yazılabilir alan yasak).",
            )
        led = HoldoutAccessLedger(ledger_path=self._ledger_path)
        if not led.exists():
            raise HoldoutAccessDenied(DENY_LEDGER_MISSING, f"HOLDOUT ledger bulunamadı: {self._ledger_path.name}.")
        try:
            led.verify()
        except HoldoutLedgerIntegrityError as exc:
            raise HoldoutAccessDenied(DENY_LEDGER_INTEGRITY, str(exc)) from exc
        return led

    def _deny(
        self,
        led: HoldoutAccessLedger | None,
        code: str,
        message: str,
        request: HoldoutAccessRequest | None = None,
    ) -> HoldoutAccessDenied:
        if led is not None:
            try:
                led.append_event(
                    event_type=EVENT_ACCESS_DENIED,
                    decision_code=code,
                    recorded_at_utc=_fmt_utc(self._now()),
                    vault_id=getattr(request, "vault_id", None),
                    vault_file_sha256=getattr(request, "vault_file_sha256", None),
                    request_id=(f"DENIED::{request.request_id}" if request is not None else None),
                    nonce=(f"DENIED::{request.nonce}" if request is not None else None),
                    operator_id=getattr(request, "operator_id", None),
                    custodian_id=getattr(request, "custodian_id", None),
                    purpose=getattr(request, "purpose", None),
                    details={"reason": message},
                )
            except EvaluationIntegrityError:
                pass
        return HoldoutAccessDenied(code, message)

    def _check_environment(self) -> None:
        marker = detect_ci_environment(self._env)
        if marker is not None:
            raise HoldoutAccessDenied(
                DENY_CI_ENVIRONMENT,
                f"CI ortamında ({marker}) HOLDOUT erişimi yasaktır; yalnız izolasyon/politika kontrolleri çalışır.",
            )

    def load_registry(self) -> HoldoutVaultRegistry:
        return load_holdout_vault_registry(self._registry_path)

    def authorize(self, request: HoldoutAccessRequest) -> HoldoutAccessGrant:
        """Authorise one HOLDOUT access (one vault read + one blind run) or raise HoldoutAccessDenied."""
        self._check_environment()
        led = self._ledger()
        try:
            registry = self.load_registry()
        except HoldoutAccessDenied as exc:
            raise self._deny(led, exc.code, str(exc), request) from exc

        vault = registry.vault(request.vault_id)
        if vault is None:
            raise self._deny(led, DENY_VAULT_UNKNOWN, f"Kayıtlı olmayan kasa: {request.vault_id}.", request)
        if vault.status != VAULT_STATUS_SEALED_AVAILABLE:
            raise self._deny(
                led,
                DENY_VAULT_CONSUMED,
                f"{vault.vault_id} durumu {vault.status}; yeni kör doğrulama için yeni kohort gerekir.",
                request,
            )
        if request.vault_file_sha256 != vault.file_sha256:
            raise self._deny(led, DENY_VAULT_HASH_MISMATCH, "İstekteki kasa dosya özeti kayıtla uyuşmuyor.", request)

        purpose = str(request.purpose or "").upper().strip()
        if purpose not in ALLOWED_PURPOSES or any(m in purpose for m in FORBIDDEN_PURPOSE_MARKERS):
            raise self._deny(led, DENY_PURPOSE_FORBIDDEN, f"İzin verilmeyen amaç: '{request.purpose}'.", request)

        cust = registry.custodian(request.custodian_id)
        if cust is None:
            raise self._deny(led, DENY_CUSTODIAN_UNKNOWN, f"Kayıtlı olmayan emanetçi: {request.custodian_id}.", request)
        now = self._now()
        valid_from = parse_utc_timestamp(cust.valid_from_utc)
        valid_until = parse_utc_timestamp(cust.valid_until_utc)
        if (
            cust.status != CUSTODIAN_STATUS_ACTIVE
            or valid_from is None
            or valid_until is None
            or not (valid_from <= now <= valid_until)
        ):
            raise self._deny(led, DENY_CUSTODIAN_INACTIVE, f"{cust.custodian_id} etkin veya geçerlilik penceresinde değil.", request)
        if request.key_id != cust.key_id or request.algorithm.upper() != cust.algorithm:
            raise self._deny(led, DENY_CUSTODIAN_KEY_MISMATCH, "İstek anahtar kimliği/algoritması kayıtla uyuşmuyor.", request)

        ok, why = verify_asymmetric_signature(
            request.signing_payload(), request.signature_b64, cust.public_key_pem, cust.algorithm
        )
        if not ok:
            raise self._deny(led, DENY_SIGNATURE_INVALID, f"İmza doğrulanamadı: {why}", request)

        req_at = parse_utc_timestamp(request.requested_at_utc)
        exp_at = parse_utc_timestamp(request.expires_at_utc)
        if (
            req_at is None
            or exp_at is None
            or exp_at <= req_at
            or (exp_at - req_at) > MAX_REQUEST_VALIDITY
            or not (req_at - timedelta(minutes=5) <= now <= exp_at)
        ):
            raise self._deny(led, DENY_REQUEST_TIME_INVALID, "İstek zaman penceresi geçersiz veya süresi dolmuş.", request)

        rec, access_no = led.reserve_grant(vault=vault, request=request, recorded_at_utc=_fmt_utc(now))
        return HoldoutAccessGrant(
            grant_id=rec["grant_id"],
            vault_id=vault.vault_id,
            vault_file_sha256=vault.file_sha256,
            case_set_sha256=vault.case_set_sha256,
            dataset_version=vault.dataset_version,
            ledger_path=str(led.path),
            ledger_id=rec["ledger_id"],
            grant_record_sha256=rec["record_sha256"],
            operator_id=request.operator_id,
            purpose=purpose,
            access_number=access_no,
            max_authorized_runs=vault.max_authorized_runs,
        )

    def _ledger_for_grant(self, grant: HoldoutAccessGrant) -> HoldoutAccessLedger:
        self._check_environment()
        if not isinstance(grant, HoldoutAccessGrant):
            raise HoldoutAccessDenied(DENY_GRANT_INVALID, "Geçerli HoldoutAccessGrant nesnesi gerekli.")
        if self._ledger_path is None:
            self._ledger_path = Path(grant.ledger_path)
        elif Path(grant.ledger_path).resolve() != self._ledger_path.resolve():
            raise HoldoutAccessDenied(DENY_GRANT_INVALID, "Grant farklı bir ledger'a ait.")
        return self._ledger()

    def record_vault_read(self, grant: HoldoutAccessGrant, *, holdout_path: str | Path) -> dict[str, Any]:
        """Verify grant + raw file hash BEFORE parsing, then record the single permitted vault read."""
        led = self._ledger_for_grant(grant)
        registry = self.load_registry()
        vault = registry.vault(grant.vault_id)
        if vault is None or vault.status != VAULT_STATUS_SEALED_AVAILABLE:
            raise HoldoutAccessDenied(DENY_VAULT_CONSUMED, f"{grant.vault_id} artık erişilebilir değil.")
        file_sha = sha256_file_bytes(holdout_path)
        if file_sha != grant.vault_file_sha256 or file_sha != vault.file_sha256:
            raise HoldoutAccessDenied(DENY_VAULT_HASH_MISMATCH, "HOLDOUT dosya baytları grant/kayıt özetiyle uyuşmuyor.")
        return led.claim_grant_event(
            grant,
            event_type=EVENT_VAULT_READ,
            recorded_at_utc=_fmt_utc(self._now()),
            details={"file_sha256": file_sha},
        )

    def begin_blind_run(
        self,
        grant: HoldoutAccessGrant,
        *,
        holdout_case_set_sha256: str,
        blind_holdout_mode: bool,
    ) -> dict[str, Any]:
        """Verify the grant for a blind run over exactly the registered case set and claim RUN_STARTED."""
        if not blind_holdout_mode:
            raise HoldoutAccessDenied(DENY_NON_BLIND, "HOLDOUT yalnız blind_holdout_mode=True ile değerlendirilebilir.")
        led = self._ledger_for_grant(grant)
        registry = self.load_registry()
        vault = registry.vault(grant.vault_id)
        if vault is None or vault.status != VAULT_STATUS_SEALED_AVAILABLE:
            raise HoldoutAccessDenied(DENY_VAULT_CONSUMED, f"{grant.vault_id} artık erişilebilir değil.")
        if holdout_case_set_sha256 != vault.case_set_sha256 or holdout_case_set_sha256 != grant.case_set_sha256:
            raise HoldoutAccessDenied(DENY_CASE_SET_MISMATCH, "Değerlendirilecek HOLDOUT vaka kümesi kayıtlı kasa ile aynı değil.")
        return led.claim_grant_event(
            grant,
            event_type=EVENT_RUN_STARTED,
            recorded_at_utc=_fmt_utc(self._now()),
            details={"case_set_sha256": holdout_case_set_sha256},
        )

    def complete_blind_run(
        self,
        grant: HoldoutAccessGrant,
        *,
        run_id: str,
        run_manifest_sha256: str,
        holdout_redacted_count: int,
    ) -> dict[str, Any]:
        led = self._ledger_for_grant(grant)
        return led.claim_grant_event(
            grant,
            event_type=EVENT_RUN_COMPLETED,
            recorded_at_utc=_fmt_utc(self._now()),
            details={
                "run_id": run_id,
                "run_manifest_sha256": run_manifest_sha256,
                "holdout_redacted_count": holdout_redacted_count,
            },
            require_prior_event=EVENT_RUN_STARTED,
        )


def assert_no_unauthorised_holdout_bytes(path: str | Path, registry_path: str | Path | None = None) -> None:
    """Refuse (before parsing) a dataset file whose raw bytes match any registered HOLDOUT vault."""
    try:
        file_sha = sha256_file_bytes(path)
    except OSError:
        return
    registry = load_holdout_vault_registry(registry_path)
    vault = registry.vault_by_file_sha256(file_sha)
    if vault is not None:
        raise HoldoutAccessDenied(
            DENY_NO_GRANT,
            f"Dosya kayıtlı HOLDOUT kasası {vault.vault_id} ile aynı; grant olmadan okunamaz.",
        )
