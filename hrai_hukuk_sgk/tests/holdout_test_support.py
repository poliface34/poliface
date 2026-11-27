"""WP-4.6 test support: synthetic HOLDOUT vaults with ephemeral custodian keys (tests only).

Nothing here touches the real HOLDOUT vault. Synthetic vaults are built from DEV/VALIDATION cases
relabelled as HOLDOUT, written to a temporary directory together with a temporary registry, an
ephemeral (runtime-generated, never persisted) custodian key and a fresh persistent ledger. These
fixtures exercise the access-control code paths; they are not legal approvals and are never
registered in the repository registry.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Any
import uuid

from engine.attestation_verifier import compute_public_key_fingerprint, generate_ephemeral_keypair, sign_canonical_payload
from engine.evaluation import (
    SPLIT_HOLDOUT,
    VAULT_STATUS_SEALED_AVAILABLE,
    HoldoutAccessGate,
    HoldoutAccessGrant,
    HoldoutAccessLedger,
    HoldoutAccessRequest,
    compute_holdout_case_set_sha256,
    sha256_file_bytes,
)
from engine.evaluation.holdout_governance import PURPOSE_FINAL_BLIND_VERIFICATION, REGISTRY_SCHEMA

_KEY_CACHE: dict[str, tuple[str, str]] = {}


def ephemeral_keypair(algorithm: str = "ED25519") -> tuple[str, str]:
    """Runtime-generated keypair shared within one test process (never written to the repository)."""
    if algorithm not in _KEY_CACHE:
        _KEY_CACHE[algorithm] = generate_ephemeral_keypair(algorithm)
    return _KEY_CACHE[algorithm]


def synthetic_holdout_case(base: Any, idx: int) -> Any:
    """Relabel a DEV/VALIDATION case as a synthetic HOLDOUT case with a consistent answer-key hash."""
    relabelled = replace(
        base,
        case_id=f"SYNTH-HO-{idx:02d}",
        split=SPLIT_HOLDOUT,
        cluster_id=f"SYNTH-HO-CLUSTER-{idx:02d}",
    )
    return replace(
        relabelled,
        legal_review=replace(relabelled.legal_review, answer_key_sha256=relabelled.expected_answer_key_sha256()),
    )


def _utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SyntheticHoldoutVault:
    """Temporary vault + registry + custodian + persistent ledger for exercising WP-4.6 controls."""

    def __init__(
        self,
        root: Path,
        cases: tuple[Any, ...],
        *,
        max_runs: int = 1,
        status: str = VAULT_STATUS_SEALED_AVAILABLE,
        algorithm: str = "ED25519",
        custodian_status: str = "ACTIVE",
        environment: dict[str, str] | None = None,
        initialize_ledger: bool = True,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.cases = tuple(cases)
        self.algorithm = algorithm
        self.vault_id = f"SYNTH-VAULT-{uuid.uuid4().hex[:8].upper()}"
        self.vault_path = self.root / "synthetic_holdout_vault.json"
        self.vault_path.write_text(
            json.dumps(
                {
                    "dataset_version": "wp46-synthetic-vault",
                    "created_at_utc": "2026-11-27T00:00:00Z",
                    "vault_scope": "SYNTHETIC_TEST_VAULT",
                    "cases": [c.to_dict() for c in self.cases],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        self.file_sha256 = sha256_file_bytes(self.vault_path)
        self.case_set_sha256 = compute_holdout_case_set_sha256(self.cases)
        self.private_key_pem, self.public_key_pem = ephemeral_keypair(algorithm)
        self.custodian_id = "SYNTH-TEST-CUSTODIAN"
        self.key_id = f"SYNTH-KEY-{algorithm}"
        self.registry_path = self.root / "registry.json"
        self.write_registry(status=status, max_runs=max_runs, custodian_status=custodian_status)
        self.ledger_path = self.root / "ledger" / "holdout_access.jsonl"
        if initialize_ledger:
            HoldoutAccessLedger.initialize(
                ledger_path=self.ledger_path,
                ledger_id="SYNTH-LEDGER",
                created_by="wp46-test",
            )
        self.environment = {} if environment is None else environment

    def write_registry(self, *, status: str, max_runs: int, custodian_status: str = "ACTIVE") -> None:
        now = datetime.now(timezone.utc)
        self.registry_path.write_text(
            json.dumps(
                {
                    "schema": REGISTRY_SCHEMA,
                    "registry_version": "synthetic-test",
                    "vaults": [
                        {
                            "vault_id": self.vault_id,
                            "dataset_version": "wp46-synthetic-vault",
                            "file_relpath": str(self.vault_path),
                            "file_sha256": self.file_sha256,
                            "case_set_sha256": self.case_set_sha256,
                            "case_count": len(self.cases),
                            "status": status,
                            "max_authorized_runs": max_runs,
                        }
                    ],
                    "custodians": [
                        {
                            "custodian_id": self.custodian_id,
                            "custodian_role": "SYNTHETIC_TEST_CUSTODIAN",
                            "identity_verification_ref": "NONE-SYNTHETIC-TEST-FIXTURE",
                            "key_id": self.key_id,
                            "algorithm": self.algorithm,
                            "public_key_pem": self.public_key_pem,
                            "public_key_fingerprint_sha256": compute_public_key_fingerprint(self.public_key_pem),
                            "valid_from_utc": _utc(now - timedelta(days=1)),
                            "valid_until_utc": _utc(now + timedelta(days=1)),
                            "status": custodian_status,
                        }
                    ],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

    def gate(self, environment: dict[str, str] | None = None, ledger_path: Path | None = None) -> HoldoutAccessGate:
        return HoldoutAccessGate(
            registry_path=self.registry_path,
            ledger_path=self.ledger_path if ledger_path is None else ledger_path,
            environment=self.environment if environment is None else environment,
        )

    def request(
        self,
        *,
        purpose: str = PURPOSE_FINAL_BLIND_VERIFICATION,
        request_id: str | None = None,
        nonce: str | None = None,
        private_key_pem: str | None = None,
        sign: bool = True,
        requested_at: datetime | None = None,
        validity: timedelta = timedelta(hours=1),
        **overrides: Any,
    ) -> HoldoutAccessRequest:
        req_at = requested_at or datetime.now(timezone.utc)
        req = HoldoutAccessRequest(
            request_id=request_id or f"REQ-{uuid.uuid4().hex[:16].upper()}",
            vault_id=overrides.pop("vault_id", self.vault_id),
            vault_file_sha256=overrides.pop("vault_file_sha256", self.file_sha256),
            purpose=purpose,
            operator_id=overrides.pop("operator_id", "AUDITOR-SYNTH-01"),
            custodian_id=overrides.pop("custodian_id", self.custodian_id),
            key_id=overrides.pop("key_id", self.key_id),
            algorithm=overrides.pop("algorithm", self.algorithm),
            requested_at_utc=_utc(req_at),
            expires_at_utc=_utc(req_at + validity),
            nonce=nonce or f"NONCE-{uuid.uuid4().hex}",
        )
        if overrides:
            raise TypeError(f"Unknown overrides: {sorted(overrides)}")
        if not sign:
            return req
        sig = sign_canonical_payload(req.signing_payload(), private_key_pem or self.private_key_pem, self.algorithm)
        return replace(req, signature_b64=sig)

    def grant(self, **request_kwargs: Any) -> HoldoutAccessGrant:
        return self.gate().authorize(self.request(**request_kwargs))

    def ledger_records(self) -> tuple[dict[str, Any], ...]:
        return HoldoutAccessLedger(ledger_path=self.ledger_path).verify()


class RegisteredVaultFileReadGuard:
    """Records any attempt to open/read/stat-for-content a registered vault file (path from registry).

    Used by WP-4.6 vault preparation tests to prove that the real HOLDOUT file is never opened. Paths
    are taken from the vault registry metadata, so no HOLDOUT file name is hard-coded in test code.
    """

    def __init__(self, targets: "list[Path] | tuple[Path, ...]") -> None:
        import builtins as _builtins
        import os as _os
        from unittest import mock as _mock

        self._builtins = _builtins
        self._os = _os
        self._mock = _mock
        self.targets = {Path(t).resolve() for t in targets}
        self.hits: list[str] = []
        self._patches: list[Any] = []

    def _check(self, p: object, api: str) -> None:
        try:
            if Path(self._os.fspath(p)).resolve() in self.targets:  # type: ignore[arg-type]
                self.hits.append(api)
        except TypeError:
            pass

    def __enter__(self) -> "RegisteredVaultFileReadGuard":
        real_open, real_os_open = self._builtins.open, self._os.open
        real_rt, real_rb = Path.read_text, Path.read_bytes
        guard = self

        def t_open(file, *a, **k):
            guard._check(file, "open")
            return real_open(file, *a, **k)

        def t_os_open(path, *a, **k):
            guard._check(path, "os.open")
            return real_os_open(path, *a, **k)

        def t_rt(self_p, *a, **k):
            guard._check(self_p, "read_text")
            return real_rt(self_p, *a, **k)

        def t_rb(self_p, *a, **k):
            guard._check(self_p, "read_bytes")
            return real_rb(self_p, *a, **k)

        self._patches = [
            self._mock.patch("builtins.open", t_open),
            self._mock.patch("io.open", t_open),
            self._mock.patch("os.open", t_os_open),
            self._mock.patch.object(Path, "read_text", t_rt),
            self._mock.patch.object(Path, "read_bytes", t_rb),
        ]
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc: object) -> None:
        for p in reversed(self._patches):
            p.stop()
