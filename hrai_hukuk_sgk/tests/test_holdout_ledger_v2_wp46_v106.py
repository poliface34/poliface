"""WP-4.6 (part 2) tests: ledger v2 record model, counter/status/signature verification, unreadable
ledger, dataset version, grant and custodian revocation, spec v1.3 hygiene and WP-1 pins.

As in `test_holdout_governance_wp46_v106.py`, nothing here parses or evaluates the real (consumed)
HOLDOUT vault. Positive paths use synthetic vaults with ephemeral keys and temporary ledgers.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

from engine.attestation_verifier import canonical_json_bytes, sign_canonical_payload
from engine.evaluation import (
    HoldoutAccessDenied,
    HoldoutAccessGrant,
    HoldoutAccessLedger,
    HoldoutLedgerIntegrityError,
    classify_score_band,
    load_dev_val_dataset,
    load_holdout_vault_registry,
)
from engine.evaluation import holdout_governance as hg

from tests.holdout_test_support import SyntheticHoldoutVault, synthetic_holdout_case

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = PROJECT_ROOT / "docs" / "WP4_5_EVALUATION_SPEC.md"

# Minimum record fields required by the WP-4.6 instruction (in addition to internal fields).
REQUIRED_LEDGER_FIELDS = {
    "event_id",
    "dataset_id",
    "dataset_version",
    "dataset_sha256",
    "operator_id",
    "purpose",
    "timestamp_utc",
    "access_count_for_version",
    "previous_record_hash",
    "record_hash",
    "signature",
    "signature_algorithm",
    "authorization_status",
    "result_status",
}

# WP-1 / policy-protected configuration: pinned so any edit fails CI (do not update without approval).
WP1_PINNED_SHA256 = {
    "config/authorized_approvers.json": "9bfd8ffb08abd5b41add74f22921da9c9381027113ea8c4935015a7ef15b539c",
}

_SHARED: dict[str, object] = {}


def _case(case_id: str):
    if "ds" not in _SHARED:
        _SHARED["ds"] = load_dev_val_dataset()
    return next(c for c in _SHARED["ds"].cases if c.case_id == case_id)  # type: ignore[attr-defined]


def _rewrite_records(path: Path, mutate) -> None:
    """Apply `mutate(records)` and re-hash/re-chain every record (simulates a capable forger)."""
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    mutate(records)
    prev = hg.GENESIS_PREVIOUS_SHA256
    out = []
    for rec in records:
        rec["previous_record_hash"] = prev
        body = {k: v for k, v in rec.items() if k != "record_hash"}
        rec["record_hash"] = hg._record_hash(body)
        prev = rec["record_hash"]
        out.append(canonical_json_bytes(rec) + b"\n")
    path.write_bytes(b"".join(out))


class TestHoldoutLedgerV2Wp46(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="wp46b_")
        self.tmp = Path(self._td.name)

    def tearDown(self) -> None:
        self._td.cleanup()

    def _vault(self, name: str = "vault", **kw) -> SyntheticHoldoutVault:
        cases = (synthetic_holdout_case(_case("EVAL-085"), 1),)
        return SyntheticHoldoutVault(self.tmp / name, cases, **kw)

    # ------------------------------------------------------------------ record model
    def test_01_records_carry_required_fields_and_derived_status(self) -> None:
        """Her kayıt talimattaki asgari alanları taşır; sayaç ve statüler olay türünden türetilir."""
        vault = self._vault(max_runs=2)
        g1 = vault.grant(operator_id="AUDITOR-A")
        with self.assertRaises(HoldoutAccessDenied):
            vault.grant(purpose="MODEL_TUNING")
        vault.grant(operator_id="AUDITOR-B")
        with self.assertRaises(HoldoutAccessDenied) as ctx:
            vault.grant()
        self.assertEqual(ctx.exception.code, hg.DENY_LIMIT_EXCEEDED)

        recs = vault.ledger_records()
        self.assertEqual(recs[0]["schema"], "hrai.holdout_access_ledger.v2")
        for r in recs:
            self.assertEqual(set(r), hg.LEDGER_RECORD_KEYS)
            self.assertTrue(REQUIRED_LEDGER_FIELDS <= set(r))
            self.assertTrue(r["event_id"].startswith("EVT-"))
            self.assertRegex(r["timestamp_utc"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertEqual(len({r["event_id"] for r in recs}), len(recs))

        self.assertEqual(
            [(r["event_type"], r["authorization_status"], r["access_count_for_version"]) for r in recs],
            [
                ("GENESIS", "NOT_APPLICABLE", 0),
                ("ACCESS_GRANTED", "AUTHORIZED", 1),
                ("ACCESS_DENIED", "DENIED", 0),  # purpose denial: dataset version unknown at that point
                ("ACCESS_GRANTED", "AUTHORIZED", 2),
                ("ACCESS_DENIED", "DENIED", 2),  # limit denial counts the grants already given
            ],
        )
        granted = [r for r in recs if r["event_type"] == "ACCESS_GRANTED"]
        for r in granted:
            self.assertEqual(r["dataset_id"], vault.vault_id)
            self.assertEqual(r["dataset_sha256"], vault.file_sha256)
            self.assertEqual(r["dataset_version"], "wp46-synthetic-vault")
            self.assertEqual(r["signature_algorithm"], "ED25519")
            self.assertEqual(r["result_status"], "PENDING_VAULT_READ")
            self.assertTrue(r["signature"])
        self.assertTrue(all(r["signature"] is None for r in recs if r["event_type"] != "ACCESS_GRANTED"))
        self.assertEqual(granted[0]["grant_id"], g1.grant_id)
        self.assertEqual(recs[4]["decision_code"], hg.DENY_LIMIT_EXCEEDED)

        # Signatures re-verify against the registry.
        HoldoutAccessLedger(ledger_path=vault.ledger_path).verify_signatures(vault.gate().load_registry())

    # ------------------------------------------------------------------ fail-closed reads
    def test_02_unreadable_ledger_refused(self) -> None:
        """Ledger dosyası var ama okunamıyorsa erişim HOLDOUT_LEDGER_UNREADABLE ile reddedilir."""
        vault = self._vault()
        real_read_bytes = Path.read_bytes
        target = vault.ledger_path.resolve()

        def failing_read_bytes(self_p, *a, **k):
            if Path(self_p).resolve() == target:
                raise PermissionError("simulated EACCES")
            return real_read_bytes(self_p, *a, **k)

        with mock.patch.object(Path, "read_bytes", failing_read_bytes):
            with self.assertRaises(HoldoutAccessDenied) as ctx:
                vault.grant()
        self.assertEqual(ctx.exception.code, hg.DENY_LEDGER_UNREADABLE)
        self.assertEqual([r["event_type"] for r in vault.ledger_records()], ["GENESIS"])

    def test_03_counter_inconsistency_detected_even_when_rehashed(self) -> None:
        """Sayaç değeri değiştirilip tüm zincir yeniden hash'lense de doğrulama başarısız olur."""
        vault = self._vault(max_runs=3)
        vault.grant()
        vault.grant()

        def lower_count(records):
            records[2]["access_count_for_version"] = 1  # pretend the 2nd grant was the 1st

        _rewrite_records(vault.ledger_path, lower_count)
        with self.assertRaises(HoldoutLedgerIntegrityError) as c1:
            HoldoutAccessLedger(ledger_path=vault.ledger_path).verify()
        self.assertIn("access_count_for_version", str(c1.exception))
        with self.assertRaises(HoldoutAccessDenied) as c2:
            vault.grant()
        self.assertEqual(c2.exception.code, hg.DENY_LEDGER_INTEGRITY)

    def test_04_status_forgery_detected(self) -> None:
        """Bir ret kaydının authorization_status değerini AUTHORIZED yapmak doğrulamayı bozar."""
        vault = self._vault()
        with self.assertRaises(HoldoutAccessDenied):
            vault.grant(purpose="DEBUG")

        def forge(records):
            records[1]["authorization_status"] = "AUTHORIZED"

        _rewrite_records(vault.ledger_path, forge)
        with self.assertRaises(HoldoutLedgerIntegrityError):
            HoldoutAccessLedger(ledger_path=vault.ledger_path).verify()

    def test_05_invalid_grant_signature_in_ledger_refused(self) -> None:
        """ACCESS_GRANTED imzası başka bir yükün geçerli imzasıyla değiştirilirse zincir sağlam olsa da erişim reddedilir."""
        vault = self._vault(max_runs=2)
        vault.grant()
        other_sig = sign_canonical_payload({"unrelated": "payload"}, vault.private_key_pem, "ED25519")

        def swap_sig(records):
            records[1]["signature"] = other_sig

        _rewrite_records(vault.ledger_path, swap_sig)
        led = HoldoutAccessLedger(ledger_path=vault.ledger_path)
        led.verify()  # hash chain alone is consistent ...
        with self.assertRaises(HoldoutLedgerIntegrityError):
            led.verify_signatures(vault.gate().load_registry())  # ... but the custodian signature is not
        with self.assertRaises(HoldoutAccessDenied) as ctx:
            vault.grant()
        self.assertEqual(ctx.exception.code, hg.DENY_LEDGER_INTEGRITY)

    def test_06_signer_missing_from_registry_refused(self) -> None:
        """İmzalayan emanetçi kayıt defterinden silinirse geçmiş grant doğrulanamaz; erişim kapanır."""
        vault = self._vault(max_runs=2)
        vault.grant()
        raw = json.loads(vault.registry_path.read_text(encoding="utf-8"))
        raw["custodians"][0]["custodian_id"] = "SOMEONE-ELSE"
        vault.registry_path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaises(HoldoutAccessDenied) as ctx:
            vault.grant(custodian_id="SOMEONE-ELSE")
        self.assertEqual(ctx.exception.code, hg.DENY_LEDGER_INTEGRITY)

    def test_07_no_mutation_api_and_genesis_cannot_be_reinitialised(self) -> None:
        """Ledger'da kayıt değiştirme/silme API'si yoktur; mevcut ledger yeniden başlatılamaz."""
        public = {n for n in dir(HoldoutAccessLedger) if not n.startswith("_")}
        self.assertEqual(
            public,
            {"initialize", "exists", "path", "verify", "head", "verify_signatures", "append_event",
             "reserve_grant", "claim_grant_event"},
        )
        vault = self._vault()
        before = vault.ledger_path.read_bytes()
        with self.assertRaises(HoldoutLedgerIntegrityError):
            HoldoutAccessLedger.initialize(ledger_path=vault.ledger_path, ledger_id="X", created_by="Y")
        self.assertEqual(vault.ledger_path.read_bytes(), before)
        with self.assertRaises(HoldoutLedgerIntegrityError):
            HoldoutAccessLedger(ledger_path=vault.ledger_path).append_event(
                event_type="GENESIS", decision_code="X", recorded_at_utc="2026-11-27T00:00:00Z"
            )

    # ------------------------------------------------------------------ dataset identity
    def test_08_wrong_dataset_hash_and_wrong_version_refused(self) -> None:
        """Yanlış dosya özeti, sahte sürüm etiketi ve kayıt sonrası sürüm değişikliği reddedilir."""
        vault = self._vault(max_runs=3)
        with self.assertRaises(HoldoutAccessDenied) as c1:
            vault.grant(vault_file_sha256="f" * 64)
        self.assertEqual(c1.exception.code, hg.DENY_VAULT_HASH_MISMATCH)

        grant = vault.grant()
        forged = replace(grant, dataset_version="wp46-synthetic-vault-v2")
        with self.assertRaises(HoldoutAccessDenied) as c2:
            vault.gate().record_vault_read(forged, holdout_path=vault.vault_path)
        self.assertEqual(c2.exception.code, hg.DENY_DATASET_VERSION_MISMATCH)

        raw = json.loads(vault.registry_path.read_text(encoding="utf-8"))
        raw["vaults"][0]["dataset_version"] = "relabelled"
        vault.registry_path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaises(HoldoutAccessDenied) as c3:
            vault.gate().record_vault_read(grant, holdout_path=vault.vault_path)
        self.assertEqual(c3.exception.code, hg.DENY_DATASET_VERSION_MISMATCH)
        # Relabelling the version does not reset the per-file limit: 1 grant already counted.
        self.assertEqual(
            sum(1 for r in vault.ledger_records() if r["event_type"] == "ACCESS_GRANTED"), 1
        )

    def test_09_in_memory_grant_is_not_proof_of_access(self) -> None:
        """Ledger'da karşılığı olmayan, elle oluşturulmuş grant (bellek içi sayaç) erişim sağlamaz."""
        vault = self._vault()
        fake = HoldoutAccessGrant(
            grant_id="GRANT-FAKE", vault_id=vault.vault_id, vault_file_sha256=vault.file_sha256,
            case_set_sha256=vault.case_set_sha256, dataset_version="wp46-synthetic-vault",
            ledger_path=str(vault.ledger_path), ledger_id="SYNTH-LEDGER", grant_record_sha256="0" * 64,
            operator_id="X", purpose="FINAL_BLIND_VERIFICATION", access_number=1, max_authorized_runs=1,
        )
        with self.assertRaises(HoldoutAccessDenied) as ctx:
            vault.gate().record_vault_read(fake, holdout_path=vault.vault_path)
        self.assertEqual(ctx.exception.code, hg.DENY_GRANT_INVALID)

    # ------------------------------------------------------------------ revocation
    def test_10_grant_revocation_blocks_further_use(self) -> None:
        """İptal edilen grant ile kasa okunamaz ve koşu başlatılamaz; iptal kaydı ledger'dadır."""
        vault = self._vault()
        grant = vault.grant()
        gate = vault.gate()
        rec = gate.revoke_grant(grant, revoked_by="CUSTODIAN-OFFICE", reason="operator role withdrawn")
        self.assertEqual(rec["event_type"], "GRANT_REVOKED")
        self.assertEqual(rec["authorization_status"], "REVOKED")
        with self.assertRaises(HoldoutAccessDenied) as c1:
            gate.record_vault_read(grant, holdout_path=vault.vault_path)
        self.assertEqual(c1.exception.code, hg.DENY_GRANT_REVOKED)
        with self.assertRaises(HoldoutAccessDenied) as c2:
            gate.begin_blind_run(grant, holdout_case_set_sha256=vault.case_set_sha256, blind_holdout_mode=True)
        self.assertEqual(c2.exception.code, hg.DENY_GRANT_REVOKED)
        with self.assertRaises(HoldoutAccessDenied):
            gate.revoke_grant(grant, revoked_by="", reason="")
        # The revoked grant still counts against the limit (no access right is returned).
        with self.assertRaises(HoldoutAccessDenied) as c3:
            vault.grant()
        self.assertEqual(c3.exception.code, hg.DENY_LIMIT_EXCEEDED)

    def test_11_custodian_revocation_invalidates_outstanding_grants(self) -> None:
        """Grant sonrası emanetçi REVOKED yapılırsa bekleyen grant ile kasa okunamaz."""
        vault = self._vault()
        grant = vault.grant()
        vault.write_registry(status=hg.VAULT_STATUS_SEALED_AVAILABLE, max_runs=1, custodian_status="REVOKED")
        with self.assertRaises(HoldoutAccessDenied) as ctx:
            vault.gate().record_vault_read(grant, holdout_path=vault.vault_path)
        self.assertEqual(ctx.exception.code, hg.DENY_CUSTODIAN_INACTIVE)
        self.assertNotIn("VAULT_READ", [r["event_type"] for r in vault.ledger_records()])


class TestSpecV13AndWp1Pins(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = SPEC_PATH.read_text(encoding="utf-8")

    def test_12_spec_version_and_no_local_links(self) -> None:
        """Spec v1.3 başlığını taşır; yerel file:/// veya /home/ bağlantısı içermez."""
        self.assertIn("**Revizyon:** `v1.3`", self.spec)
        self.assertNotIn("file:///", self.spec)
        self.assertNotRegex(self.spec, r"/home/[a-z]")

    def test_13_spec_mentions_no_holdout_case_ids(self) -> None:
        """Spec'te geçen her EVAL-NNN kimliği DEV/VALIDATION kümesindendir (HOLDOUT kimliği yok)."""
        dev_val_ids = {c.case_id for c in load_dev_val_dataset().cases}
        mentioned = set(re.findall(r"EVAL-\d{3}", self.spec))
        self.assertEqual(sorted(mentioned - dev_val_ids), [])

    def test_14_k02_thresholds_unchanged(self) -> None:
        """K-02 eşikleri (85 / 80 / 75) kodda ve spec'te değişmeden durur."""
        self.assertEqual(classify_score_band(85.0)[1], "PASS")
        self.assertEqual(classify_score_band(84.99)[1], "PARTIAL_REVIEW")
        self.assertEqual(classify_score_band(80.0)[1], "PARTIAL_REVIEW")
        self.assertEqual(classify_score_band(79.99)[1], "FAIL_SCORE")
        self.assertEqual(classify_score_band(99.0, major_count=1)[1], "FAIL_MAJOR")  # veto ayrı çalışır
        self.assertEqual(classify_score_band(99.0, fatal_count=1)[1], "FAIL_FATAL")
        runner_src = (PROJECT_ROOT / "engine" / "evaluation" / "runner.py").read_text(encoding="utf-8")
        self.assertIn("if c_avg < 75.0:", runner_src)
        for token in (">= 85.0", "80.0", "75.0"):
            self.assertIn(token, self.spec)

    def test_15_wp1_protected_config_pinned_and_gates_closed(self) -> None:
        """WP-1 korumalı onayçı defteri değişmemiş; test anahtarları üretimde yasak; gate'ler kapalı."""
        for rel, expected in WP1_PINNED_SHA256.items():
            self.assertEqual(hashlib.sha256((PROJECT_ROOT / rel).read_bytes()).hexdigest(), expected, rel)
        approvers = json.loads((PROJECT_ROOT / "config" / "authorized_approvers.json").read_text(encoding="utf-8"))
        self.assertIs(approvers["test_sandbox_keys_allowed_in_production"], False)
        for rec in approvers["approvers"].values():
            self.assertIsNone(rec["public_key_pem"])
            self.assertEqual(rec["enrollment_status"], "PENDING_PRODUCTION_KEY_ENROLLMENT")
            self.assertIs(rec["qualified_e_signature_5070_equivalent"], False)
        esign = json.loads((PROJECT_ROOT / "config" / "esign_5070_config.json").read_text(encoding="utf-8"))
        self.assertEqual(esign["deployment_status"], "NOT_CONFIGURED")
        trust = json.loads((PROJECT_ROOT / "config" / "production_trust_root_config.json").read_text(encoding="utf-8"))
        self.assertEqual(trust["deployment_status"], "NOT_CONFIGURED")

    def test_16_audit_archive_manifest_matches_preserved_files(self) -> None:
        """Arşiv manifestindeki boyut ve SHA-256 değerleri yerinde korunan dosyalarla eşleşir (ham bayt)."""
        man_path = PROJECT_ROOT / "engine" / "evaluation" / "governance" / "archive" / "HOLDOUT_V1_2_AUDIT_ARCHIVE_MANIFEST_20261127.json"
        man = json.loads(man_path.read_text(encoding="utf-8"))
        self.assertEqual(man["vault_status"]["consumption"], "CONSUMED")
        self.assertEqual(man["vault_status"]["blindness"], "CONTAMINATED")
        # Paths come from the vault registry (no direct HOLDOUT path in test code; raw bytes only).
        raw_vault = load_holdout_vault_registry().raw["vaults"][0]
        holdout_rel = Path(raw_vault["file_relpath"])
        on_disk = {
            holdout_rel.name: PROJECT_ROOT / holdout_rel,
            Path(raw_vault["consumption_evidence_relpath"]).name: PROJECT_ROOT / raw_vault["consumption_evidence_relpath"],
        }
        checked = 0
        for entry in man["entries"]:
            path = on_disk.get(entry["file_name"])
            if path is None:
                continue  # git-history-only entries (verified by blob id outside CI)
            raw = path.read_bytes()
            self.assertEqual(len(raw), entry["size_bytes"], entry["file_name"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), entry["sha256"], entry["file_name"])
            checked += 1
        self.assertEqual(checked, 2)
        statuses = {r["record"]: r["status"] for r in man["unavailable_records"]}
        self.assertTrue(all(v in {"UNAVAILABLE", "UNVERIFIED_CLAIM"} for v in statuses.values()))
        self.assertEqual(statuses["access_count_for_version=1 iddiası"], "UNVERIFIED_CLAIM")


if __name__ == "__main__":
    unittest.main()
