"""WP-4.6 GCP HOLDOUT vault PREPARATION tests (mock / synthetic data only).

No real GCP connection, no credentials and no real HOLDOUT bytes are used. In-memory fakes stand in
for GCS, Cloud KMS and Cloud Audit Logs; transfers move synthetic bytes generated inside the test.
The repository status must keep every real-infrastructure step NOT_CREATED / NOT_PROVISIONED /
UNDECIDED / NOT_STARTED, and the adapter built from it must refuse every operation as NOT_CONFIGURED.
"""

from __future__ import annotations

import ast
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import re
import tempfile
import unittest

from engine.attestation_verifier import sign_canonical_payload
from engine.evaluation import load_dev_val_dataset, load_holdout_vault_registry
from engine.evaluation import holdout_vault as hv
from engine.evaluation.holdout_governance import HoldoutAccessLedger

from tests.holdout_test_support import (
    RegisteredVaultFileReadGuard,
    SyntheticHoldoutVault,
    ephemeral_keypair,
    synthetic_holdout_case,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DOCS = PROJECT_ROOT / "docs"
VAULT_DOCS = (
    "WP4_6_GCP_HOLDOUT_VAULT_ARCHITECTURE.md",
    "WP4_6_GCP_VAULT_PROVISIONING_PROCEDURE.md",
    "WP4_6_HOLDOUT_CUSTODIAN_RESPONSIBILITY_MATRIX.md",
    "WP4_6_HOLDOUT_MIGRATION_AND_RESTORE_VERIFICATION_PROCEDURE.md",
    "WP4_6_GCP_REGION_AND_KVKK_ASSESSMENT.md",
    "WP4_6_PUBLIC_REPOSITORY_HISTORICAL_EXPOSURE_RISK_ASSESSMENT.md",
    "WP4_6_VAULT_MIGRATION_READINESS_CHECKLIST.md",
)

LOCATION = "test-region-1"  # synthetic location label, not a region decision
PROJECT = "synthetic-test-project"
KMS_KEY = f"projects/{PROJECT}/locations/{LOCATION}/keyRings/synthetic-ring/cryptoKeys/synthetic-cmek"
BUCKET = "synthetic-holdout-vault-test"
WRITER = "serviceAccount:synthetic-writer@test.invalid"
READER = "serviceAccount:synthetic-restore@test.invalid"

_SHARED: dict[str, object] = {}


def _case(case_id: str):
    if "ds" not in _SHARED:
        _SHARED["ds"] = load_dev_val_dataset()
    return next(c for c in _SHARED["ds"].cases if c.case_id == case_id)  # type: ignore[attr-defined]


# ----------------------------------------------------------------------------- in-memory fakes
class FakeKms:
    def __init__(self, **overrides: object) -> None:
        self.meta = {
            "name": KMS_KEY, "purpose": "ENCRYPT_DECRYPT", "primary_state": "ENABLED", "protection_level": "HSM",
        }
        self.meta.update(overrides)
        self.signing = {"purpose": "ASYMMETRIC_SIGN", "state": "ENABLED", "algorithm": "EC_SIGN_ED25519"}

    def get_crypto_key(self, key_name: str):
        if "/cryptoKeyVersions/" in key_name:
            return {**self.signing, "name": key_name}
        return dict(self.meta)


class FakeStore:
    def __init__(self, **bucket_overrides: object) -> None:
        self.bucket_meta = {
            "location": LOCATION, "uniform_bucket_level_access": True, "public_access_prevention": "enforced",
            "versioning_enabled": True, "default_kms_key_name": KMS_KEY, "retention_period_seconds": 86400,
            "retention_policy_locked": True,
        }
        self.bucket_meta.update(bucket_overrides)
        self.objects: dict[tuple[str, str, str], dict[str, object]] = {}
        self.uploads = 0
        self.corrupt_metadata = False
        self.corrupt_bytes = False

    def get_bucket_metadata(self, bucket: str):
        return dict(self.bucket_meta)

    def upload_file(self, bucket, object_name, local_path, *, kms_key_name, metadata):
        self.uploads += 1
        gen = str(1000 + self.uploads)
        data = Path(local_path).read_bytes()
        self.objects[(bucket, object_name, gen)] = {
            "data": data, "metadata": dict(metadata), "kms_key_name": f"{kms_key_name}/cryptoKeyVersions/1",
        }
        return {"generation": gen}

    def get_object_metadata(self, bucket, object_name, generation=None):
        obj = self.objects[(bucket, object_name, str(generation))]
        md = dict(obj["metadata"])  # type: ignore[arg-type]
        if self.corrupt_metadata:
            md["sha256"] = "0" * 64
        return {"metadata": md, "size": len(obj["data"]), "kms_key_name": obj["kms_key_name"], "generation": generation}  # type: ignore[arg-type]

    def download_file(self, bucket, object_name, generation, dest_path):
        data = self.objects[(bucket, object_name, str(generation))]["data"]
        Path(dest_path).write_bytes(data[:-1] + b"X" if self.corrupt_bytes else data)  # type: ignore[index]


class FakeAudit:
    def __init__(self, entries: list[dict[str, str]]) -> None:
        self.entries = entries

    def list_entries(self, *, bucket: str, object_name: str):
        return list(self.entries)


def _config(**kw: object) -> hv.GcsVaultConfig:
    base = dict(
        project_id=PROJECT, bucket=BUCKET, location=LOCATION, kms_key_name=KMS_KEY, object_prefix="holdout/",
        min_retention_seconds=3600, allowed_writer_principals=(WRITER,), allowed_reader_principals=(READER,),
    )
    base.update(kw)
    return hv.GcsVaultConfig(**base)  # type: ignore[arg-type]


def _two_approvals(action: str) -> tuple[hv.OperatorApproval, ...]:
    return (
        hv.OperatorApproval("APPROVER-CUSTODIAN", "AUTHORIZED_CUSTODIAN", action),
        hv.OperatorApproval("APPROVER-CLOUDADMIN", "CORPORATE_CLOUD_ADMIN", action),
    )


class TestHoldoutVaultPreparationWp46(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="wp46v_")
        self.tmp = Path(self._td.name)
        self.payload = b"synthetic vault object bytes - not HOLDOUT content\n" * 7
        self.src = self.tmp / "synthetic_object.bin"
        self.src.write_bytes(self.payload)
        self.ref = hv.HistoricalHoldoutReference(
            vault_id="SYNTH-VAULT-REF", file_relpath="synthetic/object.bin", file_name="object.bin",
            file_sha256=hashlib.sha256(self.payload).hexdigest(), git_blob_sha1="f" * 40, size_bytes=len(self.payload),
        )
        self.entry = hv.VaultManifestEntry(
            vault_id=self.ref.vault_id, object_name="holdout/synthetic/object.bin", sha256=self.ref.file_sha256,
            size_bytes=self.ref.size_bytes, git_blob_sha1=self.ref.git_blob_sha1, kms_key_name=KMS_KEY,
        )

    def tearDown(self) -> None:
        self._td.cleanup()

    def _adapter(self, store: FakeStore | None = None, kms: FakeKms | None = None, audit: FakeAudit | None = None, **cfg):
        return hv.GCSHoldoutVaultAdapter(
            _config(**cfg), store=store or FakeStore(), kms=hv.CloudKMSKeyProvider(kms or FakeKms()), audit=audit,
        )

    def _status_copy(self, mutate) -> Path:
        raw = json.loads(hv.DEFAULT_VAULT_MIGRATION_STATUS_PATH.read_text(encoding="utf-8"))
        mutate(raw)
        p = self.tmp / f"status_{len(list(self.tmp.iterdir()))}.json"
        p.write_text(json.dumps(raw), encoding="utf-8")
        return p

    # ------------------------------------------------------------------ repository status
    def test_01_repository_status_records_real_unprovisioned_state(self) -> None:
        """Depo durumu: proje/bucket/KMS yok, bölge UNDECIDED, KVKK PENDING, taşıma ve geri yükleme başlamadı."""
        st = hv.load_vault_migration_status()
        self.assertEqual(
            dict(st.statuses),
            {
                "gcp_project": "NOT_CREATED", "vault_bucket": "NOT_PROVISIONED", "kms_key": "NOT_CREATED",
                "data_region": "UNDECIDED", "kvkk_review": "PENDING",
                "custodian": "CORPORATE_CLOUD_ADMIN_ROLE_PENDING_NAMED_OWNER",
                "vault_migration": "NOT_STARTED", "restore_verification": "NOT_STARTED",
                "migration_verification": "NOT_VERIFIED",
            },
        )
        self.assertTrue(all(v is False for v in st.flags.values()))
        self.assertEqual(st.raw["named_custodians"], [])
        self.assertEqual(st.raw["custodian_model"], "kurumsal_bulut")
        self.assertFalse(st.vault_provisioned)
        self.assertFalse(st.migration_verified)
        self.assertEqual(hv.readiness_level(st, preparation_checks_passed=False), "PREPARATION_INCOMPLETE")
        self.assertEqual(hv.readiness_level(st, preparation_checks_passed=True), hv.PREPARATION_COMPLETE)
        self.assertNotEqual(hv.PREPARATION_COMPLETE, hv.VAULT_PROVISIONED)
        self.assertNotEqual(hv.VAULT_PROVISIONED, hv.MIGRATION_VERIFIED_STATE)
        gates = st.raw["production_gates_unchanged"]
        self.assertTrue(all(v is False for v in gates.values()))
        approvers = json.loads((PROJECT_ROOT / "config" / "authorized_approvers.json").read_text(encoding="utf-8"))
        self.assertIs(approvers["test_sandbox_keys_allowed_in_production"], False)
        reg = load_holdout_vault_registry()
        self.assertEqual(reg.custodians, ())  # no named custodian invented

    def test_02_premature_success_claims_rejected(self) -> None:
        """Gerçekleşmemiş adımı tamamlanmış gösteren durum dosyası fail-closed reddedilir."""
        mutations = [
            lambda r: r["status"].__setitem__("gcp_project", "CREATED"),
            lambda r: r["status"].__setitem__("vault_bucket", "PROVISIONED"),
            lambda r: r["status"].__setitem__("data_region", "europe-west3"),
            lambda r: r["status"].__setitem__("migration_verification", "VERIFIED"),
            lambda r: r["status"].__setitem__("restore_verification", "VERIFIED"),
            lambda r: r["status"].__setitem__("kvkk_review", "APPROVED"),
            lambda r: r["status"].__setitem__("extra_claim", "DONE"),
            lambda r: r["safety_flags"].__setitem__("holdout_deletion_allowed", True),
            lambda r: r["safety_flags"].__setitem__("git_history_rewrite_allowed", True),
            lambda r: r["package_exclusion"].__setitem__("absence_means_migrated", True),
            lambda r: r.__setitem__("schema", "other"),
        ]
        for i, m in enumerate(mutations):
            with self.subTest(i=i):
                with self.assertRaises(hv.VaultOperationRefused) as ctx:
                    hv.load_vault_migration_status(self._status_copy(m))
                self.assertEqual(ctx.exception.code, hv.VAULT_STATUS_INVALID)

    def test_03_repository_adapter_is_not_configured(self) -> None:
        """Depodan kurulan adaptör ve KMS sağlayıcı her işlemde NOT_CONFIGURED döner; sahte başarı yok."""
        adapter = hv.GCSHoldoutVaultAdapter.from_repository_status()
        self.assertFalse(adapter.configured)
        calls = [
            adapter.verify_bucket_policy,
            lambda: adapter.transfer(self.src, self.entry, requester_id="R", approvals=_two_approvals("VAULT_UPLOAD")),
            lambda: adapter.verify_audit_trail(self.entry),
            lambda: adapter.download_generation(self.entry, "1", self.tmp / "x"),
            lambda: hv.VaultRestoreVerifier(adapter).verify(self.entry, "1"),
            lambda: hv.CloudKMSKeyProvider().validate_cmek_key(KMS_KEY, expected_location=LOCATION),
            lambda: hv.CloudKMSKeyProvider().validate_signing_key(KMS_KEY + "/cryptoKeyVersions/1"),
        ]
        for i, call in enumerate(calls):
            with self.subTest(i=i):
                with self.assertRaises(hv.VaultOperationRefused) as ctx:
                    call()
                self.assertEqual(ctx.exception.code, hv.VAULT_NOT_CONFIGURED)
        # Even with clients injected, an UNDECIDED region refuses every operation.
        undecided = self._adapter(location="UNDECIDED")
        with self.assertRaises(hv.VaultOperationRefused) as ctx_r:
            undecided.verify_bucket_policy()
        self.assertEqual(ctx_r.exception.code, hv.VAULT_NOT_CONFIGURED)

    # ------------------------------------------------------------------ KMS + bucket policy
    def test_04_kms_key_reference_validation(self) -> None:
        """CMEK referansı: ad biçimi, konum, amaç, durum ve koruma seviyesi; imza anahtarı ledger algoritmasına eşlenir."""
        ok = hv.CloudKMSKeyProvider(FakeKms()).validate_cmek_key(KMS_KEY, expected_location=LOCATION)
        self.assertEqual(ok["status"], "KEY_REFERENCE_VALID")
        bad = [
            (FakeKms(), "not-a-key", LOCATION),
            (FakeKms(), KMS_KEY + "/cryptoKeyVersions/1", LOCATION),
            (FakeKms(), KMS_KEY, "other-region"),
            (FakeKms(purpose="ASYMMETRIC_SIGN"), KMS_KEY, LOCATION),
            (FakeKms(primary_state="DISABLED"), KMS_KEY, LOCATION),
            (FakeKms(protection_level="UNKNOWN"), KMS_KEY, LOCATION),
            (FakeKms(name="projects/x/locations/y/keyRings/z/cryptoKeys/w"), KMS_KEY, LOCATION),
        ]
        for i, (fake, name, loc) in enumerate(bad):
            with self.subTest(i=i):
                with self.assertRaises(hv.VaultOperationRefused) as ctx:
                    hv.CloudKMSKeyProvider(fake).validate_cmek_key(name, expected_location=loc)
                self.assertEqual(ctx.exception.code, hv.VAULT_KMS_KEY_INVALID)
        sk = hv.CloudKMSKeyProvider(FakeKms()).validate_signing_key(KMS_KEY + "/cryptoKeyVersions/1")
        self.assertEqual(sk["ledger_algorithm"], "ED25519")
        weak = FakeKms()
        weak.signing["algorithm"] = "EC_SIGN_P256_SHA256"
        with self.assertRaises(hv.VaultOperationRefused):
            hv.CloudKMSKeyProvider(weak).validate_signing_key(KMS_KEY + "/cryptoKeyVersions/1")

    def test_05_bucket_policy_requires_every_control(self) -> None:
        """Private bucket, UBLA, PAP, versioning, CMEK, retention ve Bucket Lock zorunlu; herhangi biri eksikse red."""
        self.assertEqual(self._adapter().verify_bucket_policy()["status"], "BUCKET_POLICY_VALID")
        for override in (
            {"location": "elsewhere"}, {"uniform_bucket_level_access": False}, {"public_access_prevention": "inherited"},
            {"versioning_enabled": False}, {"default_kms_key_name": None}, {"retention_period_seconds": 10},
            {"retention_policy_locked": False}, {"all_users_bindings": ["roles/storage.objectViewer"]},
        ):
            with self.subTest(override=override):
                with self.assertRaises(hv.VaultOperationRefused) as ctx:
                    self._adapter(store=FakeStore(**override)).verify_bucket_policy()
                self.assertEqual(ctx.exception.code, hv.VAULT_BUCKET_POLICY_INVALID)

    # ------------------------------------------------------------------ transfer / restore / audit
    def test_06_transfer_compares_source_and_target_sha256_fail_closed(self) -> None:
        """Aktarım: kaynak SHA-256 manifestle eşleşmezse yükleme yapılmaz; hedef metadata uyuşmazlığı reddedilir."""
        store = FakeStore()
        res = self._adapter(store=store).transfer(
            self.src, self.entry, requester_id="OPERATOR-1", approvals=_two_approvals("VAULT_UPLOAD")
        )
        self.assertEqual(res.status, "UPLOADED_PENDING_RESTORE_VERIFICATION")  # never VERIFIED
        self.assertEqual(res.sha256, self.ref.file_sha256)

        wrong = self.tmp / "wrong.bin"
        wrong.write_bytes(self.payload + b"!")
        store2 = FakeStore()
        with self.assertRaises(hv.VaultOperationRefused) as c1:
            self._adapter(store=store2).transfer(wrong, self.entry, requester_id="OPERATOR-1", approvals=_two_approvals("VAULT_UPLOAD"))
        self.assertEqual(c1.exception.code, hv.VAULT_HASH_MISMATCH)
        self.assertEqual(store2.uploads, 0)

        store3 = FakeStore()
        store3.corrupt_metadata = True
        with self.assertRaises(hv.VaultOperationRefused) as c2:
            self._adapter(store=store3).transfer(self.src, self.entry, requester_id="OPERATOR-1", approvals=_two_approvals("VAULT_UPLOAD"))
        self.assertEqual(c2.exception.code, hv.VAULT_HASH_MISMATCH)

        with self.assertRaises(hv.VaultOperationRefused) as c3:
            self._adapter().transfer(
                self.src, replace(self.entry, kms_key_name=KMS_KEY + "x"), requester_id="OPERATOR-1",
                approvals=_two_approvals("VAULT_UPLOAD"),
            )
        self.assertEqual(c3.exception.code, hv.VAULT_MANIFEST_INVALID)

    def test_07_two_person_rule_and_no_self_approval(self) -> None:
        """Talep eden kendi talebini onaylayamaz; tek onay, aynı kişi iki kez veya tek rol yetmez."""
        A = hv.OperatorApproval
        cases = [
            (A("OPERATOR-1", "AUTHORIZED_CUSTODIAN", "VAULT_UPLOAD"), A("APPROVER-2", "CORPORATE_CLOUD_ADMIN", "VAULT_UPLOAD")),
            (A("APPROVER-2", "CORPORATE_CLOUD_ADMIN", "VAULT_UPLOAD"),),
            (A("APPROVER-2", "CORPORATE_CLOUD_ADMIN", "VAULT_UPLOAD"), A("APPROVER-2", "AUTHORIZED_CUSTODIAN", "VAULT_UPLOAD")),
            (A("APPROVER-2", "CORPORATE_CLOUD_ADMIN", "VAULT_UPLOAD"), A("APPROVER-3", "CORPORATE_CLOUD_ADMIN", "VAULT_UPLOAD")),
            (A("APPROVER-2", "CORPORATE_CLOUD_ADMIN", "OTHER"), A("APPROVER-3", "AUTHORIZED_CUSTODIAN", "OTHER")),
        ]
        for i, approvals in enumerate(cases):
            with self.subTest(i=i):
                store = FakeStore()
                with self.assertRaises(hv.VaultOperationRefused) as ctx:
                    self._adapter(store=store).transfer(self.src, self.entry, requester_id="OPERATOR-1", approvals=approvals)
                self.assertEqual(ctx.exception.code, hv.VAULT_SEPARATION_OF_DUTIES)
                self.assertEqual(store.uploads, 0)

    def test_08_restore_verification_and_audit_trail(self) -> None:
        """Geri yükleme depo dışı geçici dizine yapılır ve SHA-256 karşılaştırılır; audit log beklenmeyen erişimi yakalar."""
        store = FakeStore()
        audit = FakeAudit([
            {"method_name": "storage.objects.create", "principal": WRITER},
            {"method_name": "storage.objects.get", "principal": READER},
        ])
        adapter = self._adapter(store=store, audit=audit)
        res = adapter.transfer(self.src, self.entry, requester_id="OPERATOR-1", approvals=_two_approvals("VAULT_UPLOAD"))
        ok = hv.VaultRestoreVerifier(adapter).verify(self.entry, res.generation)
        self.assertEqual(ok["status"], "RESTORE_MATCHED_FOR_GENERATION")
        self.assertEqual(adapter.verify_audit_trail(self.entry)["status"], "AUDIT_TRAIL_CONSISTENT")

        store.corrupt_bytes = True
        with self.assertRaises(hv.VaultOperationRefused) as c1:
            hv.VaultRestoreVerifier(adapter).verify(self.entry, res.generation)
        self.assertEqual(c1.exception.code, hv.VAULT_RESTORE_FAILED)

        for entries in (
            [{"method_name": "storage.objects.create", "principal": WRITER}],
            [{"method_name": "storage.objects.create", "principal": "user:someone@test.invalid"},
             {"method_name": "storage.objects.get", "principal": READER}],
            [{"method_name": "storage.objects.create", "principal": WRITER},
             {"method_name": "storage.objects.get", "principal": WRITER}],
            [{"method_name": "storage.objects.create", "principal": WRITER},
             {"method_name": "storage.objects.get", "principal": READER},
             {"method_name": "storage.objects.delete", "principal": WRITER}],
        ):
            with self.subTest(entries=entries):
                with self.assertRaises(hv.VaultOperationRefused) as ctx:
                    self._adapter(audit=FakeAudit(entries)).verify_audit_trail(self.entry)
                self.assertEqual(ctx.exception.code, hv.VAULT_AUDIT_LOG_INCOMPLETE)

    # ------------------------------------------------------------------ manifest + historical reference
    def test_09_manifest_validator_rejects_substitution_and_tampering(self) -> None:
        """Migration manifesti tarihsel SHA-256/boyut/blob ile eşleşmeli; ikame ve kurcalama reddedilir."""
        entry = dict(self.entry.__dict__)
        man = hv.build_vault_manifest([entry], prepared_by_role="CORPORATE_CLOUD_ADMIN")
        validator = hv.VaultManifestValidator(self.ref)
        self.assertEqual(validator.validate(man)[0], self.entry)

        sub = hv.build_vault_manifest([{**entry, "sha256": "a" * 64}], prepared_by_role="X")
        with self.assertRaises(hv.VaultOperationRefused) as c1:
            validator.validate(sub)
        self.assertEqual(c1.exception.code, hv.VAULT_HASH_MISMATCH)
        tampered = {**man, "prepared_by_role": "SOMEONE_ELSE"}
        with self.assertRaises(hv.VaultOperationRefused) as c2:
            validator.validate(tampered)
        self.assertEqual(c2.exception.code, hv.VAULT_MANIFEST_INVALID)
        for bad in ({**entry, "extra": 1}, {**entry, "object_name": "../escape"}, {**entry, "size_bytes": 1},
                    {**entry, "vault_id": "OTHER"}, {**entry, "kms_key_name": "bad"}):
            with self.subTest(bad=sorted(bad)):
                with self.assertRaises(hv.VaultOperationRefused):
                    validator.validate(hv.build_vault_manifest([bad], prepared_by_role="X"))
        with self.assertRaises(hv.VaultOperationRefused):
            validator.validate(hv.build_vault_manifest([entry, entry], prepared_by_role="X"))

    def test_10_real_historical_reference_is_metadata_only_and_pinned(self) -> None:
        """Gerçek kasa referansı yalnız kayıt defteri + arşiv manifestinden gelir; HOLDOUT dosyası açılmaz."""
        reg = load_holdout_vault_registry()
        target = PROJECT_ROOT / reg.vaults[0].file_relpath
        with RegisteredVaultFileReadGuard([target]) as guard:
            ref = hv.load_historical_holdout_reference()
            real_entry = {
                "vault_id": ref.vault_id, "object_name": "holdout/v1.2/object", "sha256": ref.file_sha256,
                "size_bytes": ref.size_bytes, "git_blob_sha1": ref.git_blob_sha1, "kms_key_name": KMS_KEY,
            }
            hv.VaultManifestValidator(ref).validate(hv.build_vault_manifest([real_entry], prepared_by_role="X"))
            self.assertEqual(hv.package_exclusion_relpaths(reg), (reg.vaults[0].file_relpath,))
        self.assertEqual(guard.hits, [])
        self.assertEqual(ref.file_sha256, hv.HISTORICAL_HOLDOUT_FILE_SHA256)

        # A registry/manifest whose SHA-256 is replaced by a new value is refused.
        raw = json.loads(hv.DEFAULT_AUDIT_ARCHIVE_MANIFEST_PATH.read_text(encoding="utf-8"))
        for e in raw["entries"]:
            if e["file_name"] == ref.file_name:
                e["sha256"] = "c" * 64
        p = self.tmp / "manifest.json"
        p.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaises(hv.VaultOperationRefused) as ctx:
            hv.load_historical_holdout_reference(archive_manifest_path=p)
        self.assertEqual(ctx.exception.code, hv.VAULT_REFERENCE_INCONSISTENT)

    def test_11_package_exclusion_policy_fail_closed(self) -> None:
        """Kasa yolları paket hariç tutma listesine kayıt defterinden gelir; geçersiz yol veya boş liste reddedilir."""
        vault = SyntheticHoldoutVault(self.tmp / "v", (synthetic_holdout_case(_case("EVAL-085"), 1),))
        raw = json.loads(vault.registry_path.read_text(encoding="utf-8"))
        for bad_rel in ("/abs/path.json", "a/../../b.json"):
            raw["vaults"][0]["file_relpath"] = bad_rel
            vault.registry_path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaises(hv.VaultOperationRefused) as ctx:
                hv.package_exclusion_relpaths(load_holdout_vault_registry(vault.registry_path))
            self.assertEqual(ctx.exception.code, hv.VAULT_PACKAGE_EXCLUSION_INVALID)
        root = self.tmp / "pkg"
        (root / "data").mkdir(parents=True)
        (root / "data" / "keep.json").write_text("{}", encoding="utf-8")
        (root / "data" / "sealed.json").write_text("{}", encoding="utf-8")
        (root / "__pycache__").mkdir()
        (root / "__pycache__" / "x.pyc").write_bytes(b"")
        self.assertEqual(hv.plan_release_package(root, ["data/sealed.json"]), ["data/keep.json"])
        bad_pkg = root / hv.PACKAGE_EXCLUSION_MANIFEST_NAME
        bad_pkg.write_text(json.dumps({"schema": hv.PACKAGE_EXCLUSION_SCHEMA, "migration_state": "VERIFIED",
                                       "absence_means_migrated": True}), encoding="utf-8")
        with self.assertRaises(hv.VaultOperationRefused):
            hv.load_package_exclusion_manifest(root)

    # ------------------------------------------------------------------ Ledger v2 integration
    def _ledger_vault(self) -> SyntheticHoldoutVault:
        return SyntheticHoldoutVault(self.tmp / "lv", (synthetic_holdout_case(_case("EVAL-085"), 1),), max_runs=2)

    def test_12_external_checkpoint_signature_and_append_only(self) -> None:
        """Harici checkpoint: imza doğrulanır, ledger kesilir/yeniden yazılırsa veya sıra geri giderse reddedilir."""
        vault = self._ledger_vault()
        vault.grant(operator_id="AUDITOR-A")
        priv, pub = ephemeral_keypair("ED25519")
        led = HoldoutAccessLedger(ledger_path=vault.ledger_path)
        signer = lambda payload: sign_canonical_payload(payload, priv, "ED25519")  # noqa: E731
        cp1 = hv.create_ledger_checkpoint(led, signer=signer, signer_key_ref="synthetic-key", algorithm="ED25519",
                                          created_at_utc="2026-11-27T16:00:00Z")
        self.assertEqual(hv.verify_ledger_checkpoint(cp1, led, public_key_pem=pub)["status"], "CHECKPOINT_VERIFIED")
        vault.grant(operator_id="AUDITOR-B")  # ledger grows: still extends the checkpointed prefix
        hv.verify_ledger_checkpoint(cp1, led, public_key_pem=pub)
        cp2 = hv.create_ledger_checkpoint(led, signer=signer, signer_key_ref="synthetic-key", algorithm="ED25519",
                                          created_at_utc="2026-11-27T16:05:00Z")
        hv.verify_ledger_checkpoint(cp2, led, public_key_pem=pub, previous=cp1)
        with self.assertRaises(hv.VaultOperationRefused):
            hv.verify_ledger_checkpoint(cp1, led, public_key_pem=pub, previous=cp2)  # sequence regression
        with self.assertRaises(hv.VaultOperationRefused):
            hv.verify_ledger_checkpoint(replace(cp1, seq=cp1.seq + 5), led, public_key_pem=pub)  # signature breaks
        other_priv, other_pub = ephemeral_keypair("RSA-PSS-SHA256")
        with self.assertRaises(hv.VaultOperationRefused):
            hv.verify_ledger_checkpoint(cp1, led, public_key_pem=other_pub)

        # Rewrite the ledger as a capable forger would (re-hash/re-chain): the checkpoint anchor no longer matches.
        from engine.attestation_verifier import canonical_json_bytes
        from engine.evaluation import holdout_governance as hg

        records = [json.loads(x) for x in vault.ledger_path.read_text(encoding="utf-8").splitlines()]
        records[1]["operator_id"] = "FORGED"
        prev = hg.GENESIS_PREVIOUS_SHA256
        out = []
        for rec in records:
            rec["previous_record_hash"] = prev
            rec["record_hash"] = hg._record_hash({k: v for k, v in rec.items() if k != "record_hash"})
            prev = rec["record_hash"]
            out.append(canonical_json_bytes(rec) + b"\n")
        vault.ledger_path.write_bytes(b"".join(out))
        with self.assertRaises(hv.VaultOperationRefused) as ctx:
            hv.verify_ledger_checkpoint(cp1, led, public_key_pem=pub)
        self.assertEqual(ctx.exception.code, hv.VAULT_CHECKPOINT_INVALID)
        # Truncation is refused as well.
        vault.ledger_path.write_bytes(b"".join(out[:1]))
        with self.assertRaises(hv.VaultOperationRefused):
            hv.verify_ledger_checkpoint(cp2, led, public_key_pem=pub)

    def test_13_grant_validator_revocation_single_use_limits_and_separation(self) -> None:
        """Kasa erişim grant'i: ledger'da geçerli, iptal edilmemiş, kullanılmamış, checkpoint'li ve iki kişi onaylı olmalı."""
        vault = self._ledger_vault()
        priv, pub = ephemeral_keypair("ED25519")
        signer = lambda payload: sign_canonical_payload(payload, priv, "ED25519")  # noqa: E731
        led = HoldoutAccessLedger(ledger_path=vault.ledger_path)
        grant = vault.grant(operator_id="AUDITOR-A")
        cp = hv.create_ledger_checkpoint(led, signer=signer, signer_key_ref="k", algorithm="ED25519",
                                         created_at_utc="2026-11-27T16:00:00Z")
        validator = hv.VaultAccessGrantValidator(vault.gate())
        approvals = _two_approvals("VAULT_RESTORE_READ")
        ok = validator.validate_restore_access(grant, requester_id="AUDITOR-A", approvals=approvals,
                                               checkpoint=cp, checkpoint_public_key_pem=pub)
        self.assertEqual(ok["status"], "RESTORE_ACCESS_PERMITTED_PENDING_VAULT_READ_RECORD")

        with self.assertRaises(hv.VaultOperationRefused) as c_other:
            validator.validate_restore_access(grant, requester_id="AUDITOR-B", approvals=approvals,
                                              checkpoint=cp, checkpoint_public_key_pem=pub)
        self.assertEqual(c_other.exception.code, hv.VAULT_ACCESS_DENIED)
        self_approval = (hv.OperatorApproval("AUDITOR-A", "AUTHORIZED_CUSTODIAN", "VAULT_RESTORE_READ"), approvals[1])
        with self.assertRaises(hv.VaultOperationRefused) as c_self:
            validator.validate_restore_access(grant, requester_id="AUDITOR-A", approvals=self_approval,
                                              checkpoint=cp, checkpoint_public_key_pem=pub)
        self.assertEqual(c_self.exception.code, hv.VAULT_SEPARATION_OF_DUTIES)

        # Grant issued after the checkpoint is not anchored externally.
        grant2 = vault.grant(operator_id="AUDITOR-C")
        with self.assertRaises(hv.VaultOperationRefused) as c_cp:
            validator.validate_restore_access(grant2, requester_id="AUDITOR-C", approvals=approvals,
                                              checkpoint=cp, checkpoint_public_key_pem=pub)
        self.assertEqual(c_cp.exception.code, hv.VAULT_CHECKPOINT_INVALID)

        # Single use: after the recorded vault read the same grant cannot restore again.
        vault.gate().record_vault_read(grant, holdout_path=vault.vault_path)
        cp_after = hv.create_ledger_checkpoint(led, signer=signer, signer_key_ref="k", algorithm="ED25519",
                                               created_at_utc="2026-11-27T16:10:00Z")
        with self.assertRaises(hv.VaultOperationRefused) as c_used:
            validator.validate_restore_access(grant, requester_id="AUDITOR-A", approvals=approvals,
                                              checkpoint=cp_after, checkpoint_public_key_pem=pub)
        self.assertEqual(c_used.exception.code, hv.VAULT_ACCESS_DENIED)

        # Revoked grant is refused.
        vault.gate().revoke_grant(grant2, revoked_by="SYNTH-TEST-CUSTODIAN", reason="test")
        cp_rev = hv.create_ledger_checkpoint(led, signer=signer, signer_key_ref="k", algorithm="ED25519",
                                             created_at_utc="2026-11-27T16:20:00Z")
        with self.assertRaises(hv.VaultOperationRefused) as c_rev:
            validator.validate_restore_access(grant2, requester_id="AUDITOR-C", approvals=approvals,
                                              checkpoint=cp_rev, checkpoint_public_key_pem=pub)
        self.assertEqual(c_rev.exception.code, hv.VAULT_ACCESS_DENIED)

        # The custodian who signed the grant cannot also be the requester.
        v2 = SyntheticHoldoutVault(self.tmp / "lv2", (synthetic_holdout_case(_case("EVAL-085"), 1),), max_runs=1)
        g_self = v2.grant(operator_id=v2.custodian_id)
        led2 = HoldoutAccessLedger(ledger_path=v2.ledger_path)
        cp_self = hv.create_ledger_checkpoint(led2, signer=signer, signer_key_ref="k", algorithm="ED25519",
                                              created_at_utc="2026-11-27T16:30:00Z")
        with self.assertRaises(hv.VaultOperationRefused) as c_cust:
            hv.VaultAccessGrantValidator(v2.gate()).validate_restore_access(
                g_self, requester_id=v2.custodian_id, approvals=approvals, checkpoint=cp_self, checkpoint_public_key_pem=pub
            )
        self.assertEqual(c_cust.exception.code, hv.VAULT_SEPARATION_OF_DUTIES)

    # ------------------------------------------------------------------ static hygiene + documents
    def test_14_no_cloud_clients_credentials_or_holdout_literals(self) -> None:
        """Modül gerçek GCP istemcisi içe aktarmaz; depoda servis hesabı anahtarı yok; HOLDOUT yolu/ID kopyalanmaz."""
        src = (PROJECT_ROOT / "engine" / "evaluation" / "holdout_vault.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        imported = {n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        imported |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        self.assertFalse(any(m.startswith(("google", "googleapiclient", "requests", "urllib", "http")) for m in imported))
        reg = load_holdout_vault_registry()
        holdout_name = Path(reg.vaults[0].file_relpath).name
        self.assertNotIn(holdout_name, src)
        for p in sorted(PROJECT_ROOT.rglob("*.json")):
            if p.resolve() == (PROJECT_ROOT / reg.vaults[0].file_relpath).resolve():
                continue  # never opened
            txt = p.read_text(encoding="utf-8", errors="replace")
            self.assertNotIn('"type": "service_account"', txt, str(p))
            self.assertNotIn('"private_key_id"', txt, str(p))

    def test_15_vault_documents_separate_status_from_target_and_leak_no_case_ids(self) -> None:
        """7 WP-4.6 kasa belgesi mevcut; mevcut durum ve hedef mimari ayrı; HOLDOUT vaka kimliği yok; bölge seçilmemiş."""
        dev_val_ids = {c.case_id for c in load_dev_val_dataset().cases}
        for name in VAULT_DOCS:
            with self.subTest(doc=name):
                text = (DOCS / name).read_text(encoding="utf-8")
                self.assertIn("PREPARATION_COMPLETE ≠ VAULT_PROVISIONED ≠ MIGRATION_VERIFIED", text)
                self.assertIn("NOT_CREATED", text)
                self.assertIn("UNDECIDED", text)
                self.assertEqual(sorted(set(re.findall(r"EVAL-\d{3}", text)) - dev_val_ids), [])
                self.assertNotIn("file:///", text)
                self.assertNotRegex(text, r"/home/[a-z]")
                self.assertNotRegex(text, r"(?i)data_region\s*[:=]\s*`?(europe|eu|us|asia|me)-")


if __name__ == "__main__":
    unittest.main()
