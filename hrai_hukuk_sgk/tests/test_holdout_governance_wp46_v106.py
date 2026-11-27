"""WP-4.6 HOLDOUT governance tests: CI isolation, unauthorised access, missing/tampered ledger,
concurrent access, access limits and audit records.

None of these tests parses or evaluates the real (consumed) HOLDOUT vault. The only operations on
its file are a raw-byte SHA-256 comparison and assertions that the file is NOT read on denied paths.
Positive access paths use synthetic vaults from `tests/holdout_test_support.py`.
"""

from __future__ import annotations

import builtins
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import io
import json
import multiprocessing
import os
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from unittest import mock

from engine.answer import HukukSgkAnswerOrchestrator
from engine.evaluation import (
    DEFAULT_HOLDOUT_PATH,
    DEFAULT_HOLDOUT_REGISTRY_PATH,
    OFFICIAL_STATUS_PASSED,
    SPLIT_HOLDOUT,
    VAULT_STATUS_CONSUMED,
    EvaluationDataset,
    HoldoutAccessDenied,
    HoldoutAccessGate,
    HoldoutAccessGrant,
    HoldoutAccessLedger,
    HoldoutLedgerIntegrityError,
    HukukSgkEvaluationRunner,
    TrustedLegalApproverRecord,
    TrustedLegalApproverRegistry,
    compute_public_key_fingerprint,
    create_signed_answer_key_approval_envelope,
    detect_ci_environment,
    load_dev_val_dataset,
    load_evaluation_dataset,
    load_holdout_vault_registry,
    sha256_file_bytes,
)
from engine.evaluation import holdout_governance as hg
from engine.evaluation.holdout_vault import (
    load_historical_holdout_reference,
    load_package_exclusion_manifest,
    verify_holdout_git_metadata,
)
from engine.rag import HukukSgkRagEngine

from tests.holdout_test_support import SyntheticHoldoutVault, ephemeral_keypair, synthetic_holdout_case

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REAL_VAULT_ID = "HOLDOUT-WP45-V1.2-30-SEALED-20261126"
REAL_VAULT_FILE_SHA256 = "b809245fa04ee6de2daf4189c115ba03860b1bd54213dfc88b86ce7a1625730f"

_SHARED: dict[str, object] = {}


def _dev_val():
    if "ds" not in _SHARED:
        _SHARED["ds"] = load_dev_val_dataset()
    return _SHARED["ds"]


def _runner() -> HukukSgkEvaluationRunner:
    if "runner" not in _SHARED:
        _SHARED["runner"] = HukukSgkEvaluationRunner(
            rag_engine=HukukSgkRagEngine.from_project_root(project_root=PROJECT_ROOT),
            answer_orchestrator=HukukSgkAnswerOrchestrator.from_project_root(project_root=PROJECT_ROOT),
            project_root=PROJECT_ROOT,
        )
    return _SHARED["runner"]  # type: ignore[return-value]


def _case(case_id: str):
    return next(c for c in _dev_val().cases if c.case_id == case_id)


class _HoldoutReadTracker:
    """Records every attempt to open/read the real HOLDOUT file through common file APIs."""

    def __init__(self) -> None:
        self.target = DEFAULT_HOLDOUT_PATH.resolve()
        self.hits: list[str] = []
        self._patches: list[mock._patch] = []

    def _check(self, p: object, api: str) -> None:
        try:
            if Path(os.fspath(p)).resolve() == self.target:  # type: ignore[arg-type]
                self.hits.append(api)
        except TypeError:
            pass

    def __enter__(self) -> "_HoldoutReadTracker":
        real_open = builtins.open
        real_read_text = Path.read_text
        real_read_bytes = Path.read_bytes
        real_os_open = os.open
        tracker = self

        def t_open(file, *a, **k):
            tracker._check(file, "open")
            return real_open(file, *a, **k)

        def t_read_text(self_p, *a, **k):
            tracker._check(self_p, "read_text")
            return real_read_text(self_p, *a, **k)

        def t_read_bytes(self_p, *a, **k):
            tracker._check(self_p, "read_bytes")
            return real_read_bytes(self_p, *a, **k)

        def t_os_open(path, *a, **k):
            tracker._check(path, "os.open")
            return real_os_open(path, *a, **k)

        self._patches = [
            mock.patch("builtins.open", t_open),
            mock.patch.object(Path, "read_text", t_read_text),
            mock.patch.object(Path, "read_bytes", t_read_bytes),
            mock.patch("os.open", t_os_open),
        ]
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc: object) -> None:
        for p in reversed(self._patches):
            p.stop()


def _race_authorize(args: tuple[str, str, dict, object]) -> str:
    """Child process: wait for the start signal, then try to obtain a grant."""
    registry_path, ledger_path, req_dict, start_evt = args
    from engine.evaluation import HoldoutAccessGate as _Gate, HoldoutAccessRequest as _Req

    start_evt.wait(30)  # type: ignore[attr-defined]
    gate = _Gate(registry_path=registry_path, ledger_path=ledger_path, environment={})
    try:
        gate.authorize(_Req(**req_dict))
        return "GRANTED"
    except HoldoutAccessDenied as exc:
        return exc.code


class TestHoldoutGovernanceWp46(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="wp46_")
        self.tmp = Path(self._td.name)

    def tearDown(self) -> None:
        self._td.cleanup()

    def _vault(self, name: str = "vault", cases: tuple | None = None, **kw) -> SyntheticHoldoutVault:
        cases = cases if cases is not None else (synthetic_holdout_case(_case("EVAL-085"), 1),)
        return SyntheticHoldoutVault(self.tmp / name, cases, **kw)

    # ------------------------------------------------------------------ CI isolation
    def test_01_normal_flow_never_reads_holdout_bytes(self) -> None:
        """Varsayılan yükleme ve DEV/VAL yüklemesi HOLDOUT dosyasına hiç dokunmaz."""
        with _HoldoutReadTracker() as tr:
            ds_default = load_evaluation_dataset()
            ds_dv = load_dev_val_dataset()
        self.assertEqual(tr.hits, [])
        for ds in (ds_default, ds_dv):
            self.assertEqual(len(ds.cases), 70)
            self.assertFalse(any(c.split == SPLIT_HOLDOUT for c in ds.cases))
            self.assertIsNone(ds.holdout_sha256)

    def test_02_real_vault_registered_as_consumed_and_byte_pinned(self) -> None:
        """Mevcut 30 vakalık kasa CONSUMED, grant verilemez, emanetçi yok; dosya baytları değişmemiş."""
        reg = load_holdout_vault_registry()
        vault = reg.vault(REAL_VAULT_ID)
        self.assertIsNotNone(vault)
        assert vault is not None
        self.assertEqual(vault.status, VAULT_STATUS_CONSUMED)
        self.assertEqual(vault.max_authorized_runs, 0)
        self.assertEqual(vault.case_count, 30)
        self.assertEqual(reg.custodians, ())
        self.assertEqual(vault.file_sha256, REAL_VAULT_FILE_SHA256)
        # WP-4.6 vault preparation: byte pinning via metadata only (registry + archive manifest + Git blob
        # id); the HOLDOUT file is not read and is absent from release packages / the CI clean extract.
        ref = load_historical_holdout_reference()
        self.assertEqual(ref.file_sha256, REAL_VAULT_FILE_SHA256)
        git_meta = verify_holdout_git_metadata(PROJECT_ROOT, vault.file_relpath, ref.git_blob_sha1)
        if git_meta["mode"] == "GIT":
            self.assertEqual(git_meta["working_tree"], "SIZE_MATCHES_HISTORICAL_REFERENCE")
        else:
            pkg = load_package_exclusion_manifest(PROJECT_ROOT)
            self.assertIsNotNone(pkg, "Git dışı paket/extract PACKAGE_EXCLUSION_MANIFEST içermeli (ci.release_package_policy).")
            assert pkg is not None
            self.assertEqual({e["registered_sha256"] for e in pkg["excluded"]}, {REAL_VAULT_FILE_SHA256})

        raw = reg.raw["vaults"][0]
        ev_path = PROJECT_ROOT / raw["consumption_evidence_relpath"]
        self.assertEqual(sha256_file_bytes(ev_path), raw["consumption_evidence_sha256"])
        evidence = json.loads(ev_path.read_text(encoding="utf-8"))
        self.assertEqual(evidence["prior_access_records"]["status"], "NOT_FOUND")
        self.assertEqual(
            {b["code"] for b in evidence["blindness_breaches"]},
            {
                "CI_NON_BLIND_EVALUATION",
                "TEST_ASSERTIONS_DEPEND_ON_HOLDOUT",
                "SPEC_ROOT_CAUSE_DISCLOSURE",
                "PRE_REMEDIATION_HOLDOUT_MEASUREMENT",
                "NON_PERSISTENT_ACCESS_LEDGER",
                "WP46_PRE_CHANGE_SUITE_EXECUTION",
            },
        )
        for p in (DEFAULT_HOLDOUT_REGISTRY_PATH, ev_path):
            self.assertNotIn(b"PRIVATE KEY", p.read_bytes())

    def test_03_static_scan_no_holdout_path_in_tests_or_ci(self) -> None:
        """Test ve motor kodunda HOLDOUT dosyasına/tam yüklemeye yetkisiz başvuru yok; CI iş akışı HOLDOUT içermez."""
        allowed = {
            Path("engine/evaluation/dataset_loader.py"),
            Path("engine/evaluation/__init__.py"),
            Path("tests/test_holdout_governance_wp46_v106.py"),
        }
        patterns = [
            re.compile(r"eval_holdout_30_sealed"),
            re.compile(r"DEFAULT_HOLDOUT_PATH"),
            re.compile(r"include_holdout\s*=\s*True"),
        ]
        offenders: list[str] = []
        for sub in ("tests", "engine"):
            for py in sorted((PROJECT_ROOT / sub).rglob("*.py")):
                rel = py.relative_to(PROJECT_ROOT)
                if rel in allowed:
                    continue
                text = py.read_text(encoding="utf-8")
                for pat in patterns:
                    if pat.search(text):
                        offenders.append(f"{rel}:{pat.pattern}")
        self.assertEqual(offenders, [])

        wf = PROJECT_ROOT.parent / ".github" / "workflows" / "ci-assurance.yml"
        if wf.is_file():  # absent in the CI clean-extract working directory
            self.assertNotIn("holdout", wf.read_text(encoding="utf-8").lower())

    def test_04_ci_environment_always_denied(self) -> None:
        """CI ortamında geçerli imzalı istek bile reddedilir; loader ve runner da reddeder."""
        vault = self._vault()
        for env in ({"GITHUB_ACTIONS": "true"}, {"CI": "1"}, {"GITLAB_CI": "yes"}):
            with self.assertRaises(HoldoutAccessDenied) as ctx:
                vault.gate(environment=env).authorize(vault.request())
            self.assertEqual(ctx.exception.code, hg.DENY_CI_ENVIRONMENT)
        self.assertIsNone(detect_ci_environment({"CI": "false"}))
        self.assertEqual(detect_ci_environment({"GITHUB_ACTIONS": "true"}), "GITHUB_ACTIONS")

        grant = vault.grant()  # local (non-CI) grant
        ci_gate = vault.gate(environment={"CI": "true"})
        with self.assertRaises(HoldoutAccessDenied) as ctx_load:
            load_evaluation_dataset(
                vault.vault_path, holdout_access_grant=grant, holdout_gate=ci_gate,
                enforce_target_counts=False, enforce_anti_leakage=False,
            )
        self.assertEqual(ctx_load.exception.code, hg.DENY_CI_ENVIRONMENT)
        ds = EvaluationDataset("ci", "2026-11-27T00:00:00Z", vault.cases, "ci")
        with self.assertRaises(HoldoutAccessDenied) as ctx_run:
            _runner().run_suite(ds, holdout_access_grant=grant, holdout_gate=ci_gate)
        self.assertEqual(ctx_run.exception.code, hg.DENY_CI_ENVIRONMENT)

    # ------------------------------------------------------------------ unauthorised access
    def test_05_unauthorised_real_vault_access_denied_before_any_read(self) -> None:
        """Gerçek kasaya grant'siz, sahte grant'li veya imzalı istekle erişim dosya okunmadan reddedilir."""
        ledger_path = self.tmp / "real" / "ledger.jsonl"
        HoldoutAccessLedger.initialize(ledger_path=ledger_path, ledger_id="REAL-CHECK", created_by="wp46-test")

        with _HoldoutReadTracker() as tr:
            with self.assertRaises(HoldoutAccessDenied) as c1:
                load_evaluation_dataset(include_holdout=True)
            self.assertEqual(c1.exception.code, hg.DENY_NO_GRANT)

            forged = HoldoutAccessGrant(
                grant_id="GRANT-FORGED", vault_id=REAL_VAULT_ID, vault_file_sha256=REAL_VAULT_FILE_SHA256,
                case_set_sha256="0" * 64, dataset_version="x", ledger_path=str(ledger_path), ledger_id="REAL-CHECK",
                grant_record_sha256="0" * 64, operator_id="DEV", purpose="FINAL_BLIND_VERIFICATION",
                access_number=1, max_authorized_runs=1,
            )
            gate = HoldoutAccessGate(ledger_path=ledger_path, environment={})
            with self.assertRaises(HoldoutAccessDenied) as c2:
                load_evaluation_dataset(include_holdout=True, holdout_access_grant=forged, holdout_gate=gate)
            self.assertEqual(c2.exception.code, hg.DENY_VAULT_CONSUMED)

            priv, _ = ephemeral_keypair("ED25519")
            req = hg.HoldoutAccessRequest(
                request_id="REQ-REAL-1", vault_id=REAL_VAULT_ID, vault_file_sha256=REAL_VAULT_FILE_SHA256,
                purpose="FINAL_BLIND_VERIFICATION", operator_id="DEV", custodian_id="NOBODY", key_id="K",
                algorithm="ED25519", requested_at_utc="2026-11-27T00:00:00Z",
                expires_at_utc="2026-11-27T01:00:00Z", nonce="N-REAL-1",
            )
            with self.assertRaises(HoldoutAccessDenied) as c3:
                gate.authorize(req)
            self.assertEqual(c3.exception.code, hg.DENY_VAULT_CONSUMED)
        self.assertEqual(tr.hits, [])

        # Explicit dataset_path pointing at a registered vault: refused after a raw-byte hash, never parsed.
        # WP-4.6 vault preparation: exercised on a synthetic registered vault (the real HOLDOUT file is not
        # read by tests and is excluded from release packages / the CI clean extract).
        synth = self._vault(name="explicit_path_vault")
        tr2 = _HoldoutReadTracker()
        tr2.target = synth.vault_path.resolve()
        with mock.patch.object(hg, "DEFAULT_HOLDOUT_REGISTRY_PATH", synth.registry_path), tr2:
            with self.assertRaises(HoldoutAccessDenied) as c4:
                load_evaluation_dataset(synth.vault_path, enforce_target_counts=False, enforce_anti_leakage=False)
        self.assertEqual(c4.exception.code, hg.DENY_NO_GRANT)
        self.assertEqual(tr2.hits, ["read_bytes"])  # yalnız ham bayt özeti; read_text/JSON ayrıştırma yok

        denied = [r for r in HoldoutAccessLedger(ledger_path=ledger_path).verify() if r["event_type"] == "ACCESS_DENIED"]
        self.assertEqual([r["decision_code"] for r in denied], [hg.DENY_VAULT_CONSUMED])
        self.assertEqual(denied[0]["dataset_id"], REAL_VAULT_ID)

    def test_06_consumed_status_blocks_even_valid_custodian(self) -> None:
        """Kasa CONSUMED işaretlenince geçerli emanetçi imzası da grant üretemez; HOLDOUT içeren dosya grant'siz yüklenemez."""
        vault = self._vault(max_runs=0, status=VAULT_STATUS_CONSUMED)
        with self.assertRaises(HoldoutAccessDenied) as ctx:
            vault.grant()
        self.assertEqual(ctx.exception.code, hg.DENY_VAULT_CONSUMED)

        other = self.tmp / "unregistered_holdout.json"
        payload = json.loads(vault.vault_path.read_text(encoding="utf-8"))
        payload["note"] = "bytes differ from registered vault"
        other.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        with self.assertRaises(HoldoutAccessDenied) as ctx2:
            load_evaluation_dataset(other, enforce_target_counts=False, enforce_anti_leakage=False)
        self.assertEqual(ctx2.exception.code, hg.DENY_NO_GRANT)

    # ------------------------------------------------------------------ ledger absence
    def test_07_missing_or_unconfigured_ledger_fails_closed(self) -> None:
        """Ledger yolu yok, dosya yok veya depo içinde: erişim reddedilir; mevcut ledger üzerine yazılamaz."""
        vault = self._vault(initialize_ledger=False)
        cases = [
            (HoldoutAccessGate(registry_path=vault.registry_path, environment={}), hg.DENY_LEDGER_NOT_CONFIGURED),
            (vault.gate(), hg.DENY_LEDGER_MISSING),
            (vault.gate(ledger_path=PROJECT_ROOT / "holdout_ledger_in_repo.jsonl"), hg.DENY_LEDGER_INSIDE_REPOSITORY),
        ]
        for gate, code in cases:
            with self.assertRaises(HoldoutAccessDenied) as ctx:
                gate.authorize(vault.request())
            self.assertEqual(ctx.exception.code, code)
        self.assertFalse((PROJECT_ROOT / "holdout_ledger_in_repo.jsonl").exists())
        with self.assertRaises(HoldoutAccessDenied) as ctx_none:
            HoldoutAccessLedger(ledger_path="")
        self.assertEqual(ctx_none.exception.code, hg.DENY_LEDGER_NOT_CONFIGURED)

        HoldoutAccessLedger.initialize(ledger_path=vault.ledger_path, ledger_id="L1", created_by="t")
        before = vault.ledger_path.read_bytes()
        with self.assertRaises(HoldoutLedgerIntegrityError):
            HoldoutAccessLedger.initialize(ledger_path=vault.ledger_path, ledger_id="L2", created_by="t")
        self.assertEqual(vault.ledger_path.read_bytes(), before)

    # ------------------------------------------------------------------ ledger integrity
    def test_08_ledger_tampering_detected_and_access_refused(self) -> None:
        """Alan değişikliği, satır silme/sıralama, kesik yazım, kanonik olmayan biçim ve ikinci GENESIS reddedilir."""
        vault = self._vault(max_runs=3)
        vault.grant()
        with self.assertRaises(HoldoutAccessDenied):
            vault.grant(purpose="DEBUG_TUNING")
        vault.grant()
        original = vault.ledger_path.read_bytes()
        lines = original.decode("utf-8").splitlines(keepends=True)
        self.assertEqual(len(lines), 4)

        def edit_field(ls):
            rec = json.loads(ls[1])
            rec["decision_code"] = "HOLDOUT_ACCESS_DENIED_NO_GRANT"
            ls[1] = json.dumps(rec, separators=(",", ":"), sort_keys=True, ensure_ascii=False) + "\n"
            return ls

        def rehash_middle(ls):
            rec = json.loads(ls[1])
            rec["operator_id"] = "SOMEONE-ELSE"
            body = {k: v for k, v in rec.items() if k != "record_hash"}
            rec["record_hash"] = hg._record_hash(body)
            from engine.attestation_verifier import canonical_json_bytes

            ls[1] = canonical_json_bytes(rec).decode("utf-8") + "\n"
            return ls

        def second_genesis(ls):
            return ls + [ls[0]]

        tampers = {
            "edit_field": edit_field,
            "rehash_middle_record_breaks_chain": rehash_middle,
            "delete_middle_line": lambda ls: [ls[0], ls[2], ls[3]],
            "reorder_lines": lambda ls: [ls[0], ls[2], ls[1], ls[3]],
            "truncate_last_line": lambda ls: ls[:-1] + [ls[-1][:-15]],
            "non_canonical_whitespace": lambda ls: [ls[0], ls[1].replace(",", ", ", 1), ls[2], ls[3]],
            "duplicate_genesis": second_genesis,
            "empty_file": lambda ls: [],
        }
        for name, fn in tampers.items():
            with self.subTest(tamper=name):
                vault.ledger_path.write_bytes("".join(fn(list(lines))).encode("utf-8"))
                with self.assertRaises(HoldoutLedgerIntegrityError):
                    HoldoutAccessLedger(ledger_path=vault.ledger_path).verify()
                with self.assertRaises(HoldoutAccessDenied) as ctx:
                    vault.grant()
                self.assertEqual(ctx.exception.code, hg.DENY_LEDGER_INTEGRITY)
        vault.ledger_path.write_bytes(original)
        seq, head = HoldoutAccessLedger(ledger_path=vault.ledger_path).head()
        self.assertEqual(seq, 3)
        self.assertEqual(len(head), 64)

    # ------------------------------------------------------------------ concurrency & limits
    def test_09_concurrent_requests_respect_limit_atomically(self) -> None:
        """8 eş zamanlı süreç: max_authorized_runs=1 -> tam 1 grant; =3 -> tam 3 grant; zincir geçerli."""
        ctx_name = "fork" if "fork" in multiprocessing.get_all_start_methods() else "spawn"
        mp = multiprocessing.get_context(ctx_name)
        for limit in (1, 3):
            with self.subTest(limit=limit):
                vault = self._vault(f"race_{limit}", max_runs=limit)
                reqs = [vault.request() for _ in range(8)]
                mgr = mp.Manager()
                try:
                    evt = mgr.Event()
                    with mp.Pool(8) as pool:
                        async_res = pool.map_async(
                            _race_authorize,
                            [(str(vault.registry_path), str(vault.ledger_path), r.__dict__, evt) for r in reqs],
                        )
                        evt.set()
                        results = async_res.get(timeout=120)
                finally:
                    mgr.shutdown()
                self.assertEqual(results.count("GRANTED"), limit, msg=results)
                self.assertEqual(results.count(hg.DENY_LIMIT_EXCEEDED), 8 - limit, msg=results)
                recs = vault.ledger_records()
                self.assertEqual(len(recs), 1 + 8)
                self.assertEqual(sum(r["event_type"] == "ACCESS_GRANTED" for r in recs), limit)
                self.assertEqual(sorted(r["details"]["access_number"] for r in recs if r["event_type"] == "ACCESS_GRANTED"),
                                 [str(i) for i in range(1, limit + 1)])

    def test_10_signature_custodian_time_and_replay_controls(self) -> None:
        """İmza, emanetçi, anahtar, zaman penceresi, kasa özeti ve tekrar (replay) kontrolleri fail-closed."""
        vault = self._vault(max_runs=5)
        gate = vault.gate()
        other_priv, _ = ephemeral_keypair("RSA-PSS-SHA256")
        old = datetime.now(timezone.utc) - timedelta(hours=3)
        checks = [
            (vault.request(sign=False), hg.DENY_SIGNATURE_INVALID),
            (replace(vault.request(), operator_id="TAMPERED-AFTER-SIGNING"), hg.DENY_SIGNATURE_INVALID),
            (vault.request(custodian_id="UNKNOWN-CUSTODIAN"), hg.DENY_CUSTODIAN_UNKNOWN),
            (vault.request(key_id="OTHER-KEY"), hg.DENY_CUSTODIAN_KEY_MISMATCH),
            (vault.request(requested_at=old), hg.DENY_REQUEST_TIME_INVALID),
            (vault.request(validity=timedelta(hours=30)), hg.DENY_REQUEST_TIME_INVALID),
            (vault.request(vault_file_sha256="f" * 64), hg.DENY_VAULT_HASH_MISMATCH),
            (vault.request(vault_id="NO-SUCH-VAULT"), hg.DENY_VAULT_UNKNOWN),
            (vault.request(purpose="CALIBRATION_RUN"), hg.DENY_PURPOSE_FORBIDDEN),
        ]
        for req, code in checks:
            with self.subTest(code=code, req=req.request_id):
                with self.assertRaises(HoldoutAccessDenied) as ctx:
                    gate.authorize(req)
                self.assertEqual(ctx.exception.code, code)
        self.assertTrue(other_priv)

        good = vault.request(request_id="REQ-REPLAY", nonce="NONCE-REPLAY")
        gate.authorize(good)
        with self.assertRaises(HoldoutAccessDenied) as ctx_rep:
            gate.authorize(good)
        self.assertEqual(ctx_rep.exception.code, hg.DENY_REQUEST_REPLAY)

        vault.write_registry(status="SEALED_AVAILABLE", max_runs=5, custodian_status="REVOKED")
        with self.assertRaises(HoldoutAccessDenied) as ctx_rev:
            gate.authorize(vault.request())
        self.assertEqual(ctx_rev.exception.code, hg.DENY_CUSTODIAN_INACTIVE)

        rsa_vault = self._vault("rsa", algorithm="RSA-PSS-SHA256")
        self.assertEqual(rsa_vault.grant().access_number, 1)

    # ------------------------------------------------------------------ audit trail & end-to-end
    def test_11_audit_records_and_single_use_vault_read(self) -> None:
        """Grant -> VAULT_READ -> RUN_STARTED -> RUN_COMPLETED kayıtları eksiksiz; okuma tek kullanımlık; bayt değişikliği reddedilir."""
        c_syn = synthetic_holdout_case(_case("EVAL-094"), 2)
        vault = self._vault("e2e", cases=(c_syn,))
        gate = vault.gate()
        grant = vault.grant(operator_id="AUDITOR-E2E")

        ds = load_evaluation_dataset(
            vault.vault_path, holdout_access_grant=grant, holdout_gate=gate,
            enforce_target_counts=False, enforce_anti_leakage=False,
        )
        self.assertEqual([c.case_id for c in ds.cases], ["SYNTH-HO-02"])
        self.assertEqual(ds.holdout_sha256, vault.case_set_sha256)
        with self.assertRaises(HoldoutAccessDenied) as ctx_twice:
            load_evaluation_dataset(
                vault.vault_path, holdout_access_grant=grant, holdout_gate=gate,
                enforce_target_counts=False, enforce_anti_leakage=False,
            )
        self.assertEqual(ctx_twice.exception.code, hg.DENY_GRANT_ALREADY_USED)

        rpt = _runner().run_suite(ds, holdout_access_grant=grant, holdout_gate=gate)
        self.assertTrue(rpt.blind_holdout_mode)
        self.assertEqual(rpt.holdout_redacted_count, 1)
        self.assertTrue(all(r.case_id.startswith("HOLDOUT-MASKED-") for r in rpt.case_reports))

        recs = vault.ledger_records()
        self.assertEqual(
            [r["event_type"] for r in recs],
            ["GENESIS", "ACCESS_GRANTED", "VAULT_READ", "RUN_STARTED", "RUN_COMPLETED"],
        )
        g = recs[1]
        self.assertEqual(g["operator_id"], "AUDITOR-E2E")
        self.assertEqual(g["custodian_id"], vault.custodian_id)
        self.assertEqual(g["purpose"], "FINAL_BLIND_VERIFICATION")
        self.assertEqual(g["dataset_sha256"], vault.file_sha256)
        self.assertEqual(g["details"]["case_set_sha256"], vault.case_set_sha256)
        self.assertEqual(g["signature_algorithm"], "ED25519")
        self.assertEqual(g["signature_key_id"], vault.key_id)
        self.assertTrue(g["signature"])
        self.assertTrue(all(r["grant_id"] == grant.grant_id for r in recs[1:]))
        self.assertEqual(recs[2]["details"]["file_sha256"], vault.file_sha256)
        self.assertEqual(recs[4]["details"]["run_manifest_sha256"], rpt.run_manifest.manifest_sha256)
        self.assertEqual(recs[4]["details"]["holdout_redacted_count"], "1")
        for prev, cur in zip(recs, recs[1:]):
            self.assertEqual(cur["previous_record_hash"], prev["record_hash"])

        # Vault bytes changed after registration -> refused before parsing.
        vault2 = self._vault("mutated", cases=(c_syn,))
        grant2 = vault2.grant()
        vault2.vault_path.write_text(vault2.vault_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        with self.assertRaises(HoldoutAccessDenied) as ctx_mut:
            load_evaluation_dataset(
                vault2.vault_path, holdout_access_grant=grant2, holdout_gate=vault2.gate(),
                enforce_target_counts=False, enforce_anti_leakage=False,
            )
        self.assertEqual(ctx_mut.exception.code, hg.DENY_VAULT_HASH_MISMATCH)

    def test_12_runner_refuses_before_evaluating_any_holdout_case(self) -> None:
        """Grant yoksa veya vaka kümesi kayıtlı kasayla aynı değilse hiçbir vaka değerlendirilmez."""
        c_a = synthetic_holdout_case(_case("EVAL-085"), 3)
        c_b = synthetic_holdout_case(_case("EVAL-094"), 4)
        vault = self._vault("set", cases=(c_a,))
        runner = _runner()
        calls: list[str] = []
        real_eval = runner.evaluate_case

        def counting(case, **kw):
            calls.append(case.case_id)
            return real_eval(case, **kw)

        with mock.patch.object(runner, "evaluate_case", side_effect=counting):
            ds_none = EvaluationDataset("x", "2026-11-27T00:00:00Z", (_case("EVAL-001"), c_a), "x")
            with self.assertRaises(HoldoutAccessDenied) as c1:
                runner.run_suite(ds_none)
            self.assertEqual(c1.exception.code, hg.DENY_NO_GRANT)

            grant = vault.grant()
            ds_other = EvaluationDataset("x", "2026-11-27T00:00:00Z", (c_a, c_b), "x")
            with self.assertRaises(HoldoutAccessDenied) as c2:
                runner.run_suite(ds_other, holdout_access_grant=grant, holdout_gate=vault.gate())
            self.assertEqual(c2.exception.code, hg.DENY_CASE_SET_MISMATCH)
        self.assertEqual(calls, [])

    def test_13_no_official_pass_without_new_holdout(self) -> None:
        """HOLDOUT olmadan (tüm DEV/VAL vakaları imzalı olsa bile) resmî PASSED üretilemez."""
        priv, pub = ephemeral_keypair("ED25519")
        fp = compute_public_key_fingerprint(pub)
        reg = TrustedLegalApproverRegistry(
            registry_version="wp46-synthetic",
            approvers=(
                TrustedLegalApproverRecord(
                    approver_id="SYNTH-COUNSEL", approver_role="INDEPENDENT_LABOR_LAW_COUNSEL",
                    bar_association_ref="SYNTHETIC-TEST-ONLY", enrollment_status="ENROLLED", key_id="SYNTH-K",
                    key_version="v1", algorithm="ED25519", public_key_pem=pub, public_key_fingerprint_sha256=fp,
                    valid_from_utc="2026-01-01T00:00:00Z", valid_until_utc="2027-12-31T23:59:59Z",
                ),
            ),
        )
        cases = (_case("EVAL-001"), _case("EVAL-085"), _case("EVAL-091"))
        envs = tuple(
            create_signed_answer_key_approval_envelope(
                case=c, dataset_version="wp46", envelope_id=f"ENV-WP46-{i}", nonce=f"nonce-wp46-{i:04d}",
                approver_id="SYNTH-COUNSEL", approver_role="INDEPENDENT_LABOR_LAW_COUNSEL", key_id="SYNTH-K",
                key_version="v1", algorithm="ED25519", private_key_pem=priv, public_key_fingerprint_sha256=fp,
                signed_at_utc="2026-11-27T00:00:00Z", legal_rationale="Sentetik test zarfı (resmî onay değildir).",
            )
            for i, c in enumerate(cases)
        )
        ds = EvaluationDataset("wp46", "2026-11-27T00:00:00Z", cases, "wp46")
        rpt = _runner().run_suite(ds, legal_signoff_envelopes=envs, approver_registry=reg)
        off = rpt.official_benchmark_metrics
        self.assertEqual(rpt.approval_coverage.approved_cases_count, 3)
        self.assertIsNone(off.official_holdout_weighted_index)
        self.assertNotEqual(off.official_status, OFFICIAL_STATUS_PASSED)
        self.assertFalse(off.official_pass_eligible)
        self.assertTrue(any("HOLDOUT" in b for b in off.blocking_reasons))
        self.assertIsNone(rpt.holdout_access_audit)


if __name__ == "__main__":
    unittest.main()
