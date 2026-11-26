"""WP-4.5 v1.2 Verification Suite (K-01..K-03, Y-01..Y-05, O-01..O-05, and 100-Case Diagnostic Suite)."""

from __future__ import annotations

import ast
import base64
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from engine.answer import AnswerGenerationRequest, EightSectionAnswer, HukukSgkAnswerOrchestrator
from engine.attestation_verifier import canonical_json_bytes, sign_canonical_payload, verify_asymmetric_signature
from engine.evaluation import (
    ACTION_APPROVE,
    ACTION_OVERRIDE_FATAL,
    ACTION_OVERTURN_OVERRIDE,
    ACTION_REVOKE,
    ACTION_SUPERSEDE_REAPPROVE,
    CASE_MINOR_BUDGET_CAP,
    CAT_IS_KANUNU_SOZLESME,
    CAT_KVKK_6698,
    CAT_UCRET_SURE_IZIN,
    CATEGORY_SPLIT_TARGETS,
    CATEGORY_TARGET_COUNTS,
    DEFECT_FIXED_PENALTIES,
    DIM_LEGAL_CORRECTNESS,
    DIM_RETRIEVAL_EFFECTIVENESS,
    DIMENSION_WEIGHTS,
    MISSING_DIM_POLICY_RENORMALIZED,
    MONETARY_CLASS_CALCULATED_PAYMENT,
    MONETARY_CLASS_STATUTORY_THRESHOLD,
    MONETARY_CLASS_USER_INPUT,
    OFFICIAL_STATUS_BELOW_THRESHOLD,
    OFFICIAL_STATUS_FAILED_FATAL_VETO,
    OFFICIAL_STATUS_PASSED,
    OFFICIAL_STATUS_RUN_INVALID_INFRA,
    OFFICIAL_STATUS_UNVERIFIED_ZERO_APPROVED,
    REVIEW_APPROVED_FOR_BENCHMARK,
    REVIEW_PENDING_LEGAL_REVIEW,
    RUN_VALIDITY_INVALID,
    RUN_VALIDITY_VALID,
    SIGNATURE_ALGORITHM_PARAMS,
    SIGNOFF_REVOKED,
    SIGNOFF_STALE,
    SIGNOFF_VERIFIED_APPROVED,
    SPLIT_DEV,
    SPLIT_HOLDOUT,
    SPLIT_TARGET_COUNTS,
    SPLIT_VALIDATION,
    TRIGGER_LEGAL_REVIEWER,
    VERDICT_EVALUATION_INFRA_FAILURE,
    VERDICT_FAIL_FATAL,
    VERDICT_FAIL_MAJOR,
    VERDICT_FAIL_SCORE,
    VERDICT_PARTIAL_REVIEW,
    VERDICT_PASS,
    EngineeringDisputeMemo,
    EvaluationDataset,
    EvaluationIntegrityError,
    EvaluationRubricScorer,
    EvaluationSuiteRunReport,
    HoldoutAccessLedger,
    HukukSgkEvaluationRunner,
    TrustedLegalApproverRecord,
    TrustedLegalApproverRegistry,
    classify_monetary_mentions,
    classify_score_band,
    compute_cross_split_jaccard,
    compute_public_key_fingerprint,
    create_signed_answer_key_approval_envelope,
    load_dev_val_dataset,
    load_evaluation_dataset,
    verify_dataset_anti_leakage,
    verify_detached_legal_signoffs,
)
from engine.evaluation.runner import _git_sha_safe
from engine.rag import HukukSgkRagEngine, RagQueryRequest
from engine.trust_root import run_live_integration_probe

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_XMLDSIG_SHA256 = "b16207b5fb71d7c0d0372838411c7795459ac460c2ff232766ae230b9cbacf85"

_SHARED_EVAL: dict[Path, tuple[HukukSgkEvaluationRunner, EvaluationDataset, EvaluationSuiteRunReport]] = {}


def _generate_runtime_ed25519_keypair(tmp_dir: Path, prefix: str) -> tuple[str, str, str]:
    """Generate ephemeral Ed25519 keypair via OpenSSL 3 at test runtime (zero hardcoded private keys)."""
    priv = tmp_dir / f"{prefix}_priv.pem"
    pub = tmp_dir / f"{prefix}_pub.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(priv)],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", str(priv), "-pubout", "-out", str(pub)],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
    )
    priv_pem = priv.read_text(encoding="utf-8")
    pub_pem = pub.read_text(encoding="utf-8")
    fp = compute_public_key_fingerprint(pub_pem)
    return priv_pem, pub_pem, fp


def _generate_runtime_rsa2048_keypair(tmp_dir: Path, prefix: str) -> tuple[str, str, str]:
    """Generate ephemeral 2048-bit RSA keypair via OpenSSL 3 at test runtime for RSA-PSS-SHA256 tests."""
    priv = tmp_dir / f"{prefix}_rsa_priv.pem"
    pub = tmp_dir / f"{prefix}_rsa_pub.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(priv)],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=20,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", str(priv), "-pubout", "-out", str(pub)],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
    )
    priv_pem = priv.read_text(encoding="utf-8")
    pub_pem = pub.read_text(encoding="utf-8")
    fp = compute_public_key_fingerprint(pub_pem)
    return priv_pem, pub_pem, fp


def _get_shared_eval() -> tuple[HukukSgkEvaluationRunner, EvaluationDataset, EvaluationSuiteRunReport]:
    resolved = PROJECT_ROOT.resolve()
    if resolved not in _SHARED_EVAL:
        rag = HukukSgkRagEngine.from_project_root(project_root=PROJECT_ROOT)
        orch = HukukSgkAnswerOrchestrator.from_project_root(project_root=PROJECT_ROOT)
        runner = HukukSgkEvaluationRunner(
            rag_engine=rag,
            answer_orchestrator=orch,
            project_root=PROJECT_ROOT,
        )
        ds = load_evaluation_dataset()
        rpt = runner.run_suite(ds, blind_holdout_mode=False)
        _SHARED_EVAL[resolved] = (runner, ds, rpt)
    return _SHARED_EVAL[resolved]


class TestEvaluationWp45V106(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner, cls.dataset, cls.report = _get_shared_eval()

    def test_01_dataset_vaults_splits_o01_jaccard_and_y02_applicable_dims(self) -> None:
        """EV-01: Ayrık kasalar (70 DEV/VAL + 30 HOLDOUT), matris, Y-02 boyutları ve O-01 Jaccard."""
        self.assertTrue(self.dataset.vault_separated)
        self.assertEqual(len(self.dataset.cases), 100)
        self.assertEqual(self.dataset.category_counts(), CATEGORY_TARGET_COUNTS)
        self.assertEqual(self.dataset.split_counts(), SPLIT_TARGET_COUNTS)
        self.assertEqual(self.dataset.category_split_counts(), CATEGORY_SPLIT_TARGETS)
        self.assertEqual(sum(DIMENSION_WEIGHTS.values()), 100)
        self.assertEqual(len(DIMENSION_WEIGHTS), 8)

        dev_val_only = load_dev_val_dataset()
        self.assertEqual(len(dev_val_only.cases), 70)
        self.assertTrue(all(c.split != SPLIT_HOLDOUT for c in dev_val_only.cases))

        for c in self.dataset.cases:
            self.assertEqual(c.legal_review.answer_key_sha256, c.expected_answer_key_sha256())
            self.assertEqual(c.legal_review.review_status, REVIEW_PENDING_LEGAL_REVIEW)
            self.assertTrue(len(c.applicable_dimensions) >= 3)

        # O-01 Formal edge cases (empty union, short text < 4, Turkish punctuation/case folding)
        self.assertEqual(compute_cross_split_jaccard("", "!!!"), 0.0)
        self.assertEqual(compute_cross_split_jaccard("ab", "ab"), 1.0)
        self.assertEqual(compute_cross_split_jaccard("İŞÇİ ÜCRETİ!", "isci ucreti?"), 1.0)

        leak = verify_dataset_anti_leakage(self.dataset)
        self.assertTrue(leak.passed, msg=f"Leakage detected: {leak.to_dict()}")
        self.assertLessEqual(leak.max_cross_split_jaccard, 0.55)

    def test_02_anti_leakage_rejects_shared_cluster_and_paraphrase_leakage(self) -> None:
        """EV-02: Farklı kümelere bölünen cluster_id veya yakın kopya metin yüklemede reddedilir."""
        c_dev = next(c for c in self.dataset.cases if c.split == SPLIT_DEV)
        c_hold = next(c for c in self.dataset.cases if c.split == SPLIT_HOLDOUT)

        leaked_cluster_case = replace(c_hold, cluster_id=c_dev.cluster_id)
        ds_clu = EvaluationDataset(
            dataset_version="clu-leak",
            created_at_utc="2026-11-26T06:20:00Z",
            cases=(c_dev, leaked_cluster_case),
            dataset_sha256="x",
        )
        leak_clu = verify_dataset_anti_leakage(ds_clu)
        self.assertFalse(leak_clu.passed)
        self.assertEqual(len(leak_clu.cross_split_cluster_violations), 1)

        leaked_text_case = replace(c_hold, query_text=c_dev.query_text + " detay")
        ds_dup = EvaluationDataset(
            dataset_version="dup-leak",
            created_at_utc="2026-11-26T06:20:00Z",
            cases=(c_dev, leaked_text_case),
            dataset_sha256="y",
        )
        leak_dup = verify_dataset_anti_leakage(ds_dup)
        self.assertFalse(leak_dup.passed)
        self.assertGreater(leak_dup.max_cross_split_jaccard, 0.55)
        self.assertEqual(len(leak_dup.near_duplicate_violations), 1)

    def test_03_k01_cryptographic_legal_signoff_revocation_and_o04_dual_control_override(self) -> None:
        """EV-03 (K-01 & O-04): Sahte inline onay reddi, Ed25519 ayrık imza, iptal/yeniden onay ve çift-göz itiraz."""
        off = self.report.official_benchmark_metrics
        self.assertEqual(off.official_status, OFFICIAL_STATUS_UNVERIFIED_ZERO_APPROVED)
        self.assertFalse(off.official_pass_eligible)
        self.assertIsNone(off.official_approved_weighted_index)
        self.assertIsNone(off.official_macro_category_index)

        # K-01(a): Veri seti dosyasına geliştirici eliyle doğrudan APPROVED_FOR_BENCHMARK yazılması yasaktır!
        raw_dv = json.loads(
            (PROJECT_ROOT / "engine" / "evaluation" / "datasets" / "eval_dev_val_70_cases.json").read_text(encoding="utf-8")
        )
        raw_dv["cases"][0]["legal_review"]["review_status"] = REVIEW_APPROVED_FOR_BENCHMARK
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            p_inline = td_path / "forged_inline.json"
            p_inline.write_text(json.dumps(raw_dv, ensure_ascii=False), encoding="utf-8")
            with self.assertRaises(EvaluationIntegrityError) as ctx:
                load_evaluation_dataset(p_inline, enforce_target_counts=False, enforce_anti_leakage=False)
            self.assertIn("FORBIDDEN_SELF_ASSERTED_APPROVAL_IN_DATASET", str(ctx.exception))

            # Runtime Ed25519 hukukçu anahtar çifti üret
            priv1, pub1, fp1 = _generate_runtime_ed25519_keypair(td_path, "counsel1")
            priv2, pub2, fp2 = _generate_runtime_ed25519_keypair(td_path, "counsel2")
            rogue_priv, _, rogue_fp = _generate_runtime_ed25519_keypair(td_path, "rogue_dev")

            registry = TrustedLegalApproverRegistry(
                registry_version="reg-v1",
                approvers=(
                    TrustedLegalApproverRecord(
                        approver_id="COUNSEL-AUDIT-01",
                        approver_role="INDEPENDENT_LABOR_LAW_COUNSEL",
                        bar_association_ref="IST-BAR-10001",
                        enrollment_status="ENROLLED",
                        key_id="KEY-C1-2026",
                        key_version="v1",
                        algorithm="ED25519",
                        public_key_pem=pub1,
                        public_key_fingerprint_sha256=fp1,
                        valid_from_utc="2026-01-01T00:00:00Z",
                        valid_until_utc="2027-12-31T23:59:59Z",
                    ),
                    TrustedLegalApproverRecord(
                        approver_id="COUNSEL-AUDIT-02",
                        approver_role="SENIOR_SOCIAL_SECURITY_COUNSEL",
                        bar_association_ref="ANK-BAR-20002",
                        enrollment_status="ENROLLED",
                        key_id="KEY-C2-2026",
                        key_version="v1",
                        algorithm="ED25519",
                        public_key_pem=pub2,
                        public_key_fingerprint_sha256=fp2,
                        valid_from_utc="2026-01-01T00:00:00Z",
                        valid_until_utc="2027-12-31T23:59:59Z",
                    ),
                ),
            )

            c_dev = next(c for c in self.dataset.cases if c.case_id == "EVAL-001")
            c_hold = next(c for c in self.dataset.cases if c.case_id == "EVAL-083")
            c_draft_fatal = next(c for c in self.dataset.cases if c.case_id == "EVAL-028")

            # K-01(b): Kayıt dışı geliştirici anahtarıyla sahte imza -> REJECTED!
            forged_env = create_signed_answer_key_approval_envelope(
                case=c_dev,
                dataset_version=self.dataset.dataset_version,
                envelope_id="ENV-ROGUE-1",
                nonce="nonce-rogue-0001",
                approver_id="DEV-FAKE-01",
                approver_role="INDEPENDENT_LABOR_LAW_COUNSEL",
                key_id="KEY-ROGUE",
                key_version="v1",
                algorithm="ED25519",
                private_key_pem=rogue_priv,
                public_key_fingerprint_sha256=rogue_fp,
                signed_at_utc="2026-11-26T06:25:00Z",
                legal_rationale="Sahte geliştirici imzası",
            )
            st_rogue = verify_detached_legal_signoffs(case=c_dev, envelopes=(forged_env,), registry=registry)
            self.assertFalse(st_rogue.approved)
            self.assertIn("UNTRUSTED_OR_UNKNOWN_LEGAL_APPROVER", st_rogue.failure_codes)

            # K-01(c): Geçerli Ed25519 detached hukuk imzaları resmî endeksi izole besler (EVAL-028 taslağı dışlanır!)
            env_dev = create_signed_answer_key_approval_envelope(
                case=c_dev,
                dataset_version=self.dataset.dataset_version,
                envelope_id="ENV-001",
                nonce="nonce-c1-000001",
                approver_id="COUNSEL-AUDIT-01",
                approver_role="INDEPENDENT_LABOR_LAW_COUNSEL",
                key_id="KEY-C1-2026",
                key_version="v1",
                algorithm="ED25519",
                private_key_pem=priv1,
                public_key_fingerprint_sha256=fp1,
                signed_at_utc="2026-11-26T06:25:00Z",
                legal_rationale="Mevzuat ve olay tarihi onaylı.",
            )
            env_hold = create_signed_answer_key_approval_envelope(
                case=c_hold,
                dataset_version=self.dataset.dataset_version,
                envelope_id="ENV-083",
                nonce="nonce-c1-000002",
                approver_id="COUNSEL-AUDIT-01",
                approver_role="INDEPENDENT_LABOR_LAW_COUNSEL",
                key_id="KEY-C1-2026",
                key_version="v1",
                algorithm="ED25519",
                private_key_pem=priv1,
                public_key_fingerprint_sha256=fp1,
                signed_at_utc="2026-11-26T06:26:00Z",
                legal_rationale="Haklı fesih m.26 süresi onaylı.",
            )
            mixed_ds = EvaluationDataset(
                dataset_version=self.dataset.dataset_version,
                created_at_utc="2026-11-26T06:25:00Z",
                cases=(c_dev, c_hold, c_draft_fatal),
                dataset_sha256="mix-k01",
            )
            mixed_rpt = self.runner.run_suite(
                mixed_ds,
                legal_signoff_envelopes=(env_dev, env_hold),
                approver_registry=registry,
                blind_holdout_mode=False,
            )
            self.assertEqual(mixed_rpt.approval_coverage.approved_cases_count, 2)
            self.assertEqual(mixed_rpt.approval_coverage.pending_or_unapproved_count, 1)
            self.assertEqual(mixed_rpt.official_benchmark_metrics.official_fatal_auto_count, 0)
            self.assertEqual(mixed_rpt.engineering_diagnostic_metrics.fatal_auto_count, 1)
            self.assertGreater(mixed_rpt.official_benchmark_metrics.official_approved_weighted_index or 0.0, 90.0)

            # K-01(d): Cevap anahtarı değişince önceki Ed25519 hukuk onayı STALE_KEY_MODIFIED_REAPPROVAL_REQUIRED ile düşer!
            edited_c_dev = replace(c_dev, query_text=c_dev.query_text + " ek")
            stale_st = verify_detached_legal_signoffs(case=edited_c_dev, envelopes=(env_dev,), registry=registry)
            self.assertFalse(stale_st.approved)
            self.assertEqual(stale_st.signoff_status, SIGNOFF_STALE)
            self.assertIn("STALE_KEY_MODIFIED_REAPPROVAL_REQUIRED", stale_st.failure_codes)

            # K-01(e): REVOKE -> REVOKED, ardından SUPERSEDE_REAPPROVE -> yeniden APPROVED, tam tarihçe!
            env_rev = create_signed_answer_key_approval_envelope(
                case=c_dev,
                dataset_version=self.dataset.dataset_version,
                envelope_id="ENV-002-REV",
                nonce="nonce-c1-000003",
                action=ACTION_REVOKE,
                approver_id="COUNSEL-AUDIT-01",
                approver_role="INDEPENDENT_LABOR_LAW_COUNSEL",
                key_id="KEY-C1-2026",
                key_version="v1",
                algorithm="ED25519",
                private_key_pem=priv1,
                public_key_fingerprint_sha256=fp1,
                signed_at_utc="2026-11-26T06:27:00Z",
                legal_rationale="İstisna güncellemesi için geçici iptal.",
                supersedes_envelope_id="ENV-001",
            )
            env_sup = create_signed_answer_key_approval_envelope(
                case=c_dev,
                dataset_version=self.dataset.dataset_version,
                envelope_id="ENV-003-SUP",
                nonce="nonce-c2-000004",
                action=ACTION_SUPERSEDE_REAPPROVE,
                approver_id="COUNSEL-AUDIT-02",
                approver_role="SENIOR_SOCIAL_SECURITY_COUNSEL",
                key_id="KEY-C2-2026",
                key_version="v1",
                algorithm="ED25519",
                private_key_pem=priv2,
                public_key_fingerprint_sha256=fp2,
                signed_at_utc="2026-11-26T06:28:00Z",
                legal_rationale="Yeniden inceleme tamamlandı, onay yenilendi.",
                supersedes_envelope_id="ENV-002-REV",
            )
            st_revoked = verify_detached_legal_signoffs(case=c_dev, envelopes=(env_dev, env_rev), registry=registry)
            self.assertFalse(st_revoked.approved)
            self.assertEqual(st_revoked.signoff_status, SIGNOFF_REVOKED)
            st_reapproved = verify_detached_legal_signoffs(
                case=c_dev, envelopes=(env_dev, env_rev, env_sup), registry=registry
            )
            self.assertTrue(st_reapproved.approved)
            self.assertEqual(st_reapproved.signoff_status, SIGNOFF_VERIFIED_APPROVED)
            self.assertEqual(len(st_reapproved.approval_history), 3)

            # O-04: Çift-göz FATAL override itiraz akışı (aynı avukat tek başına kaldıramaz; 2. hukukçu kaldırır!)
            env_ovr = create_signed_answer_key_approval_envelope(
                case=c_dev,
                dataset_version=self.dataset.dataset_version,
                envelope_id="ENV-OVR-1",
                nonce="nonce-c1-000005",
                action=ACTION_OVERRIDE_FATAL,
                approver_id="COUNSEL-AUDIT-01",
                approver_role="INDEPENDENT_LABOR_LAW_COUNSEL",
                key_id="KEY-C1-2026",
                key_version="v1",
                algorithm="ED25519",
                private_key_pem=priv1,
                public_key_fingerprint_sha256=fp1,
                signed_at_utc="2026-11-26T06:29:00Z",
                legal_rationale="Maddi hukuk istisnası nedeniyle veto.",
            )
            memo = EngineeringDisputeMemo(
                dispute_id="DISP-1",
                case_id=c_dev.case_id,
                target_override_envelope_id="ENV-OVR-1",
                filed_by="ENG-LEAD",
                filed_at_utc="2026-11-26T06:30:00Z",
                dispute_reason="Kanun fıkrası kanıtlarda mevcut.",
                evidence_trace_id="TRC-001",
            )
            same_counsel_overturn = create_signed_answer_key_approval_envelope(
                case=c_dev,
                dataset_version=self.dataset.dataset_version,
                envelope_id="ENV-OVR-SAME",
                nonce="nonce-c1-000006",
                action=ACTION_OVERTURN_OVERRIDE,
                approver_id="COUNSEL-AUDIT-01",
                approver_role="INDEPENDENT_LABOR_LAW_COUNSEL",
                key_id="KEY-C1-2026",
                key_version="v1",
                algorithm="ED25519",
                private_key_pem=priv1,
                public_key_fingerprint_sha256=fp1,
                signed_at_utc="2026-11-26T06:31:00Z",
                legal_rationale="Kendi vetomu kaldırıyorum.",
                supersedes_envelope_id="ENV-OVR-1",
            )
            st_dual_block = verify_detached_legal_signoffs(
                case=c_dev,
                envelopes=(env_ovr, same_counsel_overturn),
                dispute_memos=(memo,),
                registry=registry,
            )
            self.assertTrue(st_dual_block.legal_fatal_override_active)
            self.assertIn("DUAL_CONTROL_SECOND_REVIEWER_REQUIRED", st_dual_block.failure_codes)

            second_counsel_overturn = create_signed_answer_key_approval_envelope(
                case=c_dev,
                dataset_version=self.dataset.dataset_version,
                envelope_id="ENV-OVR-2ND",
                nonce="nonce-c2-000007",
                action=ACTION_OVERTURN_OVERRIDE,
                approver_id="COUNSEL-AUDIT-02",
                approver_role="SENIOR_SOCIAL_SECURITY_COUNSEL",
                key_id="KEY-C2-2026",
                key_version="v1",
                algorithm="ED25519",
                private_key_pem=priv2,
                public_key_fingerprint_sha256=fp2,
                signed_at_utc="2026-11-26T06:32:00Z",
                legal_rationale="İkinci bağımsız inceleme ile veto kaldırıldı.",
                supersedes_envelope_id="ENV-OVR-1",
            )
            st_overturned = verify_detached_legal_signoffs(
                case=c_dev,
                envelopes=(env_ovr, same_counsel_overturn, second_counsel_overturn),
                dispute_memos=(memo,),
                registry=registry,
            )
            self.assertFalse(st_overturned.legal_fatal_override_active)
            self.assertGreaterEqual(len(st_overturned.override_history), 4)

            # K-01(f): RSA-PSS-SHA256 (2048-bit RSA, MGF1-SHA256, saltlen=32) imza ve tahrifat reddi doğrulaması
            rsa_priv, rsa_pub, rsa_fp = _generate_runtime_rsa2048_keypair(td_path, "counsel_rsa")
            rsa_reg = TrustedLegalApproverRegistry(
                registry_version="reg-rsa-v1",
                approvers=(
                    TrustedLegalApproverRecord(
                        approver_id="COUNSEL-RSA-03",
                        approver_role="EXTERNAL_LEGAL_COUNSEL",
                        bar_association_ref="IZM-BAR-30003",
                        enrollment_status="ENROLLED",
                        key_id="KEY-RSA-2026",
                        key_version="v1",
                        algorithm="RSA-PSS-SHA256",
                        public_key_pem=rsa_pub,
                        public_key_fingerprint_sha256=rsa_fp,
                        valid_from_utc="2026-01-01T00:00:00Z",
                        valid_until_utc="2027-12-31T23:59:59Z",
                    ),
                ),
            )
            env_rsa = create_signed_answer_key_approval_envelope(
                case=c_dev,
                dataset_version=self.dataset.dataset_version,
                envelope_id="ENV-RSA-001",
                nonce="nonce-rsa-000001",
                approver_id="COUNSEL-RSA-03",
                approver_role="EXTERNAL_LEGAL_COUNSEL",
                key_id="KEY-RSA-2026",
                key_version="v1",
                algorithm="RSA-PSS-SHA256",
                private_key_pem=rsa_priv,
                public_key_fingerprint_sha256=rsa_fp,
                signed_at_utc="2026-11-26T06:33:00Z",
                legal_rationale="RSA-PSS-SHA256 (saltlen=32) ile harici hukuk onayı.",
            )
            self.assertFalse(env_rsa.qualified_e_signature_5070_equivalent)
            st_rsa_ok = verify_detached_legal_signoffs(case=c_dev, envelopes=(env_rsa,), registry=rsa_reg)
            self.assertTrue(st_rsa_ok.approved)
            self.assertEqual(st_rsa_ok.signoff_status, SIGNOFF_VERIFIED_APPROVED)
            tampered_env_rsa = replace(env_rsa, legal_rationale="Tahrif edilmis gerekce.")
            st_rsa_bad = verify_detached_legal_signoffs(case=c_dev, envelopes=(tampered_env_rsa,), registry=rsa_reg)
            self.assertFalse(st_rsa_bad.approved)
            self.assertIn("CRYPTO_SIGNATURE_INVALID", st_rsa_bad.failure_codes)

            # Bit-flipped RSA signature_b64 & algorithm metadata mismatch on envelope
            rsa_sig_raw = bytearray(base64.b64decode(env_rsa.signature_b64))
            rsa_sig_raw[0] ^= 0x01
            bad_sig_env = replace(env_rsa, signature_b64=base64.b64encode(bytes(rsa_sig_raw)).decode("ascii"))
            st_rsa_bitflip = verify_detached_legal_signoffs(case=c_dev, envelopes=(bad_sig_env,), registry=rsa_reg)
            self.assertFalse(st_rsa_bitflip.approved)
            self.assertIn("CRYPTO_SIGNATURE_INVALID", st_rsa_bitflip.failure_codes)

            bad_alg_env = replace(env_rsa, algorithm="ED25519")
            st_rsa_alg_mismatch = verify_detached_legal_signoffs(case=c_dev, envelopes=(bad_alg_env,), registry=rsa_reg)
            self.assertFalse(st_rsa_alg_mismatch.approved)

            # K-01(g): SIGNATURE_ALGORITHM_PARAMS & düşük seviye OpenSSL RFC 8032 / RSA-PSS-SHA256 negatif vektörleri
            self.assertEqual(SIGNATURE_ALGORITHM_PARAMS["ED25519"]["standard"], "RFC 8032 PureEd25519")
            self.assertFalse(SIGNATURE_ALGORITHM_PARAMS["ED25519"]["prehash"])
            self.assertEqual(SIGNATURE_ALGORITHM_PARAMS["RSA-PSS-SHA256"]["min_rsa_key_bits"], 2048)
            self.assertEqual(SIGNATURE_ALGORITHM_PARAMS["RSA-PSS-SHA256"]["hash_algorithm"], "SHA-256")
            self.assertEqual(SIGNATURE_ALGORITHM_PARAMS["RSA-PSS-SHA256"]["mgf"], "MGF1-SHA256")
            self.assertEqual(SIGNATURE_ALGORITHM_PARAMS["RSA-PSS-SHA256"]["salt_length_bytes"], 32)

            with tempfile.TemporaryDirectory(prefix="wp45_k01_neg_") as td_neg:
                neg_dir = Path(td_neg)
                ed_a_priv_p = neg_dir / "ed_a_priv.pem"
                ed_a_pub_p = neg_dir / "ed_a_pub.pem"
                ed_b_priv_p = neg_dir / "ed_b_priv.pem"
                ed_b_pub_p = neg_dir / "ed_b_pub.pem"
                for priv_p, pub_p in ((ed_a_priv_p, ed_a_pub_p), (ed_b_priv_p, ed_b_pub_p)):
                    subprocess.run(
                        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(priv_p)],
                        check=True,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=15,
                    )
                    subprocess.run(
                        ["openssl", "pkey", "-in", str(priv_p), "-pubout", "-out", str(pub_p)],
                        check=True,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=15,
                    )
                ed_a_priv = ed_a_priv_p.read_text(encoding="utf-8")
                ed_a_pub = ed_a_pub_p.read_text(encoding="utf-8")
                ed_b_pub = ed_b_pub_p.read_text(encoding="utf-8")

                rsa_a_priv_p = neg_dir / "rsa_a_priv.pem"
                rsa_a_pub_p = neg_dir / "rsa_a_pub.pem"
                rsa_b_priv_p = neg_dir / "rsa_b_priv.pem"
                rsa_b_pub_p = neg_dir / "rsa_b_pub.pem"
                for priv_p, pub_p in ((rsa_a_priv_p, rsa_a_pub_p), (rsa_b_priv_p, rsa_b_pub_p)):
                    subprocess.run(
                        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(priv_p)],
                        check=True,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=20,
                    )
                    subprocess.run(
                        ["openssl", "pkey", "-in", str(priv_p), "-pubout", "-out", str(pub_p)],
                        check=True,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=15,
                    )
                rsa_a_priv = rsa_a_priv_p.read_text(encoding="utf-8")
                rsa_a_pub = rsa_a_pub_p.read_text(encoding="utf-8")
                rsa_b_pub = rsa_b_pub_p.read_text(encoding="utf-8")

                # Ed25519 (RFC 8032): pozitif + ham OpenSSL çapraz doğrulama + bozuk mesaj + bit-flip + yanlış anahtar + alg uyuşmazlığı
                p_ed = {"case_id": c_dev.case_id, "sha": c_dev.expected_answer_key_sha256(), "alg": "ED25519"}
                sig_ed = sign_canonical_payload(p_ed, ed_a_priv, "ED25519")
                self.assertTrue(verify_asymmetric_signature(p_ed, sig_ed, ed_a_pub, "ED25519")[0])
                msg_ed_p = neg_dir / "msg_ed.bin"
                sig_ed_p = neg_dir / "sig_ed.bin"
                msg_ed_p.write_bytes(canonical_json_bytes(p_ed))
                sig_ed_p.write_bytes(base64.b64decode(sig_ed))
                ossl_ed_ok = subprocess.run(
                    ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(ed_a_pub_p), "-rawin", "-in", str(msg_ed_p), "-sigfile", str(sig_ed_p)],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(ossl_ed_ok.returncode, 0)
                ed_flip = bytearray(base64.b64decode(sig_ed))
                ed_flip[0] ^= 0x01
                self.assertFalse(verify_asymmetric_signature({**p_ed, "case_id": "TAMPERED"}, sig_ed, ed_a_pub, "ED25519")[0])
                self.assertFalse(verify_asymmetric_signature(p_ed, base64.b64encode(bytes(ed_flip)).decode("ascii"), ed_a_pub, "ED25519")[0])
                self.assertFalse(verify_asymmetric_signature(p_ed, sig_ed, ed_b_pub, "ED25519")[0])
                self.assertFalse(verify_asymmetric_signature(p_ed, sig_ed, ed_a_pub, "RSA-PSS-SHA256")[0])

                # RSA-PSS-SHA256 (saltlen=32, MGF1-SHA256): pozitif + saltlen=16 reddi + PKCS#1 v1.5 reddi + tahrifat + yanlış anahtar
                p_rsa = {"case_id": c_dev.case_id, "sha": c_dev.expected_answer_key_sha256(), "alg": "RSA-PSS-SHA256"}
                sig_rsa = sign_canonical_payload(p_rsa, rsa_a_priv, "RSA-PSS-SHA256")
                self.assertTrue(verify_asymmetric_signature(p_rsa, sig_rsa, rsa_a_pub, "RSA-PSS-SHA256")[0])
                msg_rsa_p = neg_dir / "msg_rsa.bin"
                sig_rsa_p = neg_dir / "sig_rsa.bin"
                msg_rsa_p.write_bytes(canonical_json_bytes(p_rsa))
                sig_rsa_p.write_bytes(base64.b64decode(sig_rsa))
                ossl_rsa_ok = subprocess.run(
                    [
                        "openssl", "dgst", "-sha256",
                        "-sigopt", "rsa_padding_mode:pss",
                        "-sigopt", "rsa_pss_saltlen:32",
                        "-verify", str(rsa_a_pub_p),
                        "-signature", str(sig_rsa_p),
                        str(msg_rsa_p),
                    ],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(ossl_rsa_ok.returncode, 0)

                sig_salt16_p = neg_dir / "sig_salt16.bin"
                subprocess.run(
                    [
                        "openssl", "dgst", "-sha256",
                        "-sigopt", "rsa_padding_mode:pss",
                        "-sigopt", "rsa_pss_saltlen:16",
                        "-sign", str(rsa_a_priv_p),
                        "-out", str(sig_salt16_p),
                        str(msg_rsa_p),
                    ],
                    check=True,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                )
                sig_salt16_b64 = base64.b64encode(sig_salt16_p.read_bytes()).decode("ascii")
                ok_s16, msg_s16 = verify_asymmetric_signature(p_rsa, sig_salt16_b64, rsa_a_pub, "RSA-PSS-SHA256")
                self.assertFalse(ok_s16)
                self.assertIn("salt", msg_s16.lower())

                sig_pkcs1_p = neg_dir / "sig_pkcs1.bin"
                subprocess.run(
                    ["openssl", "dgst", "-sha256", "-sign", str(rsa_a_priv_p), "-out", str(sig_pkcs1_p), str(msg_rsa_p)],
                    check=True,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                )
                sig_pkcs1_b64 = base64.b64encode(sig_pkcs1_p.read_bytes()).decode("ascii")
                self.assertFalse(verify_asymmetric_signature(p_rsa, sig_pkcs1_b64, rsa_a_pub, "RSA-PSS-SHA256")[0])

                rsa_flip = bytearray(base64.b64decode(sig_rsa))
                rsa_flip[0] ^= 0x01
                self.assertFalse(verify_asymmetric_signature({**p_rsa, "alg": "TAMPERED"}, sig_rsa, rsa_a_pub, "RSA-PSS-SHA256")[0])
                self.assertFalse(verify_asymmetric_signature(p_rsa, base64.b64encode(bytes(rsa_flip)).decode("ascii"), rsa_a_pub, "RSA-PSS-SHA256")[0])
                self.assertFalse(verify_asymmetric_signature(p_rsa, sig_rsa, rsa_b_pub, "RSA-PSS-SHA256")[0])
                self.assertFalse(verify_asymmetric_signature(p_rsa, sig_rsa, rsa_a_pub, "ED25519")[0])

    def test_04_k02_thresholds_y01_fixed_penalties_y02_na_policy_and_o03_minor_cap(self) -> None:
        """EV-04 (K-02, Y-01, Y-02, O-03): PASS>=85, PARTIAL 80..84.99, FAIL_SCORE<80, sabit cezalar & MINOR tavan."""
        orch = self.runner._orch
        rag = self.runner._rag
        scorer = EvaluationRubricScorer(source_registry=orch._sources, precedent_registry=orch._precedents)

        # Y-02: Muğlak NEUTRAL_IF_NOT_APPLICABLE seçeneği açıkça yasaktır!
        with self.assertRaises(EvaluationIntegrityError):
            EvaluationRubricScorer(missing_dimension_policy="NEUTRAL_IF_NOT_APPLICABLE")

        # Y-01: MAJOR aralık tutarlılığı kontrolü ([25..40])
        for code, pen in DEFECT_FIXED_PENALTIES.items():
            if code.startswith("MAJOR_"):
                self.assertGreaterEqual(pen, 25.0)
                self.assertLessEqual(pen, 40.0)

        clean_case = next(c for c in self.dataset.cases if c.case_id == "EVAL-001")
        bundle = rag.retrieve(RagQueryRequest(query_text=clean_case.query_text, as_of_date=clean_case.as_of_date, facts=clean_case.facts))
        ans = orch.generate_answer(AnswerGenerationRequest(trace_bundle=bundle, facts=clean_case.facts))

        # O-03: Tek vakada tüm MINOR cezaları <= 5.0 bütçesiyle sınırlanır ve PASS (>= 85.0) kalır
        minor_case = replace(
            clean_case,
            expected_outcome=replace(
                clean_case.expected_outcome,
                acceptable_answer_criteria=("yok1", "yok2", "yok3", "yok4"),
            ),
        )
        minor_rpt = scorer.score_case(case=minor_case, trace_bundle=bundle, answer=ans)
        self.assertEqual(minor_rpt.verdict, VERDICT_PASS)
        self.assertLessEqual(sum(d.penalty_applied for d in minor_rpt.defects if d.severity == "MINOR"), CASE_MINOR_BUDGET_CAP)
        self.assertGreaterEqual(minor_rpt.final_score or 0.0, 95.0)

        # K-02: PARTIAL_REVIEW (80.0 <= score < 85.0) & FAIL_SCORE (< 80.0) bandları!
        partial_case = replace(
            clean_case,
            expected_outcome=replace(clean_case.expected_outcome, expected_missing_fields=("m_1", "m_2", "m_3")),
        )
        partial_rpt = scorer.score_case(case=partial_case, trace_bundle=bundle, answer=ans)
        # 3 MODERATE_INCOMPLETE_CLARIFICATION_Q (-30 in ABSTENTION [w=10 -> -3.0] or wait: capped at 0 -> -10 weight -> 88..90; adjust confidence + 100-missing)
        fail_score_case = replace(
            clean_case,
            expected_outcome=replace(
                clean_case.expected_outcome,
                expected_confidence_statuses=("NEVER_MATCH_CONF",),
                expected_missing_fields=("m_1", "m_2", "m_3", "m_4", "m_5", "m_6", "m_7", "m_8", "m_9"),
            ),
            ground_truth=replace(
                clean_case.ground_truth,
                critical_exceptions=("yok_exc_1", "yok_exc_2"),
                required_source_ids=clean_case.ground_truth.required_source_ids,
            ),
            include_historical=True,
        )
        # Check exact verdict band transitions clearly:
        # Weight sums for clean_case: all 8 dims = 100.
        # ABSTENTION (10) -> 0 (-10 pts), HISTORICAL (18) -> exp_hist missing... let's trigger HISTORICAL + INTERPRETATION MODERATE cleanly:
        band_partial_case = replace(
            clean_case,
            include_historical=True,
            ground_truth=replace(
                clean_case.ground_truth,
                expected_historical_source_ids=("HIST-MISS-1", "HIST-MISS-2", "HIST-MISS-3", "HIST-MISS-4", "HIST-MISS-5", "HIST-MISS-6", "HIST-MISS-7", "HIST-MISS-8"),
                critical_exceptions=("yok_exc_1", clean_case.ground_truth.critical_exceptions[0])
                if clean_case.ground_truth.critical_exceptions
                else ("yok_exc_1", "4857"),
            ),
        )
        p_rpt = scorer.score_case(case=band_partial_case, trace_bundle=bundle, answer=ans)
        self.assertGreaterEqual(p_rpt.final_score or 0.0, 80.0)
        self.assertLess(p_rpt.final_score or 100.0, 85.0)
        self.assertEqual(p_rpt.verdict, VERDICT_PARTIAL_REVIEW)

        band_fail_case = replace(
            band_partial_case,
            expected_outcome=replace(
                clean_case.expected_outcome,
                expected_confidence_statuses=("UNMATCHED",),
                expected_missing_fields=("f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9"),
            ),
        )
        f_rpt = scorer.score_case(case=band_fail_case, trace_bundle=bundle, answer=ans)
        self.assertLess(f_rpt.final_score or 100.0, 80.0)
        self.assertEqual(f_rpt.verdict, VERDICT_FAIL_SCORE)

        # Y-02: ADVERSARIAL vakada N/A boyutlara asla 100 puan verilmez (raw_score=None, normalized_weight=0)
        adv_case = next(c for c in self.dataset.cases if c.case_id == "EVAL-025")
        adv_bundle = rag.retrieve(RagQueryRequest(query_text=adv_case.query_text, as_of_date=adv_case.as_of_date, facts=adv_case.facts))
        adv_ans = orch.generate_answer(
            AnswerGenerationRequest(
                trace_bundle=adv_bundle,
                facts=adv_case.facts,
                override_section_texts=adv_case.adversarial_injections["override_section_texts"],
            )
        )
        adv_rpt = scorer.score_case(case=adv_case, trace_bundle=adv_bundle, answer=adv_ans)
        self.assertEqual(adv_rpt.final_score, 100.0)
        self.assertIn(DIM_RETRIEVAL_EFFECTIVENESS, adv_rpt.na_dimension_ids)
        ret_dim = next(d for d in adv_rpt.dimension_scores if d.dimension_id == DIM_RETRIEVAL_EFFECTIVENESS)
        self.assertIsNone(ret_dim.raw_score)
        self.assertEqual(ret_dim.normalized_weight_pct, 0.0)
        self.assertAlmostEqual(sum(d.normalized_weight_pct for d in adv_rpt.dimension_scores if d.applicable), 100.0, places=2)

        # K-02 Seviye 1 (classify_score_band sınır değerleri & veto önceliği)
        self.assertEqual(classify_score_band(85.00), (85.0, VERDICT_PASS))
        self.assertEqual(classify_score_band(84.99), (84.99, VERDICT_PARTIAL_REVIEW))
        self.assertEqual(classify_score_band(80.00), (80.0, VERDICT_PARTIAL_REVIEW))
        self.assertEqual(classify_score_band(79.99), (79.99, VERDICT_FAIL_SCORE))
        self.assertEqual(classify_score_band(95.00, major_count=1), (65.0, VERDICT_FAIL_MAJOR))
        self.assertEqual(classify_score_band(95.00, fatal_count=1), (0.0, VERDICT_FAIL_FATAL))
        self.assertEqual(classify_score_band(95.00, is_infra_failure=True), (None, VERDICT_EVALUATION_INFRA_FAILURE))
        self.assertEqual(classify_score_band(None), (None, VERDICT_EVALUATION_INFRA_FAILURE))

        # K-02 Seviye 2 (Kategori & Split düzeyinde score_tier & veto_present doğrulaması - 100 vaka raporu)
        cat_map = {c.category: c for c in self.report.engineering_diagnostic_metrics.category_summaries}
        self.assertEqual(cat_map[CAT_IS_KANUNU_SOZLESME].score_tier, VERDICT_PASS)
        self.assertEqual(cat_map[CAT_UCRET_SURE_IZIN].score_tier, VERDICT_PARTIAL_REVIEW)
        self.assertEqual(cat_map[CAT_KVKK_6698].score_tier, VERDICT_FAIL_SCORE)
        for cat_sum in cat_map.values():
            self.assertGreaterEqual(cat_sum.avg_score or 0.0, 75.0)
            self.assertEqual(cat_sum.score_tier, classify_score_band(cat_sum.avg_score)[1])
            self.assertEqual(cat_sum.veto_present, (cat_sum.fatal_count > 0 or cat_sum.major_count > 0))
            if cat_sum.fatal_count > 0:
                self.assertEqual(
                    classify_score_band(
                        cat_sum.avg_score,
                        fatal_count=cat_sum.fatal_count,
                        major_count=cat_sum.major_count,
                    )[1],
                    VERDICT_FAIL_FATAL,
                )
        for sp_sum in self.report.engineering_diagnostic_metrics.split_summaries:
            self.assertEqual(sp_sum.score_tier, classify_score_band(sp_sum.avg_score)[1])
            self.assertEqual(sp_sum.veto_present, (sp_sum.fatal_count > 0 or sp_sum.major_count > 0))

        # K-02 Seviye 3 (OfficialBenchmarkMetrics kabul eşiği, 80-84.99 PARTIAL_REVIEW ve <75 kategori tabanı)
        c_d1 = next(c for c in self.dataset.cases if c.case_id == "EVAL-001")
        c_h1 = next(c for c in self.dataset.cases if c.case_id == "EVAL-083")
        c_h2 = next(c for c in self.dataset.cases if c.case_id == "EVAL-091")
        c_kvkk = next(c for c in self.dataset.cases if c.case_id == "EVAL-071")
        c_fatal = next(c for c in self.dataset.cases if c.case_id == "EVAL-028")

        with tempfile.TemporaryDirectory(prefix="wp45_k02_l3_") as td_l3:
            td_l3_p = Path(td_l3)
            priv_p = td_l3_p / "l3_ed_priv.pem"
            pub_p = td_l3_p / "l3_ed_pub.pem"
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(priv_p)],
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
            )
            subprocess.run(
                ["openssl", "pkey", "-in", str(priv_p), "-pubout", "-out", str(pub_p)],
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
            )
            l3_priv = priv_p.read_text(encoding="utf-8")
            l3_pub = pub_p.read_text(encoding="utf-8")
            l3_fp = compute_public_key_fingerprint(l3_pub)
            l3_reg = TrustedLegalApproverRegistry(
                registry_version="reg-k02-l3-v1",
                approvers=(
                    TrustedLegalApproverRecord(
                        approver_id="COUNSEL-K02-L3",
                        approver_role="INDEPENDENT_LABOR_LAW_COUNSEL",
                        bar_association_ref="İstanbul Barosu / 77001",
                        enrollment_status="ENROLLED",
                        key_id="KEY-K02-L3",
                        key_version="v1",
                        algorithm="ED25519",
                        public_key_pem=l3_pub,
                        public_key_fingerprint_sha256=l3_fp,
                        valid_from_utc="2026-01-01T00:00:00Z",
                        valid_until_utc="2027-12-31T23:59:59Z",
                    ),
                ),
            )

            def _sign_l3(c_obj, idx: int):
                return create_signed_answer_key_approval_envelope(
                    case=c_obj,
                    dataset_version="k02-l3",
                    envelope_id=f"ENV-K02-{idx}",
                    nonce=f"nonce-k02-{idx:04d}",
                    approver_id="COUNSEL-K02-L3",
                    approver_role="INDEPENDENT_LABOR_LAW_COUNSEL",
                    key_id="KEY-K02-L3",
                    key_version="v1",
                    algorithm="ED25519",
                    private_key_pem=l3_priv,
                    public_key_fingerprint_sha256=l3_fp,
                    signed_at_utc="2026-11-26T06:40:00Z",
                    legal_rationale="K-02 seviye 3 resmi ölçüm onayı.",
                )

            # 3a) Temiz resmî benchmark (>=85 genel, >=85 holdout, >=80 makro, tüm kategoriler >=75, 0 FATAL) -> PASSED
            ds_pass = EvaluationDataset("k02-l3", "2026-11-26T06:40:00Z", (c_d1, c_h1, c_h2), "k02-pass")
            rpt_pass = self.runner.run_suite(
                ds_pass,
                legal_signoff_envelopes=tuple(_sign_l3(c, i) for i, c in enumerate(ds_pass.cases, 1)),
                approver_registry=l3_reg,
                blind_holdout_mode=False,
            )
            self.assertEqual(rpt_pass.official_benchmark_metrics.official_status, OFFICIAL_STATUS_PASSED)
            self.assertTrue(rpt_pass.official_benchmark_metrics.official_pass_eligible)

            # 3b) PARTIAL_REVIEW (80.0..84.99) resmi benchmark -> BELOW_THRESHOLD (geçemez)
            c_h1_partial = replace(
                c_h1,
                include_historical=True,
                ground_truth=replace(
                    c_h1.ground_truth,
                    expected_historical_source_ids=(
                        "HIST-M1", "HIST-M2", "HIST-M3", "HIST-M4",
                        "HIST-M5", "HIST-M6", "HIST-M7", "HIST-M8",
                    ),
                ),
            )
            ds_partial = EvaluationDataset("k02-l3", "2026-11-26T06:40:00Z", (c_h1_partial,), "k02-partial")
            rpt_partial = self.runner.run_suite(
                ds_partial,
                legal_signoff_envelopes=(_sign_l3(c_h1_partial, 10),),
                approver_registry=l3_reg,
                blind_holdout_mode=False,
            )
            off_partial = rpt_partial.official_benchmark_metrics
            self.assertGreaterEqual(off_partial.official_approved_weighted_index or 0.0, 80.0)
            self.assertLess(off_partial.official_approved_weighted_index or 100.0, 85.0)
            self.assertFalse(off_partial.official_pass_eligible)
            self.assertEqual(off_partial.official_status, OFFICIAL_STATUS_BELOW_THRESHOLD)

            # 3c) Genel >=85, Holdout >=85, Makro >=80, 0 FATAL/MAJOR ama Tekil Kategori (KVKK) < 75.0 -> BELOW_THRESHOLD bloklaması!
            c_kvkk_floor = replace(
                c_kvkk,
                include_historical=True,
                ground_truth=replace(
                    c_kvkk.ground_truth,
                    expected_historical_source_ids=(
                        "HIST-M1", "HIST-M2", "HIST-M3", "HIST-M4",
                        "HIST-M5", "HIST-M6", "HIST-M7", "HIST-M8",
                    ),
                ),
                expected_outcome=replace(
                    c_kvkk.expected_outcome,
                    expected_confidence_statuses=("UNMATCHED",),
                    expected_missing_fields=("m1", "m2", "m3", "m4", "m5", "m6", "m7", "m8", "m9"),
                ),
            )
            ds_floor = EvaluationDataset("k02-l3", "2026-11-26T06:40:00Z", (c_d1, c_h1, c_h2, c_kvkk_floor), "k02-floor")
            rpt_floor = self.runner.run_suite(
                ds_floor,
                legal_signoff_envelopes=tuple(_sign_l3(c, i + 20) for i, c in enumerate(ds_floor.cases)),
                approver_registry=l3_reg,
                blind_holdout_mode=False,
            )
            off_floor = rpt_floor.official_benchmark_metrics
            self.assertGreaterEqual(off_floor.official_approved_weighted_index or 0.0, 85.0)
            self.assertGreaterEqual(off_floor.official_holdout_weighted_index or 0.0, 85.0)
            self.assertGreaterEqual(off_floor.official_macro_category_index or 0.0, 80.0)
            self.assertEqual(off_floor.official_fatal_auto_count, 0)
            self.assertEqual(off_floor.official_major_count, 0)
            self.assertFalse(off_floor.official_pass_eligible)
            self.assertEqual(off_floor.official_status, OFFICIAL_STATUS_BELOW_THRESHOLD)
            self.assertTrue(any("Tekil kategori tabanı < 75.0" in b for b in off_floor.blocking_reasons))

            # 3d) FATAL veto -> FAILED_FATAL_VETO
            ds_fatal = EvaluationDataset("k02-l3", "2026-11-26T06:40:00Z", (c_h1, c_fatal), "k02-fatal")
            rpt_fatal = self.runner.run_suite(
                ds_fatal,
                legal_signoff_envelopes=tuple(_sign_l3(c, i + 40) for i, c in enumerate(ds_fatal.cases)),
                approver_registry=l3_reg,
                blind_holdout_mode=False,
            )
            self.assertFalse(rpt_fatal.official_benchmark_metrics.official_pass_eligible)
            self.assertEqual(rpt_fatal.official_benchmark_metrics.official_status, OFFICIAL_STATUS_FAILED_FATAL_VETO)

    def test_05_full_100_case_manifest_dual_index_and_fixed_retrieval_o05(self) -> None:
        """EV-05 (Y-04, O-02, O-05): 100 vaka raporu, EvaluationRunManifest, çift endeks ve Recall@5/@10/MRR."""
        self.assertEqual(self.report.run_validity, RUN_VALIDITY_VALID)
        diag = self.report.engineering_diagnostic_metrics
        self.assertIsNotNone(diag.diagnostic_all_weighted_index)
        self.assertIsNotNone(diag.diagnostic_macro_category_index)
        self.assertGreaterEqual(diag.diagnostic_all_weighted_index or 0.0, 80.0)
        self.assertGreaterEqual(diag.diagnostic_recall_at_10, diag.diagnostic_recall_at_5)
        self.assertGreater(diag.diagnostic_mrr, 0.0)
        self.assertEqual(len(diag.category_summaries), 7)
        self.assertEqual({s.split: s.total_cases for s in diag.split_summaries}, SPLIT_TARGET_COUNTS)

        mf = self.report.run_manifest
        self.assertTrue(mf.python_version.startswith("3."))
        self.assertEqual(len(mf.kb_corpus_sha256), 64)
        self.assertEqual(len(mf.prompt_template_sha256), 64)
        self.assertEqual(len(mf.rubric_code_sha256), 64)
        self.assertEqual(mf.rag_settings["top_k"], 8)
        self.assertFalse(mf.nondeterministic_sampling)
        self.assertIn("wp43_rag_sha", mf.git_commits)

    def test_06_adversarial_blocked_and_y05_contextual_monetary_classifier(self) -> None:
        """EV-06 (Y-05): 14/14 ADVERSARIAL bloklanır ve MonetaryMentionClassifier girdi vs sınır vs hesaplamayı ayırır."""
        adv_cases = [c for c in self.dataset.cases if c.difficulty == "ADVERSARIAL"]
        adv_ids = {c.case_id for c in adv_cases}
        self.assertGreaterEqual(len(adv_ids), 10)
        for cr in self.report.case_reports:
            if cr.case_id in adv_ids:
                self.assertEqual(cr.fatal_count, 0, msg=f"{cr.case_id} failed: {cr.defects}")
                self.assertEqual(cr.verdict, VERDICT_PASS, msg=f"{cr.case_id} verdict={cr.verdict}")

        # Y-05 Contextual Classifier assertions
        sample_case = next(c for c in self.dataset.cases if c.case_id == "EVAL-058")  # Brut 85.000 TL user input
        res_exempt = classify_monetary_mentions(
            sections_dict={
                "hukuki_sonuc": "Kullanıcı tarafından belirtilen brüt 85.000 TL ücret için hesap yetkisi @ÜcretBordro ajanına aittir; @HukukSGK hesaplama yapmaz.",
                "uygulama": "Kanuni GİB 332 Tebliği 300 TL yemek istisnası sınırı uygulanabilir.",
                "hukuki_degerlendirme": "",
            },
            case=sample_case,
        )
        classes = {m.classification for m in res_exempt}
        self.assertIn(MONETARY_CLASS_USER_INPUT, classes)
        self.assertIn(MONETARY_CLASS_STATUTORY_THRESHOLD, classes)
        self.assertNotIn(MONETARY_CLASS_CALCULATED_PAYMENT, classes)

        res_calc = classify_monetary_mentions(
            sections_dict={
                "hukuki_sonuc": "Hesaplanan net kıdem tazminatı 340.000 TL olarak ödenecektir.",
                "uygulama": "Ara işlem: 4 x 85.000 = 340.000",
                "hukuki_degerlendirme": "",
            },
            case=sample_case,
        )
        self.assertTrue(all(m.classification == MONETARY_CLASS_CALCULATED_PAYMENT for m in res_calc))
        self.assertGreaterEqual(len(res_calc), 2)

    def test_07_determinism_and_wp1_governance_invariants(self) -> None:
        """EV-07: Deterministik content SHA-256 ve WP-1 şema/config/xmldsig/kapalı kapı değişmezliği."""
        subset = [c for c in self.dataset.cases if c.case_id in {"EVAL-001", "EVAL-018", "EVAL-029", "EVAL-083", "EVAL-091"}]
        ds_sub = EvaluationDataset(
            dataset_version="det-sub",
            created_at_utc="2026-11-26T06:20:00Z",
            cases=tuple(subset),
            dataset_sha256="det",
        )
        r1 = self.runner.run_suite(ds_sub, blind_holdout_mode=False)
        r2 = self.runner.run_suite(ds_sub, blind_holdout_mode=False)
        self.assertEqual(r1.report_content_sha256, r2.report_content_sha256)
        self.assertEqual(r1.run_manifest.content_manifest_sha256, r2.run_manifest.content_manifest_sha256)

        schemas = list((PROJECT_ROOT / "schemas").glob("*.json"))
        configs = list((PROJECT_ROOT / "config").glob("*.json"))
        self.assertEqual(len(schemas), 13)
        self.assertEqual(len(configs), 9)
        xmldsig_sha = hashlib.sha256((PROJECT_ROOT / "engine" / "esign5070" / "xmldsig.py").read_bytes()).hexdigest()
        self.assertEqual(xmldsig_sha, EXPECTED_XMLDSIG_SHA256)

        self.assertFalse(self.report.governance_gates["production_use_authorized"])
        self.assertFalse(self.report.governance_gates["qualified_e_signature_5070_production_ready"])
        self.assertFalse(self.report.governance_gates["qualified_e_signature_5070_equivalent"])
        self.assertFalse(self.report.governance_gates["kvkk_data_residency_approved"])
        probe = run_live_integration_probe(project_root=PROJECT_ROOT)
        self.assertFalse(probe["production_use_authorized"])

    def test_08_k03_infra_failure_yields_run_invalid_without_zero_penalizing_model(self) -> None:
        """EV-08 (K-03): Altyapı/araç arızası RUN_INVALID olur (puan üretilmez); bozuk ajan çıktısı 0.0 alır."""
        subset = tuple(c for c in self.dataset.cases if c.case_id in {"EVAL-001", "EVAL-018"})
        ds_sub = EvaluationDataset(
            dataset_version="k03-infra",
            created_at_utc="2026-11-26T06:20:00Z",
            cases=subset,
            dataset_sha256="k03",
        )
        inv_rpt = self.runner.run_suite(
            ds_sub,
            infra_fault_case_ids={"EVAL-001": "Simulated corpus I/O timeout"},
            blind_holdout_mode=False,
        )
        self.assertEqual(inv_rpt.run_validity, RUN_VALIDITY_INVALID)
        self.assertEqual(inv_rpt.infra_failure_count, 1)
        self.assertEqual(inv_rpt.official_benchmark_metrics.official_status, OFFICIAL_STATUS_RUN_INVALID_INFRA)
        self.assertIsNone(inv_rpt.official_benchmark_metrics.official_approved_weighted_index)
        self.assertIsNone(inv_rpt.engineering_diagnostic_metrics.diagnostic_all_weighted_index)
        self.assertIsNone(inv_rpt.engineering_diagnostic_metrics.diagnostic_macro_category_index)
        err_case = next(c for c in inv_rpt.case_reports if c.case_id == "EVAL-001")
        self.assertEqual(err_case.verdict, VERDICT_EVALUATION_INFRA_FAILURE)
        self.assertIsNone(err_case.final_score)

        # Compare with genuine product defect (blank mandatory section -> S_d=0.0 & FAIL_MAJOR)
        clean_case = self.dataset.cases[0]
        b = self.runner._rag.retrieve(RagQueryRequest(query_text=clean_case.query_text, as_of_date=clean_case.as_of_date, facts=clean_case.facts))
        good_ans = self.runner._orch.generate_answer(AnswerGenerationRequest(trace_bundle=b, facts=clean_case.facts))
        corrupt_ans = replace(good_ans, eight_sections=EightSectionAnswer(**{**good_ans.eight_sections.to_dict(), "hukuki_sonuc": ""}))
        scorer = EvaluationRubricScorer(source_registry=self.runner._orch._sources, precedent_registry=self.runner._orch._precedents)
        sig_rpt = scorer.score_case(case=clean_case, trace_bundle=b, answer=corrupt_ans)
        self.assertEqual(sig_rpt.verdict, VERDICT_FAIL_MAJOR)
        leg_dim = next(d for d in sig_rpt.dimension_scores if d.dimension_id == DIM_LEGAL_CORRECTNESS)
        self.assertEqual(leg_dim.raw_score, 0.0)

    def test_09_y03_blind_holdout_redaction_and_access_ledger_contamination_guard(self) -> None:
        """EV-09 (Y-03): Blind HOLDOUT modu vaka detaylarını maskeler ve aşırı tekrarlı erişimi bloklar."""
        subset = tuple(c for c in self.dataset.cases if c.case_id in {"EVAL-001", "EVAL-083"})
        ds_sub = EvaluationDataset(
            dataset_version="y03-holdout",
            created_at_utc="2026-11-26T06:20:00Z",
            cases=subset,
            dataset_sha256="y03",
            holdout_sha256="ho-sha-v1",
        )
        with tempfile.TemporaryDirectory() as td:
            ledger_file = Path(td) / "holdout_access.jsonl"
            ledger = HoldoutAccessLedger(ledger_path=ledger_file, max_runs_per_version=1)

            # 1) İlk kör denetim koşusu başarılı ve HOLDOUT detayı maskelenmiş
            blind_rpt = self.runner.run_suite(
                ds_sub,
                blind_holdout_mode=True,
                holdout_ledger=ledger,
                holdout_operator="AUDITOR-01",
                holdout_purpose="RELEASE_AUDIT",
                fail_on_holdout_contamination=True,
            )
            self.assertEqual(blind_rpt.holdout_redacted_count, 1)
            self.assertIsNotNone(blind_rpt.holdout_access_audit)
            self.assertEqual(blind_rpt.holdout_access_audit.access_count_for_version, 1)
            masked_row = next(r for r in blind_rpt.case_reports if r.split == SPLIT_HOLDOUT)
            self.assertTrue(masked_row.blind_masked)
            self.assertTrue(masked_row.case_id.startswith("HOLDOUT-MASKED-"))
            self.assertEqual(masked_row.defects, ())
            self.assertEqual(masked_row.trace_id, "REDACTED")

            # 2) Aynı HOLDOUT hash'i üzerinde 2. tekrarlı optimizasyon koşusu fail_on_holdout_contamination=True ile engellenir!
            with self.assertRaises(EvaluationIntegrityError) as ctx:
                self.runner.run_suite(
                    ds_sub,
                    blind_holdout_mode=True,
                    holdout_ledger=ledger,
                    holdout_operator="DEV-TUNER",
                    holdout_purpose="TUNING_LOOP",
                    fail_on_holdout_contamination=True,
                )
            self.assertIn("HOLDOUT_CONTAMINATION_RISK_HOLD", str(ctx.exception))

    def test_10_ast_subprocess_isolation_timeout_and_nonzero_exit_audit(self) -> None:
        """EV-10: AST subprocess güvenlik denetimi, sentetik ihlal yakalama, TimeoutExpired, non-zero çıkış ve FD/tmp sızıntısızlığı."""
        target_methods = {"run", "Popen", "call", "check_call", "check_output"}

        def _inspect_subprocess_ast(tree: ast.AST, label: str) -> tuple[int, list[str]]:
            guarded = 0
            found_violations: list[str] = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if (
                        isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "subprocess"
                        and node.func.attr in target_methods
                    ):
                        kw_names = {kw.arg for kw in node.keywords if kw.arg}
                        if "timeout" not in kw_names:
                            found_violations.append(f"{label}:{getattr(node, 'lineno', 0)} missing timeout=")
                        has_stdin = "stdin" in kw_names or "input" in kw_names
                        if not has_stdin:
                            found_violations.append(f"{label}:{getattr(node, 'lineno', 0)} missing stdin/input=")
                        for kw in node.keywords:
                            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                found_violations.append(f"{label}:{getattr(node, 'lineno', 0)} shell=True forbidden")
                        guarded += 1
            return guarded, found_violations

        # 1) Tüm engine/ ve tests/ altındaki .py dosyalarında gerçek AST taraması
        total_calls = 0
        all_violations: list[str] = []
        for folder in (PROJECT_ROOT / "engine", PROJECT_ROOT / "tests"):
            for py_path in sorted(folder.rglob("*.py")):
                tree = ast.parse(py_path.read_text(encoding="utf-8"), filename=str(py_path))
                calls, vios = _inspect_subprocess_ast(tree, str(py_path.relative_to(PROJECT_ROOT)))
                total_calls += calls
                all_violations.extend(vios)
        self.assertGreaterEqual(total_calls, 30)
        self.assertEqual(all_violations, [])

        # 2) Sentetik ihlal yakalama kanıtı (AST kuralları gerçekten bozuk çağrıyı yakalar)
        _, synth_vios = _inspect_subprocess_ast(ast.parse('subprocess.run(["echo", "unsafe"])'), "<synthetic-1>")
        self.assertEqual(len(synth_vios), 2)
        self.assertTrue(any("missing timeout=" in v for v in synth_vios))
        self.assertTrue(any("missing stdin/input=" in v for v in synth_vios))
        _, synth_shell = _inspect_subprocess_ast(
            ast.parse('subprocess.run("echo", shell=True, timeout=1, stdin=subprocess.DEVNULL)'),
            "<synthetic-2>",
        )
        self.assertTrue(any("shell=True forbidden" in v for v in synth_shell))

        # 3) Başlangıç FD & geçici dizin durumu kaydet
        proc_fd = Path("/proc/self/fd")
        before_fds = len(list(proc_fd.iterdir())) if proc_fd.exists() else None
        tmp_root = Path(tempfile.gettempdir())
        before_calisora = {p.name for p in tmp_root.glob("calisora_*")}
        before_wp45 = {p.name for p in tmp_root.glob("wp45_*")}

        # 4) Non-zero exit fail-closed & clean extract uyumluluğu + TimeoutExpired testi
        with tempfile.TemporaryDirectory(prefix="wp45_ev10_") as td10:
            td10_p = Path(td10)
            git_fail_dir = td10_p / "fake_git_repo"
            (git_fail_dir / ".git").mkdir(parents=True)
            self.assertEqual(_git_sha_safe(git_fail_dir, "rev-parse", "HEAD"), "UNKNOWN")

            no_git_dir = td10_p / "clean_extract_dir"
            no_git_dir.mkdir(parents=True)
            self.assertEqual(_git_sha_safe(no_git_dir, "rev-parse", "HEAD"), "CLEAN_EXTRACT_NO_GIT")

            with self.assertRaises(RuntimeError):
                sign_canonical_payload({"k": "v"}, "NOT-A-VALID-PEM-KEY", "ED25519")

            t0 = time.monotonic()
            with self.assertRaises(subprocess.TimeoutExpired):
                subprocess.run(
                    [sys.executable, "-c", "import time; time.sleep(2.0)"],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=0.05,
                    check=False,
                )
            self.assertLess(time.monotonic() - t0, 1.0)

        # 5) FD sızıntısı ve geçici dizin artığı olmamalı
        after_calisora = {p.name for p in tmp_root.glob("calisora_*")}
        after_wp45 = {p.name for p in tmp_root.glob("wp45_*")}
        self.assertEqual(after_calisora, before_calisora)
        self.assertEqual(after_wp45, before_wp45)
        if before_fds is not None:
            after_fds = len(list(proc_fd.iterdir()))
            self.assertLessEqual(abs(after_fds - before_fds), 1)


if __name__ == "__main__":
    unittest.main()
