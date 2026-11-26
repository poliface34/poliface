"""WP-4.5 Evaluation v1.1 Verification Suite: Anti-Leakage, FATAL Veto, Legal Sign-Off Isolation, and 100-Case Run."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from engine.answer import AnswerGenerationRequest, HukukSgkAnswerOrchestrator
from engine.evaluation import (
    CAT_ICTIHAT_YARGITAY_DANISTAY,
    CATEGORY_SPLIT_TARGETS,
    CATEGORY_TARGET_COUNTS,
    DIM_ABSTENTION_ACCURACY,
    DIM_CITATION_INTEGRITY,
    DIM_LEGAL_CORRECTNESS,
    DIM_RETRIEVAL_EFFECTIVENESS,
    DIMENSION_WEIGHTS,
    MISSING_DIM_POLICY_RENORMALIZED,
    OFFICIAL_STATUS_FAILED_FATAL_VETO,
    OFFICIAL_STATUS_UNVERIFIED_ZERO_APPROVED,
    REVIEW_APPROVED_FOR_BENCHMARK,
    REVIEW_PENDING_LEGAL_REVIEW,
    SPLIT_DEV,
    SPLIT_HOLDOUT,
    SPLIT_TARGET_COUNTS,
    SPLIT_VALIDATION,
    TRIGGER_AUTO_DETERMINISTIC,
    TRIGGER_LEGAL_REVIEWER,
    VERDICT_FAIL_FATAL,
    VERDICT_FAIL_MAJOR,
    VERDICT_PASS,
    EvaluationDataset,
    EvaluationIntegrityError,
    EvaluationRubricScorer,
    EvaluationSuiteRunReport,
    HukukSgkEvaluationRunner,
    load_evaluation_dataset,
    sign_case_legal_review,
    verify_dataset_anti_leakage,
)
from engine.rag import HukukSgkRagEngine, RagQueryRequest
from engine.trust_root import run_live_integration_probe

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_XMLDSIG_SHA256 = "b16207b5fb71d7c0d0372838411c7795459ac460c2ff232766ae230b9cbacf85"

_SHARED_EVAL: dict[Path, tuple[HukukSgkEvaluationRunner, EvaluationDataset, EvaluationSuiteRunReport]] = {}


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
        rpt = runner.run_suite(ds)
        _SHARED_EVAL[resolved] = (runner, ds, rpt)
    return _SHARED_EVAL[resolved]


class TestEvaluationWp45V106(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner, cls.dataset, cls.report = _get_shared_eval()

    def test_01_dataset_splits_weights_and_anti_leakage_gate(self) -> None:
        """EV-01: 100 vaka, DEV(40)/VAL(30)/HOLD(30) matrisi, ağırlıklar (%100) ve anti-leakage geçer."""
        self.assertEqual(len(self.dataset.cases), 100)
        self.assertEqual(self.dataset.category_counts(), CATEGORY_TARGET_COUNTS)
        self.assertEqual(self.dataset.split_counts(), SPLIT_TARGET_COUNTS)
        self.assertEqual(self.dataset.category_split_counts(), CATEGORY_SPLIT_TARGETS)
        self.assertEqual(sum(DIMENSION_WEIGHTS.values()), 100)
        self.assertEqual(len(DIMENSION_WEIGHTS), 8)

        ids = [c.case_id for c in self.dataset.cases]
        self.assertEqual(len(set(ids)), 100)
        for c in self.dataset.cases:
            self.assertEqual(c.legal_review.answer_key_sha256, c.expected_answer_key_sha256())
            self.assertEqual(c.legal_review.review_status, REVIEW_PENDING_LEGAL_REVIEW)

        leak = verify_dataset_anti_leakage(self.dataset)
        self.assertTrue(leak.passed, msg=f"Leakage detected: {leak.to_dict()}")
        self.assertEqual(leak.cross_split_cluster_violations, ())
        self.assertEqual(leak.exact_duplicate_violations, ())
        self.assertEqual(leak.near_duplicate_violations, ())
        self.assertLessEqual(leak.max_cross_split_jaccard, 0.55)

    def test_02_anti_leakage_rejects_shared_cluster_and_paraphrase_leakage(self) -> None:
        """EV-02: Farklı kümelere bölünen cluster_id veya yakın kopya metin yüklemede reddedilir."""
        c_dev = next(c for c in self.dataset.cases if c.split == SPLIT_DEV)
        c_hold = next(c for c in self.dataset.cases if c.split == SPLIT_HOLDOUT)

        # 1) Ortak cluster_id sızıntısı testi
        leaked_cluster_case = replace(c_hold, cluster_id=c_dev.cluster_id)
        ds_clu = EvaluationDataset(
            dataset_version="clu-leak",
            created_at_utc="2026-11-26T06:00:00Z",
            cases=(c_dev, leaked_cluster_case),
            dataset_sha256="x",
        )
        leak_clu = verify_dataset_anti_leakage(ds_clu)
        self.assertFalse(leak_clu.passed)
        self.assertTrue(len(leak_clu.cross_split_cluster_violations) == 1)

        # 2) Yakın kopya / ikiz metin Jaccard > 0.55 sızıntısı testi
        leaked_text_case = replace(c_hold, query_text=c_dev.query_text + " detay")
        ds_dup = EvaluationDataset(
            dataset_version="dup-leak",
            created_at_utc="2026-11-26T06:00:00Z",
            cases=(c_dev, leaked_text_case),
            dataset_sha256="y",
        )
        leak_dup = verify_dataset_anti_leakage(ds_dup)
        self.assertFalse(leak_dup.passed)
        self.assertGreater(leak_dup.max_cross_split_jaccard, 0.55)
        self.assertTrue(len(leak_dup.near_duplicate_violations) == 1)

    def test_03_legal_review_signoff_invalidation_and_strict_official_index_isolation(self) -> None:
        """EV-03: Onaysız vakalar resmî endekse giremez; anahtar değişince önceki hukuk onayı düşer."""
        # Anahtarların hiçbiri onaylı değilken resmî endeks mutlaka None ve UNVERIFIED dönmelidir
        off = self.report.official_benchmark_metrics
        self.assertEqual(off.official_status, OFFICIAL_STATUS_UNVERIFIED_ZERO_APPROVED)
        self.assertFalse(off.official_pass_eligible)
        self.assertIsNone(off.official_approved_weighted_index)
        self.assertIsNone(off.official_holdout_weighted_index)
        self.assertIsNone(off.official_dimension_averages)
        self.assertEqual(self.report.approval_coverage.approved_cases_count, 0)
        self.assertEqual(self.report.approval_coverage.legal_review_approval_rate, 0.0)

        # İmzalı onay & tek harf değişiminde invalidation (STALE_KEY_MODIFIED_REAPPROVAL_REQUIRED)
        raw_payload = json.loads(
            (PROJECT_ROOT / "engine" / "evaluation" / "datasets" / "eval_100_hr_sgk_cases.json").read_text(encoding="utf-8")
        )
        first = self.dataset.cases[0]
        signed = sign_case_legal_review(
            first,
            review_status=REVIEW_APPROVED_FOR_BENCHMARK,
            reviewer_id="COUNSEL-AUDIT-01",
            reviewer_role="INDEPENDENT_LABOR_LAW_COUNSEL",
            reviewed_at_utc="2026-11-26T06:10:00Z",
            verification_notes="Mevzuat ve olay tarihi onaylandı.",
        )
        self.assertEqual(signed.legal_review.answer_key_sha256, signed.expected_answer_key_sha256())

        # Onaylanmış vakada query_text değişirse önceki imza yüklemede reddedilmelidir
        raw_payload["cases"][0] = signed.to_dict()
        raw_payload["cases"][0]["query_text"] = signed.query_text + " ek kelime"
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "stale_approved.json"
            p.write_text(json.dumps(raw_payload, ensure_ascii=False), encoding="utf-8")
            with self.assertRaises(EvaluationIntegrityError) as ctx:
                load_evaluation_dataset(p)
            self.assertIn("STALE_KEY_MODIFIED_REAPPROVAL_REQUIRED", str(ctx.exception))

        # Karma onaylı + taslak kümede resmî metrik YALNIZCA onaylıyı sayar (taslağı dışlar!)
        c_dev = sign_case_legal_review(
            next(c for c in self.dataset.cases if c.case_id == "EVAL-001"),
            review_status=REVIEW_APPROVED_FOR_BENCHMARK,
            reviewer_id="COUNSEL-AUDIT-01",
            reviewer_role="INDEPENDENT_LABOR_LAW_COUNSEL",
            reviewed_at_utc="2026-11-26T06:10:00Z",
            verification_notes="Onaylı.",
        )
        c_hold = sign_case_legal_review(
            next(c for c in self.dataset.cases if c.case_id == "EVAL-083"),
            review_status=REVIEW_APPROVED_FOR_BENCHMARK,
            reviewer_id="COUNSEL-AUDIT-01",
            reviewer_role="INDEPENDENT_LABOR_LAW_COUNSEL",
            reviewed_at_utc="2026-11-26T06:10:00Z",
            verification_notes="Onaylı.",
        )
        c_draft_fatal = next(c for c in self.dataset.cases if c.case_id == "EVAL-028")  # Unapproved!
        mixed_ds = EvaluationDataset(
            dataset_version="mixed-rev",
            created_at_utc="2026-11-26T06:10:00Z",
            cases=(c_dev, c_hold, c_draft_fatal),
            dataset_sha256="mix",
        )
        mixed_rpt = self.runner.run_suite(mixed_ds)
        self.assertEqual(mixed_rpt.approval_coverage.approved_cases_count, 2)
        self.assertEqual(mixed_rpt.approval_coverage.pending_or_unapproved_count, 1)
        # EVAL-028 onaysız olduğu için official_fatal_auto_count == 0 kalmalıdır, ancak diagnostic toplamında görünür!
        self.assertEqual(mixed_rpt.official_benchmark_metrics.official_fatal_auto_count, 0)
        self.assertEqual(mixed_rpt.engineering_diagnostic_metrics.fatal_auto_count, 1)
        self.assertGreater(mixed_rpt.official_benchmark_metrics.official_approved_weighted_index or 0.0, 90.0)

    def test_04_auto_vs_reviewer_fatal_weights_minor_and_na_dimension_policy(self) -> None:
        """EV-04: Otomatik FATAL, Hukukçu Override FATAL, MAJOR tavanı, MINOR (-5..-1) ve N/A politikası."""
        orch = self.runner._orch
        rag = self.runner._rag
        scorer = EvaluationRubricScorer(source_registry=orch._sources, precedent_registry=orch._precedents)

        clean_case = next(c for c in self.dataset.cases if c.case_id == "EVAL-001")
        bundle = rag.retrieve(RagQueryRequest(query_text=clean_case.query_text, as_of_date=clean_case.as_of_date, facts=clean_case.facts))
        ans = orch.generate_answer(AnswerGenerationRequest(trace_bundle=bundle, facts=clean_case.facts))

        # 1) MINOR ceza: tek vakada en fazla -5.0 puan düşer ve PASS kalır
        minor_case = replace(
            clean_case,
            expected_outcome=replace(
                clean_case.expected_outcome,
                acceptable_answer_criteria=("yok1", "yok2", "yok3", "yok4"),
            ),
        )
        minor_rpt = scorer.score_case(case=minor_case, trace_bundle=bundle, answer=ans)
        self.assertEqual(minor_rpt.verdict, VERDICT_PASS)
        self.assertEqual(minor_rpt.fatal_count, 0)
        minor_sum = sum(d.penalty_applied for d in minor_rpt.defects if d.severity == "MINOR")
        self.assertGreaterEqual(minor_sum, 1.0)
        self.assertLessEqual(minor_sum, 5.0)
        self.assertGreater(minor_rpt.final_score, 90.0)

        # 2) Otomatik FATAL (F-2 geriye yürütme / F-1 yasaklı kaynak) -> score=0.0, AUTO_DETERMINISTIC
        auto_fatal_case = replace(
            clean_case,
            ground_truth=replace(clean_case.ground_truth, forbidden_source_ids=("MEVZUAT-4857",)),
        )
        auto_rpt = scorer.score_case(case=auto_fatal_case, trace_bundle=bundle, answer=ans)
        self.assertEqual(auto_rpt.verdict, VERDICT_FAIL_FATAL)
        self.assertEqual(auto_rpt.final_score, 0.0)
        self.assertGreaterEqual(auto_rpt.fatal_auto_count, 1)
        self.assertEqual(auto_rpt.fatal_reviewer_count, 0)

        # 3) Hukukçu FATAL Override (AUTO geçerken hukukçu veto koyar) -> score=0.0, INDEPENDENT_LEGAL_REVIEWER
        rev_rpt = scorer.score_case(
            case=clean_case,
            trace_bundle=bundle,
            answer=ans,
            legal_fatal_override=True,
            legal_fatal_override_reason="Maddi hukuk istisnası somut olay sonucunu tersine çevirdi.",
        )
        self.assertEqual(rev_rpt.verdict, VERDICT_FAIL_FATAL)
        self.assertEqual(rev_rpt.final_score, 0.0)
        self.assertEqual(rev_rpt.fatal_auto_count, 0)
        self.assertEqual(rev_rpt.fatal_reviewer_count, 1)
        self.assertEqual(rev_rpt.defects[0].trigger_source, TRIGGER_LEGAL_REVIEWER)

        # 4) Renormalized NA boyut politikası testi
        adv_case = next(c for c in self.dataset.cases if c.case_id == "EVAL-025")
        adv_bundle = rag.retrieve(RagQueryRequest(query_text=adv_case.query_text, as_of_date=adv_case.as_of_date, facts=adv_case.facts))
        adv_ans = orch.generate_answer(
            AnswerGenerationRequest(
                trace_bundle=adv_bundle,
                facts=adv_case.facts,
                override_section_texts=adv_case.adversarial_injections["override_section_texts"],
            )
        )
        renorm_scorer = EvaluationRubricScorer(
            source_registry=orch._sources,
            precedent_registry=orch._precedents,
            missing_dimension_policy=MISSING_DIM_POLICY_RENORMALIZED,
        )
        renorm_rpt = renorm_scorer.score_case(case=adv_case, trace_bundle=adv_bundle, answer=adv_ans)
        self.assertEqual(renorm_rpt.final_score, 100.0)
        self.assertIn(DIM_RETRIEVAL_EFFECTIVENESS, renorm_rpt.na_dimension_ids)

    def test_05_full_100_case_diagnostic_telemetry_and_split_breakdown(self) -> None:
        """EV-05: 100 vakanın DEV/VAL/HOLDOUT kırılımları, boyut ortalamaları ve FATAL/MAJOR sayıları tutarlıdır."""
        diag = self.report.engineering_diagnostic_metrics
        self.assertIn("RESMÎ HUKUKİ BAŞARI ENDEKSİ DEĞİLDİR", diag.disclaimer)
        self.assertGreaterEqual(diag.diagnostic_all_weighted_index, 80.0)
        self.assertEqual(len(diag.dimension_averages), 8)
        self.assertEqual(len(diag.category_summaries), 7)
        self.assertEqual({s.split: s.total_cases for s in diag.split_summaries}, SPLIT_TARGET_COUNTS)
        self.assertEqual(
            diag.fatal_defect_total,
            diag.fatal_auto_count + diag.fatal_reviewer_count,
        )
        self.assertGreater(len(diag.corpus_gaps.recommended_backlog_actions), 0)

    def test_06_adversarial_cases_100pct_blocked(self) -> None:
        """EV-06: Tüm ADVERSARIAL enjeksiyon/sahte atıf/bordro/kapalı kapı saldırıları bloklanır."""
        adv_cases = [c for c in self.dataset.cases if c.difficulty == "ADVERSARIAL"]
        adv_ids = {c.case_id for c in adv_cases}
        self.assertGreaterEqual(len(adv_ids), 10)
        for cr in self.report.case_reports:
            if cr.case_id in adv_ids:
                self.assertEqual(cr.fatal_count, 0, msg=f"{cr.case_id} failed: {cr.defects}")
                self.assertEqual(cr.verdict, VERDICT_PASS, msg=f"{cr.case_id} verdict={cr.verdict}")

    def test_07_determinism_and_wp1_governance_invariants(self) -> None:
        """EV-07: Deterministik report_sha256 ve WP-1 şema/config/xmldsig/kapalı kapı değişmezliği."""
        subset = [c for c in self.dataset.cases if c.case_id in {"EVAL-001", "EVAL-018", "EVAL-029", "EVAL-083", "EVAL-091"}]
        ds_sub = EvaluationDataset(
            dataset_version="det-sub",
            created_at_utc="2026-11-26T06:00:00Z",
            cases=tuple(subset),
            dataset_sha256="det",
        )
        r1 = self.runner.run_suite(ds_sub)
        r2 = self.runner.run_suite(ds_sub)
        self.assertEqual(r1.report_sha256, r2.report_sha256)

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


if __name__ == "__main__":
    unittest.main()
