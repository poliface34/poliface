"""WP-4.5 Evaluation Runner with anti-leakage auditing & strict Approved vs Draft index separation."""

from __future__ import annotations

from pathlib import Path

from ..answer import (
    CLAIM_STATUTORY_EVIDENCE,
    AnswerClaimRecord,
    AnswerGenerationRequest,
    HukukSgkAnswerOrchestrator,
)
from ..models import NormReference
from ..rag import HukukSgkRagEngine, RagQueryRequest
from ..trust_root import run_live_integration_probe
from .dataset_loader import load_evaluation_dataset, verify_dataset_anti_leakage
from .models import (
    CATEGORY_TARGET_COUNTS,
    DIM_ABSTENTION_ACCURACY,
    DIM_CITATION_INTEGRITY,
    DIM_RISK_DETECTION,
    DIM_TEMPORAL_ACCURACY,
    DIMENSION_WEIGHTS,
    EVAL_VERSION,
    MISSING_DIM_POLICY_NEUTRAL,
    OFFICIAL_STATUS_BELOW_APPROVAL_COVERAGE,
    OFFICIAL_STATUS_BELOW_THRESHOLD,
    OFFICIAL_STATUS_FAILED_FATAL_VETO,
    OFFICIAL_STATUS_PASSED,
    OFFICIAL_STATUS_UNVERIFIED_ZERO_APPROVED,
    REVIEW_APPROVED_FOR_BENCHMARK,
    ROOT_CAUSE_ABSTENTION_OVER_TRIGGER,
    ROOT_CAUSE_KB_CORPUS_GAP,
    ROOT_CAUSE_RAG_RETRIEVAL_MISS,
    SPLIT_HOLDOUT,
    VALID_SPLITS,
    VERDICT_PASS,
    ApprovalCoverageReport,
    CategoryMetricsSummary,
    CorpusGapDiagnosticReport,
    EngineeringDiagnosticMetrics,
    EvaluationCase,
    EvaluationDataset,
    EvaluationSuiteRunReport,
    OfficialBenchmarkMetrics,
    SingleCaseEvalReport,
    SplitMetricsSummary,
    canonical_eval_sha256,
)
from .rubric import EvaluationRubricScorer

DEFAULT_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class HukukSgkEvaluationRunner:
    """Runs WP-4.3 RAG + WP-4.4 Answer Engine across DEV/VALIDATION/HOLDOUT cases and separates official vs draft telemetry."""

    def __init__(
        self,
        *,
        rag_engine: HukukSgkRagEngine,
        answer_orchestrator: HukukSgkAnswerOrchestrator,
        project_root: str | Path | None = None,
        missing_dimension_policy: str = MISSING_DIM_POLICY_NEUTRAL,
    ) -> None:
        self._rag = rag_engine
        self._orch = answer_orchestrator
        self._root = Path(project_root) if project_root is not None else DEFAULT_PROJECT_ROOT
        self._missing_dim_policy = missing_dimension_policy

        store = self._rag._store
        active_chunks = getattr(store, "_active_chunks", {})
        chunks_iter = active_chunks.values() if isinstance(active_chunks, dict) else active_chunks
        self._kb_provisions = {c.provision_id for c in chunks_iter if getattr(c, "provision_id", None)}
        self._kb_sources = {c.source_id for c in chunks_iter if getattr(c, "source_id", None)}
        self._kb_provisions.update(self._orch._cards.keys())

        self._scorer = EvaluationRubricScorer(
            source_registry=self._orch._sources,
            precedent_registry=self._orch._precedents,
            known_kb_provisions=self._kb_provisions,
            known_kb_sources=self._kb_sources,
            missing_dimension_policy=self._missing_dim_policy,
        )

    @classmethod
    def from_project_root(cls, *, project_root: str | Path | None = None) -> HukukSgkEvaluationRunner:
        root = Path(project_root) if project_root is not None else DEFAULT_PROJECT_ROOT
        rag = HukukSgkRagEngine.from_project_root(project_root=root)
        orch = HukukSgkAnswerOrchestrator.from_project_root(project_root=root)
        return cls(rag_engine=rag, answer_orchestrator=orch, project_root=root)

    def evaluate_case(self, case: EvaluationCase) -> SingleCaseEvalReport:
        bundle = self._rag.retrieve(
            RagQueryRequest(
                query_text=case.query_text,
                as_of_date=case.as_of_date,
                facts=dict(case.facts or {}),
                include_historical=case.include_historical,
                top_k=8,
            )
        )
        comp_norm = None
        if case.competing_norm_spec:
            comp_norm = NormReference(
                title=case.competing_norm_spec.get("title", "Yarışan Norm"),
                norm_layer=case.competing_norm_spec.get("norm_layer", "CBA_CONTRACT_AND_HR_PROCEDURE"),
            )

        overrides: dict[str, str] | None = None
        injected_claims: tuple[AnswerClaimRecord, ...] = ()
        if case.adversarial_injections:
            overrides = case.adversarial_injections.get("override_section_texts")
            raw_claims = case.adversarial_injections.get("injected_draft_claims") or ()
            injected_claims = tuple(
                AnswerClaimRecord(
                    claim_id=str(rc.get("claim_id", "CLM-INJECT")),
                    section_name=str(rc.get("section_name", "mevzuat_dayanagi")),
                    claim_category=str(rc.get("claim_category", CLAIM_STATUTORY_EVIDENCE)),
                    statement=str(rc.get("statement", "Enjekte iddia.")),
                    provision_id=rc.get("provision_id"),
                    source_id=rc.get("source_id"),
                    precedent_id=rc.get("precedent_id"),
                    rule_id=rc.get("rule_id"),
                    chunk_id=rc.get("chunk_id"),
                    article_ref=rc.get("article_ref"),
                    law_no=rc.get("law_no"),
                    source_url=rc.get("source_url"),
                    audit_log_id=rc.get("audit_log_id"),
                    content_sha256=rc.get("content_sha256"),
                    chunk_sha256=rc.get("chunk_sha256"),
                    evidence_id=rc.get("evidence_id"),
                    registry_head_sha256=rc.get("registry_head_sha256"),
                    effective_from=rc.get("effective_from"),
                    effective_to=rc.get("effective_to"),
                    effective_on_date=bool(rc.get("effective_on_date", True)),
                )
                for rc in raw_claims
            )

        ans = self._orch.generate_answer(
            AnswerGenerationRequest(
                trace_bundle=bundle,
                facts=dict(case.facts or {}),
                scenario_type=case.scenario_type,
                precedent_application_rationale=case.precedent_application_rationale,
                include_historical_disclosure=case.include_historical,
                competing_norm=comp_norm,
                injected_draft_claims=injected_claims,
                override_section_texts=overrides,
            )
        )
        return self._scorer.score_case(case=case, trace_bundle=bundle, answer=ans)

    @staticmethod
    def _dim_avgs(reports: list[SingleCaseEvalReport] | tuple[SingleCaseEvalReport, ...]) -> dict[str, float]:
        out: dict[str, float] = {}
        for d_id in DIMENSION_WEIGHTS:
            vals = [
                ds_item.raw_score
                for r in reports
                for ds_item in r.dimension_scores
                if ds_item.dimension_id == d_id
            ]
            out[d_id] = (sum(vals) / len(vals)) if vals else 0.0
        return out

    def run_suite(
        self,
        dataset: EvaluationDataset | None = None,
        *,
        approved_only: bool = False,
        splits: frozenset[str] | None = None,
        categories: frozenset[str] | None = None,
    ) -> EvaluationSuiteRunReport:
        ds = dataset if dataset is not None else load_evaluation_dataset()
        leakage_audit = verify_dataset_anti_leakage(ds)

        selected = [
            c
            for c in ds.cases
            if (not approved_only or c.legal_review.review_status == REVIEW_APPROVED_FOR_BENCHMARK)
            and (splits is None or c.split in splits)
            and (categories is None or c.category in categories)
        ]
        reports = tuple(self.evaluate_case(c) for c in selected)
        total = len(reports)
        approved_rpts = [r for r in reports if r.review_status == REVIEW_APPROVED_FOR_BENCHMARK]
        pending_count = total - len(approved_rpts)
        approval_rate = (len(approved_rpts) / len(ds.cases)) if ds.cases else 0.0

        split_cov = {sp: sum(1 for r in reports if r.split == sp) for sp in VALID_SPLITS}
        app_split_cov = {sp: sum(1 for r in approved_rpts if r.split == sp) for sp in VALID_SPLITS}
        approval_coverage = ApprovalCoverageReport(
            total_dataset_cases=len(ds.cases),
            evaluated_cases_count=total,
            approved_cases_count=len(approved_rpts),
            pending_or_unapproved_count=pending_count,
            legal_review_approval_rate=approval_rate,
            split_coverage=split_cov,
            approved_split_coverage=app_split_cov,
        )

        # 1) STRICT OFFICIAL METRICS: Computed EXCLUSIVELY from verified APPROVED_FOR_BENCHMARK cases!
        if not approved_rpts:
            official_metrics = OfficialBenchmarkMetrics(
                official_status=OFFICIAL_STATUS_UNVERIFIED_ZERO_APPROVED,
                official_pass_eligible=False,
                official_approved_weighted_index=None,
                official_holdout_weighted_index=None,
                official_dimension_averages=None,
                official_fatal_auto_count=0,
                official_fatal_reviewer_count=0,
                official_major_count=0,
                blocking_reasons=("Bağımsız hukuk incelemesinden (APPROVED_FOR_BENCHMARK) geçmiş vaka sayısı = 0.",),
            )
        else:
            off_idx = sum(r.final_score for r in approved_rpts) / len(approved_rpts)
            app_holdout = [r for r in approved_rpts if r.split == SPLIT_HOLDOUT]
            off_hold_idx = (sum(r.final_score for r in app_holdout) / len(app_holdout)) if app_holdout else None
            off_dims = self._dim_avgs(approved_rpts)
            off_fatal_auto = sum(r.fatal_auto_count for r in approved_rpts)
            off_fatal_rev = sum(r.fatal_reviewer_count for r in approved_rpts)
            off_major = sum(r.major_count for r in approved_rpts)

            reasons: list[str] = []
            if not leakage_audit.passed:
                reasons.append("Anti-leakage denetimi başarısız.")
            if approval_rate < 1.0:
                reasons.append(f"Hukuk incelemesi onay oranı tam değil ({len(approved_rpts)}/{len(ds.cases)}).")
            if off_fatal_auto > 0 or off_fatal_rev > 0:
                reasons.append(f"Onaylı kümede FATAL hata tespit edildi (oto={off_fatal_auto}, hukukcu={off_fatal_rev}).")
            if off_idx < 85.0:
                reasons.append(f"Onaylı ağırlıklı endeks eşik altında ({off_idx:.2f} < 85.0).")
            if off_hold_idx is None or off_hold_idx < 85.0:
                reasons.append(f"Onaylı HOLDOUT endeksi eşik altında veya eksik ({off_hold_idx}).")
            if off_dims.get(DIM_TEMPORAL_ACCURACY, 0.0) < 95.0:
                reasons.append("TEMPORAL_ACCURACY < 95.0")
            if off_dims.get(DIM_CITATION_INTEGRITY, 0.0) < 98.0:
                reasons.append("CITATION_INTEGRITY < 98.0")
            if off_dims.get(DIM_RISK_DETECTION, 0.0) < 95.0:
                reasons.append("RISK_DETECTION < 95.0")
            if off_dims.get(DIM_ABSTENTION_ACCURACY, 0.0) < 90.0:
                reasons.append("ABSTENTION_ACCURACY < 90.0")

            if off_fatal_auto > 0 or off_fatal_rev > 0:
                off_status = OFFICIAL_STATUS_FAILED_FATAL_VETO
            elif approval_rate < 1.0 or not leakage_audit.passed:
                off_status = OFFICIAL_STATUS_BELOW_APPROVAL_COVERAGE
            elif reasons:
                off_status = OFFICIAL_STATUS_BELOW_THRESHOLD
            else:
                off_status = OFFICIAL_STATUS_PASSED

            official_metrics = OfficialBenchmarkMetrics(
                official_status=off_status,
                official_pass_eligible=(off_status == OFFICIAL_STATUS_PASSED and len(reasons) == 0),
                official_approved_weighted_index=off_idx,
                official_holdout_weighted_index=off_hold_idx,
                official_dimension_averages=off_dims,
                official_fatal_auto_count=off_fatal_auto,
                official_fatal_reviewer_count=off_fatal_rev,
                official_major_count=off_major,
                blocking_reasons=tuple(reasons),
            )

        # 2) ENGINEERING DIAGNOSTIC METRICS: Draft + Full suite telemetry (explicitly NOT official benchmark!)
        diag_idx = (sum(r.final_score for r in reports) / total) if total else 0.0
        diag_dims = self._dim_avgs(reports)
        diag_fatal_auto = sum(r.fatal_auto_count for r in reports)
        diag_fatal_rev = sum(r.fatal_reviewer_count for r in reports)
        diag_fatal_total = diag_fatal_auto + diag_fatal_rev
        diag_major = sum(r.major_count for r in reports)
        diag_mod = sum(r.moderate_count for r in reports)
        diag_min = sum(r.minor_count for r in reports)
        meas_incomplete = sum(1 for r in reports if any("MEASUREMENT_UNAVAILABLE" in df.message for df in r.defects))

        rc_counts: dict[str, int] = {}
        for r in reports:
            for tag in r.root_cause_tags:
                rc_counts[tag] = rc_counts.get(tag, 0) + 1

        split_summaries: list[SplitMetricsSummary] = []
        for sp in VALID_SPLITS:
            sr = [r for r in reports if r.split == sp]
            if not sr and splits is not None and sp not in splits:
                continue
            split_summaries.append(
                SplitMetricsSummary(
                    split=sp,
                    total_cases=len(sr),
                    approved_cases=sum(1 for r in sr if r.review_status == REVIEW_APPROVED_FOR_BENCHMARK),
                    avg_score=(sum(r.final_score for r in sr) / len(sr)) if sr else 0.0,
                    fatal_count=sum(r.fatal_count for r in sr),
                    major_count=sum(r.major_count for r in sr),
                    pass_count=sum(1 for r in sr if r.verdict == VERDICT_PASS),
                )
            )

        cat_summaries: list[CategoryMetricsSummary] = []
        for cat in CATEGORY_TARGET_COUNTS:
            cr = [r for r in reports if r.category == cat]
            if not cr and categories is not None and cat not in categories:
                continue
            cat_summaries.append(
                CategoryMetricsSummary(
                    category=cat,
                    total_cases=len(cr),
                    approved_cases=sum(1 for r in cr if r.review_status == REVIEW_APPROVED_FOR_BENCHMARK),
                    avg_score=(sum(r.final_score for r in cr) / len(cr)) if cr else 0.0,
                    fatal_auto_count=sum(r.fatal_auto_count for r in cr),
                    fatal_reviewer_count=sum(r.fatal_reviewer_count for r in cr),
                    major_count=sum(r.major_count for r in cr),
                    pass_count=sum(1 for r in cr if r.verdict == VERDICT_PASS),
                )
            )

        missing_provs_kb: set[str] = set()
        missing_srcs_kb: set[str] = set()
        kb_gap_cases: list[str] = []
        ret_miss_cases: list[str] = []
        over_abs_cases: list[str] = []

        case_by_id = {c.case_id: c for c in selected}
        for r in reports:
            c = case_by_id[r.case_id]
            for pid in c.ground_truth.required_provision_ids:
                if pid not in self._kb_provisions:
                    missing_provs_kb.add(pid)
            for sid in c.ground_truth.required_source_ids:
                if sid not in self._kb_sources:
                    missing_srcs_kb.add(sid)
            if ROOT_CAUSE_KB_CORPUS_GAP in r.root_cause_tags:
                kb_gap_cases.append(r.case_id)
            if ROOT_CAUSE_RAG_RETRIEVAL_MISS in r.root_cause_tags:
                ret_miss_cases.append(r.case_id)
            if ROOT_CAUSE_ABSTENTION_OVER_TRIGGER in r.root_cause_tags:
                over_abs_cases.append(r.case_id)

        backlog_recs: list[str] = []
        if missing_provs_kb:
            backlog_recs.append(f"KB Korpus Eksikliği: {sorted(missing_provs_kb)[:8]}")
        if ret_miss_cases:
            backlog_recs.append(f"RAG Erişim İyileştirmesi (DEV/VAL analizi için): {ret_miss_cases[:8]}")
        if over_abs_cases:
            backlog_recs.append(f"1-Hop Çapraz Referans Daraltma Adayları: {over_abs_cases[:8]}")

        corpus_gaps = CorpusGapDiagnosticReport(
            missing_provisions_in_kb=tuple(sorted(missing_provs_kb)),
            missing_sources_in_kb=tuple(sorted(missing_srcs_kb)),
            cases_impacted_by_kb_gap=tuple(kb_gap_cases),
            retrieval_misses_despite_kb=tuple(ret_miss_cases),
            over_triggered_abstention_cases=tuple(over_abs_cases),
            recommended_backlog_actions=tuple(backlog_recs),
        )

        engineering_metrics = EngineeringDiagnosticMetrics(
            disclaimer="ONAYSIZ TASLAK ANAHTARLARI İÇERİR — RESMÎ HUKUKİ BAŞARI ENDEKSİ DEĞİLDİR",
            diagnostic_all_weighted_index=diag_idx,
            dimension_averages=diag_dims,
            fatal_auto_count=diag_fatal_auto,
            fatal_reviewer_count=diag_fatal_rev,
            fatal_defect_total=diag_fatal_total,
            major_defect_total=diag_major,
            moderate_defect_total=diag_mod,
            minor_defect_total=diag_min,
            measurement_incomplete_count=meas_incomplete,
            root_cause_counts=rc_counts,
            split_summaries=tuple(split_summaries),
            category_summaries=tuple(cat_summaries),
            corpus_gaps=corpus_gaps,
        )

        probe = run_live_integration_probe(project_root=self._root)
        gov_gates = {
            "production_use_authorized": probe["production_use_authorized"],
            "qualified_e_signature_5070_production_ready": probe["qualified_e_signature_5070_production_ready"],
            "qualified_e_signature_5070_equivalent": probe["qualified_e_signature_5070_equivalent"],
            "kvkk_data_residency_approved": probe["production_authorization_decision"]["checks"][
                "kvkk_data_residency_approved"
            ],
        }

        report_sha = canonical_eval_sha256(
            {
                "eval_version": EVAL_VERSION,
                "dataset_sha256": ds.dataset_sha256,
                "official": official_metrics.to_dict(),
                "diagnostic_idx": round(diag_idx, 4),
                "case_hashes": [r.answer_sha256 for r in reports],
            }
        )

        return EvaluationSuiteRunReport(
            eval_version=EVAL_VERSION,
            dataset_version=ds.dataset_version,
            dataset_sha256=ds.dataset_sha256,
            missing_dimension_policy=self._missing_dim_policy,
            approval_coverage=approval_coverage,
            leakage_audit=leakage_audit,
            official_benchmark_metrics=official_metrics,
            engineering_diagnostic_metrics=engineering_metrics,
            case_reports=reports,
            governance_gates=gov_gates,
            report_sha256=report_sha,
        )
