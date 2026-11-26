"""WP-4.5 v1.2 Evaluation Runner: K-01/K-03/Y-02/Y-03/Y-04/Y-05/O-02/O-04/O-05 enforcement."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import platform
import subprocess
import sys
from typing import Any

from ..answer import (
    ANSWER_VERSION,
    CLAIM_STATUTORY_EVIDENCE,
    AnswerClaimRecord,
    AnswerGenerationRequest,
    HukukSgkAnswerOrchestrator,
)
from ..models import NormReference
from ..rag import HukukSgkRagEngine, RagQueryRequest
from ..trust_root import run_live_integration_probe
from .dataset_loader import HoldoutAccessLedger, load_evaluation_dataset, verify_dataset_anti_leakage
from .legal_signoff import (
    SIGNOFF_PENDING,
    SIGNOFF_REVOKED,
    SIGNOFF_STALE,
    SIGNOFF_VERIFIED_APPROVED,
    EngineeringDisputeMemo,
    SignedAnswerKeyApprovalEnvelope,
    TrustedLegalApproverRegistry,
    VerifiedCaseSignoffState,
    verify_detached_legal_signoffs,
)
from .models import (
    CATEGORY_TARGET_COUNTS,
    DIM_ABSTENTION_ACCURACY,
    DIM_CITATION_INTEGRITY,
    DIM_RETRIEVAL_EFFECTIVENESS,
    DIM_RISK_DETECTION,
    DIM_TEMPORAL_ACCURACY,
    DIMENSION_WEIGHTS,
    EVAL_VERSION,
    MISSING_DIM_POLICY_RENORMALIZED,
    OFFICIAL_STATUS_BELOW_APPROVAL_COVERAGE,
    OFFICIAL_STATUS_BELOW_THRESHOLD,
    OFFICIAL_STATUS_FAILED_FATAL_VETO,
    OFFICIAL_STATUS_PASSED,
    OFFICIAL_STATUS_RUN_INVALID_INFRA,
    OFFICIAL_STATUS_UNVERIFIED_ZERO_APPROVED,
    ROOT_CAUSE_ABSTENTION_OVER_TRIGGER,
    ROOT_CAUSE_INFRA_FAILURE,
    ROOT_CAUSE_KB_CORPUS_GAP,
    ROOT_CAUSE_RAG_RETRIEVAL_MISS,
    RUN_VALIDITY_INVALID,
    RUN_VALIDITY_VALID,
    SPLIT_HOLDOUT,
    VALID_MISSING_DIM_POLICIES,
    VALID_SPLITS,
    VERDICT_EVALUATION_INFRA_FAILURE,
    VERDICT_PASS,
    ApprovalCoverageReport,
    CategoryMetricsSummary,
    CorpusGapDiagnosticReport,
    EngineeringDiagnosticMetrics,
    EvaluationCase,
    EvaluationDataset,
    EvaluationIntegrityError,
    EvaluationRunManifest,
    EvaluationSuiteRunReport,
    HoldoutAccessRecord,
    OfficialBenchmarkMetrics,
    SingleCaseEvalReport,
    SplitMetricsSummary,
    canonical_eval_sha256,
)
from .rubric import EvaluationRubricScorer

DEFAULT_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def _file_sha256_safe(path: Path) -> str:
    if path.exists() and path.is_file():
        return hashlib.sha256(path.read_bytes()).hexdigest()
    return "MISSING"


def _git_sha_safe(project_root: Path, *args: str) -> str:
    repo_root = project_root.parent if (project_root.parent / ".git").exists() else project_root
    if not (repo_root / ".git").exists():
        return "CLEAN_EXTRACT_NO_GIT"
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(repo_root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=2.0,
            text=True,
            check=False,
        )
        out = (proc.stdout or "").strip() if proc.returncode == 0 else ""
        return out or "UNKNOWN"
    except Exception:
        return "UNKNOWN"


class HukukSgkEvaluationRunner:
    """Runs WP-4.3 RAG + WP-4.4 Answer Engine across DEV/VALIDATION/HOLDOUT vaults per WP4_5 v1.2."""

    def __init__(
        self,
        *,
        rag_engine: HukukSgkRagEngine,
        answer_orchestrator: HukukSgkAnswerOrchestrator,
        project_root: str | Path | None = None,
        missing_dimension_policy: str = MISSING_DIM_POLICY_RENORMALIZED,
    ) -> None:
        if missing_dimension_policy not in VALID_MISSING_DIM_POLICIES:
            raise EvaluationIntegrityError(
                f"Y-02 ihlali: '{missing_dimension_policy}' desteklenmez; yalnızca {MISSING_DIM_POLICY_RENORMALIZED}."
            )
        self._rag = rag_engine
        self._orch = answer_orchestrator
        self._root = Path(project_root) if project_root is not None else DEFAULT_PROJECT_ROOT
        self._missing_dim_policy = missing_dimension_policy

        store = self._rag._store
        active_chunks = getattr(store, "_active_chunks", {})
        chunks_iter = active_chunks.values() if isinstance(active_chunks, dict) else active_chunks
        self._kb_chunks_list = list(chunks_iter)
        self._kb_provisions = {c.provision_id for c in self._kb_chunks_list if getattr(c, "provision_id", None)}
        self._kb_sources = {c.source_id for c in self._kb_chunks_list if getattr(c, "source_id", None)}
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

    def evaluate_case(
        self,
        case: EvaluationCase,
        *,
        signoff_state: VerifiedCaseSignoffState | None = None,
        simulate_infra_error: str | None = None,
    ) -> SingleCaseEvalReport:
        """Execute 1 case with K-03 infra-failure isolation (infra exceptions NEVER become score 0.0)."""
        try:
            if simulate_infra_error:
                raise RuntimeError(simulate_infra_error)

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
            return self._scorer.score_case(case=case, trace_bundle=bundle, answer=ans, signoff_state=signoff_state)
        except Exception as exc:
            # K-03: Infrastructure/runner/tool exception -> EVALUATION_INFRA_FAILURE (NEVER penalize model score!)
            return SingleCaseEvalReport(
                case_id=case.case_id,
                category=case.category,
                split=case.split,
                cluster_id=case.cluster_id,
                difficulty=case.difficulty,
                review_status=case.legal_review.review_status,
                legal_signoff_status=signoff_state.signoff_status if signoff_state else SIGNOFF_PENDING,
                verdict=VERDICT_EVALUATION_INFRA_FAILURE,
                raw_weighted_score=None,
                final_score=None,
                dimension_scores=(),
                evaluated_dimension_ids=(),
                na_dimension_ids=(),
                defects=(),
                root_cause_tags=(ROOT_CAUSE_INFRA_FAILURE,),
                observed_status="INFRA_ERROR",
                observed_confidence="INFRA_ERROR",
                observed_risk_level="LOW",
                counsel_escalation_required=False,
                payroll_handoff_allowed=False,
                published_answer_blocked=False,
                trace_id="",
                answer_id="",
                answer_sha256="",
                retrieval_provision_recall_at_5=0.0,
                retrieval_provision_recall_at_10=0.0,
                retrieval_source_hit_rate_at_5=0.0,
                retrieval_source_hit_rate_at_10=0.0,
                retrieval_mrr=0.0,
                infra_failure_reason=f"{type(exc).__name__}: {exc}",
                approval_history=signoff_state.approval_history if signoff_state else (),
                override_history=signoff_state.override_history if signoff_state else (),
            )

    @staticmethod
    def _dim_avgs(reports: list[SingleCaseEvalReport] | tuple[SingleCaseEvalReport, ...]) -> dict[str, float] | None:
        valid = [r for r in reports if not r.is_infra_failure]
        if not valid:
            return None
        out: dict[str, float] = {}
        for d_id in DIMENSION_WEIGHTS:
            # Y-02: Compute average ONLY across cases where this dimension WAS applicable (raw_score is not None)
            vals = [
                ds_item.raw_score
                for r in valid
                for ds_item in r.dimension_scores
                if ds_item.dimension_id == d_id and ds_item.applicable and ds_item.raw_score is not None
            ]
            out[d_id] = (sum(vals) / len(vals)) if vals else 100.0
        return out

    @staticmethod
    def _macro_category_index(reports: list[SingleCaseEvalReport] | tuple[SingleCaseEvalReport, ...]) -> float | None:
        valid = [r for r in reports if not r.is_infra_failure and r.final_score is not None]
        if not valid:
            return None
        cat_means: list[float] = []
        for cat in CATEGORY_TARGET_COUNTS:
            cat_scores = [r.final_score for r in valid if r.category == cat and r.final_score is not None]
            if cat_scores:
                cat_means.append(sum(cat_scores) / len(cat_scores))
        return (sum(cat_means) / len(cat_means)) if cat_means else None

    def _build_run_manifest(
        self,
        *,
        ds: EvaluationDataset,
        evaluated_at_utc: str,
        ordering_mode: str,
        random_seed: int | None,
    ) -> EvaluationRunManifest:
        kb_sha = canonical_eval_sha256(
            {
                "chunks": sorted(getattr(c, "chunk_sha256", "") or getattr(c, "chunk_id", "") for c in self._kb_chunks_list),
                "sources": sorted(self._kb_sources),
                "cards": sorted(self._orch._cards.keys()),
            }
        )
        ans_cfg_sha = _file_sha256_safe(self._root / "engine" / "answer" / "models.py")
        prompt_sha = _file_sha256_safe(self._root / "engine" / "answer" / "formatter.py")
        eval_dir = self._root / "engine" / "evaluation"
        rubric_sha = canonical_eval_sha256(
            {
                "models": _file_sha256_safe(eval_dir / "models.py"),
                "rubric": _file_sha256_safe(eval_dir / "rubric.py"),
                "runner": _file_sha256_safe(eval_dir / "runner.py"),
                "signoff": _file_sha256_safe(eval_dir / "legal_signoff.py"),
                "loader": _file_sha256_safe(eval_dir / "dataset_loader.py"),
            }
        )
        rag_settings = {
            "top_k": 8,
            "strict_temporal_filter": True,
            "max_cross_ref_hops": 1,
            "hybrid_retrieval": True,
            "missing_dimension_policy": self._missing_dim_policy,
        }
        git_commits = {
            "head_sha": _git_sha_safe(self._root, "rev-parse", "HEAD"),
            "wp43_rag_sha": _git_sha_safe(self._root, "log", "-n", "1", "--format=%H", "--", "hrai_hukuk_sgk/engine/rag"),
            "wp44_answer_sha": _git_sha_safe(self._root, "log", "-n", "1", "--format=%H", "--", "hrai_hukuk_sgk/engine/answer"),
            "wp45_eval_sha": _git_sha_safe(self._root, "log", "-n", "1", "--format=%H", "--", "hrai_hukuk_sgk/engine/evaluation"),
        }
        content_payload = {
            "eval_version": EVAL_VERSION,
            "agent_version": ANSWER_VERSION,
            "kb_corpus_sha256": kb_sha,
            "rag_settings": rag_settings,
            "answer_engine_config_sha256": ans_cfg_sha,
            "prompt_template_sha256": prompt_sha,
            "rubric_code_sha256": rubric_sha,
            "dataset_version": ds.dataset_version,
            "dataset_sha256": ds.dataset_sha256,
            "dev_val_sha256": ds.dev_val_sha256,
            "holdout_sha256": ds.holdout_sha256,
            "as_of_date_policy": "PER_CASE_IMMUTABLE_EVENT_DATE",
            "random_seed": random_seed,
            "test_ordering_mode": ordering_mode,
            "nondeterministic_sampling": False,
        }
        content_sha = canonical_eval_sha256(content_payload)
        full_sha = canonical_eval_sha256(
            {
                **content_payload,
                "python_version": sys.version.split()[0],
                "platform": platform.platform(),
                "evaluated_at_utc": evaluated_at_utc,
                "git_commits": git_commits,
            }
        )
        return EvaluationRunManifest(
            eval_version=EVAL_VERSION,
            agent_version=ANSWER_VERSION,
            kb_corpus_version="1.0.6-wp4.2",
            kb_corpus_sha256=kb_sha,
            rag_settings=rag_settings,
            answer_engine_config_sha256=ans_cfg_sha,
            prompt_template_sha256=prompt_sha,
            rubric_code_sha256=rubric_sha,
            dataset_version=ds.dataset_version,
            dataset_sha256=ds.dataset_sha256,
            dev_val_sha256=ds.dev_val_sha256,
            holdout_sha256=ds.holdout_sha256,
            python_version=sys.version.split()[0],
            platform=platform.platform(),
            evaluated_at_utc=evaluated_at_utc,
            as_of_date_policy="PER_CASE_IMMUTABLE_EVENT_DATE",
            random_seed=random_seed,
            test_ordering_mode=ordering_mode,
            nondeterministic_sampling=False,
            git_commits=git_commits,
            content_manifest_sha256=content_sha,
            manifest_sha256=full_sha,
        )

    def run_suite(
        self,
        dataset: EvaluationDataset | None = None,
        *,
        legal_signoff_envelopes: tuple[SignedAnswerKeyApprovalEnvelope, ...] = (),
        dispute_memos: tuple[EngineeringDisputeMemo, ...] = (),
        approver_registry: TrustedLegalApproverRegistry | None = None,
        strict_signoff_integrity: bool = False,
        splits: frozenset[str] | None = None,
        categories: frozenset[str] | None = None,
        blind_holdout_mode: bool = True,
        holdout_ledger: HoldoutAccessLedger | None = None,
        holdout_operator: str = "SYSTEM_EVALUATOR",
        holdout_purpose: str = "AUDIT_VERIFICATION",
        fail_on_holdout_contamination: bool = False,
        infra_fault_case_ids: dict[str, str] | None = None,
        ordering_mode: str = "CANONICAL_CASE_ID",
        random_seed: int | None = 0,
    ) -> EvaluationSuiteRunReport:
        ds = dataset if dataset is not None else load_evaluation_dataset()
        leakage_audit = verify_dataset_anti_leakage(ds)

        selected = [
            c
            for c in ds.cases
            if (splits is None or c.split in splits)
            and (categories is None or c.category in categories)
        ]

        fault_map = infra_fault_case_ids or {}
        signoff_by_id: dict[str, VerifiedCaseSignoffState] = {}
        reports_list: list[SingleCaseEvalReport] = []
        for c in selected:
            s_state = verify_detached_legal_signoffs(
                case=c,
                envelopes=legal_signoff_envelopes,
                dispute_memos=dispute_memos,
                registry=approver_registry,
                strict_raise_on_stale_or_invalid=strict_signoff_integrity,
            )
            signoff_by_id[c.case_id] = s_state
            reports_list.append(
                self.evaluate_case(
                    c,
                    signoff_state=s_state,
                    simulate_infra_error=fault_map.get(c.case_id),
                )
            )
        raw_reports = tuple(reports_list)

        infra_failures = [r for r in raw_reports if r.is_infra_failure]
        infra_count = len(infra_failures)
        run_validity = RUN_VALIDITY_INVALID if infra_count > 0 else RUN_VALIDITY_VALID

        valid_reports = [r for r in raw_reports if not r.is_infra_failure]
        total = len(raw_reports)
        approved_rpts = [r for r in valid_reports if r.legal_signoff_status == SIGNOFF_VERIFIED_APPROVED]
        revoked_stale_count = sum(
            1
            for s_st in signoff_by_id.values()
            if s_st.signoff_status in {SIGNOFF_REVOKED, SIGNOFF_STALE} or "REJECTED" in s_st.signoff_status
        )
        pending_count = total - len(approved_rpts)
        approval_rate = (len(approved_rpts) / len(ds.cases)) if ds.cases else 0.0

        split_cov = {sp: sum(1 for r in raw_reports if r.split == sp) for sp in VALID_SPLITS}
        app_split_cov = {sp: sum(1 for r in approved_rpts if r.split == sp) for sp in VALID_SPLITS}
        approval_coverage = ApprovalCoverageReport(
            total_dataset_cases=len(ds.cases),
            evaluated_cases_count=total,
            approved_cases_count=len(approved_rpts),
            pending_or_unapproved_count=pending_count,
            revoked_or_stale_count=revoked_stale_count,
            legal_review_approval_rate=approval_rate,
            split_coverage=split_cov,
            approved_split_coverage=app_split_cov,
        )

        # 1) STRICT OFFICIAL BENCHMARK METRICS (K-01 + K-02 + K-03)
        if run_validity == RUN_VALIDITY_INVALID:
            official_metrics = OfficialBenchmarkMetrics(
                official_status=OFFICIAL_STATUS_RUN_INVALID_INFRA,
                official_pass_eligible=False,
                official_approved_weighted_index=None,
                official_holdout_weighted_index=None,
                official_macro_category_index=None,
                official_dimension_averages=None,
                official_fatal_auto_count=0,
                official_fatal_reviewer_count=0,
                official_major_count=0,
                blocking_reasons=(
                    f"RUN_INVALID (K-03): {infra_count} vakada ölçüm altyapısı hatası oluştu; model puanı üretilmedi. "
                    f"Etkilenen vakalar: {[r.case_id for r in infra_failures]}.",
                ),
            )
        elif not approved_rpts:
            official_metrics = OfficialBenchmarkMetrics(
                official_status=OFFICIAL_STATUS_UNVERIFIED_ZERO_APPROVED,
                official_pass_eligible=False,
                official_approved_weighted_index=None,
                official_holdout_weighted_index=None,
                official_macro_category_index=None,
                official_dimension_averages=None,
                official_fatal_auto_count=0,
                official_fatal_reviewer_count=0,
                official_major_count=0,
                blocking_reasons=(
                    "K-01: Harici TrustedLegalApproverRegistry üzerinde asimetrik imza doğrulamasından geçmiş vaka sayısı = 0.",
                ),
            )
        else:
            off_scores = [r.final_score for r in approved_rpts if r.final_score is not None]
            off_idx = (sum(off_scores) / len(off_scores)) if off_scores else 0.0
            app_holdout_scores = [
                r.final_score for r in approved_rpts if r.split == SPLIT_HOLDOUT and r.final_score is not None
            ]
            off_hold_idx = (sum(app_holdout_scores) / len(app_holdout_scores)) if app_holdout_scores else None
            off_macro_idx = self._macro_category_index(approved_rpts)
            off_dims = self._dim_avgs(approved_rpts) or {}
            off_fatal_auto = sum(r.fatal_auto_count for r in approved_rpts)
            off_fatal_rev = sum(r.fatal_reviewer_count for r in approved_rpts)
            off_major = sum(r.major_count for r in approved_rpts)

            reasons: list[str] = []
            if not leakage_audit.passed:
                reasons.append("Anti-leakage denetimi başarısız.")
            if approval_rate < 1.0:
                reasons.append(f"K-01 Kriptografik hukuk incelemesi tam değil ({len(approved_rpts)}/{len(ds.cases)}).")
            if off_fatal_auto > 0 or off_fatal_rev > 0:
                reasons.append(f"Onaylı kümede FATAL hata tespit edildi (oto={off_fatal_auto}, hukukcu={off_fatal_rev}).")
            if off_idx < 85.0:
                reasons.append(f"Onaylı ağırlıklı endeks eşik altında ({off_idx:.2f} < 85.0).")
            if off_hold_idx is None or off_hold_idx < 85.0:
                reasons.append(f"Onaylı HOLDOUT endeksi eşik altında veya eksik ({off_hold_idx}).")
            if off_macro_idx is None or off_macro_idx < 80.0:
                reasons.append(f"Kategori makro ortalaması eşik altında ({off_macro_idx}).")
            for cat in CATEGORY_TARGET_COUNTS:
                c_scores = [r.final_score for r in approved_rpts if r.category == cat and r.final_score is not None]
                if c_scores:
                    c_avg = sum(c_scores) / len(c_scores)
                    if c_avg < 75.0:
                        reasons.append(f"Tekil kategori tabanı < 75.0 ({cat}={c_avg:.2f}).")
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
                official_macro_category_index=off_macro_idx,
                official_dimension_averages=off_dims,
                official_fatal_auto_count=off_fatal_auto,
                official_fatal_reviewer_count=off_fatal_rev,
                official_major_count=off_major,
                blocking_reasons=tuple(reasons),
            )

        # 2) ENGINEERING DIAGNOSTIC METRICS (K-03 nullifies aggregate scores if RUN_INVALID!)
        valid_scores = [r.final_score for r in valid_reports if r.final_score is not None]
        if run_validity == RUN_VALIDITY_INVALID:
            diag_idx: float | None = None
            diag_macro_idx: float | None = None
            diag_dims: dict[str, float] | None = None
        else:
            diag_idx = (sum(valid_scores) / len(valid_scores)) if valid_scores else 0.0
            diag_macro_idx = self._macro_category_index(valid_reports)
            diag_dims = self._dim_avgs(valid_reports)

        diag_fatal_auto = sum(r.fatal_auto_count for r in valid_reports)
        diag_fatal_rev = sum(r.fatal_reviewer_count for r in valid_reports)
        diag_fatal_total = diag_fatal_auto + diag_fatal_rev
        diag_major = sum(r.major_count for r in valid_reports)
        diag_mod = sum(r.moderate_count for r in valid_reports)
        diag_min = sum(r.minor_count for r in valid_reports)
        signal_defects = sum(
            1
            for r in valid_reports
            if any("MODEL_OUTPUT_SIGNAL_DEFECT" in df.message for df in r.defects)
        )

        ret_active = [r for r in valid_reports if DIM_RETRIEVAL_EFFECTIVENESS in r.evaluated_dimension_ids]
        diag_r5 = (sum(r.retrieval_provision_recall_at_5 for r in ret_active) / len(ret_active)) if ret_active else 1.0
        diag_r10 = (sum(r.retrieval_provision_recall_at_10 for r in ret_active) / len(ret_active)) if ret_active else 1.0
        diag_mrr = (sum(r.retrieval_mrr for r in ret_active) / len(ret_active)) if ret_active else 1.0

        rc_counts: dict[str, int] = {}
        for r in raw_reports:
            for tag in r.root_cause_tags:
                rc_counts[tag] = rc_counts.get(tag, 0) + 1

        split_summaries: list[SplitMetricsSummary] = []
        for sp in VALID_SPLITS:
            sr = [r for r in raw_reports if r.split == sp]
            if not sr and splits is not None and sp not in splits:
                continue
            sp_valid = [r.final_score for r in sr if not r.is_infra_failure and r.final_score is not None]
            sp_avg = (sum(sp_valid) / len(sp_valid)) if (sp_valid and run_validity == RUN_VALIDITY_VALID) else None
            split_summaries.append(
                SplitMetricsSummary(
                    split=sp,
                    total_cases=len(sr),
                    approved_cases=sum(1 for r in sr if r.legal_signoff_status == SIGNOFF_VERIFIED_APPROVED),
                    avg_score=sp_avg,
                    fatal_count=sum(r.fatal_count for r in sr),
                    major_count=sum(r.major_count for r in sr),
                    pass_count=sum(1 for r in sr if r.verdict == VERDICT_PASS),
                )
            )

        cat_summaries: list[CategoryMetricsSummary] = []
        for cat in CATEGORY_TARGET_COUNTS:
            cr = [r for r in raw_reports if r.category == cat]
            if not cr and categories is not None and cat not in categories:
                continue
            c_valid = [r.final_score for r in cr if not r.is_infra_failure and r.final_score is not None]
            c_avg = (sum(c_valid) / len(c_valid)) if (c_valid and run_validity == RUN_VALIDITY_VALID) else None
            cat_summaries.append(
                CategoryMetricsSummary(
                    category=cat,
                    total_cases=len(cr),
                    approved_cases=sum(1 for r in cr if r.legal_signoff_status == SIGNOFF_VERIFIED_APPROVED),
                    avg_score=c_avg,
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
        for r in raw_reports:
            c = case_by_id[r.case_id]
            for pid in c.ground_truth.required_provision_ids:
                if pid not in self._kb_provisions:
                    missing_provs_kb.add(pid)
            for sid in c.ground_truth.required_source_ids:
                if sid not in self._kb_sources:
                    missing_srcs_kb.add(sid)
            label = f"HOLDOUT-MASKED({r.category})" if (blind_holdout_mode and r.split == SPLIT_HOLDOUT) else r.case_id
            if ROOT_CAUSE_KB_CORPUS_GAP in r.root_cause_tags:
                kb_gap_cases.append(label)
            if ROOT_CAUSE_RAG_RETRIEVAL_MISS in r.root_cause_tags:
                ret_miss_cases.append(label)
            if ROOT_CAUSE_ABSTENTION_OVER_TRIGGER in r.root_cause_tags:
                over_abs_cases.append(label)

        backlog_recs: list[str] = []
        if missing_provs_kb:
            backlog_recs.append(f"KB Korpus Eksikliği: {sorted(missing_provs_kb)[:8]}")
        if ret_miss_cases:
            backlog_recs.append(f"RAG Erişim İyileştirmesi (DEV/VAL analizi): {ret_miss_cases[:8]}")
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
            diagnostic_macro_category_index=diag_macro_idx,
            dimension_averages=diag_dims,
            fatal_auto_count=diag_fatal_auto,
            fatal_reviewer_count=diag_fatal_rev,
            fatal_defect_total=diag_fatal_total,
            major_defect_total=diag_major,
            moderate_defect_total=diag_mod,
            minor_defect_total=diag_min,
            measurement_signal_defect_count=signal_defects,
            infra_failure_count=infra_count,
            diagnostic_recall_at_5=diag_r5,
            diagnostic_recall_at_10=diag_r10,
            diagnostic_mrr=diag_mrr,
            root_cause_counts=rc_counts,
            split_summaries=tuple(split_summaries),
            category_summaries=tuple(cat_summaries),
            corpus_gaps=corpus_gaps,
        )

        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        run_manifest = self._build_run_manifest(
            ds=ds,
            evaluated_at_utc=now_utc,
            ordering_mode=ordering_mode,
            random_seed=random_seed,
        )

        # Y-03 Blind Holdout Masking & Access Ledger Audit
        has_holdout = any(r.split == SPLIT_HOLDOUT for r in raw_reports)
        holdout_audit: HoldoutAccessRecord | None = None
        if has_holdout:
            ledger = holdout_ledger if holdout_ledger is not None else HoldoutAccessLedger()
            holdout_audit = ledger.record_access(
                run_id=f"RUN-{run_manifest.content_manifest_sha256[:12].upper()}",
                holdout_dataset_version=ds.dataset_version,
                holdout_sha256=ds.holdout_sha256 or ds.dataset_sha256,
                operator_id=holdout_operator,
                purpose=holdout_purpose,
                executed_at_utc=now_utc,
                run_manifest_sha256=run_manifest.manifest_sha256,
                fail_on_contamination=fail_on_holdout_contamination,
            )

        exposed_reports: list[SingleCaseEvalReport] = []
        redacted_cnt = 0
        holdout_seq = 0
        for r in raw_reports:
            if blind_holdout_mode and r.split == SPLIT_HOLDOUT:
                holdout_seq += 1
                redacted_cnt += 1
                exposed_reports.append(
                    replace(
                        r,
                        case_id=f"HOLDOUT-MASKED-{holdout_seq:02d}",
                        cluster_id="REDACTED_BLIND_HOLDOUT",
                        defects=(),
                        dimension_scores=(),
                        trace_id="REDACTED",
                        answer_id="REDACTED",
                        blind_masked=True,
                    )
                )
            else:
                exposed_reports.append(r)

        probe = run_live_integration_probe(project_root=self._root)
        gov_gates = {
            "production_use_authorized": probe["production_use_authorized"],
            "qualified_e_signature_5070_production_ready": probe["qualified_e_signature_5070_production_ready"],
            "qualified_e_signature_5070_equivalent": probe["qualified_e_signature_5070_equivalent"],
            "kvkk_data_residency_approved": probe["production_authorization_decision"]["checks"][
                "kvkk_data_residency_approved"
            ],
        }

        content_report_sha = canonical_eval_sha256(
            {
                "eval_version": EVAL_VERSION,
                "dataset_sha256": ds.dataset_sha256,
                "run_validity": run_validity,
                "manifest_content_sha256": run_manifest.content_manifest_sha256,
                "official": official_metrics.to_dict(),
                "diagnostic_idx": round(diag_idx, 4) if diag_idx is not None else None,
                "case_hashes": [r.answer_sha256 for r in raw_reports],
            }
        )
        full_report_sha = canonical_eval_sha256(
            {
                "report_content_sha256": content_report_sha,
                "manifest_sha256": run_manifest.manifest_sha256,
            }
        )

        return EvaluationSuiteRunReport(
            eval_version=EVAL_VERSION,
            dataset_version=ds.dataset_version,
            dataset_sha256=ds.dataset_sha256,
            run_validity=run_validity,
            infra_failure_count=infra_count,
            missing_dimension_policy=self._missing_dim_policy,
            blind_holdout_mode=blind_holdout_mode,
            holdout_redacted_count=redacted_cnt,
            holdout_access_audit=holdout_audit,
            run_manifest=run_manifest,
            approval_coverage=approval_coverage,
            leakage_audit=leakage_audit,
            official_benchmark_metrics=official_metrics,
            engineering_diagnostic_metrics=engineering_metrics,
            case_reports=tuple(exposed_reports),
            governance_gates=gov_gates,
            report_content_sha256=content_report_sha,
            report_sha256=full_report_sha,
        )
