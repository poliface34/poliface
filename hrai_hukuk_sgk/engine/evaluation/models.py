"""WP-4.5 Evaluation v1.2 data models, fixed severity math, RunManifest, and canonical SHA-256 helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from typing import Any

EVAL_VERSION = "1.0.6-wp4.5-v1.2"

# 7 Realistic HR/SGK Evaluation Categories (Total = 100 cases)
CAT_IS_KANUNU_SOZLESME = "CAT_IS_KANUNU_SOZLESME"
CAT_SOSYAL_GUVENLIK_SGK = "CAT_SOSYAL_GUVENLIK_SGK"
CAT_UCRET_SURE_IZIN = "CAT_UCRET_SURE_IZIN"
CAT_ISG_6331 = "CAT_ISG_6331"
CAT_KVKK_6698 = "CAT_KVKK_6698"
CAT_ISTEN_AYRILIS_DISIPLIN = "CAT_ISTEN_AYRILIS_DISIPLIN"
CAT_ICTIHAT_YARGITAY_DANISTAY = "CAT_ICTIHAT_YARGITAY_DANISTAY"

CATEGORY_TARGET_COUNTS: dict[str, int] = {
    CAT_IS_KANUNU_SOZLESME: 25,
    CAT_SOSYAL_GUVENLIK_SGK: 20,
    CAT_UCRET_SURE_IZIN: 15,
    CAT_ISG_6331: 10,
    CAT_KVKK_6698: 10,
    CAT_ISTEN_AYRILIS_DISIPLIN: 10,
    CAT_ICTIHAT_YARGITAY_DANISTAY: 10,
}

# Dataset Splits (40 / 30 / 30 stratified by category & group-locked by cluster_id)
SPLIT_DEV = "DEV"
SPLIT_VALIDATION = "VALIDATION"
SPLIT_HOLDOUT = "HOLDOUT"
VALID_SPLITS: tuple[str, ...] = (SPLIT_DEV, SPLIT_VALIDATION, SPLIT_HOLDOUT)

SPLIT_TARGET_COUNTS: dict[str, int] = {
    SPLIT_DEV: 40,
    SPLIT_VALIDATION: 30,
    SPLIT_HOLDOUT: 30,
}

CATEGORY_SPLIT_TARGETS: dict[str, dict[str, int]] = {
    CAT_IS_KANUNU_SOZLESME: {SPLIT_DEV: 10, SPLIT_VALIDATION: 8, SPLIT_HOLDOUT: 7},
    CAT_SOSYAL_GUVENLIK_SGK: {SPLIT_DEV: 8, SPLIT_VALIDATION: 6, SPLIT_HOLDOUT: 6},
    CAT_UCRET_SURE_IZIN: {SPLIT_DEV: 6, SPLIT_VALIDATION: 4, SPLIT_HOLDOUT: 5},
    CAT_ISG_6331: {SPLIT_DEV: 4, SPLIT_VALIDATION: 3, SPLIT_HOLDOUT: 3},
    CAT_KVKK_6698: {SPLIT_DEV: 4, SPLIT_VALIDATION: 3, SPLIT_HOLDOUT: 3},
    CAT_ISTEN_AYRILIS_DISIPLIN: {SPLIT_DEV: 4, SPLIT_VALIDATION: 3, SPLIT_HOLDOUT: 3},
    CAT_ICTIHAT_YARGITAY_DANISTAY: {SPLIT_DEV: 4, SPLIT_VALIDATION: 3, SPLIT_HOLDOUT: 3},
}

MAX_CROSS_SPLIT_JACCARD = 0.55

# 8 Evaluation Dimensions (Weights sum strictly to 100)
DIM_TEMPORAL_ACCURACY = "TEMPORAL_ACCURACY"
DIM_CITATION_INTEGRITY = "CITATION_INTEGRITY"
DIM_LEGAL_CORRECTNESS = "LEGAL_CORRECTNESS"
DIM_SOURCE_ACCURACY = "SOURCE_ACCURACY"
DIM_RISK_DETECTION = "RISK_DETECTION"
DIM_ABSTENTION_ACCURACY = "ABSTENTION_ACCURACY"
DIM_INTERPRETATION_HIERARCHY = "INTERPRETATION_HIERARCHY"
DIM_RETRIEVAL_EFFECTIVENESS = "RETRIEVAL_EFFECTIVENESS"

DIMENSION_WEIGHTS: dict[str, int] = {
    DIM_TEMPORAL_ACCURACY: 18,
    DIM_CITATION_INTEGRITY: 16,
    DIM_LEGAL_CORRECTNESS: 16,
    DIM_SOURCE_ACCURACY: 14,
    DIM_RISK_DETECTION: 12,
    DIM_ABSTENTION_ACCURACY: 10,
    DIM_INTERPRETATION_HIERARCHY: 8,
    DIM_RETRIEVAL_EFFECTIVENESS: 6,
}

MANDATORY_DIMENSIONS: tuple[str, ...] = (
    DIM_CITATION_INTEGRITY,
    DIM_LEGAL_CORRECTNESS,
    DIM_ABSTENTION_ACCURACY,
)

# Y-02: Single mandatory N/A handling policy across all cases
MISSING_DIM_POLICY_RENORMALIZED = "RENORMALIZED_ACTIVE_WEIGHTS"
VALID_MISSING_DIM_POLICIES: frozenset[str] = frozenset({MISSING_DIM_POLICY_RENORMALIZED})

# O-03: Case-wide total MINOR budget cap
CASE_MINOR_BUDGET_CAP = 5.0

# 4 Severity Tiers (Fatal triggers score=0 + suite veto; Minor -1..-5 never vetoes)
SEVERITY_FATAL = "FATAL"
SEVERITY_MAJOR = "MAJOR"
SEVERITY_MODERATE = "MODERATE"
SEVERITY_MINOR = "MINOR"
VALID_DEFECT_SEVERITIES: frozenset[str] = frozenset(
    {SEVERITY_FATAL, SEVERITY_MAJOR, SEVERITY_MODERATE, SEVERITY_MINOR}
)

# Y-01: Single deterministic penalty table eliminating all overlapping/contradictory ranges
DEFECT_FIXED_PENALTIES: dict[str, float] = {
    # FATAL (-100.0)
    "FATAL_WRONG_ARTICLE_OR_SOURCE_CITED": 100.0,
    "FATAL_UNWHITELISTED_CLAIM": 100.0,
    "FATAL_BROKEN_AUDIT_LINEAGE": 100.0,
    "FATAL_RETROACTIVE_LAW_APPLICATION": 100.0,
    "FATAL_REPEALED_STATUTE_AS_CURRENT": 100.0,
    "FATAL_FABRICATED_PRECEDENT_OR_URL": 100.0,
    "FATAL_PENDING_REVIEW_AS_DEFINITIVE": 100.0,
    "FATAL_PRECEDENT_AS_STATUTE": 100.0,
    "FATAL_UNAUTHORIZED_PAYROLL_CALC": 100.0,
    "FATAL_GOVERNANCE_GATE_BREACH": 100.0,
    "LEGAL_FATAL_OVERRIDE": 100.0,
    # MAJOR (strictly [-25.0, -40.0])
    "MAJOR_MISSED_REQUIRED_SOURCE": 25.0,
    "MAJOR_NORM_HIERARCHY_INVERSION": 25.0,
    "MAJOR_WRONG_FINAL_OUTCOME": 30.0,
    "MAJOR_RISK_UNDERESTIMATED": 30.0,
    "MAJOR_MISSED_CRITICAL_EXCEPTION": 30.0,
    "MAJOR_MODEL_OUTPUT_SIGNAL_MISSING": 35.0,
    "MAJOR_MISSED_MANDATORY_ESCALATION": 40.0,
    "MAJOR_WRONG_PAYROLL_HANDOFF_UNLOCK": 40.0,
    "MAJOR_FALSE_ASSUMPTION_ON_MISSING_INFO": 40.0,
    # MODERATE (strictly [-10.0, -15.0])
    "MODERATE_INCOMPLETE_CLARIFICATION_Q": 10.0,
    "MODERATE_PARTIAL_EXCEPTION_COVERAGE": 12.0,
    "MODERATE_RETRIEVAL_PARTIAL_RECALL": 12.0,
    "MODERATE_MISSING_HISTORICAL_SEPARATION": 12.0,
    "MODERATE_CONFIDENCE_MISMATCH": 12.0,
    "MODERATE_L5_L6_TEMPLATE_NOTICE_MISSING": 12.0,
    "MODERATE_FALSE_ABSTENTION": 15.0,
    "MODERATE_MISSING_COUNTER_ARGUMENT": 15.0,
    # MINOR (strictly [-1.0, -5.0], capped at 5.0 per case)
    "MINOR_AUXILIARY_CONTEXT_EXTRA": 1.0,
    "MINOR_MISSING_NONCRITICAL_CRITERION": 2.0,
    "MINOR_PAYROLL_HANDOFF_CONSERVATIVE": 3.0,
}

# Distinction between automated rules vs independent legal reviewer decision
TRIGGER_AUTO_DETERMINISTIC = "AUTO_DETERMINISTIC"
TRIGGER_LEGAL_REVIEWER = "INDEPENDENT_LEGAL_REVIEWER"
VALID_TRIGGER_SOURCES: frozenset[str] = frozenset(
    {TRIGGER_AUTO_DETERMINISTIC, TRIGGER_LEGAL_REVIEWER}
)

# Case Difficulty Levels
DIFFICULTY_STANDARD = "STANDARD"
DIFFICULTY_EDGE_BOUNDARY = "EDGE_BOUNDARY"
DIFFICULTY_ADVERSARIAL = "ADVERSARIAL"
VALID_DIFFICULTIES: frozenset[str] = frozenset(
    {DIFFICULTY_STANDARD, DIFFICULTY_EDGE_BOUNDARY, DIFFICULTY_ADVERSARIAL}
)

# Independent Legal Review Governance Statuses
REVIEW_PENDING_LEGAL_REVIEW = "PENDING_LEGAL_REVIEW"
REVIEW_APPROVED_FOR_BENCHMARK = "APPROVED_FOR_BENCHMARK"
REVIEW_REVISION_REQUIRED = "REVISION_REQUIRED"
REVIEW_REVOKED = "REVOKED_LEGAL_SIGN_OFF"
VALID_REVIEW_STATUSES: frozenset[str] = frozenset(
    {
        REVIEW_PENDING_LEGAL_REVIEW,
        REVIEW_APPROVED_FOR_BENCHMARK,
        REVIEW_REVISION_REQUIRED,
        REVIEW_REVOKED,
    }
)

# K-02 & K-03 Case Verdicts (aligned >=85.0 PASS / 80-84.99 PARTIAL_REVIEW / <80.0 FAIL_SCORE)
VERDICT_PASS = "PASS"
VERDICT_PARTIAL_REVIEW = "PARTIAL_REVIEW"
VERDICT_FAIL_SCORE = "FAIL_SCORE"
VERDICT_FAIL_MAJOR = "FAIL_MAJOR"
VERDICT_FAIL_FATAL = "FAIL_FATAL"
VERDICT_EVALUATION_INFRA_FAILURE = "EVALUATION_INFRA_FAILURE"


def classify_score_band(
    score: float | None,
    *,
    fatal_count: int = 0,
    major_count: int = 0,
    is_infra_failure: bool = False,
) -> tuple[float | None, str]:
    """K-02 Canonical 3-Level Threshold Classifier (PASS >= 85.0, PARTIAL_REVIEW 80..84.99, FAIL_SCORE < 80.0)."""
    if is_infra_failure or score is None:
        return None, VERDICT_EVALUATION_INFRA_FAILURE
    if fatal_count > 0:
        return 0.0, VERDICT_FAIL_FATAL
    if major_count > 0:
        return min(65.0, float(score)), VERDICT_FAIL_MAJOR
    val = float(score)
    if val >= 85.0:
        return val, VERDICT_PASS
    if val >= 80.0:
        return val, VERDICT_PARTIAL_REVIEW
    return val, VERDICT_FAIL_SCORE


# K-03 Suite Run Validity
RUN_VALIDITY_VALID = "VALID"
RUN_VALIDITY_INVALID = "RUN_INVALID"

# Official Benchmark Status Codes
OFFICIAL_STATUS_UNVERIFIED_ZERO_APPROVED = "UNVERIFIED_ZERO_APPROVED_KEYS"
OFFICIAL_STATUS_RUN_INVALID_INFRA = "RUN_INVALID_INFRA_FAILURE"
OFFICIAL_STATUS_BELOW_APPROVAL_COVERAGE = "BELOW_APPROVAL_COVERAGE"
OFFICIAL_STATUS_FAILED_FATAL_VETO = "FAILED_FATAL_VETO"
OFFICIAL_STATUS_BELOW_THRESHOLD = "BELOW_THRESHOLD"
OFFICIAL_STATUS_PASSED = "PASSED"

# Systematic Root-Cause Diagnostic Taxonomy
ROOT_CAUSE_NONE = "NONE"
ROOT_CAUSE_KB_CORPUS_GAP = "KB_CORPUS_GAP"
ROOT_CAUSE_RAG_RETRIEVAL_MISS = "RAG_RETRIEVAL_MISS"
ROOT_CAUSE_RERANKER_NOISE = "RERANKER_NOISE"
ROOT_CAUSE_TEMPORAL_BOUNDARY_MISS = "TEMPORAL_BOUNDARY_MISS"
ROOT_CAUSE_REASONING_EXCEPTION_MISS = "REASONING_EXCEPTION_MISS"
ROOT_CAUSE_RISK_THRESHOLD_MISMATCH = "RISK_THRESHOLD_MISMATCH"
ROOT_CAUSE_ABSTENTION_OVER_TRIGGER = "ABSTENTION_OVER_TRIGGER"
ROOT_CAUSE_ABSTENTION_UNDER_TRIGGER = "ABSTENTION_UNDER_TRIGGER"
ROOT_CAUSE_CITATION_FAILURE = "CITATION_FAILURE"
ROOT_CAUSE_INJECTION_DEFENSE = "INJECTION_DEFENSE"
ROOT_CAUSE_INFRA_FAILURE = "EVALUATION_INFRA_FAILURE"


def canonical_eval_sha256(payload: Any) -> str:
    """Deterministic SHA-256 over canonical UTF-8 JSON representation."""
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class EvaluationIntegrityError(ValueError):
    """Raised when evaluation dataset schema, splits, anti-leakage, or cryptographic legal signoff fails."""


@dataclass(frozen=True)
class GroundTruthSpec:
    required_source_ids: tuple[str, ...] = ()
    optional_source_ids: tuple[str, ...] = ()
    forbidden_source_ids: tuple[str, ...] = ()
    required_provision_ids: tuple[str, ...] = ()
    forbidden_provision_ids: tuple[str, ...] = ()
    expected_historical_source_ids: tuple[str, ...] = ()
    required_precedent_ids: tuple[str, ...] = ()
    critical_exceptions: tuple[str, ...] = ()
    expected_norm_hierarchy_winner: str | None = None
    l5_l6_template_warning_expected: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "required_source_ids": list(self.required_source_ids),
            "optional_source_ids": list(self.optional_source_ids),
            "forbidden_source_ids": list(self.forbidden_source_ids),
            "required_provision_ids": list(self.required_provision_ids),
            "forbidden_provision_ids": list(self.forbidden_provision_ids),
            "expected_historical_source_ids": list(self.expected_historical_source_ids),
            "required_precedent_ids": list(self.required_precedent_ids),
            "critical_exceptions": list(self.critical_exceptions),
            "expected_norm_hierarchy_winner": self.expected_norm_hierarchy_winner,
            "l5_l6_template_warning_expected": self.l5_l6_template_warning_expected,
        }


@dataclass(frozen=True)
class ExpectedOutcomeSpec:
    expected_statuses: tuple[str, ...]
    expected_confidence_statuses: tuple[str, ...]
    expected_published_blocked: bool = False
    expected_min_risk_level: str = "LOW"
    expected_counsel_escalation_required: bool | None = None
    expected_payroll_handoff_allowed: bool | None = None
    expected_missing_fields: tuple[str, ...] = ()
    expected_answer_summary: str = ""
    acceptable_answer_criteria: tuple[str, ...] = ()
    unacceptable_failure_modes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "expected_statuses": list(self.expected_statuses),
            "expected_confidence_statuses": list(self.expected_confidence_statuses),
            "expected_published_blocked": self.expected_published_blocked,
            "expected_min_risk_level": self.expected_min_risk_level,
            "expected_counsel_escalation_required": self.expected_counsel_escalation_required,
            "expected_payroll_handoff_allowed": self.expected_payroll_handoff_allowed,
            "expected_missing_fields": list(self.expected_missing_fields),
            "expected_answer_summary": self.expected_answer_summary,
            "acceptable_answer_criteria": list(self.acceptable_answer_criteria),
            "unacceptable_failure_modes": list(self.unacceptable_failure_modes),
        }


def derive_applicable_dimensions(
    *,
    as_of_date: str | None,
    difficulty: str,
    ground_truth: GroundTruthSpec,
    expected_outcome: ExpectedOutcomeSpec,
) -> tuple[str, ...]:
    """Y-02: Deterministically declare applicable scoring dimensions for a case."""
    dims: list[str] = []
    if as_of_date is not None and "ABSTAINED_OUT_OF_DOMAIN" not in expected_outcome.expected_statuses:
        dims.append(DIM_TEMPORAL_ACCURACY)
    dims.append(DIM_CITATION_INTEGRITY)
    dims.append(DIM_LEGAL_CORRECTNESS)
    has_source_targets = bool(
        ground_truth.required_source_ids
        or ground_truth.required_provision_ids
        or ground_truth.required_precedent_ids
        or ground_truth.forbidden_source_ids
        or ground_truth.forbidden_provision_ids
    )
    if has_source_targets:
        dims.append(DIM_SOURCE_ACCURACY)
    dims.append(DIM_RISK_DETECTION)
    dims.append(DIM_ABSTENTION_ACCURACY)
    if (
        ground_truth.critical_exceptions
        or ground_truth.expected_norm_hierarchy_winner
        or ground_truth.l5_l6_template_warning_expected
    ):
        dims.append(DIM_INTERPRETATION_HIERARCHY)
    if ground_truth.required_source_ids or ground_truth.required_provision_ids:
        dims.append(DIM_RETRIEVAL_EFFECTIVENESS)
    # Keep canonical ordering
    return tuple(d for d in DIMENSION_WEIGHTS if d in dims)


@dataclass(frozen=True)
class IndependentLegalReviewRecord:
    review_status: str
    reviewer_id: str | None
    reviewer_role: str | None
    reviewed_at_utc: str | None
    verification_notes: str
    answer_key_sha256: str
    legal_fatal_override: bool = False
    legal_fatal_override_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "review_status": self.review_status,
            "reviewer_id": self.reviewer_id,
            "reviewer_role": self.reviewer_role,
            "reviewed_at_utc": self.reviewed_at_utc,
            "verification_notes": self.verification_notes,
            "answer_key_sha256": self.answer_key_sha256,
            "legal_fatal_override": self.legal_fatal_override,
            "legal_fatal_override_reason": self.legal_fatal_override_reason,
        }


def compute_case_answer_key_sha256(
    *,
    case_id: str,
    category: str,
    split: str,
    cluster_id: str,
    difficulty: str,
    title: str,
    query_text: str,
    as_of_date: str | None,
    facts: dict[str, Any],
    scenario_type: str | None,
    precedent_application_rationale: str,
    include_historical: bool,
    competing_norm_spec: dict[str, str] | None,
    adversarial_injections: dict[str, Any] | None,
    ground_truth: GroundTruthSpec,
    expected_outcome: ExpectedOutcomeSpec,
    applicable_dimensions: tuple[str, ...] | None = None,
) -> str:
    """Compute canonical SHA-256 sealing ALL immutable case parameters, applicable dims, and answer keys."""
    app_dims = (
        tuple(applicable_dimensions)
        if applicable_dimensions is not None
        else derive_applicable_dimensions(
            as_of_date=as_of_date,
            difficulty=difficulty,
            ground_truth=ground_truth,
            expected_outcome=expected_outcome,
        )
    )
    return canonical_eval_sha256(
        {
            "case_id": case_id,
            "category": category,
            "split": split,
            "cluster_id": cluster_id,
            "difficulty": difficulty,
            "title": title,
            "query_text": query_text,
            "as_of_date": as_of_date,
            "facts": facts,
            "scenario_type": scenario_type,
            "precedent_application_rationale": precedent_application_rationale,
            "include_historical": include_historical,
            "competing_norm_spec": competing_norm_spec,
            "adversarial_injections": adversarial_injections,
            "applicable_dimensions": list(app_dims),
            "ground_truth": ground_truth.to_dict(),
            "expected_outcome": expected_outcome.to_dict(),
        }
    )


@dataclass(frozen=True)
class EvaluationCase:
    case_id: str
    category: str
    split: str
    cluster_id: str
    difficulty: str
    title: str
    query_text: str
    as_of_date: str | None
    facts: dict[str, Any] = field(default_factory=dict)
    scenario_type: str | None = None
    precedent_application_rationale: str = ""
    include_historical: bool = False
    competing_norm_spec: dict[str, str] | None = None
    adversarial_injections: dict[str, Any] | None = None
    applicable_dimensions: tuple[str, ...] = ()
    ground_truth: GroundTruthSpec = field(default_factory=GroundTruthSpec)
    expected_outcome: ExpectedOutcomeSpec = field(
        default_factory=lambda: ExpectedOutcomeSpec(
            expected_statuses=("ANSWERED",),
            expected_confidence_statuses=("VERIFIED", "PARTIALLY_VERIFIED"),
        )
    )
    legal_review: IndependentLegalReviewRecord = field(
        default_factory=lambda: IndependentLegalReviewRecord(
            review_status=REVIEW_PENDING_LEGAL_REVIEW,
            reviewer_id=None,
            reviewer_role=None,
            reviewed_at_utc=None,
            verification_notes="Taslak cevap anahtarı.",
            answer_key_sha256="",
        )
    )

    def resolved_applicable_dimensions(self) -> tuple[str, ...]:
        if self.applicable_dimensions:
            return tuple(d for d in DIMENSION_WEIGHTS if d in self.applicable_dimensions)
        return derive_applicable_dimensions(
            as_of_date=self.as_of_date,
            difficulty=self.difficulty,
            ground_truth=self.ground_truth,
            expected_outcome=self.expected_outcome,
        )

    def expected_answer_key_sha256(self) -> str:
        return compute_case_answer_key_sha256(
            case_id=self.case_id,
            category=self.category,
            split=self.split,
            cluster_id=self.cluster_id,
            difficulty=self.difficulty,
            title=self.title,
            query_text=self.query_text,
            as_of_date=self.as_of_date,
            facts=self.facts,
            scenario_type=self.scenario_type,
            precedent_application_rationale=self.precedent_application_rationale,
            include_historical=self.include_historical,
            competing_norm_spec=self.competing_norm_spec,
            adversarial_injections=self.adversarial_injections,
            ground_truth=self.ground_truth,
            expected_outcome=self.expected_outcome,
            applicable_dimensions=self.resolved_applicable_dimensions(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "category": self.category,
            "split": self.split,
            "cluster_id": self.cluster_id,
            "difficulty": self.difficulty,
            "title": self.title,
            "query_text": self.query_text,
            "as_of_date": self.as_of_date,
            "facts": self.facts,
            "scenario_type": self.scenario_type,
            "precedent_application_rationale": self.precedent_application_rationale,
            "include_historical": self.include_historical,
            "competing_norm_spec": self.competing_norm_spec,
            "adversarial_injections": self.adversarial_injections,
            "applicable_dimensions": list(self.resolved_applicable_dimensions()),
            "ground_truth": self.ground_truth.to_dict(),
            "expected_outcome": self.expected_outcome.to_dict(),
            "legal_review": self.legal_review.to_dict(),
        }


@dataclass(frozen=True)
class EvaluationDataset:
    dataset_version: str
    created_at_utc: str
    cases: tuple[EvaluationCase, ...]
    dataset_sha256: str
    dev_val_sha256: str = ""
    holdout_sha256: str | None = None
    vault_separated: bool = False

    def approved_cases(self) -> tuple[EvaluationCase, ...]:
        return tuple(c for c in self.cases if c.legal_review.review_status == REVIEW_APPROVED_FOR_BENCHMARK)

    def category_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {cat: 0 for cat in CATEGORY_TARGET_COUNTS}
        for c in self.cases:
            counts[c.category] = counts.get(c.category, 0) + 1
        return counts

    def split_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {sp: 0 for sp in VALID_SPLITS}
        for c in self.cases:
            counts[c.split] = counts.get(c.split, 0) + 1
        return counts

    def category_split_counts(self) -> dict[str, dict[str, int]]:
        matrix: dict[str, dict[str, int]] = {
            cat: {sp: 0 for sp in VALID_SPLITS} for cat in CATEGORY_TARGET_COUNTS
        }
        for c in self.cases:
            matrix[c.category][c.split] = matrix[c.category].get(c.split, 0) + 1
        return matrix


@dataclass(frozen=True)
class DimensionScore:
    dimension_id: str
    weight: int
    raw_score: float | None
    applicable: bool = True
    normalized_weight_pct: float = 0.0
    evidence_notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "dimension_id": self.dimension_id,
            "weight": self.weight,
            "normalized_weight_pct": round(self.normalized_weight_pct, 2),
            "raw_score": round(self.raw_score, 2) if self.raw_score is not None else None,
            "applicable": self.applicable,
            "evidence_notes": list(self.evidence_notes),
        }


@dataclass(frozen=True)
class FailureDefectRecord:
    code: str
    severity: str
    trigger_source: str
    dimension_id: str
    penalty_applied: float
    message: str
    root_cause_tag: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "trigger_source": self.trigger_source,
            "dimension_id": self.dimension_id,
            "penalty_applied": round(self.penalty_applied, 2),
            "message": self.message,
            "root_cause_tag": self.root_cause_tag,
        }


@dataclass(frozen=True)
class SingleCaseEvalReport:
    case_id: str
    category: str
    split: str
    cluster_id: str
    difficulty: str
    review_status: str
    verdict: str
    raw_weighted_score: float | None
    final_score: float | None
    dimension_scores: tuple[DimensionScore, ...]
    evaluated_dimension_ids: tuple[str, ...]
    na_dimension_ids: tuple[str, ...]
    defects: tuple[FailureDefectRecord, ...]
    root_cause_tags: tuple[str, ...]
    observed_status: str
    observed_confidence: str
    observed_risk_level: str
    counsel_escalation_required: bool
    payroll_handoff_allowed: bool
    published_answer_blocked: bool
    trace_id: str
    answer_id: str
    answer_sha256: str
    retrieval_provision_recall_at_5: float
    retrieval_provision_recall_at_10: float
    retrieval_source_hit_rate_at_5: float
    retrieval_source_hit_rate_at_10: float
    retrieval_mrr: float
    infra_failure_reason: str | None = None
    legal_signoff_status: str = "UNVERIFIED_PENDING"
    approval_history: tuple[dict[str, Any], ...] = ()
    override_history: tuple[dict[str, Any], ...] = ()
    blind_masked: bool = False

    @property
    def retrieval_provision_recall(self) -> float:
        return self.retrieval_provision_recall_at_5

    @property
    def retrieval_source_hit_rate(self) -> float:
        return self.retrieval_source_hit_rate_at_5

    @property
    def is_infra_failure(self) -> bool:
        return self.verdict == VERDICT_EVALUATION_INFRA_FAILURE

    @property
    def fatal_auto_count(self) -> int:
        return sum(
            1 for d in self.defects if d.severity == SEVERITY_FATAL and d.trigger_source == TRIGGER_AUTO_DETERMINISTIC
        )

    @property
    def fatal_reviewer_count(self) -> int:
        return sum(
            1 for d in self.defects if d.severity == SEVERITY_FATAL and d.trigger_source == TRIGGER_LEGAL_REVIEWER
        )

    @property
    def fatal_count(self) -> int:
        return sum(1 for d in self.defects if d.severity == SEVERITY_FATAL)

    @property
    def major_count(self) -> int:
        return sum(1 for d in self.defects if d.severity == SEVERITY_MAJOR)

    @property
    def moderate_count(self) -> int:
        return sum(1 for d in self.defects if d.severity == SEVERITY_MODERATE)

    @property
    def minor_count(self) -> int:
        return sum(1 for d in self.defects if d.severity == SEVERITY_MINOR)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "category": self.category,
            "split": self.split,
            "cluster_id": self.cluster_id,
            "difficulty": self.difficulty,
            "review_status": self.review_status,
            "legal_signoff_status": self.legal_signoff_status,
            "verdict": self.verdict,
            "raw_weighted_score": round(self.raw_weighted_score, 2)
            if self.raw_weighted_score is not None
            else None,
            "final_score": round(self.final_score, 2) if self.final_score is not None else None,
            "infra_failure_reason": self.infra_failure_reason,
            "blind_masked": self.blind_masked,
            "fatal_auto_count": self.fatal_auto_count,
            "fatal_reviewer_count": self.fatal_reviewer_count,
            "fatal_count": self.fatal_count,
            "major_count": self.major_count,
            "moderate_count": self.moderate_count,
            "minor_count": self.minor_count,
            "evaluated_dimension_ids": list(self.evaluated_dimension_ids),
            "na_dimension_ids": list(self.na_dimension_ids),
            "dimension_scores": [d.to_dict() for d in self.dimension_scores],
            "defects": [df.to_dict() for df in self.defects],
            "root_cause_tags": list(self.root_cause_tags),
            "observed_status": self.observed_status,
            "observed_confidence": self.observed_confidence,
            "observed_risk_level": self.observed_risk_level,
            "counsel_escalation_required": self.counsel_escalation_required,
            "payroll_handoff_allowed": self.payroll_handoff_allowed,
            "published_answer_blocked": self.published_answer_blocked,
            "trace_id": self.trace_id,
            "answer_id": self.answer_id,
            "answer_sha256": self.answer_sha256,
            "retrieval_provision_recall_at_5": round(self.retrieval_provision_recall_at_5, 4),
            "retrieval_provision_recall_at_10": round(self.retrieval_provision_recall_at_10, 4),
            "retrieval_source_hit_rate_at_5": round(self.retrieval_source_hit_rate_at_5, 4),
            "retrieval_source_hit_rate_at_10": round(self.retrieval_source_hit_rate_at_10, 4),
            "retrieval_mrr": round(self.retrieval_mrr, 4),
            "approval_history": list(self.approval_history),
            "override_history": list(self.override_history),
        }


@dataclass(frozen=True)
class LeakageAuditReport:
    passed: bool
    cross_split_cluster_violations: tuple[str, ...]
    exact_duplicate_violations: tuple[str, ...]
    fingerprint_violations: tuple[str, ...]
    near_duplicate_violations: tuple[str, ...]
    max_cross_split_jaccard: float
    jaccard_threshold: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "cross_split_cluster_violations": list(self.cross_split_cluster_violations),
            "exact_duplicate_violations": list(self.exact_duplicate_violations),
            "fingerprint_violations": list(self.fingerprint_violations),
            "near_duplicate_violations": list(self.near_duplicate_violations),
            "max_cross_split_jaccard": round(self.max_cross_split_jaccard, 4),
            "jaccard_threshold": self.jaccard_threshold,
        }


@dataclass(frozen=True)
class ApprovalCoverageReport:
    total_dataset_cases: int
    evaluated_cases_count: int
    approved_cases_count: int
    pending_or_unapproved_count: int
    revoked_or_stale_count: int
    legal_review_approval_rate: float
    split_coverage: dict[str, int]
    approved_split_coverage: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_dataset_cases": self.total_dataset_cases,
            "evaluated_cases_count": self.evaluated_cases_count,
            "approved_cases_count": self.approved_cases_count,
            "pending_or_unapproved_count": self.pending_or_unapproved_count,
            "revoked_or_stale_count": self.revoked_or_stale_count,
            "legal_review_approval_rate": round(self.legal_review_approval_rate, 4),
            "split_coverage": dict(self.split_coverage),
            "approved_split_coverage": dict(self.approved_split_coverage),
        }


@dataclass(frozen=True)
class HoldoutAccessRecord:
    run_id: str
    holdout_dataset_version: str
    holdout_sha256: str
    operator_id: str
    purpose: str
    executed_at_utc: str
    run_manifest_sha256: str
    access_count_for_version: int
    contamination_risk_hold: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "holdout_dataset_version": self.holdout_dataset_version,
            "holdout_sha256": self.holdout_sha256,
            "operator_id": self.operator_id,
            "purpose": self.purpose,
            "executed_at_utc": self.executed_at_utc,
            "run_manifest_sha256": self.run_manifest_sha256,
            "access_count_for_version": self.access_count_for_version,
            "contamination_risk_hold": self.contamination_risk_hold,
        }


@dataclass(frozen=True)
class EvaluationRunManifest:
    eval_version: str
    agent_version: str
    kb_corpus_version: str
    kb_corpus_sha256: str
    rag_settings: dict[str, Any]
    answer_engine_config_sha256: str
    prompt_template_sha256: str
    rubric_code_sha256: str
    dataset_version: str
    dataset_sha256: str
    dev_val_sha256: str
    holdout_sha256: str | None
    python_version: str
    platform: str
    evaluated_at_utc: str
    as_of_date_policy: str
    random_seed: int | None
    test_ordering_mode: str
    nondeterministic_sampling: bool
    git_commits: dict[str, str]
    content_manifest_sha256: str
    manifest_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "eval_version": self.eval_version,
            "agent_version": self.agent_version,
            "kb_corpus_version": self.kb_corpus_version,
            "kb_corpus_sha256": self.kb_corpus_sha256,
            "rag_settings": dict(self.rag_settings),
            "answer_engine_config_sha256": self.answer_engine_config_sha256,
            "prompt_template_sha256": self.prompt_template_sha256,
            "rubric_code_sha256": self.rubric_code_sha256,
            "dataset_version": self.dataset_version,
            "dataset_sha256": self.dataset_sha256,
            "dev_val_sha256": self.dev_val_sha256,
            "holdout_sha256": self.holdout_sha256,
            "python_version": self.python_version,
            "platform": self.platform,
            "evaluated_at_utc": self.evaluated_at_utc,
            "as_of_date_policy": self.as_of_date_policy,
            "random_seed": self.random_seed,
            "test_ordering_mode": self.test_ordering_mode,
            "nondeterministic_sampling": self.nondeterministic_sampling,
            "git_commits": dict(self.git_commits),
            "content_manifest_sha256": self.content_manifest_sha256,
            "manifest_sha256": self.manifest_sha256,
        }


@dataclass(frozen=True)
class OfficialBenchmarkMetrics:
    official_status: str
    official_pass_eligible: bool
    official_approved_weighted_index: float | None
    official_holdout_weighted_index: float | None
    official_macro_category_index: float | None
    official_dimension_averages: dict[str, float] | None
    official_fatal_auto_count: int
    official_fatal_reviewer_count: int
    official_major_count: int
    blocking_reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "official_status": self.official_status,
            "official_pass_eligible": self.official_pass_eligible,
            "official_approved_weighted_index": round(self.official_approved_weighted_index, 2)
            if self.official_approved_weighted_index is not None
            else None,
            "official_holdout_weighted_index": round(self.official_holdout_weighted_index, 2)
            if self.official_holdout_weighted_index is not None
            else None,
            "official_macro_category_index": round(self.official_macro_category_index, 2)
            if self.official_macro_category_index is not None
            else None,
            "official_dimension_averages": {k: round(v, 2) for k, v in self.official_dimension_averages.items()}
            if self.official_dimension_averages is not None
            else None,
            "official_fatal_auto_count": self.official_fatal_auto_count,
            "official_fatal_reviewer_count": self.official_fatal_reviewer_count,
            "official_major_count": self.official_major_count,
            "blocking_reasons": list(self.blocking_reasons),
        }


@dataclass(frozen=True)
class CategoryMetricsSummary:
    category: str
    total_cases: int
    approved_cases: int
    avg_score: float | None
    fatal_auto_count: int
    fatal_reviewer_count: int
    major_count: int
    pass_count: int

    @property
    def fatal_count(self) -> int:
        return self.fatal_auto_count + self.fatal_reviewer_count

    @property
    def score_tier(self) -> str:
        _, tier = classify_score_band(self.avg_score)
        return tier

    @property
    def veto_present(self) -> bool:
        return self.fatal_count > 0 or self.major_count > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "total_cases": self.total_cases,
            "approved_cases": self.approved_cases,
            "avg_score": round(self.avg_score, 2) if self.avg_score is not None else None,
            "score_tier": self.score_tier,
            "veto_present": self.veto_present,
            "fatal_auto_count": self.fatal_auto_count,
            "fatal_reviewer_count": self.fatal_reviewer_count,
            "fatal_count": self.fatal_count,
            "major_count": self.major_count,
            "pass_count": self.pass_count,
        }


@dataclass(frozen=True)
class SplitMetricsSummary:
    split: str
    total_cases: int
    approved_cases: int
    avg_score: float | None
    fatal_count: int
    major_count: int
    pass_count: int

    @property
    def score_tier(self) -> str:
        _, tier = classify_score_band(self.avg_score)
        return tier

    @property
    def veto_present(self) -> bool:
        return self.fatal_count > 0 or self.major_count > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "split": self.split,
            "total_cases": self.total_cases,
            "approved_cases": self.approved_cases,
            "avg_score": round(self.avg_score, 2) if self.avg_score is not None else None,
            "score_tier": self.score_tier,
            "veto_present": self.veto_present,
            "fatal_count": self.fatal_count,
            "major_count": self.major_count,
            "pass_count": self.pass_count,
        }


@dataclass(frozen=True)
class CorpusGapDiagnosticReport:
    missing_provisions_in_kb: tuple[str, ...]
    missing_sources_in_kb: tuple[str, ...]
    cases_impacted_by_kb_gap: tuple[str, ...]
    retrieval_misses_despite_kb: tuple[str, ...]
    over_triggered_abstention_cases: tuple[str, ...]
    recommended_backlog_actions: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "missing_provisions_in_kb": list(self.missing_provisions_in_kb),
            "missing_sources_in_kb": list(self.missing_sources_in_kb),
            "cases_impacted_by_kb_gap": list(self.cases_impacted_by_kb_gap),
            "retrieval_misses_despite_kb": list(self.retrieval_misses_despite_kb),
            "over_triggered_abstention_cases": list(self.over_triggered_abstention_cases),
            "recommended_backlog_actions": list(self.recommended_backlog_actions),
        }


@dataclass(frozen=True)
class EngineeringDiagnosticMetrics:
    disclaimer: str
    diagnostic_all_weighted_index: float | None
    diagnostic_macro_category_index: float | None
    dimension_averages: dict[str, float] | None
    fatal_auto_count: int
    fatal_reviewer_count: int
    fatal_defect_total: int
    major_defect_total: int
    moderate_defect_total: int
    minor_defect_total: int
    measurement_signal_defect_count: int
    infra_failure_count: int
    diagnostic_recall_at_5: float
    diagnostic_recall_at_10: float
    diagnostic_mrr: float
    root_cause_counts: dict[str, int]
    split_summaries: tuple[SplitMetricsSummary, ...]
    category_summaries: tuple[CategoryMetricsSummary, ...]
    corpus_gaps: CorpusGapDiagnosticReport

    def to_dict(self) -> dict[str, Any]:
        return {
            "disclaimer": self.disclaimer,
            "diagnostic_all_weighted_index": round(self.diagnostic_all_weighted_index, 2)
            if self.diagnostic_all_weighted_index is not None
            else None,
            "diagnostic_macro_category_index": round(self.diagnostic_macro_category_index, 2)
            if self.diagnostic_macro_category_index is not None
            else None,
            "dimension_averages": {k: round(v, 2) for k, v in self.dimension_averages.items()}
            if self.dimension_averages is not None
            else None,
            "fatal_auto_count": self.fatal_auto_count,
            "fatal_reviewer_count": self.fatal_reviewer_count,
            "fatal_defect_total": self.fatal_defect_total,
            "major_defect_total": self.major_defect_total,
            "moderate_defect_total": self.moderate_defect_total,
            "minor_defect_total": self.minor_defect_total,
            "measurement_signal_defect_count": self.measurement_signal_defect_count,
            "infra_failure_count": self.infra_failure_count,
            "diagnostic_recall_at_5": round(self.diagnostic_recall_at_5, 4),
            "diagnostic_recall_at_10": round(self.diagnostic_recall_at_10, 4),
            "diagnostic_mrr": round(self.diagnostic_mrr, 4),
            "root_cause_counts": dict(self.root_cause_counts),
            "split_summaries": [s.to_dict() for s in self.split_summaries],
            "category_summaries": [c.to_dict() for c in self.category_summaries],
            "corpus_gaps": self.corpus_gaps.to_dict(),
        }


@dataclass(frozen=True)
class EvaluationSuiteRunReport:
    eval_version: str
    dataset_version: str
    dataset_sha256: str
    run_validity: str
    infra_failure_count: int
    missing_dimension_policy: str
    blind_holdout_mode: bool
    holdout_redacted_count: int
    holdout_access_audit: HoldoutAccessRecord | None
    run_manifest: EvaluationRunManifest
    approval_coverage: ApprovalCoverageReport
    leakage_audit: LeakageAuditReport
    official_benchmark_metrics: OfficialBenchmarkMetrics
    engineering_diagnostic_metrics: EngineeringDiagnosticMetrics
    case_reports: tuple[SingleCaseEvalReport, ...]
    governance_gates: dict[str, Any]
    report_content_sha256: str
    report_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "eval_version": self.eval_version,
            "dataset_version": self.dataset_version,
            "dataset_sha256": self.dataset_sha256,
            "run_validity": self.run_validity,
            "infra_failure_count": self.infra_failure_count,
            "missing_dimension_policy": self.missing_dimension_policy,
            "blind_holdout_mode": self.blind_holdout_mode,
            "holdout_redacted_count": self.holdout_redacted_count,
            "holdout_access_audit": self.holdout_access_audit.to_dict()
            if self.holdout_access_audit is not None
            else None,
            "run_manifest": self.run_manifest.to_dict(),
            "approval_coverage": self.approval_coverage.to_dict(),
            "leakage_audit": self.leakage_audit.to_dict(),
            "official_benchmark_metrics": self.official_benchmark_metrics.to_dict(),
            "engineering_diagnostic_metrics": self.engineering_diagnostic_metrics.to_dict(),
            "governance_gates": self.governance_gates,
            "report_content_sha256": self.report_content_sha256,
            "report_sha256": self.report_sha256,
        }
