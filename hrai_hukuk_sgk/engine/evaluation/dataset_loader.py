"""WP-4.5 Evaluation dataset loader, canonical SHA-256 verification, and 4-layer anti-leakage gate."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import re
from typing import Any

from ..knowledge_base.chunker import tr_fold
from .models import (
    CATEGORY_SPLIT_TARGETS,
    CATEGORY_TARGET_COUNTS,
    EVAL_VERSION,
    MAX_CROSS_SPLIT_JACCARD,
    REVIEW_APPROVED_FOR_BENCHMARK,
    REVIEW_PENDING_LEGAL_REVIEW,
    SPLIT_TARGET_COUNTS,
    VALID_DIFFICULTIES,
    VALID_REVIEW_STATUSES,
    VALID_SPLITS,
    EvaluationCase,
    EvaluationDataset,
    EvaluationIntegrityError,
    ExpectedOutcomeSpec,
    GroundTruthSpec,
    IndependentLegalReviewRecord,
    LeakageAuditReport,
    canonical_eval_sha256,
)

DEFAULT_DATASET_PATH = Path(__file__).resolve().parent / "datasets" / "eval_100_hr_sgk_cases.json"


def _query_shingles(query_text: str) -> set[str]:
    norm = re.sub(r"\s+", " ", re.sub(r"[^\w\s]", " ", tr_fold(query_text))).strip()
    if not norm:
        return set()
    words = [w for w in norm.split(" ") if w]
    shingles: set[str] = set(words)
    compact = " ".join(words)
    if len(compact) >= 4:
        for i in range(len(compact) - 3):
            shingles.add(compact[i : i + 4])
    return shingles


def compute_cross_split_jaccard(text_a: str, text_b: str) -> float:
    sa = _query_shingles(text_a)
    sb = _query_shingles(text_b)
    if not sa or not sb:
        return 0.0
    union = sa | sb
    if not union:
        return 0.0
    return len(sa & sb) / len(union)


def verify_dataset_anti_leakage(
    dataset: EvaluationDataset,
    *,
    max_jaccard_threshold: float = MAX_CROSS_SPLIT_JACCARD,
) -> LeakageAuditReport:
    """Enforce 4 anti-leakage rules across DEV, VALIDATION, and HOLDOUT splits."""
    cluster_to_splits: dict[str, set[str]] = {}
    for c in dataset.cases:
        cluster_to_splits.setdefault(c.cluster_id, set()).add(c.split)

    cluster_violations = tuple(
        sorted(f"{clu}:{sorted(sps)}" for clu, sps in cluster_to_splits.items() if len(sps) > 1)
    )

    exact_dups: list[str] = []
    fingerprint_dups: list[str] = []
    near_dups: list[str] = []
    max_jac = 0.0

    shingles_cache = {c.case_id: _query_shingles(c.query_text) for c in dataset.cases}
    norm_cache = {c.case_id: re.sub(r"\s+", " ", tr_fold(c.query_text)).strip() for c in dataset.cases}
    fp_cache = {
        c.case_id: (
            c.as_of_date,
            tuple(sorted((str(k), repr(v)) for k, v in c.facts.items())),
            tuple(sorted(c.ground_truth.required_provision_ids)),
        )
        for c in dataset.cases
    }

    cases = dataset.cases
    n = len(cases)
    for i in range(n):
        ca = cases[i]
        sa = shingles_cache[ca.case_id]
        na = norm_cache[ca.case_id]
        fpa = fp_cache[ca.case_id]
        for j in range(i + 1, n):
            cb = cases[j]
            if ca.split == cb.split:
                continue
            if na and na == norm_cache[cb.case_id]:
                exact_dups.append(f"{ca.case_id}({ca.split})=={cb.case_id}({cb.split})")
            if fpa == fp_cache[cb.case_id] and (fpa[0] is not None or fpa[2]):
                # Distinguish out-of-domain vs distinct queries cleanly when fingerprints tie
                if ca.ground_truth.required_provision_ids or cb.ground_truth.required_provision_ids:
                    fingerprint_dups.append(f"{ca.case_id}({ca.split})~{cb.case_id}({cb.split})")
            sb = shingles_cache[cb.case_id]
            if sa and sb:
                jac = len(sa & sb) / len(sa | sb)
                if jac > max_jac:
                    max_jac = jac
                if jac > max_jaccard_threshold:
                    near_dups.append(f"{ca.case_id}({ca.split})<->{cb.case_id}({cb.split}):{jac:.3f}")

    passed = (
        not cluster_violations
        and not exact_dups
        and not fingerprint_dups
        and not near_dups
    )
    return LeakageAuditReport(
        passed=passed,
        cross_split_cluster_violations=cluster_violations,
        exact_duplicate_violations=tuple(exact_dups),
        fingerprint_violations=tuple(fingerprint_dups),
        near_duplicate_violations=tuple(near_dups),
        max_cross_split_jaccard=max_jac,
        jaccard_threshold=max_jaccard_threshold,
    )


def _parse_case(raw: dict[str, Any], *, verify_hash: bool = True) -> EvaluationCase:
    cid = str(raw["case_id"])
    cat = str(raw["category"])
    split = str(raw["split"])
    cluster_id = str(raw["cluster_id"])
    diff = str(raw["difficulty"])
    if cat not in CATEGORY_TARGET_COUNTS:
        raise EvaluationIntegrityError(f"{cid}: geçersiz kategori '{cat}'.")
    if split not in VALID_SPLITS:
        raise EvaluationIntegrityError(f"{cid}: geçersiz küme '{split}'.")
    if not cluster_id.strip():
        raise EvaluationIntegrityError(f"{cid}: cluster_id boş olamaz.")
    if diff not in VALID_DIFFICULTIES:
        raise EvaluationIntegrityError(f"{cid}: geçersiz zorluk derecesi '{diff}'.")

    gt_raw = raw.get("ground_truth") or {}
    gt = GroundTruthSpec(
        required_source_ids=tuple(gt_raw.get("required_source_ids") or ()),
        optional_source_ids=tuple(gt_raw.get("optional_source_ids") or ()),
        forbidden_source_ids=tuple(gt_raw.get("forbidden_source_ids") or ()),
        required_provision_ids=tuple(gt_raw.get("required_provision_ids") or ()),
        forbidden_provision_ids=tuple(gt_raw.get("forbidden_provision_ids") or ()),
        expected_historical_source_ids=tuple(gt_raw.get("expected_historical_source_ids") or ()),
        required_precedent_ids=tuple(gt_raw.get("required_precedent_ids") or ()),
        critical_exceptions=tuple(gt_raw.get("critical_exceptions") or ()),
        expected_norm_hierarchy_winner=gt_raw.get("expected_norm_hierarchy_winner"),
        l5_l6_template_warning_expected=bool(gt_raw.get("l5_l6_template_warning_expected", False)),
    )

    exp_raw = raw.get("expected_outcome") or {}
    exp = ExpectedOutcomeSpec(
        expected_statuses=tuple(exp_raw["expected_statuses"]),
        expected_confidence_statuses=tuple(exp_raw["expected_confidence_statuses"]),
        expected_published_blocked=bool(exp_raw.get("expected_published_blocked", False)),
        expected_min_risk_level=str(exp_raw.get("expected_min_risk_level", "LOW")),
        expected_counsel_escalation_required=exp_raw.get("expected_counsel_escalation_required"),
        expected_payroll_handoff_allowed=exp_raw.get("expected_payroll_handoff_allowed"),
        expected_missing_fields=tuple(exp_raw.get("expected_missing_fields") or ()),
        expected_answer_summary=str(exp_raw.get("expected_answer_summary", "")),
        acceptable_answer_criteria=tuple(exp_raw.get("acceptable_answer_criteria") or ()),
        unacceptable_failure_modes=tuple(exp_raw.get("unacceptable_failure_modes") or ()),
    )

    lr_raw = raw.get("legal_review") or {}
    r_status = str(lr_raw.get("review_status") or REVIEW_PENDING_LEGAL_REVIEW)
    if r_status not in VALID_REVIEW_STATUSES:
        raise EvaluationIntegrityError(f"{cid}: geçersiz inceleme statüsü '{r_status}'.")
    lr = IndependentLegalReviewRecord(
        review_status=r_status,
        reviewer_id=lr_raw.get("reviewer_id"),
        reviewer_role=lr_raw.get("reviewer_role"),
        reviewed_at_utc=lr_raw.get("reviewed_at_utc"),
        verification_notes=str(lr_raw.get("verification_notes") or ""),
        answer_key_sha256=str(lr_raw.get("answer_key_sha256") or ""),
        legal_fatal_override=bool(lr_raw.get("legal_fatal_override", False)),
        legal_fatal_override_reason=str(lr_raw.get("legal_fatal_override_reason") or ""),
    )

    case = EvaluationCase(
        case_id=cid,
        category=cat,
        split=split,
        cluster_id=cluster_id,
        difficulty=diff,
        title=str(raw["title"]),
        query_text=str(raw["query_text"]),
        as_of_date=raw.get("as_of_date"),
        facts=dict(raw.get("facts") or {}),
        scenario_type=raw.get("scenario_type"),
        precedent_application_rationale=str(raw.get("precedent_application_rationale") or ""),
        include_historical=bool(raw.get("include_historical", False)),
        competing_norm_spec=raw.get("competing_norm_spec"),
        adversarial_injections=raw.get("adversarial_injections"),
        ground_truth=gt,
        expected_outcome=exp,
        legal_review=lr,
    )

    expected_sha = case.expected_answer_key_sha256()
    if verify_hash and case.legal_review.answer_key_sha256 != expected_sha:
        status_note = (
            "STALE_KEY_MODIFIED_REAPPROVAL_REQUIRED"
            if case.legal_review.review_status == REVIEW_APPROVED_FOR_BENCHMARK
            else "ANSWER_KEY_HASH_MISMATCH"
        )
        raise EvaluationIntegrityError(
            f"{cid} ({status_note}): answer_key_sha256 geçersiz "
            f"(beklenen={expected_sha}, kayıtlı={case.legal_review.answer_key_sha256})."
        )
    return case


def load_evaluation_dataset(
    dataset_path: str | Path | None = None,
    *,
    enforce_target_counts: bool = True,
    enforce_anti_leakage: bool = True,
    verify_hashes: bool = True,
) -> EvaluationDataset:
    """Load and cryptographically validate a WP-4.5 evaluation dataset including splits & anti-leakage."""
    path = Path(dataset_path) if dataset_path is not None else DEFAULT_DATASET_PATH
    payload = json.loads(path.read_text(encoding="utf-8"))
    raw_cases = payload.get("cases") or []
    cases: list[EvaluationCase] = []
    seen_ids: set[str] = set()
    for rc in raw_cases:
        c = _parse_case(rc, verify_hash=verify_hashes)
        if c.case_id in seen_ids:
            raise EvaluationIntegrityError(f"Yinelenen vaka kimliği: '{c.case_id}'.")
        seen_ids.add(c.case_id)
        cases.append(c)

    ds = EvaluationDataset(
        dataset_version=str(payload.get("dataset_version") or EVAL_VERSION),
        created_at_utc=str(payload.get("created_at_utc") or ""),
        cases=tuple(cases),
        dataset_sha256=canonical_eval_sha256([c.to_dict() for c in cases]),
    )
    if enforce_target_counts:
        counts = ds.category_counts()
        if counts != CATEGORY_TARGET_COUNTS:
            raise EvaluationIntegrityError(
                f"WP-4.5 vaka kategori dağılımı 100 vaka hedefiyle uyuşmuyor: {counts} != {CATEGORY_TARGET_COUNTS}."
            )
        scounts = ds.split_counts()
        if scounts != SPLIT_TARGET_COUNTS:
            raise EvaluationIntegrityError(
                f"WP-4.5 küme dağılımı 40/30/30 hedefiyle uyuşmuyor: {scounts} != {SPLIT_TARGET_COUNTS}."
            )
        matrix = ds.category_split_counts()
        if matrix != CATEGORY_SPLIT_TARGETS:
            raise EvaluationIntegrityError(
                f"WP-4.5 kategori x küme matrisi uyuşmuyor: {matrix} != {CATEGORY_SPLIT_TARGETS}."
            )
    if enforce_anti_leakage:
        leak = verify_dataset_anti_leakage(ds)
        if not leak.passed:
            raise EvaluationIntegrityError(
                f"WP-4.5 anti-leakage ihlali tespit edildi: {leak.to_dict()}"
            )
    return ds


def sign_case_legal_review(
    case: EvaluationCase,
    *,
    review_status: str = REVIEW_APPROVED_FOR_BENCHMARK,
    reviewer_id: str,
    reviewer_role: str,
    reviewed_at_utc: str,
    verification_notes: str,
    legal_fatal_override: bool = False,
    legal_fatal_override_reason: str = "",
) -> EvaluationCase:
    """Seal an EvaluationCase answer key after independent legal review (invalidates on any edit)."""
    if review_status not in VALID_REVIEW_STATUSES:
        raise EvaluationIntegrityError(f"Geçersiz review_status: '{review_status}'.")
    key_sha = case.expected_answer_key_sha256()
    updated_lr = IndependentLegalReviewRecord(
        review_status=review_status,
        reviewer_id=reviewer_id,
        reviewer_role=reviewer_role,
        reviewed_at_utc=reviewed_at_utc,
        verification_notes=verification_notes,
        answer_key_sha256=key_sha,
        legal_fatal_override=legal_fatal_override,
        legal_fatal_override_reason=legal_fatal_override_reason,
    )
    return replace(case, legal_review=updated_lr)
