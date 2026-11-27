"""WP-4.5 Evaluation v1.2 dataset loader (WP-4.6 HOLDOUT governance): K-01 self-approval blocker, Y-02 applicable_dimensions, Y-03 split vaults, O-01 formal 4-gram Jaccard.

WP-4.6: HOLDOUT cases are never loaded by default. Loading a HOLDOUT vault requires a
`HoldoutAccessGrant` issued by `HoldoutAccessGate`; the raw file hash is checked and the read is
recorded in the persistent ledger BEFORE any HOLDOUT byte is parsed.
"""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import re
import string
from typing import Any
import unicodedata

from .models import (
    CATEGORY_SPLIT_TARGETS,
    CATEGORY_TARGET_COUNTS,
    DIMENSION_WEIGHTS,
    EVAL_VERSION,
    MANDATORY_DIMENSIONS,
    MAX_CROSS_SPLIT_JACCARD,
    REVIEW_APPROVED_FOR_BENCHMARK,
    REVIEW_PENDING_LEGAL_REVIEW,
    SPLIT_DEV,
    SPLIT_HOLDOUT,
    SPLIT_TARGET_COUNTS,
    SPLIT_VALIDATION,
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
    derive_applicable_dimensions,
)
from .holdout_governance import (
    DENY_CASE_SET_MISMATCH,
    DENY_NO_GRANT,
    HoldoutAccessDenied,
    HoldoutAccessGate,
    HoldoutAccessGrant,
    HoldoutAccessLedger,
    assert_no_unauthorised_holdout_bytes,
    compute_holdout_case_set_sha256,
)

DATASETS_DIR = Path(__file__).resolve().parent / "datasets"
DEFAULT_DEV_VAL_PATH = DATASETS_DIR / "eval_dev_val_70_cases.json"
DEFAULT_HOLDOUT_PATH = DATASETS_DIR / "eval_holdout_30_sealed.json"

_TR_CHAR_MAP = str.maketrans(
    {
        "Ç": "c",
        "Ğ": "g",
        "İ": "i",
        "I": "i",
        "Ö": "o",
        "Ş": "s",
        "Ü": "u",
        "ç": "c",
        "ğ": "g",
        "ı": "i",
        "ö": "o",
        "ş": "s",
        "ü": "u",
    }
)
_PUNCT_AND_EXTRA = string.punctuation + "“”‘’–—…«»′″"
_PUNCT_MAP = str.maketrans({ch: " " for ch in _PUNCT_AND_EXTRA})


def normalize_for_shingles(text: str) -> str:
    """O-01 Formal deterministic normalization: NFKC -> Turkish fold -> lower -> punctuation to space."""
    nfkc = unicodedata.normalize("NFKC", str(text or ""))
    folded = nfkc.translate(_TR_CHAR_MAP).lower()
    no_punct = folded.translate(_PUNCT_MAP)
    cleaned = re.sub(r"[^a-z0-9\s]", " ", no_punct)
    return re.sub(r"\s+", " ", cleaned).strip()


def _query_shingles(query_text: str) -> set[str]:
    """O-01 Formal token + 4-gram character shingle set (empty set for empty input; word-only when len < 4)."""
    norm = normalize_for_shingles(query_text)
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
    """O-01 Formal Jaccard similarity returning 0.0 safely when union is empty."""
    sa = _query_shingles(text_a)
    sb = _query_shingles(text_b)
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
    norm_cache = {c.case_id: normalize_for_shingles(c.query_text) for c in dataset.cases}
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
                if ca.ground_truth.required_provision_ids or cb.ground_truth.required_provision_ids:
                    fingerprint_dups.append(f"{ca.case_id}({ca.split})~{cb.case_id}({cb.split})")
            sb = shingles_cache[cb.case_id]
            union = sa | sb
            if union:
                jac = len(sa & sb) / len(union)
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


def _parse_case(
    raw: dict[str, Any],
    *,
    verify_hash: bool = True,
    allow_inline_self_asserted_approval: bool = False,
) -> EvaluationCase:
    cid = str(raw["case_id"])
    cat = str(raw["category"])
    split = str(raw["split"])
    cluster_id = str(raw["cluster_id"])
    diff = str(raw.get("difficulty", "STANDARD"))

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

    # Y-02: Parse & strictly validate pre-declared applicable_dimensions
    raw_app_dims = raw.get("applicable_dimensions")
    if raw_app_dims is not None:
        app_dims = tuple(str(d) for d in raw_app_dims)
        unknown = [d for d in app_dims if d not in DIMENSION_WEIGHTS]
        if unknown or not app_dims:
            raise EvaluationIntegrityError(f"{cid}: geçersiz applicable_dimensions: {raw_app_dims}.")
        missing_mand = [m for m in MANDATORY_DIMENSIONS if m not in app_dims]
        if missing_mand:
            raise EvaluationIntegrityError(f"{cid}: zorunlu boyutlar eksik: {missing_mand}.")
        app_dims = tuple(d for d in DIMENSION_WEIGHTS if d in app_dims)
    else:
        app_dims = derive_applicable_dimensions(
            as_of_date=raw.get("as_of_date"),
            difficulty=diff,
            ground_truth=gt,
            expected_outcome=exp,
        )

    lr_raw = raw.get("legal_review") or {}
    r_status = str(lr_raw.get("review_status") or REVIEW_PENDING_LEGAL_REVIEW)
    if r_status not in VALID_REVIEW_STATUSES:
        raise EvaluationIntegrityError(f"{cid}: geçersiz inceleme statüsü '{r_status}'.")
    # K-01: Developers CANNOT self-assert APPROVED_FOR_BENCHMARK inline inside dataset files!
    if r_status == REVIEW_APPROVED_FOR_BENCHMARK and not allow_inline_self_asserted_approval:
        raise EvaluationIntegrityError(
            f"{cid} (FORBIDDEN_SELF_ASSERTED_APPROVAL_IN_DATASET): Veri seti dosyası içinde doğrudan "
            f"APPROVED_FOR_BENCHMARK beyanı yasaktır; kriptografik detached hukuk imza zarfı zorunludur."
        )

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
        applicable_dimensions=app_dims,
        ground_truth=gt,
        expected_outcome=exp,
        legal_review=lr,
    )

    expected_sha = case.expected_answer_key_sha256()
    if verify_hash and case.legal_review.answer_key_sha256 != expected_sha:
        raise EvaluationIntegrityError(
            f"{cid} (ANSWER_KEY_HASH_MISMATCH): answer_key_sha256 geçersiz "
            f"(beklenen={expected_sha}, kayıtlı={case.legal_review.answer_key_sha256})."
        )
    return case


def load_dev_val_dataset(
    dev_val_path: str | Path | None = None,
    *,
    verify_hashes: bool = True,
) -> EvaluationDataset:
    """Y-03: Load ONLY the 70 DEV + VALIDATION cases for development work (HOLDOUT stays isolated)."""
    path = Path(dev_val_path) if dev_val_path is not None else DEFAULT_DEV_VAL_PATH
    payload = json.loads(path.read_text(encoding="utf-8"))
    raw_cases = payload.get("cases") or []
    cases: list[EvaluationCase] = []
    seen_ids: set[str] = set()
    for rc in raw_cases:
        c = _parse_case(rc, verify_hash=verify_hashes)
        if c.split == SPLIT_HOLDOUT:
            raise EvaluationIntegrityError(f"DEV/VAL kasasında yasaklı HOLDOUT vakası tespit edildi: {c.case_id}.")
        if c.case_id in seen_ids:
            raise EvaluationIntegrityError(f"Yinelenen vaka kimliği: '{c.case_id}'.")
        seen_ids.add(c.case_id)
        cases.append(c)
    if len(cases) != 70:
        raise EvaluationIntegrityError(f"DEV/VAL veri seti tam 70 vaka içermelidir, bulunan={len(cases)}.")
    dv_sha = canonical_eval_sha256([c.to_dict() for c in cases])
    return EvaluationDataset(
        dataset_version=str(payload.get("dataset_version") or EVAL_VERSION),
        created_at_utc=str(payload.get("created_at_utc") or ""),
        cases=tuple(cases),
        dataset_sha256=dv_sha,
        dev_val_sha256=dv_sha,
        holdout_sha256=None,
        vault_separated=True,
    )


def load_evaluation_dataset(
    dataset_path: str | Path | None = None,
    *,
    holdout_path: str | Path | None = None,
    include_holdout: bool = False,
    holdout_access_grant: HoldoutAccessGrant | None = None,
    holdout_gate: HoldoutAccessGate | None = None,
    enforce_target_counts: bool = True,
    enforce_anti_leakage: bool = True,
    verify_hashes: bool = True,
    allow_inline_self_asserted_approval: bool = False,
) -> EvaluationDataset:
    """Load & validate DEV/VAL (default) or, with a WP-4.6 grant, DEV/VAL + one sealed HOLDOUT vault.

    WP-4.6 fail-closed rules:
    - `include_holdout` defaults to False; HOLDOUT is never part of the normal development/CI flow.
    - `include_holdout=True` without a `HoldoutAccessGrant` raises `HOLDOUT_ACCESS_DENIED_NO_GRANT`
      before the HOLDOUT file is opened.
    - With a grant, the raw file SHA-256 is checked and a single VAULT_READ is recorded in the
      persistent ledger before parsing; the parsed case set must match the registered case-set hash.
    - An explicit `dataset_path` whose bytes match a registered vault, or which contains HOLDOUT
      cases, is refused without a grant.
    """
    if dataset_path is not None:
        path = Path(dataset_path)
        if holdout_access_grant is None:
            assert_no_unauthorised_holdout_bytes(path)
        else:
            gate = holdout_gate or HoldoutAccessGate(ledger_path=holdout_access_grant.ledger_path)
            gate.record_vault_read(holdout_access_grant, holdout_path=path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        raw_cases = payload.get("cases") or []
        cases: list[EvaluationCase] = []
        seen_ids: set[str] = set()
        for rc in raw_cases:
            c = _parse_case(
                rc,
                verify_hash=verify_hashes,
                allow_inline_self_asserted_approval=allow_inline_self_asserted_approval,
            )
            if c.case_id in seen_ids:
                raise EvaluationIntegrityError(f"Yinelenen vaka kimliği: '{c.case_id}'.")
            seen_ids.add(c.case_id)
            cases.append(c)
        ds_ver = str(payload.get("dataset_version") or EVAL_VERSION)
        created = str(payload.get("created_at_utc") or "")
        dev_val_cases = [c for c in cases if c.split != SPLIT_HOLDOUT]
        holdout_cases = [c for c in cases if c.split == SPLIT_HOLDOUT]
        if holdout_cases and holdout_access_grant is None:
            raise HoldoutAccessDenied(
                DENY_NO_GRANT, "Açık veri seti dosyası HOLDOUT vakası içeriyor; WP-4.6 grant olmadan yüklenemez."
            )
        dv_sha = canonical_eval_sha256([c.to_dict() for c in dev_val_cases])
        ho_sha = compute_holdout_case_set_sha256(holdout_cases) if holdout_cases else None
        if holdout_access_grant is not None and ho_sha != holdout_access_grant.case_set_sha256:
            raise HoldoutAccessDenied(DENY_CASE_SET_MISMATCH, "Yüklenen HOLDOUT vaka kümesi grant ile uyuşmuyor.")
        vault_sep = False
    else:
        dv_ds = load_dev_val_dataset(DEFAULT_DEV_VAL_PATH, verify_hashes=verify_hashes)
        all_cases = list(dv_ds.cases)
        ho_sha: str | None = None
        if include_holdout:
            if holdout_access_grant is None:
                raise HoldoutAccessDenied(
                    DENY_NO_GRANT,
                    "HOLDOUT kasası yalnız HoldoutAccessGate tarafından verilmiş grant ile okunabilir (WP-4.6).",
                )
            h_path = Path(holdout_path) if holdout_path is not None else DEFAULT_HOLDOUT_PATH
            gate = holdout_gate or HoldoutAccessGate(ledger_path=holdout_access_grant.ledger_path)
            gate.record_vault_read(holdout_access_grant, holdout_path=h_path)
            h_payload = json.loads(h_path.read_text(encoding="utf-8"))
            h_raw = h_payload.get("cases") or []
            seen_ids = {c.case_id for c in all_cases}
            h_cases: list[EvaluationCase] = []
            for rc in h_raw:
                c = _parse_case(
                    rc,
                    verify_hash=verify_hashes,
                    allow_inline_self_asserted_approval=allow_inline_self_asserted_approval,
                )
                if c.split != SPLIT_HOLDOUT:
                    raise EvaluationIntegrityError(f"Mühürlü HOLDOUT kasasında {c.split} vakası yasak: {c.case_id}.")
                if c.case_id in seen_ids:
                    raise EvaluationIntegrityError(f"Yinelenen vaka kimliği: '{c.case_id}'.")
                seen_ids.add(c.case_id)
                h_cases.append(c)
            file_order_sha = canonical_eval_sha256([c.to_dict() for c in h_cases])
            declared_vault_sha = str(h_payload.get("holdout_vault_sha256") or "")
            if verify_hashes and declared_vault_sha and declared_vault_sha != file_order_sha:
                raise EvaluationIntegrityError(
                    f"HOLDOUT kasa bütünlük özeti uyuşmuyor: beklenen={file_order_sha}, kayıtlı={declared_vault_sha}."
                )
            ho_sha = compute_holdout_case_set_sha256(h_cases)
            if ho_sha != holdout_access_grant.case_set_sha256:
                raise HoldoutAccessDenied(DENY_CASE_SET_MISMATCH, "Yüklenen HOLDOUT vaka kümesi grant ile uyuşmuyor.")
            all_cases.extend(h_cases)
            all_cases.sort(key=lambda item: item.case_id)
        cases = all_cases
        ds_ver = dv_ds.dataset_version
        created = dv_ds.created_at_utc
        dv_sha = dv_ds.dev_val_sha256
        vault_sep = True

    ds = EvaluationDataset(
        dataset_version=ds_ver,
        created_at_utc=created,
        cases=tuple(cases),
        dataset_sha256=canonical_eval_sha256([c.to_dict() for c in cases]),
        dev_val_sha256=dv_sha,
        holdout_sha256=ho_sha,
        vault_separated=vault_sep,
    )

    if enforce_target_counts and ho_sha is None:
        # WP-4.6: normal flow validates only the 70-case DEV/VAL matrix (HOLDOUT stays sealed).
        dv_expected = {
            cat: {sp: (n if sp != SPLIT_HOLDOUT else 0) for sp, n in per.items()}
            for cat, per in CATEGORY_SPLIT_TARGETS.items()
        }
        if ds.category_split_counts() != dv_expected:
            raise EvaluationIntegrityError(
                f"WP-4.6 DEV/VAL kategori x küme matrisi uyuşmuyor: {ds.category_split_counts()} != {dv_expected}."
            )
    elif enforce_target_counts:
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
            raise EvaluationIntegrityError(f"WP-4.5 anti-leakage ihlali tespit edildi: {leak.to_dict()}")

    return ds
