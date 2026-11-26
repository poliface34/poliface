"""WP-4.5 v1.2 Severity-Weighted Evaluation Rubric (K-02, K-03, Y-01, Y-02, Y-05, O-03, O-05)."""

from __future__ import annotations

from dataclasses import dataclass
import re

from ..answer.models import (
    CLAIM_JUDICIAL_PRECEDENT,
    CLAIM_LEGAL_INTERPRETATION,
    CLAIM_STATUTORY_EVIDENCE,
    STATUS_BLOCKED_CITATION_VALIDATION_FAILED,
    VerifiedAnswerPackage,
)
from ..knowledge_base.chunker import tr_fold
from ..models import LegalSourceRecord, PrecedentRecord
from ..rag.models import RetrievalTraceBundle
from .legal_signoff import SIGNOFF_PENDING, VerifiedCaseSignoffState
from .models import (
    CASE_MINOR_BUDGET_CAP,
    DEFECT_FIXED_PENALTIES,
    DIM_ABSTENTION_ACCURACY,
    DIM_CITATION_INTEGRITY,
    DIM_INTERPRETATION_HIERARCHY,
    DIM_LEGAL_CORRECTNESS,
    DIM_RETRIEVAL_EFFECTIVENESS,
    DIM_RISK_DETECTION,
    DIM_SOURCE_ACCURACY,
    DIM_TEMPORAL_ACCURACY,
    DIMENSION_WEIGHTS,
    MISSING_DIM_POLICY_RENORMALIZED,
    ROOT_CAUSE_ABSTENTION_OVER_TRIGGER,
    ROOT_CAUSE_ABSTENTION_UNDER_TRIGGER,
    ROOT_CAUSE_CITATION_FAILURE,
    ROOT_CAUSE_INJECTION_DEFENSE,
    ROOT_CAUSE_KB_CORPUS_GAP,
    ROOT_CAUSE_NONE,
    ROOT_CAUSE_RAG_RETRIEVAL_MISS,
    ROOT_CAUSE_REASONING_EXCEPTION_MISS,
    ROOT_CAUSE_RISK_THRESHOLD_MISMATCH,
    ROOT_CAUSE_TEMPORAL_BOUNDARY_MISS,
    SEVERITY_FATAL,
    SEVERITY_MAJOR,
    SEVERITY_MINOR,
    SEVERITY_MODERATE,
    TRIGGER_AUTO_DETERMINISTIC,
    TRIGGER_LEGAL_REVIEWER,
    VALID_MISSING_DIM_POLICIES,
    VERDICT_FAIL_FATAL,
    VERDICT_FAIL_MAJOR,
    VERDICT_FAIL_SCORE,
    VERDICT_PARTIAL_REVIEW,
    VERDICT_PASS,
    DimensionScore,
    EvaluationCase,
    EvaluationIntegrityError,
    FailureDefectRecord,
    SingleCaseEvalReport,
    classify_score_band,
)

_RISK_RANK: dict[str, int] = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_RANK_NAME: dict[int, str] = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}

MONETARY_CLASS_USER_INPUT = "USER_PROVIDED_INPUT_AMOUNT"
MONETARY_CLASS_STATUTORY_THRESHOLD = "STATUTORY_LEGAL_THRESHOLD"
MONETARY_CLASS_DELEGATION_NOTICE = "DELEGATION_NOTICE_ONLY"
MONETARY_CLASS_CALCULATED_PAYMENT = "CALCULATED_PAYMENT_AMOUNT"

_CURRENCY_SPAN_RE = re.compile(r"\b(\d[\d.,]*)\s*(?:tl|₺|lira|kuruş|kurus)\b", re.IGNORECASE)
_FORMULA_OUT_RE = re.compile(
    r"(?:"
    r"\b\d[\d.,]*\s*[×x*]\s*\d[\d.,]*\s*=\s*(\d[\d.,]*)\b"
    r"|(?:hesaplanan(?:\s+net|\s+brüt)?|net\s+(?:ödenecek|tutar|tazminat|kıdem|ihbar|alacak)|ele\s+geçecek|toplam\s+(?:ödenecek|alacağınız|tazminat))\s*[:=]?\s*(\d{2,}(?:[.,]\d+)*)\b"
    r")(?!-\d{2}-\d{2})",
    re.IGNORECASE,
)
_COMPUTATION_VERBS = (
    "hesaplanan",
    "ödenecek",
    "odenecek",
    "ödenecektir",
    "odenecektir",
    "ele geçecek",
    "ele gececek",
    "net tutar",
    "net kıdem",
    "net kidem",
    "net ihbar",
    "olarak ödenmelidir",
    "olarak odenmelidir",
    "kesinti sonrası",
    "kesinti sonrasi",
)
_USER_INPUT_CUES = (
    "belirtilen",
    "verilen",
    "sorudaki",
    "brüt maaşlı",
    "brut maasli",
    "brüt ücretli",
    "brut ucretli",
    "talep edilen",
    "girilen",
)
_STATUTORY_THRESHOLD_NUMS = frozenset(
    {"300", "240", "190", "158", "170", "50", "40", "9", "7.5", "7,5", "33030", "297270", "247725", "26005.5", "22504.17"}
)
_STATUTORY_CUES = (
    "tebliğ",
    "teblig",
    "kanun",
    "istisna",
    "sınır",
    "sinir",
    "tavan",
    "katsayı",
    "katsayi",
    "spek",
    "prime esas",
    "asgari",
    "alt sınır",
    "ust sinir",
    "üst sınır",
    "yemek",
    "madde",
    "m.",
    "devredilir",
    "genelge",
)
_DELEGATION_CUES = ("@ucretbordro", "bordro ajanı", "bordro ajani", "hesaplama yapmaz", "hesaplanmaz", "yetkisi @ucretbordro")


@dataclass(frozen=True)
class MonetaryMentionClassification:
    section_name: str
    matched_text: str
    numeric_canonical: str
    classification: str
    sentence_context: str


def _canon_num(raw: str) -> str:
    """Normalize Turkish formatted integer/decimal like '85.000,50' -> '85000.50' or '85000'."""
    s = str(raw or "").strip()
    if "," in s and "." in s:
        s = s.replace(".", "").replace(",", ".")
    elif "." in s:
        parts = s.split(".")
        if all(len(p) == 3 for p in parts[1:]):
            s = "".join(parts)
    elif "," in s:
        s = s.replace(",", ".")
    if s.endswith(".00"):
        s = s[:-3]
    return s


def _extract_user_input_numbers(case: EvaluationCase) -> set[str]:
    nums: set[str] = set()
    for m in re.finditer(r"\b\d[\d.,]*\b", f"{case.query_text} {case.facts}"):
        nums.add(_canon_num(m.group(0)))
    return nums


def _extract_kb_statutory_numbers(trace_bundle: RetrievalTraceBundle | None) -> set[str]:
    nums = set(_STATUTORY_THRESHOLD_NUMS)
    if trace_bundle is None:
        return nums
    for it in (
        *trace_bundle.normative_bucket,
        *trace_bundle.interpretation_bucket,
        *trace_bundle.autonomous_norm_bucket,
    ):
        txt = str(getattr(it.chunk, "text", "") or "")
        for m in re.finditer(r"\b\d[\d.,]*\b", txt):
            nums.add(_canon_num(m.group(0)))
    return nums


def classify_monetary_mentions(
    *,
    sections_dict: dict[str, str],
    case: EvaluationCase,
    trace_bundle: RetrievalTraceBundle | None = None,
) -> tuple[MonetaryMentionClassification, ...]:
    """Y-05: 4-class contextual classifier distinguishing calculated payroll outputs vs user inputs/legal thresholds."""
    user_nums = _extract_user_input_numbers(case)
    stat_nums = _extract_kb_statutory_numbers(trace_bundle)
    results: list[MonetaryMentionClassification] = []
    target_sections = ("hukuki_sonuc", "uygulama", "hukuki_degerlendirme")

    for sec in target_sections:
        raw_text = str(sections_dict.get(sec) or "")
        if not raw_text.strip():
            continue
        sentences = [s.strip() for s in re.split(r"(?<=[^0-9])[.!?]\s+|\n+", raw_text) if s.strip()]
        for sent in sentences:
            sent_fold = tr_fold(sent)
            matches: list[tuple[str, str]] = []
            for m in _CURRENCY_SPAN_RE.finditer(sent):
                matches.append((m.group(0), _canon_num(m.group(1))))
            for m in _FORMULA_OUT_RE.finditer(sent):
                num_raw = m.group(1) or m.group(2) or ""
                can = _canon_num(num_raw)
                if num_raw and all(existing not in m.group(0) and m.group(0) not in existing for existing, _ in matches):
                    matches.append((m.group(0), can))
            if not matches:
                continue

            has_calc_verb = any(cv in sent_fold for cv in _COMPUTATION_VERBS) or bool(re.search(r"(?<![<>!])=\s*\d", sent_fold))
            has_delegation = any(dc in sent_fold for dc in _DELEGATION_CUES)
            has_stat_cue = any(sc in sent_fold for sc in _STATUTORY_CUES)
            has_input_cue = any(uc in sent_fold for uc in _USER_INPUT_CUES)

            for matched_span, num_canon in matches:
                if has_calc_verb:
                    cls = MONETARY_CLASS_CALCULATED_PAYMENT
                elif has_delegation and num_canon in user_nums:
                    cls = MONETARY_CLASS_USER_INPUT
                elif num_canon in user_nums and (has_input_cue or not has_calc_verb):
                    cls = MONETARY_CLASS_USER_INPUT
                elif num_canon in stat_nums and has_stat_cue:
                    cls = MONETARY_CLASS_STATUTORY_THRESHOLD
                elif has_delegation and not any(v in sent_fold for v in ("hesaplanan", "net tutar", "ödenecek")):
                    cls = MONETARY_CLASS_DELEGATION_NOTICE
                else:
                    cls = MONETARY_CLASS_CALCULATED_PAYMENT

                results.append(
                    MonetaryMentionClassification(
                        section_name=sec,
                        matched_text=matched_span,
                        numeric_canonical=num_canon,
                        classification=cls,
                        sentence_context=sent[:180],
                    )
                )
    return tuple(results)


def _norm_tokens(phrase: str) -> list[str]:
    folded = tr_fold(phrase)
    return [tok for tok in re.split(r"[^a-z0-9]+", folded) if len(tok) >= 3]


def _concept_matched(concept: str, blob_folded: str) -> bool:
    c_fold = tr_fold(concept).strip()
    if not c_fold:
        return True
    if c_fold in blob_folded:
        return True
    tokens = _norm_tokens(concept)
    if not tokens:
        return True
    hits = sum(1 for tok in tokens if tok in blob_folded)
    needed = 1 if len(tokens) == 1 else max(1, (len(tokens) + 1) // 2)
    return hits >= needed


class EvaluationRubricScorer:
    """Deterministic v1.2 8-dimension & 4-tier severity evaluator conforming to WP4_5_EVALUATION_SPEC v1.2."""

    def __init__(
        self,
        *,
        source_registry: dict[str, LegalSourceRecord] | None = None,
        precedent_registry: dict[str, PrecedentRecord] | None = None,
        known_kb_provisions: set[str] | None = None,
        known_kb_sources: set[str] | None = None,
        missing_dimension_policy: str = MISSING_DIM_POLICY_RENORMALIZED,
    ) -> None:
        if missing_dimension_policy not in VALID_MISSING_DIM_POLICIES:
            raise EvaluationIntegrityError(
                f"Y-02 ihlali: Desteklenmeyen missing_dimension_policy='{missing_dimension_policy}'. "
                f"Yalnızca {sorted(VALID_MISSING_DIM_POLICIES)} kabul edilir."
            )
        self._sources = source_registry or {}
        self._precedents = precedent_registry or {}
        self._kb_provisions = known_kb_provisions or set()
        self._kb_sources = known_kb_sources or set()
        self._missing_dim_policy = missing_dimension_policy

    @staticmethod
    def _fixed_penalty(code: str) -> float:
        if code not in DEFECT_FIXED_PENALTIES:
            raise EvaluationIntegrityError(f"Tanımsız DefectCode cezası: '{code}'.")
        return DEFECT_FIXED_PENALTIES[code]

    @staticmethod
    def _compute_fixed_cutoff_retrieval(
        trace_bundle: RetrievalTraceBundle,
        *,
        required_provision_ids: tuple[str, ...],
        required_source_ids: tuple[str, ...],
    ) -> tuple[float, float, float, float, float, set[str], set[str], set[str]]:
        """O-05 Fixed Retrieval Cutoffs: Provision Recall@5, Recall@10, Source Hit@5/@10, and MRR."""
        raw_items = [
            *trace_bundle.normative_bucket,
            *trace_bundle.interpretation_bucket,
            *trace_bundle.autonomous_norm_bucket,
            *trace_bundle.precedent_bucket,
        ]
        # Deterministic descending score sort preserving relative order cleanly
        ranked = sorted(
            enumerate(raw_items),
            key=lambda pair: (-float(getattr(pair[1], "score", 0.0)), pair[0]),
        )
        ranked_items = [item for _, item in ranked]

        all_sources = {it.chunk.source_id for it in ranked_items if it.chunk.source_id}
        all_provs = {it.chunk.provision_id for it in ranked_items if it.chunk.provision_id}
        all_precs = {
            str((it.precedent_metadata or {}).get("precedent_id") or it.chunk.source_id)
            for it in trace_bundle.precedent_bucket
        }

        def _item_keys(it: object) -> set[str]:
            keys: set[str] = set()
            ch = getattr(it, "chunk", None)
            if ch is not None and getattr(ch, "provision_id", None):
                keys.add(ch.provision_id)
            if ch is not None and getattr(ch, "source_id", None):
                keys.add(ch.source_id)
            pm = getattr(it, "precedent_metadata", None) or {}
            if pm.get("precedent_id"):
                keys.add(str(pm["precedent_id"]))
            return keys

        # Build deduplicated top-k provision/source streams
        top5_items = ranked_items[:5]
        top10_items = ranked_items[:10]

        provs_top5 = {k for it in top5_items for k in _item_keys(it)}
        provs_top10 = {k for it in top10_items for k in _item_keys(it)}
        srcs_top5 = {it.chunk.source_id for it in top5_items if it.chunk.source_id}
        srcs_top10 = {it.chunk.source_id for it in top10_items if it.chunk.source_id}

        prov_r5 = (
            sum(1 for pid in required_provision_ids if pid in provs_top5) / len(required_provision_ids)
            if required_provision_ids
            else 1.0
        )
        prov_r10 = (
            sum(1 for pid in required_provision_ids if pid in provs_top10) / len(required_provision_ids)
            if required_provision_ids
            else 1.0
        )
        src_h5 = (
            sum(1 for sid in required_source_ids if sid in srcs_top5) / len(required_source_ids)
            if required_source_ids
            else 1.0
        )
        src_h10 = (
            sum(1 for sid in required_source_ids if sid in srcs_top10) / len(required_source_ids)
            if required_source_ids
            else 1.0
        )

        # Mean Reciprocal Rank for first matching required provision (or required source)
        targets = set(required_provision_ids) or set(required_source_ids)
        mrr = 1.0 if not targets else 0.0
        if targets:
            for idx, it in enumerate(ranked_items, start=1):
                if _item_keys(it).intersection(targets):
                    mrr = 1.0 / idx
                    break

        return prov_r5, prov_r10, src_h5, src_h10, mrr, all_sources, all_provs, all_precs

    def score_case(
        self,
        *,
        case: EvaluationCase,
        trace_bundle: RetrievalTraceBundle,
        answer: VerifiedAnswerPackage,
        signoff_state: VerifiedCaseSignoffState | None = None,
        legal_fatal_override: bool | None = None,
        legal_fatal_override_reason: str | None = None,
    ) -> SingleCaseEvalReport:
        gt = case.ground_truth
        exp = case.expected_outcome
        defects: list[FailureDefectRecord] = []

        max_rank = max((_RISK_RANK.get(r.risk_level, 1) for r in answer.risks), default=1)
        observed_risk = _RANK_NAME[max_rank]

        active_sources = {b.source_id for b in answer.legal_bases if b.effective_on_date} | {
            c.source_id for c in answer.claims if c.effective_on_date and c.source_id
        }
        active_provs = {c.provision_id for c in answer.claims if c.effective_on_date and c.provision_id}
        for b in answer.legal_bases:
            if b.effective_on_date:
                m = re.search(r"\(([^()]+)\)", b.legal_reference)
                if m:
                    active_provs.add(m.group(1).strip())
        active_precs = {c.precedent_id for c in answer.claims if c.effective_on_date and c.precedent_id}
        hist_sources = {h.source_id for h in answer.historical_context if not h.effective_on_date}

        (
            prov_r5,
            prov_r10,
            src_h5,
            src_h10,
            mrr,
            retrieved_sources,
            retrieved_provs,
            retrieved_precs,
        ) = self._compute_fixed_cutoff_retrieval(
            trace_bundle,
            required_provision_ids=gt.required_provision_ids,
            required_source_ids=gt.required_source_ids,
        )

        sections_dict = answer.eight_sections.to_dict() if answer.eight_sections is not None else {}
        eval_text_folded = tr_fold(
            "\n".join(
                [
                    sections_dict.get("hukuki_sonuc", ""),
                    sections_dict.get("mevzuat_dayanagi", ""),
                    sections_dict.get("hukuki_degerlendirme", ""),
                    sections_dict.get("uygulama", ""),
                    sections_dict.get("risk", ""),
                    sections_dict.get("istisnalar", ""),
                ]
            )
        )
        full_text_folded = tr_fold("\n".join(str(v) for v in sections_dict.values()))

        # Y-02: Start strictly from declared applicable_dimensions
        declared_app = set(case.resolved_applicable_dimensions())
        dim_applicable: dict[str, bool] = {k: (k in declared_app) for k in DIMENSION_WEIGHTS}
        dim_scores: dict[str, float] = {k: 100.0 for k in DIMENSION_WEIGHTS}
        dim_notes: dict[str, list[str]] = {k: [] for k in DIMENSION_WEIGHTS}
        minor_penalty_accum = 0.0

        def _add_defect(
            code: str,
            severity: str,
            dim_id: str,
            message: str,
            root_cause: str,
            *,
            trigger_source: str = TRIGGER_AUTO_DETERMINISTIC,
            force_zero_dimension: bool = False,
        ) -> None:
            nonlocal minor_penalty_accum
            raw_pen = self._fixed_penalty(code)
            actual_pen = raw_pen
            if severity == SEVERITY_MINOR:
                # O-03: Case-wide total MINOR penalty budget <= 5.0 across all dimensions
                remaining_minor = max(0.0, CASE_MINOR_BUDGET_CAP - minor_penalty_accum)
                actual_pen = min(raw_pen, remaining_minor) if remaining_minor > 0.0 else 0.0
                minor_penalty_accum += actual_pen
            defects.append(
                FailureDefectRecord(
                    code=code,
                    severity=severity,
                    trigger_source=trigger_source,
                    dimension_id=dim_id,
                    penalty_applied=actual_pen,
                    message=message,
                    root_cause_tag=root_cause,
                )
            )
            # Re-activate dimension automatically if an unexpected leak/defect occurs in it
            dim_applicable[dim_id] = True
            if force_zero_dimension or severity == SEVERITY_FATAL:
                dim_scores[dim_id] = 0.0
            else:
                dim_scores[dim_id] = max(0.0, min(100.0, dim_scores[dim_id] - actual_pen))
            dim_notes[dim_id].append(f"[{severity} | {trigger_source}] {code} (-{actual_pen:.1f}): {message}")

        # ------------------------------------------------------------------
        # F-5: Closed governance gates & K-03 Model Output Signal Contract
        # ------------------------------------------------------------------
        gates = answer.governance_gates or {}
        if (
            gates.get("production_use_authorized") is not False
            or gates.get("qualified_e_signature_5070_equivalent") is not False
            or gates.get("kvkk_data_residency_approved") is not False
            or (
                "qualified_e_signature_5070_production_ready" in gates
                and gates.get("qualified_e_signature_5070_production_ready") is not False
            )
        ):
            _add_defect(
                "FATAL_GOVERNANCE_GATE_BREACH",
                SEVERITY_FATAL,
                DIM_LEGAL_CORRECTNESS,
                "Üretim, 5070 sayılı Kanun veya KVKK m.9 kapılarından biri kapalı olmaktan çıktı.",
                ROOT_CAUSE_CITATION_FAILURE,
            )

        # K-03 Model Output Signal Defects (product produced incomplete/missing contract fields -> S_d = 0.0)
        missing_sections = not all(str(sections_dict.get(k) or "").strip() for k in ("hukuki_sonuc", "guven_durumu"))
        if missing_sections or answer.citation_audit is None or answer.audit_trace is None:
            _add_defect(
                "MAJOR_MODEL_OUTPUT_SIGNAL_MISSING",
                SEVERITY_MAJOR,
                DIM_LEGAL_CORRECTNESS,
                "MODEL_OUTPUT_SIGNAL_DEFECT: @HukukSGK zorunlu çıkış sözleşme alanlarından biri boş veya eksik.",
                ROOT_CAUSE_CITATION_FAILURE,
                force_zero_dimension=True,
            )

        if not trace_bundle.trace_id or not answer.answer_sha256 or not answer.audit_trace or not answer.audit_trace.audit_trace_sha256:
            _add_defect(
                "FATAL_BROKEN_AUDIT_LINEAGE",
                SEVERITY_FATAL,
                DIM_CITATION_INTEGRITY,
                "MODEL_OUTPUT_SIGNAL_DEFECT: Zorunlu izlenebilirlik veya answer_sha256 sinyali eksik.",
                ROOT_CAUSE_CITATION_FAILURE,
            )
        elif (
            answer.audit_trace.source_trace_id != trace_bundle.trace_id
            or answer.audit_trace.source_bundle_sha256 != trace_bundle.bundle_sha256
            or answer.audit_trace.answer_sha256 != answer.answer_sha256
        ):
            _add_defect(
                "FATAL_BROKEN_AUDIT_LINEAGE",
                SEVERITY_FATAL,
                DIM_CITATION_INTEGRITY,
                "AnswerAuditTrace ile RetrievalTraceBundle kriptografik iz bağı kopuk.",
                ROOT_CAUSE_CITATION_FAILURE,
            )

        # ------------------------------------------------------------------
        # F-4 (Y-05): Contextual 4-class MonetaryMentionClassifier
        # ------------------------------------------------------------------
        if not answer.published_answer_blocked:
            mentions = classify_monetary_mentions(sections_dict=sections_dict, case=case, trace_bundle=trace_bundle)
            leaked_calcs = [m for m in mentions if m.classification == MONETARY_CLASS_CALCULATED_PAYMENT]
            if leaked_calcs:
                _add_defect(
                    "FATAL_UNAUTHORIZED_PAYROLL_CALC",
                    SEVERITY_FATAL,
                    DIM_LEGAL_CORRECTNESS,
                    f"@HukukSGK yetkisiz hesaplanan ödeme tutarı üretti: '{leaked_calcs[0].matched_text}'.",
                    ROOT_CAUSE_CITATION_FAILURE,
                )

        # ------------------------------------------------------------------
        # F-1 / F-2 / F-3: Active claim, whitelist, temporal, pending_review & precedent checks
        # ------------------------------------------------------------------
        if not exp.expected_published_blocked and not answer.published_answer_blocked:
            bad_forb_src = sorted(active_sources.intersection(gt.forbidden_source_ids))
            for sid in bad_forb_src:
                src_rec = self._sources.get(sid)
                if src_rec and src_rec.verification_status in {"PENDING_REVIEW", "UNVERIFIED"}:
                    _add_defect(
                        "FATAL_PENDING_REVIEW_AS_DEFINITIVE",
                        SEVERITY_FATAL,
                        DIM_SOURCE_ACCURACY,
                        f"Doğrulama bekleyen kaynak ({sid}) aktif hukuki dayanak olarak sunuldu.",
                        ROOT_CAUSE_CITATION_FAILURE,
                    )
                elif sid == "RG-9368-20241228" or (src_rec and src_rec.verification_status == "SUPERSEDED"):
                    _add_defect(
                        "FATAL_REPEALED_STATUTE_AS_CURRENT",
                        SEVERITY_FATAL,
                        DIM_TEMPORAL_ACCURACY,
                        f"Yürürlükten kalkmış düzenleme ({sid}) güncel dayanak olarak sunuldu.",
                        ROOT_CAUSE_TEMPORAL_BOUNDARY_MISS,
                    )
                else:
                    _add_defect(
                        "FATAL_RETROACTIVE_LAW_APPLICATION",
                        SEVERITY_FATAL,
                        DIM_TEMPORAL_ACCURACY,
                        f"Olay tarihine uygulanamayacak/yasaklı kaynak ({sid}) aktif dayanak yapıldı.",
                        ROOT_CAUSE_TEMPORAL_BOUNDARY_MISS,
                    )

            bad_forb_prov = sorted(active_provs.intersection(gt.forbidden_provision_ids))
            if bad_forb_prov:
                _add_defect(
                    "FATAL_WRONG_ARTICLE_OR_SOURCE_CITED",
                    SEVERITY_FATAL,
                    DIM_SOURCE_ACCURACY,
                    f"Yanlış veya yasaklı madde düğümleri aktif sunuldu: {bad_forb_prov}.",
                    ROOT_CAUSE_CITATION_FAILURE,
                )

            for sid in active_sources:
                src_rec = self._sources.get(sid)
                if src_rec and src_rec.verification_status in {"PENDING_REVIEW", "UNVERIFIED"}:
                    _add_defect(
                        "FATAL_PENDING_REVIEW_AS_DEFINITIVE",
                        SEVERITY_FATAL,
                        DIM_CITATION_INTEGRITY,
                        f"PENDING_REVIEW durumundaki {sid} aktif dayanak olarak sunulamaz.",
                        ROOT_CAUSE_CITATION_FAILURE,
                    )
            for pid in active_precs:
                prec_rec = self._precedents.get(pid)
                if prec_rec and prec_rec.verification_status in {"PENDING_REVIEW", "UNVERIFIED"}:
                    _add_defect(
                        "FATAL_PENDING_REVIEW_AS_DEFINITIVE",
                        SEVERITY_FATAL,
                        DIM_CITATION_INTEGRITY,
                        f"PENDING_REVIEW durumundaki içtihat {pid} aktif sunulamaz.",
                        ROOT_CAUSE_CITATION_FAILURE,
                    )

            for clm in answer.claims:
                if clm.claim_category == CLAIM_STATUTORY_EVIDENCE and clm.precedent_id:
                    _add_defect(
                        "FATAL_PRECEDENT_AS_STATUTE",
                        SEVERITY_FATAL,
                        DIM_INTERPRETATION_HIERARCHY,
                        f"İçtihat ({clm.precedent_id}) kanun basamağına çıkarıldı.",
                        ROOT_CAUSE_REASONING_EXCEPTION_MISS,
                    )
                if clm.claim_category in {CLAIM_STATUTORY_EVIDENCE, CLAIM_JUDICIAL_PRECEDENT, CLAIM_LEGAL_INTERPRETATION}:
                    if not clm.effective_on_date:
                        _add_defect(
                            "FATAL_RETROACTIVE_LAW_APPLICATION",
                            SEVERITY_FATAL,
                            DIM_TEMPORAL_ACCURACY,
                            f"Aktif iddialarda effective_on_date=False kayıt ({clm.claim_id}) bulundu.",
                            ROOT_CAUSE_TEMPORAL_BOUNDARY_MISS,
                        )
                    if clm.claim_category == CLAIM_JUDICIAL_PRECEDENT:
                        if not clm.precedent_id or not trace_bundle.citation_whitelist.contains_precedent(clm.precedent_id):
                            _add_defect(
                                "FATAL_UNWHITELISTED_CLAIM",
                                SEVERITY_FATAL,
                                DIM_CITATION_INTEGRITY,
                                f"Beyaz liste dışı içtihat iddiası: {clm.precedent_id}.",
                                ROOT_CAUSE_CITATION_FAILURE,
                            )
                    elif not clm.source_id or not trace_bundle.citation_whitelist.contains_source(clm.source_id):
                        _add_defect(
                            "FATAL_UNWHITELISTED_CLAIM",
                            SEVERITY_FATAL,
                            DIM_CITATION_INTEGRITY,
                            f"Beyaz liste dışı kaynak iddiası: {clm.source_id}.",
                            ROOT_CAUSE_CITATION_FAILURE,
                        )

        # Blockers vs Adversarial defenses
        if exp.expected_published_blocked:
            if not answer.published_answer_blocked or answer.status != STATUS_BLOCKED_CITATION_VALIDATION_FAILED:
                _add_defect(
                    "FATAL_FABRICATED_PRECEDENT_OR_URL",
                    SEVERITY_FATAL,
                    DIM_CITATION_INTEGRITY,
                    "Olumsuz enjeksiyon / sahte atıf saldırısı CitationValidator tarafından engellenmedi!",
                    ROOT_CAUSE_INJECTION_DEFENSE,
                )
        elif answer.published_answer_blocked:
            b_codes = set(answer.citation_audit.blocker_codes) if answer.citation_audit else set()
            if "WRONG_ARTICLE_OR_PROVISION_CITED" in b_codes:
                _add_defect(
                    "FATAL_WRONG_ARTICLE_OR_SOURCE_CITED",
                    SEVERITY_FATAL,
                    DIM_SOURCE_ACCURACY,
                    f"Taslak yanlış madde nedeniyle bloklandı: {tuple(sorted(b_codes))}",
                    ROOT_CAUSE_CITATION_FAILURE,
                )
            elif "TEMPORAL_RETROACTIVITY_VIOLATION_BLOCKED" in b_codes or "ARTICLE_NOT_EFFECTIVE_ON_DATE" in b_codes:
                _add_defect(
                    "FATAL_RETROACTIVE_LAW_APPLICATION",
                    SEVERITY_FATAL,
                    DIM_TEMPORAL_ACCURACY,
                    f"Taslak zamansal ihlal nedeniyle bloklandı: {tuple(sorted(b_codes))}",
                    ROOT_CAUSE_TEMPORAL_BOUNDARY_MISS,
                )
            elif "EXPIRED_OR_REPEALED_STATUTE" in b_codes:
                _add_defect(
                    "FATAL_REPEALED_STATUTE_AS_CURRENT",
                    SEVERITY_FATAL,
                    DIM_TEMPORAL_ACCURACY,
                    f"Taslak mülga kaynak nedeniyle bloklandı: {tuple(sorted(b_codes))}",
                    ROOT_CAUSE_TEMPORAL_BOUNDARY_MISS,
                )
            elif "UNAUTHORIZED_PAYROLL_CALCULATION" in b_codes:
                _add_defect(
                    "FATAL_UNAUTHORIZED_PAYROLL_CALC",
                    SEVERITY_FATAL,
                    DIM_LEGAL_CORRECTNESS,
                    "Taslak yetkisiz bordro hesabı nedeniyle bloklandı.",
                    ROOT_CAUSE_CITATION_FAILURE,
                )
            elif "GOVERNANCE_GATE_VIOLATION" in b_codes:
                _add_defect(
                    "FATAL_GOVERNANCE_GATE_BREACH",
                    SEVERITY_FATAL,
                    DIM_LEGAL_CORRECTNESS,
                    "Taslak yönetişim kapısı ihlali nedeniyle bloklandı.",
                    ROOT_CAUSE_CITATION_FAILURE,
                )
            else:
                _add_defect(
                    "FATAL_UNWHITELISTED_CLAIM",
                    SEVERITY_FATAL,
                    DIM_CITATION_INTEGRITY,
                    f"Pozitif vaka beklenmedik şekilde CitationValidator blokajına takıldı: {tuple(sorted(b_codes))}",
                    ROOT_CAUSE_CITATION_FAILURE,
                )

        if not answer.published_answer_blocked and exp.unacceptable_failure_modes:
            for bad_pat in exp.unacceptable_failure_modes:
                if tr_fold(bad_pat) in full_text_folded:
                    _add_defect(
                        "FATAL_WRONG_ARTICLE_OR_SOURCE_CITED",
                        SEVERITY_FATAL,
                        DIM_LEGAL_CORRECTNESS,
                        f"Yasaklı hukuki ifade cevaba sızdı: '{bad_pat}'.",
                        ROOT_CAUSE_REASONING_EXCEPTION_MISS,
                    )

        # Independent Legal Reviewer FATAL Override (K-01 signed or explicit override)
        if signoff_state is not None:
            use_rev_override = signoff_state.legal_fatal_override_active if legal_fatal_override is None else legal_fatal_override
            rev_reason_text = legal_fatal_override_reason or signoff_state.legal_fatal_override_reason
        else:
            use_rev_override = case.legal_review.legal_fatal_override if legal_fatal_override is None else legal_fatal_override
            rev_reason_text = legal_fatal_override_reason or case.legal_review.legal_fatal_override_reason

        if use_rev_override:
            _add_defect(
                "LEGAL_FATAL_OVERRIDE",
                SEVERITY_FATAL,
                DIM_LEGAL_CORRECTNESS,
                rev_reason_text or "Bağımsız hukuk değerlendiricisi tarafından maddi hukuk ihlali gerekçesiyle FATAL işaretlendi.",
                ROOT_CAUSE_REASONING_EXCEPTION_MISS,
                trigger_source=TRIGGER_LEGAL_REVIEWER,
            )

        # ------------------------------------------------------------------
        # Positive Dimension Checks (using strict pre-declared N/A + Y-01 fixed penalties)
        # ------------------------------------------------------------------
        is_clean_blocked_adversarial = exp.expected_published_blocked and answer.published_answer_blocked
        if not is_clean_blocked_adversarial:
            if answer.status not in exp.expected_statuses:
                is_expected_abstain = any(s.startswith("ABSTAINED_") for s in exp.expected_statuses)
                is_observed_abstain = answer.status.startswith("ABSTAINED_")
                if is_expected_abstain and not is_observed_abstain:
                    _add_defect(
                        "MAJOR_FALSE_ASSUMPTION_ON_MISSING_INFO",
                        SEVERITY_MAJOR,
                        DIM_ABSTENTION_ACCURACY,
                        f"Durması gereken ({exp.expected_statuses}) vakada varsayımla '{answer.status}' üretildi.",
                        ROOT_CAUSE_ABSTENTION_UNDER_TRIGGER,
                    )
                    _add_defect(
                        "MAJOR_WRONG_FINAL_OUTCOME",
                        SEVERITY_MAJOR,
                        DIM_LEGAL_CORRECTNESS,
                        f"Beklenen statü {exp.expected_statuses}, gerçekleşen '{answer.status}'.",
                        ROOT_CAUSE_ABSTENTION_UNDER_TRIGGER,
                    )
                elif not is_expected_abstain and is_observed_abstain:
                    missing_from_kb = [
                        p for p in gt.required_provision_ids if self._kb_provisions and p not in self._kb_provisions
                    ]
                    if missing_from_kb:
                        rc = ROOT_CAUSE_KB_CORPUS_GAP
                    elif trace_bundle.missing_facts and not exp.expected_missing_fields:
                        rc = ROOT_CAUSE_ABSTENTION_OVER_TRIGGER
                    elif prov_r5 < 0.5 or src_h5 < 0.5:
                        rc = ROOT_CAUSE_RAG_RETRIEVAL_MISS
                    else:
                        rc = ROOT_CAUSE_ABSTENTION_OVER_TRIGGER
                    _add_defect(
                        "MODERATE_FALSE_ABSTENTION",
                        SEVERITY_MODERATE,
                        DIM_ABSTENTION_ACCURACY,
                        f"Beklenen {exp.expected_statuses} yerine '{answer.status}' durması (eksik={list(trace_bundle.missing_facts)}).",
                        rc,
                    )
                    _add_defect(
                        "MODERATE_FALSE_ABSTENTION",
                        SEVERITY_MODERATE,
                        DIM_LEGAL_CORRECTNESS,
                        f"Beklenen statü {exp.expected_statuses} yerine muhafazakâr durma ({answer.status}).",
                        rc,
                    )
                else:
                    _add_defect(
                        "MAJOR_WRONG_FINAL_OUTCOME",
                        SEVERITY_MAJOR,
                        DIM_LEGAL_CORRECTNESS,
                        f"Beklenen statü {exp.expected_statuses}, gerçekleşen '{answer.status}'.",
                        ROOT_CAUSE_RISK_THRESHOLD_MISMATCH,
                    )

            if exp.expected_confidence_statuses and answer.confidence_status not in exp.expected_confidence_statuses:
                _add_defect(
                    "MODERATE_CONFIDENCE_MISMATCH",
                    SEVERITY_MODERATE,
                    DIM_ABSTENTION_ACCURACY,
                    f"Beklenen güven {exp.expected_confidence_statuses}, gerçekleşen '{answer.confidence_status}'.",
                    ROOT_CAUSE_ABSTENTION_OVER_TRIGGER
                    if answer.confidence_status == "INSUFFICIENT_EVIDENCE"
                    else ROOT_CAUSE_CITATION_FAILURE,
                )

            if exp.expected_missing_fields:
                surfaced_fields = {m.field for m in answer.missing_information}
                for mf in exp.expected_missing_fields:
                    if mf not in surfaced_fields:
                        _add_defect(
                            "MODERATE_INCOMPLETE_CLARIFICATION_Q",
                            SEVERITY_MODERATE,
                            DIM_ABSTENTION_ACCURACY,
                            f"Beklenen eksik olgu '{mf}' missing_information listesinde sorulmadı.",
                            ROOT_CAUSE_ABSTENTION_UNDER_TRIGGER,
                        )

            exp_min_rank = _RISK_RANK.get(exp.expected_min_risk_level, 1)
            obs_risk_rank = _RISK_RANK.get(observed_risk, 1)
            if obs_risk_rank < exp_min_rank:
                _add_defect(
                    "MAJOR_RISK_UNDERESTIMATED",
                    SEVERITY_MAJOR,
                    DIM_RISK_DETECTION,
                    f"Risk düzeyi beklenenin altında: beklenen >= {exp.expected_min_risk_level}, gerçekleşen {observed_risk}.",
                    ROOT_CAUSE_RISK_THRESHOLD_MISMATCH,
                )
            if exp.expected_counsel_escalation_required is True and not answer.human_approval.counsel_escalation_required:
                _add_defect(
                    "MAJOR_MISSED_MANDATORY_ESCALATION",
                    SEVERITY_MAJOR,
                    DIM_RISK_DETECTION,
                    "Zorunlu şirket avukatı eskalasyonu (counsel_escalation_required=True) açılmadı.",
                    ROOT_CAUSE_RISK_THRESHOLD_MISMATCH,
                )
            if exp.expected_payroll_handoff_allowed is False and answer.human_approval.payroll_handoff_allowed:
                _add_defect(
                    "MAJOR_WRONG_PAYROLL_HANDOFF_UNLOCK",
                    SEVERITY_MAJOR,
                    DIM_RISK_DETECTION,
                    "Kilitli kalması gereken @ÜcretBordro devri açık bırakıldı.",
                    ROOT_CAUSE_RISK_THRESHOLD_MISMATCH,
                )
            elif exp.expected_payroll_handoff_allowed is True and not answer.human_approval.payroll_handoff_allowed:
                _add_defect(
                    "MINOR_PAYROLL_HANDOFF_CONSERVATIVE",
                    SEVERITY_MINOR,
                    DIM_RISK_DETECTION,
                    "@ÜcretBordro devri muhafazakâr biçimde kilitli tutuldu.",
                    ROOT_CAUSE_ABSTENTION_OVER_TRIGGER,
                )

            # O-05 Fixed Cutoff Retrieval Scoring (based strictly on @5 primary cutoff)
            if gt.required_provision_ids or gt.required_source_ids:
                ret_pct = 100.0 * (
                    (0.6 * prov_r5 + 0.4 * src_h5)
                    if (gt.required_provision_ids and gt.required_source_ids)
                    else (prov_r5 if gt.required_provision_ids else src_h5)
                )
                if ret_pct < 100.0:
                    missing_in_kb = any(
                        p not in self._kb_provisions for p in gt.required_provision_ids
                    ) if self._kb_provisions else False
                    rc_ret = ROOT_CAUSE_KB_CORPUS_GAP if missing_in_kb else ROOT_CAUSE_RAG_RETRIEVAL_MISS
                    _add_defect(
                        "MODERATE_RETRIEVAL_PARTIAL_RECALL",
                        SEVERITY_MODERATE,
                        DIM_RETRIEVAL_EFFECTIVENESS,
                        f"Retrieval Recall@5 tam değil (prov@5={prov_r5:.2f}, prov@10={prov_r10:.2f}, src@5={src_h5:.2f}, mrr={mrr:.2f}).",
                        rc_ret,
                    )
                    dim_scores[DIM_RETRIEVAL_EFFECTIVENESS] = min(dim_scores[DIM_RETRIEVAL_EFFECTIVENESS], ret_pct)

            if not answer.status.startswith("ABSTAINED_"):
                missing_srcs = [s for s in gt.required_source_ids if s not in active_sources]
                missing_precs = [p for p in gt.required_precedent_ids if p not in active_precs]
                missing_provs = [p for p in gt.required_provision_ids if p not in active_provs]
                for ms in missing_srcs:
                    if self._kb_sources and ms not in self._kb_sources:
                        rc = ROOT_CAUSE_KB_CORPUS_GAP
                    elif ms in retrieved_sources:
                        rc = ROOT_CAUSE_REASONING_EXCEPTION_MISS
                    else:
                        rc = ROOT_CAUSE_RAG_RETRIEVAL_MISS
                    _add_defect(
                        "MAJOR_MISSED_REQUIRED_SOURCE",
                        SEVERITY_MAJOR,
                        DIM_SOURCE_ACCURACY,
                        f"Zorunlu kaynak ({ms}) aktif legal_bases / iddialara bağlanmadı.",
                        rc,
                    )
                for mp in missing_provs:
                    if self._kb_provisions and mp not in self._kb_provisions:
                        rc = ROOT_CAUSE_KB_CORPUS_GAP
                    elif mp in retrieved_provs or mp in retrieved_precs:
                        rc = ROOT_CAUSE_REASONING_EXCEPTION_MISS
                    else:
                        rc = ROOT_CAUSE_RAG_RETRIEVAL_MISS
                    _add_defect(
                        "MODERATE_RETRIEVAL_PARTIAL_RECALL",
                        SEVERITY_MODERATE,
                        DIM_SOURCE_ACCURACY,
                        f"Zorunlu madde düğümü ({mp}) aktif iddialarda yer almadı.",
                        rc,
                    )
                for mprec in missing_precs:
                    _add_defect(
                        "MAJOR_MISSED_REQUIRED_SOURCE",
                        SEVERITY_MAJOR,
                        DIM_SOURCE_ACCURACY,
                        f"Beklenen içtihat ({mprec}) içtihat bloğuna bağlanmadı.",
                        ROOT_CAUSE_RAG_RETRIEVAL_MISS,
                    )

            if case.include_historical and gt.expected_historical_source_ids:
                for hsid in gt.expected_historical_source_ids:
                    if hsid not in hist_sources:
                        _add_defect(
                            "MODERATE_MISSING_HISTORICAL_SEPARATION",
                            SEVERITY_MODERATE,
                            DIM_TEMPORAL_ACCURACY,
                            f"Beklenen tarihsel bağlam kaynağı ({hsid}) historical_context içine ayrıştırılmadı.",
                            ROOT_CAUSE_TEMPORAL_BOUNDARY_MISS,
                        )

            if gt.l5_l6_template_warning_expected and "reference_template_pending_company_adoption" not in tr_fold(
                sections_dict.get("hukuki_degerlendirme", "") + "\n" + sections_dict.get("istisnalar", "")
            ):
                _add_defect(
                    "MODERATE_L5_L6_TEMPLATE_NOTICE_MISSING",
                    SEVERITY_MODERATE,
                    DIM_INTERPRETATION_HIERARCHY,
                    "L5/L6 kabul edilmemiş şablon sınırı uyarısı yer almadı.",
                    ROOT_CAUSE_REASONING_EXCEPTION_MISS,
                )
            if gt.expected_norm_hierarchy_winner and not _concept_matched(
                gt.expected_norm_hierarchy_winner, eval_text_folded
            ):
                _add_defect(
                    "MAJOR_NORM_HIERARCHY_INVERSION",
                    SEVERITY_MAJOR,
                    DIM_INTERPRETATION_HIERARCHY,
                    f"Beklenen norm hiyerarşisi sonucu '{gt.expected_norm_hierarchy_winner}' gerekçelendirilmedi.",
                    ROOT_CAUSE_REASONING_EXCEPTION_MISS,
                )
            if gt.critical_exceptions:
                missed_excs = [ex for ex in gt.critical_exceptions if not _concept_matched(ex, eval_text_folded)]
                if missed_excs:
                    ratio = len(missed_excs) / len(gt.critical_exceptions)
                    # Y-01 Fixed threshold & fixed deterministic penalty (zero overlap!)
                    if ratio > 0.5 and not answer.status.startswith("ABSTAINED_"):
                        _add_defect(
                            "MAJOR_MISSED_CRITICAL_EXCEPTION",
                            SEVERITY_MAJOR,
                            DIM_INTERPRETATION_HIERARCHY,
                            f"Kritik istisna kavramlarının yarısından fazlası eksik ({len(missed_excs)}/{len(gt.critical_exceptions)}): {missed_excs}",
                            ROOT_CAUSE_REASONING_EXCEPTION_MISS,
                        )
                    else:
                        _add_defect(
                            "MODERATE_PARTIAL_EXCEPTION_COVERAGE",
                            SEVERITY_MODERATE,
                            DIM_INTERPRETATION_HIERARCHY,
                            f"Koşullu/kısmi istisna noktaları eksik: {missed_excs}",
                            ROOT_CAUSE_REASONING_EXCEPTION_MISS,
                        )

            if exp.acceptable_answer_criteria and not answer.status.startswith("ABSTAINED_"):
                missed_crit = [cr for cr in exp.acceptable_answer_criteria if not _concept_matched(cr, full_text_folded)]
                for cr in missed_crit:
                    if minor_penalty_accum >= CASE_MINOR_BUDGET_CAP:
                        break
                    _add_defect(
                        "MINOR_MISSING_NONCRITICAL_CRITERION",
                        SEVERITY_MINOR,
                        DIM_LEGAL_CORRECTNESS,
                        f"İkincil ifade/kapsam ölçütü eksik: '{cr}'",
                        ROOT_CAUSE_NONE,
                    )

        # Y-02 Strict RENORMALIZED_ACTIVE_WEIGHTS calculation (never free 100.0 for N/A!)
        evaluated_dims = tuple(d for d in DIMENSION_WEIGHTS if dim_applicable[d])
        na_dims = tuple(d for d in DIMENSION_WEIGHTS if not dim_applicable[d])
        active_weight_sum = sum(DIMENSION_WEIGHTS[d] for d in evaluated_dims)
        if active_weight_sum <= 0:
            raise EvaluationIntegrityError(f"{case.case_id}: aktif değerlendirilen boyut ağırlıkları toplamı 0 olamaz.")
        raw_weighted = sum(DIMENSION_WEIGHTS[d] * dim_scores[d] for d in evaluated_dims) / float(active_weight_sum)

        # K-02 Consistent Thresholds (PASS >= 85.0, PARTIAL_REVIEW 80.0..84.99, FAIL_SCORE < 80.0)
        fatal_cnt = sum(1 for d in defects if d.severity == SEVERITY_FATAL)
        major_cnt = sum(1 for d in defects if d.severity == SEVERITY_MAJOR)
        final_score, verdict = classify_score_band(raw_weighted, fatal_count=fatal_cnt, major_count=major_cnt)
        assert final_score is not None

        root_tags = tuple(dict.fromkeys(d.root_cause_tag for d in defects if d.root_cause_tag != ROOT_CAUSE_NONE))
        dim_tuples = tuple(
            DimensionScore(
                dimension_id=d_id,
                weight=DIMENSION_WEIGHTS[d_id],
                raw_score=dim_scores[d_id] if dim_applicable[d_id] else None,
                applicable=dim_applicable[d_id],
                normalized_weight_pct=(100.0 * DIMENSION_WEIGHTS[d_id] / active_weight_sum)
                if dim_applicable[d_id]
                else 0.0,
                evidence_notes=tuple(dim_notes[d_id]),
            )
            for d_id in DIMENSION_WEIGHTS
        )

        review_st = (
            "APPROVED_FOR_BENCHMARK"
            if (signoff_state is not None and signoff_state.approved)
            else case.legal_review.review_status
        )
        sign_st = signoff_state.signoff_status if signoff_state is not None else SIGNOFF_PENDING
        app_hist = signoff_state.approval_history if signoff_state is not None else ()
        ovr_hist = signoff_state.override_history if signoff_state is not None else ()

        return SingleCaseEvalReport(
            case_id=case.case_id,
            category=case.category,
            split=case.split,
            cluster_id=case.cluster_id,
            difficulty=case.difficulty,
            review_status=review_st,
            legal_signoff_status=sign_st,
            verdict=verdict,
            raw_weighted_score=raw_weighted,
            final_score=final_score,
            dimension_scores=dim_tuples,
            evaluated_dimension_ids=evaluated_dims,
            na_dimension_ids=na_dims,
            defects=tuple(defects),
            root_cause_tags=root_tags,
            observed_status=answer.status,
            observed_confidence=answer.confidence_status,
            observed_risk_level=observed_risk,
            counsel_escalation_required=answer.human_approval.counsel_escalation_required,
            payroll_handoff_allowed=answer.human_approval.payroll_handoff_allowed,
            published_answer_blocked=answer.published_answer_blocked,
            trace_id=trace_bundle.trace_id,
            answer_id=answer.answer_id,
            answer_sha256=answer.answer_sha256,
            retrieval_provision_recall_at_5=prov_r5,
            retrieval_provision_recall_at_10=prov_r10,
            retrieval_source_hit_rate_at_5=src_h5,
            retrieval_source_hit_rate_at_10=src_h10,
            retrieval_mrr=mrr,
            approval_history=app_hist,
            override_history=ovr_hist,
        )
