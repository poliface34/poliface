"""WP-4.5 Evaluation severity-weighted scoring rubric (`AUTO_DETERMINISTIC` vs `INDEPENDENT_LEGAL_REVIEWER`)."""

from __future__ import annotations

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
from .models import (
    DIM_ABSTENTION_ACCURACY,
    DIM_CITATION_INTEGRITY,
    DIM_INTERPRETATION_HIERARCHY,
    DIM_LEGAL_CORRECTNESS,
    DIM_RETRIEVAL_EFFECTIVENESS,
    DIM_RISK_DETECTION,
    DIM_SOURCE_ACCURACY,
    DIM_TEMPORAL_ACCURACY,
    DIMENSION_WEIGHTS,
    MISSING_DIM_POLICY_NEUTRAL,
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
    VERDICT_FAIL_FATAL,
    VERDICT_FAIL_MAJOR,
    VERDICT_PARTIAL_REVIEW,
    VERDICT_PASS,
    DimensionScore,
    EvaluationCase,
    FailureDefectRecord,
    SingleCaseEvalReport,
)

_RISK_RANK: dict[str, int] = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_RANK_NAME: dict[int, str] = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
_PAYROLL_LEAK_RE = re.compile(
    r"(?:hesaplanan\s+net|ödenecek\s+net\s+tutar)\s*[:=]?\s*\d[\d.,]*\s*(?:tl|₺|lira)",
    re.IGNORECASE,
)


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
    """Deterministic 8-dimension & 4-tier severity evaluator strictly matching WP4_5_EVALUATION_SPEC v1.1."""

    def __init__(
        self,
        *,
        source_registry: dict[str, LegalSourceRecord] | None = None,
        precedent_registry: dict[str, PrecedentRecord] | None = None,
        known_kb_provisions: set[str] | None = None,
        known_kb_sources: set[str] | None = None,
        missing_dimension_policy: str = MISSING_DIM_POLICY_NEUTRAL,
    ) -> None:
        self._sources = source_registry or {}
        self._precedents = precedent_registry or {}
        self._kb_provisions = known_kb_provisions or set()
        self._kb_sources = known_kb_sources or set()
        self._missing_dim_policy = missing_dimension_policy

    def score_case(
        self,
        *,
        case: EvaluationCase,
        trace_bundle: RetrievalTraceBundle,
        answer: VerifiedAnswerPackage,
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

        all_active_buckets = (
            *trace_bundle.normative_bucket,
            *trace_bundle.interpretation_bucket,
            *trace_bundle.autonomous_norm_bucket,
            *trace_bundle.precedent_bucket,
        )
        retrieved_sources = {it.chunk.source_id for it in all_active_buckets if it.chunk.source_id}
        retrieved_provs = {it.chunk.provision_id for it in all_active_buckets if it.chunk.provision_id}
        retrieved_precs = {
            str((it.precedent_metadata or {}).get("precedent_id") or it.chunk.source_id)
            for it in trace_bundle.precedent_bucket
        }

        sections_dict = answer.eight_sections.to_dict()
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
        full_text_folded = tr_fold("\n".join(sections_dict.values()))

        prov_recall = 1.0
        if gt.required_provision_ids:
            prov_hits = sum(
                1 for pid in gt.required_provision_ids if pid in retrieved_provs or pid in retrieved_precs
            )
            prov_recall = prov_hits / len(gt.required_provision_ids)

        src_hit_rate = 1.0
        if gt.required_source_ids:
            src_hits = sum(1 for sid in gt.required_source_ids if sid in retrieved_sources)
            src_hit_rate = src_hits / len(gt.required_source_ids)

        dim_scores: dict[str, float] = {k: 100.0 for k in DIMENSION_WEIGHTS}
        dim_notes: dict[str, list[str]] = {k: [] for k in DIMENSION_WEIGHTS}
        dim_applicable: dict[str, bool] = {k: True for k in DIMENSION_WEIGHTS}
        minor_penalty_accum = 0.0

        def _add_defect(
            code: str,
            severity: str,
            dim_id: str,
            penalty: float,
            message: str,
            root_cause: str,
            trigger_source: str = TRIGGER_AUTO_DETERMINISTIC,
        ) -> None:
            nonlocal minor_penalty_accum
            actual_pen = penalty
            if severity == SEVERITY_MINOR:
                remaining_minor = max(0.0, 5.0 - minor_penalty_accum)
                actual_pen = min(max(1.0, penalty), remaining_minor) if remaining_minor > 0 else 0.0
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
            dim_applicable[dim_id] = True
            dim_scores[dim_id] = max(0.0, min(100.0, dim_scores[dim_id] - actual_pen))
            dim_notes[dim_id].append(f"[{severity} | {trigger_source}] {code} (-{actual_pen:.1f}): {message}")

        # ------------------------------------------------------------------
        # F-5: Closed governance gates & cryptographic lineage check
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
                100.0,
                "Üretim, 5070 sayılı Kanun veya KVKK m.9 kapılarından biri kapalı olmaktan çıktı.",
                ROOT_CAUSE_CITATION_FAILURE,
            )

        # Missing required telemetry signals -> MEASUREMENT_UNAVAILABLE (S_d = 0.0)
        if not trace_bundle.trace_id or not answer.answer_sha256 or not answer.audit_trace.audit_trace_sha256:
            _add_defect(
                "FATAL_UNWHITELISTED_CLAIM",
                SEVERITY_FATAL,
                DIM_CITATION_INTEGRITY,
                100.0,
                "MEASUREMENT_UNAVAILABLE: Zorunlu izlenebilirlik veya answer_sha256 sinyali eksik.",
                ROOT_CAUSE_CITATION_FAILURE,
            )
        elif (
            answer.audit_trace.source_trace_id != trace_bundle.trace_id
            or answer.audit_trace.source_bundle_sha256 != trace_bundle.bundle_sha256
            or answer.audit_trace.answer_sha256 != answer.answer_sha256
        ):
            _add_defect(
                "FATAL_UNWHITELISTED_CLAIM",
                SEVERITY_FATAL,
                DIM_CITATION_INTEGRITY,
                100.0,
                "AnswerAuditTrace ile RetrievalTraceBundle kriptografik iz bağı kopuk.",
                ROOT_CAUSE_CITATION_FAILURE,
            )

        # F-4: Unauthorized TL calculation leak outside @ÜcretBordro handoff
        if (
            _PAYROLL_LEAK_RE.search(answer.eight_sections.uygulama)
            or _PAYROLL_LEAK_RE.search(answer.eight_sections.hukuki_sonuc)
        ) and not answer.published_answer_blocked:
            _add_defect(
                "FATAL_UNAUTHORIZED_PAYROLL_CALC",
                SEVERITY_FATAL,
                DIM_LEGAL_CORRECTNESS,
                100.0,
                "@HukukSGK cevabı yetkisiz parasal net TL hesabı yayınladı.",
                ROOT_CAUSE_CITATION_FAILURE,
            )

        # F-1 / F-2 / F-3: Active claim, whitelist, temporal, pending_review & precedent checks
        if not exp.expected_published_blocked and not answer.published_answer_blocked:
            bad_forb_src = sorted(active_sources.intersection(gt.forbidden_source_ids))
            for sid in bad_forb_src:
                src_rec = self._sources.get(sid)
                if src_rec and src_rec.verification_status in {"PENDING_REVIEW", "UNVERIFIED"}:
                    _add_defect(
                        "FATAL_PENDING_REVIEW_AS_DEFINITIVE",
                        SEVERITY_FATAL,
                        DIM_SOURCE_ACCURACY,
                        100.0,
                        f"Doğrulama bekleyen kaynak ({sid}) aktif hukuki dayanak olarak sunuldu.",
                        ROOT_CAUSE_CITATION_FAILURE,
                    )
                elif sid == "RG-9368-20241228" or (src_rec and src_rec.verification_status == "SUPERSEDED"):
                    _add_defect(
                        "FATAL_REPEALED_STATUTE_AS_CURRENT",
                        SEVERITY_FATAL,
                        DIM_TEMPORAL_ACCURACY,
                        100.0,
                        f"Yürürlükten kalkmış düzenleme ({sid}) güncel dayanak olarak sunuldu.",
                        ROOT_CAUSE_TEMPORAL_BOUNDARY_MISS,
                    )
                else:
                    _add_defect(
                        "FATAL_RETROACTIVE_LAW_APPLICATION",
                        SEVERITY_FATAL,
                        DIM_TEMPORAL_ACCURACY,
                        100.0,
                        f"Olay tarihine uygulanamayacak/yasaklı kaynak ({sid}) aktif dayanak yapıldı.",
                        ROOT_CAUSE_TEMPORAL_BOUNDARY_MISS,
                    )

            bad_forb_prov = sorted(active_provs.intersection(gt.forbidden_provision_ids))
            if bad_forb_prov:
                _add_defect(
                    "FATAL_WRONG_ARTICLE_OR_SOURCE_CITED",
                    SEVERITY_FATAL,
                    DIM_SOURCE_ACCURACY,
                    100.0,
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
                        100.0,
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
                        100.0,
                        f"PENDING_REVIEW durumundaki içtihat {pid} aktif sunulamaz.",
                        ROOT_CAUSE_CITATION_FAILURE,
                    )

            for clm in answer.claims:
                if clm.claim_category == CLAIM_STATUTORY_EVIDENCE and clm.precedent_id:
                    _add_defect(
                        "FATAL_PRECEDENT_AS_STATUTE",
                        SEVERITY_FATAL,
                        DIM_INTERPRETATION_HIERARCHY,
                        100.0,
                        f"İçtihat ({clm.precedent_id}) kanun basamağına çıkarıldı.",
                        ROOT_CAUSE_REASONING_EXCEPTION_MISS,
                    )
                if clm.claim_category in {CLAIM_STATUTORY_EVIDENCE, CLAIM_JUDICIAL_PRECEDENT, CLAIM_LEGAL_INTERPRETATION}:
                    if not clm.effective_on_date:
                        _add_defect(
                            "FATAL_RETROACTIVE_LAW_APPLICATION",
                            SEVERITY_FATAL,
                            DIM_TEMPORAL_ACCURACY,
                            100.0,
                            f"Aktif iddialarda effective_on_date=False kayıt ({clm.claim_id}) bulundu.",
                            ROOT_CAUSE_TEMPORAL_BOUNDARY_MISS,
                        )
                    if clm.claim_category == CLAIM_JUDICIAL_PRECEDENT:
                        if not clm.precedent_id or not trace_bundle.citation_whitelist.contains_precedent(clm.precedent_id):
                            _add_defect(
                                "FATAL_UNWHITELISTED_CLAIM",
                                SEVERITY_FATAL,
                                DIM_CITATION_INTEGRITY,
                                100.0,
                                f"Beyaz liste dışı içtihat iddiası: {clm.precedent_id}.",
                                ROOT_CAUSE_CITATION_FAILURE,
                            )
                    elif not clm.source_id or not trace_bundle.citation_whitelist.contains_source(clm.source_id):
                        _add_defect(
                            "FATAL_UNWHITELISTED_CLAIM",
                            SEVERITY_FATAL,
                            DIM_CITATION_INTEGRITY,
                            100.0,
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
                    100.0,
                    "Olumsuz enjeksiyon / sahte atıf saldırısı CitationValidator tarafından engellenmedi!",
                    ROOT_CAUSE_INJECTION_DEFENSE,
                )
        elif answer.published_answer_blocked:
            b_codes = set(answer.citation_audit.blocker_codes)
            if "WRONG_ARTICLE_OR_PROVISION_CITED" in b_codes:
                _add_defect(
                    "FATAL_WRONG_ARTICLE_OR_SOURCE_CITED",
                    SEVERITY_FATAL,
                    DIM_SOURCE_ACCURACY,
                    100.0,
                    f"Taslak yanlış madde nedeniyle bloklandı: {answer.citation_audit.blocker_codes}",
                    ROOT_CAUSE_CITATION_FAILURE,
                )
            elif "TEMPORAL_RETROACTIVITY_VIOLATION_BLOCKED" in b_codes or "ARTICLE_NOT_EFFECTIVE_ON_DATE" in b_codes:
                _add_defect(
                    "FATAL_RETROACTIVE_LAW_APPLICATION",
                    SEVERITY_FATAL,
                    DIM_TEMPORAL_ACCURACY,
                    100.0,
                    f"Taslak zamansal ihlal nedeniyle bloklandı: {answer.citation_audit.blocker_codes}",
                    ROOT_CAUSE_TEMPORAL_BOUNDARY_MISS,
                )
            elif "EXPIRED_OR_REPEALED_STATUTE" in b_codes:
                _add_defect(
                    "FATAL_REPEALED_STATUTE_AS_CURRENT",
                    SEVERITY_FATAL,
                    DIM_TEMPORAL_ACCURACY,
                    100.0,
                    f"Taslak mülga kaynak nedeniyle bloklandı: {answer.citation_audit.blocker_codes}",
                    ROOT_CAUSE_TEMPORAL_BOUNDARY_MISS,
                )
            elif "UNAUTHORIZED_PAYROLL_CALCULATION" in b_codes:
                _add_defect(
                    "FATAL_UNAUTHORIZED_PAYROLL_CALC",
                    SEVERITY_FATAL,
                    DIM_LEGAL_CORRECTNESS,
                    100.0,
                    "Taslak yetkisiz bordro hesabı nedeniyle bloklandı.",
                    ROOT_CAUSE_CITATION_FAILURE,
                )
            elif "GOVERNANCE_GATE_VIOLATION" in b_codes:
                _add_defect(
                    "FATAL_GOVERNANCE_GATE_BREACH",
                    SEVERITY_FATAL,
                    DIM_LEGAL_CORRECTNESS,
                    100.0,
                    "Taslak yönetişim kapısı ihlali nedeniyle bloklandı.",
                    ROOT_CAUSE_CITATION_FAILURE,
                )
            else:
                _add_defect(
                    "FATAL_UNWHITELISTED_CLAIM",
                    SEVERITY_FATAL,
                    DIM_CITATION_INTEGRITY,
                    100.0,
                    f"Pozitif vaka beklenmedik şekilde CitationValidator blokajına takıldı: {answer.citation_audit.blocker_codes}",
                    ROOT_CAUSE_CITATION_FAILURE,
                )

        if not answer.published_answer_blocked and exp.unacceptable_failure_modes:
            for bad_pat in exp.unacceptable_failure_modes:
                if tr_fold(bad_pat) in full_text_folded:
                    _add_defect(
                        "FATAL_WRONG_ARTICLE_OR_SOURCE_CITED",
                        SEVERITY_FATAL,
                        DIM_LEGAL_CORRECTNESS,
                        100.0,
                        f"Yasaklı hukuki ifade cevaba sızdı: '{bad_pat}'.",
                        ROOT_CAUSE_REASONING_EXCEPTION_MISS,
                    )

        # Independent Legal Reviewer FATAL Override (semantic review decision separate from automated rules)
        use_rev_override = (
            case.legal_review.legal_fatal_override
            if legal_fatal_override is None
            else legal_fatal_override
        )
        if use_rev_override:
            rev_reason = (
                legal_fatal_override_reason
                or case.legal_review.legal_fatal_override_reason
                or "Bağımsız hukuk değerlendiricisi tarafından maddi hukuk ihlali gerekçesiyle FATAL işaretlendi."
            )
            _add_defect(
                "LEGAL_FATAL_OVERRIDE",
                SEVERITY_FATAL,
                DIM_LEGAL_CORRECTNESS,
                100.0,
                rev_reason,
                ROOT_CAUSE_REASONING_EXCEPTION_MISS,
                trigger_source=TRIGGER_LEGAL_REVIEWER,
            )

        # ------------------------------------------------------------------
        # Positive Dimension Checks (Not Applicable marking supported cleanly)
        # ------------------------------------------------------------------
        is_clean_blocked_adversarial = exp.expected_published_blocked and answer.published_answer_blocked
        if is_clean_blocked_adversarial:
            # Mark positive retrieval & interpretation as NOT_APPLICABLE if not specified on adversarial case
            if not gt.required_source_ids and not gt.required_provision_ids:
                dim_applicable[DIM_RETRIEVAL_EFFECTIVENESS] = False
                dim_applicable[DIM_SOURCE_ACCURACY] = False
            if not gt.critical_exceptions and not gt.expected_norm_hierarchy_winner:
                dim_applicable[DIM_INTERPRETATION_HIERARCHY] = False
        else:
            if not gt.required_source_ids and not gt.required_provision_ids and not gt.required_precedent_ids:
                if not gt.forbidden_source_ids and not gt.forbidden_provision_ids:
                    dim_applicable[DIM_RETRIEVAL_EFFECTIVENESS] = False
                    dim_applicable[DIM_SOURCE_ACCURACY] = False
            if not gt.critical_exceptions and not gt.expected_norm_hierarchy_winner and not gt.l5_l6_template_warning_expected:
                dim_applicable[DIM_INTERPRETATION_HIERARCHY] = False

            if answer.status not in exp.expected_statuses:
                is_expected_abstain = any(s.startswith("ABSTAINED_") for s in exp.expected_statuses)
                is_observed_abstain = answer.status.startswith("ABSTAINED_")
                if is_expected_abstain and not is_observed_abstain:
                    _add_defect(
                        "MAJOR_FALSE_ASSUMPTION_ON_MISSING_INFO",
                        SEVERITY_MAJOR,
                        DIM_ABSTENTION_ACCURACY,
                        40.0,
                        f"Durması gereken ({exp.expected_statuses}) vakada varsayımla '{answer.status}' üretildi.",
                        ROOT_CAUSE_ABSTENTION_UNDER_TRIGGER,
                    )
                    _add_defect(
                        "MAJOR_WRONG_FINAL_OUTCOME",
                        SEVERITY_MAJOR,
                        DIM_LEGAL_CORRECTNESS,
                        30.0,
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
                    elif prov_recall < 0.5 or src_hit_rate < 0.5:
                        rc = ROOT_CAUSE_RAG_RETRIEVAL_MISS
                    else:
                        rc = ROOT_CAUSE_ABSTENTION_OVER_TRIGGER
                    _add_defect(
                        "MODERATE_FALSE_ABSTENTION",
                        SEVERITY_MODERATE,
                        DIM_ABSTENTION_ACCURACY,
                        15.0,
                        f"Beklenen {exp.expected_statuses} yerine '{answer.status}' durması (eksik={list(trace_bundle.missing_facts)}).",
                        rc,
                    )
                    _add_defect(
                        "MODERATE_FALSE_ABSTENTION",
                        SEVERITY_MODERATE,
                        DIM_LEGAL_CORRECTNESS,
                        15.0,
                        f"Beklenen statü {exp.expected_statuses} yerine muhafazakâr durma ({answer.status}).",
                        rc,
                    )
                else:
                    _add_defect(
                        "MAJOR_WRONG_FINAL_OUTCOME",
                        SEVERITY_MAJOR,
                        DIM_LEGAL_CORRECTNESS,
                        30.0,
                        f"Beklenen statü {exp.expected_statuses}, gerçekleşen '{answer.status}'.",
                        ROOT_CAUSE_RISK_THRESHOLD_MISMATCH,
                    )

            if exp.expected_confidence_statuses and answer.confidence_status not in exp.expected_confidence_statuses:
                _add_defect(
                    "MODERATE_CONFIDENCE_MISMATCH",
                    SEVERITY_MODERATE,
                    DIM_ABSTENTION_ACCURACY,
                    12.0,
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
                            10.0,
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
                    30.0,
                    f"Risk düzeyi beklenenin altında: beklenen >= {exp.expected_min_risk_level}, gerçekleşen {observed_risk}.",
                    ROOT_CAUSE_RISK_THRESHOLD_MISMATCH,
                )
            if exp.expected_counsel_escalation_required is True and not answer.human_approval.counsel_escalation_required:
                _add_defect(
                    "MAJOR_MISSED_MANDATORY_ESCALATION",
                    SEVERITY_MAJOR,
                    DIM_RISK_DETECTION,
                    40.0,
                    "Zorunlu şirket avukatı eskalasyonu (counsel_escalation_required=True) açılmadı.",
                    ROOT_CAUSE_RISK_THRESHOLD_MISMATCH,
                )
            if exp.expected_payroll_handoff_allowed is False and answer.human_approval.payroll_handoff_allowed:
                _add_defect(
                    "MAJOR_WRONG_PAYROLL_HANDOFF_UNLOCK",
                    SEVERITY_MAJOR,
                    DIM_RISK_DETECTION,
                    40.0,
                    "Kilitli kalması gereken @ÜcretBordro devri açık bırakıldı.",
                    ROOT_CAUSE_RISK_THRESHOLD_MISMATCH,
                )
            elif exp.expected_payroll_handoff_allowed is True and not answer.human_approval.payroll_handoff_allowed:
                _add_defect(
                    "MINOR_PAYROLL_HANDOFF_CONSERVATIVE",
                    SEVERITY_MINOR,
                    DIM_RISK_DETECTION,
                    3.0,
                    "@ÜcretBordro devri muhafazakâr biçimde kilitli tutuldu.",
                    ROOT_CAUSE_ABSTENTION_OVER_TRIGGER,
                )

            if gt.required_provision_ids or gt.required_source_ids:
                ret_pct = 100.0 * (
                    (0.6 * prov_recall + 0.4 * src_hit_rate)
                    if (gt.required_provision_ids and gt.required_source_ids)
                    else (prov_recall if gt.required_provision_ids else src_hit_rate)
                )
                if ret_pct < 100.0:
                    loss = 100.0 - ret_pct
                    missing_in_kb = any(
                        p not in self._kb_provisions for p in gt.required_provision_ids
                    ) if self._kb_provisions else False
                    rc_ret = ROOT_CAUSE_KB_CORPUS_GAP if missing_in_kb else ROOT_CAUSE_RAG_RETRIEVAL_MISS
                    _add_defect(
                        "MODERATE_RETRIEVAL_PARTIAL_RECALL",
                        SEVERITY_MODERATE,
                        DIM_RETRIEVAL_EFFECTIVENESS,
                        min(15.0, max(10.0, loss)),
                        f"Retrieval Recall tam değil (prov={prov_recall:.2f}, src={src_hit_rate:.2f}).",
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
                        25.0,
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
                        12.0,
                        f"Zorunlu madde düğümü ({mp}) aktif iddialarda yer almadı.",
                        rc,
                    )
                for mprec in missing_precs:
                    _add_defect(
                        "MAJOR_MISSED_REQUIRED_SOURCE",
                        SEVERITY_MAJOR,
                        DIM_SOURCE_ACCURACY,
                        25.0,
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
                            12.0,
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
                    12.0,
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
                    25.0,
                    f"Beklenen norm hiyerarşisi sonucu '{gt.expected_norm_hierarchy_winner}' gerekçelendirilmedi.",
                    ROOT_CAUSE_REASONING_EXCEPTION_MISS,
                )
            if gt.critical_exceptions:
                missed_excs = [ex for ex in gt.critical_exceptions if not _concept_matched(ex, eval_text_folded)]
                if missed_excs:
                    ratio = len(missed_excs) / len(gt.critical_exceptions)
                    if ratio > 0.5 and not answer.status.startswith("ABSTAINED_"):
                        _add_defect(
                            "MAJOR_MISSED_CRITICAL_EXCEPTION",
                            SEVERITY_MAJOR,
                            DIM_INTERPRETATION_HIERARCHY,
                            min(35.0, 20.0 * ratio + 10.0),
                            f"Kritik istisna kavramları eksik: {missed_excs}",
                            ROOT_CAUSE_REASONING_EXCEPTION_MISS,
                        )
                    else:
                        _add_defect(
                            "MODERATE_MISSING_COUNTER_ARGUMENT",
                            SEVERITY_MODERATE,
                            DIM_INTERPRETATION_HIERARCHY,
                            min(15.0, max(10.0, 10.0 * ratio + 3.0)),
                            f"İkincil/koşullu istisna noktaları eksik: {missed_excs}",
                            ROOT_CAUSE_REASONING_EXCEPTION_MISS,
                        )

            if exp.acceptable_answer_criteria and not answer.status.startswith("ABSTAINED_"):
                missed_crit = [cr for cr in exp.acceptable_answer_criteria if not _concept_matched(cr, full_text_folded)]
                if missed_crit:
                    raw_minor = float(len(missed_crit) * 2)
                    _add_defect(
                        "MINOR_MISSING_NONCRITICAL_CRITERION",
                        SEVERITY_MINOR,
                        DIM_LEGAL_CORRECTNESS,
                        min(5.0, raw_minor),
                        f"İfade/kapsam ölçütü kısmen eksik: {missed_crit[:2]}",
                        ROOT_CAUSE_NONE,
                    )

        evaluated_dims = tuple(d for d in DIMENSION_WEIGHTS if dim_applicable[d] or self._missing_dim_policy == MISSING_DIM_POLICY_NEUTRAL)
        na_dims = tuple(d for d in DIMENSION_WEIGHTS if not dim_applicable[d])
        active_weight_sum = sum(DIMENSION_WEIGHTS[d] for d in evaluated_dims)
        if active_weight_sum <= 0:
            active_weight_sum = 100
            evaluated_dims = tuple(DIMENSION_WEIGHTS.keys())
        raw_weighted = sum(DIMENSION_WEIGHTS[d] * dim_scores[d] for d in evaluated_dims) / float(active_weight_sum)

        has_fatal = any(d.severity == SEVERITY_FATAL for d in defects)
        has_major = any(d.severity == SEVERITY_MAJOR for d in defects)
        if has_fatal:
            final_score = 0.0
            verdict = VERDICT_FAIL_FATAL
        elif has_major:
            final_score = min(65.0, raw_weighted)
            verdict = VERDICT_FAIL_MAJOR
        else:
            final_score = raw_weighted
            verdict = VERDICT_PASS if final_score >= 80.0 else VERDICT_PARTIAL_REVIEW

        root_tags = tuple(dict.fromkeys(d.root_cause_tag for d in defects if d.root_cause_tag != ROOT_CAUSE_NONE))
        dim_tuples = tuple(
            DimensionScore(
                dimension_id=d_id,
                weight=DIMENSION_WEIGHTS[d_id],
                raw_score=dim_scores[d_id],
                applicable=dim_applicable[d_id],
                evidence_notes=tuple(dim_notes[d_id]),
            )
            for d_id in DIMENSION_WEIGHTS
        )

        return SingleCaseEvalReport(
            case_id=case.case_id,
            category=case.category,
            split=case.split,
            cluster_id=case.cluster_id,
            difficulty=case.difficulty,
            review_status=case.legal_review.review_status,
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
            retrieval_provision_recall=prov_recall,
            retrieval_source_hit_rate=src_hit_rate,
        )
