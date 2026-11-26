"""Stage 5 AnswerAbstentionHandler & deterministic confidence derivation (WP-4.4)."""

from __future__ import annotations

from ..models import HumanApprovalRequirement, MissingInfoItem
from ..rag.models import (
    BINDING_TRUST_CHAIN_EVIDENCE_BOUND,
    GATE_ABSTAIN_INSUFFICIENT_EVIDENCE,
    GATE_ABSTAIN_MISSING_INFO,
    GATE_ABSTAIN_OUT_OF_DOMAIN,
    RetrievalTraceBundle,
)
from .models import (
    CONFIDENCE_INSUFFICIENT_EVIDENCE,
    CONFIDENCE_PARTIALLY_VERIFIED,
    CONFIDENCE_VERIFIED,
    STATUS_ABSTAINED_INSUFFICIENT_EVIDENCE,
    STATUS_ABSTAINED_MISSING_INFO,
    STATUS_ABSTAINED_OUT_OF_DOMAIN,
    STATUS_ANSWERED,
    STATUS_ANSWERED_WITH_ESCALATION,
    AnswerAbstentionDecision,
    AnswerReasoningResult,
    AnswerRiskAssessmentResult,
    TemporalValidationReport,
)

_FACT_REQUIRED_DOCS: dict[str, tuple[str, str]] = {
    "as_of_date": ("Olay/değerlendirme tarihi kesinleşmeden yürürlük denetimi yapılamaz.", "Fesih/olay tutanağı veya tarihli bildirim belgesi"),
    "notification_channel": ("24.07.2025 sonrası 4857 m.109 yazılılık şartı kanala bağlıdır.", "Tebellüğ imzalı yazı, noter ihtarnamesi veya KEP kaydı"),
    "written_notice_with_clear_reason": ("4857 m.19/1 ve m.109 yazılı ve açık sebep koşulu kontrol edilmelidir.", "İmzalı yazılı fesih bildirim metni"),
    "discovery_date": ("4857 m.26 kapsamındaki 6 iş günlük hak düşürücü süre başlangıcı belirlenemez.", "Feshe yetkili organ/makam öğrenme tarihli disiplin tutanağı"),
    "incident_date": ("4857 m.26 1 yıllık üst süre ve fiil tarihi doğrulanmalıdır.", "Olay tespit tutanağı veya puantaj/kamera/sistem kaydı"),
    "discovering_authority_status": ("6 iş günü yalnızca feshe yetkili makamın öğrenmesiyle başlar.", "İmza sirküleri / disiplin kurulu görev ve yetki çizelgesi"),
    "weekly_rest_day": ("4857 m.46 yasal hafta tatili günü m.26 dışlaması için zorunludur.", "İş sözleşmesi veya TİS çalışma düzeni maddesi"),
    "termination_reason_type": ("1475 m.14 kıdem tazminatı hakkı fesih sebebine bağlıdır.", "Yazılı fesih bildirimi ve SGK işten ayrılış bildirgesi"),
    "tenure_months": ("En az 1 yıllık kıdem ve 6 ay iş güvencesi eşiği kontrol edilmelidir.", "SGK hizmet dökümü ve işe giriş bildirgesi"),
    "autonomous_norm_adoption_proof": ("Kabul edilmemiş L5/L6 şablonları bağlayıcı kural sayılamaz.", "Yönetim onaylı politika veya yürürlükteki TİS"),
    "written_employee_consent_4857_m22": ("İşçi aleyhine esaslı değişiklikte 6 iş günü içinde yazılı rıza şarttır.", "İşçi imzalı 4857 m.22 değişiklik kabul yazısı"),
}


class AnswerAbstentionHandler:
    """Enforces fail-closed stopping & deterministic WP-4.1 confidence derivation."""

    def decide(
        self,
        *,
        trace_bundle: RetrievalTraceBundle,
        temporal_report: TemporalValidationReport,
        reasoning_result: AnswerReasoningResult,
        risk_result: AnswerRiskAssessmentResult,
    ) -> AnswerAbstentionDecision:
        missing_items = tuple(
            MissingInfoItem(
                field=f,
                reason=_FACT_REQUIRED_DOCS.get(f, ("Zorunlu olgu veya belge eksikliği hukuki değerlendirmeyi durdurur.", ""))[0],
                required_document=_FACT_REQUIRED_DOCS.get(f, ("", "İlgili İK/SGK resmi ispat belgesi"))[1],
            )
            for f in trace_bundle.missing_facts
        )
        clarification_qs = trace_bundle.clarification_questions
        reason_codes: list[str] = []

        # 1. OUT_OF_DOMAIN / Av. K. m.35 refusal
        if trace_bundle.rag_gate_status == GATE_ABSTAIN_OUT_OF_DOMAIN:
            return AnswerAbstentionDecision(
                should_abstain=True,
                status=STATUS_ABSTAINED_OUT_OF_DOMAIN,
                should_conclude=False,
                confidence_status=CONFIDENCE_INSUFFICIENT_EVIDENCE,
                confidence_reason_codes=("OUT_OF_DOMAIN_OR_AV_K_M35_BOUNDARY",),
                missing_information=(),
                clarification_questions=(),
                disclosure_message=trace_bundle.out_of_domain_message,
                human_approval=HumanApprovalRequirement(
                    required=True,
                    approval_level="MANDATORY_LEGAL_COUNSEL_APPROVAL",
                    counsel_escalation_required=True,
                    payroll_handoff_allowed=False,
                    reasons=("OUT_OF_DOMAIN_OR_AV_K_M35_AUTHORITY_LIMIT",),
                ),
            )

        # 2. Temporal invalidity or missing blocking info -> ABSTAINED_MISSING_INFO
        if not temporal_report.date_valid or trace_bundle.rag_gate_status == GATE_ABSTAIN_MISSING_INFO:
            has_grounded_laws = bool(reasoning_result.legal_bases) or bool(reasoning_result.precedent_claims)
            conf = CONFIDENCE_PARTIALLY_VERIFIED if (temporal_report.date_valid and has_grounded_laws) else CONFIDENCE_INSUFFICIENT_EVIDENCE
            if not temporal_report.date_valid:
                reason_codes.append(temporal_report.error_code or "MISSING_AS_OF_DATE")
            else:
                reason_codes.append("BLOCKING_MISSING_FACTS")
            if temporal_report.rejected_retroactive_items:
                reason_codes.append("RETROACTIVE_ITEMS_REMOVED")
            return AnswerAbstentionDecision(
                should_abstain=True,
                status=STATUS_ABSTAINED_MISSING_INFO,
                should_conclude=False,
                confidence_status=conf,
                confidence_reason_codes=tuple(reason_codes),
                missing_information=missing_items
                or (
                    MissingInfoItem(
                        field="as_of_date",
                        reason="Olay tarihi eksik/çelişkili olduğundan geriye dönük veya güncel yürürlük karşılaştırması yapılamaz.",
                        required_document="Olay veya tebliğ tarihli resmî İK/SGK belgesi",
                    ),
                ),
                clarification_questions=clarification_qs
                or ("Değerlendirilecek olay/fesih tarihi (YYYY-MM-DD) kesin olarak nedir?",),
                disclosure_message=trace_bundle.out_of_domain_message,
                human_approval=HumanApprovalRequirement(
                    required=True,
                    approval_level=risk_result.approval_level,
                    counsel_escalation_required=risk_result.counsel_escalation_required,
                    payroll_handoff_allowed=False,
                    reasons=("BLOCKING_MISSING_FACTS_PREVENT_FINAL_RULING", *risk_result.escalation_reasons),
                ),
            )

        # 3. Insufficient / Pending-Only / Tamper-Emptied Evidence -> ABSTAINED_INSUFFICIENT_EVIDENCE
        has_active_grounding = bool(
            reasoning_result.statutory_claims
            or reasoning_result.interpretation_claims
            or reasoning_result.precedent_claims
        )
        if trace_bundle.rag_gate_status == GATE_ABSTAIN_INSUFFICIENT_EVIDENCE or not has_active_grounding:
            reason_codes.append("NO_VERIFIED_ACTIVE_EVIDENCE")
            if trace_bundle.quarantined_evidence_mismatches:
                reason_codes.append("TRUST_CHAIN_INTEGRITY_MISMATCH")
            if trace_bundle.excluded_unverified_notices:
                reason_codes.append("PENDING_OR_UNVERIFIED_SOURCE_ONLY")
            return AnswerAbstentionDecision(
                should_abstain=True,
                status=STATUS_ABSTAINED_INSUFFICIENT_EVIDENCE,
                should_conclude=False,
                confidence_status=CONFIDENCE_INSUFFICIENT_EVIDENCE,
                confidence_reason_codes=tuple(reason_codes),
                missing_information=missing_items,
                clarification_questions=clarification_qs,
                disclosure_message=trace_bundle.unverified_disclosure_message
                or "Doğrulanmış ve yürürlükte aktif hukuki kaynak bulunamadığından cevap verilmesinden kaçınıldı.",
                human_approval=HumanApprovalRequirement(
                    required=True,
                    approval_level="MANDATORY_LEGAL_COUNSEL_APPROVAL"
                    if (trace_bundle.quarantined_evidence_mismatches or risk_result.counsel_escalation_required)
                    else "SENIOR_HR_AND_LEGAL_REVIEW",
                    counsel_escalation_required=bool(
                        trace_bundle.quarantined_evidence_mismatches or risk_result.counsel_escalation_required
                    ),
                    payroll_handoff_allowed=False,
                    reasons=("INSUFFICIENT_OR_UNVERIFIED_EVIDENCE", *risk_result.escalation_reasons),
                ),
            )

        # 4. Deterministic confidence derivation for verified / escalated conclusions (WP4_1 §7.3)
        trust_bound_recs = [
            b for b in trace_bundle.evidence_bindings if b.evidence_binding_status == BINDING_TRUST_CHAIN_EVIDENCE_BOUND
        ]
        all_live_trust_bound = bool(trust_bound_recs) and len(trust_bound_recs) == len(trace_bundle.evidence_bindings) and all(
            b.live_verified and b.raw_content_verified for b in trust_bound_recs
        )
        has_test_transport_only = any(not b.live_verified for b in trust_bound_recs)

        if risk_result.counsel_escalation_required or reasoning_result.has_conflicting_precedent_or_norm:
            if reasoning_result.has_conflicting_precedent_or_norm:
                reason_codes.append("CONFLICTING_PRECEDENT_OR_UNRESOLVED_NORM")
            if risk_result.escalation_reasons:
                reason_codes.extend(risk_result.escalation_reasons[:3])
            confidence = CONFIDENCE_PARTIALLY_VERIFIED
            status = STATUS_ANSWERED_WITH_ESCALATION
            should_abstain = bool(reasoning_result.has_conflicting_precedent_or_norm)
            should_conclude = not reasoning_result.has_conflicting_precedent_or_norm
        elif all_live_trust_bound:
            confidence = CONFIDENCE_VERIFIED
            reason_codes.append("LIVE_HTTPS_TRUST_CHAIN_VERIFIED")
            status = STATUS_ANSWERED
            should_abstain = False
            should_conclude = True
        else:
            confidence = CONFIDENCE_PARTIALLY_VERIFIED
            if has_test_transport_only:
                reason_codes.append("VERIFIED_TEST_TRANSPORT_NON_LIVE")
            elif any(
                b.evidence_binding_status != BINDING_TRUST_CHAIN_EVIDENCE_BOUND for b in trace_bundle.evidence_bindings
            ):
                reason_codes.append("AUDIT_LOG_BACKED_WITHOUT_LIVE_TRUST_CHAIN")
            if trace_bundle.excluded_unverified_notices:
                reason_codes.append("EXCLUDED_UNVERIFIED_OR_UNADOPTED_NOTICES_PRESENT")
            status = STATUS_ANSWERED
            should_abstain = False
            should_conclude = True

        return AnswerAbstentionDecision(
            should_abstain=should_abstain,
            status=status,
            should_conclude=should_conclude,
            confidence_status=confidence,
            confidence_reason_codes=tuple(dict.fromkeys(reason_codes)),
            missing_information=missing_items,
            clarification_questions=clarification_qs,
            disclosure_message=None,
            human_approval=HumanApprovalRequirement(
                required=True,
                approval_level=risk_result.approval_level,
                counsel_escalation_required=risk_result.counsel_escalation_required,
                payroll_handoff_allowed=risk_result.payroll_handoff_allowed,
                reasons=risk_result.escalation_reasons
                or ("Yalnızca İK ön incelemesidir; nihai uygulama insan/hukuk onayı gerektirir.",),
            ),
        )
