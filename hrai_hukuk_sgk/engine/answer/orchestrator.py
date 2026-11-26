"""Stage 1 AnswerOrchestrator coordinating all 8 Answer Engine components (WP-4.4)."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path

from ..knowledge_card_validator import load_knowledge_cards
from ..models import (
    HumanApprovalRequirement,
    LegalKnowledgeCard,
    LegalSourceRecord,
    PrecedentRecord,
)
from ..precedent_verifier import load_precedent_registry
from ..rag.models import RetrievalTraceBundle, compute_deterministic_trace_hashes
from ..source_validator import load_source_registry
from .abstention_handler import AnswerAbstentionHandler
from .audit_trace import AnswerAuditTracer
from .citation_validator import AnswerCitationValidator
from .formatter import EightSectionAnswerFormatter
from .models import (
    ANSWER_VERSION,
    CLOSED_GOVERNANCE_GATES,
    CONFIDENCE_DISPLAY_LABELS_TR,
    CONFIDENCE_INSUFFICIENT_EVIDENCE,
    STATUS_BLOCKED_CITATION_VALIDATION_FAILED,
    AnswerGenerationRequest,
    EmployerEmployeeRiskItem,
    VerifiedAnswerPackage,
    compute_canonical_answer_sha256,
)
from .reasoning import AnswerLegalReasoningEngine
from .risk_assessor import AnswerRiskAssessor
from .temporal_validator import AnswerTemporalValidator

DEFAULT_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class AnswerBundleIntegrityError(ValueError):
    """Fail-closed exception raised when input RetrievalTraceBundle has been tampered with."""


def verify_retrieval_trace_bundle_integrity(bundle: RetrievalTraceBundle) -> None:
    """Recompute deterministic RAG bundle SHA-256 and fail closed on mismatch."""
    expected_id, expected_sha = compute_deterministic_trace_hashes(
        query_text=bundle.query_text,
        as_of_date=bundle.as_of_date,
        intent_classification=bundle.intent_classification,
        temporal_audit=bundle.temporal_audit,
        rag_gate_status=bundle.rag_gate_status,
        should_conclude=bundle.should_conclude,
        counsel_escalation_required=bundle.counsel_escalation_required,
        escalation_reasons=bundle.escalation_reasons,
        payroll_handoff_allowed=bundle.payroll_handoff_allowed,
        missing_facts=bundle.missing_facts,
        clarification_questions=bundle.clarification_questions,
        normative_bucket=bundle.normative_bucket,
        interpretation_bucket=bundle.interpretation_bucket,
        precedent_bucket=bundle.precedent_bucket,
        autonomous_norm_bucket=bundle.autonomous_norm_bucket,
        historical_context_bucket=bundle.historical_context_bucket,
        excluded_unverified_notices=bundle.excluded_unverified_notices,
        evidence_bindings=bundle.evidence_bindings,
        quarantined_evidence_mismatches=bundle.quarantined_evidence_mismatches,
        citation_whitelist=bundle.citation_whitelist,
        pipeline_audit_trail=bundle.pipeline_audit_trail,
    )
    if bundle.bundle_sha256 != expected_sha or bundle.trace_id != expected_id:
        raise AnswerBundleIntegrityError(
            f"[INVALID_TRACE_BUNDLE_INTEGRITY] RetrievalTraceBundle bütünlük özeti "
            f"(trace_id={bundle.trace_id!r}, bundle_sha256={bundle.bundle_sha256!r}) "
            f"beklenen değerle ({expected_id!r}, {expected_sha!r}) uyuşmuyor; cevap üretimi durduruldu."
        )


class HukukSgkAnswerOrchestrator:
    """Deterministic 8-component WP-4.4 Answer Engine consuming WP-4.3 RetrievalTraceBundle."""

    def __init__(
        self,
        *,
        source_registry: dict[str, LegalSourceRecord] | None = None,
        precedent_registry: dict[str, PrecedentRecord] | None = None,
        knowledge_cards: dict[str, LegalKnowledgeCard] | None = None,
    ) -> None:
        self._sources = source_registry or {}
        self._precedents = precedent_registry or {}
        self._cards = knowledge_cards or {}

        self._temporal = AnswerTemporalValidator()
        self._reasoning = AnswerLegalReasoningEngine(
            source_registry=self._sources,
            precedent_registry=self._precedents,
            knowledge_cards=self._cards,
        )
        self._risk = AnswerRiskAssessor()
        self._abstention = AnswerAbstentionHandler()
        self._formatter = EightSectionAnswerFormatter()
        self._citation_validator = AnswerCitationValidator(
            source_registry=self._sources,
            precedent_registry=self._precedents,
        )
        self._auditor = AnswerAuditTracer()

    @classmethod
    def from_project_root(cls, *, project_root: str | Path | None = None) -> HukukSgkAnswerOrchestrator:
        root = Path(project_root) if project_root is not None else DEFAULT_PROJECT_ROOT
        sources = load_source_registry(root / "config" / "legal_sources_registry.json", strict=True)
        precedents = load_precedent_registry(
            root / "config" / "yargitay_precedents.json",
            source_registry=sources,
            strict=True,
        )
        cards = load_knowledge_cards(
            root / "rag_kb",
            source_registry=sources,
            precedent_registry=precedents,
            strict=True,
            audit_log_path=root / "config" / "verification_audit_log.json",
        )
        return cls(
            source_registry=sources,
            precedent_registry=precedents,
            knowledge_cards=cards,
        )

    def generate_answer(self, request: AnswerGenerationRequest) -> VerifiedAnswerPackage:
        bundle = request.trace_bundle
        verify_retrieval_trace_bundle_integrity(bundle)

        generated_at_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        facts = dict(request.facts or {})

        # Stage 2: AnswerTemporalValidator
        temporal_report = self._temporal.validate(bundle)

        # Stage 3: AnswerLegalReasoningEngine (strictly separated Evidence/Precedent/Interpretation/Ops)
        reasoning_res = self._reasoning.reason(
            trace_bundle=bundle,
            temporal_report=temporal_report,
            facts=facts,
            scenario_type=request.scenario_type,
            precedent_application_rationale=request.precedent_application_rationale,
            competing_norm=request.competing_norm,
        )

        # Stage 4: AnswerRiskAssessor
        risk_res = self._risk.assess(
            trace_bundle=bundle,
            temporal_report=temporal_report,
            reasoning_result=reasoning_res,
            facts=facts,
        )

        # Stage 5: AnswerAbstentionHandler & Confidence Derivation
        abstention = self._abstention.decide(
            trace_bundle=bundle,
            temporal_report=temporal_report,
            reasoning_result=reasoning_res,
            risk_result=risk_res,
        )

        # Stage 6: EightSectionAnswerFormatter (draft rendering)
        draft_sections = self._formatter.format_draft(
            trace_bundle=bundle,
            temporal_report=temporal_report,
            reasoning_result=reasoning_res,
            risk_result=risk_res,
            abstention=abstention,
            include_historical_disclosure=request.include_historical_disclosure,
            override_section_texts=request.override_section_texts,
        )

        # Combine generated claims + optional negative test injected_draft_claims before CitationValidator
        claims_to_validate = (*reasoning_res.all_claims(), *request.injected_draft_claims)

        # Stage 7: AnswerCitationValidator (two-layer fail-closed gate)
        citation_audit = self._citation_validator.validate(
            trace_bundle=bundle,
            sections=draft_sections,
            claims=claims_to_validate,
            should_abstain=abstention.should_abstain,
            temporal_report=temporal_report,
            counsel_escalation_required=risk_res.counsel_escalation_required,
            payroll_handoff_allowed=abstention.human_approval.payroll_handoff_allowed,
            overridden_sections=frozenset((request.override_section_texts or {}).keys()),
        )

        if not citation_audit.passed:
            sig = hashlib.sha256(
                f"{bundle.trace_id}|{'|'.join(citation_audit.blocker_codes)}".encode("utf-8")
            ).hexdigest()[:10].upper()
            block_ticket = risk_res.escalation_ticket_id or f"LEGAL-ESC-{sig}"
            final_sections = self._formatter.build_blocked_response(
                blocker_codes=citation_audit.blocker_codes,
                blocker_messages=citation_audit.blocker_messages,
                ticket_id=block_ticket,
            )
            published_blocked = True
            final_status = STATUS_BLOCKED_CITATION_VALIDATION_FAILED
            final_claims = ()
            final_bases = ()
            final_hist = ()
            final_risks = (
                EmployerEmployeeRiskItem(
                    risk_level="CRITICAL",
                    perspective="BOTH",
                    category="CITATION_OR_GUARDRAIL_BLOCKER",
                    description="Taslak cevap atıf, madde, tarih veya aşırı genelleme doğrulamasını geçemediği için bloklandı.",
                    legal_consequence=f"Blokaj nedenleri: {', '.join(citation_audit.blocker_codes)}.",
                    grounded_source_ids=(),
                ),
                *risk_res.risks,
            )
            final_conf = CONFIDENCE_INSUFFICIENT_EVIDENCE
            final_conf_reasons = ("CITATION_VALIDATION_FAILED", *citation_audit.blocker_codes)
            final_approval = HumanApprovalRequirement(
                required=True,
                approval_level="MANDATORY_LEGAL_COUNSEL_APPROVAL",
                counsel_escalation_required=True,
                payroll_handoff_allowed=False,
                reasons=("CITATION_OR_GUARDRAIL_BLOCKER", *citation_audit.blocker_codes),
            )
        else:
            final_sections = draft_sections
            published_blocked = False
            final_status = abstention.status
            final_claims = reasoning_res.all_claims()
            final_bases = reasoning_res.legal_bases
            final_hist = reasoning_res.historical_context
            final_risks = risk_res.risks
            final_conf = abstention.confidence_status
            final_conf_reasons = abstention.confidence_reason_codes
            final_approval = abstention.human_approval

        answer_sha = compute_canonical_answer_sha256(
            query_text=bundle.query_text,
            as_of_date=temporal_report.as_of_date,
            status=final_status,
            published_answer_blocked=published_blocked,
            eight_sections=final_sections,
            claims=final_claims,
            legal_bases=final_bases,
            historical_context=final_hist,
            risks=final_risks,
            human_approval=final_approval,
            confidence_status=final_conf,
            citation_audit=citation_audit,
            source_trace_id=bundle.trace_id,
            source_bundle_sha256=bundle.bundle_sha256,
        )
        answer_id = f"ANS-{answer_sha[:12].upper()}"

        # Stage 8: AnswerAuditTracer
        audit_trace = self._auditor.build_trace(
            trace_bundle=bundle,
            claims=final_claims,
            temporal_report=temporal_report,
            citation_audit=citation_audit,
            answer_sha256=answer_sha,
        )

        return VerifiedAnswerPackage(
            answer_version=ANSWER_VERSION,
            answer_id=answer_id,
            generated_at_utc=generated_at_utc,
            query_text=bundle.query_text,
            as_of_date=temporal_report.as_of_date,
            status=final_status,
            published_answer_blocked=published_blocked,
            eight_sections=final_sections,
            claims=final_claims,
            legal_bases=final_bases,
            historical_context=final_hist,
            precedent_assessments=reasoning_res.precedent_assessments,
            risks=final_risks,
            missing_information=abstention.missing_information,
            clarification_questions=abstention.clarification_questions,
            human_approval=final_approval,
            confidence_status=final_conf,
            confidence_display_label=CONFIDENCE_DISPLAY_LABELS_TR[final_conf],
            confidence_reason_codes=final_conf_reasons,
            citation_audit=citation_audit,
            temporal_report=temporal_report,
            audit_trace=audit_trace,
            governance_gates=dict(CLOSED_GOVERNANCE_GATES),
            answer_sha256=answer_sha,
        )
