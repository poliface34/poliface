"""Core contracts, claim ledger, 8-section answer models, and audit trace structures (WP-4.4)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ..knowledge_base.models import canonical_kb_sha256
from ..models import HumanApprovalRequirement, LegalBasisItem, MissingInfoItem, NormReference
from ..rag.models import RetrievalTraceBundle

ANSWER_VERSION = "1.0.6-wp4.4"

# Answer claim separation categories (Evidence vs Interpretation vs Precedent vs Operational Guidance)
CLAIM_STATUTORY_EVIDENCE = "STATUTORY_EVIDENCE"
CLAIM_JUDICIAL_PRECEDENT = "JUDICIAL_PRECEDENT"
CLAIM_LEGAL_INTERPRETATION = "LEGAL_INTERPRETATION"
CLAIM_OPERATIONAL_GUIDANCE = "OPERATIONAL_GUIDANCE"

VALID_CLAIM_CATEGORIES: frozenset[str] = frozenset(
    {
        CLAIM_STATUTORY_EVIDENCE,
        CLAIM_JUDICIAL_PRECEDENT,
        CLAIM_LEGAL_INTERPRETATION,
        CLAIM_OPERATIONAL_GUIDANCE,
    }
)

# Deterministic confidence derivation levels (WP4_1 §7.3)
CONFIDENCE_VERIFIED = "VERIFIED"
CONFIDENCE_PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
CONFIDENCE_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

CONFIDENCE_DISPLAY_LABELS_TR: dict[str, str] = {
    CONFIDENCE_VERIFIED: "Doğrulanmış",
    CONFIDENCE_PARTIALLY_VERIFIED: "Kısmen Doğrulanmış",
    CONFIDENCE_INSUFFICIENT_EVIDENCE: "Cevap İçin Yetersiz Kaynak",
}

# VerifiedAnswerPackage terminal statuses
STATUS_ANSWERED = "ANSWERED"
STATUS_ANSWERED_WITH_ESCALATION = "ANSWERED_WITH_ESCALATION"
STATUS_ABSTAINED_MISSING_INFO = "ABSTAINED_MISSING_INFO"
STATUS_ABSTAINED_INSUFFICIENT_EVIDENCE = "ABSTAINED_INSUFFICIENT_EVIDENCE"
STATUS_ABSTAINED_OUT_OF_DOMAIN = "ABSTAINED_OUT_OF_DOMAIN"
STATUS_BLOCKED_CITATION_VALIDATION_FAILED = "BLOCKED_CITATION_VALIDATION_FAILED"

CLOSED_GOVERNANCE_GATES: dict[str, bool] = {
    "production_use_authorized": False,
    "qualified_e_signature_5070_equivalent": False,
    "kvkk_data_residency_approved": False,
}

STANDARD_DISCLAIMER_TR = (
    "HUKUKİ SINIR VE YETKİ BEYANI (1136 s. Avukatlık Kanunu m.35): Bu çıktı hrAI (@hrAI / @HukukSGK — "
    "www.insenai.com.tr) tarafından yalnızca doğrulanmış L1–L4 mevzuat/içtihat havuzu üzerinden hazırlanan ön "
    "inceleme ve risk taramasıdır; kesin hukuki mütalaa veya dava dilekçesi yerine geçmez ve parasal bordro hesabı "
    "yapmaz (yalnızca yetkili şirket avukatı ve İK insan onayı ile uygulanabilir)."
)

TRUST_CHAIN_LEGAL_BOUNDARY_NOTICE_TR = (
    "YÖNETİŞİM VE GÜVEN KAPILARI: Üretim kullanımı yetkisi kapalıdır (production_use_authorized=false); "
    "nitelikli elektronik imza (e-İmza / 5070) eşdeğerliği kapalıdır (qualified_e_signature_5070_equivalent=false); "
    "KVKK m.9 yurt dışı aktarım kapısı kapalıdır (kvkk_data_residency_approved=false)."
)


@dataclass(frozen=True)
class AnswerGenerationRequest:
    """Typed orchestrator input wrapping WP-4.3 RetrievalTraceBundle + concrete case context."""

    trace_bundle: RetrievalTraceBundle
    facts: dict[str, Any] = field(default_factory=dict)
    scenario_type: str | None = None
    precedent_application_rationale: str = ""
    competing_norm: NormReference | None = None
    include_historical_disclosure: bool = True
    # Optional negative/stress verification hooks for CitationValidator & TemporalValidator
    injected_draft_claims: tuple["AnswerClaimRecord", ...] = ()
    override_section_texts: dict[str, str] | None = None


@dataclass(frozen=True)
class AnswerClaimRecord:
    """Explicitly categorized claim linking every assertion to a single verified retrieval source/chunk."""

    claim_id: str
    section_name: str
    claim_category: str
    statement: str
    provision_id: str | None
    source_id: str | None
    precedent_id: str | None
    rule_id: str | None
    chunk_id: str | None
    article_ref: str | None
    law_no: str | None
    source_url: str
    audit_log_id: str
    content_sha256: str | None
    chunk_sha256: str | None
    evidence_id: str | None
    registry_head_sha256: str | None
    effective_from: str | None
    effective_to: str | None
    effective_on_date: bool
    historical_disclosure_note: str = ""

    def __post_init__(self) -> None:
        if self.claim_category not in VALID_CLAIM_CATEGORIES:
            raise ValueError(f"Geçersiz claim_category: {self.claim_category!r}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EmployerEmployeeRiskItem:
    """Dual-perspective legal/financial/SGK/KVKK risk unit."""

    risk_level: str  # LOW | MEDIUM | HIGH | CRITICAL
    perspective: str  # EMPLOYER | EMPLOYEE | BOTH
    category: str
    description: str
    legal_consequence: str
    grounded_source_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["grounded_source_ids"] = list(self.grounded_source_ids)
        return out


@dataclass(frozen=True)
class TemporalValidationReport:
    """Output of Stage 2 AnswerTemporalValidator enforcing non-retroactivity & historical separation."""

    as_of_date: str | None
    date_valid: bool
    active_normative_items: tuple[Any, ...] = ()
    active_interpretation_items: tuple[Any, ...] = ()
    active_autonomous_items: tuple[Any, ...] = ()
    validated_precedent_items: tuple[Any, ...] = ()
    historical_context_items: tuple[Any, ...] = ()
    rejected_retroactive_items: tuple[dict[str, Any], ...] = ()
    temporal_flags: tuple[str, ...] = ()
    error_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "as_of_date": self.as_of_date,
            "date_valid": self.date_valid,
            "active_normative_count": len(self.active_normative_items),
            "active_interpretation_count": len(self.active_interpretation_items),
            "active_autonomous_count": len(self.active_autonomous_items),
            "validated_precedent_count": len(self.validated_precedent_items),
            "historical_context_count": len(self.historical_context_items),
            "rejected_retroactive_items": list(self.rejected_retroactive_items),
            "temporal_flags": list(self.temporal_flags),
            "error_code": self.error_code,
        }


@dataclass(frozen=True)
class AnswerReasoningResult:
    """Output of AnswerLegalReasoningEngine keeping Evidence, Precedents, Interpretations & Steps apart."""

    statutory_claims: tuple[AnswerClaimRecord, ...] = ()
    precedent_claims: tuple[AnswerClaimRecord, ...] = ()
    interpretation_claims: tuple[AnswerClaimRecord, ...] = ()
    operational_claims: tuple[AnswerClaimRecord, ...] = ()
    legal_bases: tuple[LegalBasisItem, ...] = ()
    historical_context: tuple[LegalBasisItem, ...] = ()
    precedent_assessments: tuple[dict[str, Any], ...] = ()
    norm_conflict_resolutions: tuple[dict[str, Any], ...] = ()
    exceptions_and_conditions: tuple[str, ...] = ()
    counter_arguments: tuple[str, ...] = ()
    required_documents: tuple[str, ...] = ()
    escalation_flags: tuple[str, ...] = ()
    has_conflicting_precedent_or_norm: bool = False
    matched_scenario_type: str | None = None
    payroll_handoff_summary: str | None = None

    def all_claims(self) -> tuple[AnswerClaimRecord, ...]:
        return (
            *self.statutory_claims,
            *self.precedent_claims,
            *self.interpretation_claims,
            *self.operational_claims,
        )


@dataclass(frozen=True)
class AnswerRiskAssessmentResult:
    """Output of AnswerRiskAssessor."""

    overall_risk_level: str
    decision_badge: str
    approval_level: str
    counsel_escalation_required: bool
    escalation_ticket_id: str | None
    escalation_reasons: tuple[str, ...]
    payroll_handoff_allowed: bool
    risks: tuple[EmployerEmployeeRiskItem, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_risk_level": self.overall_risk_level,
            "decision_badge": self.decision_badge,
            "approval_level": self.approval_level,
            "counsel_escalation_required": self.counsel_escalation_required,
            "escalation_ticket_id": self.escalation_ticket_id,
            "escalation_reasons": list(self.escalation_reasons),
            "payroll_handoff_allowed": self.payroll_handoff_allowed,
            "risks": [r.to_dict() for r in self.risks],
        }


@dataclass(frozen=True)
class AnswerAbstentionDecision:
    """Output of AnswerAbstentionHandler including deterministic confidence derivation."""

    should_abstain: bool
    status: str
    should_conclude: bool
    confidence_status: str
    confidence_reason_codes: tuple[str, ...]
    missing_information: tuple[MissingInfoItem, ...]
    clarification_questions: tuple[str, ...]
    disclosure_message: str | None
    human_approval: HumanApprovalRequirement


@dataclass(frozen=True)
class AnswerCitationAuditReport:
    """Output of dual-layer fail-closed AnswerCitationValidator."""

    passed: bool
    checked_claim_count: int
    matched_source_ids: tuple[str, ...]
    matched_precedent_ids: tuple[str, ...]
    blocker_codes: tuple[str, ...]
    blocker_messages: tuple[str, ...]
    warning_codes: tuple[str, ...]
    guardrail_flags: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "checked_claim_count": self.checked_claim_count,
            "matched_source_ids": list(self.matched_source_ids),
            "matched_precedent_ids": list(self.matched_precedent_ids),
            "blocker_codes": list(self.blocker_codes),
            "blocker_messages": list(self.blocker_messages),
            "warning_codes": list(self.warning_codes),
            "guardrail_flags": list(self.guardrail_flags),
        }


@dataclass(frozen=True)
class EightSectionAnswer:
    """Fixed 8-section standard response defined in WP4_1_AGENT_CORE_SPEC §7.1."""

    hukuki_sonuc: str
    mevzuat_dayanagi: str
    hukuki_degerlendirme: str
    uygulama: str
    risk: str
    istisnalar: str
    kaynaklar: str
    guven_durumu: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class ClaimEvidenceLink:
    """Per-claim lineage binding every answer claim to its exact chunk, source, and audit log."""

    claim_id: str
    section_name: str
    claim_category: str
    chunk_id: str | None
    provision_id: str | None
    source_id: str | None
    precedent_id: str | None
    rule_id: str | None
    audit_log_id: str
    content_sha256: str | None
    chunk_sha256: str | None
    evidence_id: str | None
    registry_head_sha256: str | None
    effective_on_date: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AnswerAuditTrace:
    """End-to-end cryptographic audit trail linking VerifiedAnswerPackage back to RetrievalTraceBundle."""

    source_trace_id: str
    source_bundle_sha256: str
    source_retrieved_at_utc: str
    claim_evidence_links: tuple[ClaimEvidenceLink, ...]
    unverified_or_excluded_refs: tuple[dict[str, Any], ...]
    citation_audit_passed: bool
    citation_audit_blocker_codes: tuple[str, ...]
    temporal_flags: tuple[str, ...]
    governance_gates: dict[str, bool]
    answer_sha256: str
    audit_trace_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_trace_id": self.source_trace_id,
            "source_bundle_sha256": self.source_bundle_sha256,
            "source_retrieved_at_utc": self.source_retrieved_at_utc,
            "claim_evidence_links": [lnk.to_dict() for lnk in self.claim_evidence_links],
            "unverified_or_excluded_refs": list(self.unverified_or_excluded_refs),
            "citation_audit_passed": self.citation_audit_passed,
            "citation_audit_blocker_codes": list(self.citation_audit_blocker_codes),
            "temporal_flags": list(self.temporal_flags),
            "governance_gates": dict(self.governance_gates),
            "answer_sha256": self.answer_sha256,
            "audit_trace_sha256": self.audit_trace_sha256,
        }


@dataclass(frozen=True)
class VerifiedAnswerPackage:
    """Complete verified, traceable WP-4.4 Answer Engine output."""

    answer_version: str
    answer_id: str
    generated_at_utc: str
    query_text: str
    as_of_date: str | None
    status: str
    published_answer_blocked: bool
    eight_sections: EightSectionAnswer
    claims: tuple[AnswerClaimRecord, ...]
    legal_bases: tuple[LegalBasisItem, ...]
    historical_context: tuple[LegalBasisItem, ...]
    precedent_assessments: tuple[dict[str, Any], ...]
    risks: tuple[EmployerEmployeeRiskItem, ...]
    missing_information: tuple[MissingInfoItem, ...]
    clarification_questions: tuple[str, ...]
    human_approval: HumanApprovalRequirement
    confidence_status: str
    confidence_display_label: str
    confidence_reason_codes: tuple[str, ...]
    citation_audit: AnswerCitationAuditReport
    temporal_report: TemporalValidationReport
    audit_trace: AnswerAuditTrace
    governance_gates: dict[str, bool]
    answer_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "answer_version": self.answer_version,
            "answer_id": self.answer_id,
            "generated_at_utc": self.generated_at_utc,
            "query_text": self.query_text,
            "as_of_date": self.as_of_date,
            "status": self.status,
            "published_answer_blocked": self.published_answer_blocked,
            "eight_sections": self.eight_sections.to_dict(),
            "claims": [c.to_dict() for c in self.claims],
            "legal_bases": [b.to_dict() for b in self.legal_bases],
            "historical_context": [h.to_dict() for h in self.historical_context],
            "precedent_assessments": list(self.precedent_assessments),
            "risks": [r.to_dict() for r in self.risks],
            "missing_information": [m.to_dict() for m in self.missing_information],
            "clarification_questions": list(self.clarification_questions),
            "human_approval": self.human_approval.to_dict(),
            "confidence_status": self.confidence_status,
            "confidence_display_label": self.confidence_display_label,
            "confidence_reason_codes": list(self.confidence_reason_codes),
            "citation_audit": self.citation_audit.to_dict(),
            "temporal_report": self.temporal_report.to_dict(),
            "audit_trace": self.audit_trace.to_dict(),
            "governance_gates": dict(self.governance_gates),
            "answer_sha256": self.answer_sha256,
        }


def compute_canonical_answer_sha256(
    *,
    query_text: str,
    as_of_date: str | None,
    status: str,
    published_answer_blocked: bool,
    eight_sections: EightSectionAnswer,
    claims: tuple[AnswerClaimRecord, ...],
    legal_bases: tuple[LegalBasisItem, ...],
    historical_context: tuple[LegalBasisItem, ...],
    risks: tuple[EmployerEmployeeRiskItem, ...],
    human_approval: HumanApprovalRequirement,
    confidence_status: str,
    citation_audit: AnswerCitationAuditReport,
    source_trace_id: str,
    source_bundle_sha256: str,
) -> str:
    """Compute wall-clock-independent canonical SHA-256 over semantic answer & evidence linkage."""
    payload = {
        "answer_version": ANSWER_VERSION,
        "query_text": query_text,
        "as_of_date": as_of_date,
        "status": status,
        "published_answer_blocked": published_answer_blocked,
        "eight_sections": eight_sections.to_dict(),
        "claims": [c.to_dict() for c in claims],
        "legal_bases": [b.to_dict() for b in legal_bases],
        "historical_context": [h.to_dict() for h in historical_context],
        "risks": [r.to_dict() for r in risks],
        "human_approval": human_approval.to_dict(),
        "confidence_status": confidence_status,
        "citation_audit": citation_audit.to_dict(),
        "source_trace_id": source_trace_id,
        "source_bundle_sha256": source_bundle_sha256,
        "governance_gates": CLOSED_GOVERNANCE_GATES,
    }
    return canonical_kb_sha256(payload)
