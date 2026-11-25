"""Core domain models and constants for CALISORA @HukukSGK verification & legal reasoning engine (v1.0.2c)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# Pure normative legislation & autonomous contract hierarchy (Anayasa m.11, m.90/5, m.104, m.124).
# NOTE: Yargıtay precedents are NOT a legislative norm layer; they are evaluated under 2797 s. Kanun m.45
# via JUDICIAL_INTERPRETATION_LAYERS and evaluate_precedent_application().
NORM_LAYER_PRIORITY: dict[str, int] = {
    "CONSTITUTION": 1,                            # Anayasa (Anayasa m.11 — en üst norm)
    "INTERNATIONAL_TREATY_FUNDAMENTAL_RIGHTS": 2, # Anayasa m.90/5 son cümle (Temel hak/özgürlük antlaşmaları; Anayasa altında, kanunla çatışmada esas alınır)
    "STATUTORY_LAW": 3,                           # Kanun
    "INTERNATIONAL_TREATY_GENERAL": 3,            # Anayasa m.90/5 cümle 1 (Genel uluslararası/ILO antlaşmaları — kanun hükmündedir)
    "PRESIDENTIAL_DECREE": 4,                     # Cumhurbaşkanlığı Kararnamesi (CBK — Anayasa m.104/17)
    "PRESIDENTIAL_DECISION": 5,                   # Cumhurbaşkanı Kararı (CK — kanuni yetkiye dayalı idari karar)
    "REGULATION": 6,                              # Yönetmelik (Anayasa m.124)
    "COMMUNIQUE_AND_SGK_CIRCULAR": 7,             # Tebliğ ve SGK Genelgesi
    "CBA_CONTRACT_AND_HR_PROCEDURE": 8,           # TİS / İş Sözleşmesi / İşyeri Uygulaması / İK Prosedürü
}

JUDICIAL_INTERPRETATION_LAYERS: set[str] = {
    "YARGITAY_PRECEDENT",
}

ALL_CONFLICT_EVALUATION_LAYERS: set[str] = set(NORM_LAYER_PRIORITY.keys()) | JUDICIAL_INTERPRETATION_LAYERS

VALID_SOURCE_TYPES: set[str] = {
    "CONSTITUTION",
    "INTERNATIONAL_TREATY_FUNDAMENTAL_RIGHTS",
    "INTERNATIONAL_TREATY_GENERAL",
    "OFFICIAL_GAZETTE_LAW",
    "PRESIDENTIAL_DECREE",
    "PRESIDENTIAL_DECISION",
    "REGULATION",
    "GIB_COMMUNIQUE",
    "SGK_CIRCULAR",
    "HR_PROCEDURE",
}

VALID_SOURCE_STATUSES: set[str] = {
    "VERIFIED",
    "SUPERSEDED",
    "REPEALED",
    "PENDING_REVIEW",
    "UNVERIFIED",
}

VALID_PRECEDENT_CHAMBERS: set[str] = {
    "YIBBGK",
    "HGK",
    "9_HD",
    "22_HD_HISTORICAL",
    "10_HD",
    "21_HD_HISTORICAL",
    "AYM",
}

VALID_PRECEDENT_STATUSES: set[str] = {
    "VERIFIED",
    "PENDING_REVIEW",
    "SUPERSEDED",
    "CONFLICTING",
    "UNVERIFIED",
}

PRECEDENT_BINDING_RANK: dict[str, int] = {
    "STATUTORY_BINDING_YIBBGK": 1,
    "HGK_PERSUASIVE": 2,
    "CHAMBER_SETTLED": 3,
    "CHAMBER_ISOLATED": 4,
    "NONE": 99,
}

VALID_MANDATORY_TYPES: set[str] = {
    "RELATIVE_EMPLOYEE_FAVORABLE",
    "ABSOLUTE_MANDATORY",
    "DISPOSITIVE",
}

VALID_TREATY_PROVISION_NATURES: set[str] = {
    "UNSPECIFIED",
    "MINIMUM_STANDARD_FLOOR",
    "DIRECT_SUBSTANTIVE_RULE",
}

VALID_SCENARIO_TYPES: set[str] = {
    "TERMINATION_VALIDITY",
    "REINSTATEMENT_CLAIM",
    "SEVERANCE_AND_NOTICE",
    "OVERTIME_COMPLIANCE",
    "ANNUAL_LEAVE_COMPLIANCE",
    "SGK_EXIT_CODE_AND_UNEMPLOYMENT",
    "EMPLOYEE_FAVORABLE_NORM_COMPARISON",
}

VALID_DECISION_BADGES: set[str] = {
    "UYGUN_ON_DEGERLENDIRME",
    "USUL_EKSIGI_DUZELTME_GEREKLI",
    "EKSIK_BILGI_TAMAMLANMALI",
    "YUKSEK_RISK_AVUKAT_ESKALASYONU",
}

VALID_RISK_LEVELS: set[str] = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

VALID_APPROVAL_LEVELS: set[str] = {
    "HR_OPERATIONS_VERIFICATION",
    "SENIOR_HR_AND_LEGAL_REVIEW",
    "MANDATORY_LEGAL_COUNSEL_APPROVAL",
}

VALID_DISCOVERING_AUTHORITY_STATUSES: set[str] = {
    "AUTHORIZED_DISMISSAL_BODY",
    "NON_AUTHORIZED_SUPERVISOR_ONLY",
    "UNCERTAIN",
    "UNKNOWN",
}

VALID_VERIFIER_ROLES: set[str] = {
    "SENIOR_LABOR_LAW_REVIEWER",
    "SGK_COMPLIANCE_SPECIALIST",
    "EXTERNAL_LEGAL_COUNSEL",
    "LEGAL_OPS_AUDITOR",
}

VALID_VERIFICATION_METHODS: set[str] = {
    "LIVE_HTTP_FETCH_AND_LEGAL_REVIEW",
    "OFFICIAL_GAZETTE_ARCHIVE_CHECK",
    "MEVZUAT_GOV_TR_CONSOLIDATED_CHECK",
    "MANUAL_LEGAL_SIGN_OFF",
    "UNVERIFIED_METADATA_ONLY",
}

VALID_DOCUMENT_FETCH_STATUSES: set[str] = {
    "FETCHED_AND_MATCHED",
    "METADATA_VERIFIED_PENDING_LIVE_FETCH",
    "FAILED",
    "NOT_CHECKED",
}


@dataclass(frozen=True)
class VerificationAudit:
    verifier_id: str
    verifier_role: str
    verification_method: str
    audit_log_id: str
    verified_at: str
    document_fetch_status: str = "NOT_CHECKED"
    retrieved_http_status: int | None = None
    retrieved_content_sha256: str | None = None
    expected_text_markers: tuple[str, ...] = field(default_factory=tuple)
    matched_text_markers: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["expected_text_markers"] = list(self.expected_text_markers)
        data["matched_text_markers"] = list(self.matched_text_markers)
        return data


@dataclass(frozen=True)
class AmendmentRecord:
    amending_law_no: str
    official_gazette_no: str
    publication_date: str
    affected_articles: tuple[str, ...]
    effective_from: str
    summary: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["affected_articles"] = list(self.affected_articles)
        return data


@dataclass(frozen=True)
class ArticleEffectiveRule:
    article_ref: str
    effective_from: str
    effective_to: str
    basis: str
    amended_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LegalSourceRecord:
    source_id: str
    source_title: str
    source_url: str
    source_type: str
    norm_layer: str
    norm_priority: int
    legal_reference: str
    statute_number: str
    official_gazette_no: str
    publication_date: str
    effective_from: str
    effective_to: str
    last_verified_at: str
    verified_by: str
    verification_status: str
    supersedes: str
    superseded_by: str | None = None
    secondary_official_url: str | None = None
    url_granularity: str = "DIRECT_DOCUMENT"
    keywords: tuple[str, ...] = field(default_factory=tuple)
    content_sha256: str | None = None
    verification_audit: VerificationAudit | None = None
    original_publication: dict[str, Any] | None = None
    consolidated_text: dict[str, Any] | None = None
    amendment_history: tuple[AmendmentRecord, ...] = field(default_factory=tuple)
    article_effective_rules: tuple[ArticleEffectiveRule, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["keywords"] = list(self.keywords)
        data["amendment_history"] = [a.to_dict() for a in self.amendment_history]
        data["article_effective_rules"] = [r.to_dict() for r in self.article_effective_rules]
        if self.verification_audit is not None:
            data["verification_audit"] = self.verification_audit.to_dict()
        return data


@dataclass(frozen=True)
class PrecedentRecord:
    precedent_id: str
    chamber: str
    binding_level: str
    esas_no: str
    karar_no: str
    decision_date: str
    official_source_url: str
    related_source_ids: tuple[str, ...]
    legal_principle: str
    scope_limitations: str
    verification_status: str
    verified_by: str
    last_verified_at: str
    official_gazette_no: str | None = None
    official_gazette_date: str | None = None
    url_granularity: str = "DIRECT_DOCUMENT"
    superseded_by: str | None = None
    conflicting_precedent_ids: tuple[str, ...] = field(default_factory=tuple)
    keywords: tuple[str, ...] = field(default_factory=tuple)
    full_text_verification: dict[str, Any] | None = None
    operative_holding: dict[str, Any] | None = None
    scope_limitations_detail: dict[str, Any] | None = None
    verification_audit: VerificationAudit | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["related_source_ids"] = list(self.related_source_ids)
        data["conflicting_precedent_ids"] = list(self.conflicting_precedent_ids)
        data["keywords"] = list(self.keywords)
        if self.verification_audit is not None:
            data["verification_audit"] = self.verification_audit.to_dict()
        return data


@dataclass(frozen=True)
class LegalKnowledgeCard:
    card_id: str
    source_id: str
    law_no: str
    law_title: str
    article_ref: str
    topic: str
    legal_basis: dict[str, Any]
    scope_of_application: str
    exceptions: tuple[str, ...]
    required_documents: tuple[str, ...]
    related_precedent_ids: tuple[str, ...]
    precedent_note: str
    effective_validity: dict[str, Any]
    norm_character: str
    risks: tuple[str, ...]
    primary_specialist: str
    collaborating_specialists: tuple[str, ...]
    disclaimer: str
    verification_status: str
    source_verification: dict[str, Any]
    legal_interpretation_verification: dict[str, Any]
    verification_audit: dict[str, Any]
    application_scenarios: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    data_category_controls: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    special_calculation_rules: dict[str, Any] = field(default_factory=dict)
    statutory_subordination: dict[str, Any] | None = None
    keywords: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["exceptions"] = list(self.exceptions)
        data["required_documents"] = list(self.required_documents)
        data["related_precedent_ids"] = list(self.related_precedent_ids)
        data["risks"] = list(self.risks)
        data["collaborating_specialists"] = list(self.collaborating_specialists)
        data["application_scenarios"] = list(self.application_scenarios)
        data["data_category_controls"] = list(self.data_category_controls)
        data["keywords"] = list(self.keywords)
        return data


@dataclass(frozen=True)
class DocumentFetchResult:
    url: str
    resolved_document_url: str
    ok: bool
    http_status: int | None
    content_type: str
    content_length: int
    content_sha256: str | None
    expected_markers: tuple[str, ...]
    matched_markers: tuple[str, ...]
    missing_markers: tuple[str, ...]
    checked_at_utc: str
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["expected_markers"] = list(self.expected_markers)
        data["matched_markers"] = list(self.matched_markers)
        data["missing_markers"] = list(self.missing_markers)
        return data


@dataclass(frozen=True)
class VerificationFlag:
    code: str
    severity: str  # "BLOCKER" | "WARNING"
    message: str
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RegistryValidationReport:
    registry_name: str
    valid: bool
    total_records: int
    verified_count: int
    flags: list[VerificationFlag] = field(default_factory=list)

    @property
    def blocker_count(self) -> int:
        return sum(1 for f in self.flags if f.severity == "BLOCKER")

    def to_dict(self) -> dict[str, Any]:
        return {
            "registry_name": self.registry_name,
            "valid": self.valid,
            "total_records": self.total_records,
            "verified_count": self.verified_count,
            "blocker_count": self.blocker_count,
            "flags": [f.to_dict() for f in self.flags],
        }


@dataclass
class CitationAuditResult:
    passed: bool
    as_of_date: str
    requires_counsel_escalation: bool
    matched_source_ids: list[str] = field(default_factory=list)
    matched_precedent_ids: list[str] = field(default_factory=list)
    flags: list[VerificationFlag] = field(default_factory=list)

    @property
    def blocker_codes(self) -> list[str]:
        return [f.code for f in self.flags if f.severity == "BLOCKER"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "as_of_date": self.as_of_date,
            "requires_counsel_escalation": self.requires_counsel_escalation,
            "matched_source_ids": self.matched_source_ids,
            "matched_precedent_ids": self.matched_precedent_ids,
            "blocker_codes": self.blocker_codes,
            "flags": [f.to_dict() for f in self.flags],
        }


@dataclass(frozen=True)
class NormReference:
    title: str
    norm_layer: str
    precedent_level: str = "NONE"
    source_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class NormConflictResolution:
    winning_side: str  # "NORM_A" | "NORM_B" | "UNRESOLVED_ESCALATE"
    winning_norm: NormReference | None
    losing_norm: NormReference | None
    rule_applied: str
    mandatory_type: str
    requires_counsel_escalation: bool
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "winning_side": self.winning_side,
            "winning_norm": self.winning_norm.to_dict() if self.winning_norm else None,
            "losing_norm": self.losing_norm.to_dict() if self.losing_norm else None,
            "rule_applied": self.rule_applied,
            "mandatory_type": self.mandatory_type,
            "requires_counsel_escalation": self.requires_counsel_escalation,
            "explanation": self.explanation,
        }


@dataclass(frozen=True)
class PrecedentApplicationAssessment:
    precedent_id: str
    interpreted_source_id: str
    as_of_date: str
    precedent_applicable_to_statute: bool
    effective_outcome: str  # "UNDERLYING_STATUTE_WITH_PRECEDENT_PREVAILS" | "COMPETING_NORM_PREVAILS" | "PRECEDENT_NOT_APPLICABLE" | "ESCALATE_TO_LEGAL_COUNSEL"
    binding_nature: str     # "BINDING_JUDICIAL_UNIFICATION_2797_M45" | "PERSUASIVE_JUDICIAL_INTERPRETATION" | "UNVERIFIED_OR_BLOCKED"
    binding_basis: str
    scope_match_status: str
    application_rationale: str = ""
    rationale_requirement_status: str = ""
    post_decision_amendments: tuple[str, ...] = field(default_factory=tuple)
    underlying_norm_resolution: NormConflictResolution | None = None
    requires_counsel_escalation: bool = False
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "precedent_id": self.precedent_id,
            "interpreted_source_id": self.interpreted_source_id,
            "as_of_date": self.as_of_date,
            "precedent_applicable_to_statute": self.precedent_applicable_to_statute,
            "effective_outcome": self.effective_outcome,
            "binding_nature": self.binding_nature,
            "binding_basis": self.binding_basis,
            "scope_match_status": self.scope_match_status,
            "application_rationale": self.application_rationale,
            "rationale_requirement_status": self.rationale_requirement_status,
            "post_decision_amendments": list(self.post_decision_amendments),
            "underlying_norm_resolution": (
                self.underlying_norm_resolution.to_dict() if self.underlying_norm_resolution else None
            ),
            "requires_counsel_escalation": self.requires_counsel_escalation,
            "explanation": self.explanation,
        }


@dataclass(frozen=True)
class LegalBasisItem:
    source_id: str
    legal_reference: str
    verification_status: str
    effective_on_date: bool
    note: str
    card_id: str | None = None
    precedent_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RiskItem:
    risk_level: str  # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    category: str
    description: str
    legal_consequence: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MissingInfoItem:
    field: str
    reason: str
    required_document: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HumanApprovalRequirement:
    required: bool
    approval_level: str  # "HR_OPERATIONS_VERIFICATION" | "SENIOR_HR_AND_LEGAL_REVIEW" | "MANDATORY_LEGAL_COUNSEL_APPROVAL"
    counsel_escalation_required: bool
    payroll_handoff_allowed: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)
    external_counsel_signoff_status: str = "PENDING_SIGNED_EXTERNAL_ATTESTATION"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["reasons"] = list(self.reasons)
        return data


@dataclass(frozen=True)
class LegalScenarioEvaluation:
    scenario_type: str
    as_of_date: str
    decision_badge: str
    assessment_summary: str
    legal_bases: tuple[LegalBasisItem, ...]
    counter_arguments: tuple[str, ...]
    risks: tuple[RiskItem, ...]
    missing_information: tuple[MissingInfoItem, ...]
    human_approval: HumanApprovalRequirement
    recommended_actions: tuple[str, ...]
    disclaimer: str
    historical_context: tuple[LegalBasisItem, ...] = field(default_factory=tuple)
    structured_findings: dict[str, Any] = field(default_factory=dict)
    norm_conflict_resolution: NormConflictResolution | None = None
    precedent_application_assessment: PrecedentApplicationAssessment | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_type": self.scenario_type,
            "as_of_date": self.as_of_date,
            "decision_badge": self.decision_badge,
            "assessment_summary": self.assessment_summary,
            "legal_bases": [b.to_dict() for b in self.legal_bases],
            "historical_context": [h.to_dict() for h in self.historical_context],
            "counter_arguments": list(self.counter_arguments),
            "risks": [r.to_dict() for r in self.risks],
            "missing_information": [m.to_dict() for m in self.missing_information],
            "human_approval": self.human_approval.to_dict(),
            "recommended_actions": list(self.recommended_actions),
            "structured_findings": dict(self.structured_findings),
            "norm_conflict_resolution": (
                self.norm_conflict_resolution.to_dict() if self.norm_conflict_resolution else None
            ),
            "precedent_application_assessment": (
                self.precedent_application_assessment.to_dict() if self.precedent_application_assessment else None
            ),
            "disclaimer": self.disclaimer,
        }


