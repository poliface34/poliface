"""Core domain contracts, trace bundles, and citation whitelist models for WP-4.3 RAG Engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ..knowledge_base.models import (
    ExcludedUnverifiedNotice,
    InterpretationAndBoundaryRule,
    LegalSearchChunk,
    canonical_kb_sha256,
)

RAG_VERSION = "1.0.6-wp4.3"

# Stage 1: Query Intent Taxonomy (WP4_3_RAG_ENGINE_SPEC §3.1)
INTENT_FACT_SCENARIO_ANALYSIS = "FACT_SCENARIO_ANALYSIS"
INTENT_STATUTE_LOOKUP = "STATUTE_LOOKUP"
INTENT_PROCEDURE_AND_AUTONOMOUS_NORM = "PROCEDURE_AND_AUTONOMOUS_NORM"
INTENT_PRECEDENT_CHECK = "PRECEDENT_CHECK"
INTENT_PAYROLL_DELEGATION_ONLY = "PAYROLL_DELEGATION_ONLY"
INTENT_OUT_OF_DOMAIN = "OUT_OF_DOMAIN"

VALID_QUERY_INTENTS: frozenset[str] = frozenset(
    {
        INTENT_FACT_SCENARIO_ANALYSIS,
        INTENT_STATUTE_LOOKUP,
        INTENT_PROCEDURE_AND_AUTONOMOUS_NORM,
        INTENT_PRECEDENT_CHECK,
        INTENT_PAYROLL_DELEGATION_ONLY,
        INTENT_OUT_OF_DOMAIN,
    }
)

# Legal Domain Taxonomy (aligned with WP4_1_AGENT_CORE_SPEC §4.1 & WP4_3 §3.2)
DOMAIN_LABOR_LAW = "LABOR_LAW"
DOMAIN_SOCIAL_SECURITY = "SOCIAL_SECURITY"
DOMAIN_OCCUPATIONAL_HEALTH_AND_SAFETY = "OCCUPATIONAL_HEALTH_AND_SAFETY"
DOMAIN_PERSONAL_DATA_PROTECTION = "PERSONAL_DATA_PROTECTION"
DOMAIN_MIXED_MULTI_DOMAIN = "MIXED_MULTI_DOMAIN"
DOMAIN_PAYROLL_DELEGATION_ONLY = "PAYROLL_DELEGATION_ONLY"
DOMAIN_OUT_OF_DOMAIN = "OUT_OF_DOMAIN"

VALID_LEGAL_DOMAINS: frozenset[str] = frozenset(
    {
        DOMAIN_LABOR_LAW,
        DOMAIN_SOCIAL_SECURITY,
        DOMAIN_OCCUPATIONAL_HEALTH_AND_SAFETY,
        DOMAIN_PERSONAL_DATA_PROTECTION,
        DOMAIN_MIXED_MULTI_DOMAIN,
        DOMAIN_PAYROLL_DELEGATION_ONLY,
        DOMAIN_OUT_OF_DOMAIN,
    }
)

# Stage 3/4: Isolated Buckets
BUCKET_NORMATIVE = "NORMATIVE"
BUCKET_INTERPRETATION_BOUNDARY = "INTERPRETATION_BOUNDARY"
BUCKET_PRECEDENT = "PRECEDENT"
BUCKET_AUTONOMOUS_NORM = "AUTONOMOUS_NORM"
BUCKET_HISTORICAL_CONTEXT = "HISTORICAL_CONTEXT"

# Stage 5: Evidence Binding Statuses (WP4_3 §7)
BINDING_TRUST_CHAIN_EVIDENCE_BOUND = "TRUST_CHAIN_EVIDENCE_BOUND"
BINDING_REGISTRY_AUDIT_BACKED_NO_TRUST_CHAIN = "REGISTRY_AUDIT_BACKED_NO_TRUST_CHAIN"
BINDING_TRUST_CHAIN_INTEGRITY_MISMATCH = "TRUST_CHAIN_INTEGRITY_MISMATCH"

# Stage 6: RagGateStatus Values (WP4_3 §8)
GATE_EVIDENCE_READY = "EVIDENCE_READY"
GATE_EVIDENCE_READY_WITH_ESCALATION = "EVIDENCE_READY_WITH_ESCALATION"
GATE_ABSTAIN_MISSING_INFO = "ABSTAIN_MISSING_INFO"
GATE_ABSTAIN_INSUFFICIENT_EVIDENCE = "ABSTAIN_INSUFFICIENT_EVIDENCE"
GATE_ABSTAIN_OUT_OF_DOMAIN = "ABSTAIN_OUT_OF_DOMAIN"

VALID_RAG_GATE_STATUSES: frozenset[str] = frozenset(
    {
        GATE_EVIDENCE_READY,
        GATE_EVIDENCE_READY_WITH_ESCALATION,
        GATE_ABSTAIN_MISSING_INFO,
        GATE_ABSTAIN_INSUFFICIENT_EVIDENCE,
        GATE_ABSTAIN_OUT_OF_DOMAIN,
    }
)


@dataclass(frozen=True)
class RagQueryRequest:
    """Typed retrieval request entering WP-4.3 RAG Engine."""

    query_text: str
    as_of_date: str | None = None
    facts: dict[str, Any] = field(default_factory=dict)
    include_historical: bool = False
    top_k: int = 5
    require_adopted_autonomous_norms: bool = True
    court_systems: tuple[str, ...] | None = None


@dataclass(frozen=True)
class SubQuerySpec:
    """Domain-specific sub-query spawned when handling MIXED_MULTI_DOMAIN or companion lookups."""

    domain: str
    query_text: str
    law_nos: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "query_text": self.query_text,
            "law_nos": list(self.law_nos),
        }


@dataclass(frozen=True)
class QueryIntentAnalysis:
    """Stage 1 deterministic output: intent, legal domain routing, entities, and controlled aliases."""

    intent: str
    primary_domain: str
    secondary_domains: tuple[str, ...] = ()
    extracted_entities: dict[str, Any] = field(default_factory=dict)
    sub_queries: tuple[SubQuerySpec, ...] = ()
    rewritten_query_text: str = ""

    def __post_init__(self) -> None:
        if self.intent not in VALID_QUERY_INTENTS:
            raise ValueError(f"Geçersiz QueryIntent: {self.intent!r}")
        if self.primary_domain not in VALID_LEGAL_DOMAINS:
            raise ValueError(f"Geçersiz primary_domain: {self.primary_domain!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent": self.intent,
            "primary_domain": self.primary_domain,
            "secondary_domains": list(self.secondary_domains),
            "extracted_entities": dict(self.extracted_entities),
            "sub_queries": [sq.to_dict() for sq in self.sub_queries],
            "rewritten_query_text": self.rewritten_query_text,
        }


@dataclass(frozen=True)
class TemporalAuditReport:
    """Stage 2 temporal gate & cutoff verification audit block."""

    as_of_date: str | None
    date_source: str  # EXPLICIT_PARAMETER | EXTRACTED_FROM_QUERY | MISSING | AMBIGUOUS_MULTIPLE_DATES | INVALID
    date_valid: bool
    candidate_dates_found: tuple[str, ...] = ()
    cutoff_flags: tuple[str, ...] = ()
    historical_versions_filtered_count: int = 0
    error_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "as_of_date": self.as_of_date,
            "date_source": self.date_source,
            "date_valid": self.date_valid,
            "candidate_dates_found": list(self.candidate_dates_found),
            "cutoff_flags": list(self.cutoff_flags),
            "historical_versions_filtered_count": self.historical_versions_filtered_count,
            "error_code": self.error_code,
        }


@dataclass(frozen=True)
class RankedEvidenceItem:
    """Single ranked evidence item isolated into its typed legal bucket."""

    bucket: str
    rank: int
    rerank_score: float
    base_rrf_score: float
    vector_score: float
    lexical_score: float
    clause_match_score: float
    hierarchy_score: float
    lex_specialis_bonus: float
    precedent_binding_weight: float
    anchor_overlap_score: float
    post_amendment_penalty: float
    origin: str  # PRIMARY_SEARCH | CROSS_REF_EXPANSION | COMPANION_RULE_EXTRACT
    source_url: str
    audit_log_id: str
    evidence_binding_status: str
    chunk: LegalSearchChunk
    companion_rules: tuple[InterpretationAndBoundaryRule, ...] = ()
    precedent_metadata: dict[str, Any] = field(default_factory=dict)
    flags: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "bucket": self.bucket,
            "rank": self.rank,
            "rerank_score": round(self.rerank_score, 6),
            "base_rrf_score": round(self.base_rrf_score, 6),
            "vector_score": round(self.vector_score, 6),
            "lexical_score": round(self.lexical_score, 6),
            "clause_match_score": round(self.clause_match_score, 6),
            "hierarchy_score": round(self.hierarchy_score, 6),
            "lex_specialis_bonus": round(self.lex_specialis_bonus, 6),
            "precedent_binding_weight": round(self.precedent_binding_weight, 6),
            "anchor_overlap_score": round(self.anchor_overlap_score, 6),
            "post_amendment_penalty": round(self.post_amendment_penalty, 6),
            "origin": self.origin,
            "source_url": self.source_url,
            "audit_log_id": self.audit_log_id,
            "evidence_binding_status": self.evidence_binding_status,
            "chunk": self.chunk.to_dict(),
            "companion_rules": [r.to_dict() for r in self.companion_rules],
            "precedent_metadata": dict(self.precedent_metadata),
            "flags": list(self.flags),
        }


@dataclass(frozen=True)
class EvidenceBindingRecord:
    """Stage 5 cryptographic Trust Chain or registry audit log linkage record."""

    chunk_id: str
    provision_id: str
    source_id: str
    document_kind: str
    bucket: str
    evidence_binding_status: str
    evidence_id: str | None
    record_sha256: str | None
    registry_head_sha256: str | None
    content_sha256: str
    chunk_sha256: str
    audit_log_id: str
    source_url: str
    transport_mode: str
    live_verified: bool
    raw_content_verified: bool
    failure_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CitationWhitelist:
    """Strict allowlist passed to WP-4.4 Answer Engine; non-listed citations MUST fail closed."""

    allowed_provision_ids: tuple[str, ...] = ()
    allowed_source_ids: tuple[str, ...] = ()
    allowed_precedent_ids: tuple[str, ...] = ()
    allowed_rule_ids: tuple[str, ...] = ()
    allowed_source_urls: tuple[str, ...] = ()
    allowed_evidence_ids: tuple[str, ...] = ()
    allowed_audit_log_ids: tuple[str, ...] = ()
    historical_only_source_ids: tuple[str, ...] = ()

    def contains_source(self, source_id: str) -> bool:
        return source_id in self.allowed_source_ids

    def contains_precedent(self, precedent_id: str) -> bool:
        return precedent_id in self.allowed_precedent_ids

    def contains_url(self, url: str) -> bool:
        return url in self.allowed_source_urls

    def contains_provision(self, provision_id: str) -> bool:
        return provision_id in self.allowed_provision_ids

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_provision_ids": list(self.allowed_provision_ids),
            "allowed_source_ids": list(self.allowed_source_ids),
            "allowed_precedent_ids": list(self.allowed_precedent_ids),
            "allowed_rule_ids": list(self.allowed_rule_ids),
            "allowed_source_urls": list(self.allowed_source_urls),
            "allowed_evidence_ids": list(self.allowed_evidence_ids),
            "allowed_audit_log_ids": list(self.allowed_audit_log_ids),
            "historical_only_source_ids": list(self.historical_only_source_ids),
        }


@dataclass(frozen=True)
class RetrievalTraceBundle:
    """Complete auditable output of WP-4.3 RAG Engine (WP4_3_RAG_ENGINE_SPEC §9)."""

    trace_id: str
    retrieved_at_utc: str
    query_text: str
    intent_classification: QueryIntentAnalysis
    as_of_date: str | None
    temporal_audit: TemporalAuditReport
    rag_gate_status: str
    should_conclude: bool
    counsel_escalation_required: bool
    escalation_reasons: tuple[str, ...]
    payroll_handoff_allowed: bool
    missing_facts: tuple[str, ...]
    clarification_questions: tuple[str, ...]
    normative_bucket: tuple[RankedEvidenceItem, ...]
    interpretation_bucket: tuple[RankedEvidenceItem, ...]
    precedent_bucket: tuple[RankedEvidenceItem, ...]
    autonomous_norm_bucket: tuple[RankedEvidenceItem, ...]
    historical_context_bucket: tuple[RankedEvidenceItem, ...]
    excluded_unverified_notices: tuple[ExcludedUnverifiedNotice, ...]
    evidence_bindings: tuple[EvidenceBindingRecord, ...]
    quarantined_evidence_mismatches: tuple[EvidenceBindingRecord, ...]
    unverified_disclosure_message: str | None
    out_of_domain_message: str | None
    citation_whitelist: CitationWhitelist
    pipeline_audit_trail: tuple[str, ...]
    bundle_sha256: str

    def active_evidence_count(self) -> int:
        return (
            len(self.normative_bucket)
            + len(self.interpretation_bucket)
            + len(self.precedent_bucket)
            + len(self.autonomous_norm_bucket)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "rag_version": RAG_VERSION,
            "trace_id": self.trace_id,
            "retrieved_at_utc": self.retrieved_at_utc,
            "query_text": self.query_text,
            "intent_classification": self.intent_classification.to_dict(),
            "as_of_date": self.as_of_date,
            "temporal_audit": self.temporal_audit.to_dict(),
            "rag_gate_status": self.rag_gate_status,
            "should_conclude": self.should_conclude,
            "counsel_escalation_required": self.counsel_escalation_required,
            "escalation_reasons": list(self.escalation_reasons),
            "payroll_handoff_allowed": self.payroll_handoff_allowed,
            "missing_facts": list(self.missing_facts),
            "clarification_questions": list(self.clarification_questions),
            "normative_bucket": [item.to_dict() for item in self.normative_bucket],
            "interpretation_bucket": [item.to_dict() for item in self.interpretation_bucket],
            "precedent_bucket": [item.to_dict() for item in self.precedent_bucket],
            "autonomous_norm_bucket": [item.to_dict() for item in self.autonomous_norm_bucket],
            "historical_context_bucket": [item.to_dict() for item in self.historical_context_bucket],
            "excluded_unverified_notices": [n.to_dict() for n in self.excluded_unverified_notices],
            "evidence_bindings": [b.to_dict() for b in self.evidence_bindings],
            "quarantined_evidence_mismatches": [q.to_dict() for q in self.quarantined_evidence_mismatches],
            "unverified_disclosure_message": self.unverified_disclosure_message,
            "out_of_domain_message": self.out_of_domain_message,
            "citation_whitelist": self.citation_whitelist.to_dict(),
            "pipeline_audit_trail": list(self.pipeline_audit_trail),
            "bundle_sha256": self.bundle_sha256,
        }


def compute_deterministic_trace_hashes(
    *,
    query_text: str,
    as_of_date: str | None,
    intent_classification: QueryIntentAnalysis,
    temporal_audit: TemporalAuditReport,
    rag_gate_status: str,
    should_conclude: bool,
    counsel_escalation_required: bool,
    escalation_reasons: tuple[str, ...],
    payroll_handoff_allowed: bool,
    missing_facts: tuple[str, ...],
    clarification_questions: tuple[str, ...],
    normative_bucket: tuple[RankedEvidenceItem, ...],
    interpretation_bucket: tuple[RankedEvidenceItem, ...],
    precedent_bucket: tuple[RankedEvidenceItem, ...],
    autonomous_norm_bucket: tuple[RankedEvidenceItem, ...],
    historical_context_bucket: tuple[RankedEvidenceItem, ...],
    excluded_unverified_notices: tuple[ExcludedUnverifiedNotice, ...],
    evidence_bindings: tuple[EvidenceBindingRecord, ...],
    quarantined_evidence_mismatches: tuple[EvidenceBindingRecord, ...],
    citation_whitelist: CitationWhitelist,
    pipeline_audit_trail: tuple[str, ...],
) -> tuple[str, str]:
    """Compute canonical, wall-clock-independent `(trace_id, bundle_sha256)` over retrieval semantics."""
    canonical_payload = {
        "rag_version": RAG_VERSION,
        "query_text": query_text,
        "as_of_date": as_of_date,
        "intent_classification": intent_classification.to_dict(),
        "temporal_audit": temporal_audit.to_dict(),
        "rag_gate_status": rag_gate_status,
        "should_conclude": should_conclude,
        "counsel_escalation_required": counsel_escalation_required,
        "escalation_reasons": list(escalation_reasons),
        "payroll_handoff_allowed": payroll_handoff_allowed,
        "missing_facts": list(missing_facts),
        "clarification_questions": list(clarification_questions),
        "normative_bucket": [item.to_dict() for item in normative_bucket],
        "interpretation_bucket": [item.to_dict() for item in interpretation_bucket],
        "precedent_bucket": [item.to_dict() for item in precedent_bucket],
        "autonomous_norm_bucket": [item.to_dict() for item in autonomous_norm_bucket],
        "historical_context_bucket": [item.to_dict() for item in historical_context_bucket],
        "excluded_unverified_notices": [n.to_dict() for n in excluded_unverified_notices],
        "evidence_bindings": [b.to_dict() for b in evidence_bindings],
        "quarantined_evidence_mismatches": [q.to_dict() for q in quarantined_evidence_mismatches],
        "citation_whitelist": citation_whitelist.to_dict(),
        "pipeline_audit_trail": list(pipeline_audit_trail),
    }
    bundle_sha = canonical_kb_sha256(canonical_payload)
    trace_id = f"RAG-TRC-{bundle_sha[:12].upper()}"
    return trace_id, bundle_sha
