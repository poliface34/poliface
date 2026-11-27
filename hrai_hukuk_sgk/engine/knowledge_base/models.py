"""Core domain models, bitemporal provision nodes, jurisprudence separation, and abstention boundaries (WP-4.2)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date
import hashlib
import json
import re
from typing import Any, Protocol, runtime_checkable

from ..models import NORM_LAYER_PRIORITY

KB_VERSION = "1.0.6-wp4.2"

# Document kinds keeping statutes, secondary rules, jurisprudence, interpretation cards & L5/L6 strictly isolated
DOC_KIND_STATUTORY_PROVISION = "STATUTORY_PROVISION"
DOC_KIND_SECONDARY_REGULATION = "SECONDARY_REGULATION"
DOC_KIND_JUDICIAL_PRECEDENT = "JUDICIAL_PRECEDENT"
DOC_KIND_INTERPRETATION_CARD = "INTERPRETATION_CARD"
DOC_KIND_AUTONOMOUS_NORM = "AUTONOMOUS_NORM"

VALID_DOCUMENT_KINDS: frozenset[str] = frozenset(
    {
        DOC_KIND_STATUTORY_PROVISION,
        DOC_KIND_SECONDARY_REGULATION,
        DOC_KIND_JUDICIAL_PRECEDENT,
        DOC_KIND_INTERPRETATION_CARD,
        DOC_KIND_AUTONOMOUS_NORM,
    }
)

# Structural chunk typology (never blind fixed-token splitting)
CHUNK_KIND_STATUTORY_PARAGRAPH = "STATUTORY_PARAGRAPH"
CHUNK_KIND_RULE_AND_EXCEPTION = "RULE_AND_EXCEPTION"
CHUNK_KIND_ABSTENTION_BOUNDARY = "ABSTENTION_BOUNDARY"
CHUNK_KIND_PRECEDENT_UNIT = "PRECEDENT_UNIT"
CHUNK_KIND_AUTONOMOUS_RULE_UNIT = "AUTONOMOUS_RULE_UNIT"

VALID_CHUNK_KINDS: frozenset[str] = frozenset(
    {
        CHUNK_KIND_STATUTORY_PARAGRAPH,
        CHUNK_KIND_RULE_AND_EXCEPTION,
        CHUNK_KIND_ABSTENTION_BOUNDARY,
        CHUNK_KIND_PRECEDENT_UNIT,
        CHUNK_KIND_AUTONOMOUS_RULE_UNIT,
    }
)

# Court systems & statutory authority levels (explicitly non-legislative)
COURT_YARGITAY = "YARGITAY"
COURT_DANISTAY = "DANISTAY"
COURT_AYM = "AYM"

VALID_COURT_SYSTEMS: frozenset[str] = frozenset({COURT_YARGITAY, COURT_DANISTAY, COURT_AYM})

VALID_PRECEDENT_BINDING_LEVELS: frozenset[str] = frozenset(
    {
        "STATUTORY_BINDING_YIBBGK",       # 2797 s. Kanun m.45
        "STATUTORY_BINDING_DANISTAY_IBK", # 2575 s. Danıştay Kanunu m.39
        "HGK_PERSUASIVE",
        "DANISTAY_IDDK_PERSUASIVE",
        "CHAMBER_SETTLED",
        "DANISTAY_DAIRE_SETTLED",
        "CHAMBER_ISOLATED",
        "DANISTAY_ISOLATED",
    }
)

VERIFICATION_VERIFIED = "VERIFIED"
VERIFICATION_PENDING_REVIEW = "PENDING_REVIEW"
VERIFICATION_PENDING_LEGAL_REVIEW = "PENDING_LEGAL_REVIEW"
VERIFICATION_UNVERIFIED = "UNVERIFIED"
VERIFICATION_SUPERSEDED = "SUPERSEDED"
VERIFICATION_REPEALED = "REPEALED"
VERIFICATION_REJECTED_CONTENT_MISMATCH = "REJECTED_CONTENT_MISMATCH"
VERIFICATION_TRANSPORT_ONLY = "TRANSPORT_ONLY_UNVERIFIED_CONTENT"
VERIFICATION_UNREACHABLE = "UNREACHABLE_NOT_VERIFIED"
VERIFICATION_QUARANTINED_TAMPER = "KB_CHUNK_TAMPER_QUARANTINED"

DISALLOWED_ACTIVE_VERIFICATION_STATUSES: frozenset[str] = frozenset(
    {
        VERIFICATION_PENDING_REVIEW,
        VERIFICATION_PENDING_LEGAL_REVIEW,
        VERIFICATION_UNVERIFIED,
        VERIFICATION_REJECTED_CONTENT_MISMATCH,
        VERIFICATION_TRANSPORT_ONLY,
        VERIFICATION_UNREACHABLE,
        VERIFICATION_QUARANTINED_TAMPER,
    }
)

VALID_KB_NORM_CHARACTERS: frozenset[str] = frozenset(
    {
        "ABSOLUTE_MANDATORY",
        "RELATIVE_EMPLOYEE_FAVORABLE",
        "DISPOSITIVE",
        "SUPPLEMENTARY_DEFAULT",
        "JUDICIAL_INTERPRETATION_NON_LEGISLATIVE",
    }
)

_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class KnowledgeBaseError(RuntimeError):
    """Fail-closed exception raised for schema, versioning, tamper, or temporal violations in WP-4.2 KB."""

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(f"[{error_code}] {message}")
        self.error_code = error_code
        self.message = message


def canonical_kb_sha256(obj: Any) -> str:
    """Compute deterministic lowercase hex SHA-256 digest over canonical UTF-8 JSON."""
    payload = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def parse_strict_kb_date(value: Any, field_name: str = "date") -> date:
    """Parse strict `YYYY-MM-DD` ISO date; fail closed on invalid, missing, or non-string dates."""
    if not isinstance(value, str) or not _ISO_DATE_RE.fullmatch(value.strip()):
        raise KnowledgeBaseError(
            "MISSING_OR_INVALID_ISO_DATE",
            f"'{field_name}' alanı geçerli YYYY-MM-DD biçiminde olmalıdır: {value!r}",
        )
    try:
        return date.fromisoformat(value.strip())
    except ValueError as exc:
        raise KnowledgeBaseError(
            "MISSING_OR_INVALID_ISO_DATE",
            f"'{field_name}' geçersiz takvim tarihidir: {value!r}",
        ) from exc


def is_valid_kb_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256_RE.fullmatch(value))


@runtime_checkable
class TrustChainEvidenceAdapterProtocol(Protocol):
    """Structural interface decoupling WP-4.2 KB from PR #3's `EvidenceRegistry` until merged."""

    def get(self, evidence_id: str) -> Any: ...

    def verify_integrity(self, *, require_raw_content: bool = True) -> tuple[bool, dict[str, Any]]: ...

    def get_raw_bytes(self, evidence_id: str) -> bytes | None: ...


@dataclass(frozen=True)
class LegalDocumentVersion:
    """Bitemporal verified version header of an official legislation source or regulatory instrument."""

    document_version_id: str
    source_id: str
    document_kind: str
    norm_layer: str
    norm_priority: int
    statute_no: str
    title: str
    official_gazette_no: str
    publication_date: str
    effective_from: str
    effective_to: str | None
    supersedes_version_id: str | None
    content_sha256: str
    verification_status: str
    document_fetch_status: str
    audit_log_id: str
    evidence_id: str | None = None
    source_url: str = ""
    amendment_summary: str = ""

    def __post_init__(self) -> None:
        if self.document_kind not in VALID_DOCUMENT_KINDS:
            raise KnowledgeBaseError("INVALID_DOCUMENT_KIND", f"Geçersiz document_kind: {self.document_kind!r}")
        if self.norm_layer not in NORM_LAYER_PRIORITY and self.norm_layer != "YARGITAY_PRECEDENT":
            raise KnowledgeBaseError("INVALID_NORM_LAYER", f"Geçersiz norm_layer: {self.norm_layer!r}")
        parse_strict_kb_date(self.publication_date, "publication_date")
        eff_from = parse_strict_kb_date(self.effective_from, "effective_from")
        if self.effective_to is not None:
            eff_to = parse_strict_kb_date(self.effective_to, "effective_to")
            if eff_to < eff_from:
                raise KnowledgeBaseError(
                    "INVALID_EFFECTIVE_WINDOW",
                    f"effective_to ({self.effective_to}) effective_from ({self.effective_from}) öncesinde olamaz.",
                )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LegalProvisionNode:
    """Hierarchical statutory/regulatory unit: Kanun -> Bölüm -> Madde -> Fıkra -> Bent -> Alt bent."""

    provision_id: str
    document_version_id: str
    source_id: str
    law_no: str
    article_no: str
    article_title: str
    raw_text: str
    normalized_text: str
    publication_date: str
    effective_from: str
    effective_to: str | None
    norm_layer: str
    norm_priority: int
    norm_character: str
    verification_status: str
    content_sha256: str
    chapter_title: str = ""
    paragraph_no: str | None = None
    subparagraph_no: str | None = None
    sub_clause_no: str | None = None
    hierarchy_path: str = ""
    document_kind: str = DOC_KIND_STATUTORY_PROVISION
    amendment_history: tuple[dict[str, Any], ...] = ()
    transitional_provision_ref: str | None = None
    cross_reference_ids: tuple[str, ...] = ()
    evidence_id: str | None = None
    supersedes_version_id: str | None = None
    source_url: str = ""
    adoption_status: str | None = None
    keywords: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.norm_character not in VALID_KB_NORM_CHARACTERS:
            raise KnowledgeBaseError("INVALID_NORM_CHARACTER", f"Geçersiz norm_character: {self.norm_character!r}")
        if not self.raw_text.strip():
            raise KnowledgeBaseError("EMPTY_PROVISION_TEXT", f"'{self.provision_id}' metni boş olamaz.")
        parse_strict_kb_date(self.publication_date, "publication_date")
        eff_from = parse_strict_kb_date(self.effective_from, "effective_from")
        if self.effective_to is not None:
            eff_to = parse_strict_kb_date(self.effective_to, "effective_to")
            if eff_to < eff_from:
                raise KnowledgeBaseError("INVALID_EFFECTIVE_WINDOW", f"'{self.provision_id}' yürürlük aralığı geçersiz.")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["amendment_history"] = [dict(x) for x in self.amendment_history]
        d["cross_reference_ids"] = list(self.cross_reference_ids)
        d["keywords"] = list(self.keywords)
        return d


@dataclass(frozen=True)
class AbstentionBoundary:
    """First-class explicit rule encoding WHEN the agent MUST refuse a definitive answer or escalate."""

    blocking_missing_facts: tuple[str, ...] = ()
    clarification_questions: tuple[str, ...] = ()
    mandatory_escalation_triggers: tuple[str, ...] = ()
    payroll_handoff_prohibition_conditions: tuple[str, ...] = ()
    unanswerable_boundary_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "blocking_missing_facts": list(self.blocking_missing_facts),
            "clarification_questions": list(self.clarification_questions),
            "mandatory_escalation_triggers": list(self.mandatory_escalation_triggers),
            "payroll_handoff_prohibition_conditions": list(self.payroll_handoff_prohibition_conditions),
            "unanswerable_boundary_reason": self.unanswerable_boundary_reason,
        }


@dataclass(frozen=True)
class InterpretationAndBoundaryRule:
    """Actionable legal interpretation, exceptions, transitional rules, pitfalls, and abstention boundaries."""

    rule_id: str
    provision_id: str
    source_id: str
    card_id: str | None
    topic: str
    effective_from: str
    effective_to: str | None
    verification_status: str
    how_to_interpret: tuple[dict[str, Any], ...] = ()
    exceptions: tuple[str, ...] = ()
    transitional_rules: tuple[dict[str, Any], ...] = ()
    counter_arguments_and_pitfalls: tuple[str, ...] = ()
    required_documents: tuple[str, ...] = ()
    abstention_boundary: AbstentionBoundary = field(default_factory=AbstentionBoundary)
    related_precedent_ids: tuple[str, ...] = ()
    legal_interpretation_verification: dict[str, Any] = field(default_factory=dict)
    content_sha256: str = ""

    def __post_init__(self) -> None:
        parse_strict_kb_date(self.effective_from, "effective_from")
        if self.effective_to is not None:
            parse_strict_kb_date(self.effective_to, "effective_to")

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "provision_id": self.provision_id,
            "source_id": self.source_id,
            "card_id": self.card_id,
            "topic": self.topic,
            "effective_from": self.effective_from,
            "effective_to": self.effective_to,
            "verification_status": self.verification_status,
            "how_to_interpret": [dict(x) for x in self.how_to_interpret],
            "exceptions": list(self.exceptions),
            "transitional_rules": [dict(x) for x in self.transitional_rules],
            "counter_arguments_and_pitfalls": list(self.counter_arguments_and_pitfalls),
            "required_documents": list(self.required_documents),
            "abstention_boundary": self.abstention_boundary.to_dict(),
            "related_precedent_ids": list(self.related_precedent_ids),
            "legal_interpretation_verification": dict(self.legal_interpretation_verification),
            "content_sha256": self.content_sha256,
        }


@dataclass(frozen=True)
class JudicialPrecedentNode:
    """Explicitly non-legislative jurisprudence node covering both Yargıtay and Danıştay decisions."""

    precedent_id: str
    court_system: str
    chamber: str
    binding_level: str
    esas_no: str
    karar_no: str
    decision_date: str
    official_source_url: str
    interpreted_provision_ids: tuple[str, ...]
    legal_principle: str
    operative_holding: str
    applies_to: tuple[str, ...]
    does_not_apply_to: tuple[str, ...]
    verification_status: str
    content_sha256: str
    official_gazette_no: str | None = None
    requires_application_rationale: bool = True
    post_decision_amendment_status: str = "UNAFFECTED"
    conflicting_precedent_ids: tuple[str, ...] = ()
    evidence_id: str | None = None
    keywords: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.court_system not in VALID_COURT_SYSTEMS:
            raise KnowledgeBaseError("INVALID_COURT_SYSTEM", f"Geçersiz court_system: {self.court_system!r}")
        if self.binding_level not in VALID_PRECEDENT_BINDING_LEVELS:
            raise KnowledgeBaseError("INVALID_BINDING_LEVEL", f"Geçersiz binding_level: {self.binding_level!r}")
        parse_strict_kb_date(self.decision_date, "decision_date")

    @property
    def is_statutorily_binding(self) -> bool:
        return self.binding_level in {"STATUTORY_BINDING_YIBBGK", "STATUTORY_BINDING_DANISTAY_IBK"}

    def to_dict(self) -> dict[str, Any]:
        return {
            "precedent_id": self.precedent_id,
            "court_system": self.court_system,
            "chamber": self.chamber,
            "binding_level": self.binding_level,
            "is_statutorily_binding": self.is_statutorily_binding,
            "requires_application_rationale": self.requires_application_rationale,
            "esas_no": self.esas_no,
            "karar_no": self.karar_no,
            "decision_date": self.decision_date,
            "official_gazette_no": self.official_gazette_no,
            "official_source_url": self.official_source_url,
            "evidence_id": self.evidence_id,
            "interpreted_provision_ids": list(self.interpreted_provision_ids),
            "legal_principle": self.legal_principle,
            "operative_holding": self.operative_holding,
            "applies_to": list(self.applies_to),
            "does_not_apply_to": list(self.does_not_apply_to),
            "post_decision_amendment_status": self.post_decision_amendment_status,
            "conflicting_precedent_ids": list(self.conflicting_precedent_ids),
            "verification_status": self.verification_status,
            "content_sha256": self.content_sha256,
            "keywords": list(self.keywords),
        }


@dataclass(frozen=True)
class LegalSearchChunk:
    """Atomic, context-enriched search unit indexed by vector+lexical hybrid storage."""

    chunk_id: str
    provision_id: str
    document_version_id: str
    source_id: str
    document_kind: str
    chunk_kind: str
    norm_layer: str
    norm_priority: int
    effective_from: str
    effective_to: str | None
    verification_status: str
    content_verified: bool
    content_sha256: str
    raw_text: str
    context_header: str
    chunk_sha256: str
    law_no: str | None = None
    article_no: str | None = None
    evidence_id: str | None = None
    adoption_status: str | None = None
    embedding: tuple[float, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.document_kind not in VALID_DOCUMENT_KINDS:
            raise KnowledgeBaseError("INVALID_DOCUMENT_KIND", f"Geçersiz chunk document_kind: {self.document_kind!r}")
        if self.chunk_kind not in VALID_CHUNK_KINDS:
            raise KnowledgeBaseError("INVALID_CHUNK_KIND", f"Geçersiz chunk_kind: {self.chunk_kind!r}")

    def to_dict(self, *, include_embedding: bool = False) -> dict[str, Any]:
        out: dict[str, Any] = {
            "chunk_id": self.chunk_id,
            "provision_id": self.provision_id,
            "document_version_id": self.document_version_id,
            "source_id": self.source_id,
            "evidence_id": self.evidence_id,
            "document_kind": self.document_kind,
            "chunk_kind": self.chunk_kind,
            "norm_layer": self.norm_layer,
            "norm_priority": self.norm_priority,
            "law_no": self.law_no,
            "article_no": self.article_no,
            "effective_from": self.effective_from,
            "effective_to": self.effective_to,
            "verification_status": self.verification_status,
            "content_verified": self.content_verified,
            "adoption_status": self.adoption_status,
            "content_sha256": self.content_sha256,
            "raw_text": self.raw_text,
            "context_header": self.context_header,
            "chunk_sha256": self.chunk_sha256,
            "metadata": dict(self.metadata),
        }
        if include_embedding:
            out["embedding"] = list(self.embedding)
        return out


@dataclass(frozen=True)
class KnowledgeSearchQuery:
    """Strict retrieval query enforcing temporal anchoring and pool isolation."""

    query_text: str
    as_of_date: str | None
    document_kinds: tuple[str, ...] | None = None
    chunk_kinds: tuple[str, ...] | None = None
    law_nos: tuple[str, ...] | None = None
    court_systems: tuple[str, ...] | None = None
    include_historical: bool = False
    require_adopted_autonomous_norms: bool = True
    top_k: int = 5


@dataclass(frozen=True)
class ExcludedUnverifiedNotice:
    """Transparent notice emitted when matching records exist ONLY in pending/unverified/rejected pools."""

    record_id: str
    source_id: str
    document_kind: str
    status: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SearchHit:
    """Single verified retrieval hit bound to its structural chunk and companion boundary rules."""

    rank: int
    rrf_score: float
    vector_score: float
    lexical_score: float
    chunk: LegalSearchChunk
    is_historical_context: bool = False
    companion_rules: tuple[InterpretationAndBoundaryRule, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "rank": self.rank,
            "rrf_score": round(self.rrf_score, 6),
            "vector_score": round(self.vector_score, 6),
            "lexical_score": round(self.lexical_score, 6),
            "is_historical_context": self.is_historical_context,
            "chunk": self.chunk.to_dict(),
            "companion_rules": [r.to_dict() for r in self.companion_rules],
        }


@dataclass(frozen=True)
class KnowledgeSearchResult:
    """Audit-ready output of a dual-gated hybrid legal KB search."""

    query_text: str
    as_of_date: str
    provider_name: str
    integration_mode: str
    active_hits: tuple[SearchHit, ...]
    historical_hits: tuple[SearchHit, ...] = ()
    excluded_unverified_notices: tuple[ExcludedUnverifiedNotice, ...] = ()
    prefilter_summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_text": self.query_text,
            "as_of_date": self.as_of_date,
            "provider_name": self.provider_name,
            "integration_mode": self.integration_mode,
            "active_hit_count": len(self.active_hits),
            "historical_hit_count": len(self.historical_hits),
            "excluded_unverified_count": len(self.excluded_unverified_notices),
            "active_hits": [h.to_dict() for h in self.active_hits],
            "historical_hits": [h.to_dict() for h in self.historical_hits],
            "excluded_unverified_notices": [n.to_dict() for n in self.excluded_unverified_notices],
            "prefilter_summary": dict(self.prefilter_summary),
        }
