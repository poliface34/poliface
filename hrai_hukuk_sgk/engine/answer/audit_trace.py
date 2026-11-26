"""Stage 8 AnswerAuditTracer building cryptographic Claim-to-RetrievalTraceBundle audit links (WP-4.4)."""

from __future__ import annotations

from ..knowledge_base.models import canonical_kb_sha256
from ..rag.models import RetrievalTraceBundle
from .models import (
    CLOSED_GOVERNANCE_GATES,
    AnswerAuditTrace,
    AnswerCitationAuditReport,
    AnswerClaimRecord,
    ClaimEvidenceLink,
    TemporalValidationReport,
)


class AnswerAuditTracer:
    """Produces deterministic cryptographic lineage linking Answer claims to RAG trace & EvidenceRegistry."""

    def build_trace(
        self,
        *,
        trace_bundle: RetrievalTraceBundle,
        claims: tuple[AnswerClaimRecord, ...],
        temporal_report: TemporalValidationReport,
        citation_audit: AnswerCitationAuditReport,
        answer_sha256: str,
    ) -> AnswerAuditTrace:
        links = tuple(
            ClaimEvidenceLink(
                claim_id=c.claim_id,
                section_name=c.section_name,
                claim_category=c.claim_category,
                chunk_id=c.chunk_id,
                provision_id=c.provision_id,
                source_id=c.source_id,
                precedent_id=c.precedent_id,
                rule_id=c.rule_id,
                audit_log_id=c.audit_log_id,
                content_sha256=c.content_sha256,
                chunk_sha256=c.chunk_sha256,
                evidence_id=c.evidence_id,
                registry_head_sha256=c.registry_head_sha256,
                effective_on_date=c.effective_on_date,
            )
            for c in claims
        )
        excluded_refs = tuple(n.to_dict() for n in trace_bundle.excluded_unverified_notices)
        payload = {
            "source_trace_id": trace_bundle.trace_id,
            "source_bundle_sha256": trace_bundle.bundle_sha256,
            "claim_evidence_links": [lnk.to_dict() for lnk in links],
            "unverified_or_excluded_refs": list(excluded_refs),
            "citation_audit_passed": citation_audit.passed,
            "citation_audit_blocker_codes": list(citation_audit.blocker_codes),
            "temporal_flags": list(temporal_report.temporal_flags),
            "governance_gates": CLOSED_GOVERNANCE_GATES,
            "answer_sha256": answer_sha256,
        }
        trace_sha = canonical_kb_sha256(payload)
        return AnswerAuditTrace(
            source_trace_id=trace_bundle.trace_id,
            source_bundle_sha256=trace_bundle.bundle_sha256,
            source_retrieved_at_utc=trace_bundle.retrieved_at_utc,
            claim_evidence_links=links,
            unverified_or_excluded_refs=excluded_refs,
            citation_audit_passed=citation_audit.passed,
            citation_audit_blocker_codes=citation_audit.blocker_codes,
            temporal_flags=temporal_report.temporal_flags,
            governance_gates=dict(CLOSED_GOVERNANCE_GATES),
            answer_sha256=answer_sha256,
            audit_trace_sha256=trace_sha,
        )
