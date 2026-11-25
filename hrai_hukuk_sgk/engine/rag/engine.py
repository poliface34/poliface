"""Orchestrator for WP-4.3 6-Stage RAG Engine (`HukukSgkRagEngine`)."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from ..knowledge_base.loader import load_wp42_knowledge_base
from ..knowledge_base.models import (
    DOC_KIND_AUTONOMOUS_NORM,
    DOC_KIND_INTERPRETATION_CARD,
    DOC_KIND_JUDICIAL_PRECEDENT,
    DOC_KIND_SECONDARY_REGULATION,
    DOC_KIND_STATUTORY_PROVISION,
    ExcludedUnverifiedNotice,
    KnowledgeSearchQuery,
    LegalSearchChunk,
    SearchHit,
    TrustChainEvidenceAdapterProtocol,
)
from ..knowledge_base.store import LocalDeterministicHybridStore
from .abstention import AbstentionEvaluator
from .evidence_linker import EvidenceLinker
from .intent import QueryIntentAnalyzer, TemporalGate
from .models import (
    BUCKET_AUTONOMOUS_NORM,
    BUCKET_HISTORICAL_CONTEXT,
    GATE_ABSTAIN_INSUFFICIENT_EVIDENCE,
    GATE_ABSTAIN_OUT_OF_DOMAIN,
    INTENT_OUT_OF_DOMAIN,
    INTENT_PRECEDENT_CHECK,
    CitationWhitelist,
    QueryIntentAnalysis,
    RagQueryRequest,
    RankedEvidenceItem,
    RetrievalTraceBundle,
    TemporalAuditReport,
    compute_deterministic_trace_hashes,
)
from .reranker import CrossReferenceExpander, LegalDomainReranker

DEFAULT_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def _build_audit_and_url_catalog(project_root: Path | None) -> tuple[dict[str, str], dict[str, str]]:
    """Load read-only source/precedent/autonomous audit ID and URL maps from config JSON registries."""
    audit_map: dict[str, str] = {}
    url_map: dict[str, str] = {}
    if project_root is None:
        return audit_map, url_map

    sources_path = project_root / "config" / "legal_sources_registry.json"
    if sources_path.exists():
        try:
            raw = json.loads(sources_path.read_text(encoding="utf-8"))
            recs = raw.get("sources", []) if isinstance(raw, dict) else raw
            for rec in recs:
                sid = str(rec.get("source_id") or "")
                aud = str((rec.get("verification_audit") or {}).get("audit_log_id") or "")
                url = str(rec.get("source_url") or "")
                if sid and aud:
                    audit_map[sid] = aud
                if sid and url:
                    url_map[sid] = url
        except Exception:
            pass

    prec_path = project_root / "config" / "yargitay_precedents.json"
    if prec_path.exists():
        try:
            raw = json.loads(prec_path.read_text(encoding="utf-8"))
            recs = raw.get("precedents", []) if isinstance(raw, dict) else raw
            for rec in recs:
                pid = str(rec.get("precedent_id") or "")
                aud = str((rec.get("verification_audit") or {}).get("audit_log_id") or "")
                url = str(rec.get("official_source_url") or "")
                if pid and aud:
                    audit_map[pid] = aud
                if pid and url:
                    url_map[pid] = url
        except Exception:
            pass

    auto_path = project_root / "config" / "autonomous_norms_audit_log.json"
    if auto_path.exists():
        try:
            raw = json.loads(auto_path.read_text(encoding="utf-8"))
            for entry in raw.get("entries", []):
                sid = str(entry.get("source_document_id") or "")
                aud = str(entry.get("audit_id") or "")
                if sid and aud:
                    audit_map[sid] = aud
        except Exception:
            pass

    return audit_map, url_map


class HukukSgkRagEngine:
    """Deterministic 6-stage retrieval, reranking, EvidenceRegistry linkage, and fail-closed RAG engine."""

    def __init__(
        self,
        store: LocalDeterministicHybridStore,
        *,
        project_root: str | Path | None = None,
        trust_chain_adapter: TrustChainEvidenceAdapterProtocol | None = None,
    ) -> None:
        self._store = store
        self._root = Path(project_root) if project_root is not None else DEFAULT_PROJECT_ROOT
        self._trust_chain_adapter = trust_chain_adapter
        self._intent_analyzer = QueryIntentAnalyzer()
        self._temporal_gate = TemporalGate()
        self._cross_ref = CrossReferenceExpander()
        self._reranker = LegalDomainReranker()
        self._evidence_linker = EvidenceLinker(trust_chain_adapter=trust_chain_adapter)
        self._abstention = AbstentionEvaluator()

        cfg_audit, cfg_urls = _build_audit_and_url_catalog(self._root)
        self._audit_by_doc_ver: dict[str, str] = {}
        self._url_by_doc_ver: dict[str, str] = {}
        self._audit_by_source: dict[str, str] = dict(cfg_audit)
        self._url_by_source: dict[str, str] = dict(cfg_urls)

        for dv in store.version_manager._doc_versions_by_id.values():
            if dv.audit_log_id:
                self._audit_by_doc_ver[dv.document_version_id] = dv.audit_log_id
                self._audit_by_source.setdefault(dv.source_id, dv.audit_log_id)
            if dv.source_url:
                self._url_by_doc_ver[dv.document_version_id] = dv.source_url
                self._url_by_source.setdefault(dv.source_id, dv.source_url)

    @classmethod
    def from_project_root(
        cls,
        *,
        project_root: str | Path | None = None,
        trust_chain_adapter: TrustChainEvidenceAdapterProtocol | None = None,
    ) -> HukukSgkRagEngine:
        root = Path(project_root) if project_root is not None else DEFAULT_PROJECT_ROOT
        store, _ = load_wp42_knowledge_base(project_root=root, trust_chain_adapter=trust_chain_adapter)
        return cls(store, project_root=root, trust_chain_adapter=trust_chain_adapter)

    @property
    def store(self) -> LocalDeterministicHybridStore:
        return self._store

    def _resolve_audit_log_id(self, chunk: LegalSearchChunk) -> str:
        if chunk.document_version_id in self._audit_by_doc_ver:
            return self._audit_by_doc_ver[chunk.document_version_id]
        if chunk.source_id in self._audit_by_source:
            return self._audit_by_source[chunk.source_id]
        if chunk.metadata.get("audit_log_id"):
            return str(chunk.metadata["audit_log_id"])
        if chunk.evidence_id:
            return f"AUD-TC-{chunk.evidence_id}"
        return f"AUD-KB-{chunk.source_id}"

    def _resolve_source_url(self, chunk: LegalSearchChunk) -> str:
        if chunk.document_version_id in self._url_by_doc_ver:
            return self._url_by_doc_ver[chunk.document_version_id]
        if chunk.metadata.get("official_source_url"):
            return str(chunk.metadata["official_source_url"])
        if chunk.metadata.get("source_url"):
            return str(chunk.metadata["source_url"])
        if chunk.source_id in self._url_by_source:
            return self._url_by_source[chunk.source_id]
        return ""

    def retrieve(self, request: RagQueryRequest) -> RetrievalTraceBundle:
        audit_trail: list[str] = []
        retrieved_at_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        facts = dict(request.facts or {})

        # Stage 1: QueryIntentAnalyzer
        intent_analysis = self._intent_analyzer.analyze(request.query_text)
        audit_trail.append(
            f"STAGE1_INTENT:intent={intent_analysis.intent},domain={intent_analysis.primary_domain},"
            f"sub_queries={len(intent_analysis.sub_queries)}"
        )

        # Short-circuit Stage 1 OUT_OF_DOMAIN (no KB search executed)
        if intent_analysis.intent == INTENT_OUT_OF_DOMAIN:
            temp_empty = TemporalAuditReport(
                as_of_date=request.as_of_date,
                date_source="SKIPPED_OUT_OF_DOMAIN",
                date_valid=False,
            )
            gate = self._abstention.evaluate(
                query_text=request.query_text,
                facts=facts,
                intent_analysis=intent_analysis,
                temporal_audit=temp_empty,
                normative_bucket=(),
                interpretation_bucket=(),
                precedent_bucket=(),
                autonomous_norm_bucket=(),
                excluded_unverified_notices=(),
                quarantined_evidence_mismatches=(),
            )
            audit_trail.append(f"STAGE6_GATE:{gate['rag_gate_status']}")
            wl = CitationWhitelist()
            trace_id, b_sha = compute_deterministic_trace_hashes(
                query_text=request.query_text,
                as_of_date=None,
                intent_classification=intent_analysis,
                temporal_audit=temp_empty,
                rag_gate_status=gate["rag_gate_status"],
                should_conclude=gate["should_conclude"],
                counsel_escalation_required=gate["counsel_escalation_required"],
                escalation_reasons=gate["escalation_reasons"],
                payroll_handoff_allowed=gate["payroll_handoff_allowed"],
                missing_facts=gate["missing_facts"],
                clarification_questions=gate["clarification_questions"],
                normative_bucket=(),
                interpretation_bucket=(),
                precedent_bucket=(),
                autonomous_norm_bucket=(),
                historical_context_bucket=(),
                excluded_unverified_notices=(),
                evidence_bindings=(),
                quarantined_evidence_mismatches=(),
                citation_whitelist=wl,
                pipeline_audit_trail=tuple(audit_trail),
            )
            return RetrievalTraceBundle(
                trace_id=trace_id,
                retrieved_at_utc=retrieved_at_utc,
                query_text=request.query_text,
                intent_classification=intent_analysis,
                as_of_date=None,
                temporal_audit=temp_empty,
                rag_gate_status=gate["rag_gate_status"],
                should_conclude=gate["should_conclude"],
                counsel_escalation_required=gate["counsel_escalation_required"],
                escalation_reasons=gate["escalation_reasons"],
                payroll_handoff_allowed=gate["payroll_handoff_allowed"],
                missing_facts=gate["missing_facts"],
                clarification_questions=gate["clarification_questions"],
                normative_bucket=(),
                interpretation_bucket=(),
                precedent_bucket=(),
                autonomous_norm_bucket=(),
                historical_context_bucket=(),
                excluded_unverified_notices=(),
                evidence_bindings=(),
                quarantined_evidence_mismatches=(),
                unverified_disclosure_message=gate["unverified_disclosure_message"],
                out_of_domain_message=gate["out_of_domain_message"],
                citation_whitelist=wl,
                pipeline_audit_trail=tuple(audit_trail),
                bundle_sha256=b_sha,
            )

        # Stage 2: TemporalGate
        temporal_audit = self._temporal_gate.evaluate(request.query_text, as_of_date=request.as_of_date)
        audit_trail.append(
            f"STAGE2_TEMPORAL:valid={temporal_audit.date_valid},as_of_date={temporal_audit.as_of_date},"
            f"source={temporal_audit.date_source}"
        )

        # Short-circuit Stage 2 if as_of_date is missing / invalid / ambiguous
        if not temporal_audit.date_valid or not temporal_audit.as_of_date:
            gate = self._abstention.evaluate(
                query_text=request.query_text,
                facts=facts,
                intent_analysis=intent_analysis,
                temporal_audit=temporal_audit,
                normative_bucket=(),
                interpretation_bucket=(),
                precedent_bucket=(),
                autonomous_norm_bucket=(),
                excluded_unverified_notices=(),
                quarantined_evidence_mismatches=(),
            )
            audit_trail.append(f"STAGE6_GATE:{gate['rag_gate_status']}")
            wl = CitationWhitelist()
            trace_id, b_sha = compute_deterministic_trace_hashes(
                query_text=request.query_text,
                as_of_date=None,
                intent_classification=intent_analysis,
                temporal_audit=temporal_audit,
                rag_gate_status=gate["rag_gate_status"],
                should_conclude=gate["should_conclude"],
                counsel_escalation_required=gate["counsel_escalation_required"],
                escalation_reasons=gate["escalation_reasons"],
                payroll_handoff_allowed=gate["payroll_handoff_allowed"],
                missing_facts=gate["missing_facts"],
                clarification_questions=gate["clarification_questions"],
                normative_bucket=(),
                interpretation_bucket=(),
                precedent_bucket=(),
                autonomous_norm_bucket=(),
                historical_context_bucket=(),
                excluded_unverified_notices=(),
                evidence_bindings=(),
                quarantined_evidence_mismatches=(),
                citation_whitelist=wl,
                pipeline_audit_trail=tuple(audit_trail),
            )
            return RetrievalTraceBundle(
                trace_id=trace_id,
                retrieved_at_utc=retrieved_at_utc,
                query_text=request.query_text,
                intent_classification=intent_analysis,
                as_of_date=None,
                temporal_audit=temporal_audit,
                rag_gate_status=gate["rag_gate_status"],
                should_conclude=gate["should_conclude"],
                counsel_escalation_required=gate["counsel_escalation_required"],
                escalation_reasons=gate["escalation_reasons"],
                payroll_handoff_allowed=gate["payroll_handoff_allowed"],
                missing_facts=gate["missing_facts"],
                clarification_questions=gate["clarification_questions"],
                normative_bucket=(),
                interpretation_bucket=(),
                precedent_bucket=(),
                autonomous_norm_bucket=(),
                historical_context_bucket=(),
                excluded_unverified_notices=(),
                evidence_bindings=(),
                quarantined_evidence_mismatches=(),
                unverified_disclosure_message=gate["unverified_disclosure_message"],
                out_of_domain_message=gate["out_of_domain_message"],
                citation_whitelist=wl,
                pipeline_audit_trail=tuple(audit_trail),
                bundle_sha256=b_sha,
            )

        as_of_date = temporal_audit.as_of_date
        top_k = max(1, min(20, int(request.top_k)))
        search_text = intent_analysis.rewritten_query_text or request.query_text

        # Stage 3: BucketedHybridSearch (3+1 isolated buckets)
        norm_hits_map: dict[str, SearchHit] = {}
        hist_hits_map: dict[str, SearchHit] = {}
        excluded_map: dict[tuple[str, str, str], ExcludedUnverifiedNotice] = {}

        def _absorb_excluded(notices: tuple[ExcludedUnverifiedNotice, ...]) -> None:
            for n in notices:
                key = (n.source_id, n.record_id, n.status)
                if key not in excluded_map:
                    excluded_map[key] = n

        # Bucket 1: Normative Legislation (STATUTORY_PROVISION + SECONDARY_REGULATION)
        res_norm_main = self._store.hybrid_search(
            KnowledgeSearchQuery(
                query_text=search_text,
                as_of_date=as_of_date,
                document_kinds=(DOC_KIND_STATUTORY_PROVISION, DOC_KIND_SECONDARY_REGULATION),
                include_historical=request.include_historical,
                top_k=max(top_k, 8),
            )
        )
        for h in res_norm_main.active_hits:
            norm_hits_map[h.chunk.chunk_id] = h
        for h in res_norm_main.historical_hits:
            hist_hits_map[h.chunk.chunk_id] = h
        _absorb_excluded(res_norm_main.excluded_unverified_notices)

        # Multi-domain decomposition sub-queries (ensures no secondary domain is drowned out)
        for sq in intent_analysis.sub_queries:
            res_sub = self._store.hybrid_search(
                KnowledgeSearchQuery(
                    query_text=sq.query_text,
                    as_of_date=as_of_date,
                    document_kinds=(DOC_KIND_STATUTORY_PROVISION, DOC_KIND_SECONDARY_REGULATION),
                    law_nos=sq.law_nos or None,
                    include_historical=request.include_historical,
                    top_k=4,
                )
            )
            for h in res_sub.active_hits:
                prev = norm_hits_map.get(h.chunk.chunk_id)
                if prev is None or h.rrf_score > prev.rrf_score:
                    norm_hits_map[h.chunk.chunk_id] = h
            for h in res_sub.historical_hits:
                hist_hits_map.setdefault(h.chunk.chunk_id, h)
            _absorb_excluded(res_sub.excluded_unverified_notices)

        # Bucket 2: Interpretation, Exception & Abstention Boundary Cards
        res_interp = self._store.hybrid_search(
            KnowledgeSearchQuery(
                query_text=search_text,
                as_of_date=as_of_date,
                document_kinds=(DOC_KIND_INTERPRETATION_CARD,),
                include_historical=request.include_historical,
                top_k=max(top_k, 8),
            )
        )
        for h in res_interp.historical_hits:
            hist_hits_map.setdefault(h.chunk.chunk_id, h)
        _absorb_excluded(res_interp.excluded_unverified_notices)

        # Bucket 3: Judicial Precedent Pool (Yargıtay / Danıştay / AYM — non-legislative)
        res_prec = self._store.hybrid_search(
            KnowledgeSearchQuery(
                query_text=search_text,
                as_of_date=as_of_date,
                document_kinds=(DOC_KIND_JUDICIAL_PRECEDENT,),
                court_systems=request.court_systems,
                include_historical=request.include_historical,
                top_k=top_k,
            )
        )
        for h in res_prec.historical_hits:
            hist_hits_map.setdefault(h.chunk.chunk_id, h)
        _absorb_excluded(res_prec.excluded_unverified_notices)

        # Bucket 4: L5/L6 Autonomous Norms (strictly requiring COMPANY_ADOPTED_COUNSEL_VERIFIED)
        res_auto = self._store.hybrid_search(
            KnowledgeSearchQuery(
                query_text=search_text,
                as_of_date=as_of_date,
                document_kinds=(DOC_KIND_AUTONOMOUS_NORM,),
                require_adopted_autonomous_norms=request.require_adopted_autonomous_norms,
                include_historical=request.include_historical,
                top_k=top_k,
            )
        )
        for h in res_auto.historical_hits:
            hist_hits_map.setdefault(h.chunk.chunk_id, h)
        _absorb_excluded(res_auto.excluded_unverified_notices)

        audit_trail.append(
            f"STAGE3_BUCKET_SEARCH:b1={len(norm_hits_map)},b2={len(res_interp.active_hits)},"
            f"b3={len(res_prec.active_hits)},b4={len(res_auto.active_hits)},hist={len(hist_hits_map)}"
        )

        # Stage 4: 1-Hop Cross-Reference Expansion + LegalDomainReranker
        primary_norm_sorted = sorted(
            norm_hits_map.values(),
            key=lambda h: (-h.rrf_score, -h.lexical_score, h.chunk.norm_priority, h.chunk.chunk_id),
        )
        expanded_norm_pairs = self._cross_ref.expand_one_hop(
            normative_hits=primary_norm_sorted,
            store=self._store,
            as_of_date=as_of_date,
            seed_limit=3,
        )
        ranked_norm = self._reranker.rerank_normative_bucket(
            expanded_norm_pairs,
            query_text=request.query_text,
            intent_analysis=intent_analysis,
            resolve_audit_fn=self._resolve_audit_log_id,
            resolve_url_fn=self._resolve_source_url,
        )

        # For PRECEDENT_CHECK where query didn't pull underlying statutory provision directly, hydrate interpreted anchors
        if intent_analysis.intent == INTENT_PRECEDENT_CHECK and res_prec.active_hits and not ranked_norm:
            extra_pairs: list[tuple[SearchHit, str]] = []
            for p_hit in res_prec.active_hits[:2]:
                anchors = tuple(p_hit.chunk.metadata.get("interpreted_provision_ids") or ())
                if anchors:
                    anc_res = self._store.hybrid_search(
                        KnowledgeSearchQuery(
                            query_text=" ".join(anchors),
                            as_of_date=as_of_date,
                            document_kinds=(DOC_KIND_STATUTORY_PROVISION, DOC_KIND_SECONDARY_REGULATION),
                            top_k=3,
                        )
                    )
                    for ah in anc_res.active_hits:
                        extra_pairs.append((ah, "CROSS_REF_EXPANSION"))
            if extra_pairs:
                ranked_norm = self._reranker.rerank_normative_bucket(
                    extra_pairs,
                    query_text=request.query_text,
                    intent_analysis=intent_analysis,
                    resolve_audit_fn=self._resolve_audit_log_id,
                    resolve_url_fn=self._resolve_source_url,
                )

        ranked_interp = self._reranker.rerank_interpretation_bucket(
            card_hits=list(res_interp.active_hits),
            normative_items=ranked_norm,
            store=self._store,
            resolve_audit_fn=self._resolve_audit_log_id,
            resolve_url_fn=self._resolve_source_url,
        )
        ranked_prec = self._reranker.rerank_precedent_bucket(
            list(res_prec.active_hits),
            normative_items=ranked_norm,
            query_text=request.query_text,
            resolve_audit_fn=self._resolve_audit_log_id,
            resolve_url_fn=self._resolve_source_url,
        )
        ranked_auto = self._reranker.wrap_autonomous_or_historical_hits(
            list(res_auto.active_hits),
            bucket=BUCKET_AUTONOMOUS_NORM,
            resolve_audit_fn=self._resolve_audit_log_id,
            resolve_url_fn=self._resolve_source_url,
        )
        ranked_hist = self._reranker.wrap_autonomous_or_historical_hits(
            sorted(hist_hits_map.values(), key=lambda h: (-h.rrf_score, h.chunk.chunk_id)),
            bucket=BUCKET_HISTORICAL_CONTEXT,
            resolve_audit_fn=self._resolve_audit_log_id,
            resolve_url_fn=self._resolve_source_url,
        )

        # Update historical count inside temporal_audit
        temporal_audit = TemporalAuditReport(
            as_of_date=temporal_audit.as_of_date,
            date_source=temporal_audit.date_source,
            date_valid=temporal_audit.date_valid,
            candidate_dates_found=temporal_audit.candidate_dates_found,
            cutoff_flags=temporal_audit.cutoff_flags,
            historical_versions_filtered_count=len(ranked_hist),
            error_code=temporal_audit.error_code,
        )
        audit_trail.append(
            f"STAGE4_RERANK:norm={len(ranked_norm)},interp={len(ranked_interp)},"
            f"prec={len(ranked_prec)},auto={len(ranked_auto)}"
        )

        # Stage 5: EvidenceLinker (TrustChainEvidenceAdapterProtocol / AuditLog integrity gate)
        link_res = self._evidence_linker.link_all_buckets(
            normative_bucket=ranked_norm,
            interpretation_bucket=ranked_interp,
            precedent_bucket=ranked_prec,
            autonomous_norm_bucket=ranked_auto,
            historical_context_bucket=ranked_hist,
        )
        linked_norm = link_res["normative_bucket"]
        linked_interp = link_res["interpretation_bucket"]
        linked_prec = link_res["precedent_bucket"]
        linked_auto = link_res["autonomous_norm_bucket"]
        linked_hist = link_res["historical_context_bucket"]
        ev_bindings = link_res["evidence_bindings"]
        quarantined_mismatches = link_res["quarantined_evidence_mismatches"]
        excluded_notices = tuple(
            sorted(excluded_map.values(), key=lambda n: (n.source_id, n.record_id, n.status))
        )
        audit_trail.append(
            f"STAGE5_EVIDENCE_LINK:bound={len(ev_bindings)},quarantined={len(quarantined_mismatches)}"
        )

        # Stage 6: AbstentionEvaluator
        gate = self._abstention.evaluate(
            query_text=request.query_text,
            facts=facts,
            intent_analysis=intent_analysis,
            temporal_audit=temporal_audit,
            normative_bucket=linked_norm,
            interpretation_bucket=linked_interp,
            precedent_bucket=linked_prec,
            autonomous_norm_bucket=linked_auto,
            excluded_unverified_notices=excluded_notices,
            quarantined_evidence_mismatches=quarantined_mismatches,
        )
        audit_trail.append(f"STAGE6_GATE:{gate['rag_gate_status']}")

        # Build strict CitationWhitelist (empty if ABSTAIN_INSUFFICIENT_EVIDENCE or ABSTAIN_OUT_OF_DOMAIN)
        citation_whitelist = self._build_citation_whitelist(
            rag_gate_status=gate["rag_gate_status"],
            normative_bucket=linked_norm,
            interpretation_bucket=linked_interp,
            precedent_bucket=linked_prec,
            autonomous_norm_bucket=linked_auto,
            historical_context_bucket=linked_hist,
            evidence_bindings=ev_bindings,
        )

        trace_id, bundle_sha = compute_deterministic_trace_hashes(
            query_text=request.query_text,
            as_of_date=as_of_date,
            intent_classification=intent_analysis,
            temporal_audit=temporal_audit,
            rag_gate_status=gate["rag_gate_status"],
            should_conclude=gate["should_conclude"],
            counsel_escalation_required=gate["counsel_escalation_required"],
            escalation_reasons=gate["escalation_reasons"],
            payroll_handoff_allowed=gate["payroll_handoff_allowed"],
            missing_facts=gate["missing_facts"],
            clarification_questions=gate["clarification_questions"],
            normative_bucket=linked_norm,
            interpretation_bucket=linked_interp,
            precedent_bucket=linked_prec,
            autonomous_norm_bucket=linked_auto,
            historical_context_bucket=linked_hist,
            excluded_unverified_notices=excluded_notices,
            evidence_bindings=ev_bindings,
            quarantined_evidence_mismatches=quarantined_mismatches,
            citation_whitelist=citation_whitelist,
            pipeline_audit_trail=tuple(audit_trail),
        )

        return RetrievalTraceBundle(
            trace_id=trace_id,
            retrieved_at_utc=retrieved_at_utc,
            query_text=request.query_text,
            intent_classification=intent_analysis,
            as_of_date=as_of_date,
            temporal_audit=temporal_audit,
            rag_gate_status=gate["rag_gate_status"],
            should_conclude=gate["should_conclude"],
            counsel_escalation_required=gate["counsel_escalation_required"],
            escalation_reasons=gate["escalation_reasons"],
            payroll_handoff_allowed=gate["payroll_handoff_allowed"],
            missing_facts=gate["missing_facts"],
            clarification_questions=gate["clarification_questions"],
            normative_bucket=linked_norm,
            interpretation_bucket=linked_interp,
            precedent_bucket=linked_prec,
            autonomous_norm_bucket=linked_auto,
            historical_context_bucket=linked_hist,
            excluded_unverified_notices=excluded_notices,
            evidence_bindings=ev_bindings,
            quarantined_evidence_mismatches=quarantined_mismatches,
            unverified_disclosure_message=gate["unverified_disclosure_message"],
            out_of_domain_message=gate["out_of_domain_message"],
            citation_whitelist=citation_whitelist,
            pipeline_audit_trail=tuple(audit_trail),
            bundle_sha256=bundle_sha,
        )

    @staticmethod
    def _build_citation_whitelist(
        *,
        rag_gate_status: str,
        normative_bucket: tuple[RankedEvidenceItem, ...],
        interpretation_bucket: tuple[RankedEvidenceItem, ...],
        precedent_bucket: tuple[RankedEvidenceItem, ...],
        autonomous_norm_bucket: tuple[RankedEvidenceItem, ...],
        historical_context_bucket: tuple[RankedEvidenceItem, ...],
        evidence_bindings: Any,
    ) -> CitationWhitelist:
        if rag_gate_status in {GATE_ABSTAIN_OUT_OF_DOMAIN, GATE_ABSTAIN_INSUFFICIENT_EVIDENCE}:
            return CitationWhitelist()

        prov_ids: list[str] = []
        src_ids: list[str] = []
        prec_ids: list[str] = []
        rule_ids: list[str] = []
        urls: list[str] = []
        ev_ids: list[str] = []
        aud_ids: list[str] = []

        for item in (*normative_bucket, *interpretation_bucket, *autonomous_norm_bucket):
            if item.chunk.provision_id not in prov_ids:
                prov_ids.append(item.chunk.provision_id)
            if item.chunk.source_id not in src_ids:
                src_ids.append(item.chunk.source_id)
            if item.source_url and item.source_url not in urls:
                urls.append(item.source_url)
            if item.audit_log_id and item.audit_log_id not in aud_ids:
                aud_ids.append(item.audit_log_id)
            for r in item.companion_rules:
                if r.rule_id not in rule_ids:
                    rule_ids.append(r.rule_id)

        for item in precedent_bucket:
            pid = str(item.precedent_metadata.get("precedent_id") or item.chunk.source_id)
            if pid not in prec_ids:
                prec_ids.append(pid)
            if item.source_url and item.source_url not in urls:
                urls.append(item.source_url)
            if item.audit_log_id and item.audit_log_id not in aud_ids:
                aud_ids.append(item.audit_log_id)

        for b in evidence_bindings:
            if b.bucket != BUCKET_HISTORICAL_CONTEXT and b.evidence_id and b.evidence_id not in ev_ids:
                ev_ids.append(b.evidence_id)

        hist_only_srcs = tuple(
            dict.fromkeys(
                item.chunk.source_id
                for item in historical_context_bucket
                if item.chunk.source_id not in src_ids
            )
        )
        return CitationWhitelist(
            allowed_provision_ids=tuple(prov_ids),
            allowed_source_ids=tuple(src_ids),
            allowed_precedent_ids=tuple(prec_ids),
            allowed_rule_ids=tuple(rule_ids),
            allowed_source_urls=tuple(urls),
            allowed_evidence_ids=tuple(ev_ids),
            allowed_audit_log_ids=tuple(aud_ids),
            historical_only_source_ids=hist_only_srcs,
        )
