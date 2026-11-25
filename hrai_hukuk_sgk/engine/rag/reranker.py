"""Stage 4 CrossReferenceExpander (max_depth=1) & norm-hierarchy-aware LegalDomainReranker."""

from __future__ import annotations

import re
from typing import Any

from ..knowledge_base.chunker import tokenize_legal_text, tr_fold
from ..knowledge_base.models import (
    DOC_KIND_AUTONOMOUS_NORM,
    DOC_KIND_INTERPRETATION_CARD,
    DOC_KIND_JUDICIAL_PRECEDENT,
    DOC_KIND_SECONDARY_REGULATION,
    DOC_KIND_STATUTORY_PROVISION,
    VERIFICATION_VERIFIED,
    InterpretationAndBoundaryRule,
    LegalSearchChunk,
    SearchHit,
)
from ..knowledge_base.quality_gate import verify_chunk_runtime_integrity
from ..knowledge_base.store import LocalDeterministicHybridStore, _is_chunk_active_as_of
from .models import (
    BUCKET_AUTONOMOUS_NORM,
    BUCKET_HISTORICAL_CONTEXT,
    BUCKET_INTERPRETATION_BOUNDARY,
    BUCKET_NORMATIVE,
    BUCKET_PRECEDENT,
    QueryIntentAnalysis,
    RankedEvidenceItem,
)

_LAW_QUERY_RE = re.compile(r"\b(\d{3,5})\b")
_ART_CLAUSE_RE = re.compile(r"\b(?:m\.|madde\s*)(\d+)(?:/([ivxlcdm]+))?(?:[-–/\s]+([a-z]))?\b", re.IGNORECASE)
_CORPUS_REG_TOKENS = ("yönetmelik", "tebliğ", "genelge")

_PRECEDENT_BINDING_WEIGHT: dict[str, float] = {
    "STATUTORY_BINDING_YIBBGK": 1.00,
    "STATUTORY_BINDING_DANISTAY_IBK": 1.00,
    "HGK_PERSUASIVE": 0.75,
    "DANISTAY_IDDK_PERSUASIVE": 0.75,
    "CHAMBER_SETTLED": 0.50,
    "DANISTAY_DAIRE_SETTLED": 0.50,
    "CHAMBER_ISOLATED": 0.20,
    "DANISTAY_ISOLATED": 0.20,
}

_CANONICAL_CROSS_REF_ALIASES: dict[str, tuple[str, ...]] = {
    "1475:m-14": ("1475:m-14:f-1", "CARD-1475-M14", "SRC:MEVZUAT-1475"),
    "7036:m-3": ("7036:m-3:f-1", "CARD-7036-M03", "SRC:MEVZUAT-7036"),
}

_LEX_SPECIALIS_LAWS: frozenset[str] = frozenset({"4857", "5510", "6331", "6356", "7036", "1475"})


class CrossReferenceExpander:
    """Bounded 1-hop statutory cross-reference expansion preserving strict date & quality gates."""

    def expand_one_hop(
        self,
        *,
        normative_hits: list[SearchHit],
        store: LocalDeterministicHybridStore,
        as_of_date: str,
        seed_limit: int = 3,
    ) -> list[tuple[SearchHit, str]]:
        """Return deduplicated list of `(SearchHit, origin)` combining primaries + active 1-hop cross-refs."""
        results: list[tuple[SearchHit, str]] = []
        seen_chunk_ids: set[str] = set()
        seen_prov_versions: set[tuple[str, str]] = set()

        for h in normative_hits:
            if h.chunk.chunk_id not in seen_chunk_ids:
                results.append((h, "PRIMARY_SEARCH"))
                seen_chunk_ids.add(h.chunk.chunk_id)
                seen_prov_versions.add((h.chunk.provision_id, h.chunk.document_version_id))

        # 1-hop expansion from top `seed_limit` hits ONLY (never unbounded multi-hop graph walk)
        for seed in normative_hits[:seed_limit]:
            refs = tuple(seed.chunk.metadata.get("cross_reference_ids") or ())
            for raw_ref in refs:
                ref_candidates = self._resolve_candidate_provision_ids(raw_ref)
                for chunk in store._active_chunks.values():
                    if chunk.document_kind not in {DOC_KIND_STATUTORY_PROVISION, DOC_KIND_SECONDARY_REGULATION}:
                        continue
                    if chunk.provision_id not in ref_candidates:
                        continue
                    if chunk.chunk_id in seen_chunk_ids:
                        continue
                    if chunk.verification_status != VERIFICATION_VERIFIED or not chunk.content_verified:
                        continue
                    ok_int, _ = verify_chunk_runtime_integrity(chunk)
                    if not ok_int:
                        continue
                    if not _is_chunk_active_as_of(chunk, as_of_date):
                        continue

                    companions = store.get_rules_for_provision(chunk.provision_id, as_of_date)
                    exp_hit = SearchHit(
                        rank=len(results) + 1,
                        rrf_score=max(0.010, seed.rrf_score * 0.72),
                        vector_score=max(0.05, seed.vector_score * 0.70),
                        lexical_score=max(1.0, seed.lexical_score * 0.60),
                        chunk=chunk,
                        is_historical_context=False,
                        companion_rules=companions,
                    )
                    results.append((exp_hit, "CROSS_REF_EXPANSION"))
                    seen_chunk_ids.add(chunk.chunk_id)
                    seen_prov_versions.add((chunk.provision_id, chunk.document_version_id))
                    break

        return results

    @staticmethod
    def _resolve_candidate_provision_ids(ref_id: str) -> tuple[str, ...]:
        aliases = _CANONICAL_CROSS_REF_ALIASES.get(ref_id, ())
        return (ref_id, *aliases)


class LegalDomainReranker:
    """Bucket-isolated deterministic reranker upholding Anayasa norm hierarchy & court separation."""

    def rerank_normative_bucket(
        self,
        hits_with_origin: list[tuple[SearchHit, str]],
        *,
        query_text: str,
        intent_analysis: QueryIntentAnalysis,
        resolve_audit_fn: Any,
        resolve_url_fn: Any,
    ) -> tuple[RankedEvidenceItem, ...]:
        if not hits_with_origin:
            return ()

        q_fold = tr_fold(query_text)
        q_laws = set(_LAW_QUERY_RE.findall(q_fold))
        q_arts = _ART_CLAUSE_RE.findall(q_fold)
        asks_general_civil = any(w in q_fold for w in ("6098", "tbk", "ibra", "ceza koşulu", "cezai şart", "rekabet yasağı", "420", "444"))
        explicitly_asks_subordinate = any(tok in q_fold for tok in _CORPUS_REG_TOKENS)

        scored: list[tuple[float, RankedEvidenceItem]] = []
        for hit, origin in hits_with_origin:
            ch = hit.chunk
            norm_rrf = min(1.0, hit.rrf_score / 0.0328)
            clause_sc = self._clause_match_score(ch, q_laws=q_laws, q_arts=q_arts)
            hierarchy_sc = max(0.0, (10 - min(9, int(ch.norm_priority))) / 9.0)
            lex_spec = self._lex_specialis_bonus(ch, asks_general_civil=asks_general_civil)
            origin_penalty = 0.08 if origin == "CROSS_REF_EXPANSION" else 0.0

            # Enforce hierarchy supremacy so subordinate regulations/circulars do not bury primary statutory anchors
            # unless the query explicitly names that subordinate regulation/communique number/type.
            if (
                not explicitly_asks_subordinate
                and ch.norm_priority >= 6
                and ch.law_no not in q_laws
                and q_laws
            ):
                hierarchy_sc *= 0.25

            rerank_sc = (
                0.34 * norm_rrf
                + 0.34 * clause_sc
                + 0.24 * hierarchy_sc
                + 0.08 * lex_spec
                - origin_penalty
            )
            flags: list[str] = []
            if ch.norm_layer == "PRESIDENTIAL_DECISION":
                flags.append("NORM_LAYER_CK_PRESIDENTIAL_DECISION_NOT_CBK")
            if ch.norm_layer == "STATUTORY_LAW":
                flags.append("NORM_LAYER_STATUTORY_LAW")

            item = RankedEvidenceItem(
                bucket=BUCKET_NORMATIVE,
                rank=0,
                rerank_score=rerank_sc,
                base_rrf_score=hit.rrf_score,
                vector_score=hit.vector_score,
                lexical_score=hit.lexical_score,
                clause_match_score=clause_sc,
                hierarchy_score=hierarchy_sc,
                lex_specialis_bonus=lex_spec,
                precedent_binding_weight=0.0,
                anchor_overlap_score=0.0,
                post_amendment_penalty=0.0,
                origin=origin,
                source_url=resolve_url_fn(ch),
                audit_log_id=resolve_audit_fn(ch),
                evidence_binding_status="PENDING_EVIDENCE_LINK",
                chunk=ch,
                companion_rules=hit.companion_rules,
                precedent_metadata={},
                flags=tuple(flags),
            )
            scored.append((rerank_sc, item))

        # Sort with strict deterministic tie-breakers
        scored.sort(key=lambda pair: (-pair[0], pair[1].chunk.norm_priority, pair[1].chunk.chunk_id))
        return tuple(
            RankedEvidenceItem(**{**item.__dict__, "rank": idx})
            for idx, (_, item) in enumerate(scored, start=1)
        )

    def rerank_interpretation_bucket(
        self,
        *,
        card_hits: list[SearchHit],
        normative_items: tuple[RankedEvidenceItem, ...],
        store: LocalDeterministicHybridStore,
        resolve_audit_fn: Any,
        resolve_url_fn: Any,
    ) -> tuple[RankedEvidenceItem, ...]:
        norm_prov_ids = {item.chunk.provision_id for item in normative_items}
        norm_src_ids = {item.chunk.source_id for item in normative_items}
        by_chunk_id: dict[str, RankedEvidenceItem] = {}

        def _register_candidate(hit: SearchHit, origin: str) -> None:
            ch = hit.chunk
            if ch.chunk_id in by_chunk_id:
                return
            anchor_bonus = 0.25 if (ch.provision_id in norm_prov_ids or ch.source_id in norm_src_ids) else 0.0
            norm_rrf = min(1.0, hit.rrf_score / 0.0328)
            rerank_sc = 0.65 * norm_rrf + anchor_bonus + (0.10 if len(hit.companion_rules) > 0 else 0.0)
            by_chunk_id[ch.chunk_id] = RankedEvidenceItem(
                bucket=BUCKET_INTERPRETATION_BOUNDARY,
                rank=0,
                rerank_score=rerank_sc,
                base_rrf_score=hit.rrf_score,
                vector_score=hit.vector_score,
                lexical_score=hit.lexical_score,
                clause_match_score=anchor_bonus,
                hierarchy_score=max(0.0, (10 - min(9, int(ch.norm_priority))) / 9.0),
                lex_specialis_bonus=0.0,
                precedent_binding_weight=0.0,
                anchor_overlap_score=anchor_bonus,
                post_amendment_penalty=0.0,
                origin=origin,
                source_url=resolve_url_fn(ch),
                audit_log_id=resolve_audit_fn(ch),
                evidence_binding_status="PENDING_EVIDENCE_LINK",
                chunk=ch,
                companion_rules=hit.companion_rules,
                precedent_metadata={},
                flags=("INTERPRETATION_AND_BOUNDARY_ONLY",),
            )

        for hit in card_hits:
            _register_candidate(hit, "PRIMARY_SEARCH")

        # Also extract verified interpretation/abstention chunks directly anchored to active Bucket 1 provisions!
        rule_ids_anchored: set[str] = {
            r.rule_id for item in normative_items for r in item.companion_rules
        }
        if norm_prov_ids or rule_ids_anchored:
            for ch in store._active_chunks.values():
                if ch.document_kind != DOC_KIND_INTERPRETATION_CARD:
                    continue
                if ch.verification_status != VERIFICATION_VERIFIED or not ch.content_verified:
                    continue
                ch_rule_id = ch.metadata.get("rule_id")
                if ch.provision_id in norm_prov_ids or (ch_rule_id and ch_rule_id in rule_ids_anchored):
                    synth_hit = SearchHit(
                        rank=1,
                        rrf_score=0.025,
                        vector_score=0.50,
                        lexical_score=4.0,
                        chunk=ch,
                        is_historical_context=False,
                        companion_rules=store.get_rules_for_provision(ch.provision_id, ch.effective_from),
                    )
                    _register_candidate(synth_hit, "COMPANION_RULE_EXTRACT")

        ranked = sorted(
            by_chunk_id.values(),
            key=lambda item: (-item.rerank_score, item.chunk.chunk_id),
        )
        return tuple(
            RankedEvidenceItem(**{**item.__dict__, "rank": idx})
            for idx, item in enumerate(ranked, start=1)
        )

    def rerank_precedent_bucket(
        self,
        precedent_hits: list[SearchHit],
        *,
        normative_items: tuple[RankedEvidenceItem, ...],
        query_text: str,
        resolve_audit_fn: Any,
        resolve_url_fn: Any,
    ) -> tuple[RankedEvidenceItem, ...]:
        if not precedent_hits:
            return ()

        q_fold = tr_fold(query_text)
        active_norm_tokens: set[str] = set()
        for item in normative_items:
            if item.chunk.law_no:
                active_norm_tokens.add(item.chunk.law_no)
            if item.chunk.provision_id:
                active_norm_tokens.update(tokenize_legal_text(item.chunk.provision_id))

        scored: list[tuple[float, RankedEvidenceItem]] = []
        seen_chunk_ids: set[str] = set()
        for hit in precedent_hits:
            ch = hit.chunk
            if ch.chunk_id in seen_chunk_ids:
                continue
            seen_chunk_ids.add(ch.chunk_id)
            meta = ch.metadata or {}
            binding_level = str(meta.get("binding_level") or "")
            court_system = str(meta.get("court_system") or "")
            post_status = str(meta.get("post_decision_amendment_status") or "UNAFFECTED")

            binding_wt = _PRECEDENT_BINDING_WEIGHT.get(binding_level, 0.30)
            interpreted_refs = tuple(meta.get("interpreted_provision_ids") or ())
            anchor_tokens = set(tokenize_legal_text(" ".join(interpreted_refs)))
            overlap = len(anchor_tokens & active_norm_tokens) / max(1, len(anchor_tokens)) if anchor_tokens and active_norm_tokens else 0.0
            amendment_penalty = 0.35 if post_status != "UNAFFECTED" else 0.0
            norm_rrf = min(1.0, hit.rrf_score / 0.0328)
            case_match_bonus = 0.25 if (
                str(meta.get("esas_no") or "").lower() in q_fold
                or str(meta.get("karar_no") or "").lower() in q_fold
            ) else 0.0

            rerank_sc = 0.40 * norm_rrf + 0.30 * binding_wt + 0.20 * overlap + case_match_bonus - amendment_penalty
            flags: list[str] = [
                "NON_LEGISLATIVE_JUDICIAL_PRECEDENT",
                f"COURT_SYSTEM_{court_system or 'UNKNOWN'}",
            ]
            if binding_level == "STATUTORY_BINDING_YIBBGK":
                binding_basis = "2797 s. Kanun m.45 (Kanuni Bağlayıcı YİBBGK)"
            elif binding_level == "STATUTORY_BINDING_DANISTAY_IBK":
                binding_basis = "2575 s. Danıştay Kanunu m.39 (Kanuni Bağlayıcı İBK)"
            else:
                binding_basis = "İkna Edici / Yerleşik İçtihat (Kanun Hükmünde Değildir)"

            if post_status != "UNAFFECTED":
                flags.append("COUNSEL_REVIEW_REQUIRED_POST_DECISION_AMENDMENT")
            if binding_level in {"CHAMBER_ISOLATED", "DANISTAY_ISOLATED"}:
                flags.append("ISOLATED_PRECEDENT_COUNSEL_REVIEW")

            precedent_meta = {
                "precedent_id": meta.get("precedent_id") or ch.source_id,
                "court_system": court_system,
                "chamber": meta.get("chamber"),
                "binding_level": binding_level,
                "binding_statutory_basis": binding_basis,
                "is_non_legislative": True,
                "is_statutorily_binding": bool(meta.get("is_statutorily_binding", False)),
                "requires_application_rationale": bool(meta.get("requires_application_rationale", True)),
                "esas_no": meta.get("esas_no"),
                "karar_no": meta.get("karar_no"),
                "interpreted_provision_ids": list(interpreted_refs),
                "applies_to": list(meta.get("applies_to") or ()),
                "does_not_apply_to": list(meta.get("does_not_apply_to") or ()),
                "post_decision_amendment_status": post_status,
                "official_source_url": meta.get("official_source_url") or resolve_url_fn(ch),
            }

            item = RankedEvidenceItem(
                bucket=BUCKET_PRECEDENT,
                rank=0,
                rerank_score=rerank_sc,
                base_rrf_score=hit.rrf_score,
                vector_score=hit.vector_score,
                lexical_score=hit.lexical_score,
                clause_match_score=case_match_bonus,
                hierarchy_score=0.0,  # Explicitly never placed on statutory hierarchy ladder
                lex_specialis_bonus=0.0,
                precedent_binding_weight=binding_wt,
                anchor_overlap_score=overlap,
                post_amendment_penalty=amendment_penalty,
                origin="PRIMARY_SEARCH",
                source_url=str(precedent_meta["official_source_url"]),
                audit_log_id=resolve_audit_fn(ch),
                evidence_binding_status="PENDING_EVIDENCE_LINK",
                chunk=ch,
                companion_rules=(),
                precedent_metadata=precedent_meta,
                flags=tuple(flags),
            )
            scored.append((rerank_sc, item))

        scored.sort(key=lambda pair: (-pair[0], -pair[1].precedent_binding_weight, pair[1].chunk.chunk_id))
        return tuple(
            RankedEvidenceItem(**{**item.__dict__, "rank": idx})
            for idx, (_, item) in enumerate(scored, start=1)
        )

    def wrap_autonomous_or_historical_hits(
        self,
        hits: list[SearchHit],
        *,
        bucket: str,
        resolve_audit_fn: Any,
        resolve_url_fn: Any,
    ) -> tuple[RankedEvidenceItem, ...]:
        out: list[RankedEvidenceItem] = []
        seen: set[str] = set()
        for idx, hit in enumerate(hits, start=1):
            ch = hit.chunk
            if ch.chunk_id in seen:
                continue
            seen.add(ch.chunk_id)
            flags: tuple[str, ...] = (
                ("HISTORICAL_SUPERSEDED_OR_REPEALED_NOT_CURRENT",)
                if bucket == BUCKET_HISTORICAL_CONTEXT
                else (
                    ("COMPANY_ADOPTED_COUNSEL_VERIFIED",)
                    if ch.adoption_status == "COMPANY_ADOPTED_COUNSEL_VERIFIED"
                    else ("UNADOPTED_TEMPLATE",)
                )
            )
            out.append(
                RankedEvidenceItem(
                    bucket=bucket,
                    rank=idx,
                    rerank_score=hit.rrf_score,
                    base_rrf_score=hit.rrf_score,
                    vector_score=hit.vector_score,
                    lexical_score=hit.lexical_score,
                    clause_match_score=0.0,
                    hierarchy_score=max(0.0, (10 - min(9, int(ch.norm_priority))) / 9.0),
                    lex_specialis_bonus=0.0,
                    precedent_binding_weight=0.0,
                    anchor_overlap_score=0.0,
                    post_amendment_penalty=0.0,
                    origin="PRIMARY_SEARCH",
                    source_url=resolve_url_fn(ch),
                    audit_log_id=resolve_audit_fn(ch),
                    evidence_binding_status="PENDING_EVIDENCE_LINK",
                    chunk=ch,
                    companion_rules=hit.companion_rules,
                    precedent_metadata={},
                    flags=flags,
                )
            )
        return tuple(out)

    @staticmethod
    def _clause_match_score(
        ch: LegalSearchChunk,
        *,
        q_laws: set[str],
        q_arts: list[tuple[str, str, str]],
    ) -> float:
        score = 0.0
        if ch.law_no and str(ch.law_no) in q_laws:
            score += 0.30
        if q_arts:
            hay = tr_fold(f"{ch.provision_id} {ch.context_header} {ch.raw_text}")
            prov_low = ch.provision_id.lower()
            rom_map = {"i": "f-1", "ii": "f-2", "iii": "f-3", "iv": "f-4"}
            for art_num, f_rom, b_let in q_arts:
                if f"m-{art_num}" in prov_low or f"madde {art_num}" in hay or f"m.{art_num}" in hay:
                    score += 0.35
                    if not ch.provision_id.startswith("SRC:"):
                        score += 0.05
                    if f_rom:
                        expected_f = rom_map.get(f_rom.lower(), f"f-{f_rom.lower()}")
                        if expected_f in prov_low:
                            score += 0.20
                        elif any(other in prov_low for other in ("f-1", "f-2", "f-3", "f-4") if other != expected_f):
                            score -= 0.15
                    if b_let:
                        if f"b-{b_let.lower()}" in prov_low:
                            score += 0.15
                        elif re.search(r"b-[a-z]", prov_low):
                            score -= 0.15
        return max(0.0, min(1.0, score))

    @staticmethod
    def _lex_specialis_bonus(ch: LegalSearchChunk, *, asks_general_civil: bool) -> float:
        law = str(ch.law_no or "")
        if asks_general_civil:
            return 1.0 if law == "6098" else (0.3 if law in _LEX_SPECIALIS_LAWS else 0.0)
        return 1.0 if law in _LEX_SPECIALIS_LAWS else 0.0
