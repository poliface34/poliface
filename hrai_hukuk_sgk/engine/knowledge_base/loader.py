"""Unified WP-4.2 Knowledge Base loader bridging existing L1–L6 registries/cards & extended structured corpus."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..autonomous_norms import load_l5_hr_procedures, load_l6_cba_contract_practices
from ..knowledge_card_validator import load_knowledge_cards
from ..models import NORM_LAYER_PRIORITY, LegalKnowledgeCard, LegalSourceRecord, PrecedentRecord
from ..precedent_verifier import load_precedent_registry
from ..source_validator import load_source_registry
from .chunker import LegalStructuralChunker
from .models import (
    DOC_KIND_AUTONOMOUS_NORM,
    DOC_KIND_INTERPRETATION_CARD,
    DOC_KIND_JUDICIAL_PRECEDENT,
    DOC_KIND_SECONDARY_REGULATION,
    DOC_KIND_STATUTORY_PROVISION,
    VERIFICATION_SUPERSEDED,
    VERIFICATION_VERIFIED,
    AbstentionBoundary,
    InterpretationAndBoundaryRule,
    JudicialPrecedentNode,
    LegalDocumentVersion,
    LegalProvisionNode,
    LegalSearchChunk,
    TrustChainEvidenceAdapterProtocol,
    canonical_kb_sha256,
    is_valid_kb_sha256,
)
from .store import LocalDeterministicHybridStore

DEFAULT_EXTENDED_CORPUS_PATH = Path(__file__).resolve().parent / "data" / "wp42_extended_corpus.json"

_SECONDARY_SOURCE_TYPES: frozenset[str] = frozenset(
    {
        "PRESIDENTIAL_DECREE",
        "PRESIDENTIAL_DECISION",
        "REGULATION",
        "GIB_COMMUNIQUE",
        "SGK_CIRCULAR",
    }
)


def _source_sha256(src: LegalSourceRecord) -> str:
    if src.verification_audit and is_valid_kb_sha256(src.verification_audit.retrieved_content_sha256):
        return str(src.verification_audit.retrieved_content_sha256)
    if is_valid_kb_sha256(src.content_sha256):
        return str(src.content_sha256)
    return canonical_kb_sha256(src.to_dict())


def _precedent_sha256(prec: PrecedentRecord) -> str:
    ft = prec.full_text_verification or {}
    if is_valid_kb_sha256(ft.get("retrieved_content_sha256")):
        return str(ft["retrieved_content_sha256"])
    if prec.verification_audit and is_valid_kb_sha256(prec.verification_audit.retrieved_content_sha256):
        return str(prec.verification_audit.retrieved_content_sha256)
    return canonical_kb_sha256(prec.to_dict())


def _source_doc_kind(src: LegalSourceRecord) -> str:
    if src.source_type in _SECONDARY_SOURCE_TYPES:
        return DOC_KIND_SECONDARY_REGULATION
    return DOC_KIND_STATUTORY_PROVISION


def _source_is_content_verified(src: LegalSourceRecord) -> bool:
    if src.verification_audit is None:
        return False
    return src.verification_audit.document_fetch_status == "FETCHED_AND_MATCHED"


def _card_is_verified(card: LegalKnowledgeCard, parent_src: LegalSourceRecord | None) -> bool:
    if card.verification_status != VERIFICATION_VERIFIED:
        return False
    if card.effective_validity.get("effective_date_verified") is not True:
        return False
    if card.source_verification.get("status") != VERIFICATION_VERIFIED:
        return False
    if card.legal_interpretation_verification.get("status") != VERIFICATION_VERIFIED:
        return False
    if parent_src is None:
        return False
    if parent_src.verification_status not in {VERIFICATION_VERIFIED, VERIFICATION_SUPERSEDED}:
        return False
    return _source_is_content_verified(parent_src)


def _build_card_abstention_boundary(card: LegalKnowledgeCard) -> AbstentionBoundary:
    blocking: list[str] = ["as_of_date"]
    clarifying: list[str] = ["Olay / değerlendirme tarihi (YYYY-MM-DD) nedir?"]
    escalations: list[str] = []
    prohibitions: list[str] = []

    req_docs_text = " ".join(card.required_documents)
    if "30" in req_docs_text or "kıdem" in req_docs_text.lower():
        blocking.extend(["workplace_total_employees", "tenure_months"])
    if "savunma" in req_docs_text.lower():
        blocking.append("written_defense_status")
    if card.law_no == "6698":
        escalations.append("KVKK özel nitelikli veri veya yurt dışı aktarım (m.9) şüphesinde şirket avukatı eskalasyonu zorunludur.")
    if card.risks:
        escalations.append(f"Öncelikli hukuki risk uyarısı: {card.risks[0]}")
    prohibitions.append("Gerekli belgeler ve hukuki uygunluk teyit edilmeden @ÜcretBordro devri yapılmaz.")

    return AbstentionBoundary(
        blocking_missing_facts=tuple(dict.fromkeys(blocking)),
        clarification_questions=tuple(clarifying),
        mandatory_escalation_triggers=tuple(escalations),
        payroll_handoff_prohibition_conditions=tuple(prohibitions),
        unanswerable_boundary_reason=(
            f"{card.law_no} ({card.article_ref}) kapsamında olay tarihi ve zorunlu belgeler teyit edilmeden kesin sonuç üretilemez."
        ),
    )


def load_wp42_knowledge_base(
    *,
    project_root: str | Path | None = None,
    extended_corpus_path: str | Path | None = None,
    chunker: LegalStructuralChunker | None = None,
    trust_chain_adapter: TrustChainEvidenceAdapterProtocol | None = None,
) -> tuple[LocalDeterministicHybridStore, dict[str, Any]]:
    """Build and verify a complete WP-4.2 `LocalDeterministicHybridStore` from existing codebase core + extended corpus."""
    root = Path(project_root) if project_root is not None else Path(__file__).resolve().parent.parent.parent
    corpus_file = Path(extended_corpus_path) if extended_corpus_path is not None else DEFAULT_EXTENDED_CORPUS_PATH
    kb_chunker = chunker if chunker is not None else LegalStructuralChunker()

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
    l5_mods = load_l5_hr_procedures(root / "rag_kb", sources, cards, precedents, strict=True)
    l6_mods = load_l6_cba_contract_practices(root / "rag_kb", sources, cards, precedents, strict=True)

    ext_raw = json.loads(corpus_file.read_text(encoding="utf-8"))

    store = LocalDeterministicHybridStore(
        embedding_dim=kb_chunker.embedding_dim,
        trust_chain_adapter=trust_chain_adapter,
    )

    doc_versions: list[LegalDocumentVersion] = []
    provisions: list[LegalProvisionNode] = []
    rules: list[InterpretationAndBoundaryRule] = []
    precedent_nodes: list[JudicialPrecedentNode] = []
    chunks: list[LegalSearchChunk] = []

    seen_doc_ver_ids: set[str] = set()
    registered_sources_in_ext: set[str] = set()

    # 1. Extended versioned corpus (multi-version laws + Madde/Fıkra/Bent nodes + AbstentionBoundary rules)
    for raw_dv in ext_raw.get("document_versions", []):
        sid = str(raw_dv["source_id"])
        src_rec = sources.get(sid)
        sha = _source_sha256(src_rec) if src_rec else canonical_kb_sha256(raw_dv)
        dv = LegalDocumentVersion(
            document_version_id=str(raw_dv["document_version_id"]),
            source_id=sid,
            document_kind=str(raw_dv["document_kind"]),
            norm_layer=str(raw_dv["norm_layer"]),
            norm_priority=int(raw_dv["norm_priority"]),
            statute_no=str(raw_dv["statute_no"]),
            title=str(raw_dv["title"]),
            official_gazette_no=str(raw_dv["official_gazette_no"]),
            publication_date=str(raw_dv["publication_date"]),
            effective_from=str(raw_dv["effective_from"]),
            effective_to=raw_dv.get("effective_to"),
            supersedes_version_id=raw_dv.get("supersedes_version_id"),
            content_sha256=sha,
            verification_status=str(raw_dv["verification_status"]),
            document_fetch_status=str(raw_dv["document_fetch_status"]),
            audit_log_id=str(raw_dv["audit_log_id"]),
            source_url=src_rec.source_url if src_rec else "",
            amendment_summary=str(raw_dv.get("amendment_summary", "")),
        )
        doc_versions.append(dv)
        seen_doc_ver_ids.add(dv.document_version_id)
        registered_sources_in_ext.add(sid)

    for raw_p in ext_raw.get("provisions", []):
        sid = str(raw_p["source_id"])
        src_rec = sources.get(sid)
        sha = _source_sha256(src_rec) if src_rec else canonical_kb_sha256(raw_p)
        raw_txt = str(raw_p["raw_text"]).strip()
        prov = LegalProvisionNode(
            provision_id=str(raw_p["provision_id"]),
            document_version_id=str(raw_p["document_version_id"]),
            source_id=sid,
            law_no=str(raw_p["law_no"]),
            article_no=str(raw_p["article_no"]),
            article_title=str(raw_p["article_title"]),
            raw_text=raw_txt,
            normalized_text=" ".join(raw_txt.split()),
            publication_date=str(raw_p["publication_date"]),
            effective_from=str(raw_p["effective_from"]),
            effective_to=raw_p.get("effective_to"),
            norm_layer=str(raw_p["norm_layer"]),
            norm_priority=int(raw_p["norm_priority"]),
            norm_character=str(raw_p["norm_character"]),
            verification_status=str(raw_p["verification_status"]),
            content_sha256=sha,
            chapter_title=str(raw_p.get("chapter_title", "")),
            paragraph_no=raw_p.get("paragraph_no"),
            subparagraph_no=raw_p.get("subparagraph_no"),
            sub_clause_no=raw_p.get("sub_clause_no"),
            hierarchy_path=str(raw_p.get("hierarchy_path", "")),
            document_kind=str(raw_p.get("document_kind", DOC_KIND_STATUTORY_PROVISION)),
            transitional_provision_ref=raw_p.get("transitional_provision_ref"),
            cross_reference_ids=tuple(raw_p.get("cross_reference_ids", [])),
            supersedes_version_id=raw_p.get("supersedes_version_id"),
            source_url=src_rec.source_url if src_rec else "",
            keywords=tuple(raw_p.get("keywords", [])),
        )
        provisions.append(prov)
        chunks.extend(kb_chunker.chunk_provision(prov, content_verified=True))

    for raw_r in ext_raw.get("interpretation_rules", []):
        sid = str(raw_r["source_id"])
        src_rec = sources.get(sid)
        sha = _source_sha256(src_rec) if src_rec else canonical_kb_sha256(raw_r)
        ab_raw = raw_r.get("abstention_boundary") or {}
        rule = InterpretationAndBoundaryRule(
            rule_id=str(raw_r["rule_id"]),
            provision_id=str(raw_r["provision_id"]),
            source_id=sid,
            card_id=raw_r.get("card_id"),
            topic=str(raw_r["topic"]),
            effective_from=str(raw_r["effective_from"]),
            effective_to=raw_r.get("effective_to"),
            verification_status=str(raw_r["verification_status"]),
            how_to_interpret=tuple(raw_r.get("how_to_interpret", [])),
            exceptions=tuple(raw_r.get("exceptions", [])),
            transitional_rules=tuple(raw_r.get("transitional_rules", [])),
            counter_arguments_and_pitfalls=tuple(raw_r.get("counter_arguments_and_pitfalls", [])),
            required_documents=tuple(raw_r.get("required_documents", [])),
            abstention_boundary=AbstentionBoundary(
                blocking_missing_facts=tuple(ab_raw.get("blocking_missing_facts", [])),
                clarification_questions=tuple(ab_raw.get("clarification_questions", [])),
                mandatory_escalation_triggers=tuple(ab_raw.get("mandatory_escalation_triggers", [])),
                payroll_handoff_prohibition_conditions=tuple(ab_raw.get("payroll_handoff_prohibition_conditions", [])),
                unanswerable_boundary_reason=str(ab_raw.get("unanswerable_boundary_reason", "")),
            ),
            related_precedent_ids=tuple(raw_r.get("related_precedent_ids", [])),
            content_sha256=sha,
        )
        rules.append(rule)
        law_no_part = rule.provision_id.split(":")[0]
        chunks.extend(
            kb_chunker.chunk_interpretation_rule(
                rule,
                law_no=law_no_part,
                article_no=rule.provision_id,
                norm_layer="STATUTORY_LAW",
                norm_priority=3,
                document_kind=DOC_KIND_INTERPRETATION_CARD,
                content_verified=True,
                extra_keywords=tuple(rule.topic.lower().split()),
            )
        )

    # 2. Secondary regulations & remaining official sources (e.g. RG-10766-20251225, mülga RG-9368-20241228, PENDING GIB-332)
    for sid, src in sources.items():
        if sid not in registered_sources_in_ext:
            dv_id = f"DV-SRC-{sid}"
            if dv_id not in seen_doc_ver_ids:
                dv = LegalDocumentVersion(
                    document_version_id=dv_id,
                    source_id=sid,
                    document_kind=_source_doc_kind(src),
                    norm_layer=src.norm_layer,
                    norm_priority=src.norm_priority,
                    statute_no=src.statute_number,
                    title=src.source_title,
                    official_gazette_no=src.official_gazette_no,
                    publication_date=src.publication_date,
                    effective_from=src.effective_from,
                    effective_to=src.effective_to,
                    supersedes_version_id=None,
                    content_sha256=_source_sha256(src),
                    verification_status=src.verification_status,
                    document_fetch_status=(
                        src.verification_audit.document_fetch_status if src.verification_audit else "NOT_CHECKED"
                    ),
                    audit_log_id=src.verification_audit.audit_log_id if src.verification_audit else "",
                    source_url=src.source_url,
                )
                doc_versions.append(dv)
                seen_doc_ver_ids.add(dv_id)
                prov_src = LegalProvisionNode(
                    provision_id=f"SRC:{sid}",
                    document_version_id=dv_id,
                    source_id=sid,
                    law_no=src.statute_number,
                    article_no="Genel Düzenleme",
                    article_title=src.source_title,
                    raw_text=f"{src.source_title} ({src.legal_reference}).",
                    normalized_text=f"{src.source_title} ({src.legal_reference}).",
                    publication_date=src.publication_date,
                    effective_from=src.effective_from,
                    effective_to=src.effective_to,
                    norm_layer=src.norm_layer,
                    norm_priority=src.norm_priority,
                    norm_character="ABSOLUTE_MANDATORY",
                    verification_status=src.verification_status,
                    content_sha256=_source_sha256(src),
                    hierarchy_path=f"{src.norm_layer} > {src.source_id}",
                    document_kind=_source_doc_kind(src),
                    source_url=src.source_url,
                    keywords=tuple(src.keywords),
                )
                provisions.append(prov_src)
                chunks.extend(
                    kb_chunker.chunk_provision(
                        prov_src,
                        content_verified=_source_is_content_verified(src),
                    )
                )

    # 3. Existing 39 verified/pending L1–L3 Knowledge Cards (`rag_kb/01..03`)
    for cid, card in cards.items():
        parent_src = sources.get(card.source_id)
        eff = card.effective_validity
        eff_from = str(eff.get("effective_from") or (parent_src.effective_from if parent_src else "2003-06-10"))
        eff_to = eff.get("effective_to")
        sha = _source_sha256(parent_src) if parent_src else canonical_kb_sha256(card.to_dict())
        dv_id = f"DV-SRC-{card.source_id}" if f"DV-SRC-{card.source_id}" in seen_doc_ver_ids else f"DV-{card.source_id}-V1"
        norm_layer = parent_src.norm_layer if parent_src else "STATUTORY_LAW"
        norm_prio = NORM_LAYER_PRIORITY.get(norm_layer, 6)
        doc_kind = _source_doc_kind(parent_src) if parent_src else DOC_KIND_INTERPRETATION_CARD
        card_ok = _card_is_verified(card, parent_src)

        card_prov = LegalProvisionNode(
            provision_id=cid,
            document_version_id=dv_id,
            source_id=card.source_id,
            law_no=card.law_no,
            article_no=card.article_ref,
            article_title=card.topic,
            raw_text=card.scope_of_application,
            normalized_text=" ".join(card.scope_of_application.split()),
            publication_date=parent_src.publication_date if parent_src else eff_from,
            effective_from=eff_from,
            effective_to=eff_to,
            norm_layer=norm_layer,
            norm_priority=norm_prio,
            norm_character=card.norm_character,
            verification_status=card.verification_status,
            content_sha256=sha,
            hierarchy_path=f"{card.law_no} > {card.article_ref} > {cid}",
            document_kind=DOC_KIND_INTERPRETATION_CARD,
            source_url=str(card.legal_basis.get("consolidated_text_url") or (parent_src.source_url if parent_src else "")),
            keywords=tuple(card.keywords) + (card.law_no, card.article_ref),
        )
        provisions.append(card_prov)
        chunks.extend(kb_chunker.chunk_provision(card_prov, content_verified=card_ok))

        rule = InterpretationAndBoundaryRule(
            rule_id=f"RULE-FROM-{cid}",
            provision_id=cid,
            source_id=card.source_id,
            card_id=cid,
            topic=card.topic,
            effective_from=eff_from,
            effective_to=eff_to,
            verification_status=VERIFICATION_VERIFIED if card_ok else card.verification_status,
            how_to_interpret=card.application_scenarios,
            exceptions=card.exceptions,
            counter_arguments_and_pitfalls=card.risks,
            required_documents=card.required_documents,
            abstention_boundary=_build_card_abstention_boundary(card),
            related_precedent_ids=card.related_precedent_ids,
            legal_interpretation_verification=card.legal_interpretation_verification,
            content_sha256=sha,
        )
        rules.append(rule)
        chunks.extend(
            kb_chunker.chunk_interpretation_rule(
                rule,
                law_no=card.law_no,
                article_no=card.article_ref,
                norm_layer=norm_layer,
                norm_priority=norm_prio,
                document_kind=DOC_KIND_INTERPRETATION_CARD,
                content_verified=card_ok,
                extra_keywords=tuple(card.keywords),
            )
        )

    # 4. Jurisprudence Pool (config/yargitay_precedents.json + extended pending Danıştay entries — strictly separated!)
    for pid, prec in precedents.items():
        ft_ok = (prec.full_text_verification or {}).get("status") == "FETCHED_AND_MATCHED"
        op_ok = (prec.operative_holding or {}).get("verified_against_gazette") is True
        sc_ok = (prec.scope_limitations_detail or {}).get("verified_by_legal_review") is True
        prec_verified = prec.verification_status == VERIFICATION_VERIFIED and ft_ok and op_ok and sc_ok
        anchors = tuple((prec.scope_limitations_detail or {}).get("statutory_anchors", ())) or tuple(prec.related_source_ids)
        applies_to = tuple((prec.scope_limitations_detail or {}).get("applies_to", ())) or (prec.legal_principle,)
        does_not = tuple((prec.scope_limitations_detail or {}).get("does_not_apply_to", ())) or (prec.scope_limitations,)
        pnode = JudicialPrecedentNode(
            precedent_id=pid,
            court_system="AYM" if prec.chamber == "AYM" else "YARGITAY",
            chamber=prec.chamber,
            binding_level=prec.binding_level,
            esas_no=prec.esas_no,
            karar_no=prec.karar_no,
            decision_date=prec.decision_date,
            official_source_url=prec.official_source_url,
            interpreted_provision_ids=anchors,
            legal_principle=prec.legal_principle,
            operative_holding=str((prec.operative_holding or {}).get("text") or prec.legal_principle),
            applies_to=applies_to,
            does_not_apply_to=does_not,
            verification_status=prec.verification_status,
            content_sha256=_precedent_sha256(prec),
            official_gazette_no=prec.official_gazette_no,
            requires_application_rationale=(prec.binding_level != "STATUTORY_BINDING_YIBBGK"),
            conflicting_precedent_ids=prec.conflicting_precedent_ids,
            keywords=prec.keywords,
        )
        precedent_nodes.append(pnode)
        chunks.extend(kb_chunker.chunk_precedent(pnode, content_verified=prec_verified))

    for raw_pend in ext_raw.get("pending_unverified_quarantine_samples", []):
        p_sha = canonical_kb_sha256(raw_pend)
        pend_prec = JudicialPrecedentNode(
            precedent_id=str(raw_pend["source_id"]),
            court_system=str(raw_pend["court_system"]),
            chamber=str(raw_pend["chamber"]),
            binding_level=str(raw_pend["binding_level"]),
            esas_no=str(raw_pend["esas_no"]),
            karar_no=str(raw_pend["karar_no"]),
            decision_date=str(raw_pend["decision_date"]),
            official_source_url=str(raw_pend["official_source_url"]),
            interpreted_provision_ids=(str(raw_pend["provision_id"]),),
            legal_principle=str(raw_pend.get("note", "Bekleyen içtihat kaydı.")),
            operative_holding="Tam metin doğrulaması bekleniyor.",
            applies_to=("Doğrulanmadı",),
            does_not_apply_to=("Aktif kaynak olarak kullanılamaz",),
            verification_status=str(raw_pend["verification_status"]),
            content_sha256=p_sha,
            keywords=("danıştay", "pending"),
        )
        precedent_nodes.append(pend_prec)
        chunks.extend(kb_chunker.chunk_precedent(pend_prec, content_verified=False))

    # 5. L5 & L6 Autonomous Norms (strictly isolated with REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION)
    for mod in (*l5_mods.values(), *l6_mods.values()):
        for r in mod.rules:
            r_sha = canonical_kb_sha256(r.to_dict())
            auto_prov = LegalProvisionNode(
                provision_id=r.rule_id,
                document_version_id=f"DV-AUTO-{mod.module_id}",
                source_id=r.source_document_id,
                law_no="L5_L6",
                article_no=r.rule_id,
                article_title=r.title,
                raw_text=f"{r.rule_summary} ({r.norm_type} | adoption_status={r.adoption_status})",
                normalized_text=r.rule_summary,
                publication_date="2026-11-24",
                effective_from="2026-11-24",
                effective_to=None,
                norm_layer="CBA_CONTRACT_AND_HR_PROCEDURE",
                norm_priority=8,
                norm_character="RELATIVE_EMPLOYEE_FAVORABLE",
                verification_status=VERIFICATION_VERIFIED,
                content_sha256=r_sha,
                hierarchy_path=f"{r.layer_id} > {mod.module_id} > {r.rule_id}",
                document_kind=DOC_KIND_AUTONOMOUS_NORM,
                cross_reference_ids=r.legal_basis_ids,
                adoption_status=r.adoption_status,
                keywords=(r.norm_type.lower(), mod.layer_id.lower(), r.title.lower()),
            )
            provisions.append(auto_prov)
            chunks.extend(kb_chunker.chunk_provision(auto_prov, content_verified=True))

    summary = store.upsert_bundle(
        document_versions=doc_versions,
        provisions=provisions,
        rules=rules,
        precedents=precedent_nodes,
        chunks=chunks,
    )
    return store, summary
