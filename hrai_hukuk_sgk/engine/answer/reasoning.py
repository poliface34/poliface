"""Stage 3 AnswerLegalReasoningEngine enforcing Evidence vs Interpretation separation (WP-4.4)."""

from __future__ import annotations

import re
from typing import Any

from ..autonomous_norms import evaluate_autonomous_norm_conflict
from ..knowledge_base.chunker import tr_fold
from ..legal_reasoning import evaluate_hr_legal_scenario
from ..models import (
    VALID_SCENARIO_TYPES,
    LegalBasisItem,
    LegalKnowledgeCard,
    LegalSourceRecord,
    NormReference,
    PrecedentRecord,
)
from ..norm_hierarchy import evaluate_precedent_application, resolve_norm_conflict
from ..rag.models import (
    DOMAIN_LABOR_LAW,
    DOMAIN_PERSONAL_DATA_PROTECTION,
    DOMAIN_SOCIAL_SECURITY,
    INTENT_PAYROLL_DELEGATION_ONLY,
    INTENT_PRECEDENT_CHECK,
    INTENT_PROCEDURE_AND_AUTONOMOUS_NORM,
    RankedEvidenceItem,
    RetrievalTraceBundle,
)
from .models import (
    CLAIM_JUDICIAL_PRECEDENT,
    CLAIM_LEGAL_INTERPRETATION,
    CLAIM_OPERATIONAL_GUIDANCE,
    CLAIM_STATUTORY_EVIDENCE,
    AnswerClaimRecord,
    AnswerReasoningResult,
    TemporalValidationReport,
)

_NORM_LAYER_TURKISH_LABELS: dict[str, str] = {
    "CONSTITUTION": "Anayasa",
    "INTERNATIONAL_TREATY_FUNDAMENTAL_RIGHTS": "Temel Hak Antlaşması (Anayasa m.90/5)",
    "STATUTORY_LAW": "Kanun",
    "INTERNATIONAL_TREATY_GENERAL": "Genel Uluslararası Antlaşma",
    "PRESIDENTIAL_DECREE": "Cumhurbaşkanlığı Kararnamesi",
    "PRESIDENTIAL_DECISION": "Cumhurbaşkanı Kararı",
    "REGULATION": "Yönetmelik",
    "COMMUNIQUE_AND_SGK_CIRCULAR": "Tebliğ / SGK Genelgesi",
    "CBA_CONTRACT_AND_HR_PROCEDURE": "TİS / İş Sözleşmesi / İK Prosedürü",
}

_OFFICIAL_REF_BY_SOURCE_ID: dict[str, str] = {
    "RG-10766-20251225": "10766 Sayılı Cumhurbaşkanı Kararı (2026 Ar-Ge/Teknokent Uzaktan Çalışma)",
    "RG-9368-20241228": "9368 Sayılı Cumhurbaşkanı Kararı (31.12.2025 Tarihli Eski Düzenleme)",
    "RG-7555-20250724": "7555 Sayılı Kanun (m.23 -> 4857 Sayılı Kanun m.109 Yazılı Fesih Bildirimi)",
    "RG-7566-20251219": "7566 Sayılı Kanun (5510 Sayılı Kanun m.82 9 Kat SPEK Tavanı)",
    "MEVZUAT-4857": "4857 Sayılı İş Kanunu",
    "MEVZUAT-1475": "1475 Sayılı İş Kanunu",
    "MEVZUAT-5510": "5510 Sayılı Sosyal Sigortalar ve Genel Sağlık Sigortası Kanunu",
    "MEVZUAT-6098": "6098 Sayılı Türk Borçlar Kanunu",
    "MEVZUAT-6331": "6331 Sayılı İş Sağlığı ve Güvenliği Kanunu",
    "MEVZUAT-6698": "6698 Sayılı Kişisel Verilerin Korunması Kanunu",
    "MEVZUAT-6356": "6356 Sayılı Sendikalar ve Toplu İş Sözleşmesi Kanunu",
    "MEVZUAT-7036": "7036 Sayılı İş Mahkemeleri Kanunu",
    "MEVZUAT-4447": "4447 Sayılı İşsizlik Sigortası Kanunu",
}


def _clean_article_label(item: RankedEvidenceItem) -> str:
    ch = item.chunk
    # Trim noisy headers; build clean human reference matching citation validator rules
    law = str(ch.law_no or "").strip()
    art = str(ch.article_no or "").strip()
    if ch.source_id in _OFFICIAL_REF_BY_SOURCE_ID:
        base = _OFFICIAL_REF_BY_SOURCE_ID[ch.source_id]
        if art and art != "Genel Düzenleme" and art.lower() not in base.lower() and not art.startswith("CARD-"):
            if ":" in art:
                return f"{base} ({ch.provision_id})"
            return f"{base} {art}"
        return base
    layer_tr = _NORM_LAYER_TURKISH_LABELS.get(ch.norm_layer, ch.norm_layer)
    if law and law.isdigit() and art and art.startswith("Madde"):
        return f"{law} Sayılı Kanun {art}"
    if law and law.isdigit():
        return f"{law} Sayılı {layer_tr}"
    return ch.provision_id or ch.source_id


def _binding_map_by_chunk(trace_bundle: RetrievalTraceBundle) -> dict[str, Any]:
    return {b.chunk_id: b for b in trace_bundle.evidence_bindings}


class AnswerLegalReasoningEngine:
    """Builds separated Statutory Evidence, Judicial Precedent, Interpretation, and Operational layers."""

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

    def reason(
        self,
        *,
        trace_bundle: RetrievalTraceBundle,
        temporal_report: TemporalValidationReport,
        facts: dict[str, Any],
        scenario_type: str | None = None,
        precedent_application_rationale: str = "",
        competing_norm: NormReference | None = None,
    ) -> AnswerReasoningResult:
        as_of_date = temporal_report.as_of_date or ""
        wl = trace_bundle.citation_whitelist
        if not temporal_report.date_valid or (
            not wl.allowed_source_ids and not wl.allowed_precedent_ids
        ):
            # When CitationWhitelist is empty (OUT_OF_DOMAIN / INSUFFICIENT_EVIDENCE / missing date),
            # NEVER emit active statutory, precedent, or interpretation claims.
            return AnswerReasoningResult(
                historical_context=tuple(
                    LegalBasisItem(
                        source_id=item.chunk.source_id,
                        legal_reference=_clean_article_label(item),
                        verification_status="SUPERSEDED"
                        if item.chunk.verification_status == "SUPERSEDED"
                        else "VERIFIED",
                        effective_on_date=False,
                        note=f"[TARİHSEL BAĞLAM] {item.chunk.context_header}",
                    )
                    for item in temporal_report.historical_context_items
                ),
            )

        bindings_by_chunk = _binding_map_by_chunk(trace_bundle)
        claim_counter = 0

        def _next_id(prefix: str) -> str:
            nonlocal claim_counter
            claim_counter += 1
            return f"CLM-{prefix}-{claim_counter:03d}"

        statutory_claims: list[AnswerClaimRecord] = []
        precedent_claims: list[AnswerClaimRecord] = []
        interpretation_claims: list[AnswerClaimRecord] = []
        operational_claims: list[AnswerClaimRecord] = []
        legal_bases: list[LegalBasisItem] = []
        historical_context: list[LegalBasisItem] = []
        precedent_assessments: list[dict[str, Any]] = []
        norm_conflicts: list[dict[str, Any]] = []
        exceptions_list: list[str] = []
        counter_args: list[str] = []
        required_docs: list[str] = []
        esc_flags: list[str] = []
        has_conflict = False

        seen_basis_keys: set[tuple[str, str | None, str | None]] = set()

        # 1. STATUTORY_EVIDENCE layer (Normative bucket ONLY, strictly in whitelist & effective_on_date=True)
        for item in temporal_report.active_normative_items:
            ch = item.chunk
            if not wl.contains_source(ch.source_id) or not wl.contains_provision(ch.provision_id):
                continue
            b_rec = bindings_by_chunk.get(ch.chunk_id)
            legal_ref = _clean_article_label(item)
            layer_tr = _NORM_LAYER_TURKISH_LABELS.get(ch.norm_layer, ch.norm_layer)
            stmt = (
                f"[{layer_tr} | Öncelik {ch.norm_priority} | Yürürlük: {ch.effective_from}.."
                f"{ch.effective_to or 'GÜNCEL'}] {legal_ref}: {ch.raw_text}"
            )
            statutory_claims.append(
                AnswerClaimRecord(
                    claim_id=_next_id("STAT"),
                    section_name="mevzuat_dayanagi",
                    claim_category=CLAIM_STATUTORY_EVIDENCE,
                    statement=stmt,
                    provision_id=ch.provision_id,
                    source_id=ch.source_id,
                    precedent_id=None,
                    rule_id=None,
                    chunk_id=ch.chunk_id,
                    article_ref=ch.article_no,
                    law_no=ch.law_no,
                    source_url=item.source_url,
                    audit_log_id=item.audit_log_id,
                    content_sha256=ch.content_sha256,
                    chunk_sha256=ch.chunk_sha256,
                    evidence_id=b_rec.evidence_id if b_rec else ch.evidence_id,
                    registry_head_sha256=b_rec.registry_head_sha256 if b_rec else None,
                    effective_from=ch.effective_from,
                    effective_to=ch.effective_to,
                    effective_on_date=True,
                )
            )
            bkey = (ch.source_id, ch.provision_id, None)
            if bkey not in seen_basis_keys:
                seen_basis_keys.add(bkey)
                legal_bases.append(
                    LegalBasisItem(
                        source_id=ch.source_id,
                        legal_reference=f"{legal_ref} ({ch.provision_id})",
                        verification_status=ch.verification_status,
                        effective_on_date=True,
                        note=f"Yürürlük aralığı {ch.effective_from}..{ch.effective_to or 'GÜNCEL'} | {ch.context_header}",
                    )
                )

        # Optional deterministic norm conflict resolution against competing norm
        if competing_norm is not None and temporal_report.active_normative_items:
            top_norm_ch = temporal_report.active_normative_items[0].chunk
            norm_a = NormReference(
                title=_clean_article_label(temporal_report.active_normative_items[0]),
                norm_layer=top_norm_ch.norm_layer,
                precedent_level="NONE",
                source_id=top_norm_ch.source_id,
            )
            mand_type = str((top_norm_ch.metadata or {}).get("norm_character") or "RELATIVE_EMPLOYEE_FAVORABLE")
            if mand_type not in {"RELATIVE_EMPLOYEE_FAVORABLE", "ABSOLUTE_MANDATORY", "DISPOSITIVE"}:
                mand_type = "RELATIVE_EMPLOYEE_FAVORABLE"
            fav_side = str(facts.get("favors_employee_side") or "NORM_B")
            if fav_side not in {"NORM_A", "NORM_B", "NEUTRAL", "UNKNOWN"}:
                fav_side = "UNKNOWN"
            treaty_nat = str(facts.get("treaty_provision_nature") or "UNSPECIFIED")
            nc_res = resolve_norm_conflict(
                norm_a=norm_a,
                norm_b=competing_norm,
                mandatory_type=mand_type,
                favors_employee_side=fav_side,
                treaty_provision_nature=treaty_nat,
            )
            norm_conflicts.append(nc_res.to_dict())
            if nc_res.requires_counsel_escalation or nc_res.winning_side == "UNRESOLVED_ESCALATE":
                has_conflict = True
                esc_flags.append(f"NORM_CONFLICT_ESCALATION:{nc_res.rule_applied}")

        # 2. JUDICIAL_PRECEDENT layer (never legislative tier!)
        seen_prec_ids: set[str] = set()
        for item in temporal_report.validated_precedent_items:
            ch = item.chunk
            pmeta = item.precedent_metadata or {}
            pid = str(pmeta.get("precedent_id") or ch.source_id)
            if not wl.contains_precedent(pid):
                continue
            b_rec = bindings_by_chunk.get(ch.chunk_id)

            esas = pmeta.get("esas_no") or ""
            karar = pmeta.get("karar_no") or ""
            binding_level = str(pmeta.get("binding_level") or "")
            court_sys = str(pmeta.get("court_system") or "YARGITAY")
            binding_basis = str(pmeta.get("binding_statutory_basis") or "Yargısal içtihat (kanun değildir)")
            applies_to = tuple(pmeta.get("applies_to") or ())
            does_not_apply = tuple(pmeta.get("does_not_apply_to") or ())
            post_status = str(pmeta.get("post_decision_amendment_status") or "UNAFFECTED")

            # Run full engine precedent verification once per unique precedent_id when in central registry
            if pid not in seen_prec_ids:
                seen_prec_ids.add(pid)
                reg_prec = self._precedents.get(pid)
                if reg_prec is not None:
                    if reg_prec.verification_status == "CONFLICTING" or reg_prec.conflicting_precedent_ids:
                        has_conflict = True
                        esc_flags.append(f"CONFLICTING_PRECEDENT_ESCALATE:{pid}")
                    rel_src = next(
                        (self._sources[sid] for sid in reg_prec.related_source_ids if sid in self._sources),
                        None,
                    )
                    if rel_src is not None:
                        scope_st = str(facts.get("precedent_scope_match_status") or ("IN_SCOPE" if facts else "UNCERTAIN"))
                        if scope_st not in {"IN_SCOPE", "OUT_OF_SCOPE", "UNCERTAIN"}:
                            scope_st = "UNCERTAIN"
                        pa = evaluate_precedent_application(
                            precedent=reg_prec,
                            interpreted_source=rel_src,
                            as_of_date=as_of_date,
                            scope_match_status=scope_st,
                            competing_norm=competing_norm,
                            application_rationale=precedent_application_rationale,
                        )
                        precedent_assessments.append(pa.to_dict())
                        if pa.requires_counsel_escalation and (
                            pa.rationale_requirement_status == "MISSING_PERSUASIVE_PRECEDENT_RATIONALE"
                            or bool(pa.post_decision_amendments)
                            or reg_prec.binding_level == "CHAMBER_ISOLATED"
                        ):
                            has_conflict = True
                            esc_flags.append(f"PRECEDENT_COUNSEL_REVIEW:{pid}:{pa.rationale_requirement_status}")
                else:
                    # Handle synthetic/Danıştay precedent nodes cleanly via chunk metadata
                    req_rat = bool(pmeta.get("requires_application_rationale", True))
                    if post_status != "UNAFFECTED":
                        has_conflict = True
                        esc_flags.append(f"PRECEDENT_POST_DECISION_AMENDMENT:{pid}")
                    elif binding_level in {"CHAMBER_ISOLATED", "DANISTAY_ISOLATED"}:
                        has_conflict = True
                        esc_flags.append(f"ISOLATED_PRECEDENT_ESCALATE:{pid}")
                    elif binding_level not in {"STATUTORY_BINDING_YIBBGK", "STATUTORY_BINDING_DANISTAY_IBK"} and req_rat and len(precedent_application_rationale.strip()) < 25:
                        esc_flags.append(f"MISSING_PERSUASIVE_PRECEDENT_RATIONALE:{pid}")

                    precedent_assessments.append(
                        {
                            "precedent_id": pid,
                            "court_system": court_sys,
                            "binding_level": binding_level,
                            "binding_basis": binding_basis,
                            "esas_no": esas,
                            "karar_no": karar,
                            "applies_to": list(applies_to),
                            "does_not_apply_to": list(does_not_apply),
                            "post_decision_amendment_status": post_status,
                            "requires_counsel_escalation": post_status != "UNAFFECTED"
                            or binding_level in {"CHAMBER_ISOLATED", "DANISTAY_ISOLATED"},
                        }
                    )

            scope_note = f"Uygulandığı Haller: {'; '.join(applies_to)} | Kapsam Dışı: {'; '.join(does_not_apply)}"
            prec_stmt = (
                f"[{court_sys} İÇTİHADI — KANUN HÜKMÜNDE DEĞİLDİR | {binding_basis} | "
                f"E. {esas}, K. {karar} ({pid})] {ch.raw_text} ({scope_note})"
            )
            precedent_claims.append(
                AnswerClaimRecord(
                    claim_id=_next_id("PREC"),
                    section_name="hukuki_degerlendirme",
                    claim_category=CLAIM_JUDICIAL_PRECEDENT,
                    statement=prec_stmt,
                    provision_id=ch.provision_id,
                    source_id=ch.source_id,
                    precedent_id=pid,
                    rule_id=None,
                    chunk_id=ch.chunk_id,
                    article_ref=None,
                    law_no=None,
                    source_url=item.source_url,
                    audit_log_id=item.audit_log_id,
                    content_sha256=ch.content_sha256,
                    chunk_sha256=ch.chunk_sha256,
                    evidence_id=b_rec.evidence_id if b_rec else ch.evidence_id,
                    registry_head_sha256=b_rec.registry_head_sha256 if b_rec else None,
                    effective_from=ch.effective_from,
                    effective_to=None,
                    effective_on_date=True,
                )
            )

        # 3. LEGAL_INTERPRETATION layer (interpretation cards + companion rules + L5/L6)
        from ..precedent_verifier import (
            LAW_CITATION_RE,
            PRESIDENTIAL_DECISION_CITATION_RE,
            PRESIDENTIAL_DECREE_CITATION_RE,
            TEBLIG_CITATION_RE,
        )
        from ..source_validator import parse_iso_date

        target_dt = parse_iso_date(as_of_date) if as_of_date else None

        def _mentions_future_statute(txt: str) -> bool:
            if not txt or target_dt is None or not self._sources:
                return False
            by_num: dict[str, list[LegalSourceRecord]] = {}
            for s in self._sources.values():
                by_num.setdefault(s.statute_number, []).append(s)
            for pat in (
                PRESIDENTIAL_DECISION_CITATION_RE,
                PRESIDENTIAL_DECREE_CITATION_RE,
                TEBLIG_CITATION_RE,
                LAW_CITATION_RE,
            ):
                for m in pat.finditer(txt):
                    num = m.group("num")
                    cands = by_num.get(num, [])
                    if not cands:
                        continue
                    has_active_or_past = any(
                        (parse_iso_date(c.effective_from) is not None and parse_iso_date(c.effective_from) <= target_dt)
                        for c in cands
                    )
                    if not has_active_or_past:
                        return True
            return False

        top_norm_provs = {item.chunk.provision_id for item in temporal_report.active_normative_items[:5]}
        top_norm_srcs = {item.chunk.source_id for item in temporal_report.active_normative_items[:5]}
        relevant_interp_items = tuple(
            item
            for idx, item in enumerate(temporal_report.active_interpretation_items)
            if (idx == 0 and not temporal_report.active_normative_items)
            or item.rerank_score >= 0.55
            or item.chunk.provision_id in top_norm_provs
            or item.chunk.source_id in top_norm_srcs
            or trace_bundle.intent_classification.intent == INTENT_PROCEDURE_AND_AUTONOMOUS_NORM
        )

        seen_rules: set[str] = set()
        for item in (*temporal_report.active_normative_items, *relevant_interp_items):
            b_rec = bindings_by_chunk.get(item.chunk.chunk_id)
            for rule in item.companion_rules:
                if rule.rule_id in seen_rules:
                    continue
                if wl.allowed_rule_ids and rule.rule_id not in wl.allowed_rule_ids:
                    continue
                seen_rules.add(rule.rule_id)

                for sc in rule.how_to_interpret:
                    txt = (
                        f"[YORUM — {rule.topic}] Koşul: {sc.get('condition', '')} -> "
                        f"Kural: {sc.get('legal_rule', '')} ({sc.get('statutory_basis', '')})"
                    )
                    if _mentions_future_statute(txt):
                        continue
                    interpretation_claims.append(
                        AnswerClaimRecord(
                            claim_id=_next_id("INTP"),
                            section_name="hukuki_degerlendirme",
                            claim_category=CLAIM_LEGAL_INTERPRETATION,
                            statement=txt,
                            provision_id=rule.provision_id,
                            source_id=rule.source_id,
                            precedent_id=None,
                            rule_id=rule.rule_id,
                            chunk_id=item.chunk.chunk_id,
                            article_ref=item.chunk.article_no,
                            law_no=item.chunk.law_no,
                            source_url=item.source_url,
                            audit_log_id=item.audit_log_id,
                            content_sha256=item.chunk.content_sha256,
                            chunk_sha256=item.chunk.chunk_sha256,
                            evidence_id=b_rec.evidence_id if b_rec else item.chunk.evidence_id,
                            registry_head_sha256=b_rec.registry_head_sha256 if b_rec else None,
                            effective_from=rule.effective_from,
                            effective_to=rule.effective_to,
                            effective_on_date=True,
                        )
                    )
                for exc in rule.exceptions:
                    if not _mentions_future_statute(exc) and exc not in exceptions_list:
                        exceptions_list.append(exc)
                for tr in rule.transitional_rules:
                    tr_note = (
                        f"Geçiş Hükmü ({tr.get('cutoff_date', '')}): Öncesi={tr.get('pre_cutoff_rule', '')} | "
                        f"Sonrası={tr.get('post_cutoff_rule', '')}"
                    )
                    if not _mentions_future_statute(tr_note) and tr_note not in exceptions_list:
                        exceptions_list.append(tr_note)
                for pit in rule.counter_arguments_and_pitfalls:
                    if not _mentions_future_statute(pit) and pit not in counter_args:
                        counter_args.append(pit)
                for doc in rule.required_documents:
                    if doc not in required_docs:
                        required_docs.append(doc)

        # Standalone interpretation card summary chunks not having companion_rules attached
        for item in relevant_interp_items:
            ch = item.chunk
            if not item.companion_rules and wl.contains_source(ch.source_id) and wl.contains_provision(ch.provision_id):
                if _mentions_future_statute(ch.raw_text):
                    continue
                b_rec = bindings_by_chunk.get(ch.chunk_id)
                interpretation_claims.append(
                    AnswerClaimRecord(
                        claim_id=_next_id("INTP"),
                        section_name="hukuki_degerlendirme",
                        claim_category=CLAIM_LEGAL_INTERPRETATION,
                        statement=f"[BİLGİ KARTI YORUMU — {ch.provision_id}] {ch.raw_text}",
                        provision_id=ch.provision_id,
                        source_id=ch.source_id,
                        precedent_id=None,
                        rule_id=ch.metadata.get("rule_id"),
                        chunk_id=ch.chunk_id,
                        article_ref=ch.article_no,
                        law_no=ch.law_no,
                        source_url=item.source_url,
                        audit_log_id=item.audit_log_id,
                        content_sha256=ch.content_sha256,
                        chunk_sha256=ch.chunk_sha256,
                        evidence_id=b_rec.evidence_id if b_rec else ch.evidence_id,
                        registry_head_sha256=b_rec.registry_head_sha256 if b_rec else None,
                        effective_from=ch.effective_from,
                        effective_to=ch.effective_to,
                        effective_on_date=True,
                    )
                )

        # L5 / L6 Autonomous Norms (adopted vs template pending company adoption)
        for item in temporal_report.active_autonomous_items:
            ch = item.chunk
            if not wl.contains_source(ch.source_id) or not wl.contains_provision(ch.provision_id):
                continue
            b_rec = bindings_by_chunk.get(ch.chunk_id)
            l_res = evaluate_autonomous_norm_conflict(
                {
                    "rule_id": ch.provision_id,
                    "title": ch.context_header,
                    "norm_type": ch.metadata.get("norm_type", "INTERNAL_REGULATION"),
                    "adoption_status": ch.adoption_status or "REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION",
                    "rule_summary": ch.raw_text,
                    "legal_basis_ids": ch.metadata.get("cross_reference_ids", []),
                },
                proposed_change_direction=str(facts.get("proposed_change_direction") or "NEUTRAL_CLARIFICATION"),
                written_employee_consent_4857_m22=bool(facts.get("written_employee_consent_4857_m22", False)),
            )
            interpretation_claims.append(
                AnswerClaimRecord(
                    claim_id=_next_id("L56"),
                    section_name="hukuki_degerlendirme",
                    claim_category=CLAIM_LEGAL_INTERPRETATION,
                    statement=f"[ÖZERKNORM ({ch.adoption_status})] {ch.raw_text} — {l_res.explanation}",
                    provision_id=ch.provision_id,
                    source_id=ch.source_id,
                    precedent_id=None,
                    rule_id=ch.provision_id,
                    chunk_id=ch.chunk_id,
                    article_ref=ch.article_no,
                    law_no=None,
                    source_url=item.source_url,
                    audit_log_id=item.audit_log_id,
                    content_sha256=ch.content_sha256,
                    chunk_sha256=ch.chunk_sha256,
                    evidence_id=b_rec.evidence_id if b_rec else ch.evidence_id,
                    registry_head_sha256=b_rec.registry_head_sha256 if b_rec else None,
                    effective_from=ch.effective_from,
                    effective_to=ch.effective_to,
                    effective_on_date=True,
                )
            )
            if l_res.requires_counsel_escalation:
                esc_flags.append(f"AUTONOMOUS_NORM_ESCALATION:{ch.provision_id}")

        # Warn explicitly when unadopted L5/L6 templates were excluded
        has_m22_whitelisted = any(pid.startswith("4857:m-22") for pid in wl.allowed_provision_ids)
        allow_m22_notice = has_m22_whitelisted
        for notice in trace_bundle.excluded_unverified_notices:
            if notice.status == "REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION":
                consent_clause = (
                    "işçi aleyhine değişikliklerde 4857 m.22 yazılı rıza zorunludur."
                    if allow_m22_notice
                    else "çalışma koşullarında işçi aleyhine esaslı değişikliklerde yazılı rıza şartı saklıdır."
                )
                msg = (
                    f"L5/L6 Şablon Sınırı ({notice.source_id} / {notice.record_id}): "
                    f"REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION nedeniyle bağlayıcı şirket politikası sayılmaz; "
                    f"{consent_clause}"
                )
                if msg not in exceptions_list:
                    exceptions_list.append(msg)

        # Optional deterministic scenario enrichment (strictly gated by CitationWhitelist!)
        resolved_scenario = self._infer_scenario_type(scenario_type, trace_bundle)
        if resolved_scenario and self._sources and self._cards and facts:
            try:
                scen_eval = evaluate_hr_legal_scenario(
                    scenario_type=resolved_scenario,
                    facts=facts,
                    as_of_date=as_of_date,
                    source_registry=self._sources,
                    precedent_registry=self._precedents,
                    knowledge_cards=self._cards,
                )
                for ca in scen_eval.counter_arguments:
                    if ca not in counter_args:
                        counter_args.append(ca)
                if scen_eval.human_approval.counsel_escalation_required:
                    for rsn in scen_eval.human_approval.reasons:
                        if rsn not in esc_flags:
                            esc_flags.append(rsn)
            except Exception:
                # Non-blocking enrichment: whitelist-grounded RAG reasoning always governs
                pass

        # 4. HISTORICAL CONTEXT strictly marked effective_on_date=False
        seen_hist_keys: set[tuple[str, str]] = set()
        for item in temporal_report.historical_context_items:
            ch = item.chunk
            hkey = (ch.source_id, ch.document_version_id)
            if hkey in seen_hist_keys:
                continue
            seen_hist_keys.add(hkey)
            ref_txt = _clean_article_label(item)
            hist_note = (
                f"[TARİHSEL BAĞLAM — {as_of_date} tarihinde yürürlükte değildir / mülga veya eski düzenleme; "
                f"geçerlilik: {ch.effective_from}..{ch.effective_to or 'YÜRÜRLÜK_DIŞI'}] {ch.context_header}"
            )
            historical_context.append(
                LegalBasisItem(
                    source_id=ch.source_id,
                    legal_reference=ref_txt,
                    verification_status="SUPERSEDED" if ch.verification_status == "SUPERSEDED" else "VERIFIED",
                    effective_on_date=False,
                    note=hist_note,
                )
            )

        # 5. OPERATIONAL_GUIDANCE steps (strictly non-statutory, zero monetary computation)
        anchor_item = (
            temporal_report.active_normative_items[0]
            if temporal_report.active_normative_items
            else (
                temporal_report.active_interpretation_items[0]
                if temporal_report.active_interpretation_items
                else None
            )
        )
        anchor_sid = anchor_item.chunk.source_id if anchor_item else None
        anchor_prov = anchor_item.chunk.provision_id if anchor_item else None
        anchor_cid = anchor_item.chunk.chunk_id if anchor_item else None
        anchor_url = anchor_item.source_url if anchor_item else ""
        anchor_aud = anchor_item.audit_log_id if anchor_item else "AUD-OPERATIONAL-GUIDANCE"
        anchor_sha = anchor_item.chunk.content_sha256 if anchor_item else None

        if required_docs:
            operational_claims.append(
                AnswerClaimRecord(
                    claim_id=_next_id("OPER"),
                    section_name="uygulama",
                    claim_category=CLAIM_OPERATIONAL_GUIDANCE,
                    statement=f"[OPERASYONEL ÖNERİ] Özlük/Belge Kontrol Listesi: {'; '.join(required_docs[:5])}.",
                    provision_id=anchor_prov,
                    source_id=anchor_sid,
                    precedent_id=None,
                    rule_id=None,
                    chunk_id=anchor_cid,
                    article_ref=None,
                    law_no=None,
                    source_url=anchor_url,
                    audit_log_id=anchor_aud,
                    content_sha256=anchor_sha,
                    chunk_sha256=anchor_item.chunk.chunk_sha256 if anchor_item else None,
                    evidence_id=None,
                    registry_head_sha256=None,
                    effective_from=as_of_date or None,
                    effective_to=None,
                    effective_on_date=True,
                )
            )

        payroll_summary: str | None = None
        if trace_bundle.intent_classification.intent == INTENT_PAYROLL_DELEGATION_ONLY or trace_bundle.payroll_handoff_allowed:
            if trace_bundle.payroll_handoff_allowed and not esc_flags and not has_conflict:
                payroll_summary = (
                    "@ÜcretBordro Devri Uygun: Parasal brüt/net hesaplama @HukukSGK tarafından yapılmaz; "
                    "yalnızca hukuki ön koşullar doğrulanmış olup bordro hesaplama paketi @ÜcretBordro ajanına devredilebilir."
                )
            else:
                payroll_summary = (
                    "@ÜcretBordro Devri Kilitli: Eksik olgu veya hukuki eskalasyon giderilmeden parasal hesaplama "
                    "için @ÜcretBordro devri yapılamaz."
                )
            operational_claims.append(
                AnswerClaimRecord(
                    claim_id=_next_id("OPER"),
                    section_name="uygulama",
                    claim_category=CLAIM_OPERATIONAL_GUIDANCE,
                    statement=f"[OPERASYONEL ÖNERİ] {payroll_summary}",
                    provision_id=anchor_prov,
                    source_id=anchor_sid,
                    precedent_id=None,
                    rule_id=None,
                    chunk_id=anchor_cid,
                    article_ref=None,
                    law_no=None,
                    source_url=anchor_url,
                    audit_log_id=anchor_aud,
                    content_sha256=anchor_sha,
                    chunk_sha256=anchor_item.chunk.chunk_sha256 if anchor_item else None,
                    evidence_id=None,
                    registry_head_sha256=None,
                    effective_from=as_of_date or None,
                    effective_to=None,
                    effective_on_date=True,
                )
            )

        return AnswerReasoningResult(
            statutory_claims=tuple(statutory_claims),
            precedent_claims=tuple(precedent_claims),
            interpretation_claims=tuple(interpretation_claims),
            operational_claims=tuple(operational_claims),
            legal_bases=tuple(legal_bases),
            historical_context=tuple(historical_context),
            precedent_assessments=tuple(precedent_assessments),
            norm_conflict_resolutions=tuple(norm_conflicts),
            exceptions_and_conditions=tuple(exceptions_list),
            counter_arguments=tuple(counter_args),
            required_documents=tuple(required_docs),
            escalation_flags=tuple(dict.fromkeys(esc_flags)),
            has_conflicting_precedent_or_norm=has_conflict,
            matched_scenario_type=resolved_scenario,
            payroll_handoff_summary=payroll_summary,
        )

    @staticmethod
    def _infer_scenario_type(explicit: str | None, bundle: RetrievalTraceBundle) -> str | None:
        if explicit in VALID_SCENARIO_TYPES:
            return explicit
        q = tr_fold(bundle.query_text)
        dom = bundle.intent_classification.primary_domain
        if bundle.intent_classification.intent == INTENT_PROCEDURE_AND_AUTONOMOUS_NORM:
            return "EMPLOYEE_FAVORABLE_NORM_COMPARISON"
        if bundle.intent_classification.intent == INTENT_PAYROLL_DELEGATION_ONLY:
            return "SEVERANCE_AND_NOTICE"
        if any(w in q for w in ("fesih", "işten çıkar", "m.25", "m.26", "m.19", "m.109", "savunma")):
            return "TERMINATION_VALIDITY"
        if any(w in q for w in ("işe iade", "7036")):
            return "REINSTATEMENT_CLAIM"
        if any(w in q for w in ("kıdem", "ihbar")):
            return "SEVERANCE_AND_NOTICE"
        if any(w in q for w in ("fazla çalışma", "fazla mesai", "m.41")):
            return "OVERTIME_COMPLIANCE"
        if any(w in q for w in ("yıllık izin", "m.53")):
            return "ANNUAL_LEAVE_COMPLIANCE"
        if dom == DOMAIN_SOCIAL_SECURITY or "çıkış kodu" in q:
            return "SGK_EXIT_CODE_AND_UNEMPLOYMENT"
        if dom in {DOMAIN_LABOR_LAW, DOMAIN_PERSONAL_DATA_PROTECTION} and bundle.intent_classification.intent != INTENT_PRECEDENT_CHECK:
            return "TERMINATION_VALIDITY"
        return None
