"""Stage 6 AbstentionEvaluator & fail-closed RAG gate decision engine (WP-4.3)."""

from __future__ import annotations

import re
from typing import Any

from ..knowledge_base.chunker import tr_fold
from ..knowledge_base.models import DOC_KIND_AUTONOMOUS_NORM, ExcludedUnverifiedNotice
from .models import (
    GATE_ABSTAIN_INSUFFICIENT_EVIDENCE,
    GATE_ABSTAIN_MISSING_INFO,
    GATE_ABSTAIN_OUT_OF_DOMAIN,
    GATE_EVIDENCE_READY,
    GATE_EVIDENCE_READY_WITH_ESCALATION,
    INTENT_FACT_SCENARIO_ANALYSIS,
    INTENT_OUT_OF_DOMAIN,
    INTENT_PAYROLL_DELEGATION_ONLY,
    INTENT_PRECEDENT_CHECK,
    INTENT_PROCEDURE_AND_AUTONOMOUS_NORM,
    EvidenceBindingRecord,
    QueryIntentAnalysis,
    RankedEvidenceItem,
    TemporalAuditReport,
)

_FACT_QUESTIONS_TR: dict[str, str] = {
    "as_of_date": "Hukuki değerlendirme yapılacak olay veya fesih tarihi (YYYY-MM-DD) nedir?",
    "notification_channel": "Fesih/bildirim hangi kanalla (ıslak imzalı elden teslim, noter, KEP, e-posta, sözlü) yapılmıştır?",
    "written_notice_with_clear_reason": "Fesih bildirimi yazılı olup fesih sebebi açık ve kesin biçimde belirtilmiş midir?",
    "discovery_date": "Feshe yetkili makam/organ olayı ilk olarak hangi tarihte (YYYY-MM-DD) öğrenmiştir?",
    "incident_date": "Feshe konu fiil/davranış hangi tarihte (YYYY-MM-DD) gerçekleşmiştir?",
    "discovering_authority_status": "Olayı öğrenen kişi feshe yetkili organ/makam (AUTHORIZED_DISMISSAL_BODY) mıdır, yoksa yalnızca amir midir?",
    "weekly_rest_day": "İş sözleşmesi/TİS'teki yasal hafta tatili günü (varsayılan Pazar vb.) hangi gündür?",
    "workplace_total_employees": "İşverenin aynı işkolundaki tüm işyerlerinde çalıştırdığı toplam işçi sayısı (30 işçi eşiği) kaçtır?",
    "tenure_months": "Çalışanın ilgili işyerindeki kıdem süresi kaç ay/yıldır?",
    "written_defense_status": "4857 m.19/2 kapsamında davranış/verim feshi öncesi yazılı savunma alınmış mıdır?",
    "termination_reason_type": "İş sözleşmesinin sona erme/fesih türü (ör. işverence geçerli/haksız fesih, 25/II haklı fesih, istifa, emeklilik) nedir?",
    "alternative_pdks_exists": "Biyometrik PDKS yerine kartlı/mobil/şifreli ölçülü giriş alternatifi mevcut mudur?",
    "cross_border_saas_transfer": "İK/bordro veya özel nitelikli çalışan verileri yurt dışındaki sunuculara aktarılmakta mıdır?",
    "autonomous_norm_adoption_proof": "Söz konusu prosedür/TİS/işyeri uygulaması için imzalı şirket kabulü veya TİS belgesi mevcut mudur?",
    "written_employee_consent_4857_m22": "Çalışma koşullarında işçi aleyhine değişiklik için 4857 m.22 uyarınca 6 iş gününde yazılı rıza alınmış mıdır?",
}

_PENDING_UNVERIFIED_STATUSES: frozenset[str] = frozenset(
    {
        "PENDING_REVIEW",
        "PENDING_LEGAL_REVIEW",
        "UNVERIFIED",
        "REJECTED_CONTENT_MISMATCH",
        "TRANSPORT_ONLY_UNVERIFIED_CONTENT",
        "UNREACHABLE_NOT_VERIFIED",
        "KB_CHUNK_TAMPER_QUARANTINED",
    }
)

_CITED_ID_IN_QUERY_RE = re.compile(r"\b(\d{3,5}|\d{4}/\d+)\b")


def _fact_present(facts: dict[str, Any], key: str) -> bool:
    alias_keys: dict[str, tuple[str, ...]] = {
        "workplace_total_employees": ("workplace_total_employees", "company_size"),
    }
    if key == "written_defense_status":
        if "written_defense_status" in facts:
            val = facts["written_defense_status"]
            if val is not None and not (isinstance(val, str) and val.strip().upper() in {"", "UNKNOWN", "BELIRSIZ", "NA", "NONE"}):
                return True
        return facts.get("defense_taken_before_termination") is not None

    for k in alias_keys.get(key, (key,)):
        if k not in facts:
            continue
        val = facts[k]
        if val is None:
            continue
        if isinstance(val, str):
            norm = val.strip().upper()
            if bool(norm) and norm not in {"UNKNOWN", "BELIRSIZ", "NA", "NONE"}:
                return True
        else:
            return True
    return False


class AbstentionEvaluator:
    """Stage 6 fail-closed gate deciding ABSTAIN_*, EVIDENCE_READY_WITH_ESCALATION, or EVIDENCE_READY."""

    def evaluate(
        self,
        *,
        query_text: str,
        facts: dict[str, Any],
        intent_analysis: QueryIntentAnalysis,
        temporal_audit: TemporalAuditReport,
        normative_bucket: tuple[RankedEvidenceItem, ...],
        interpretation_bucket: tuple[RankedEvidenceItem, ...],
        precedent_bucket: tuple[RankedEvidenceItem, ...],
        autonomous_norm_bucket: tuple[RankedEvidenceItem, ...],
        excluded_unverified_notices: tuple[ExcludedUnverifiedNotice, ...],
        quarantined_evidence_mismatches: tuple[EvidenceBindingRecord, ...],
    ) -> dict[str, Any]:
        # 1. Domain boundary check
        if intent_analysis.intent == INTENT_OUT_OF_DOMAIN:
            return {
                "rag_gate_status": GATE_ABSTAIN_OUT_OF_DOMAIN,
                "should_conclude": False,
                "counsel_escalation_required": True,
                "escalation_reasons": (
                    "OUT_OF_DOMAIN_OR_AV_K_M35_BOUNDARY:"
                    + str(intent_analysis.extracted_entities.get("out_of_domain_reason") or "KAPSAM_DISI"),
                ),
                "payroll_handoff_allowed": False,
                "missing_facts": (),
                "clarification_questions": (),
                "unverified_disclosure_message": None,
                "out_of_domain_message": (
                    "@HukukSGK yalnızca Türkiye İş Hukuku, Sosyal Güvenlik, İSG ve Çalışan KVKK ön incelemesi yapar; "
                    "Avukatlık Kanunu m.35 kapsamındaki dava dilekçesi veya alan dışı ticari/ceza/aile hukuku taleplerini "
                    "yanıtlayamaz ve bu konularda mevzuat/içtihat üretmez."
                ),
            }

        # 2. Temporal date gate
        if not temporal_audit.date_valid or not temporal_audit.as_of_date:
            reason_code = temporal_audit.error_code or "MISSING_AS_OF_DATE"
            msg = (
                "Sorguda birden fazla farklı tarih tespit edildi; kesin olay tarihi belirtilmeden değerlendirme yapılamaz."
                if reason_code == "AMBIGUOUS_MULTIPLE_DATES"
                else "Olay/değerlendirme tarihi (as_of_date) belirtilmediği için bugünün tarihi varsayılmaz ve hukuki hüküm üretilmez."
            )
            return {
                "rag_gate_status": GATE_ABSTAIN_MISSING_INFO,
                "should_conclude": False,
                "counsel_escalation_required": False,
                "escalation_reasons": (),
                "payroll_handoff_allowed": False,
                "missing_facts": ("as_of_date",),
                "clarification_questions": (_FACT_QUESTIONS_TR["as_of_date"],),
                "unverified_disclosure_message": None,
                "out_of_domain_message": msg,
            }

        # 3. Unverified / Tampered / Pending-Only source gate
        unverified_target_notices = self._find_primary_unverified_target_notices(
            query_text=query_text,
            normative_bucket=normative_bucket,
            precedent_bucket=precedent_bucket,
            excluded_unverified_notices=excluded_unverified_notices,
            quarantined_evidence_mismatches=quarantined_evidence_mismatches,
        )
        has_active_primary = bool(normative_bucket) or bool(interpretation_bucket) or bool(autonomous_norm_bucket)
        has_precedent_only_ok = intent_analysis.intent == INTENT_PRECEDENT_CHECK and bool(precedent_bucket)

        if unverified_target_notices:
            ids_str = ", ".join(f"{n.source_id} ({n.status})" for n in unverified_target_notices)
            return {
                "rag_gate_status": GATE_ABSTAIN_INSUFFICIENT_EVIDENCE,
                "should_conclude": False,
                "counsel_escalation_required": True if quarantined_evidence_mismatches else False,
                "escalation_reasons": (
                    ("TRUST_CHAIN_INTEGRITY_MISMATCH_DETECTED",) if quarantined_evidence_mismatches else ()
                ),
                "payroll_handoff_allowed": False,
                "missing_facts": (),
                "clarification_questions": (),
                "unverified_disclosure_message": (
                    f"Talep edilen kaynaklar ({ids_str}) henüz doğrulanmamış/beklemede veya bütünlük kontrolünden "
                    "geçemediği için aktif dayanak olarak kullanılamaz; kesin cevap verilmesinden kaçınıldı."
                ),
                "out_of_domain_message": None,
            }

        if not has_active_primary and not has_precedent_only_ok:
            extra_msg = (
                "Trust Chain SHA-256/ham içerik bütünlüğü uyuşmazlığı nedeniyle aday kanıtlar karantinaya alındı."
                if quarantined_evidence_mismatches
                else "Sorgu ve olay tarihi için doğrulama kapısından geçen aktif hukuki kanıt bulunamadı."
            )
            return {
                "rag_gate_status": GATE_ABSTAIN_INSUFFICIENT_EVIDENCE,
                "should_conclude": False,
                "counsel_escalation_required": bool(quarantined_evidence_mismatches),
                "escalation_reasons": (
                    ("TRUST_CHAIN_INTEGRITY_MISMATCH_DETECTED",) if quarantined_evidence_mismatches else ()
                ),
                "payroll_handoff_allowed": False,
                "missing_facts": (),
                "clarification_questions": (),
                "unverified_disclosure_message": extra_msg,
                "out_of_domain_message": None,
            }

        # 4. Missing Facts Matrix (blocking facts on FACT_SCENARIO / PAYROLL_DELEGATION / AUTONOMOUS_NORM)
        missing_facts: list[str] = []
        clarification_questions: list[str] = []

        def _add_missing(fact_key: str, custom_question: str | None = None) -> None:
            if fact_key == "as_of_date" or _fact_present(facts, fact_key):
                return
            if fact_key not in missing_facts:
                missing_facts.append(fact_key)
            q_text = custom_question or _FACT_QUESTIONS_TR.get(
                fact_key,
                f"'{fact_key}' olgusu hakkında kesin bilgi ve dayanak belgeyi paylaşınız.",
            )
            if q_text not in clarification_questions:
                clarification_questions.append(q_text)

        if intent_analysis.intent == INTENT_FACT_SCENARIO_ANALYSIS:
            q_fold = tr_fold(query_text)
            q_arts = set(intent_analysis.extracted_entities.get("article_refs") or ())
            relevant_rules = self._collect_relevant_boundary_rules(
                normative_bucket=normative_bucket,
                interpretation_bucket=interpretation_bucket,
            )
            top_prov = normative_bucket[0].chunk.provision_id if normative_bucket else ""
            for rule in relevant_rules:
                r_prov = rule.provision_id
                # Only enforce provision-specific blocking_missing_facts when query/top anchor invokes that domain/provision
                if r_prov.startswith("4857:m-22") and top_prov != r_prov and not (
                    "22" in q_arts
                    or any(w in q_fold for w in ("ikramiye", "işyeri uygulaması", "esaslı değişiklik", "tek taraflı", "kesinti", "rızası"))
                ):
                    continue
                if r_prov.startswith("4857:m-26") and top_prov != r_prov and not (
                    "26" in q_arts
                    or "25" in " ".join(q_arts)
                    or any(w in q_fold for w in ("hak düşürücü", "6 iş günü", "altı iş günü", "güveni kötüye", "m.25/ii", "m.26"))
                ):
                    continue
                if r_prov == "4857:m-109" and top_prov != r_prov and not (
                    "109" in q_arts
                    or any(w in q_fold for w in ("fesih", "kep", "bildirim", "işten çıkar", "yazılılık"))
                ):
                    continue
                ab = rule.abstention_boundary
                for bf in ab.blocking_missing_facts:
                    _add_missing(bf)
                # Preserve explicit rule-level clarification questions when triggered
                for bf in ab.blocking_missing_facts:
                    if bf != "as_of_date" and not _fact_present(facts, bf):
                        for cq in ab.clarification_questions:
                            if cq not in clarification_questions:
                                clarification_questions.append(cq)
                        break

        elif intent_analysis.intent == INTENT_PAYROLL_DELEGATION_ONLY:
            # Statutory pre-check for @ÜcretBordro handoff (e.g., 1475 m.14 severance & 4857 m.17 notice)
            _add_missing("termination_reason_type")
            if not _fact_present(facts, "tenure_months") and not re.search(r"\b\d+\s*y[ıi]ll?[ıi]k\b", tr_fold(query_text)):
                _add_missing("tenure_months")

        elif intent_analysis.intent == INTENT_PROCEDURE_AND_AUTONOMOUS_NORM:
            q_fold = tr_fold(query_text)
            is_unilateral_cut = any(w in q_fold for w in ("tek taraflı", "kestik", "kaldır", "düşür", "indirim", "değişiklik"))
            if is_unilateral_cut and not autonomous_norm_bucket:
                _add_missing("written_employee_consent_4857_m22")
                _add_missing("autonomous_norm_adoption_proof")

        if missing_facts:
            return {
                "rag_gate_status": GATE_ABSTAIN_MISSING_INFO,
                "should_conclude": False,
                "counsel_escalation_required": False,
                "escalation_reasons": (),
                "payroll_handoff_allowed": False,
                "missing_facts": tuple(missing_facts),
                "clarification_questions": tuple(clarification_questions[:5]),
                "unverified_disclosure_message": None,
                "out_of_domain_message": None,
            }

        # 5. Mandatory Escalation Triggers -> EVIDENCE_READY_WITH_ESCALATION vs EVIDENCE_READY
        escalation_reasons = self._detect_mandatory_escalations(
            query_text=query_text,
            facts=facts,
            as_of_date=temporal_audit.as_of_date,
            temporal_audit=temporal_audit,
            intent_analysis=intent_analysis,
            normative_bucket=normative_bucket,
            precedent_bucket=precedent_bucket,
            autonomous_norm_bucket=autonomous_norm_bucket,
            excluded_unverified_notices=excluded_unverified_notices,
        )
        if escalation_reasons:
            return {
                "rag_gate_status": GATE_EVIDENCE_READY_WITH_ESCALATION,
                "should_conclude": True,
                "counsel_escalation_required": True,
                "escalation_reasons": escalation_reasons,
                "payroll_handoff_allowed": False,
                "missing_facts": (),
                "clarification_questions": (),
                "unverified_disclosure_message": None,
                "out_of_domain_message": None,
            }

        # 6. EVIDENCE_READY (all facts verified, verified authority intact, zero mandatory escalations)
        q_fold = tr_fold(query_text)
        payroll_calc_terms = ("tazminat", "bordro", "ücret", "kıdem", "ihbar", "maaş", "brüt", "net")
        payroll_allowed = intent_analysis.intent == INTENT_PAYROLL_DELEGATION_ONLY or (
            intent_analysis.intent == INTENT_FACT_SCENARIO_ANALYSIS
            and _fact_present(facts, "termination_reason_type")
            and _fact_present(facts, "tenure_months")
            and any(tok in q_fold for tok in payroll_calc_terms)
        )
        return {
            "rag_gate_status": GATE_EVIDENCE_READY,
            "should_conclude": True,
            "counsel_escalation_required": False,
            "escalation_reasons": (),
            "payroll_handoff_allowed": payroll_allowed,
            "missing_facts": (),
            "clarification_questions": (),
            "unverified_disclosure_message": None,
            "out_of_domain_message": None,
        }

    @staticmethod
    def _find_primary_unverified_target_notices(
        *,
        query_text: str,
        normative_bucket: tuple[RankedEvidenceItem, ...],
        precedent_bucket: tuple[RankedEvidenceItem, ...],
        excluded_unverified_notices: tuple[ExcludedUnverifiedNotice, ...],
        quarantined_evidence_mismatches: tuple[EvidenceBindingRecord, ...],
    ) -> tuple[ExcludedUnverifiedNotice, ...]:
        q_fold = tr_fold(query_text)
        cited_nums = set(_CITED_ID_IN_QUERY_RE.findall(q_fold))
        active_texts = tr_fold(
            " ".join(
                f"{item.chunk.source_id} {item.chunk.provision_id} {item.chunk.context_header} {item.chunk.raw_text}"
                for item in (*normative_bucket, *precedent_bucket)
            )
        )

        # Build synthetic notices for Trust Chain runtime quarantine drops too
        candidates: list[ExcludedUnverifiedNotice] = [
            n for n in excluded_unverified_notices if n.status in _PENDING_UNVERIFIED_STATUSES
        ]
        for q_rec in quarantined_evidence_mismatches:
            candidates.append(
                ExcludedUnverifiedNotice(
                    record_id=q_rec.provision_id,
                    source_id=q_rec.source_id,
                    document_kind=q_rec.document_kind,
                    status=q_rec.failure_reason or "TRUST_CHAIN_INTEGRITY_MISMATCH",
                    reason="Trust Chain SHA-256 / yetki doğrulamasından geçemediği için reddedildi.",
                )
            )

        matched: list[ExcludedUnverifiedNotice] = []
        for notice in candidates:
            if notice.document_kind == DOC_KIND_AUTONOMOUS_NORM:
                continue
            sid_fold = tr_fold(notice.source_id)
            rec_fold = tr_fold(notice.record_id)
            if notice.source_id.lower() in q_fold or any(num in sid_fold or num in rec_fold for num in cited_nums):
                # Check whether an active verified chunk actually satisfies that specific cited number/source
                num_matched_in_active = any(num in active_texts for num in cited_nums if num in sid_fold or num in rec_fold)
                if not num_matched_in_active:
                    matched.append(notice)
        return tuple(matched)

    @staticmethod
    def _collect_relevant_boundary_rules(
        *,
        normative_bucket: tuple[RankedEvidenceItem, ...],
        interpretation_bucket: tuple[RankedEvidenceItem, ...],
    ) -> list[Any]:
        seen_rule_ids: set[str] = set()
        rules: list[Any] = []
        for item in normative_bucket[:3]:
            for rule in item.companion_rules:
                if rule.rule_id not in seen_rule_ids:
                    seen_rule_ids.add(rule.rule_id)
                    rules.append(rule)
        active_provs = {item.chunk.provision_id for item in normative_bucket[:3]}
        for item in interpretation_bucket:
            if item.chunk.provision_id in active_provs:
                for rule in item.companion_rules:
                    if rule.rule_id not in seen_rule_ids:
                        seen_rule_ids.add(rule.rule_id)
                        rules.append(rule)
        return rules

    @staticmethod
    def _detect_mandatory_escalations(
        *,
        query_text: str,
        facts: dict[str, Any],
        as_of_date: str,
        temporal_audit: TemporalAuditReport,
        intent_analysis: QueryIntentAnalysis,
        normative_bucket: tuple[RankedEvidenceItem, ...],
        precedent_bucket: tuple[RankedEvidenceItem, ...],
        autonomous_norm_bucket: tuple[RankedEvidenceItem, ...],
        excluded_unverified_notices: tuple[ExcludedUnverifiedNotice, ...],
    ) -> tuple[str, ...]:
        reasons: list[str] = []
        q_fold = tr_fold(query_text)

        # 1. Post-7555 (24.07.2025+) non-written termination channel trigger
        notif = str(facts.get("notification_channel") or "").strip().upper()
        if as_of_date >= "2025-07-24" and notif in {"KEP_ONLY", "ORAL_OR_DE_FACTO", "EMAIL_OR_SMS"}:
            reasons.append("M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI")

        # 2. 4857 m.26 arife / outside holiday calendar coverage / non-authorized supervisor
        if facts.get("half_day_eve_in_window") is True:
            reasons.append("M26_YARIM_GUN_TATIL_HUKUKI_INCELEME_GEREKLI")
        if str(facts.get("discovering_authority_status") or "").strip().upper() in {
            "NON_AUTHORIZED_SUPERVISOR_ONLY",
            "UNCERTAIN",
        }:
            reasons.append("M26_YETKILI_MAKAM_ESKALASYONU")
        has_m26_scope = any(item.chunk.provision_id == "4857:m-26:f-1" for item in normative_bucket)
        if has_m26_scope and "OUTSIDE_2024_2027_CALENDAR_COVERAGE" in temporal_audit.cutoff_flags:
            reasons.append("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")

        # 3. KVKK m.9 / Biometric PDKS proportionality
        asks_kvkk_m9 = (
            ("6698" in q_fold or "kvkk" in q_fold)
            and any(k in q_fold for k in ("yurt dış", "yurtdış", "madde 9", "m.9", "bulut", "saas"))
        )
        if facts.get("cross_border_saas_transfer") is True or asks_kvkk_m9:
            reasons.append("KVKK_M9_CROSS_BORDER_TRANSFER_GATE_CLOSED")
        if facts.get("biometric_pdks_used") is True:
            reasons.append("KVKK_BIOMETRIC_PROPORTIONALITY_COUNSEL_REVIEW")

        # 3b. 4857 m.19/2 missing written defense in behavior/performance dismissal
        if (
            facts.get("defense_taken_before_termination") is False
            or str(facts.get("written_defense_status") or "").strip().upper() in {"NOT_TAKEN", "NONE", "FALSE"}
        ):
            reasons.append("M19_2_SAVUNMA_ALINMADAN_FESIH_IHLALI")

        # 4. Critical statutory protections
        for flag_key, reason_code in (
            ("union_rep_termination", "CRITICAL_6356_M24_UNION_REP_TERMINATION"),
            ("pregnancy_termination", "CRITICAL_PREGNANCY_MATERNITY_TERMINATION"),
            ("collective_dismissal_m29", "CRITICAL_4857_M29_COLLECTIVE_DISMISSAL"),
        ):
            if facts.get(flag_key) is True:
                reasons.append(reason_code)

        # 5. Judicial precedent amendment / isolated chamber escalation
        for item in precedent_bucket:
            if "COUNSEL_REVIEW_REQUIRED_POST_DECISION_AMENDMENT" in item.flags:
                reasons.append(
                    f"COUNSEL_REVIEW_REQUIRED_POST_DECISION_AMENDMENT:{item.precedent_metadata.get('precedent_id', item.chunk.source_id)}"
                )
            if "ISOLATED_PRECEDENT_COUNSEL_REVIEW" in item.flags:
                reasons.append(
                    f"ISOLATED_PRECEDENT_COUNSEL_REVIEW:{item.precedent_metadata.get('precedent_id', item.chunk.source_id)}"
                )

        # 6. L5/L6 unadopted template notice on procedure queries
        if intent_analysis.intent == INTENT_PROCEDURE_AND_AUTONOMOUS_NORM and not autonomous_norm_bucket:
            if any(n.status == "REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION" for n in excluded_unverified_notices) or "ticaret" not in q_fold:
                reasons.append("REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION")

        return tuple(dict.fromkeys(reasons))
