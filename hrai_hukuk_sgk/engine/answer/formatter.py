"""Stage 6 EightSectionAnswerFormatter enforcing WP-4.1 fixed 8 sections & layer labels (WP-4.4)."""

from __future__ import annotations

from ..rag.models import RetrievalTraceBundle
from .models import (
    CONFIDENCE_DISPLAY_LABELS_TR,
    STANDARD_DISCLAIMER_TR,
    TRUST_CHAIN_LEGAL_BOUNDARY_NOTICE_TR,
    AnswerAbstentionDecision,
    AnswerReasoningResult,
    AnswerRiskAssessmentResult,
    EightSectionAnswer,
    TemporalValidationReport,
)


class EightSectionAnswerFormatter:
    """Formats deterministic 8-section Turkish HR/SGK answers with strict Evidence vs Interpretation separation."""

    def format_draft(
        self,
        *,
        trace_bundle: RetrievalTraceBundle,
        temporal_report: TemporalValidationReport,
        reasoning_result: AnswerReasoningResult,
        risk_result: AnswerRiskAssessmentResult,
        abstention: AnswerAbstentionDecision,
        include_historical_disclosure: bool = True,
        override_section_texts: dict[str, str] | None = None,
    ) -> EightSectionAnswer:
        # 1. Hukuki Sonuç
        if abstention.should_abstain:
            if abstention.status == "ABSTAINED_OUT_OF_DOMAIN":
                sec1 = (
                    f"[YETKİ VE ALAN SINIRI — KESİN CEVAP VERİLMEDİ] {abstention.disclosure_message or ''}"
                ).strip()
            elif abstention.status == "ABSTAINED_MISSING_INFO":
                missing_str = ", ".join(m.field for m in abstention.missing_information) or "eksik olgu"
                sec1 = (
                    f"[EKSİK BİLGİ NEDENİYLE KESİN HÜKÜM VERİLEMEDİ | Olay Tarihi: {temporal_report.as_of_date or 'BELİRTİLMEDİ'}] "
                    f"Zorunlu olgular ({missing_str}) eksik olduğu için somut olaya ilişkin kesin hukuki sonuç üretilememektedir; "
                    f"yalnızca netleştirme soruları yöneltilmiştir."
                )
            elif abstention.status == "ABSTAINED_INSUFFICIENT_EVIDENCE":
                sec1 = (
                    f"[YETERSİZ / DOĞRULANMAMIŞ KAYNAK — CEVAP VERİLMEDİ] {abstention.disclosure_message or ''}"
                ).strip()
            else:
                sec1 = (
                    f"[YÜKSEK RİSK / ÇELİŞKİLİ KAYNAK — OTOMATİK HÜKÜM DURDURULDU | Bilet: {risk_result.escalation_ticket_id or 'ESKALASYON'}] "
                    f"Olay tarihi {temporal_report.as_of_date} itibarıyla çelişkili içtihat/norm veya zorunlu hukuk müşaviri "
                    f"incelemesi gerektiren etkenler bulunduğu için kesin onay verilememektedir."
                )
        elif risk_result.counsel_escalation_required:
            sec1 = (
                f"[ÖN İNCELEME + ZORUNLU AVUKAT ESKALASYONU | Rozet: {risk_result.decision_badge} | "
                f"Risk: {risk_result.overall_risk_level} | Olay Tarihi: {temporal_report.as_of_date}] "
                f"Doğrulanmış kaynaklar ışığında hukuki risk/usul engeli tespit edilmiştir "
                f"({', '.join(risk_result.escalation_reasons)}); şirket avukatı onayı ({risk_result.escalation_ticket_id}) "
                f"olmadan işlem kesinleştirilemez."
            )
        else:
            sec1 = (
                f"[ÖN İNCELEME UYGUN | Rozet: {risk_result.decision_badge} | Risk: {risk_result.overall_risk_level} | "
                f"Olay Tarihi: {temporal_report.as_of_date}] Doğrulanmış mevzuat ve sunulan olgular çerçevesinde ön inceleme "
                f"tamamlanmıştır; uygulama öncesi İK insan onayı gereklidir."
            )

        # 2. Mevzuat Dayanağı (strictly active effective_on_date=True FIRST, historical context separated BELOW)
        if abstention.status == "ABSTAINED_OUT_OF_DOMAIN" or not reasoning_result.legal_bases:
            active_lines = ["Olay tarihinde yürürlükte ve doğrulanmış aktif mevzuat dayanağı bağlanmamıştır."]
        else:
            active_lines = [
                f"- [KANIT | effective_on_date=True] {b.legal_reference} (source_id={b.source_id}) — {b.note}"
                for b in reasoning_result.legal_bases
            ]

        if include_historical_disclosure and reasoning_result.historical_context:
            hist_lines = [
                "\nTarihsel Bağlam (Yürürlük Dışı / Eski Düzenleme — Güncel Dayanak Değildir):"
            ]
            superseding_hint = (
                reasoning_result.legal_bases[0].legal_reference if reasoning_result.legal_bases else "yürürlükteki mevzuat"
            )
            for h in reasoning_result.historical_context:
                hist_lines.append(
                    f"- [TARİHSEL BAĞLAM | effective_on_date=False | mülga / yürürlükten kalkmış eski düzenleme; "
                    f"yerine {superseding_hint} geçmiştir] {h.legal_reference} (source_id={h.source_id}) — {h.note}"
                )
            active_lines.extend(hist_lines)
        sec2 = "\n".join(active_lines)

        # 3. Hukuki Değerlendirme (Strictly separated 5 sub-blocks)
        stat_block = (
            "\n".join(f"- [KANIT] {c.statement}" for c in reasoning_result.statutory_claims)
            or "- Aktif normatif hüküm metni bulunmuyor."
        )
        interp_lines = [
            f"- [YERİNDE YORUM] {c.statement}"
            for c in reasoning_result.interpretation_claims
            if not c.statement.startswith("[ÖZERKNORM")
        ]
        interp_block = "\n".join(interp_lines) or "- Ek yorum/geçiş kartı eşleşmesi yok."

        prec_block = (
            "\n".join(f"- [İÇTİHAT] {c.statement}" for c in reasoning_result.precedent_claims)
            or "- Doğrulanmış içtihat kayıt defterinden bu sorgu için ayrı bir karar eklenmedi."
        )

        auto_lines = [
            f"- {c.statement}" for c in reasoning_result.interpretation_claims if c.statement.startswith("[ÖZERKNORM")
        ]
        for notice in trace_bundle.excluded_unverified_notices:
            if notice.status == "REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION":
                auto_lines.append(
                    f"- [ÖZERKNORM UYARISI] {notice.source_id} ({notice.record_id}): "
                    f"REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION — kurum kabul belgesi olmadan bağlayıcı politika değildir."
                )
        auto_block = "\n".join(auto_lines) or "- Uygulanan şirket onaylı L5/L6 özerk normu yok."

        counter_block = (
            "\n".join(f"- [KARŞI GÖRÜŞ / TUZAK] {ca}" for ca in reasoning_result.counter_arguments)
            or "- Karşıt sav/tuzak uyarısı bulunmuyor."
        )
        sec3 = (
            f"[KANIT — Kanun / İkincil Norm Hükmü]\n{stat_block}\n\n"
            f"[YERİNDE YORUM — İstisna ve Geçiş Hükmü]\n{interp_block}\n\n"
            f"[İÇTİHAT — Kanun Hükmünde Değildir]\n{prec_block}\n\n"
            f"[ÖZERKNORM / L5–L6 ve İşyeri Uygulaması]\n{auto_block}\n\n"
            f"[KARŞI GÖRÜŞLER ve Olası Tuzaklar]\n{counter_block}"
        )

        # 4. Uygulama ([OPERASYONEL ÖNERİ] labeled steps & conditional @ÜcretBordro boundary)
        app_lines: list[str] = []
        if abstention.clarification_questions:
            app_lines.append("[OPERASYONEL ÖNERİ] Tamamlanması Gereken Netleştirme Soruları:")
            for idx, q in enumerate(abstention.clarification_questions, start=1):
                app_lines.append(f"  {idx}. {q}")
        for oc in reasoning_result.operational_claims:
            app_lines.append(f"- {oc.statement}")
        if not risk_result.payroll_handoff_allowed and "Bordro" not in "\n".join(app_lines):
            app_lines.append(
                "- [OPERASYONEL ÖNERİ] @ÜcretBordro devri kilitlidir (payroll_handoff_allowed=false); "
                "parasal hesaplama yapılmaz."
            )
        elif not app_lines:
            app_lines.append(
                "- [OPERASYONEL ÖNERİ] Hukuki dayanak ve özlük belgeleri arşivlenerek İK onayı ile ilerlenmelidir."
            )
        sec4 = "\n".join(app_lines)

        # 5. Risk
        risk_lines = [
            f"- [{r.risk_level} | Taraf={r.perspective} | {r.category}] {r.description} -> Sonuç: {r.legal_consequence}"
            for r in risk_result.risks
        ]
        if risk_result.escalation_ticket_id:
            risk_lines.append(
                f"- Zorunlu Hukuk Müşaviri Eskalasyonu Açıldı: {risk_result.escalation_ticket_id} "
                f"(Nedenler: {', '.join(risk_result.escalation_reasons)})"
            )
        sec5 = "\n".join(risk_lines)

        # 6. İstisnalar
        sec6 = (
            "\n".join(f"- {exc}" for exc in reasoning_result.exceptions_and_conditions)
            or "- Belirtilen senaryo kapsamında ayrı istisna tetiklenmemiştir."
        )

        # 7. Kaynaklar
        if abstention.status == "ABSTAINED_OUT_OF_DOMAIN" or (
            abstention.status == "ABSTAINED_INSUFFICIENT_EVIDENCE" and not reasoning_result.statutory_claims
        ):
            src_lines = ["Doğrulanmış aktif kaynak bulunamadı (cevap üretilmedi)."]
            if trace_bundle.excluded_unverified_notices:
                for n in trace_bundle.excluded_unverified_notices:
                    src_lines.append(
                        f"- [HARİÇ TUTULAN KAYNAK: {n.status}] {n.source_id} ({n.record_id}) — {n.reason}"
                    )
        else:
            seen_chunks: set[str] = set()
            src_lines = []
            for clm in (*reasoning_result.statutory_claims, *reasoning_result.precedent_claims, *reasoning_result.interpretation_claims):
                if clm.chunk_id and clm.chunk_id in seen_chunks:
                    continue
                if clm.chunk_id:
                    seen_chunks.add(clm.chunk_id)
                ev_str = f", evidence_id={clm.evidence_id}, head_sha256={clm.registry_head_sha256}" if clm.evidence_id else ""
                url_str = clm.source_url or "Resmî sicil kaydı"
                src_lines.append(
                    f"- source_id={clm.source_id}, provision_id={clm.provision_id}, chunk_id={clm.chunk_id}, "
                    f"URL={url_str}, effective={clm.effective_from}..{clm.effective_to or 'GÜNCEL'}, "
                    f"content_sha256={clm.content_sha256}, audit_log_id={clm.audit_log_id}{ev_str}"
                )
            if not src_lines:
                src_lines = ["Doğrulanmış aktif kaynak bulunamadı."]
        sec7 = "\n".join(src_lines)

        # 8. Güven Durumu
        disp = CONFIDENCE_DISPLAY_LABELS_TR[abstention.confidence_status]
        sec8 = (
            f"Güven Durumu: {disp} ({abstention.confidence_status})\n"
            f"Gerekçe Kodları: {', '.join(abstention.confidence_reason_codes) or 'NONE'}\n"
            f"İnsan/Hukuk Onayı: required={abstention.human_approval.required}, "
            f"level={abstention.human_approval.approval_level}, "
            f"counsel_escalation_required={abstention.human_approval.counsel_escalation_required}, "
            f"payroll_handoff_allowed={abstention.human_approval.payroll_handoff_allowed}\n"
            f"{STANDARD_DISCLAIMER_TR}\n"
            f"{TRUST_CHAIN_LEGAL_BOUNDARY_NOTICE_TR}"
        )

        # Apply optional negative test overrides BEFORE CitationValidator checks them
        if override_section_texts:
            sec1 = override_section_texts.get("hukuki_sonuc", sec1)
            sec2 = override_section_texts.get("mevzuat_dayanagi", sec2)
            sec3 = override_section_texts.get("hukuki_degerlendirme", sec3)
            sec4 = override_section_texts.get("uygulama", sec4)
            sec5 = override_section_texts.get("risk", sec5)
            sec6 = override_section_texts.get("istisnalar", sec6)
            sec7 = override_section_texts.get("kaynaklar", sec7)
            sec8 = override_section_texts.get("guven_durumu", sec8)

        return EightSectionAnswer(
            hukuki_sonuc=sec1,
            mevzuat_dayanagi=sec2,
            hukuki_degerlendirme=sec3,
            uygulama=sec4,
            risk=sec5,
            istisnalar=sec6,
            kaynaklar=sec7,
            guven_durumu=sec8,
        )

    @staticmethod
    def build_blocked_response(
        *,
        blocker_codes: tuple[str, ...],
        blocker_messages: tuple[str, ...],
        ticket_id: str | None,
    ) -> EightSectionAnswer:
        """Fail-closed suppressed answer emitted ONLY when AnswerCitationValidator blocks a draft."""
        reason_txt = "; ".join(blocker_messages)
        code_txt = ", ".join(blocker_codes)
        esc_id = ticket_id or "LEGAL-ESC-CITBLOCK"
        return EightSectionAnswer(
            hukuki_sonuc=(
                f"[YAYIN ENGELLENDİ — FAIL-CLOSED ATIF/DOĞRULUK BLOKAJI ({code_txt})] "
                f"Taslak cevap atıf veya tarih bütünlüğü denetimini geçemediği için kullanıcıya açılmadı: {reason_txt}"
            ),
            mevzuat_dayanagi="Blokaj nedeniyle taslak mevzuat dayanakları bastırıldı.",
            hukuki_degerlendirme="Atıf denetimi BLOCKER verdiğinden taslak hukuki değerlendirme yayınlanmadı.",
            uygulama=f"[OPERASYONEL ÖNERİ] Hukuk Müşavirliği eskalasyonu ({esc_id}) ile manuel inceleme talep ediniz.",
            risk=f"[CRITICAL | BOTH | CITATION_OR_TEMPORAL_VALIDATION_BLOCKED] Blokaj kodları: {code_txt}",
            istisnalar="Atıf blokajı aşılmadan istisna/uygunluk üretilmez.",
            kaynaklar="Blokaj nedeniyle doğrulanmış kaynak listesi yayınlanmadı.",
            guven_durumu=(
                f"Güven Durumu: Cevap İçin Yetersiz Kaynak (INSUFFICIENT_EVIDENCE)\n"
                f"Blokaj Kodları: {code_txt} | Eskalasyon Bileti: {esc_id}\n"
                f"{STANDARD_DISCLAIMER_TR}\n{TRUST_CHAIN_LEGAL_BOUNDARY_NOTICE_TR}"
            ),
        )
