"""Stage 4 AnswerRiskAssessor computing Employer/Employee risks, escalation tickets & payroll locks (WP-4.4)."""

from __future__ import annotations

import hashlib
from typing import Any

from ..rag.models import RetrievalTraceBundle
from .models import (
    AnswerReasoningResult,
    AnswerRiskAssessmentResult,
    EmployerEmployeeRiskItem,
    TemporalValidationReport,
)


class AnswerRiskAssessor:
    """Deterministically classifies LOW/MEDIUM/HIGH/CRITICAL risks from evidence, cutoffs, and facts."""

    def assess(
        self,
        *,
        trace_bundle: RetrievalTraceBundle,
        temporal_report: TemporalValidationReport,
        reasoning_result: AnswerReasoningResult,
        facts: dict[str, Any],
    ) -> AnswerRiskAssessmentResult:
        risks: list[EmployerEmployeeRiskItem] = []
        esc_reasons: list[str] = list(trace_bundle.escalation_reasons) + list(reasoning_result.escalation_flags)
        grounded_sids = tuple(dict.fromkeys(b.source_id for b in reasoning_result.legal_bases))

        max_sev_rank = 1  # 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL

        def _push_risk(
            level: str,
            perspective: str,
            category: str,
            description: str,
            consequence: str,
        ) -> None:
            nonlocal max_sev_rank
            rank_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            if rank_map[level] > max_sev_rank:
                max_sev_rank = rank_map[level]
            risks.append(
                EmployerEmployeeRiskItem(
                    risk_level=level,
                    perspective=perspective,
                    category=category,
                    description=description,
                    legal_consequence=consequence,
                    grounded_source_ids=grounded_sids,
                )
            )

        # 1. Critical statutory & integrity triggers
        if trace_bundle.quarantined_evidence_mismatches or any("TRUST_CHAIN" in r for r in esc_reasons):
            _push_risk(
                "CRITICAL",
                "BOTH",
                "TRUST_CHAIN_INTEGRITY_BLOCK",
                "Trust Chain ham belge/SHA-256 doğrulama hatası veya karantina tespit edildi.",
                "Doğrulanmamış/tahrif edilmiş kanıtlar cevap üretiminden düşürülür; zorunlu hukuk müşaviri incelemesi gerekir.",
            )
        if any("CONFLICTING_PRECEDENT" in r or "NORM_CONFLICT_ESCALATION" in r for r in esc_reasons):
            _push_risk(
                "CRITICAL",
                "BOTH",
                "CONFLICTING_AUTHORITY_ESCALATION",
                "Çelişkili yargı içtihadı veya otomatik çözülemeyen eşit katmanlı norm çatışması saptandı.",
                "Otomatik kesin hüküm verilemez; şirket avukatı kararı beklenir.",
            )
        for critical_key, desc, cons in (
            (
                "union_rep_termination",
                "Sendika işyeri temsilcisi feshi (6356 m.24 yazılı izin/kesin geçersizlik rejimi).",
                "İşe iade, boşta geçen tüm süre ücreti ve ağır tazminat yaptırımı doğabilir.",
            ),
            (
                "pregnancy_termination",
                "Gebelik/analık dönemi feshi veya eşit işlem borcuna aykırılık şüphesi.",
                "Kötü niyet/ayrımcılık tazminatı ve fesih geçersizliği riski yüksektir.",
            ),
            (
                "collective_dismissal_m29",
                "4857 m.29 toplu işçi çıkarma prosedürü ve 30 gün öncesi İŞKUR/sendika bildirim sınırı.",
                "Usule aykırı toplu fesihlerde 4857 m.100 idari para cezası ve fesih geçersizliği doğar.",
            ),
        ):
            if facts.get(critical_key) is True or any(critical_key.upper() in r for r in esc_reasons):
                _push_risk("CRITICAL", "EMPLOYER", f"CRITICAL_{critical_key.upper()}", desc, cons)

        if any("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE" in r for r in esc_reasons):
            _push_risk(
                "CRITICAL",
                "EMPLOYER",
                "HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE",
                "Olay yılı 2024–2027 arşivlenmiş Diyanet UBGT/bayram takvimi kapsamı dışındadır.",
                "4857 m.26 hak düşürücü 6 iş günü süresi doğrulanmış resmî takvim olmadan kesin hesaplanamaz.",
            )

        q_fold = trace_bundle.query_text.lower()
        asks_kvkk_m9_transfer = (
            ("6698" in q_fold or "kvkk" in q_fold)
            and any(k in q_fold for k in ("yurt dış", "yurtdış", "madde 9", "m.9", "bulut", "saas"))
        )
        if facts.get("cross_border_saas_transfer") is True or asks_kvkk_m9_transfer or any("KVKK_M9" in r for r in esc_reasons):
            _push_risk(
                "CRITICAL",
                "BOTH",
                "KVKK_M9_CROSS_BORDER_BLOCK",
                "6698 KVKK m.9 yurt dışı veri aktarımı (Standart Sözleşme / 5 iş günü bildirim) kapısı kapalıdır.",
                "Hukuki aktarım rejimi onaylanmadan bulut/SaaS yurt dışı aktarımı KVKK İPC riski doğurur.",
            )

        # 2. High risks
        defense_not_taken = (
            facts.get("defense_taken_before_termination") is False
            or str(facts.get("written_defense_status") or "").strip().upper() in {"NOT_TAKEN", "NONE", "FALSE"}
        )
        if defense_not_taken or any("M19_2_SAVUNMA" in r for r in esc_reasons):
            _push_risk(
                "HIGH",
                "EMPLOYER",
                "M19_2_SAVUNMA_EKSIGI_IHLALI",
                "4857 m.19/2 uyarınca davranış veya verim (performans) feshinden önce işçinin yazılı savunmasının alınmaması emredici şekil şartı ihlalidir.",
                "İşe iade davasında fesih doğrudan geçersiz sayılabilir; boşta geçen süre ücreti ve işe başlatmama tazminatı riski doğar.",
            )
            _push_risk(
                "HIGH",
                "EMPLOYEE",
                "M19_2_EMPLOYEE_REINSTATEMENT_CLAIM",
                "Savunması alınmadan işten çıkarılan işçi 1 ay içinde zorunlu arabuluculuk ve işe iade talebinde bulunabilir.",
                "İşe iade ve geçersiz fesih talebi riski yüksektir.",
            )
        if any("M109_7555" in r for r in esc_reasons):
            _push_risk(
                "HIGH",
                "EMPLOYER",
                "M109_7555_WRITTEN_TERMINATION_VIOLATION",
                "24.07.2025 sonrası fesihte KEP/sözlü/e-posta kanalı kullanımı 7555 m.23 ile değişik 4857 m.109 yazılılık şartını ihlal edebilir.",
                "Haklı fesih veya iş güvencesi dışı fesihlerde dahi şekle/ispata aykırılık sebebiyle kıdem/ihbar ve işe iade riski doğar.",
            )
            _push_risk(
                "HIGH",
                "EMPLOYEE",
                "M109_EMPLOYEE_CONTEST_RIGHT",
                "Çalışan yazılı fesih bildirimi yapılmadığı gerekçesiyle feshin geçersizliğini veya tazminat haklarını talep edebilir.",
                "Zorunlu arabuluculuk ve iş mahkemesi davası açılabilir.",
            )
        if any("M26_YARIM_GUN" in r or "M26_YETKILI_MAKAM" in r for r in esc_reasons):
            _push_risk(
                "HIGH",
                "EMPLOYER",
                "M26_SIX_WORKING_DAY_FORFEITURE_RISK",
                "4857 m.26 altı iş günlük hak düşürücü süre (arife yarım gün veya feshe yetkili makam öğrenme tarihi belirsizliği) riski.",
                "6 iş günü aşılırsa haklı fesih hakkı düşer; fesih haksız feshe dönüşerek kıdem/ihbar tazminatı doğurur.",
            )
        if any("ISOLATED_PRECEDENT" in r or "POST_DECISION_AMENDMENT" in r or "MISSING_PERSUASIVE_PRECEDENT_RATIONALE" in r for r in esc_reasons):
            _push_risk(
                "HIGH",
                "BOTH",
                "PRECEDENT_APPLICATION_REVIEW_REQUIRED",
                "İzole daire kararı, karar sonrası kanun değişikliği veya yetersiz içtihat gerekçesi (<25 karakter).",
                "İçtihadın olaya uygulanabilirliği şirket avukatı incelemesi olmadan otomatik kesinleştirilemez.",
            )
        if facts.get("biometric_pdks_used") is True:
            _push_risk(
                "HIGH",
                "BOTH",
                "KVKK_BIOMETRIC_PDKS_PROPORTIONALITY",
                "Alternatif giriş yöntemleri varken parmak izi/yüz tanıma gibi biyometrik PDKS kullanımı 6698 m.4 ölçülülük ilkesiyle çelişebilir.",
                "Kurul şikâyeti halinde veri silme/imha emri ve yüksek KVKK idari para cezası uygulanabilir.",
            )
        if any("OUTSIDE" not in r and "TEMPORAL_RETROACTIVITY_VIOLATION_BLOCKED" in temporal_report.temporal_flags for r in ("1",)):
            esc_reasons.append("TEMPORAL_RETROACTIVITY_ATTEMPT")
            _push_risk(
                "HIGH",
                "BOTH",
                "TEMPORAL_RETROACTIVITY_ATTEMPT",
                "Olay tarihinde yürürlükte olmayan mevzuat/karar parçası tespit edildi ve aktif havuzdan dışlandı.",
                "Tarihsel hata önlendi; geçmiş olaylar yalnızca yürürlükteki tarihi rejimle değerlendirilmelidir.",
            )

        # 3. Medium risks (L5/L6 pending adoption or operational warnings)
        if any("REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION" in r for r in esc_reasons) or any(
            "AUTONOMOUS_NORM" in r for r in esc_reasons
        ):
            _push_risk(
                "MEDIUM",
                "BOTH",
                "UNADOPTED_L5_L6_TEMPLATE_BOUNDARY",
                "L5/L6 iç prosedür/TİS/işyeri uygulaması şablonu şirketçe resmen benimsenmemiştir; tek taraflı kesinti 4857 m.22 yazılı rızasına tabidir.",
                "6 iş günü içinde yazılı rıza yoksa esaslı değişiklik çalışanı bağlamaz ve alacak davası açılabilir.",
            )

        # 4. Baseline employer/employee balanced operational risk if nothing critical/high was triggered
        if not risks:
            _push_risk(
                "LOW",
                "BOTH",
                "BASELINE_EVIDENTIARY_COMPLIANCE",
                "İlgili kanuni şartlar ön incelemede uyumlu görünmekle birlikte özlük/tebliğ ispat belgelerinin dosyada saklanması gereklidir.",
                "Belgelenemeyen bildirim ve savunma işlemleri yargılama aşamasında işveren aleyhine ispat yükü doğurabilir.",
            )

        level_names = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
        overall_level = level_names[max_sev_rank]
        needs_escalation = bool(esc_reasons) or overall_level in {"HIGH", "CRITICAL"} or reasoning_result.has_conflicting_precedent_or_norm

        if overall_level == "CRITICAL" or (needs_escalation and overall_level == "HIGH"):
            badge = "YUKSEK_RISK_AVUKAT_ESKALASYONU"
            approval_level = "MANDATORY_LEGAL_COUNSEL_APPROVAL"
        elif overall_level == "MEDIUM" or trace_bundle.missing_facts:
            badge = "EKSIK_BILGI_TAMAMLANMALI" if trace_bundle.missing_facts else "SENIOR_HR_REVIEW_NOTE"
            if badge == "SENIOR_HR_REVIEW_NOTE":
                badge = "UYGUN_ON_DEGERLENDIRME"
            approval_level = "SENIOR_HR_AND_LEGAL_REVIEW"
        else:
            badge = "UYGUN_ON_DEGERLENDIRME"
            approval_level = "HR_OPERATIONS_VERIFICATION"

        if trace_bundle.missing_facts and overall_level not in {"HIGH", "CRITICAL"}:
            badge = "EKSIK_BILGI_TAMAMLANMALI"
            approval_level = "SENIOR_HR_AND_LEGAL_REVIEW"

        esc_ticket: str | None = None
        if needs_escalation:
            sig = hashlib.sha256(
                f"{trace_bundle.trace_id}|{'|'.join(sorted(set(esc_reasons)))}".encode("utf-8")
            ).hexdigest()[:10].upper()
            esc_ticket = f"LEGAL-ESC-{sig}"

        payroll_allowed = bool(
            trace_bundle.payroll_handoff_allowed
            and not needs_escalation
            and overall_level not in {"HIGH", "CRITICAL"}
            and not trace_bundle.missing_facts
        )

        return AnswerRiskAssessmentResult(
            overall_risk_level=overall_level,
            decision_badge=badge,
            approval_level=approval_level,
            counsel_escalation_required=needs_escalation,
            escalation_ticket_id=esc_ticket,
            escalation_reasons=tuple(dict.fromkeys(esc_reasons)),
            payroll_handoff_allowed=payroll_allowed,
            risks=tuple(risks),
        )
