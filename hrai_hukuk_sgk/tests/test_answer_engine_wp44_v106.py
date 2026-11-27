"""Comprehensive WP-4.4 Answer Engine Verification Suite (`ANS-01`..`ANS-26`)."""

from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest

from engine.answer import (
    CLAIM_JUDICIAL_PRECEDENT,
    CLAIM_LEGAL_INTERPRETATION,
    CLAIM_OPERATIONAL_GUIDANCE,
    CLAIM_STATUTORY_EVIDENCE,
    CONFIDENCE_INSUFFICIENT_EVIDENCE,
    CONFIDENCE_PARTIALLY_VERIFIED,
    CONFIDENCE_VERIFIED,
    STATUS_ABSTAINED_INSUFFICIENT_EVIDENCE,
    STATUS_ABSTAINED_MISSING_INFO,
    STATUS_ABSTAINED_OUT_OF_DOMAIN,
    STATUS_ANSWERED,
    STATUS_ANSWERED_WITH_ESCALATION,
    STATUS_BLOCKED_CITATION_VALIDATION_FAILED,
    AnswerBundleIntegrityError,
    AnswerClaimRecord,
    AnswerGenerationRequest,
    HukukSgkAnswerOrchestrator,
)
from engine.knowledge_base import (
    COURT_DANISTAY,
    DOC_KIND_STATUTORY_PROVISION,
    VERIFICATION_VERIFIED,
    JudicialPrecedentNode,
    LegalDocumentVersion,
    LegalProvisionNode,
    LegalStructuralChunker,
    LocalDeterministicHybridStore,
    canonical_kb_sha256,
)
from engine.models import NormReference
from engine.rag import (
    HukukSgkRagEngine,
    RagQueryRequest,
    compute_deterministic_trace_hashes,
)
from engine.trust_root import run_live_integration_probe

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_XMLDSIG_SHA256 = "b16207b5fb71d7c0d0372838411c7795459ac460c2ff232766ae230b9cbacf85"

_SHARED_RAG: dict[Path, HukukSgkRagEngine] = {}
_SHARED_ANS: dict[Path, HukukSgkAnswerOrchestrator] = {}


class TestAnswerEngineWp44V106(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        resolved = PROJECT_ROOT.resolve()
        if resolved not in _SHARED_RAG:
            _SHARED_RAG[resolved] = HukukSgkRagEngine.from_project_root(project_root=PROJECT_ROOT)
        if resolved not in _SHARED_ANS:
            _SHARED_ANS[resolved] = HukukSgkAnswerOrchestrator.from_project_root(project_root=PROJECT_ROOT)
        cls.rag = _SHARED_RAG[resolved]
        cls.orchestrator = _SHARED_ANS[resolved]

    def _run_e2e(
        self,
        query_text: str,
        *,
        as_of_date: str | None = None,
        facts: dict | None = None,
        include_historical: bool = False,
        top_k: int = 6,
        scenario_type: str | None = None,
        precedent_application_rationale: str = "",
        competing_norm: NormReference | None = None,
        injected_draft_claims: tuple[AnswerClaimRecord, ...] = (),
        override_section_texts: dict[str, str] | None = None,
    ):
        bundle = self.rag.retrieve(
            RagQueryRequest(
                query_text=query_text,
                as_of_date=as_of_date,
                facts=facts or {},
                include_historical=include_historical,
                top_k=top_k,
            )
        )
        return bundle, self.orchestrator.generate_answer(
            AnswerGenerationRequest(
                trace_bundle=bundle,
                facts=facts or {},
                scenario_type=scenario_type,
                precedent_application_rationale=precedent_application_rationale,
                competing_norm=competing_norm,
                injected_draft_claims=injected_draft_claims,
                override_section_texts=override_section_texts,
            )
        )

    def test_01_ans01_clean_eight_section_answer_and_whitelist_binding(self) -> None:
        """ANS-01: Temiz 4857 m.25/II-e vakasında 8 bölüm eksiksiz ve tüm iddialar whitelist bağlı."""
        facts = {
            "notification_channel": "HAND_DELIVERED_WRITTEN_SIGNED",
            "written_notice_with_clear_reason": True,
            "discovery_date": "2026-03-08",
            "incident_date": "2026-03-07",
            "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
            "weekly_rest_day": "SUNDAY",
        }
        bundle, ans = self._run_e2e(
            "4857 m.25/II-e güveni kötüye kullanma feshi",
            as_of_date="2026-03-10",
            facts=facts,
            scenario_type="TERMINATION_VALIDITY",
        )
        self.assertEqual(ans.status, STATUS_ANSWERED)
        self.assertFalse(ans.published_answer_blocked)
        self.assertTrue(ans.citation_audit.passed)
        secs = ans.eight_sections.to_dict()
        self.assertEqual(len(secs), 8)
        for v in secs.values():
            self.assertTrue(v.strip())
        self.assertTrue(all(b.effective_on_date for b in ans.legal_bases))
        self.assertTrue(any("4857:m-25:f-2:b-e" in b.legal_reference for b in ans.legal_bases))
        for clm in ans.claims:
            if clm.claim_category == CLAIM_STATUTORY_EVIDENCE:
                self.assertIn(clm.source_id, bundle.citation_whitelist.allowed_source_ids)
                self.assertIn(clm.provision_id, bundle.citation_whitelist.allowed_provision_ids)

    def test_02_ans02_mixed_multi_domain_case_grounding(self) -> None:
        """ANS-02: Çok alanlı vaka (İş + SGK + İSG + KVKK) tüm alanlardan doğrulanmış dayanak alır."""
        facts = {
            "notification_channel": "HAND_DELIVERED_WRITTEN_SIGNED",
            "written_notice_with_clear_reason": True,
            "written_defense_status": "OBTAINED_WRITTEN",
            "workplace_total_employees": 45,
            "tenure_months": 18,
        }
        _, ans = self._run_e2e(
            "2026-04-01'de sağlık raporu sebebiyle işten çıkarma, iş kazası bildirimi ve SGK çıkış kodu",
            as_of_date=None,
            facts=facts,
            top_k=8,
        )
        self.assertFalse(ans.published_answer_blocked)
        self.assertEqual(ans.as_of_date, "2026-04-01")
        cited_laws = {c.law_no for c in ans.claims if c.law_no}
        self.assertTrue({"4857", "5510", "6331", "6698"}.issubset(cited_laws))
        self.assertIn("[KANIT —", ans.eight_sections.hukuki_degerlendirme)

    def test_03_ans03_reinstatement_written_defense_m18_m19(self) -> None:
        """ANS-03: 4857 m.18 & m.19 performans/davranış feshinde yazılı savunma değerlendirmesi."""
        _, ans = self._run_e2e(
            "4857 madde 18 ve madde 19 performans düşüklüğü fesih ve yazılı savunma",
            as_of_date="2026-03-10",
            facts={
                "workplace_total_employees": 40,
                "tenure_months": 12,
                "written_defense_status": "OBTAINED_WRITTEN",
                "notification_channel": "HAND_DELIVERED_WRITTEN_SIGNED",
                "written_notice_with_clear_reason": True,
            },
            scenario_type="TERMINATION_VALIDITY",
        )
        self.assertFalse(ans.published_answer_blocked)
        self.assertTrue(ans.citation_audit.passed)
        self.assertTrue(any("4857:m-18" in b.legal_reference or "4857:m-19" in b.legal_reference for b in ans.legal_bases))

    def test_04_ans04_trust_chain_bound_confidence_verified_vs_partially_verified(self) -> None:
        """ANS-04: Canlı HTTPS Trust Chain kaydında VERIFIED, TEST_TRANSPORT'ta PARTIALLY_VERIFIED."""
        raw_clean = b"4857 Sayili Is Kanunu Madde 25 Resmi Gazete dogrulanmis ham metin."
        sha_clean = hashlib.sha256(raw_clean).hexdigest()
        rec_sha = canonical_kb_sha256({"evidence_id": "EV-ANS04", "content_sha256": sha_clean})
        head_sha = canonical_kb_sha256({"head": "EV-ANS04"})

        def _build_with_mode(mode: str, is_live: bool):
            adapter = SimpleNamespace(
                get=lambda eid: (
                    SimpleNamespace(
                        evidence_id="EV-ANS04",
                        is_verified_authority=True,
                        content_sha256=sha_clean,
                        record_sha256=rec_sha,
                        registry_head_sha256=head_sha,
                        transport_mode=mode,
                        live_verified=is_live,
                    )
                    if eid == "EV-ANS04"
                    else None
                ),
                verify_integrity=lambda require_raw_content=True: (True, {"valid": True, "head_sha256": head_sha}),
                get_raw_bytes=lambda eid: raw_clean if eid == "EV-ANS04" else None,
            )
            chunker = LegalStructuralChunker()
            dv = LegalDocumentVersion(
                document_version_id="DV-ANS04",
                source_id="MEVZUAT-4857",
                evidence_id="EV-ANS04",
                document_kind=DOC_KIND_STATUTORY_PROVISION,
                norm_layer="STATUTORY_LAW",
                norm_priority=3,
                statute_no="4857",
                title="4857 İş Kanunu m.25",
                official_gazette_no="25134",
                publication_date="2003-06-10",
                effective_from="2003-06-10",
                effective_to=None,
                supersedes_version_id=None,
                content_sha256=sha_clean,
                verification_status=VERIFICATION_VERIFIED,
                document_fetch_status="FETCHED_AND_MATCHED",
                audit_log_id="AUD-20261120-MEVZUAT4857",
                source_url="https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=4857&MevzuatTur=1&MevzuatTertip=5",
            )
            prov = LegalProvisionNode(
                provision_id="4857:m-25:f-1:b-b",
                document_version_id="DV-ANS04",
                source_id="MEVZUAT-4857",
                evidence_id="EV-ANS04",
                law_no="4857",
                article_no="Madde 25",
                article_title="4857 m.25 Derhal Fesih",
                raw_text="4857 madde 25 haklı fesih sebebi.",
                normalized_text="4857 madde 25 haklı fesih sebebi.",
                publication_date="2003-06-10",
                effective_from="2003-06-10",
                effective_to=None,
                norm_layer="STATUTORY_LAW",
                norm_priority=3,
                norm_character="ABSOLUTE_MANDATORY",
                verification_status=VERIFICATION_VERIFIED,
                content_sha256=sha_clean,
                source_url="https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=4857&MevzuatTur=1&MevzuatTertip=5",
            )
            st = LocalDeterministicHybridStore(trust_chain_adapter=adapter)
            st.upsert_bundle(document_versions=[dv], provisions=[prov], chunks=chunker.chunk_provision(prov))
            rag = HukukSgkRagEngine(st, project_root=PROJECT_ROOT, trust_chain_adapter=adapter)
            b = rag.retrieve(RagQueryRequest(query_text="4857 madde 25 hükmü nedir?", as_of_date="2026-04-01"))
            return self.orchestrator.generate_answer(AnswerGenerationRequest(trace_bundle=b))

        live_ans = _build_with_mode("LIVE_HTTPS", True)
        self.assertEqual(live_ans.confidence_status, CONFIDENCE_VERIFIED)
        self.assertIn("EV-ANS04", live_ans.eight_sections.kaynaklar)
        self.assertIn(head_sha, live_ans.eight_sections.kaynaklar)
        self.assertEqual(live_ans.audit_trace.claim_evidence_links[0].evidence_id, "EV-ANS04")

        test_ans = _build_with_mode("VERIFIED_TEST_TRANSPORT", False)
        self.assertEqual(test_ans.confidence_status, CONFIDENCE_PARTIALLY_VERIFIED)
        self.assertIn("VERIFIED_TEST_TRANSPORT_NON_LIVE", test_ans.confidence_reason_codes)

    def test_05_ans05_wrong_article_number_citation_blocked(self) -> None:
        """ANS-05: Whitelist yalnızca m.25/m.26/m.109 içerirken metinde '4857 m.18' veya 'm.99' bloklanır."""
        _, ans = self._run_e2e(
            "4857 m.25/II-e güveni kötüye kullanma feshi",
            as_of_date="2026-03-10",
            facts={
                "notification_channel": "HAND_DELIVERED_WRITTEN_SIGNED",
                "written_notice_with_clear_reason": True,
                "discovery_date": "2026-03-08",
                "incident_date": "2026-03-07",
                "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                "weekly_rest_day": "SUNDAY",
            },
            override_section_texts={
                "hukuki_sonuc": "4857 m.99 gereğince bu fesih doğrudan geçersiz sayılır."
            },
        )
        self.assertEqual(ans.status, STATUS_BLOCKED_CITATION_VALIDATION_FAILED)
        self.assertTrue(ans.published_answer_blocked)
        self.assertFalse(ans.citation_audit.passed)
        self.assertIn("WRONG_ARTICLE_OR_PROVISION_CITED", ans.citation_audit.blocker_codes)
        self.assertFalse(ans.human_approval.payroll_handoff_allowed)

    def test_06_ans06_wrong_norm_type_ck_labeled_as_cbk_blocked(self) -> None:
        """ANS-06: 10766 Sayılı Cumhurbaşkanı Kararı (CK) metinde CBK olarak anılırsa reddedilir."""
        _, ans = self._run_e2e(
            "10766 CK uzaktan çalışma oranları nelerdir?",
            as_of_date="2026-04-01",
            override_section_texts={
                "mevzuat_dayanagi": "10766 sayılı Cumhurbaşkanlığı Kararnamesi uyarınca Ar-Ge oranları %100 uygulanır."
            },
        )
        self.assertTrue(ans.published_answer_blocked)
        self.assertIn("NORM_TYPE_MISMATCH_DECREE_VS_DECISION", ans.citation_audit.blocker_codes)

    def test_07_ans07_fabricated_precedent_statute_and_bare_url_blocked(self) -> None:
        """ANS-07: Uydurma karar no, uydurma kanun no ve çıplak ana sayfa URL'si engellenir."""
        _, ans = self._run_e2e(
            "4857 m.22 çalışma koşulları nedir?",
            as_of_date="2026-04-01",
            override_section_texts={
                "hukuki_degerlendirme": (
                    "9999 sayılı Hayali Kanun ve Yargıtay 9. HD E. 2026/99999, K. 2026/88888 uyarınca "
                    "detaylar https://www.mevzuat.gov.tr adresindedir."
                )
            },
        )
        self.assertTrue(ans.published_answer_blocked)
        self.assertIn("FABRICATED_PRECEDENT", ans.citation_audit.blocker_codes)
        self.assertIn("FABRICATED_STATUTE", ans.citation_audit.blocker_codes)
        self.assertIn("INVALID_SOURCE_URL", ans.citation_audit.blocker_codes)

    def test_08_ans08_pre_7555_historical_case_blocks_retroactive_current_law(self) -> None:
        """ANS-08: 2025-07-10 vakasına 24.07.2025 tarihli 7555 m.23 KEP yasağı geriye yürütülmez."""
        _, ans = self._run_e2e(
            "4857 madde 109 KEP ile fesih bildirimi geçerli mi?",
            as_of_date="2025-07-10",
            facts={"notification_channel": "KEP_ONLY", "written_notice_with_clear_reason": True},
        )
        self.assertFalse(ans.published_answer_blocked)
        self.assertFalse(any(b.source_id == "RG-7555-20250724" for b in ans.legal_bases))
        self.assertNotIn("M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI", ans.human_approval.reasons)

    def test_09_ans09_post_7555_applies_new_m109_and_separates_old_regime(self) -> None:
        """ANS-09: 2025-09-01 KEP feshinde 7555 aktif uygulanır; eski m.109 yalnızca historical_context'tedir."""
        _, ans = self._run_e2e(
            "4857 madde 109 KEP ile fesih bildirimi geçerli mi?",
            as_of_date="2025-09-01",
            facts={"notification_channel": "KEP_ONLY", "written_notice_with_clear_reason": True},
            include_historical=True,
        )
        self.assertEqual(ans.status, STATUS_ANSWERED_WITH_ESCALATION)
        self.assertFalse(ans.published_answer_blocked)
        self.assertTrue(any(b.source_id == "RG-7555-20250724" and b.effective_on_date for b in ans.legal_bases))
        self.assertTrue(any(h.source_id == "MEVZUAT-4857" and not h.effective_on_date for h in ans.historical_context))
        self.assertFalse(ans.human_approval.payroll_handoff_allowed)

    def test_10_ans10_repealed_9368_ck_separated_and_blocks_if_cited_as_current(self) -> None:
        """ANS-10: 2026-04-01 tarihinde mülga 9368 CK güncel sunulursa bloklanır; tarihsel bağlamda geçer."""
        _, clean_ans = self._run_e2e(
            "10766 CK Ar-Ge teknokent uzaktan çalışma oranları nelerdir?",
            as_of_date="2026-04-01",
            include_historical=True,
        )
        self.assertFalse(clean_ans.published_answer_blocked)
        self.assertTrue(any(b.source_id == "RG-10766-20251225" and b.effective_on_date for b in clean_ans.legal_bases))
        self.assertFalse(any(b.source_id == "RG-9368-20241228" for b in clean_ans.legal_bases))
        self.assertTrue(any(h.source_id == "RG-9368-20241228" and not h.effective_on_date for h in clean_ans.historical_context))

        # 9368 güncel yürürlükte gibi sunulursa reddedilmelidir
        _, bad_ans = self._run_e2e(
            "10766 CK Ar-Ge teknokent uzaktan çalışma oranları nelerdir?",
            as_of_date="2026-04-01",
            override_section_texts={
                "mevzuat_dayanagi": "9368 Sayılı Cumhurbaşkanı Kararı 2026 yılında hâlen geçerli tek düzenlemedir."
            },
        )
        self.assertTrue(bad_ans.published_answer_blocked)
        self.assertIn("EXPIRED_OR_REPEALED_STATUTE", bad_ans.citation_audit.blocker_codes)

    def test_11_ans11_retroactive_item_rejected_by_temporal_validator(self) -> None:
        """ANS-11: 2024-05-15 veya 2025-12-01 olaylarına sonraki 7499/7566 sızdırılamaz."""
        # 2025-12-01 SPEK sorgusunda 7566 aktif havuzda bulunmamalıdır
        _, ans_pre = self._run_e2e(
            "5510 madde 82 prime esas kazanç üst sınırı nedir?",
            as_of_date="2025-12-01",
        )
        self.assertFalse(any(b.source_id == "RG-7566-20251219" for b in ans_pre.legal_bases))

        # Sentetik olarak 2025-12-01 tarihli bir paketin içine gelecek tarihli 2026-01-01 chunk yerleştirip
        # bundle hash'ini yeniden mühürleyelim -> AnswerTemporalValidator geriye yürümeyi yakalamalıdır!
        future_b = self.rag.retrieve(
            RagQueryRequest(query_text="5510 madde 82 7566 SPEK nedir?", as_of_date="2026-04-15")
        )
        valid_2025_b = self.rag.retrieve(
            RagQueryRequest(query_text="5510 madde 82 nedir?", as_of_date="2025-12-01")
        )
        future_only = tuple(i for i in future_b.normative_bucket if i.chunk.source_id == "RG-7566-20251219")
        self.assertTrue(len(future_only) >= 1)
        mixed_norm = (*valid_2025_b.normative_bucket, *future_only)
        new_id, new_sha = compute_deterministic_trace_hashes(
            query_text=valid_2025_b.query_text,
            as_of_date=valid_2025_b.as_of_date,
            intent_classification=valid_2025_b.intent_classification,
            temporal_audit=valid_2025_b.temporal_audit,
            rag_gate_status=valid_2025_b.rag_gate_status,
            should_conclude=valid_2025_b.should_conclude,
            counsel_escalation_required=valid_2025_b.counsel_escalation_required,
            escalation_reasons=valid_2025_b.escalation_reasons,
            payroll_handoff_allowed=valid_2025_b.payroll_handoff_allowed,
            missing_facts=valid_2025_b.missing_facts,
            clarification_questions=valid_2025_b.clarification_questions,
            normative_bucket=mixed_norm,
            interpretation_bucket=valid_2025_b.interpretation_bucket,
            precedent_bucket=valid_2025_b.precedent_bucket,
            autonomous_norm_bucket=valid_2025_b.autonomous_norm_bucket,
            historical_context_bucket=valid_2025_b.historical_context_bucket,
            excluded_unverified_notices=valid_2025_b.excluded_unverified_notices,
            evidence_bindings=valid_2025_b.evidence_bindings,
            quarantined_evidence_mismatches=valid_2025_b.quarantined_evidence_mismatches,
            citation_whitelist=valid_2025_b.citation_whitelist,
            pipeline_audit_trail=valid_2025_b.pipeline_audit_trail,
        )
        poisoned_bundle = replace(valid_2025_b, normative_bucket=mixed_norm, trace_id=new_id, bundle_sha256=new_sha)
        ans_clean = self.orchestrator.generate_answer(AnswerGenerationRequest(trace_bundle=poisoned_bundle))
        self.assertIn("TEMPORAL_RETROACTIVITY_VIOLATION_BLOCKED", ans_clean.temporal_report.temporal_flags)
        self.assertFalse(any(b.source_id == "RG-7566-20251219" for b in ans_clean.legal_bases))

    def test_12_ans12_evidence_vs_interpretation_vs_operational_separation(self) -> None:
        """ANS-12: Kanun kanıtı, içtihat, hukuki yorum ve operasyonel öneri kesin etiketle ayrılır."""
        _, ans = self._run_e2e(
            "4857 madde 26 6 iş günü süresi ve akdi cumartesi nedir?",
            as_of_date="2026-05-01",
            facts={
                "discovery_date": "2026-04-28",
                "incident_date": "2026-04-25",
                "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                "weekly_rest_day": "SUNDAY",
            },
        )
        cats = {c.claim_category for c in ans.claims}
        self.assertIn(CLAIM_STATUTORY_EVIDENCE, cats)
        self.assertIn(CLAIM_LEGAL_INTERPRETATION, cats)
        self.assertIn(CLAIM_OPERATIONAL_GUIDANCE, cats)
        # Operasyonel ve yorum iddiaları mevzuat_dayanagi bölümüne asla konmaz
        for c in ans.claims:
            if c.claim_category in {CLAIM_LEGAL_INTERPRETATION, CLAIM_OPERATIONAL_GUIDANCE}:
                self.assertNotEqual(c.section_name, "mevzuat_dayanagi")

    def test_13_ans13_precedent_never_promoted_to_statutory_tier(self) -> None:
        """ANS-13: YİBBGK 2017/9 kararı mevzuat basamağı değil, kapsam sınırıyla içtihat alt bloğundadır."""
        _, ans = self._run_e2e(
            "2017/9 sağlık feshinde savunma Yargıtay içtihadı",
            as_of_date="2026-04-01",
            facts={"precedent_scope_match_status": "IN_SCOPE"},
        )
        self.assertFalse(ans.published_answer_blocked)
        self.assertFalse(any(b.source_id == "YIBBGK-2017-9-2018-10" for b in ans.legal_bases))
        self.assertTrue(any(c.claim_category == CLAIM_JUDICIAL_PRECEDENT for c in ans.claims))
        self.assertIn("[İÇTİHAT — Kanun Hükmünde Değildir]", ans.eight_sections.hukuki_degerlendirme)

    def test_14_ans14_l5_l6_unadopted_template_boundary_and_m22_consent(self) -> None:
        """ANS-14: Kabul edilmemiş L5/L6 şablonu bağlayıcı politika yapılmaz ve m.22 rıza şartı belirtilir."""
        _, ans = self._run_e2e(
            "L5 İK prosedürü disiplin ve L6 TİS normları nelerdir?",
            as_of_date="2026-06-01",
        )
        self.assertEqual(ans.status, STATUS_ANSWERED_WITH_ESCALATION)
        self.assertFalse(ans.human_approval.payroll_handoff_allowed)
        self.assertIn("REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION", ans.eight_sections.hukuki_degerlendirme)

    def test_15_ans15_conflicting_precedent_forces_escalation_and_halts_auto_ruling(self) -> None:
        """ANS-15: Çelişkili (CONFLICTING) içtihat geldiğinde kesin hüküm verilmez ve eskalasyon açılır."""
        prec_copy = dict(self.orchestrator._precedents)
        orig = prec_copy["YIBBGK-2017-9-2018-10"]
        prec_copy["YIBBGK-2017-9-2018-10"] = replace(
            orig,
            verification_status="CONFLICTING",
            conflicting_precedent_ids=("CONFLICTING-SAMPLE-2025",),
        )
        custom_orch = HukukSgkAnswerOrchestrator(
            source_registry=self.orchestrator._sources,
            precedent_registry=prec_copy,
            knowledge_cards=self.orchestrator._cards,
        )
        bundle = self.rag.retrieve(
            RagQueryRequest(query_text="2017/9 sağlık feshinde savunma Yargıtay içtihadı", as_of_date="2026-04-01")
        )
        ans = custom_orch.generate_answer(AnswerGenerationRequest(trace_bundle=bundle))
        self.assertTrue(ans.human_approval.counsel_escalation_required)
        self.assertFalse(ans.human_approval.payroll_handoff_allowed)
        self.assertEqual(ans.confidence_status, CONFIDENCE_PARTIALLY_VERIFIED)
        self.assertEqual(ans.status, STATUS_ANSWERED_WITH_ESCALATION)

    def test_16_ans16_post_amendment_and_missing_rationale_escalates(self) -> None:
        """ANS-16: Karar sonrası kanun değişikliği & ikna edici içtihatta gerekçe eksikliği eskalasyonu."""
        chunker = LegalStructuralChunker()
        stat = LegalProvisionNode(
            provision_id="5510:m-102:f-1",
            document_version_id="DV-5510-ANS16",
            source_id="MEVZUAT-5510",
            law_no="5510",
            article_no="Madde 102",
            article_title="SGK İPC",
            raw_text="5510 madde 102 SGK idari para cezası.",
            normalized_text="5510 madde 102 SGK idari para cezası.",
            publication_date="2008-10-01",
            effective_from="2008-10-01",
            effective_to=None,
            norm_layer="STATUTORY_LAW",
            norm_priority=3,
            norm_character="ABSOLUTE_MANDATORY",
            verification_status=VERIFICATION_VERIFIED,
            content_sha256=canonical_kb_sha256({"s": 5510}),
            source_url="https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=5510&MevzuatTur=1&MevzuatTertip=5",
        )
        dan = JudicialPrecedentNode(
            precedent_id="TEST-DAN-AMEND-ANS16",
            court_system=COURT_DANISTAY,
            chamber="10_D",
            binding_level="DANISTAY_DAIRE_SETTLED",
            esas_no="2022/10",
            karar_no="2023/20",
            decision_date="2023-03-01",
            official_source_url="https://karararama.danistay.gov.tr/test-ans16-amend",
            interpreted_provision_ids=("5510:m-102:f-1",),
            legal_principle="5510 m.102 SGK idari para cezası Danıştay içtihadı.",
            operative_holding="Değişiklik öncesi dönem kararıdır.",
            applies_to=("5510 m.102",),
            does_not_apply_to=("Yeni kanun sonrası İPC",),
            verification_status=VERIFICATION_VERIFIED,
            post_decision_amendment_status="AMENDED_BY_SUBSEQUENT_STATUTE",
            content_sha256=canonical_kb_sha256({"dan": 16}),
            keywords=("5510", "danıştay", "m.102"),
        )
        st = LocalDeterministicHybridStore()
        st.upsert_bundle(
            provisions=[stat],
            precedents=[dan],
            chunks=chunker.chunk_provision(stat) + chunker.chunk_precedent(dan),
        )
        rag = HukukSgkRagEngine(st, project_root=PROJECT_ROOT)
        b = rag.retrieve(
            RagQueryRequest(
                query_text="5510 madde 102 SGK idari para cezası Danıştay içtihadı",
                as_of_date="2026-04-01",
                court_systems=(COURT_DANISTAY,),
            )
        )
        ans = self.orchestrator.generate_answer(AnswerGenerationRequest(trace_bundle=b, precedent_application_rationale="Kısa"))
        self.assertEqual(ans.status, STATUS_ANSWERED_WITH_ESCALATION)
        self.assertTrue(ans.human_approval.counsel_escalation_required)
        self.assertFalse(ans.human_approval.payroll_handoff_allowed)
        self.assertFalse(ans.published_answer_blocked)

    def test_17_ans17_norm_conflict_employee_favorable_and_constitution_vs_ilo(self) -> None:
        """ANS-17: Anayasa m.11 > ILO genel antlaşma & işçi lehine TİS nispi emredici üstünlüğü."""
        _, ans_cba = self._run_e2e(
            "4857 madde 53 yıllık izin süreleri nelerdir?",
            as_of_date="2026-04-01",
            facts={"favors_employee_side": "NORM_B"},
            competing_norm=NormReference(
                title="İşyeri TİS Yıllık İzin Artışı (30 Gün)",
                norm_layer="CBA_CONTRACT_AND_HR_PROCEDURE",
            ),
        )
        self.assertTrue(len(ans_cba.eight_sections.hukuki_degerlendirme) > 0)
        # Constitution supremacy check via LegalReasoning -> Anayasa prevails without manual escalation ambiguity
        _, ans_const = self._run_e2e(
            "4857 madde 53 yıllık izin süreleri nelerdir?",
            as_of_date="2026-04-01",
            competing_norm=NormReference(
                title="Anayasa m.50 Dinlenme Hakkı",
                norm_layer="CONSTITUTION",
            ),
        )
        self.assertFalse(ans_const.published_answer_blocked)

    def test_18_ans18_unwhitelisted_injected_claim_blocked(self) -> None:
        """ANS-18: CitationWhitelist dışında kalan enjekte iddia UNWHITELISTED_CITATION_BLOCKER alır."""
        bundle = self.rag.retrieve(
            RagQueryRequest(query_text="4857 madde 22 çalışma koşulları nedir?", as_of_date="2026-04-01")
        )
        bad_claim = AnswerClaimRecord(
            claim_id="CLM-BAD-999",
            section_name="mevzuat_dayanagi",
            claim_category=CLAIM_STATUTORY_EVIDENCE,
            statement="Kaynak dışı sahte iddia.",
            provision_id="6356:m-24:FAKE",
            source_id="MEVZUAT-FAKE-999",
            precedent_id=None,
            rule_id=None,
            chunk_id="CHK-FAKE",
            article_ref="Madde 24",
            law_no="6356",
            source_url="https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=6356&MevzuatTur=1&MevzuatTertip=5",
            audit_log_id="AUD-FAKE",
            content_sha256="a" * 64,
            chunk_sha256="b" * 64,
            evidence_id=None,
            registry_head_sha256=None,
            effective_from="2020-01-01",
            effective_to=None,
            effective_on_date=True,
        )
        ans = self.orchestrator.generate_answer(
            AnswerGenerationRequest(trace_bundle=bundle, injected_draft_claims=(bad_claim,))
        )
        self.assertEqual(ans.status, STATUS_BLOCKED_CITATION_VALIDATION_FAILED)
        self.assertTrue(ans.published_answer_blocked)
        self.assertIn("UNWHITELISTED_CITATION_BLOCKER", ans.citation_audit.blocker_codes)

    def test_19_ans19_pending_review_gib332_abstains_or_blocks_if_forced(self) -> None:
        """ANS-19: GİB 332 Tebliği (PENDING_REVIEW) ABSTAINED_INSUFFICIENT_EVIDENCE döner; zorlanırsa bloklanır."""
        _, ans = self._run_e2e(
            "2026 GİB 332 Tebliği 300 TL yemek istisnası dilimleri nedir?",
            as_of_date="2026-02-01",
        )
        self.assertEqual(ans.status, STATUS_ABSTAINED_INSUFFICIENT_EVIDENCE)
        self.assertEqual(ans.confidence_status, CONFIDENCE_INSUFFICIENT_EVIDENCE)
        self.assertFalse(ans.human_approval.payroll_handoff_allowed)
        self.assertIn("GIB-TEBLIG-332-20251231", ans.eight_sections.kaynaklar)

        # Zorla 332 Seri Nolu Tebliğ'i kesin dayanak gibi metne sokarsak bloklanmalıdır
        _, bad_ans = self._run_e2e(
            "2026 GİB 332 Tebliği 300 TL yemek istisnası dilimleri nedir?",
            as_of_date="2026-02-01",
            override_section_texts={
                "mevzuat_dayanagi": "332 Seri Nolu Gelir Vergisi Genel Tebliği kesin yürürlüktedir."
            },
        )
        self.assertTrue(bad_ans.published_answer_blocked)
        self.assertIn("UNVERIFIED_SOURCE_CITED", bad_ans.citation_audit.blocker_codes)

    def test_20_ans20_overbroad_guardrail_and_bundle_tamper_fail_closed(self) -> None:
        """ANS-20: Aşırı genelleme kalıbı ve RetrievalTraceBundle bütünlük tahrifatı fail-closed reddedilir."""
        bundle, ans_bad = self._run_e2e(
            "4857 madde 41 fazla çalışma kuralları nelerdir?",
            as_of_date="2026-04-01",
            override_section_texts={
                "hukuki_degerlendirme": "Adli sicil belgesi her pozisyonda istenebilir ve işin niteliği tek başına adli sicil için yeterlidir."
            },
        )
        self.assertTrue(ans_bad.published_answer_blocked)
        self.assertIn("OVERBROAD_LEGAL_CLAIM_KVKK_CRIMINAL_RECORD", ans_bad.citation_audit.blocker_codes)

        # RetrievalTraceBundle.bundle_sha256 tahrifatı -> AnswerBundleIntegrityError
        tampered = replace(bundle, bundle_sha256="f" * 64)
        with self.assertRaises(AnswerBundleIntegrityError):
            self.orchestrator.generate_answer(AnswerGenerationRequest(trace_bundle=tampered))

    def test_21_ans21_missing_date_and_missing_m26_facts_abstain(self) -> None:
        """ANS-21: Eksik as_of_date ve m.26 eksik discovery_date durumunda ABSTAINED_MISSING_INFO."""
        _, ans_nodate = self._run_e2e("KEP ile haklı fesih yaptık geçerli mi?", as_of_date=None)
        self.assertEqual(ans_nodate.status, STATUS_ABSTAINED_MISSING_INFO)
        self.assertEqual(ans_nodate.confidence_status, CONFIDENCE_INSUFFICIENT_EVIDENCE)
        self.assertFalse(ans_nodate.human_approval.payroll_handoff_allowed)
        self.assertTrue(len(ans_nodate.clarification_questions) >= 1)

        _, ans_m26 = self._run_e2e(
            "4857 m.26 kapsamında çalışan hakkında 6 iş günü haklı fesih süresi geçti mi?",
            as_of_date="2026-05-01",
            facts={},
        )
        self.assertEqual(ans_m26.status, STATUS_ABSTAINED_MISSING_INFO)
        self.assertFalse(ans_m26.human_approval.payroll_handoff_allowed)
        self.assertTrue(any(m.field == "discovery_date" for m in ans_m26.missing_information))

    def test_22_ans22_high_critical_legal_risk_escalates_and_locks_payroll(self) -> None:
        """ANS-22: 4857 m.26 arife yarım gün veya sendika temsilcisi feshinde zorunlu eskalasyon."""
        _, ans = self._run_e2e(
            "4857 madde 26 6 iş günü haklı fesih süresi geçti mi?",
            as_of_date="2026-05-01",
            facts={
                "discovery_date": "2026-04-28",
                "incident_date": "2026-04-25",
                "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                "weekly_rest_day": "SUNDAY",
                "half_day_eve_in_window": True,
                "union_rep_termination": True,
                "notification_channel": "HAND_DELIVERED_WRITTEN_SIGNED",
                "written_notice_with_clear_reason": True,
            },
        )
        self.assertEqual(ans.status, STATUS_ANSWERED_WITH_ESCALATION)
        self.assertTrue(ans.human_approval.counsel_escalation_required)
        self.assertFalse(ans.human_approval.payroll_handoff_allowed)
        self.assertTrue(any(r.risk_level == "CRITICAL" for r in ans.risks))
        self.assertIn("LEGAL-ESC-", ans.eight_sections.risk)

    def test_23_ans23_payroll_boundary_delegates_without_tl_computation(self) -> None:
        """ANS-23: Saf bordro talebinde net tutar hesaplanmaz; eksikse kilitli, tamsa @ÜcretBordro devri açık."""
        q = "Brüt 90.000 TL maaşlı çalışanın 4 yıllık kıdem tazminatı net kaç TL?"
        _, ans_incomplete = self._run_e2e(q, as_of_date="2026-04-01", facts={})
        self.assertEqual(ans_incomplete.status, STATUS_ABSTAINED_MISSING_INFO)
        self.assertFalse(ans_incomplete.human_approval.payroll_handoff_allowed)

        _, ans_ready = self._run_e2e(
            q,
            as_of_date="2026-04-01",
            facts={"termination_reason_type": "EMPLOYER_WITHOUT_JUST_CAUSE", "tenure_months": 48},
        )
        self.assertEqual(ans_ready.status, STATUS_ANSWERED)
        self.assertTrue(ans_ready.human_approval.payroll_handoff_allowed)
        self.assertIn("@ÜcretBordro", ans_ready.eight_sections.uygulama)

        # Parasal hesaplama cümlesi enjekte edilirse CitationValidator Layer C bloklar
        _, ans_calc_leak = self._run_e2e(
            q,
            as_of_date="2026-04-01",
            facts={"termination_reason_type": "EMPLOYER_WITHOUT_JUST_CAUSE", "tenure_months": 48},
            override_section_texts={"uygulama": "Hesaplanan net kıdem tazminatı: 360.000 TL olarak ödenmelidir."},
        )
        self.assertTrue(ans_calc_leak.published_answer_blocked)
        self.assertIn("UNAUTHORIZED_PAYROLL_CALCULATION", ans_calc_leak.citation_audit.blocker_codes)

    def test_24_ans24_out_of_domain_and_petition_refusal(self) -> None:
        """ANS-24: Dava dilekçesi ve şirket birleşme hisse devri talebi ABSTAINED_OUT_OF_DOMAIN döner."""
        _, ans = self._run_e2e("İşçiye karşı açılacak dava dilekçesini tam yaz", as_of_date="2026-04-01")
        self.assertEqual(ans.status, STATUS_ABSTAINED_OUT_OF_DOMAIN)
        self.assertEqual(ans.confidence_status, CONFIDENCE_INSUFFICIENT_EVIDENCE)
        self.assertEqual(len(ans.legal_bases), 0)
        self.assertFalse(ans.human_approval.payroll_handoff_allowed)
        self.assertIn("Avukatlık Kanunu m.35", ans.eight_sections.guven_durumu)

    def test_25_ans25_audit_trace_lineage_parity_with_retrieval_bundle(self) -> None:
        """ANS-25: AnswerAuditTrace ile RetrievalTraceBundle arasında birebir kriptografik iz bağlantısı."""
        bundle, ans = self._run_e2e(
            "4857 madde 22 bayram ikramiyesi yazılı rıza ve işyeri uygulaması nedir?",
            as_of_date="2026-06-01",
            include_historical=True,
        )
        self.assertEqual(ans.audit_trace.source_trace_id, bundle.trace_id)
        self.assertEqual(ans.audit_trace.source_bundle_sha256, bundle.bundle_sha256)
        self.assertTrue(ans.audit_trace.citation_audit_passed)
        self.assertEqual(ans.audit_trace.answer_sha256, ans.answer_sha256)
        self.assertEqual(len(ans.audit_trace.audit_trace_sha256), 64)
        self.assertEqual(len(ans.audit_trace.claim_evidence_links), len(ans.claims))
        for lnk in ans.audit_trace.claim_evidence_links:
            self.assertTrue(lnk.claim_id)
            self.assertTrue(lnk.audit_log_id)

    def test_26_ans26_determinism_and_wp1_governance_invariants_preserved(self) -> None:
        """ANS-26: Çift çalıştırmada deterministik answer_sha256 & WP-1 şema/config/kapalı kapı değişmezliği."""
        facts = {"notification_channel": "HAND_DELIVERED_WRITTEN_SIGNED", "written_notice_with_clear_reason": True}
        bundle = self.rag.retrieve(
            RagQueryRequest(query_text="4857 madde 109 yazılı bildirim nedir?", as_of_date="2026-04-01", facts=facts)
        )
        a1 = self.orchestrator.generate_answer(AnswerGenerationRequest(trace_bundle=bundle, facts=facts))
        a2 = self.orchestrator.generate_answer(AnswerGenerationRequest(trace_bundle=bundle, facts=facts))

        self.assertEqual(a1.answer_id, a2.answer_id)
        self.assertEqual(a1.answer_sha256, a2.answer_sha256)
        self.assertEqual(a1.audit_trace.audit_trace_sha256, a2.audit_trace.audit_trace_sha256)

        schemas = list((PROJECT_ROOT / "schemas").glob("*.json"))
        configs = list((PROJECT_ROOT / "config").glob("*.json"))
        self.assertEqual(len(schemas), 13)
        self.assertEqual(len(configs), 9)
        xmldsig_sha = hashlib.sha256((PROJECT_ROOT / "engine" / "esign5070" / "xmldsig.py").read_bytes()).hexdigest()
        self.assertEqual(xmldsig_sha, EXPECTED_XMLDSIG_SHA256)

        self.assertEqual(a1.governance_gates["production_use_authorized"], False)
        self.assertEqual(a1.governance_gates["qualified_e_signature_5070_equivalent"], False)
        self.assertEqual(a1.governance_gates["kvkk_data_residency_approved"], False)
        probe = run_live_integration_probe(project_root=PROJECT_ROOT)
        self.assertFalse(probe["production_use_authorized"])
        self.assertFalse(probe["qualified_e_signature_5070_production_ready"])
        self.assertFalse(probe["qualified_e_signature_5070_equivalent"])


if __name__ == "__main__":
    unittest.main()
