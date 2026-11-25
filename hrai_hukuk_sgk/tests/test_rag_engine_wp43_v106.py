"""Comprehensive WP-4.3 RAG Engine Acceptance Tests (`RAG-01`..`RAG-12`)."""

from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest

from engine.knowledge_base import (
    COURT_DANISTAY,
    COURT_YARGITAY,
    DOC_KIND_AUTONOMOUS_NORM,
    DOC_KIND_INTERPRETATION_CARD,
    DOC_KIND_JUDICIAL_PRECEDENT,
    DOC_KIND_SECONDARY_REGULATION,
    DOC_KIND_STATUTORY_PROVISION,
    VERIFICATION_VERIFIED,
    JudicialPrecedentNode,
    LegalDocumentVersion,
    LegalProvisionNode,
    LegalStructuralChunker,
    LocalDeterministicHybridStore,
    canonical_kb_sha256,
)
from engine.rag import (
    BINDING_REGISTRY_AUDIT_BACKED_NO_TRUST_CHAIN,
    BINDING_TRUST_CHAIN_EVIDENCE_BOUND,
    BINDING_TRUST_CHAIN_INTEGRITY_MISMATCH,
    BUCKET_PRECEDENT,
    DOMAIN_LABOR_LAW,
    DOMAIN_MIXED_MULTI_DOMAIN,
    DOMAIN_OCCUPATIONAL_HEALTH_AND_SAFETY,
    DOMAIN_OUT_OF_DOMAIN,
    DOMAIN_PAYROLL_DELEGATION_ONLY,
    DOMAIN_PERSONAL_DATA_PROTECTION,
    DOMAIN_SOCIAL_SECURITY,
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
    HukukSgkRagEngine,
    RagQueryRequest,
)
from engine.trust_root import run_live_integration_probe

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_XMLDSIG_SHA256 = "b16207b5fb71d7c0d0372838411c7795459ac460c2ff232766ae230b9cbacf85"
_SHARED_RAG_ENGINES: dict[Path, HukukSgkRagEngine] = {}


class TestRagEngineWp43V106(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        resolved = PROJECT_ROOT.resolve()
        eng = _SHARED_RAG_ENGINES.get(resolved)
        if eng is None:
            eng = HukukSgkRagEngine.from_project_root(project_root=PROJECT_ROOT)
            _SHARED_RAG_ENGINES[resolved] = eng
        cls.engine = eng

    def test_01_rag01_intent_multi_domain_and_inline_date_extraction(self) -> None:
        """RAG-01: Niyet & çoklu alan yönlendirme + metinden tekil as_of_date çıkarımı."""
        bundle = self.engine.retrieve(
            RagQueryRequest(
                query_text="2026-04-01'de sağlık raporu sebebiyle işten çıkarma, iş kazası bildirimi ve SGK çıkış kodu",
                as_of_date=None,
                facts={
                    "notification_channel": "HAND_DELIVERED_WRITTEN_SIGNED",
                    "written_notice_with_clear_reason": True,
                    "written_defense_status": "OBTAINED_WRITTEN",
                    "workplace_total_employees": 50,
                    "tenure_months": 24,
                },
                top_k=8,
            )
        )
        self.assertEqual(bundle.as_of_date, "2026-04-01")
        self.assertEqual(bundle.temporal_audit.date_source, "EXTRACTED_FROM_QUERY")
        self.assertEqual(bundle.intent_classification.intent, INTENT_FACT_SCENARIO_ANALYSIS)
        self.assertEqual(bundle.intent_classification.primary_domain, DOMAIN_MIXED_MULTI_DOMAIN)
        for dom in (
            DOMAIN_LABOR_LAW,
            DOMAIN_SOCIAL_SECURITY,
            DOMAIN_OCCUPATIONAL_HEALTH_AND_SAFETY,
            DOMAIN_PERSONAL_DATA_PROTECTION,
        ):
            self.assertIn(dom, bundle.intent_classification.secondary_domains)

        norm_laws = {item.chunk.law_no for item in bundle.normative_bucket}
        self.assertTrue({"4857", "5510", "6331", "6698"}.issubset(norm_laws), f"Eksik çoklu alan kanunu: {norm_laws}")
        self.assertGreater(len(bundle.intent_classification.sub_queries), 1)

    def test_02_rag02_missing_as_of_date_fails_closed_without_guessing_today(self) -> None:
        """RAG-02: Olay tarihi (as_of_date) yoksa bugünün tarihi varsayılmadan ABSTAIN_MISSING_INFO."""
        bundle = self.engine.retrieve(
            RagQueryRequest(
                query_text="KEP ile haklı fesih yaptık geçerli mi?",
                as_of_date=None,
            )
        )
        self.assertEqual(bundle.rag_gate_status, GATE_ABSTAIN_MISSING_INFO)
        self.assertFalse(bundle.should_conclude)
        self.assertFalse(bundle.payroll_handoff_allowed)
        self.assertIsNone(bundle.as_of_date)
        self.assertEqual(bundle.temporal_audit.error_code, "MISSING_AS_OF_DATE")
        self.assertIn("as_of_date", bundle.missing_facts)
        self.assertTrue(len(bundle.clarification_questions) >= 1)
        self.assertEqual(len(bundle.normative_bucket), 0)
        self.assertEqual(len(bundle.citation_whitelist.allowed_source_ids), 0)

        # Birden fazla çelişkili tarih varsa da sessiz varsayım yapılmaz
        ambiguous = self.engine.retrieve(
            RagQueryRequest(
                query_text="2025-07-10 tarihinde olay oldu 2025-09-01 tarihinde KEP feshi yaptık geçerli mi?",
                as_of_date=None,
            )
        )
        self.assertEqual(ambiguous.rag_gate_status, GATE_ABSTAIN_MISSING_INFO)
        self.assertEqual(ambiguous.temporal_audit.error_code, "AMBIGUOUS_MULTIPLE_DATES")
        self.assertFalse(ambiguous.should_conclude)

    def test_03_rag03_temporal_cutoff_7555_m109_version_switch_and_kep_escalation(self) -> None:
        """RAG-03: 7555 kesim tarihi (2025-07-24) öncesi vs sonrası m.109 sürüm ayrımı ve KEP eskalasyonu."""
        q = "4857 madde 109 KEP ile fesih bildirimi geçerli mi?"
        facts_kep = {
            "notification_channel": "KEP_ONLY",
            "written_notice_with_clear_reason": True,
        }

        pre = self.engine.retrieve(
            RagQueryRequest(query_text=q, as_of_date="2025-07-10", facts=facts_kep, include_historical=True)
        )
        pre_m109_dvs = [i.chunk.document_version_id for i in pre.normative_bucket if i.chunk.provision_id == "4857:m-109"]
        self.assertIn("DV-MEVZUAT-4857-V1", pre_m109_dvs)
        self.assertNotIn("DV-RG-7555-20250724", pre_m109_dvs)
        self.assertIn("PRE_7555_OLD_M109_REGIME", pre.temporal_audit.cutoff_flags)
        self.assertNotIn("M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI", pre.escalation_reasons)

        post = self.engine.retrieve(
            RagQueryRequest(query_text=q, as_of_date="2025-09-01", facts=facts_kep, include_historical=True)
        )
        post_m109_dvs = [i.chunk.document_version_id for i in post.normative_bucket if i.chunk.provision_id == "4857:m-109"]
        hist_m109_dvs = [
            i.chunk.document_version_id
            for i in post.historical_context_bucket
            if i.chunk.provision_id == "4857:m-109"
        ]
        self.assertIn("DV-RG-7555-20250724", post_m109_dvs)
        self.assertNotIn("DV-MEVZUAT-4857-V1", post_m109_dvs)
        self.assertIn("DV-MEVZUAT-4857-V1", hist_m109_dvs)
        self.assertEqual(post.rag_gate_status, GATE_EVIDENCE_READY_WITH_ESCALATION)
        self.assertTrue(post.should_conclude)
        self.assertTrue(post.counsel_escalation_required)
        self.assertFalse(post.payroll_handoff_allowed)
        self.assertIn("M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI", post.escalation_reasons)

    def test_04_rag04_bucket_isolation_and_one_hop_cross_ref_expansion(self) -> None:
        """RAG-04: 3+1 kova izolasyonu ve 4857 m.25/II-e -> 1-hop m.26 & m.109 çapraz atıf genişletmesi."""
        full_facts = {
            "notification_channel": "HAND_DELIVERED_WRITTEN_SIGNED",
            "written_notice_with_clear_reason": True,
            "discovery_date": "2026-03-08",
            "incident_date": "2026-03-07",
            "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
            "weekly_rest_day": "SUNDAY",
        }
        bundle = self.engine.retrieve(
            RagQueryRequest(
                query_text="4857 m.25/II-e güveni kötüye kullanma feshi",
                as_of_date="2026-03-10",
                facts=full_facts,
                top_k=5,
            )
        )
        self.assertEqual(bundle.rag_gate_status, GATE_EVIDENCE_READY)
        self.assertTrue(bundle.should_conclude)

        norm_provs = [i.chunk.provision_id for i in bundle.normative_bucket]
        self.assertEqual(norm_provs[0], "4857:m-25:f-2:b-e")
        self.assertIn("4857:m-26:f-1", norm_provs)
        self.assertIn("4857:m-109", norm_provs)
        # Çapraz atıfla gelen m.109 yalnızca 2026'da yürürlükte olan 7555 sonrası sürüm olmalıdır
        m109_items = [i for i in bundle.normative_bucket if i.chunk.provision_id == "4857:m-109"]
        self.assertEqual([i.chunk.document_version_id for i in m109_items], ["DV-RG-7555-20250724"])
        self.assertTrue(any(i.origin == "CROSS_REF_EXPANSION" for i in bundle.normative_bucket))

        # Kova saflığı kontrolleri
        self.assertTrue(
            all(
                i.chunk.document_kind in {DOC_KIND_STATUTORY_PROVISION, DOC_KIND_SECONDARY_REGULATION}
                for i in bundle.normative_bucket
            )
        )
        self.assertTrue(
            all(i.chunk.document_kind == DOC_KIND_INTERPRETATION_CARD for i in bundle.interpretation_bucket)
        )
        self.assertTrue(
            all(i.chunk.document_kind == DOC_KIND_JUDICIAL_PRECEDENT for i in bundle.precedent_bucket)
        )
        self.assertTrue(
            all(i.chunk.document_kind == DOC_KIND_AUTONOMOUS_NORM for i in bundle.autonomous_norm_bucket)
        )
        # 1-hop genişletilen m.26 & m.109 yorum kuralları Bucket 2'ye yansımalı
        interp_rule_ids = {r.rule_id for i in bundle.interpretation_bucket for r in i.companion_rules}
        self.assertIn("INT-4857-M26-DEADLINE-CALENDAR", interp_rule_ids)
        self.assertIn("INT-4857-M109-7555-BOUNDARY", interp_rule_ids)

    def test_05_rag05_norm_hierarchy_supremacy_and_ck_distinct_from_cbk(self) -> None:
        """RAG-05: Yönetmelik/Genelge Kanunu bastıramaz; CK (10766) asla CBK sayılmaz."""
        res_stat = self.engine.retrieve(
            RagQueryRequest(
                query_text="4857 yıllık izin ve fazla çalışma süresi",
                as_of_date="2026-04-01",
            )
        )
        self.assertGreater(len(res_stat.normative_bucket), 0)
        top_norm = res_stat.normative_bucket[0]
        self.assertEqual(top_norm.chunk.norm_layer, "STATUTORY_LAW")
        self.assertEqual(top_norm.chunk.norm_priority, 3)
        self.assertIn(top_norm.chunk.provision_id, {"4857:m-41:f-1", "4857:m-53:f-1"})

        res_ck = self.engine.retrieve(
            RagQueryRequest(
                query_text="10766 CK Ar-Ge teknokent uzaktan çalışma oranları nedir?",
                as_of_date="2026-04-01",
                include_historical=True,
            )
        )
        ck_items = [i for i in res_ck.normative_bucket if i.chunk.source_id == "RG-10766-20251225"]
        self.assertEqual(len(ck_items), 1)
        self.assertEqual(ck_items[0].chunk.norm_layer, "PRESIDENTIAL_DECISION")
        self.assertEqual(ck_items[0].chunk.norm_priority, 5)
        self.assertNotEqual(ck_items[0].chunk.norm_layer, "PRESIDENTIAL_DECREE")
        self.assertIn("NORM_LAYER_CK_PRESIDENTIAL_DECISION_NOT_CBK", ck_items[0].flags)
        # 10766 CK (priority 5) Yönetmelik'in (priority 6) altında kalmamalı
        ck_rank = ck_items[0].rank
        reg_ranks = [i.rank for i in res_ck.normative_bucket if i.chunk.norm_layer == "REGULATION"]
        if reg_ranks:
            self.assertLess(ck_rank, min(reg_ranks))
        # Mülga 9368 CK yalnızca tarihsel kovada yer alır
        self.assertFalse(any(i.chunk.source_id == "RG-9368-20241228" for i in res_ck.normative_bucket))
        self.assertTrue(any(i.chunk.source_id == "RG-9368-20241228" for i in res_ck.historical_context_bucket))

    def test_06_rag06_precedent_isolation_yargitay_vs_danistay_and_post_amendment_escalation(self) -> None:
        """RAG-06: Yargıtay/Danıştay ayrı içtihat kovası + karar sonrası kanun değişikliği cezası."""
        res_yarg = self.engine.retrieve(
            RagQueryRequest(
                query_text="2017/9 sağlık feshinde savunma Yargıtay içtihadı",
                as_of_date="2026-04-01",
            )
        )
        self.assertEqual(res_yarg.intent_classification.intent, INTENT_PRECEDENT_CHECK)
        self.assertFalse(any(i.chunk.source_id == "YIBBGK-2017-9-2018-10" for i in res_yarg.normative_bucket))
        yarg_prec = [
            i for i in res_yarg.precedent_bucket if i.precedent_metadata.get("precedent_id") == "YIBBGK-2017-9-2018-10"
        ]
        self.assertTrue(len(yarg_prec) >= 1)
        self.assertEqual(yarg_prec[0].precedent_metadata["court_system"], COURT_YARGITAY)
        self.assertTrue(yarg_prec[0].precedent_metadata["is_non_legislative"])
        self.assertTrue(len(yarg_prec[0].precedent_metadata["applies_to"]) >= 1)
        self.assertTrue(len(yarg_prec[0].precedent_metadata["does_not_apply_to"]) >= 1)

        # İzole depoda sentetik doğrulanmış Danıştay + karar sonrası değişiklik cezası testi
        iso_store = LocalDeterministicHybridStore()
        chunker = LegalStructuralChunker()
        stat_node = LegalProvisionNode(
            provision_id="5510:m-102:f-1",
            document_version_id="DV-TEST-5510",
            source_id="MEVZUAT-5510",
            law_no="5510",
            article_no="Madde 102",
            article_title="SGK İPC",
            raw_text="5510 m.102 SGK idari para cezası tebliğ ve itiraz.",
            normalized_text="5510 m.102 SGK idari para cezası.",
            publication_date="2008-10-01",
            effective_from="2008-10-01",
            effective_to=None,
            norm_layer="STATUTORY_LAW",
            norm_priority=3,
            norm_character="ABSOLUTE_MANDATORY",
            verification_status=VERIFICATION_VERIFIED,
            content_sha256=canonical_kb_sha256({"s": 5510}),
        )
        dan_amended = JudicialPrecedentNode(
            precedent_id="TEST-DAN-10D-AMENDED",
            court_system=COURT_DANISTAY,
            chamber="10_D",
            binding_level="DANISTAY_DAIRE_SETTLED",
            esas_no="2020/11",
            karar_no="2022/22",
            decision_date="2022-05-01",
            official_source_url="https://karararama.danistay.gov.tr/test-dan-amended",
            interpreted_provision_ids=("5510:m-102:f-1",),
            legal_principle="5510 m.102 SGK idari para cezası tebliğ itiraz usulü (eski dönem).",
            operative_holding="Karar sonrası kanun değişikliği mevcuttur.",
            applies_to=("5510 m.102 eski dönem İPC",),
            does_not_apply_to=("Değişiklik sonrası yeni dönem İPC",),
            verification_status=VERIFICATION_VERIFIED,
            post_decision_amendment_status="AMENDED_BY_SUBSEQUENT_STATUTE",
            content_sha256=canonical_kb_sha256({"dan": 1}),
            keywords=("5510", "danıştay", "m.102"),
        )
        dan_ibk = JudicialPrecedentNode(
            precedent_id="TEST-DAN-IBK-UNAFFECTED",
            court_system=COURT_DANISTAY,
            chamber="IBK",
            binding_level="STATUTORY_BINDING_DANISTAY_IBK",
            esas_no="2024/5",
            karar_no="2025/1",
            decision_date="2025-06-01",
            official_source_url="https://karararama.danistay.gov.tr/test-dan-ibk",
            interpreted_provision_ids=("5510:m-102:f-1",),
            legal_principle="5510 m.102 idari para cezası itirazında 2575 m.39 uyarınca güncel İBK ilkesi.",
            operative_holding="Güncel İBK yürürlükteki 5510 m.102 ile uyumludur.",
            applies_to=("5510 m.102 SGK idari para cezası",),
            does_not_apply_to=("Bireysel iş davaları",),
            verification_status=VERIFICATION_VERIFIED,
            post_decision_amendment_status="UNAFFECTED",
            content_sha256=canonical_kb_sha256({"dan": 2}),
            keywords=("5510", "danıştay", "m.102"),
        )
        yarg_other = JudicialPrecedentNode(
            precedent_id="TEST-YARG-9HD",
            court_system=COURT_YARGITAY,
            chamber="9_HD",
            binding_level="CHAMBER_SETTLED",
            esas_no="2024/1",
            karar_no="2024/2",
            decision_date="2024-03-01",
            official_source_url="https://karararama.yargitay.gov.tr/test-yarg",
            interpreted_provision_ids=("4857:m-25",),
            legal_principle="4857 m.25 fesih.",
            operative_holding="İş yargısı kararı.",
            applies_to=("4857",),
            does_not_apply_to=("5510 İPC",),
            verification_status=VERIFICATION_VERIFIED,
            content_sha256=canonical_kb_sha256({"yarg": 1}),
            keywords=("4857",),
        )
        iso_store.upsert_bundle(
            provisions=[stat_node],
            precedents=[dan_amended, dan_ibk, yarg_other],
            chunks=(
                chunker.chunk_provision(stat_node, content_verified=True)
                + chunker.chunk_precedent(dan_amended, content_verified=True)
                + chunker.chunk_precedent(dan_ibk, content_verified=True)
                + chunker.chunk_precedent(yarg_other, content_verified=True)
            ),
        )
        iso_rag = HukukSgkRagEngine(iso_store, project_root=None)
        dan_bundle = iso_rag.retrieve(
            RagQueryRequest(
                query_text="5510 m.102 SGK idari para cezası Danıştay içtihadı",
                as_of_date="2026-04-01",
                court_systems=(COURT_DANISTAY,),
            )
        )
        self.assertTrue(len(dan_bundle.precedent_bucket) >= 2)
        self.assertTrue(all(i.precedent_metadata["court_system"] == COURT_DANISTAY for i in dan_bundle.precedent_bucket))
        self.assertEqual(dan_bundle.precedent_bucket[0].precedent_metadata["precedent_id"], "TEST-DAN-IBK-UNAFFECTED")
        self.assertEqual(dan_bundle.rag_gate_status, GATE_EVIDENCE_READY_WITH_ESCALATION)
        self.assertTrue(
            any("COUNSEL_REVIEW_REQUIRED_POST_DECISION_AMENDMENT:TEST-DAN-10D-AMENDED" in r for r in dan_bundle.escalation_reasons)
        )

    def test_07_rag07_pending_review_only_source_abstains_honestly(self) -> None:
        """RAG-07: Yalnızca PENDING_REVIEW kaynakta (GİB 332 Tebliği) fail-closed ABSTAIN_INSUFFICIENT_EVIDENCE."""
        bundle = self.engine.retrieve(
            RagQueryRequest(
                query_text="2026 GİB 332 Tebliği 300 TL yemek istisnası dilimleri nedir?",
                as_of_date="2026-02-01",
            )
        )
        self.assertEqual(bundle.rag_gate_status, GATE_ABSTAIN_INSUFFICIENT_EVIDENCE)
        self.assertFalse(bundle.should_conclude)
        self.assertFalse(bundle.payroll_handoff_allowed)
        excl_ids = {n.source_id for n in bundle.excluded_unverified_notices}
        self.assertIn("GIB-TEBLIG-332-20251231", excl_ids)
        self.assertIsNotNone(bundle.unverified_disclosure_message)
        self.assertIn("GIB-TEBLIG-332-20251231", bundle.unverified_disclosure_message or "")
        self.assertNotIn("GIB-TEBLIG-332-20251231", bundle.citation_whitelist.allowed_source_ids)

    def test_08_rag08_evidence_registry_binding_and_tamper_rejection(self) -> None:
        """RAG-08: TrustChainEvidenceAdapterProtocol pozitif bağlama ve SHA-256 tahrifatında ret."""
        raw_clean = b"4857 Sayili Is Kanunu Madde 25 Resmi Gazete dogrulanmis ham icerik."
        sha_clean = hashlib.sha256(raw_clean).hexdigest()
        rec_sha_clean = canonical_kb_sha256({"evidence_id": "EV-4857-25", "content_sha256": sha_clean})
        head_sha = canonical_kb_sha256({"head": "EV-4857-25"})

        class _MockTrustChainAdapter:
            def __init__(self, *, tamper_raw: bool = False) -> None:
                self._tamper_raw = tamper_raw
                self._records = {
                    "EV-4857-25": SimpleNamespace(
                        evidence_id="EV-4857-25",
                        is_verified_authority=True,
                        content_sha256=sha_clean,
                        record_sha256=rec_sha_clean,
                        registry_head_sha256=head_sha,
                        transport_mode="VERIFIED_TEST_TRANSPORT",
                        live_verified=False,
                    )
                }

            def get(self, evidence_id: str):
                return self._records.get(evidence_id)

            def verify_integrity(self, *, require_raw_content: bool = True):
                return True, {"valid": True, "head_sha256": head_sha}

            def get_raw_bytes(self, evidence_id: str):
                if evidence_id != "EV-4857-25":
                    return None
                return b"TAHRIF EDILMIS HAM BAYT!" if self._tamper_raw else raw_clean

        chunker = LegalStructuralChunker()
        dv = LegalDocumentVersion(
            document_version_id="DV-TC-4857",
            source_id="MEVZUAT-4857",
            evidence_id="EV-4857-25",
            document_kind=DOC_KIND_STATUTORY_PROVISION,
            norm_layer="STATUTORY_LAW",
            norm_priority=3,
            statute_no="4857",
            title="4857 İş Kanunu TC Test",
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
            document_version_id="DV-TC-4857",
            source_id="MEVZUAT-4857",
            evidence_id="EV-4857-25",
            law_no="4857",
            article_no="Madde 25",
            article_title="4857 m.25 Trust Chain Kanıtlı Hüküm",
            raw_text="4857 madde 25 haklı fesih sebebi ve yazılı bildirim.",
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
        chunks = chunker.chunk_provision(prov, content_verified=True)

        # 1. Pozitif bağlama: TRUST_CHAIN_EVIDENCE_BOUND
        good_adapter = _MockTrustChainAdapter(tamper_raw=False)
        store_good = LocalDeterministicHybridStore(trust_chain_adapter=good_adapter)
        store_good.upsert_bundle(document_versions=[dv], provisions=[prov], chunks=chunks)
        rag_good = HukukSgkRagEngine(store_good, trust_chain_adapter=good_adapter)
        res_good = rag_good.retrieve(RagQueryRequest(query_text="4857 madde 25 hükmü nedir?", as_of_date="2026-04-01"))
        self.assertEqual(res_good.rag_gate_status, GATE_EVIDENCE_READY)
        self.assertEqual(len(res_good.normative_bucket), 1)
        self.assertEqual(res_good.normative_bucket[0].evidence_binding_status, BINDING_TRUST_CHAIN_EVIDENCE_BOUND)
        self.assertEqual(res_good.evidence_bindings[0].evidence_id, "EV-4857-25")
        self.assertEqual(res_good.evidence_bindings[0].record_sha256, rec_sha_clean)
        self.assertEqual(res_good.evidence_bindings[0].registry_head_sha256, head_sha)
        self.assertTrue(res_good.evidence_bindings[0].raw_content_verified)
        self.assertIn("EV-4857-25", res_good.citation_whitelist.allowed_evidence_ids)

        # 2. Negatif tahrifat: ham bayt SHA-256 uyuşmazlığında TRUST_CHAIN_INTEGRITY_MISMATCH + ABSTAIN
        bad_adapter = _MockTrustChainAdapter(tamper_raw=True)
        store_bad = LocalDeterministicHybridStore(trust_chain_adapter=bad_adapter)
        store_bad.upsert_bundle(document_versions=[dv], provisions=[prov], chunks=chunks)
        rag_bad = HukukSgkRagEngine(store_bad, trust_chain_adapter=bad_adapter)
        res_bad = rag_bad.retrieve(RagQueryRequest(query_text="4857 madde 25 hükmü nedir?", as_of_date="2026-04-01"))
        self.assertEqual(res_bad.rag_gate_status, GATE_ABSTAIN_INSUFFICIENT_EVIDENCE)
        self.assertFalse(res_bad.should_conclude)
        self.assertEqual(len(res_bad.normative_bucket), 0)
        self.assertEqual(len(res_bad.quarantined_evidence_mismatches), 1)
        self.assertEqual(
            res_bad.quarantined_evidence_mismatches[0].evidence_binding_status,
            BINDING_TRUST_CHAIN_INTEGRITY_MISMATCH,
        )
        self.assertEqual(res_bad.quarantined_evidence_mismatches[0].failure_reason, "TRUST_CHAIN_RAW_BYTES_SHA256_MISMATCH")

    def test_09_rag09_missing_facts_matrix_blocks_conclusion_and_asks_questions(self) -> None:
        """RAG-09: as_of_date verilmiş olsa dahi m.26 kritik olguları eksikse ABSTAIN_MISSING_INFO."""
        bundle = self.engine.retrieve(
            RagQueryRequest(
                query_text="4857 m.26 kapsamında çalışan hakkında 6 iş günü haklı fesih süresi geçti mi?",
                as_of_date="2026-05-01",
                facts={},
            )
        )
        self.assertEqual(bundle.rag_gate_status, GATE_ABSTAIN_MISSING_INFO)
        self.assertFalse(bundle.should_conclude)
        self.assertFalse(bundle.payroll_handoff_allowed)
        self.assertIn("discovery_date", bundle.missing_facts)
        self.assertIn("incident_date", bundle.missing_facts)
        self.assertTrue(len(bundle.clarification_questions) >= 2)

    def test_10_rag10_pure_payroll_delegation_checks_prerequisites_and_never_calculates(self) -> None:
        """RAG-10: Saf bordro hesabı sorusunda 1475 m.14 ön koşulu + çıkış nedeni yoksa devir kilitli, tam ise açık."""
        q = "Brüt 90.000 TL maaşlı çalışanın 4 yıllık kıdem tazminatı net kaç TL?"

        incomplete = self.engine.retrieve(
            RagQueryRequest(query_text=q, as_of_date="2026-04-01", facts={})
        )
        self.assertEqual(incomplete.intent_classification.intent, INTENT_PAYROLL_DELEGATION_ONLY)
        self.assertEqual(incomplete.intent_classification.primary_domain, DOMAIN_PAYROLL_DELEGATION_ONLY)
        self.assertEqual(incomplete.rag_gate_status, GATE_ABSTAIN_MISSING_INFO)
        self.assertFalse(incomplete.payroll_handoff_allowed)
        self.assertIn("termination_reason_type", incomplete.missing_facts)

        complete = self.engine.retrieve(
            RagQueryRequest(
                query_text=q,
                as_of_date="2026-04-01",
                facts={
                    "termination_reason_type": "EMPLOYER_WITHOUT_JUST_CAUSE",
                    "tenure_months": 48,
                },
            )
        )
        self.assertEqual(complete.rag_gate_status, GATE_EVIDENCE_READY)
        self.assertTrue(complete.should_conclude)
        self.assertTrue(complete.payroll_handoff_allowed)
        self.assertTrue(
            any(i.chunk.provision_id in {"1475:m-14:f-1", "CARD-1475-M14"} for i in (*complete.normative_bucket, *complete.interpretation_bucket))
        )

    def test_11_rag11_out_of_domain_and_petition_requests_abstain_cleanly(self) -> None:
        """RAG-11: Dava dilekçesi ve şirket birleşme/hisse devri gibi alan dışı taleplerde fail-closed ret."""
        for bad_q in (
            "İşçiye karşı açılacak dava dilekçesini tam yaz",
            "Şirket birleşme hisse devri sözleşmesi hazırla",
        ):
            bundle = self.engine.retrieve(RagQueryRequest(query_text=bad_q, as_of_date="2026-04-01"))
            self.assertEqual(bundle.intent_classification.intent, INTENT_OUT_OF_DOMAIN, bad_q)
            self.assertEqual(bundle.intent_classification.primary_domain, DOMAIN_OUT_OF_DOMAIN, bad_q)
            self.assertEqual(bundle.rag_gate_status, GATE_ABSTAIN_OUT_OF_DOMAIN, bad_q)
            self.assertFalse(bundle.should_conclude, bad_q)
            self.assertFalse(bundle.payroll_handoff_allowed, bad_q)
            self.assertEqual(bundle.normative_bucket, (), bad_q)
            self.assertEqual(bundle.precedent_bucket, (), bad_q)
            self.assertEqual(bundle.citation_whitelist.allowed_source_ids, (), bad_q)

    def test_12_rag12_full_traceability_whitelist_and_determinism_plus_wp1_invariants(self) -> None:
        """RAG-12: Tam izlenebilirlik (chunk/provision/source/sha256/audit_log_id), CitationWhitelist ve determinizm."""
        req = RagQueryRequest(
            query_text="4857 madde 22 bayram ikramiyesi yazılı rıza ve işyeri uygulaması nedir?",
            as_of_date="2026-06-01",
            include_historical=True,
        )
        run1 = self.engine.retrieve(req)
        run2 = self.engine.retrieve(req)

        # Deterministik bundle_sha256 ve trace_id (duvar saatinden bağımsız)
        self.assertEqual(run1.trace_id, run2.trace_id)
        self.assertEqual(run1.bundle_sha256, run2.bundle_sha256)
        self.assertEqual(len(run1.bundle_sha256), 64)
        self.assertTrue(run1.trace_id.startswith("RAG-TRC-"))

        # Her aktif kova öğesi tam kimlik + SHA-256 + audit_log_id + dürüst binding taşımalı
        all_active = (
            *run1.normative_bucket,
            *run1.interpretation_bucket,
            *run1.precedent_bucket,
            *run1.autonomous_norm_bucket,
        )
        self.assertGreater(len(all_active), 0)
        for item in all_active:
            self.assertTrue(item.chunk.chunk_id)
            self.assertTrue(item.chunk.provision_id)
            self.assertTrue(item.chunk.source_id)
            self.assertEqual(len(item.chunk.content_sha256), 64)
            self.assertTrue(item.audit_log_id)
            self.assertEqual(item.evidence_binding_status, BINDING_REGISTRY_AUDIT_BACKED_NO_TRUST_CHAIN)
            if item.bucket == BUCKET_PRECEDENT:
                self.assertIn(item.chunk.source_id, run1.citation_whitelist.allowed_precedent_ids)
            else:
                self.assertIn(item.chunk.source_id, run1.citation_whitelist.allowed_source_ids)

        # Pending GİB 332 ve kabul edilmemiş L5/L6 hiçbir zaman whitelist'e giremez
        self.assertNotIn("GIB-TEBLIG-332-20251231", run1.citation_whitelist.allowed_source_ids)
        self.assertNotIn("RG-9368-20241228", run1.citation_whitelist.allowed_source_ids)
        self.assertNotIn("HRAI-L6-UYG-04", run1.citation_whitelist.allowed_source_ids)

        # WP-1 değişmezleri ve kapalı kapılar kontrolü
        schemas = list((PROJECT_ROOT / "schemas").glob("*.json"))
        configs = list((PROJECT_ROOT / "config").glob("*.json"))
        self.assertEqual(len(schemas), 13)
        self.assertEqual(len(configs), 9)
        xmldsig_sha = hashlib.sha256((PROJECT_ROOT / "engine" / "esign5070" / "xmldsig.py").read_bytes()).hexdigest()
        self.assertEqual(xmldsig_sha, EXPECTED_XMLDSIG_SHA256)
        probe = run_live_integration_probe(project_root=PROJECT_ROOT)
        self.assertFalse(probe["production_use_authorized"])
        self.assertFalse(probe["qualified_e_signature_5070_production_ready"])
        self.assertFalse(probe["qualified_e_signature_5070_equivalent"])

    def test_13_l5_l6_procedure_intent_separates_unadopted_templates_and_escalates(self) -> None:
        """L5/L6 prosedür ve işyeri uygulaması sorusunda kabul edilmemiş şablonlar hariç tutulur."""
        res_unadopted = self.engine.retrieve(
            RagQueryRequest(
                query_text="L5 disiplin tutanak savunma prosedürü ve L6 bayram ikramiyesi tek taraflı kesinti",
                as_of_date="2026-06-01",
                facts={},
            )
        )
        self.assertEqual(res_unadopted.intent_classification.intent, INTENT_PROCEDURE_AND_AUTONOMOUS_NORM)
        self.assertEqual(len(res_unadopted.autonomous_norm_bucket), 0)
        self.assertTrue(
            any(n.status == "REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION" for n in res_unadopted.excluded_unverified_notices)
        )
        # Somut kesinti senaryosunda yazılı rıza ve kabul belgesi sorulur
        self.assertEqual(res_unadopted.rag_gate_status, GATE_ABSTAIN_MISSING_INFO)
        self.assertIn("written_employee_consent_4857_m22", res_unadopted.missing_facts)

        # Genel prosedür bilgilendirme sorusunda şablon uyarısıyla eskalasyon üretir
        res_info = self.engine.retrieve(
            RagQueryRequest(
                query_text="L5 İK prosedürü disiplin ve L6 TİS normları nelerdir?",
                as_of_date="2026-06-01",
            )
        )
        self.assertEqual(res_info.rag_gate_status, GATE_EVIDENCE_READY_WITH_ESCALATION)
        self.assertIn("REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION", res_info.escalation_reasons)
        self.assertFalse(res_info.payroll_handoff_allowed)


if __name__ == "__main__":
    unittest.main()
