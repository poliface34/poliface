"""Comprehensive WP-4.2 Legal Knowledge Base, Bitemporal Versioning, PG+pgvector & 16-Case HR Retrieval Tests."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

from engine.knowledge_base import (
    CHUNK_KIND_ABSTENTION_BOUNDARY,
    CHUNK_KIND_PRECEDENT_UNIT,
    CHUNK_KIND_RULE_AND_EXCEPTION,
    CHUNK_KIND_STATUTORY_PARAGRAPH,
    COURT_DANISTAY,
    COURT_YARGITAY,
    DOC_KIND_AUTONOMOUS_NORM,
    DOC_KIND_INTERPRETATION_CARD,
    DOC_KIND_JUDICIAL_PRECEDENT,
    DOC_KIND_SECONDARY_REGULATION,
    DOC_KIND_STATUTORY_PROVISION,
    POSTGRES_PGVECTOR_SCHEMA_DDL,
    POOL_FAILED_QUARANTINED,
    VERIFICATION_QUARANTINED_TAMPER,
    VERIFICATION_VERIFIED,
    AbstentionBoundary,
    BitemporalVersionManager,
    InterpretationAndBoundaryRule,
    JudicialPrecedentNode,
    KnowledgeBaseError,
    KnowledgeSearchQuery,
    LegalDocumentVersion,
    LegalProvisionNode,
    LegalStructuralChunker,
    LocalDeterministicHybridStore,
    PostgresPgvectorKnowledgeStore,
    canonical_kb_sha256,
    evaluate_chunk_ingest_gate,
    load_wp42_knowledge_base,
)
from engine.trust_root import run_live_integration_probe

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_BENCHMARK_PATH = PROJECT_ROOT / "tests" / "fixtures" / "wp42_kb_retrieval_benchmark.json"
EXPECTED_XMLDSIG_SHA256 = "b16207b5fb71d7c0d0372838411c7795459ac460c2ff232766ae230b9cbacf85"


class TestLegalKnowledgeBaseWp42V106(unittest.TestCase):
    def test_01_load_unified_kb_and_baseline_invariants_intact(self) -> None:
        store, summary = load_wp42_knowledge_base(project_root=PROJECT_ROOT)
        ok, rep = store.verify_integrity()
        self.assertTrue(ok, rep["errors"])
        self.assertEqual(summary["quarantined_chunks"], 0)
        self.assertGreater(summary["ingested_active_chunks"], 100)
        self.assertGreaterEqual(summary["isolated_pending_chunks"], 25)  # 8 pending L1/L3/precedent + 19 L5/L6 templates

        # Ensure 13 schemas, 9 config files, xmldsig invariant, and closed gates remain untouched
        schemas = list((PROJECT_ROOT / "schemas").glob("*.json"))
        configs = list((PROJECT_ROOT / "config").glob("*.json"))
        self.assertEqual(len(schemas), 13)
        self.assertEqual(len(configs), 9)

        import hashlib

        xmldsig_sha = hashlib.sha256((PROJECT_ROOT / "engine" / "esign5070" / "xmldsig.py").read_bytes()).hexdigest()
        self.assertEqual(xmldsig_sha, EXPECTED_XMLDSIG_SHA256)

        probe = run_live_integration_probe(project_root=PROJECT_ROOT)
        self.assertFalse(probe["production_use_authorized"])
        self.assertFalse(probe["qualified_e_signature_5070_production_ready"])
        self.assertFalse(probe["qualified_e_signature_5070_equivalent"])

    def test_02_structural_chunking_preserves_fikra_and_clause_stems(self) -> None:
        long_clause_a = " ".join(["calisma"] * 30) + " birinci sart saglanirsa fesih uygulanir."
        long_clause_b = " ".join(["saglik"] * 30) + " altı hafta asilirsa derhal fesih dogar."
        multi_para_text = (
            "(1) İşveren aşağıda sayılan sağlık nedenlerinin varlığı halinde derhal fesih yapabilir:\n"
            f"a) {long_clause_a}\n"
            f"b) {long_clause_b}\n"
            "(2) Ayrı fıkra olarak bildirilen ahlak ve iyiniyet kurallarına aykırılık hali ayrıca değerlendirilir."
        )
        sha = canonical_kb_sha256({"txt": multi_para_text})
        prov = LegalProvisionNode(
            provision_id="4857:m-test-multi",
            document_version_id="DV-TEST-4857",
            source_id="MEVZUAT-4857",
            law_no="4857",
            article_no="Madde Test",
            article_title="Çok Fıkralı ve Bentli Yapı Testi",
            raw_text=multi_para_text,
            normalized_text=" ".join(multi_para_text.split()),
            publication_date="2003-06-10",
            effective_from="2003-06-10",
            effective_to=None,
            norm_layer="STATUTORY_LAW",
            norm_priority=3,
            norm_character="ABSOLUTE_MANDATORY",
            verification_status=VERIFICATION_VERIFIED,
            content_sha256=sha,
        )
        # Force clause split on paragraph 1 (> 45 words) while keeping paragraph 1 stem on both a) and b) chunks
        chunker = LegalStructuralChunker(max_paragraph_words=45)
        chunks = chunker.chunk_provision(prov, content_verified=True)

        self.assertEqual(len(chunks), 3)  # f-1/b-a, f-1/b-b, and f-2
        for ch in chunks:
            self.assertEqual(ch.chunk_kind, CHUNK_KIND_STATUTORY_PARAGRAPH)
            self.assertIn("[K: 4857 | M: Madde Test", ch.context_header)

        # Clause chunks retain the introductory stem of Fıkra 1!
        self.assertIn("aşağıda sayılan sağlık nedenlerinin varlığı halinde", chunks[0].raw_text)
        self.assertIn("a)", chunks[0].raw_text)
        self.assertIn("aşağıda sayılan sağlık nedenlerinin varlığı halinde", chunks[1].raw_text)
        self.assertIn("b)", chunks[1].raw_text)
        self.assertIn("Ayrı fıkra", chunks[2].raw_text)
        self.assertNotIn("a)", chunks[2].raw_text)

    def test_03_bitemporal_versioning_append_only_and_overlap_rejection(self) -> None:
        mgr = BitemporalVersionManager()
        sha_v1 = canonical_kb_sha256({"v": 1})
        sha_v2 = canonical_kb_sha256({"v": 2})

        dv1 = LegalDocumentVersion(
            document_version_id="DV-TEST-1",
            source_id="MEVZUAT-4857",
            document_kind=DOC_KIND_STATUTORY_PROVISION,
            norm_layer="STATUTORY_LAW",
            norm_priority=3,
            statute_no="4857",
            title="Test Kanun V1",
            official_gazette_no="25134",
            publication_date="2003-06-10",
            effective_from="2003-06-10",
            effective_to="2025-07-23",
            supersedes_version_id=None,
            content_sha256=sha_v1,
            verification_status=VERIFICATION_VERIFIED,
            document_fetch_status="FETCHED_AND_MATCHED",
            audit_log_id="AUD-20261120-MEVZUAT4857",
        )
        mgr.register_document_version(dv1)

        # Overlapping date window MUST fail closed!
        dv_overlap = LegalDocumentVersion(
            document_version_id="DV-TEST-2-BAD",
            source_id="MEVZUAT-4857",
            document_kind=DOC_KIND_STATUTORY_PROVISION,
            norm_layer="STATUTORY_LAW",
            norm_priority=3,
            statute_no="4857",
            title="Test Çakışan Sürüm",
            official_gazette_no="32965",
            publication_date="2025-07-24",
            effective_from="2025-07-01",
            effective_to=None,
            supersedes_version_id="DV-TEST-1",
            content_sha256=sha_v2,
            verification_status=VERIFICATION_VERIFIED,
            document_fetch_status="FETCHED_AND_MATCHED",
            audit_log_id="AUD-20261120-RG7555",
        )
        with self.assertRaises(KnowledgeBaseError) as ctx_ov:
            mgr.register_document_version(dv_overlap)
        self.assertEqual(ctx_ov.exception.error_code, "OVERLAPPING_EFFECTIVE_WINDOW")

        # Duplicate version ID MUST fail closed (append-only protection)
        with self.assertRaises(KnowledgeBaseError) as ctx_dup:
            mgr.register_document_version(dv1)
        self.assertEqual(ctx_dup.exception.error_code, "DUPLICATE_DOCUMENT_VERSION_ID")

        # Valid chained version
        dv2 = replace(dv_overlap, document_version_id="DV-TEST-2", effective_from="2025-07-24")
        mgr.register_document_version(dv2)

        p1 = LegalProvisionNode(
            provision_id="4857:m-109",
            document_version_id="DV-TEST-1",
            source_id="MEVZUAT-4857",
            law_no="4857",
            article_no="Madde 109",
            article_title="7555 Öncesi",
            raw_text="Eski m.109 metni.",
            normalized_text="Eski m.109 metni.",
            publication_date="2003-06-10",
            effective_from="2003-06-10",
            effective_to="2025-07-23",
            norm_layer="STATUTORY_LAW",
            norm_priority=3,
            norm_character="ABSOLUTE_MANDATORY",
            verification_status=VERIFICATION_VERIFIED,
            content_sha256=sha_v1,
        )
        p2 = replace(
            p1,
            document_version_id="DV-TEST-2",
            article_title="7555 Sonrası",
            raw_text="Fesih bildirimi her halde yazılı yapılır.",
            normalized_text="Fesih bildirimi her halde yazılı yapılır.",
            publication_date="2025-07-24",
            effective_from="2025-07-24",
            effective_to=None,
            supersedes_version_id="DV-TEST-1",
            content_sha256=sha_v2,
        )
        mgr.register_provision_version(p1)
        mgr.register_provision_version(p2)

        res_pre = mgr.resolve_version_as_of("4857:m-109", "2025-07-10")
        self.assertEqual(res_pre["active_version"]["document_version_id"], "DV-TEST-1")
        self.assertEqual(len(res_pre["future_versions"]), 1)

        res_post = mgr.resolve_version_as_of("4857:m-109", "2025-09-01")
        self.assertEqual(res_post["active_version"]["document_version_id"], "DV-TEST-2")
        self.assertEqual(len(res_post["historical_versions"]), 1)
        self.assertEqual(res_post["historical_versions"][0]["document_version_id"], "DV-TEST-1")

    def test_04_decoupled_trust_chain_adapter_protocol_enforces_hash_match(self) -> None:
        good_sha = canonical_kb_sha256({"doc": "4857-clean"})
        bad_sha = canonical_kb_sha256({"doc": "4857-tampered"})

        class _FakeTrustChainRegistry:
            def __init__(self) -> None:
                self._recs = {
                    "EV-GOOD-1": SimpleNamespace(is_verified_authority=True, content_sha256=good_sha),
                    "EV-UNVER-1": SimpleNamespace(is_verified_authority=False, content_sha256=good_sha),
                }

            def get(self, evidence_id: str):
                return self._recs.get(evidence_id)

            def verify_integrity(self, *, require_raw_content: bool = True):
                return True, {"valid": True}

            def get_raw_bytes(self, evidence_id: str):
                return b"bytes"

        store = LocalDeterministicHybridStore(trust_chain_adapter=_FakeTrustChainRegistry())
        dv_ok = LegalDocumentVersion(
            document_version_id="DV-TC-OK",
            source_id="MEVZUAT-4857",
            evidence_id="EV-GOOD-1",
            document_kind=DOC_KIND_STATUTORY_PROVISION,
            norm_layer="STATUTORY_LAW",
            norm_priority=3,
            statute_no="4857",
            title="TC Bağlı Sürüm",
            official_gazette_no="25134",
            publication_date="2003-06-10",
            effective_from="2003-06-10",
            effective_to=None,
            supersedes_version_id=None,
            content_sha256=good_sha,
            verification_status=VERIFICATION_VERIFIED,
            document_fetch_status="FETCHED_AND_MATCHED",
            audit_log_id="AUD-20261120-TC1",
        )
        store.upsert_bundle(document_versions=[dv_ok])

        # Unverified Trust Chain record MUST fail closed
        dv_unver = replace(dv_ok, document_version_id="DV-TC-UNVER", source_id="S-UNVER", evidence_id="EV-UNVER-1")
        with self.assertRaises(KnowledgeBaseError) as ctx1:
            store.upsert_bundle(document_versions=[dv_unver])
        self.assertEqual(ctx1.exception.error_code, "TRUST_CHAIN_EVIDENCE_UNVERIFIED")

        # SHA mismatch with Trust Chain record MUST fail closed
        dv_mismatch = replace(dv_ok, document_version_id="DV-TC-MISM", source_id="S-MISM", content_sha256=bad_sha)
        with self.assertRaises(KnowledgeBaseError) as ctx2:
            store.upsert_bundle(document_versions=[dv_mismatch])
        self.assertEqual(ctx2.exception.error_code, "TRUST_CHAIN_SHA256_MISMATCH")

    def test_05_postgresql_pgvector_ddl_sql_prefilters_and_not_configured_fail_closed(self) -> None:
        pg = PostgresPgvectorKnowledgeStore()
        self.assertEqual(pg.integration_mode, "NOT_CONFIGURED")
        hc = pg.health_check()
        self.assertEqual(hc["integration_mode"], "NOT_CONFIGURED")
        self.assertFalse(hc["configured"])
        self.assertFalse(hc["reachable"])

        # DDL structure checks
        self.assertIn("CREATE EXTENSION IF NOT EXISTS vector;", POSTGRES_PGVECTOR_SCHEMA_DDL)
        self.assertIn("VECTOR(1024)", POSTGRES_PGVECTOR_SCHEMA_DDL)
        self.assertIn("to_tsvector('turkish'", POSTGRES_PGVECTOR_SCHEMA_DDL)
        self.assertIn("USING hnsw (embedding vector_cosine_ops)", POSTGRES_PGVECTOR_SCHEMA_DDL)
        self.assertIn("kb_judicial_precedents", POSTGRES_PGVECTOR_SCHEMA_DDL)
        self.assertIn("kb_interpretation_rules", POSTGRES_PGVECTOR_SCHEMA_DDL)

        # Pre-filtered hybrid SQL generator checks
        sql, params = pg.build_hybrid_search_sql(
            KnowledgeSearchQuery(
                query_text="4857 m.109 yazılı fesih",
                as_of_date="2026-03-01",
                document_kinds=(DOC_KIND_STATUTORY_PROVISION,),
                law_nos=("4857",),
                top_k=5,
            )
        )
        self.assertIn("SET LOCAL hnsw.iterative_scan = strict_order;", sql)
        self.assertIn("verification_status = 'VERIFIED'", sql)
        self.assertIn("content_verified = TRUE", sql)
        self.assertIn("effective_from <= %(as_of_date)s::date", sql)
        self.assertIn("1.0 / (%(rrf_k)s + vec_rank)", sql)
        self.assertEqual(params["as_of_date"], "2026-03-01")
        self.assertEqual(params["law_nos"], ["4857"])

        # Runtime execution fails closed when PostgreSQL is NOT_CONFIGURED
        with self.assertRaises(KnowledgeBaseError) as ctx:
            pg.hybrid_search(KnowledgeSearchQuery(query_text="4857 fesih", as_of_date="2026-03-01"))
        self.assertEqual(ctx.exception.error_code, "POSTGRES_PGVECTOR_NOT_CONFIGURED")

    def test_06_runtime_chunk_tamper_fails_closed_and_quarantines(self) -> None:
        store, _ = load_wp42_knowledge_base(project_root=PROJECT_ROOT)
        any_id = next(iter(store._active_chunks.keys()))
        orig_chunk = store._active_chunks[any_id]
        # Tamper raw_text in memory without updating chunk_sha256
        store._active_chunks[any_id] = replace(orig_chunk, raw_text="TAHRIF EDILMIS SAHTE KANUN METNI")

        ok, rep = store.verify_integrity()
        self.assertFalse(ok)
        self.assertTrue(any(VERIFICATION_QUARANTINED_TAMPER in err for err in rep["errors"]))

        with self.assertRaises(KnowledgeBaseError) as ctx:
            store.hybrid_search(KnowledgeSearchQuery(query_text="4857 fesih", as_of_date="2026-04-01"))
        self.assertEqual(ctx.exception.error_code, VERIFICATION_QUARANTINED_TAMPER)

    def test_07_abstention_boundary_companion_rules_always_attached(self) -> None:
        store, _ = load_wp42_knowledge_base(project_root=PROJECT_ROOT)
        res = store.hybrid_search(
            KnowledgeSearchQuery(
                query_text="4857 madde 26 6 iş günü arife akdi cumartesi",
                as_of_date="2026-05-01",
                document_kinds=(DOC_KIND_STATUTORY_PROVISION,),
                top_k=5,
            )
        )
        self.assertGreater(len(res.active_hits), 0)
        m26_hits = [h for h in res.active_hits if h.chunk.provision_id == "4857:m-26:f-1"]
        self.assertEqual(len(m26_hits), 1)
        rules = m26_hits[0].companion_rules
        self.assertEqual(len(rules), 1)
        ab = rules[0].abstention_boundary
        self.assertIn("discovery_date", ab.blocking_missing_facts)
        self.assertTrue(any("M26_YARIM_GUN_TATIL" in t for t in ab.mandatory_escalation_triggers))
        self.assertTrue(len(ab.clarification_questions) >= 1)
        self.assertTrue(len(ab.payroll_handoff_prohibition_conditions) >= 1)

    def test_08_golden_16_case_hr_retrieval_benchmark_and_kpis(self) -> None:
        benchmark = json.loads(FIXTURE_BENCHMARK_PATH.read_text(encoding="utf-8"))
        store, _ = load_wp42_knowledge_base(project_root=PROJECT_ROOT)

        cases = benchmark["cases"]
        self.assertEqual(len(cases), 16)

        recall_passed = 0
        recall_total = 0
        temporal_leaks = 0
        temporal_total = 0
        unverified_leaks = 0
        unverified_total = 0
        precedent_sep_passed = 0
        precedent_sep_total = 0
        abstention_passed = 0
        abstention_total = 0

        for case in cases:
            cid = case["case_id"]
            mode = case.get("mode", "SEARCH")

            if mode == "UNIT_NEGATIVE_QUALITY_GATE":
                unverified_total += 1
                chunker = LegalStructuralChunker()
                neg_statuses = (
                    "REJECTED_CONTENT_MISMATCH",
                    "TRANSPORT_ONLY_UNVERIFIED_CONTENT",
                    "UNREACHABLE_NOT_VERIFIED",
                )
                iso_store = LocalDeterministicHybridStore()
                bad_chunks = []
                for idx, st in enumerate(neg_statuses):
                    txt = f"Sahte belge denemesi sgk teşvik 4857 fesih içerik uyuşmazlık {st}"
                    p = LegalProvisionNode(
                        provision_id=f"NEG:{idx}:{st}",
                        document_version_id=f"DV-NEG-{idx}",
                        source_id=f"SRC-NEG-{idx}",
                        law_no="4857",
                        article_no="Madde Negatif",
                        article_title=f"Negatif Test {st}",
                        raw_text=txt,
                        normalized_text=txt,
                        publication_date="2026-01-01",
                        effective_from="2026-01-01",
                        effective_to=None,
                        norm_layer="STATUTORY_LAW",
                        norm_priority=3,
                        norm_character="ABSOLUTE_MANDATORY",
                        verification_status=st,
                        content_sha256=canonical_kb_sha256({"bad": st}),
                    )
                    bad_chunks.extend(chunker.chunk_provision(p, content_verified=False))
                for bc in bad_chunks:
                    gate = evaluate_chunk_ingest_gate(bc)
                    self.assertFalse(gate.accepted_active, cid)
                    self.assertEqual(gate.pool, POOL_FAILED_QUARANTINED, cid)
                ing_rep = iso_store.upsert_bundle(chunks=bad_chunks)
                self.assertEqual(ing_rep["ingested_active_chunks"], 0, cid)
                self.assertEqual(ing_rep["quarantined_chunks"], 3, cid)
                res_neg = iso_store.hybrid_search(
                    KnowledgeSearchQuery(query_text="4857 fesih teşvik içerik uyuşmazlık", as_of_date="2026-04-01")
                )
                self.assertEqual(len(res_neg.active_hits), 0, cid)
                self.assertEqual(len(res_neg.excluded_unverified_notices), 3, cid)
                if len(res_neg.active_hits) > 0:
                    unverified_leaks += 1
                continue

            if mode == "UNIT_DANISTAY_SEPARATION":
                precedent_sep_total += 1
                unverified_total += 1
                # Verify built-in unverified Danıştay placeholder never enters active pool
                res_pending_dan = store.hybrid_search(
                    KnowledgeSearchQuery(
                        query_text="danıştay karararama 5510",
                        as_of_date="2026-04-01",
                        document_kinds=(DOC_KIND_JUDICIAL_PRECEDENT,),
                    )
                )
                self.assertFalse(
                    any(h.chunk.source_id == "DANISTAY-PENDING-FULLTEXT-SAMPLE" for h in res_pending_dan.active_hits),
                    cid,
                )

                # Test verified synthetic Danıştay vs Yargıtay separation in isolated store
                iso_store = LocalDeterministicHybridStore()
                chunker = LegalStructuralChunker()
                dan_node = JudicialPrecedentNode(
                    precedent_id="TEST-DANISTAY-10D-SGK-IPC",
                    court_system=COURT_DANISTAY,
                    chamber="10_D",
                    binding_level="DANISTAY_DAIRE_SETTLED",
                    esas_no="2025/100",
                    karar_no="2025/200",
                    decision_date="2025-11-15",
                    official_source_url="https://karararama.danistay.gov.tr/test-sentetik-2025-200",
                    interpreted_provision_ids=("5510:m-102",),
                    legal_principle="SGK idari para cezası (5510 m.102) tebliğ ve itiraz usulü idari yargı denetimine tabidir.",
                    operative_holding="TEST FİKSTÜR: Danıştay 10. Daire idari işlem iptal sınırı.",
                    applies_to=("5510 m.102 idari para cezası uyuşmazlıkları",),
                    does_not_apply_to=("İşçi-işveren bireysel alacak davaları",),
                    verification_status=VERIFICATION_VERIFIED,
                    content_sha256=canonical_kb_sha256({"dan_test": 1}),
                    requires_application_rationale=True,
                )
                yarg_node = JudicialPrecedentNode(
                    precedent_id="TEST-YARGITAY-9HD-FESIH",
                    court_system=COURT_YARGITAY,
                    chamber="9_HD",
                    binding_level="CHAMBER_SETTLED",
                    esas_no="2025/300",
                    karar_no="2025/400",
                    decision_date="2025-10-10",
                    official_source_url="https://karararama.yargitay.gov.tr/test-sentetik-2025-400",
                    interpreted_provision_ids=("4857:m-25",),
                    legal_principle="SGK çıkış kodu iş hukukunda ispat vasıtası değildir.",
                    operative_holding="TEST FİKSTÜR: Yargıtay 9. HD iş davası.",
                    applies_to=("İşe iade davaları",),
                    does_not_apply_to=("5510 m.102 idari para cezası iptali",),
                    verification_status=VERIFICATION_VERIFIED,
                    content_sha256=canonical_kb_sha256({"yarg_test": 1}),
                    requires_application_rationale=True,
                )
                iso_store.upsert_bundle(
                    precedents=[dan_node, yarg_node],
                    chunks=chunker.chunk_precedent(dan_node, content_verified=True)
                    + chunker.chunk_precedent(yarg_node, content_verified=True),
                )
                dan_res = iso_store.hybrid_search(
                    KnowledgeSearchQuery(
                        query_text="5510 m.102 SGK idari para cezası",
                        as_of_date="2026-04-01",
                        document_kinds=(DOC_KIND_JUDICIAL_PRECEDENT,),
                        court_systems=(COURT_DANISTAY,),
                    )
                )
                self.assertGreater(len(dan_res.active_hits), 0, cid)
                self.assertTrue(
                    all(h.chunk.metadata.get("court_system") == COURT_DANISTAY for h in dan_res.active_hits),
                    cid,
                )
                self.assertFalse(
                    any(h.chunk.metadata.get("court_system") == COURT_YARGITAY for h in dan_res.active_hits),
                    cid,
                )
                precedent_sep_passed += 1
                continue

            if mode == "UNIT_MISSING_AS_OF_DATE":
                abstention_total += 1
                with self.assertRaises(KnowledgeBaseError) as ctx_nodate:
                    store.hybrid_search(KnowledgeSearchQuery(query_text="4857 kıdem tazminatı", as_of_date=None))
                self.assertEqual(ctx_nodate.exception.error_code, "MISSING_AS_OF_DATE_FOR_TEMPORAL_SEARCH", cid)
                abstention_passed += 1
                continue

            # Standard search case from golden benchmark
            doc_kinds = tuple(case["document_kinds"]) if case.get("document_kinds") else None
            q = KnowledgeSearchQuery(
                query_text=case["query_text"],
                as_of_date=case["as_of_date"],
                document_kinds=doc_kinds,
                include_historical=bool(case.get("include_historical", False)),
                top_k=5,
            )
            res = store.hybrid_search(q)
            active_prov_ids = [h.chunk.provision_id for h in res.active_hits]
            active_dv_ids = [h.chunk.document_version_id for h in res.active_hits]
            active_pv_ids = [f"{h.chunk.provision_id}@{h.chunk.document_version_id}" for h in res.active_hits]
            active_src_ids = [h.chunk.source_id for h in res.active_hits]
            active_kinds = [h.chunk.document_kind for h in res.active_hits]
            hist_dv_ids = [h.chunk.document_version_id for h in res.historical_hits]
            hist_pv_ids = [f"{h.chunk.provision_id}@{h.chunk.document_version_id}" for h in res.historical_hits]
            hist_src_ids = [h.chunk.source_id for h in res.historical_hits]

            if "expected_any_provision_ids" in case or "expected_active_source_ids" in case or "expected_top1_provision_id" in case:
                recall_total += 1
                ok_recall = True
                if "expected_any_provision_ids" in case:
                    ok_recall = ok_recall and any(pid in active_prov_ids for pid in case["expected_any_provision_ids"])
                if "expected_active_source_ids" in case:
                    ok_recall = ok_recall and any(sid in active_src_ids for sid in case["expected_active_source_ids"])
                if "expected_top1_provision_id" in case:
                    ok_recall = ok_recall and bool(active_prov_ids) and active_prov_ids[0] == case["expected_top1_provision_id"]
                self.assertTrue(ok_recall, f"{cid} recall failed: got prov={active_prov_ids}, src={active_src_ids}")
                if ok_recall:
                    recall_passed += 1

            if "reverse_pair_query" in case:
                rp = case["reverse_pair_query"]
                rp_res = store.hybrid_search(
                    KnowledgeSearchQuery(
                        query_text=rp["query_text"],
                        as_of_date=case["as_of_date"],
                        document_kinds=doc_kinds,
                        top_k=5,
                    )
                )
                self.assertGreater(len(rp_res.active_hits), 0, cid)
                self.assertEqual(rp_res.active_hits[0].chunk.provision_id, rp["expected_top1_provision_id"], cid)

            if (
                "forbidden_active_doc_version_ids" in case
                or "forbidden_active_provision_versions" in case
                or "forbidden_active_source_ids" in case
                or "expected_active_doc_version_ids" in case
                or "expected_active_provision_versions" in case
            ):
                temporal_total += 1
                for exp_dv in case.get("expected_active_doc_version_ids", []):
                    self.assertIn(exp_dv, active_dv_ids, f"{cid}: expected active version {exp_dv}")
                for exp_pv in case.get("expected_active_provision_versions", []):
                    self.assertIn(exp_pv, active_pv_ids, f"{cid}: expected active provision@version {exp_pv}")
                for f_dv in case.get("forbidden_active_doc_version_ids", []):
                    if f_dv in active_dv_ids:
                        temporal_leaks += 1
                    self.assertNotIn(f_dv, active_dv_ids, f"{cid}: temporal leak of {f_dv}")
                for f_pv in case.get("forbidden_active_provision_versions", []):
                    if f_pv in active_pv_ids:
                        temporal_leaks += 1
                    self.assertNotIn(f_pv, active_pv_ids, f"{cid}: temporal leak of {f_pv}")
                for f_sid in case.get("forbidden_active_source_ids", []):
                    if f_sid in active_src_ids:
                        temporal_leaks += 1
                    self.assertNotIn(f_sid, active_src_ids, f"{cid}: forbidden source {f_sid}")
                for exp_h_dv in case.get("expected_historical_doc_version_ids", []):
                    self.assertIn(exp_h_dv, hist_dv_ids, f"{cid}: missing historical version {exp_h_dv}")
                for exp_h_pv in case.get("expected_historical_provision_versions", []):
                    self.assertIn(exp_h_pv, hist_pv_ids, f"{cid}: missing historical provision@version {exp_h_pv}")
                for exp_h_sid in case.get("expected_historical_source_ids", []):
                    self.assertIn(exp_h_sid, hist_src_ids, f"{cid}: missing historical source {exp_h_sid}")

            if "expected_excluded_source_ids" in case or "expected_excluded_statuses" in case:
                unverified_total += 1
                excl_src = {n.source_id for n in res.excluded_unverified_notices}
                excl_st = {n.status for n in res.excluded_unverified_notices}
                for sid in case.get("expected_excluded_source_ids", []):
                    self.assertIn(sid, excl_src, cid)
                    if sid in active_src_ids:
                        unverified_leaks += 1
                for st in case.get("expected_excluded_statuses", []):
                    self.assertIn(st, excl_st, cid)

            if "forbidden_active_document_kinds" in case:
                precedent_sep_total += 1
                for f_kind in case["forbidden_active_document_kinds"]:
                    self.assertNotIn(f_kind, active_kinds, cid)
                precedent_sep_passed += 1

            if "precedent_followup" in case:
                precedent_sep_total += 1
                pf = case["precedent_followup"]
                p_res = store.hybrid_search(
                    KnowledgeSearchQuery(
                        query_text=pf["query_text"],
                        as_of_date=case["as_of_date"],
                        document_kinds=(DOC_KIND_JUDICIAL_PRECEDENT,),
                        top_k=5,
                    )
                )
                found_pids = [h.chunk.source_id for h in p_res.active_hits]
                self.assertIn(pf["expected_precedent_id"], found_pids, cid)
                self.assertTrue(
                    all(h.chunk.document_kind == DOC_KIND_JUDICIAL_PRECEDENT for h in p_res.active_hits),
                    cid,
                )
                precedent_sep_passed += 1

            if "expected_companion_rule_ids" in case:
                abstention_total += 1
                comp_ids = {r.rule_id for h in res.active_hits for r in h.companion_rules}
                for exp_rid in case["expected_companion_rule_ids"]:
                    self.assertIn(exp_rid, comp_ids, cid)
                abstention_passed += 1

        # Verify KPI thresholds strictly match WP4_2_LEGAL_KNOWLEDGE_BASE_SPEC Section 9.1
        thresh = benchmark["kpi_thresholds"]
        recall_rate = recall_passed / max(1, recall_total)
        temporal_leak_rate = temporal_leaks / max(1, temporal_total)
        unverified_exclusion_rate = 1.0 - (unverified_leaks / max(1, unverified_total))
        precedent_sep_rate = precedent_sep_passed / max(1, precedent_sep_total)
        abstention_rate = abstention_passed / max(1, abstention_total)

        self.assertGreaterEqual(recall_rate, thresh["critical_provision_recall_min"])
        self.assertLessEqual(temporal_leak_rate, thresh["temporal_leakage_rate_max"])
        self.assertGreaterEqual(unverified_exclusion_rate, thresh["unverified_exclusion_rate_min"])
        self.assertGreaterEqual(precedent_sep_rate, thresh["precedent_isolation_rate_min"])
        self.assertGreaterEqual(abstention_rate, thresh["abstention_attachment_rate_min"])

    def test_09_l5_l6_adoption_status_gate_blocks_unadopted_and_allows_counsel_verified(self) -> None:
        store, _ = load_wp42_knowledge_base(project_root=PROJECT_ROOT)
        # All 19 built-in L5/L6 templates MUST be excluded from active AUTONOMOUS_NORM hits!
        res_unadopted = store.hybrid_search(
            KnowledgeSearchQuery(
                query_text="disiplin savunma tutanak prim ikramiye TİS",
                as_of_date="2026-06-01",
                document_kinds=(DOC_KIND_AUTONOMOUS_NORM,),
                require_adopted_autonomous_norms=True,
                top_k=10,
            )
        )
        self.assertEqual(len(res_unadopted.active_hits), 0)
        self.assertGreater(len(res_unadopted.excluded_unverified_notices), 0)
        self.assertTrue(
            all(n.status == "REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION" for n in res_unadopted.excluded_unverified_notices)
        )

        # Explicitly counsel-verified adopted policy IS admitted into AUTONOMOUS_NORM active pool
        chunker = LegalStructuralChunker()
        adopted_prov = LegalProvisionNode(
            provision_id="CUSTOM-ADOPTED-HR-01",
            document_version_id="DV-CUSTOM-HR-01",
            source_id="CORP-ADOPTED-2026",
            law_no="L5_L6",
            article_no="İK Politika 1",
            article_title="Şirket Onaylı Fazla Çalışma İzin Prosedürü",
            raw_text="Onaylı kurumsal prosedür: 4857 m.41 fazla çalışma öncesi yazılı çalışan muvafakati saklanır.",
            normalized_text="Onaylı kurumsal prosedür.",
            publication_date="2026-01-01",
            effective_from="2026-01-01",
            effective_to=None,
            norm_layer="CBA_CONTRACT_AND_HR_PROCEDURE",
            norm_priority=8,
            norm_character="RELATIVE_EMPLOYEE_FAVORABLE",
            verification_status=VERIFICATION_VERIFIED,
            content_sha256=canonical_kb_sha256({"custom_adopted": 1}),
            document_kind=DOC_KIND_AUTONOMOUS_NORM,
            adoption_status="COMPANY_ADOPTED_COUNSEL_VERIFIED",
            keywords=("fazla çalışma", "muvafakat", "prosedür"),
        )
        store.upsert_bundle(
            provisions=[adopted_prov],
            chunks=chunker.chunk_provision(adopted_prov, content_verified=True),
        )
        res_adopted = store.hybrid_search(
            KnowledgeSearchQuery(
                query_text="fazla çalışma yazılı muvafakat kurumsal prosedür",
                as_of_date="2026-06-01",
                document_kinds=(DOC_KIND_AUTONOMOUS_NORM,),
                require_adopted_autonomous_norms=True,
                top_k=5,
            )
        )
        self.assertEqual(len(res_adopted.active_hits), 1)
        self.assertEqual(res_adopted.active_hits[0].chunk.provision_id, "CUSTOM-ADOPTED-HR-01")
        self.assertEqual(res_adopted.active_hits[0].chunk.adoption_status, "COMPANY_ADOPTED_COUNSEL_VERIFIED")

    def test_10_postgresql_sql_builder_validates_dates_and_court_filters(self) -> None:
        pg = PostgresPgvectorKnowledgeStore()
        with self.assertRaises(KnowledgeBaseError) as ctx_nodate:
            pg.build_hybrid_search_sql(KnowledgeSearchQuery(query_text="4857", as_of_date=None))
        self.assertEqual(ctx_nodate.exception.error_code, "MISSING_AS_OF_DATE_FOR_TEMPORAL_SEARCH")

        with self.assertRaises(KnowledgeBaseError) as ctx_baddate:
            pg.build_hybrid_search_sql(KnowledgeSearchQuery(query_text="4857", as_of_date="2026/01/01"))
        self.assertEqual(ctx_baddate.exception.error_code, "MISSING_OR_INVALID_ISO_DATE")

        sql, params = pg.build_hybrid_search_sql(
            KnowledgeSearchQuery(
                query_text="5510 m.102 idari para cezası",
                as_of_date="2026-05-01",
                document_kinds=(DOC_KIND_JUDICIAL_PRECEDENT,),
                court_systems=(COURT_DANISTAY,),
                chunk_kinds=(CHUNK_KIND_PRECEDENT_UNIT,),
            )
        )
        self.assertIn("(metadata_json->>'court_system') = ANY(%(court_systems)s)", sql)
        self.assertIn("document_kind = ANY(%(document_kinds)s)", sql)
        self.assertIn("chunk_kind = ANY(%(chunk_kinds)s)", sql)
        self.assertEqual(params["court_systems"], ["DANISTAY"])
        self.assertEqual(params["document_kinds"], ["JUDICIAL_PRECEDENT"])


if __name__ == "__main__":
    unittest.main()
