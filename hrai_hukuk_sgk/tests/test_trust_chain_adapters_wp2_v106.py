"""Comprehensive WP-2 Trust Chain Adapters, EvidenceRegistry & Answer Linkage Tests (hrAI @HukukSGK v1.0.6 WP2.7).

Covers all 10 WP-2 acceptance criteria with positive, negative, tamper, unreachable-source,
historical versioning, end-to-end `@HukukSGK` router traceability, and baseline regression invariants.
Zero external network access is performed during unit testing.
"""

from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
import zlib

from engine.tools_router import HukukSGKToolRouter
from engine.trust_chain import (
    ADAPTER_DANISTAY,
    ADAPTER_ISKUR,
    ADAPTER_MEVZUAT,
    ADAPTER_RESMI_GAZETE,
    ADAPTER_SGK,
    ADAPTER_YARGITAY,
    CONTENT_MATCH_MATCHED,
    CONTENT_MATCH_MISMATCH,
    CONTENT_MATCH_UNPARSEABLE_BINARY,
    HEAD_STATUS_EXACT_MATCH,
    HEAD_STATUS_HISTORICAL_GREW,
    HEAD_STATUS_UNKNOWN_OR_FORKED,
    SNAPSHOT_MODE_FULL_WITH_RAW,
    SNAPSHOT_MODE_METADATA_ONLY,
    STATUS_REJECTED_CONTENT_MISMATCH,
    STATUS_REJECTED_INVALID_SOURCE,
    STATUS_TRANSPORT_ONLY_UNVERIFIED_CONTENT,
    STATUS_UNREACHABLE_NOT_VERIFIED,
    STATUS_VERIFIED_TEST_TRANSPORT,
    TRANSPORT_INJECTED_TEST,
    AnswerLinkageError,
    DanistayAdapter,
    EvidenceBackedLegalAnswerBuilder,
    EvidenceRegistry,
    EvidenceRegistryError,
    FileSystemContentStore,
    InMemoryContentStore,
    IskurAdapter,
    MevzuatAdapter,
    ResmiGazeteAdapter,
    SgkAdapter,
    SourceDocumentRequest,
    YargitayAdapter,
    verify_answer_traceability,
)
from engine.trust_chain.answer_linker import _compute_answer_sha256
from engine.trust_chain.models import canonical_sha256
from engine.trust_root import run_live_integration_probe

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_XMLDSIG_SHA256 = "b16207b5fb71d7c0d0372838411c7795459ac460c2ff232766ae230b9cbacf85"


def _make_ok_transport(
    payload_bytes: bytes,
    *,
    acquired_at_utc: str = "2026-11-25T10:00:00+03:00",
    content_type: str = "text/html; charset=utf-8",
    final_url: str | None = None,
    redirect_chain: list[str] | None = None,
    spoof_live_mode: bool = False,
):
    def _transport(url: str) -> dict[str, object]:
        resp: dict[str, object] = {
            "raw_bytes": payload_bytes,
            "final_url": final_url or url,
            "redirect_chain": redirect_chain if redirect_chain is not None else [url],
            "http_status": 200,
            "http_headers": {"Content-Type": content_type},
            "acquired_at_utc": acquired_at_utc,
        }
        if spoof_live_mode:
            resp["fetcher_mode"] = "LIVE_HTTPS"
            resp["tls_verification_result"] = {"verified": True}
        return resp

    return _transport


class TestTrustChainAdaptersWp2V106(unittest.TestCase):
    def test_01_all_six_adapters_positive_acquisition_and_distinct_metadata(self) -> None:
        """Criteria 1, 2, 3, 4: all 6 adapters acquire, validate, match content, hash, separate dates, and register unique IDs."""
        reg = EvidenceRegistry()

        specs = [
            (
                ResmiGazeteAdapter,
                SourceDocumentRequest(
                    source_key="RG-32766-2024",
                    source_url="https://www.resmigazete.gov.tr/eskiler/2024/12/20241228-1.htm",
                    title="2025 Yılı Asgari Ücret Tespit Komisyonu Kararı",
                    publication_date="2024-12-28",
                    effective_date="2025-01-01",
                    adapter_metadata={"gazette_number": "32766", "is_mukerrer": False},
                ),
                b"<html><body>Resmi Gazete Sayi 32766 - Asgari Ucret Karari metni.</body></html>",
                ADAPTER_RESMI_GAZETE,
            ),
            (
                MevzuatAdapter,
                SourceDocumentRequest(
                    source_key="KANUN-4857",
                    source_url="https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=4857&MevzuatTur=1&MevzuatTertip=5",
                    title="4857 Sayılı İş Kanunu",
                    publication_date="2003-06-10",
                    effective_date="2003-06-10",
                    adapter_metadata={"mevzuat_no": "4857", "mevzuat_turu": "KANUN", "article_ref": "m.17"},
                ),
                b"<html><body>4857 Sayili Is Kanunu Madde 17 - Sureli fesih hukumleri.</body></html>",
                ADAPTER_MEVZUAT,
            ),
            (
                SgkAdapter,
                SourceDocumentRequest(
                    source_key="SGK-GENELGE-2020-20",
                    source_url="https://www.sgk.gov.tr/Duyuru/Detay/2020-20-Isveren-Islemleri-Genelgesi",
                    title="SGK 2020/20 Sayılı İşveren İşlemleri Genelgesi",
                    publication_date="2020-06-18",
                    effective_date="2020-07-01",
                    adapter_metadata={"document_type": "GENELGE", "reference_no": "2020/20"},
                ),
                b"%PDF-1.7\n%SGK 2020/20 Genelgesi icerik baytlari 0123456789\x00%%EOF",
                ADAPTER_SGK,
            ),
            (
                IskurAdapter,
                SourceDocumentRequest(
                    source_key="ISKUR-KCO-2026-01",
                    source_url="https://www.iskur.gov.tr/mevzuat/kisa-calisma-odenegi-usul-esaslar-2026",
                    title="İŞKUR Kısa Çalışma Ödeneği Usul ve Esasları",
                    publication_date="2026-01-15",
                    effective_date="2026-02-01",
                    adapter_metadata={"document_type": "USUL_VE_ESASLAR", "reference_no": "ISKUR-2026/01"},
                ),
                b"<html><body>ISKUR-2026/01 Kisa Calisma Odenegi Usul ve Esaslari 2026 metni.</body></html>",
                ADAPTER_ISKUR,
            ),
            (
                YargitayAdapter,
                SourceDocumentRequest(
                    source_key="YARGITAY-9HD-2025-1200-2025-4500",
                    source_url="https://karararama.yargitay.gov.tr/YargitayBilgiBankasiIstemciWeb/karar/2025-4500",
                    title="Yargıtay 9. Hukuk Dairesi Fazla Mesai İspat Kararı",
                    publication_date="2025-05-20",
                    effective_date="2025-05-20",
                    adapter_metadata={
                        "chamber": "9. Hukuk Dairesi",
                        "esas_no": "2025/1200",
                        "karar_no": "2025/4500",
                        "decision_date": "2025-04-10",
                    },
                ),
                b"<html><body>Yargitay 9. HD E. 2025/1200 K. 2025/4500 gerekceli karar metni.</body></html>",
                ADAPTER_YARGITAY,
            ),
            (
                DanistayAdapter,
                SourceDocumentRequest(
                    source_key="DANISTAY-10D-2024-880-2025-110",
                    source_url="https://karararama.danistay.gov.tr/karar/2025-110",
                    title="Danıştay 10. Daire SGK İdari Para Cezası Kararı",
                    publication_date="2025-06-05",
                    effective_date="2025-06-05",
                    adapter_metadata={
                        "chamber": "10. Daire",
                        "esas_no": "2024/880",
                        "karar_no": "2025/110",
                        "decision_date": "2025-03-18",
                    },
                ),
                b"<html><body>Danistay 10. Daire E. 2024/880 K. 2025/110 idari para cezasi karari.</body></html>",
                ADAPTER_DANISTAY,
            ),
        ]

        seen_ids: set[str] = set()
        for adapter_cls, req, raw_b, exp_type in specs:
            # Deliberately spoof LIVE_HTTPS from injected transport to verify anti-spoofing!
            adapter = adapter_cls(
                transport=_make_ok_transport(raw_b, acquired_at_utc="2026-11-25T13:30:00+03:00", spoof_live_mode=True)
            )
            res = adapter.acquire_and_validate(req)
            self.assertTrue(res.ok, f"{exp_type} failed: {res.errors}")
            self.assertEqual(res.status, STATUS_VERIFIED_TEST_TRANSPORT)
            self.assertEqual(res.record.adapter_type, exp_type)
            self.assertEqual(res.record.transport_mode, TRANSPORT_INJECTED_TEST)
            self.assertFalse(res.record.live_verified, "Injected transport must NEVER produce live_verified=True")
            self.assertTrue(res.record.content_verified)
            self.assertEqual(res.record.content_verification.get("content_match_status"), CONTENT_MATCH_MATCHED)
            self.assertEqual(res.record.acquired_at_utc, "2026-11-25T10:30:00Z")
            self.assertEqual(res.record.source_url, req.source_url)
            self.assertEqual(res.record.publication_date, req.publication_date)
            self.assertEqual(res.record.effective_date, req.effective_date)
            self.assertEqual(res.record.content_sha256, hashlib.sha256(raw_b).hexdigest())

            sealed = reg.register(res)
            self.assertNotIn(sealed.evidence_id, seen_ids)
            seen_ids.add(sealed.evidence_id)
            self.assertEqual(sealed.version_number, 1)
            self.assertEqual(reg.get_raw_bytes(sealed.evidence_id), raw_b)

        ok, rep = reg.verify_integrity()
        self.assertTrue(ok, rep)
        self.assertTrue(rep["full_content_archive_verified"])
        self.assertEqual(rep["raw_content_verified_count"], 6)
        self.assertEqual(rep["record_count"], 6)
        self.assertEqual(len(seen_ids), 6)

    def test_02_negative_fake_domains_http_downgrade_generic_root_and_userinfo(self) -> None:
        """Criterion 8: reject fake domains, cross-adapter hosts, HTTP, HTTP redirects, generic roots, and userinfo."""
        payload = b"<html><body>Resmi belge icerigi 01234567890123456789</body></html>"
        sgk = SgkAdapter(transport=_make_ok_transport(payload))

        bad_url_cases = [
            ("fake_domain", "https://sgk.gov.tr.evil.example/genelge/2026-1", "DISALLOWED_OFFICIAL_SOURCE_DOMAIN"),
            ("cross_adapter_host", "https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=4857", "DISALLOWED_OFFICIAL_SOURCE_DOMAIN"),
            ("plain_http", "http://www.sgk.gov.tr/Duyuru/Detay/2026-1", "SOURCE_ACQUISITION_HTTPS_REQUIRED"),
            ("generic_root", "https://www.sgk.gov.tr/", "GENERIC_ROOT_URL_REJECTED"),
            ("userinfo_in_url", "https://admin:secret@www.sgk.gov.tr/Duyuru/Detay/1", "DISALLOWED_OFFICIAL_SOURCE_DOMAIN"),
        ]
        for label, bad_url, exp_code in bad_url_cases:
            req = SourceDocumentRequest(
                source_key="SGK-TEST-1",
                source_url=bad_url,
                title="SGK Negatif URL Testi",
                publication_date="2026-01-10",
                effective_date="2026-01-10",
                adapter_metadata={"document_type": "GENELGE", "reference_no": "2026/1"},
            )
            res = sgk.acquire_and_validate(req)
            self.assertFalse(res.ok, label)
            self.assertEqual(res.status, STATUS_REJECTED_INVALID_SOURCE, label)
            self.assertIn(exp_code, res.error_codes, label)

        # Redirect downgrade from HTTPS to HTTP inside redirect chain must be blocked
        sgk_downgrade = SgkAdapter(
            transport=_make_ok_transport(
                payload,
                final_url="https://www.sgk.gov.tr/Duyuru/Detay/2026-1",
                redirect_chain=[
                    "https://www.sgk.gov.tr/Duyuru/Detay/2026-1",
                    "http://www.sgk.gov.tr/Duyuru/Detay/2026-1-plain",
                ],
            )
        )
        res_dg = sgk_downgrade.acquire_and_validate(
            SourceDocumentRequest(
                source_key="SGK-TEST-DG",
                source_url="https://www.sgk.gov.tr/Duyuru/Detay/2026-1",
                title="SGK Yönlendirme Downgrade Testi",
                publication_date="2026-01-10",
                effective_date="2026-01-10",
                adapter_metadata={"document_type": "GENELGE", "reference_no": "2026/1"},
            )
        )
        self.assertFalse(res_dg.ok)
        self.assertIn("HTTPS_DOWNGRADE_REDIRECT_BLOCKED", res_dg.error_codes)

    def test_03_negative_corrupt_empty_sha256_mismatch_dates_and_adapter_metadata(self) -> None:
        """Criteria 3, 4, 8: reject empty/corrupt bodies, SHA-256 mismatch, bad dates, undeclared retroactive dates, bad metadata."""
        good_payload = b"<html><body>4857 Sayili Is Kanunu Madde 25 icerigi.</body></html>"
        mev = MevzuatAdapter(transport=_make_ok_transport(good_payload))

        # 1. Expected SHA-256 mismatch -> CONTENT_SHA256_MISMATCH
        res_sha = mev.acquire_and_validate(
            SourceDocumentRequest(
                source_key="KANUN-4857",
                source_url="https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=4857",
                title="4857 Sayılı İş Kanunu",
                publication_date="2026-01-10",
                effective_date="2026-01-10",
                expected_content_sha256="0" * 64,
                adapter_metadata={"mevzuat_no": "4857", "mevzuat_turu": "KANUN"},
            )
        )
        self.assertFalse(res_sha.ok)
        self.assertIn("CONTENT_SHA256_MISMATCH", res_sha.error_codes)

        # 2. Empty / truncated body -> EMPTY_OR_TRUNCATED_DOCUMENT_BODY
        mev_empty = MevzuatAdapter(transport=_make_ok_transport(b"short"))
        res_empty = mev_empty.acquire_and_validate(
            SourceDocumentRequest(
                source_key="KANUN-4857",
                source_url="https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=4857",
                title="4857 Sayılı İş Kanunu",
                publication_date="2026-01-10",
                effective_date="2026-01-10",
                adapter_metadata={"mevzuat_no": "4857", "mevzuat_turu": "KANUN"},
            )
        )
        self.assertFalse(res_empty.ok)
        self.assertIn("EMPTY_OR_TRUNCATED_DOCUMENT_BODY", res_empty.error_codes)

        # 3. NUL byte in non-PDF HTML -> MEVZUAT_CORRUPT_PAYLOAD
        mev_nul = MevzuatAdapter(transport=_make_ok_transport(b"<html><body>corrupt\x00payload bytes 12345</body></html>"))
        res_nul = mev_nul.acquire_and_validate(
            SourceDocumentRequest(
                source_key="KANUN-4857",
                source_url="https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=4857",
                title="4857 Sayılı İş Kanunu",
                publication_date="2026-01-10",
                effective_date="2026-01-10",
                adapter_metadata={"mevzuat_no": "4857", "mevzuat_turu": "KANUN"},
            )
        )
        self.assertFalse(res_nul.ok)
        self.assertIn("MEVZUAT_CORRUPT_PAYLOAD", res_nul.error_codes)

        # 4. Undeclared retroactive effective_date < publication_date -> rejected; explicit retroactive with rationale -> accepted
        res_retro_bad = mev.acquire_and_validate(
            SourceDocumentRequest(
                source_key="KANUN-RETRO",
                source_url="https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=7500",
                title="Geriye Yürürlüklü Kanun Testi",
                publication_date="2026-02-15",
                effective_date="2026-01-01",
                adapter_metadata={"mevzuat_no": "7500", "mevzuat_turu": "KANUN"},
            )
        )
        self.assertFalse(res_retro_bad.ok)
        self.assertIn("RETROACTIVE_EFFECTIVE_DATE_UNDECLARED", res_retro_bad.error_codes)

        mev_retro = MevzuatAdapter(
            transport=_make_ok_transport(
                b"<html><body>7500 Sayili Geriye Yururluklu Kanun 01.01.2026 tarihinden gecerlidir.</body></html>"
            )
        )
        res_retro_ok = mev_retro.acquire_and_validate(
            SourceDocumentRequest(
                source_key="KANUN-RETRO",
                source_url="https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=7500",
                title="Geriye Yürürlüklü Kanun Testi",
                publication_date="2026-02-15",
                effective_date="2026-01-01",
                retroactive_effective_allowed=True,
                adapter_metadata={
                    "mevzuat_no": "7500",
                    "mevzuat_turu": "KANUN",
                    "retroactive_rationale": "Kanun yürürlük maddesinde 01.01.2026 tarihinden geçerli olduğu açıkça belirtilmiştir.",
                },
            )
        )
        self.assertTrue(res_retro_ok.ok, res_retro_ok.errors)

        # 5. Yargıtay invalid Esas/Karar & decision_date > publication_date
        yarg = YargitayAdapter(transport=_make_ok_transport(good_payload))
        res_ybad = yarg.acquire_and_validate(
            SourceDocumentRequest(
                source_key="YARG-BAD-1",
                source_url="https://karararama.yargitay.gov.tr/karar/bad",
                title="Hatalı Yargıtay Metadatası",
                publication_date="2025-01-10",
                effective_date="2025-01-10",
                adapter_metadata={
                    "chamber": "9. Hukuk Dairesi",
                    "esas_no": "INVALID",
                    "karar_no": "2025/100",
                    "decision_date": "2025-02-01",
                },
            )
        )
        self.assertFalse(res_ybad.ok)
        self.assertIn("YARGITAY_INVALID_ESAS_NO", res_ybad.error_codes)
        self.assertIn("YARGITAY_DECISION_DATE_AFTER_PUBLICATION", res_ybad.error_codes)

        # 6. Resmî Gazete missing issue number
        rg = ResmiGazeteAdapter(transport=_make_ok_transport(good_payload))
        res_rgbad = rg.acquire_and_validate(
            SourceDocumentRequest(
                source_key="RG-BAD",
                source_url="https://www.resmigazete.gov.tr/eskiler/2026/01/20260101-1.htm",
                title="Sayı Numarası Eksik Resmî Gazete",
                publication_date="2026-01-01",
                effective_date="2026-01-01",
                adapter_metadata={},
            )
        )
        self.assertFalse(res_rgbad.ok)
        self.assertIn("RESMI_GAZETE_INVALID_ISSUE_NUMBER", res_rgbad.error_codes)

    def test_04_unreachable_sources_fail_closed_and_cannot_enter_verified_authority(self) -> None:
        """Criterion 6: unreachable/timeout/HTTP-503 sources NEVER appear verified and cannot bind answers."""
        reg = EvidenceRegistry()
        req = SourceDocumentRequest(
            source_key="ISKUR-UNREACH-1",
            source_url="https://www.iskur.gov.tr/mevzuat/genelge-2026-99",
            title="Erişilemeyen İŞKUR Genelgesi",
            publication_date="2026-01-10",
            effective_date="2026-01-10",
            adapter_metadata={"document_type": "GENELGE", "reference_no": "2026/99"},
        )

        def _timeout_transport(_url: str) -> dict[str, object]:
            raise TimeoutError("simulated socket read timeout")

        def _http_503_transport(url: str) -> dict[str, object]:
            return {
                "raw_bytes": b"Service Unavailable",
                "final_url": url,
                "redirect_chain": [url],
                "http_status": 503,
                "http_headers": {},
                "acquired_at_utc": "2026-11-25T10:00:00Z",
            }

        for label, tr in (
            ("timeout", _timeout_transport),
            ("http_503", _http_503_transport),
            ("unreachable_flag", lambda _u: {"unreachable": True}),
        ):
            res = IskurAdapter(transport=tr).acquire_and_validate(req)
            self.assertFalse(res.ok, label)
            self.assertEqual(res.status, STATUS_UNREACHABLE_NOT_VERIFIED, label)
            self.assertFalse(res.record.live_verified, label)
            self.assertFalse(res.record.is_verified_authority, label)
            self.assertEqual(res.record.content_sha256, "", label)

            with self.assertRaises(EvidenceRegistryError) as ctx:
                reg.register(res)
            self.assertEqual(ctx.exception.error_code, "UNREACHABLE_OR_UNVERIFIED_EVIDENCE_REJECTED")
            self.assertIsNone(reg.get(res.record.evidence_id))

            # Attempting to link unreachable evidence ID into legal answer fails closed
            builder = EvidenceBackedLegalAnswerBuilder(reg)
            with self.assertRaises(AnswerLinkageError) as ans_ctx:
                builder.build_answer(
                    query="İŞKUR 2026/99 genelgesi yürürlükte mi?",
                    answer_text="Genelge yürürlüktedir.",
                    evidence_ids=[res.record.evidence_id],
                    as_of_date="2026-06-01",
                )
            self.assertEqual(ans_ctx.exception.error_code, "EVIDENCE_NOT_FOUND_OR_UNVERIFIED")

        self.assertEqual(reg.record_count, 0)
        self.assertEqual(len(reg.failed_attempts), 3)

    def test_05_evidence_registry_versioning_historical_preservation_and_tamper_detection(self) -> None:
        """Criteria 1, 4, 5: preserve old versions, prevent confusion with current, reject duplicates, detect tampering."""
        reg = EvidenceRegistry()
        v1_bytes = b"<html><body>4857 Sayili Is Kanunu 2024 metni - surum 1.</body></html>"
        v2_bytes = b"<html><body>4857 Sayili Is Kanunu 2026 degisiklik metni - surum 2.</body></html>"

        res_v1 = MevzuatAdapter(
            transport=_make_ok_transport(v1_bytes, acquired_at_utc="2024-02-01T09:00:00Z")
        ).acquire_and_validate(
            SourceDocumentRequest(
                source_key="KANUN-4857",
                source_url="https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=4857&Surum=1",
                title="4857 Sayılı İş Kanunu (2024 Sürümü)",
                publication_date="2024-01-01",
                effective_date="2024-01-01",
                expiry_or_repeal_date="2025-12-31",
                adapter_metadata={"mevzuat_no": "4857", "mevzuat_turu": "KANUN"},
            )
        )
        rec_v1 = reg.register(res_v1)

        # Duplicate evidence_id registration fails closed
        with self.assertRaises(EvidenceRegistryError) as dup_ctx:
            reg.register(res_v1)
        self.assertEqual(dup_ctx.exception.error_code, "DUPLICATE_EVIDENCE_ID")

        # Register v2 superseding v1
        res_v2 = MevzuatAdapter(
            transport=_make_ok_transport(v2_bytes, acquired_at_utc="2026-01-05T09:00:00Z")
        ).acquire_and_validate(
            SourceDocumentRequest(
                source_key="KANUN-4857",
                source_url="https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=4857&Surum=2",
                title="4857 Sayılı İş Kanunu (2026 Güncel Sürümü)",
                publication_date="2025-12-20",
                effective_date="2026-01-01",
                supersedes_evidence_id=rec_v1.evidence_id,
                adapter_metadata={"mevzuat_no": "4857", "mevzuat_turu": "KANUN"},
            )
        )
        rec_v2 = reg.register(res_v2)

        # Verify version chain & historical preservation
        history = reg.get_version_history("KANUN-4857")
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0].evidence_id, rec_v1.evidence_id)
        self.assertEqual(history[1].evidence_id, rec_v2.evidence_id)
        self.assertEqual(rec_v1.version_number, 1)
        self.assertEqual(rec_v2.version_number, 2)
        self.assertEqual(rec_v2.supersedes_evidence_id, rec_v1.evidence_id)
        self.assertTrue(reg.is_superseded(rec_v1.evidence_id))
        self.assertFalse(reg.is_superseded(rec_v2.evidence_id))
        self.assertEqual(reg.get_current("KANUN-4857"), rec_v2)

        # Date-based resolution cleanly separates historical v1 vs current v2
        resolved_2025, meta_2025 = reg.resolve_for_date("KANUN-4857", "2025-06-15")
        self.assertEqual(resolved_2025, rec_v1)
        self.assertTrue(meta_2025["is_superseded_by_later_version"])
        self.assertEqual(meta_2025["latest_evidence_id"], rec_v2.evidence_id)

        resolved_2026, meta_2026 = reg.resolve_for_date("KANUN-4857", "2026-06-15")
        self.assertEqual(resolved_2026, rec_v2)
        self.assertTrue(meta_2026["is_current_latest"])

        # Snapshot export + round-trip rehydration (including full raw bytes!) + tamper rejection
        snap = reg.export_snapshot_dict()
        self.assertEqual(snap["snapshot_mode"], SNAPSHOT_MODE_FULL_WITH_RAW)
        restored = EvidenceRegistry.from_snapshot_dict(snap)
        ok_rest, rep_rest = restored.verify_integrity()
        self.assertTrue(ok_rest, rep_rest)
        self.assertTrue(rep_rest["full_content_archive_verified"])
        self.assertEqual(restored.head_sha256, reg.head_sha256)
        self.assertEqual(restored.get_raw_bytes(rec_v1.evidence_id), v1_bytes)
        self.assertEqual(restored.get_raw_bytes(rec_v2.evidence_id), v2_bytes)

        tampered_snap = reg.export_snapshot_dict()
        tampered_snap["records"][0]["title"] = "Tahrif Edilmiş Kanun Başlığı"
        with self.assertRaises(EvidenceRegistryError) as snap_ctx:
            EvidenceRegistry.from_snapshot_dict(tampered_snap)
        self.assertEqual(snap_ctx.exception.error_code, "REGISTRY_SNAPSHOT_INTEGRITY_FAILED")

        # In-memory raw byte tampering inside ContentStore detected by verify_integrity()
        assert isinstance(reg.content_store, InMemoryContentStore)
        reg.content_store._blobs[rec_v1.evidence_id] = v1_bytes + b"TAMPER"
        ok_tamper, rep_tamper = reg.verify_integrity()
        self.assertFalse(ok_tamper)
        self.assertFalse(rep_tamper["full_content_archive_verified"])
        self.assertTrue(any("tahrifat" in e for e in rep_tamper["errors"]))

    def test_06_evidence_linked_answer_router_integration_and_end_to_end_traceability(self) -> None:
        """Criteria 5, 7, 10: bind @HukukSGK answers to verified evidence via HukukSGKToolRouter with full traceability."""
        reg = EvidenceRegistry()
        v1_res = MevzuatAdapter(
            transport=_make_ok_transport(b"<html><body>4857 Sayili Is Kanunu eski surum metni 2024.</body></html>")
        ).acquire_and_validate(
            SourceDocumentRequest(
                source_key="KANUN-4857-M17",
                source_url="https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=4857&Madde=17&v=1",
                title="4857 Sayılı İş Kanunu m.17 (2024)",
                publication_date="2024-01-01",
                effective_date="2024-01-01",
                expiry_or_repeal_date="2025-12-31",
                adapter_metadata={"mevzuat_no": "4857", "mevzuat_turu": "KANUN", "article_ref": "m.17"},
            )
        )
        rec_old = reg.register(v1_res)

        v2_res = MevzuatAdapter(
            transport=_make_ok_transport(b"<html><body>4857 Sayili Is Kanunu m.17 guncel 2026 metni.</body></html>")
        ).acquire_and_validate(
            SourceDocumentRequest(
                source_key="KANUN-4857-M17",
                source_url="https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=4857&Madde=17&v=2",
                title="4857 Sayılı İş Kanunu m.17 (2026 Güncel)",
                publication_date="2025-12-20",
                effective_date="2026-01-01",
                adapter_metadata={"mevzuat_no": "4857", "mevzuat_turu": "KANUN", "article_ref": "m.17"},
            )
        )
        rec_cur = reg.register(v2_res)

        yarg_res = YargitayAdapter(
            transport=_make_ok_transport(
                b"<html><body>Yargitay 9. HD E. 2025/900 K. 2025/2100 ihbar suresi uygulamasi karar metni.</body></html>"
            )
        ).acquire_and_validate(
            SourceDocumentRequest(
                source_key="YARGITAY-9HD-2025-900-2025-2100",
                source_url="https://karararama.yargitay.gov.tr/karar/2025-2100",
                title="Yargıtay 9. HD İhbar Süresi Kararı",
                publication_date="2025-09-15",
                effective_date="2025-09-15",
                adapter_metadata={
                    "chamber": "9. Hukuk Dairesi",
                    "esas_no": "2025/900",
                    "karar_no": "2025/2100",
                    "decision_date": "2025-09-01",
                },
            )
        )
        rec_yarg = reg.register(yarg_res)

        router = HukukSGKToolRouter(evidence_registry=reg)
        linked_dict = router.dispatch(
            "build_evidence_linked_answer",
            {
                "query": "2026 yılında 4857 m.17 bildirim süreleri nasıl uygulanır?",
                "answer_text": "4857 sayılı İş Kanunu m.17 ve Yargıtay 9. HD içtihadı uyarınca kıdeme göre bildirim süreleri uygulanır.",
                "evidence_ids": [rec_cur.evidence_id, rec_yarg.evidence_id],
                "as_of_date": "2026-06-15",
            },
        )
        self.assertTrue(linked_dict["all_evidence_verified"])
        self.assertFalse(linked_dict["all_evidence_live_verified"])
        self.assertFalse(linked_dict["production_use_authorized"])
        self.assertFalse(linked_dict["qualified_e_signature_5070_equivalent"])
        self.assertFalse(linked_dict["kvkk_data_residency_approved"])
        self.assertEqual(linked_dict["evidence_ids"], [rec_cur.evidence_id, rec_yarg.evidence_id])

        # Re-verify end-to-end traceability with EvidenceBackedLegalAnswerBuilder + verify_answer_traceability
        builder = EvidenceBackedLegalAnswerBuilder(reg)
        ans = builder.build_answer(
            query="2026 yılında 4857 m.17 bildirim süreleri nasıl uygulanır?",
            answer_text="4857 sayılı İş Kanunu m.17 ve Yargıtay 9. HD içtihadı uyarınca bildirim süreleri uygulanır.",
            evidence_ids=[rec_cur.evidence_id, rec_yarg.evidence_id],
            as_of_date="2026-06-15",
        )
        ok_trace, trace_rep = verify_answer_traceability(ans, reg)
        self.assertTrue(ok_trace, trace_rep)
        self.assertEqual(trace_rep["traced_evidence_count"], 2)
        self.assertEqual(trace_rep["registry_head_status"], HEAD_STATUS_EXACT_MATCH)
        self.assertTrue(trace_rep["full_content_archive_verified"])

        # Tampered answer text detected by verify_answer_traceability
        tampered_ans = replace(ans, answer_text="Değiştirilmiş yetkisiz hukuki yorum.")
        ok_bad_trace, bad_trace_rep = verify_answer_traceability(tampered_ans, reg)
        self.assertFalse(ok_bad_trace)
        self.assertTrue(any("answer_sha256" in e for e in bad_trace_rep["errors"]))

        # Negative linkage rules:
        # 1. Empty evidence_ids -> NO_EVIDENCE_IDS_PROVIDED
        with self.assertRaises(AnswerLinkageError) as e_empty:
            builder.build_answer(query="Sorgu", answer_text="Cevap metni.", evidence_ids=[], as_of_date="2026-06-15")
        self.assertEqual(e_empty.exception.error_code, "NO_EVIDENCE_IDS_PROVIDED")

        # 2. require_live_verified=True rejects test-transport evidence
        with self.assertRaises(AnswerLinkageError) as e_live:
            builder.build_answer(
                query="Canlı zorunlu sorgu",
                answer_text="Cevap metni.",
                evidence_ids=[rec_cur.evidence_id],
                as_of_date="2026-06-15",
                require_live_verified=True,
            )
        self.assertEqual(e_live.exception.error_code, "LIVE_VERIFICATION_REQUIRED")

        # 3. Future evidence (not yet effective on as_of_date) rejected
        with self.assertRaises(AnswerLinkageError) as e_fut:
            builder.build_answer(
                query="Geçmiş tarihli sorgu",
                answer_text="2025 için 2026 kuralı uygulanamaz.",
                evidence_ids=[rec_cur.evidence_id],
                as_of_date="2025-06-15",
            )
        self.assertEqual(e_fut.exception.error_code, "EVIDENCE_NOT_YET_EFFECTIVE")

        # 4. Superseded/repealed old version cited on 2026-06-15 WITHOUT disclosure -> rejected; WITH disclosure -> allowed
        with self.assertRaises(AnswerLinkageError) as e_sup:
            builder.build_answer(
                query="Eski sürüm atfı",
                answer_text="2024 metnine atıf.",
                evidence_ids=[rec_old.evidence_id],
                as_of_date="2026-06-15",
            )
        self.assertEqual(e_sup.exception.error_code, "SUPERSEDED_OR_REPEALED_EVIDENCE_REQUIRES_HISTORICAL_DISCLOSURE")

        hist_ans = builder.build_answer(
            query="Eski 2024 dönemine ilişkin tarihsel değerlendirme",
            answer_text="2024 dönemi uyuşmazlığı için mülga 2024 sürümü tarihsel karşılaştırma amacıyla bağlanmıştır.",
            evidence_ids=[rec_old.evidence_id],
            as_of_date="2026-06-15",
            allow_historical_superseded=True,
            historical_disclosure_text="DİKKAT: Bu kanıt 2025-12-31 tarihinde mülga olmuş/değiştirilmiş tarihsel sürümdür.",
        )
        self.assertTrue(hist_ans.historical_disclosure_included)

    def test_07_baseline_immutability_schema_config_counts_and_closed_gates_preserved(self) -> None:
        """Criterion 9: WP-2 leaves xmldsig.py, 13 schemas, 9 configs, and closed production/5070/KVKK gates intact."""
        xmldsig_sha = hashlib.sha256((PROJECT_ROOT / "engine" / "esign5070" / "xmldsig.py").read_bytes()).hexdigest()
        self.assertEqual(xmldsig_sha, EXPECTED_XMLDSIG_SHA256)
        self.assertEqual(len(list((PROJECT_ROOT / "schemas").glob("*.json"))), 13)
        self.assertEqual(len(list((PROJECT_ROOT / "config").glob("*.json"))), 9)

        probe = run_live_integration_probe()
        self.assertFalse(probe["production_use_authorized"])
        self.assertFalse(probe["qualified_e_signature_5070_production_ready"])
        self.assertFalse(probe["qualified_e_signature_5070_equivalent"])
        pad = probe["production_authorization_decision"]
        self.assertFalse(pad["checks"]["kvkk_data_residency_approved"])
        self.assertTrue(all(v == "NOT_CONFIGURED" for v in pad["integration_modes"].values()))

    def test_08_security_hardening_live_fetcher_scope_redirect_chain_defensive_clone_and_temporal_split(self) -> None:
        """Verify live_fetcher domain-scope enforcement, redirect_chain consistency, defensive cloning, and historical-date binding."""
        from engine.trust_root.source_acquisition import LiveHttpsSourceFetcher

        # 1. Overly broad LiveHttpsSourceFetcher rejected before network call
        broad_fetcher = LiveHttpsSourceFetcher(allowed_domains=frozenset({"www.sgk.gov.tr", "evil.example.com"}))
        sgk_broad = SgkAdapter(live_fetcher=broad_fetcher)
        res_broad = sgk_broad.acquire_and_validate(
            SourceDocumentRequest(
                source_key="SGK-SCOPE-1",
                source_url="https://www.sgk.gov.tr/Duyuru/Detay/2026-10",
                title="SGK Alan Adı Kapsam Testi",
                publication_date="2026-01-10",
                effective_date="2026-01-10",
                adapter_metadata={"document_type": "GENELGE", "reference_no": "2026/10"},
            )
        )
        self.assertFalse(res_broad.ok)
        self.assertIn("LIVE_FETCHER_DOMAIN_SCOPE_EXCEEDED", res_broad.error_codes)

        # 2. Inconsistent redirect_chain (final_url not matching last hop) rejected
        sgk_bad_hop = SgkAdapter(
            transport=_make_ok_transport(
                b"<html><body>SGK belge metni 12345678901234567890</body></html>",
                final_url="https://www.sgk.gov.tr/Duyuru/Detay/other",
                redirect_chain=["https://www.sgk.gov.tr/Duyuru/Detay/2026-10"],
            )
        )
        res_hop = sgk_bad_hop.acquire_and_validate(
            SourceDocumentRequest(
                source_key="SGK-HOP-1",
                source_url="https://www.sgk.gov.tr/Duyuru/Detay/2026-10",
                title="SGK Tutarsız Yönlendirme Testi",
                publication_date="2026-01-10",
                effective_date="2026-01-10",
                adapter_metadata={"document_type": "GENELGE", "reference_no": "2026/10"},
            )
        )
        self.assertFalse(res_hop.ok)
        self.assertIn("REDIRECT_CHAIN_INCONSISTENT", res_hop.error_codes)

        # 3. Defensive cloning prevents caller mutation of adapter_metadata from corrupting registry
        reg = EvidenceRegistry()
        req_meta = {"mevzuat_no": "4857", "mevzuat_turu": "KANUN", "nested": {"tag": "orig"}}
        v1 = reg.register(
            MevzuatAdapter(
                transport=_make_ok_transport(b"<html><body>4857 Sayili Kanun Izolasyon 2024 versiyonu icerik metni.</body></html>")
            ).acquire_and_validate(
                SourceDocumentRequest(
                    source_key="KANUN-4857-ISO",
                    source_url="https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=4857&iso=1",
                    title="4857 İzolasyon 2024",
                    publication_date="2024-01-01",
                    effective_date="2024-01-01",
                    expiry_or_repeal_date="2025-12-31",
                    adapter_metadata=req_meta,
                )
            )
        )
        req_meta["nested"]["tag"] = "mutated_caller"
        fetched = reg.get(v1.evidence_id)
        assert fetched is not None
        fetched.adapter_metadata["nested"]["tag"] = "mutated_getter"
        ok_int, rep_int = reg.verify_integrity()
        self.assertTrue(ok_int, rep_int)
        fetched_again = reg.get(v1.evidence_id)
        assert fetched_again is not None
        self.assertEqual(fetched_again.adapter_metadata["nested"]["tag"], "orig")

        # 4. Historical dispute date (2025-06-15) cleanly binds v1 while accurately marking is_superseded=True once v2 exists
        reg.register(
            MevzuatAdapter(
                transport=_make_ok_transport(b"<html><body>4857 Sayili Kanun Izolasyon 2026 guncel versiyon icerik metni.</body></html>")
            ).acquire_and_validate(
                SourceDocumentRequest(
                    source_key="KANUN-4857-ISO",
                    source_url="https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=4857&iso=2",
                    title="4857 İzolasyon 2026",
                    publication_date="2025-12-20",
                    effective_date="2026-01-01",
                    adapter_metadata={"mevzuat_no": "4857", "mevzuat_turu": "KANUN"},
                )
            )
        )
        ans_2025 = EvidenceBackedLegalAnswerBuilder(reg).build_answer(
            query="2025 tarihli uyuşmazlıkta 4857 hükmü nedir?",
            answer_text="2025 uyuşmazlığı için 2025-06-15 tarihinde yürürlükte olan v1 metni esas alınır.",
            evidence_ids=[v1.evidence_id],
            as_of_date="2025-06-15",
        )
        self.assertEqual(len(ans_2025.evidence_links), 1)
        self.assertTrue(ans_2025.evidence_links[0].is_superseded)
        self.assertFalse(ans_2025.evidence_links[0].is_current_version)

        # 5. Unsupported snapshot schema_version rejected fail-closed
        bad_snap = reg.export_snapshot_dict()
        bad_snap["schema_version"] = "9.9.9"
        with self.assertRaises(EvidenceRegistryError) as sv_ctx:
            EvidenceRegistry.from_snapshot_dict(bad_snap)
        self.assertEqual(sv_ctx.exception.error_code, "UNSUPPORTED_SNAPSHOT_SCHEMA_VERSION")

    def test_09_snapshot_raw_content_archive_filesystem_store_and_missing_content_fail_closed(self) -> None:
        """PR #3 Finding 1: raw bytes preserved/verified across snapshots & FileSystemContentStore; metadata-only fails closed."""
        raw_1 = b"<html><body>4857 Sayili Is Kanunu Madde 18 tam belge arsivi 2025.</body></html>"
        raw_2 = b"<html><body>Resmi Gazete Sayi 32766 - 2025 Asgari Ucret Karari tam arsiv.</body></html>"

        reg = EvidenceRegistry()
        rec1 = reg.register(
            MevzuatAdapter(transport=_make_ok_transport(raw_1)).acquire_and_validate(
                SourceDocumentRequest(
                    source_key="KANUN-4857-ARCHIVE",
                    source_url="https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=4857&m=18",
                    title="4857 Sayılı İş Kanunu Madde 18",
                    publication_date="2025-01-01",
                    effective_date="2025-01-01",
                    adapter_metadata={"mevzuat_no": "4857", "mevzuat_turu": "KANUN"},
                )
            )
        )
        rec2 = reg.register(
            ResmiGazeteAdapter(transport=_make_ok_transport(raw_2)).acquire_and_validate(
                SourceDocumentRequest(
                    source_key="RG-32766-ARCHIVE",
                    source_url="https://www.resmigazete.gov.tr/eskiler/2024/12/20241228-1.htm",
                    title="2025 Yılı Asgari Ücret Kararı",
                    publication_date="2024-12-28",
                    effective_date="2025-01-01",
                    adapter_metadata={"gazette_number": "32766"},
                )
            )
        )

        # 1. Default full snapshot preserves raw bytes and bundle SHA-256 across round-trip rehydration
        full_snap = reg.export_snapshot_dict(include_raw_content=True)
        self.assertEqual(full_snap["snapshot_mode"], SNAPSHOT_MODE_FULL_WITH_RAW)
        self.assertIsInstance(full_snap["raw_content_b64"], dict)
        self.assertEqual(full_snap["raw_content_bundle_sha256"], canonical_sha256(full_snap["raw_content_b64"]))

        restored_full = EvidenceRegistry.from_snapshot_dict(full_snap)
        ok_full, rep_full = restored_full.verify_integrity(require_raw_content=True)
        self.assertTrue(ok_full, rep_full)
        self.assertTrue(rep_full["full_content_archive_verified"])
        self.assertEqual(rep_full["raw_content_verified_count"], 2)
        self.assertEqual(rep_full["raw_content_missing_ids"], [])
        self.assertEqual(restored_full.get_raw_bytes(rec1.evidence_id), raw_1)
        self.assertEqual(restored_full.get_raw_bytes(rec2.evidence_id), raw_2)

        # 2. Tampering 1 byte of raw_content_b64 (both with and without bundle digest recomputation) fails closed
        tampered_b64_only = reg.export_snapshot_dict(include_raw_content=True)
        tampered_b64_only["raw_content_b64"][rec1.evidence_id] = base64.b64encode(raw_1 + b"!").decode("ascii")
        with self.assertRaises(EvidenceRegistryError) as ctx_b1:
            EvidenceRegistry.from_snapshot_dict(tampered_b64_only)
        self.assertEqual(ctx_b1.exception.error_code, "RAW_CONTENT_BUNDLE_SHA256_MISMATCH")

        tampered_with_recomputed_bundle = reg.export_snapshot_dict(include_raw_content=True)
        tampered_with_recomputed_bundle["raw_content_b64"][rec1.evidence_id] = base64.b64encode(raw_1 + b"!").decode("ascii")
        tampered_with_recomputed_bundle["raw_content_bundle_sha256"] = canonical_sha256(
            tampered_with_recomputed_bundle["raw_content_b64"]
        )
        with self.assertRaises(EvidenceRegistryError) as ctx_b2:
            EvidenceRegistry.from_snapshot_dict(tampered_with_recomputed_bundle)
        self.assertEqual(ctx_b2.exception.error_code, "REGISTRY_SNAPSHOT_INTEGRITY_FAILED")

        # Stray key in raw_content_b64 rejected even with recomputed bundle digest
        stray_key_snap = reg.export_snapshot_dict(include_raw_content=True)
        stray_key_snap["raw_content_b64"]["EVD-STRAY-999999"] = base64.b64encode(b"stray").decode("ascii")
        stray_key_snap["raw_content_bundle_sha256"] = canonical_sha256(stray_key_snap["raw_content_b64"])
        with self.assertRaises(EvidenceRegistryError) as ctx_stray:
            EvidenceRegistry.from_snapshot_dict(stray_key_snap)
        self.assertEqual(ctx_stray.exception.error_code, "RAW_CONTENT_MISSING_OR_CORRUPT_IN_SNAPSHOT")

        # 3. Metadata-only snapshot fails closed on default from_snapshot_dict(), verify_integrity(), AND answer building
        meta_snap = reg.export_snapshot_dict(include_raw_content=False)
        self.assertEqual(meta_snap["snapshot_mode"], SNAPSHOT_MODE_METADATA_ONLY)
        self.assertIsNone(meta_snap["raw_content_b64"])

        with self.assertRaises(EvidenceRegistryError) as ctx_meta_default:
            EvidenceRegistry.from_snapshot_dict(meta_snap)
        self.assertEqual(ctx_meta_default.exception.error_code, "RAW_CONTENT_REQUIRED_FOR_METADATA_ONLY_SNAPSHOT")

        meta_only_reg = EvidenceRegistry.from_snapshot_dict(meta_snap, require_raw_content=False)
        ok_strict, rep_strict = meta_only_reg.verify_integrity(require_raw_content=True)
        self.assertFalse(ok_strict)
        self.assertFalse(rep_strict["full_content_archive_verified"])
        self.assertEqual(rep_strict["raw_content_verified_count"], 0)
        self.assertEqual(set(rep_strict["raw_content_missing_ids"]), {rec1.evidence_id, rec2.evidence_id})
        self.assertTrue(any("RAW_CONTENT_UNAVAILABLE_FOR_VERIFICATION" in e for e in rep_strict["errors"]))

        ok_relaxed, rep_relaxed = meta_only_reg.verify_integrity(require_raw_content=False)
        self.assertTrue(ok_relaxed)
        self.assertFalse(rep_relaxed["full_content_archive_verified"])

        with self.assertRaises(AnswerLinkageError) as ctx_ans_meta:
            EvidenceBackedLegalAnswerBuilder(meta_only_reg).build_answer(
                query="Ham içeriksiz anlık görüntüden cevap bağlanabilir mi?",
                answer_text="Bağlanamamalıdır.",
                evidence_ids=[rec1.evidence_id],
                as_of_date="2025-06-01",
            )
        self.assertEqual(ctx_ans_meta.exception.error_code, "EVIDENCE_REGISTRY_INTEGRITY_FAILED")

        # 4. FileSystemContentStore: write-once persistence, symlink rejection, and metadata-only + store rehydration
        with tempfile.TemporaryDirectory() as tmpdir:
            store_dir = Path(tmpdir) / "raw_archive"
            fs_store = FileSystemContentStore(store_dir)
            fs_reg = EvidenceRegistry(content_store=fs_store)
            fs_rec = fs_reg.register(
                MevzuatAdapter(transport=_make_ok_transport(raw_1)).acquire_and_validate(
                    SourceDocumentRequest(
                        source_key="KANUN-4857-FS",
                        source_url="https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=4857&fs=1",
                        title="4857 Sayılı İş Kanunu Madde 18",
                        publication_date="2025-01-01",
                        effective_date="2025-01-01",
                        adapter_metadata={"mevzuat_no": "4857", "mevzuat_turu": "KANUN"},
                    )
                )
            )
            self.assertTrue((store_dir / f"{fs_rec.evidence_id}.bin").is_file())
            self.assertEqual(fs_reg.get_raw_bytes(fs_rec.evidence_id), raw_1)

            # Write-once rejects silent overwrite
            with self.assertRaises(EvidenceRegistryError) as ctx_ow:
                fs_store.put(fs_rec.evidence_id, b"overwrite attempt")
            self.assertEqual(ctx_ow.exception.error_code, "CONTENT_STORE_OVERWRITE_FORBIDDEN")

            # Rehydrating metadata-only snapshot WITH FileSystemContentStore succeeds with full verification
            fs_meta_snap = fs_reg.export_snapshot_dict(include_raw_content=False)
            rehydrated_fs = EvidenceRegistry.from_snapshot_dict(
                fs_meta_snap,
                content_store=FileSystemContentStore(store_dir),
                require_raw_content=True,
            )
            ok_fs, rep_fs = rehydrated_fs.verify_integrity(require_raw_content=True)
            self.assertTrue(ok_fs, rep_fs)
            self.assertTrue(rep_fs["full_content_archive_verified"])
            self.assertEqual(rehydrated_fs.get_raw_bytes(fs_rec.evidence_id), raw_1)

            # Conflicting bytes between pre-populated FileSystemContentStore and full snapshot fail closed
            conflict_full_snap = fs_reg.export_snapshot_dict(include_raw_content=True)
            conflict_full_snap["raw_content_b64"][fs_rec.evidence_id] = base64.b64encode(raw_1 + b"X").decode("ascii")
            conflict_full_snap["raw_content_bundle_sha256"] = canonical_sha256(conflict_full_snap["raw_content_b64"])
            with self.assertRaises(EvidenceRegistryError) as ctx_conf:
                EvidenceRegistry.from_snapshot_dict(
                    conflict_full_snap,
                    content_store=FileSystemContentStore(store_dir),
                    require_raw_content=True,
                )
            self.assertEqual(ctx_conf.exception.error_code, "RAW_CONTENT_STORE_SNAPSHOT_CONFLICT")

            # Symlinked store directory (existing & broken) and symlinked blob file rejected fail-closed
            symlink_dir = Path(tmpdir) / "symlink_store"
            os.symlink(store_dir, symlink_dir)
            with self.assertRaises(EvidenceRegistryError) as ctx_sdir:
                FileSystemContentStore(symlink_dir)
            self.assertEqual(ctx_sdir.exception.error_code, "INVALID_CONTENT_STORE_DIR")

            broken_symlink_dir = Path(tmpdir) / "broken_symlink_store"
            os.symlink(Path(tmpdir) / "nonexistent_target", broken_symlink_dir)
            with self.assertRaises(EvidenceRegistryError) as ctx_bsdir:
                FileSystemContentStore(broken_symlink_dir)
            self.assertEqual(ctx_bsdir.exception.error_code, "INVALID_CONTENT_STORE_DIR")

            outside_file = Path(tmpdir) / "outside.bin"
            outside_file.write_bytes(raw_1)
            (store_dir / f"{fs_rec.evidence_id}.bin").unlink()
            os.symlink(outside_file, store_dir / f"{fs_rec.evidence_id}.bin")
            ok_sym_blob, rep_sym_blob = rehydrated_fs.verify_integrity(require_raw_content=True)
            self.assertFalse(ok_sym_blob)
            self.assertTrue(any("symlink" in e.lower() for e in rep_sym_blob["errors"]))

    def test_10_document_content_mismatch_rejection_and_unparseable_binary_honest_status(self) -> None:
        """PR #3 Finding 2: reject mismatched official-domain pages across all 6 adapters; classify scanned PDF honestly."""
        reg = EvidenceRegistry()

        # 1. Unrelated HTML from allowed official domains MUST fail with STATUS_REJECTED_CONTENT_MISMATCH
        mismatch_cases = [
            (
                ResmiGazeteAdapter,
                SourceDocumentRequest(
                    source_key="RG-MISMATCH-ISSUE",
                    source_url="https://www.resmigazete.gov.tr/eskiler/2024/12/20241228-1.htm",
                    title="2025 Yılı Asgari Ücret Kararı",
                    publication_date="2024-12-28",
                    effective_date="2025-01-01",
                    adapter_metadata={"gazette_number": "32766"},
                ),
                b"<html><body>Resmi Gazete Sayi 32999 - Tamamen farkli tarim tebligi metni.</body></html>",
                "RESMI_GAZETE_CONTENT_MISMATCH",
            ),
            (
                ResmiGazeteAdapter,
                SourceDocumentRequest(
                    source_key="RG-MISMATCH-ERROR-PAGE",
                    source_url="https://www.resmigazete.gov.tr/eskiler/2024/12/20241228-1.htm",
                    title="2025 Yılı Asgari Ücret Kararı",
                    publication_date="2024-12-28",
                    effective_date="2025-01-01",
                    adapter_metadata={"gazette_number": "32766"},
                ),
                b"<html><body>Resmi Gazete 32766 sayfasi sistem bakimi nedeniyle goruntulenemedi.</body></html>",
                "RESMI_GAZETE_CONTENT_MISMATCH",
            ),
            (
                MevzuatAdapter,
                SourceDocumentRequest(
                    source_key="KANUN-4857-MISMATCH",
                    source_url="https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=4857",
                    title="4857 Sayılı İş Kanunu",
                    publication_date="2003-06-10",
                    effective_date="2003-06-10",
                    adapter_metadata={"mevzuat_no": "4857", "mevzuat_turu": "KANUN"},
                ),
                b"<html><body>5510 Sayili Sosyal Sigortalar ve Genel Saglik Sigortasi Kanunu metni.</body></html>",
                "MEVZUAT_CONTENT_MISMATCH",
            ),
            (
                SgkAdapter,
                SourceDocumentRequest(
                    source_key="SGK-MISMATCH-1",
                    source_url="https://www.sgk.gov.tr/Duyuru/Detay/2026-15",
                    title="SGK 2026/15 Sayılı İşveren İşlemleri Genelgesi",
                    publication_date="2026-02-01",
                    effective_date="2026-02-01",
                    adapter_metadata={"document_type": "GENELGE", "reference_no": "2026/15"},
                ),
                b"<html><body>SGK 2024/02 duyurusu - ilgisiz emekli ikramiyesi haberi.</body></html>",
                "SGK_CONTENT_MISMATCH",
            ),
            (
                IskurAdapter,
                SourceDocumentRequest(
                    source_key="ISKUR-MISMATCH-1",
                    source_url="https://www.iskur.gov.tr/mevzuat/kco-2026",
                    title="İŞKUR Kısa Çalışma Ödeneği Usul ve Esasları",
                    publication_date="2026-01-15",
                    effective_date="2026-02-01",
                    adapter_metadata={"document_type": "USUL_VE_ESASLAR", "reference_no": "ISKUR-2026/01"},
                ),
                b"<html><body>ISKUR genel duyuru sayfasi - mesleki egitim fuari takvimi.</body></html>",
                "ISKUR_CONTENT_MISMATCH",
            ),
            (
                YargitayAdapter,
                SourceDocumentRequest(
                    source_key="YARG-MISMATCH-1",
                    source_url="https://karararama.yargitay.gov.tr/karar/2025-4500",
                    title="Yargıtay 9. Hukuk Dairesi Fazla Mesai Kararı",
                    publication_date="2025-05-20",
                    effective_date="2025-05-20",
                    adapter_metadata={
                        "chamber": "9. Hukuk Dairesi",
                        "esas_no": "2025/1200",
                        "karar_no": "2025/4500",
                        "decision_date": "2025-04-10",
                    },
                ),
                b"<html><body>Yargitay 9. HD E. 2024/111 K. 2024/222 bambaska bir karar metni.</body></html>",
                "YARGITAY_CONTENT_MISMATCH",
            ),
            (
                DanistayAdapter,
                SourceDocumentRequest(
                    source_key="DAN-MISMATCH-1",
                    source_url="https://karararama.danistay.gov.tr/karar/2025-110",
                    title="Danıştay 10. Daire SGK İdari Para Cezası Kararı",
                    publication_date="2025-06-05",
                    effective_date="2025-06-05",
                    adapter_metadata={
                        "chamber": "10. Daire",
                        "esas_no": "2024/880",
                        "karar_no": "2025/110",
                        "decision_date": "2025-03-18",
                    },
                ),
                b"<html><body>Danistay 4. Daire E. 2023/10 K. 2024/50 vergi uyusmazligi karari.</body></html>",
                "DANISTAY_CONTENT_MISMATCH",
            ),
        ]

        for adapter_cls, req, wrong_html, exp_code in mismatch_cases:
            res = adapter_cls(transport=_make_ok_transport(wrong_html)).acquire_and_validate(req)
            self.assertFalse(res.ok, exp_code)
            self.assertEqual(res.status, STATUS_REJECTED_CONTENT_MISMATCH, exp_code)
            self.assertIn(exp_code, res.error_codes, exp_code)
            self.assertFalse(res.record.content_verified, exp_code)
            self.assertFalse(res.record.is_verified_authority, exp_code)
            self.assertEqual(res.record.content_verification.get("content_match_status"), CONTENT_MATCH_MISMATCH)
            with self.assertRaises(EvidenceRegistryError) as reg_exc:
                reg.register(res)
            self.assertEqual(reg_exc.exception.error_code, "UNREACHABLE_OR_UNVERIFIED_EVIDENCE_REJECTED")

        # 2. Opaque image-only / scanned PDF MUST return STATUS_TRANSPORT_ONLY_UNVERIFIED_CONTENT (NEVER VERIFIED_LIVE)
        scanned_pdf = (
            b"%PDF-1.7\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /XObject /Subtype /Image /Width 800 /Height 1200 /Length 16 >>\n"
            b"stream\n\xff\xd8\xff\xe0\x00\x10\x01\x02\x89\xab\xcd\xef\x00\xfe\xff\xd9\nendstream\nendobj\n"
            b"%%EOF"
        )
        sgk_req = SourceDocumentRequest(
            source_key="SGK-SCANNED-2026-15",
            source_url="https://www.sgk.gov.tr/Duyuru/Detay/2026-15-genelge.pdf",
            title="SGK 2026/15 Sayılı İşveren İşlemleri Genelgesi",
            publication_date="2026-02-01",
            effective_date="2026-02-01",
            adapter_metadata={"document_type": "GENELGE", "reference_no": "2026/15"},
        )
        res_scan = SgkAdapter(
            transport=_make_ok_transport(scanned_pdf, content_type="application/pdf")
        ).acquire_and_validate(sgk_req)
        self.assertFalse(res_scan.ok)
        self.assertEqual(res_scan.status, STATUS_TRANSPORT_ONLY_UNVERIFIED_CONTENT)
        self.assertEqual(res_scan.error_codes, ("DOCUMENT_CONTENT_UNPARSEABLE_BINARY",))
        self.assertFalse(res_scan.record.content_verified)
        self.assertFalse(res_scan.record.live_verified)
        self.assertFalse(res_scan.record.is_verified_authority)
        self.assertEqual(
            res_scan.record.content_verification.get("content_match_status"),
            CONTENT_MATCH_UNPARSEABLE_BINARY,
        )
        self.assertEqual(res_scan.record.content_sha256, hashlib.sha256(scanned_pdf).hexdigest())
        self.assertEqual(res_scan.raw_bytes, scanned_pdf)
        with self.assertRaises(EvidenceRegistryError) as scan_reg_exc:
            reg.register(res_scan)
        self.assertEqual(scan_reg_exc.exception.error_code, "UNREACHABLE_OR_UNVERIFIED_EVIDENCE_REJECTED")

        # 3. FlateDecode compressed PDF stream with real Turkish text IS parsed via stdlib zlib and matched!
        good_stream = zlib.compress(b"T.C. Sosyal Guvenlik Kurumu (SGK) 2026/15 Sayili Isveren Islemleri Genelgesi")
        flate_pdf_ok = (
            b"%PDF-1.7\n1 0 obj\n<< /Filter /FlateDecode /Length "
            + str(len(good_stream)).encode("ascii")
            + b" >>\nstream\n"
            + good_stream
            + b"\nendstream\nendobj\n%%EOF"
        )
        res_flate_ok = SgkAdapter(
            transport=_make_ok_transport(flate_pdf_ok, content_type="application/pdf")
        ).acquire_and_validate(sgk_req)
        self.assertTrue(res_flate_ok.ok, res_flate_ok.errors)
        self.assertTrue(res_flate_ok.record.content_verified)
        self.assertEqual(res_flate_ok.record.content_verification.get("extracted_text_format"), "PDF_TEXT_STREAM")

        bad_stream = zlib.compress(b"T.C. Sosyal Guvenlik Kurumu (SGK) 2019/01 eski duyuru metni")
        flate_pdf_bad = (
            b"%PDF-1.7\n1 0 obj\n<< /Filter /FlateDecode /Length "
            + str(len(bad_stream)).encode("ascii")
            + b" >>\nstream\n"
            + bad_stream
            + b"\nendstream\nendobj\n%%EOF"
        )
        res_flate_bad = SgkAdapter(
            transport=_make_ok_transport(flate_pdf_bad, content_type="application/pdf")
        ).acquire_and_validate(sgk_req)
        self.assertFalse(res_flate_bad.ok)
        self.assertEqual(res_flate_bad.status, STATUS_REJECTED_CONTENT_MISMATCH)
        self.assertIn("SGK_CONTENT_MISMATCH", res_flate_bad.error_codes)

    def test_11_answer_traceability_registry_head_match_growth_and_forked_rejection(self) -> None:
        """PR #3 Finding 3: verify answer.registry_head_sha256 exact match, growth policy, post-dating, and fork rejection."""
        reg = EvidenceRegistry()
        rec1 = reg.register(
            MevzuatAdapter(
                transport=_make_ok_transport(b"<html><body>4857 Sayili Is Kanunu Madde 17 temel metni.</body></html>")
            ).acquire_and_validate(
                SourceDocumentRequest(
                    source_key="KANUN-4857-HEAD",
                    source_url="https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=4857&h=1",
                    title="4857 Sayılı İş Kanunu Madde 17",
                    publication_date="2025-01-01",
                    effective_date="2025-01-01",
                    adapter_metadata={"mevzuat_no": "4857", "mevzuat_turu": "KANUN"},
                )
            )
        )
        head_after_rec1 = reg.head_sha256

        builder = EvidenceBackedLegalAnswerBuilder(reg)
        ans1 = builder.build_answer(
            query="4857 m.17 bildirim süreleri nedir?",
            answer_text="4857 sayılı İş Kanunu m.17 uyarınca kıdeme göre bildirim süreleri uygulanır.",
            evidence_ids=[rec1.evidence_id],
            as_of_date="2026-06-01",
        )
        self.assertEqual(ans1.registry_head_sha256, head_after_rec1)

        # 1. Exact head match -> valid=True, EXACT_HEAD_MATCH, answer_bound_to_older_snapshot=False
        ok_exact, rep_exact = verify_answer_traceability(ans1, reg)
        self.assertTrue(ok_exact, rep_exact)
        self.assertEqual(rep_exact["registry_head_status"], HEAD_STATUS_EXACT_MATCH)
        self.assertFalse(rep_exact["answer_bound_to_older_snapshot"])
        self.assertTrue(rep_exact["full_content_archive_verified"])

        # 2. Registry grows (append rec2): default verify_answer_traceability() FAILS CLOSED!
        rec2 = reg.register(
            ResmiGazeteAdapter(
                transport=_make_ok_transport(
                    b"<html><body>Resmi Gazete Sayi 32766 - 2025 Asgari Ucret Karari metni.</body></html>"
                )
            ).acquire_and_validate(
                SourceDocumentRequest(
                    source_key="RG-32766-HEAD",
                    source_url="https://www.resmigazete.gov.tr/eskiler/2024/12/20241228-1.htm",
                    title="2025 Yılı Asgari Ücret Kararı",
                    publication_date="2024-12-28",
                    effective_date="2025-01-01",
                    adapter_metadata={"gazette_number": "32766"},
                )
            )
        )
        self.assertNotEqual(reg.head_sha256, head_after_rec1)

        ok_grew_strict, rep_grew_strict = verify_answer_traceability(ans1, reg)
        self.assertFalse(ok_grew_strict)
        self.assertEqual(rep_grew_strict["registry_head_status"], HEAD_STATUS_HISTORICAL_GREW)
        self.assertTrue(rep_grew_strict["answer_bound_to_older_snapshot"])
        self.assertTrue(any("REGISTRY_HEAD_MISMATCH_HISTORICAL_SNAPSHOT" in e for e in rep_grew_strict["errors"]))

        # 3. Explicit allow_registry_growth=True passes while transparently reporting older snapshot binding
        ok_grew_allowed, rep_grew_allowed = verify_answer_traceability(ans1, reg, allow_registry_growth=True)
        self.assertTrue(ok_grew_allowed, rep_grew_allowed)
        self.assertEqual(rep_grew_allowed["registry_head_status"], HEAD_STATUS_HISTORICAL_GREW)
        self.assertTrue(rep_grew_allowed["answer_bound_to_older_snapshot"])

        # 4. Post-dating attack: answer claiming older head_after_rec1 while citing rec2 (appended AFTER rec1) fails closed!
        ans2 = builder.build_answer(
            query="Asgari ücret kararı nedir?",
            answer_text="32766 sayılı Resmî Gazete kararı geçerlidir.",
            evidence_ids=[rec2.evidence_id],
            as_of_date="2026-06-01",
        )
        postdated_sha = _compute_answer_sha256(
            query=ans2.query,
            as_of_date=ans2.as_of_date,
            generated_at_utc=ans2.generated_at_utc,
            answer_text=ans2.answer_text,
            evidence_links=ans2.evidence_links,
            historical_disclosure_text=ans2.historical_disclosure_text,
            registry_head_sha256=head_after_rec1,
        )
        postdated_ans = replace(
            ans2,
            registry_head_sha256=head_after_rec1,
            answer_sha256=postdated_sha,
            answer_id=f"ANS-HUKUKSGK-{postdated_sha[:14].upper()}",
        )
        ok_postdated, rep_postdated = verify_answer_traceability(postdated_ans, reg, allow_registry_growth=True)
        self.assertFalse(ok_postdated)
        self.assertTrue(any("EVIDENCE_POSTDATES_ANSWER_REGISTRY_HEAD" in e for e in rep_postdated["errors"]))

        # 5. Unknown / forked registry_head_sha256 ALWAYS fails closed — even with allow_registry_growth=True!
        forged_head = "f" * 64
        forged_sha = _compute_answer_sha256(
            query=ans1.query,
            as_of_date=ans1.as_of_date,
            generated_at_utc=ans1.generated_at_utc,
            answer_text=ans1.answer_text,
            evidence_links=ans1.evidence_links,
            historical_disclosure_text=ans1.historical_disclosure_text,
            registry_head_sha256=forged_head,
        )
        forged_ans = replace(
            ans1,
            registry_head_sha256=forged_head,
            answer_sha256=forged_sha,
            answer_id=f"ANS-HUKUKSGK-{forged_sha[:14].upper()}",
        )
        for allow_growth in (False, True):
            ok_fork, rep_fork = verify_answer_traceability(forged_ans, reg, allow_registry_growth=allow_growth)
            self.assertFalse(ok_fork)
            self.assertEqual(rep_fork["registry_head_status"], HEAD_STATUS_UNKNOWN_OR_FORKED)
            self.assertFalse(rep_fork["answer_bound_to_older_snapshot"])
            self.assertTrue(any("REGISTRY_HEAD_UNKNOWN_OR_FORKED" in e for e in rep_fork["errors"]))

        # 6. Metadata-only registry fails default verify_answer_traceability(require_raw_content=True)
        meta_snap = reg.export_snapshot_dict(include_raw_content=False)
        meta_reg = EvidenceRegistry.from_snapshot_dict(meta_snap, require_raw_content=False)
        ok_meta_tr, rep_meta_tr = verify_answer_traceability(ans2, meta_reg)
        self.assertFalse(ok_meta_tr)
        self.assertFalse(rep_meta_tr["full_content_archive_verified"])


if __name__ == "__main__":
    unittest.main()
