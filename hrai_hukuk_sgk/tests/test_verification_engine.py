"""Unit and adversarial test suite for CALISORA @HukukSGK v1.0.2c.6 (Safe Snapshot Path & Symlink Containment, Mandatory External Trust Anchor, Spec-Exact RFC 8785 JCS, Source Content Verification, Asymmetric Digital Signatures, Approver Identity & Revocation Governance, Two-Stage Verification, m.26 Calendar Integrity, m.109 Law No. 7555 m.23 & Historical Basis Hardening)."""

from __future__ import annotations

import base64
import copy
from dataclasses import replace
from datetime import date, timedelta
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest

from engine.attestation_verifier import (
    GENESIS_PREV_HASH,
    PARSER_VERSION,
    SIGNATURE_5070_NON_EQUIVALENCE_NOTICE,
    append_ledger_entry,
    build_calendar_attestation_signing_payload,
    canonical_json_bytes,
    compute_public_key_fingerprint,
    create_ledger_checkpoint,
    create_revised_snapshot_entry,
    generate_ephemeral_keypair,
    parse_turkish_religious_holidays_from_source,
    resolve_safe_project_path,
    sign_canonical_payload,
    validate_authorized_approver_for_attestation,
    verify_asymmetric_signature,
    verify_attestation_ledger,
    verify_holiday_source_snapshot,
    verify_signed_calendar_attestation,
)
from engine.document_integrity import compute_sha256, verify_archived_holiday_snapshots, verify_official_document
from engine.knowledge_card_validator import (
    load_central_audit_index,
    load_knowledge_cards,
    query_knowledge_cards,
    validate_central_audit_log,
    validate_knowledge_card_file,
)
from engine.legal_reasoning import (
    OFFICIAL_HOLIDAY_CALENDAR_DOMAINS,
    TURKISH_RELIGIOUS_FULL_HOLIDAYS,
    TURKISH_RELIGIOUS_HALF_DAY_EVES,
    TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA,
    _business_days_between,
    add_turkish_working_days,
    evaluate_hr_legal_scenario,
    evaluate_m26_forfeiture_deadlines,
    get_holiday_calendar_coverage_info,
    get_turkish_half_day_eves,
    get_turkish_ubgt_calendar_report,
    get_turkish_ubgt_holidays,
    validate_external_yearly_holiday_calendar,
)
from engine.models import (
    ALL_CONFLICT_EVALUATION_LAYERS,
    JUDICIAL_INTERPRETATION_LAYERS,
    NORM_LAYER_PRIORITY,
    VALID_SCENARIO_TYPES,
    AmendmentRecord,
    NormReference,
    PrecedentRecord,
)
from engine.norm_hierarchy import evaluate_precedent_application, resolve_norm_conflict
from engine.precedent_verifier import (
    load_precedent_registry,
    validate_precedent_registry,
    verify_response_citations,
)
from engine.source_validator import (
    is_specific_official_url,
    load_source_registry,
    resolve_effective_article,
    resolve_effective_sources,
    validate_source_registry,
)
from engine.tools_router import HukukSGKToolRouter

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOURCES_PATH = PROJECT_ROOT / "config" / "legal_sources_registry.json"
PRECEDENTS_PATH = PROJECT_ROOT / "config" / "yargitay_precedents.json"
AUDIT_LOG_PATH = PROJECT_ROOT / "config" / "verification_audit_log.json"
APPROVERS_PATH = PROJECT_ROOT / "config" / "authorized_approvers.json"
LEDGER_PATH = PROJECT_ROOT / "config" / "calendar_attestation_ledger.json"
TAXONOMY_PATH = PROJECT_ROOT / "config" / "knowledge_taxonomy.json"
TOOLS_SCHEMA_PATH = PROJECT_ROOT / "agent" / "tool_schemas.json"
SOURCE_SCHEMA_PATH = PROJECT_ROOT / "schemas" / "legal_source_registry.schema.json"
PRECEDENT_SCHEMA_PATH = PROJECT_ROOT / "schemas" / "yargitay_precedent_registry.schema.json"
CARD_SCHEMA_PATH = PROJECT_ROOT / "schemas" / "legal_knowledge_card.schema.json"
SCENARIO_SCHEMA_PATH = PROJECT_ROOT / "schemas" / "legal_scenario_evaluation.schema.json"
APPROVERS_SCHEMA_PATH = PROJECT_ROOT / "schemas" / "authorized_approvers.schema.json"
LEDGER_SCHEMA_PATH = PROJECT_ROOT / "schemas" / "calendar_attestation_ledger.schema.json"
KB_LAWS_DIR = PROJECT_ROOT / "rag_kb" / "01_kanunlar"
KB_REGULATIONS_DIR = PROJECT_ROOT / "rag_kb" / "02_yonetmelikler"
KB_CIRCULARS_DIR = PROJECT_ROOT / "rag_kb" / "03_teblig_ve_genelgeler"
KB_ALL_DIR = PROJECT_ROOT / "rag_kb"

_TR_MONTHS_UPPER = {
    1: "OCAK",
    2: "ŞUBAT",
    3: "MART",
    4: "NİSAN",
    5: "MAYIS",
    6: "HAZİRAN",
    7: "TEMMUZ",
    8: "AĞUSTOS",
    9: "EYLÜL",
    10: "EKİM",
    11: "KASIM",
    12: "ARALIK",
}

_EPHEMERAL_KEYS_CACHE: dict[str, tuple[str, str]] = {}
_EPHEMERAL_KEYS_LOCK = threading.Lock()


def _get_ephemeral_keypair(slot: str, algorithm: str = "ED25519") -> tuple[str, str]:
    """Generate ephemeral keypairs strictly in memory for test execution (NEVER written to disk/repo)."""
    cache_key = f"{slot}:{algorithm}"
    with _EPHEMERAL_KEYS_LOCK:
        if cache_key not in _EPHEMERAL_KEYS_CACHE:
            _EPHEMERAL_KEYS_CACHE[cache_key] = generate_ephemeral_keypair(algorithm)
        return _EPHEMERAL_KEYS_CACHE[cache_key]


def _build_diyanet_html_for_record(rec: dict[str, object]) -> str:
    """Build a Diyanet-format HTML table for a yearly holiday record (including non-holiday distractors)."""
    ram_arife = date.fromisoformat(str(rec["ramazan_arife_date"]))
    ram_s = date.fromisoformat(str(rec["ramazan_start_date"]))
    kurb_arife = date.fromisoformat(str(rec["kurban_arife_date"]))
    kurb_s = date.fromisoformat(str(rec["kurban_start_date"]))

    def _row(h_day: str, h_month: str, h_year: str, dt: date, label: str) -> str:
        my = f"{_TR_MONTHS_UPPER[dt.month]}-{dt.year}"
        return f"<tr><td>{h_day}</td><td>{h_month}</td><td>{h_year}</td><td>{dt.day:02d}</td><td>{my}</td><td>GÜN</td><td>{label}</td></tr>"

    ram_start_month_dt = ram_s - timedelta(days=30)
    kadir_dt = ram_s - timedelta(days=4)
    rows = [
        _row("01", "RAMAZAN", "1449", ram_start_month_dt, "RAMAZAN BAŞLANGICI"),
        _row("27", "RAMAZAN", "1449", kadir_dt, "KADİR GECESİ"),
        _row("29", "RAMAZAN", "1449", ram_arife, "AREFE"),
        _row("01", "ŞEVVAL", "1449", ram_s, "RAMAZAN BAYRAMI (1.Gün)"),
        _row("02", "ŞEVVAL", "1449", ram_s + timedelta(days=1), "RAMAZAN BAYRAMI (2.Gün)"),
        _row("03", "ŞEVVAL", "1449", ram_s + timedelta(days=2), "RAMAZAN BAYRAMI (3.Gün)"),
        _row("09", "ZİLHİCCE", "1449", kurb_arife, "AREFE"),
        _row("10", "ZİLHİCCE", "1449", kurb_s, "KURBAN BAYRAMI (1.Gün)"),
        _row("11", "ZİLHİCCE", "1449", kurb_s + timedelta(days=1), "KURBAN BAYRAMI (2.Gün)"),
        _row("12", "ZİLHİCCE", "1449", kurb_s + timedelta(days=2), "KURBAN BAYRAMI (3.Gün)"),
        _row("13", "ZİLHİCCE", "1449", kurb_s + timedelta(days=3), "KURBAN BAYRAMI (4.Gün)"),
    ]
    return f"<!doctype html><html><body><table>{''.join(rows)}</table></body></html>"


def _build_signed_external_calendar_bundle(
    records_by_year: dict[str, dict[str, object]],
    *,
    counsel_algorithm: str = "ED25519",
    sealer_algorithm: str = "RSA-PSS-SHA256",
    approver_id: str = "CALISORA-HUKUK-01",
    key_trust_tier: str = "PRODUCTION_QUALIFIED_COUNSEL",
    environment_restrictions: list[str] | None = None,
    authorized_scopes: list[str] | None = None,
    valid_from_utc: str = "2026-01-01T00:00:00Z",
    valid_until_utc: str = "2030-12-31T23:59:59Z",
    revoked_at_utc: str | None = None,
    revocation_reason: str = "NONE",
    approver_status: str = "ACTIVE",
    approved_at_utc: str = "2027-12-15T10:00:00Z",
    checkpoint_created_at_utc: str = "2027-12-15T12:00:00Z",
    timestamp_trust_level: str = "SELF_ASSERTED_UNTRUSTED",
    sealer_trust_tier: str = "PRODUCTION_AUDIT_SEALER",
    sealer_environments: list[str] | None = None,
) -> tuple[dict[str, dict[str, object]], dict[str, object], dict[str, object], dict[str, str]]:
    """Build an in-memory cryptographically attested external calendar bundle with ephemeral keys and signed ledger."""
    c_priv, c_pub = _get_ephemeral_keypair(f"counsel_{counsel_algorithm}", counsel_algorithm)
    s_priv, s_pub = _get_ephemeral_keypair(f"sealer_{sealer_algorithm}", sealer_algorithm)
    c_fp = compute_public_key_fingerprint(c_pub)
    s_fp = compute_public_key_fingerprint(s_pub)

    approvers_registry: dict[str, object] = {
        "schema_version": "1.0.2c.5",
        "description": "Test ephemeral in-memory approvers registry",
        "signature_legal_notice": SIGNATURE_5070_NON_EQUIVALENCE_NOTICE,
        "key_management_policy": "EXTERNAL_KMS_HSM_REQUIRED_NO_PRIVATE_KEYS_IN_REPO",
        "test_sandbox_keys_allowed_in_production": False,
        "approvers": {
            approver_id: {
                "approver_id": approver_id,
                "display_name": f"Test Counsel ({approver_id})",
                "role": "EXTERNAL_LEGAL_COUNSEL",
                "status": approver_status,
                "enrollment_status": "ENROLLED_EPHEMERAL_TEST",
                "key_trust_tier": key_trust_tier,
                "key_management_mode": "EXTERNAL_KMS_HSM_REQUIRED",
                "key_id": f"KEY-{approver_id}-{counsel_algorithm}",
                "key_version": "v1",
                "key_algorithm": counsel_algorithm,
                "public_key_pem": c_pub,
                "public_key_fingerprint_sha256": c_fp,
                "valid_from_utc": valid_from_utc,
                "valid_until_utc": valid_until_utc,
                "revoked_at_utc": revoked_at_utc,
                "revocation_reason": revocation_reason,
                "authorized_scopes": authorized_scopes or ["HOLIDAY_CALENDAR_LEGAL_APPROVAL:2024-2030"],
                "environment_restrictions": environment_restrictions or ["PRODUCTION", "STAGING"],
                "qualified_e_signature_5070_equivalent": False,
            },
            "CALISORA-LEDGER-SEALER-01": {
                "approver_id": "CALISORA-LEDGER-SEALER-01",
                "display_name": "Test Audit Sealer",
                "role": "AUDIT_LEDGER_CHECKPOINT_SIGNER",
                "status": "ACTIVE",
                "enrollment_status": "ENROLLED_EPHEMERAL_TEST",
                "key_trust_tier": sealer_trust_tier,
                "key_management_mode": "EXTERNAL_KMS_HSM_REQUIRED",
                "key_id": f"KEY-SEALER-{sealer_algorithm}",
                "key_version": "v1",
                "key_algorithm": sealer_algorithm,
                "public_key_pem": s_pub,
                "public_key_fingerprint_sha256": s_fp,
                "valid_from_utc": "2026-01-01T00:00:00Z",
                "valid_until_utc": "2030-12-31T23:59:59Z",
                "revoked_at_utc": None,
                "revocation_reason": "NONE",
                "authorized_scopes": ["AUDIT_CHECKPOINT_SEAL"],
                "environment_restrictions": sealer_environments or ["PRODUCTION", "STAGING", "TEST_SANDBOX_ONLY"],
                "qualified_e_signature_5070_equivalent": False,
            },
        },
    }

    ledger: dict[str, object] = {
        "schema_version": "1.0.2c.5",
        "ledger_id": "TEST-ATTESTATION-LEDGER",
        "description": "In-memory test attestation ledger",
        "hash_algorithm": "SHA-256",
        "canonicalization_standard": "RFC-8785-JCS",
        "worm_storage_policy": "WORM_AND_INDEPENDENT_TSA_REQUIRED_FOR_PRODUCTION",
        "external_legal_counsel_signoff_status": "PENDING_SIGNED_EXTERNAL_ATTESTATION",
        "entries": [],
        "checkpoints": [],
    }

    signed_calendars: dict[str, dict[str, object]] = {}
    for yr_key, base_rec in sorted(records_by_year.items()):
        yr = int(yr_key)
        rec = copy.deepcopy(base_rec)
        rec["verified_by"] = approver_id
        html_doc = _build_diyanet_html_for_record(rec)
        doc_sha = compute_sha256(html_doc.encode("utf-8"))
        rec_id = f"CAL-REC-{yr}-V1"
        nonce = f"NONCE-{yr}-{counsel_algorithm}-0001"
        tech_entry_id = f"LED-TECH-{yr}-V1"
        att_entry_id = f"LED-LEGAL-{yr}-V1"

        rec["record_id"] = rec_id
        rec["snapshot_id"] = f"SNAP-DIYANET-{yr}-V1"
        rec["snapshot_version"] = "v1"
        rec["source_document_content"] = html_doc
        rec["source_document_sha256"] = doc_sha
        rec["source_content_type"] = "text/html"
        rec["extraction_method"] = "NATIVE_HTML_TABLE"

        append_ledger_entry(
            ledger,
            entry_id=tech_entry_id,
            entry_type="TECHNICAL_SOURCE_VERIFICATION",
            recorded_at_utc=approved_at_utc,
            payload={
                "year": yr,
                "snapshot_id": rec["snapshot_id"],
                "source_document_sha256": doc_sha,
                "parser_version": PARSER_VERSION,
                "technical_verification_status": "TECHNICAL_VERIFIED",
            },
        )

        key_id = f"KEY-{approver_id}-{counsel_algorithm}"
        signing_payload = build_calendar_attestation_signing_payload(
            record_id=rec_id,
            nonce=nonce,
            year=yr,
            calendar_record=rec,
            source_document_sha256=doc_sha,
            approver_id=approver_id,
            approved_at_utc=approved_at_utc,
            key_id=key_id,
            key_version="v1",
            algorithm=counsel_algorithm,
        )
        sig_b64 = sign_canonical_payload(signing_payload, c_priv, algorithm=counsel_algorithm)
        rec["legal_attestation"] = {
            "record_id": rec_id,
            "nonce": nonce,
            "year": yr,
            "approver_id": approver_id,
            "approved_at_utc": approved_at_utc,
            "algorithm": counsel_algorithm,
            "key_id": key_id,
            "key_version": "v1",
            "public_key_fingerprint_sha256": c_fp,
            "signature_b64": sig_b64,
            "ledger_entry_id": att_entry_id,
            "timestamp_trust_level": timestamp_trust_level,
            "qualified_e_signature_5070_equivalent": False,
        }
        append_ledger_entry(
            ledger,
            entry_id=att_entry_id,
            entry_type="LEGAL_COUNSEL_ATTESTATION",
            recorded_at_utc=approved_at_utc,
            payload={
                "record_id": rec_id,
                "nonce": nonce,
                "year": yr,
                "approver_id": approver_id,
                "approved_at_utc": approved_at_utc,
                "source_document_sha256": doc_sha,
                "signature_b64": sig_b64,
                "algorithm": counsel_algorithm,
                "key_id": key_id,
                "key_version": "v1",
            },
        )
        signed_calendars[str(yr)] = rec

    create_ledger_checkpoint(
        ledger,
        checkpoint_id="CHK-TEST-BUNDLE-001",
        checkpoint_scope="TEST_BUNDLE_SEAL",
        created_at_utc=checkpoint_created_at_utc,
        nonce=f"CHK-NONCE-TEST-{sealer_algorithm}-001",
        signer_approver_id="CALISORA-LEDGER-SEALER-01",
        private_key_pem=s_priv,
        key_id=f"KEY-SEALER-{sealer_algorithm}",
        key_version="v1",
        algorithm=sealer_algorithm,
        public_key_pem=s_pub,
        external_tsa_token_status="VERIFIED_EXTERNAL_TSA",
    )

    keys = {
        "counsel_priv": c_priv,
        "counsel_pub": c_pub,
        "sealer_priv": s_priv,
        "sealer_pub": s_pub,
    }
    return signed_calendars, approvers_registry, ledger, keys


class TestSeedRegistriesSchemasAndTaxonomy(unittest.TestCase):
    def test_all_json_artifacts_parse_cleanly(self) -> None:
        for path in (
            SOURCES_PATH,
            PRECEDENTS_PATH,
            AUDIT_LOG_PATH,
            TAXONOMY_PATH,
            TOOLS_SCHEMA_PATH,
            SOURCE_SCHEMA_PATH,
            PRECEDENT_SCHEMA_PATH,
            CARD_SCHEMA_PATH,
            SCENARIO_SCHEMA_PATH,
        ):
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertIsInstance(data, dict, f"{path.name} geçerli JSON nesnesi olmalıdır.")

    def test_seed_legal_sources_registry_is_strictly_valid(self) -> None:
        raw = json.loads(SOURCES_PATH.read_text(encoding="utf-8"))
        report = validate_source_registry(raw)
        self.assertTrue(report.valid, f"Beklenmeyen doğrulama hataları: {report.flags}")
        self.assertEqual(report.total_records, 30)
        self.assertEqual(report.verified_count, 28)
        self.assertEqual(report.blocker_count, 0)
        self.assertEqual(raw["sources"]["GIB-TEBLIG-332-20251231"]["verification_status"], "PENDING_REVIEW")
        self.assertEqual(raw["sources"]["RG-9368-20241228"]["verification_status"], "SUPERSEDED")
        m4857_amends = {a["amending_law_no"] for a in raw["sources"]["MEVZUAT-4857"]["amendment_history"]}
        self.assertTrue({"6552", "6645", "7036"}.issubset(m4857_amends))

    def test_seed_yargitay_precedents_registry_is_strictly_valid(self) -> None:
        sources = load_source_registry(SOURCES_PATH, strict=True)
        raw_prec = json.loads(PRECEDENTS_PATH.read_text(encoding="utf-8"))
        report = validate_precedent_registry(raw_prec, source_registry=sources)
        self.assertTrue(report.valid, f"Beklenmeyen içtihat doğrulama hataları: {report.flags}")
        self.assertEqual(report.total_records, 5)
        self.assertEqual(report.verified_count, 4)
        self.assertEqual(report.blocker_count, 0)
        self.assertEqual(raw_prec["precedents"]["YIBBGK-2021-8-2026-1"]["verification_status"], "PENDING_REVIEW")

    def test_taxonomy_separates_l6_cba_contracts_from_verification_infrastructure(self) -> None:
        tax = json.loads(TAXONOMY_PATH.read_text(encoding="utf-8"))
        layers = tax["knowledge_layers"]
        self.assertEqual(len(layers), 6)
        self.assertEqual(layers[5]["id"], "L6_CBA_CONTRACTS_AND_WORKPLACE_PRACTICES")
        self.assertIn("verification_infrastructure", tax)
        self.assertEqual(
            tax["verification_infrastructure"]["registries"]["legal_sources_registry"],
            "config/legal_sources_registry.json",
        )
        self.assertTrue(
            tax["verification_infrastructure"]["strict_rules"].get(
                "require_statutory_subordination_for_secondary_legislation"
            )
        )
        card_schema = json.loads(CARD_SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertIn("statutory_subordination", card_schema["$defs"]["knowledgeCard"]["properties"])

    def test_audit_log_covers_all_74_records_including_39_knowledge_cards(self) -> None:
        log = json.loads(AUDIT_LOG_PATH.read_text(encoding="utf-8"))
        self.assertEqual(log["summary"]["total_audited_records"], 74)
        self.assertEqual(log["summary"]["legal_sources_count"], 30)
        self.assertEqual(log["summary"]["verified_legal_sources_count"], 28)
        self.assertEqual(log["summary"]["pending_legal_sources_count"], 1)
        self.assertEqual(log["summary"]["superseded_legal_sources_count"], 1)
        self.assertEqual(log["summary"]["yargitay_precedents_count"], 5)
        self.assertEqual(log["summary"]["verified_yargitay_precedents_count"], 4)
        self.assertEqual(log["summary"]["pending_yargitay_precedents_count"], 1)
        self.assertEqual(log["summary"]["knowledge_cards_count"], 39)
        self.assertEqual(log["summary"]["verified_knowledge_cards_count"], 38)
        self.assertEqual(log["summary"]["pending_knowledge_cards_count"], 1)
        self.assertEqual(log["summary"]["l1_law_cards_count"], 25)
        self.assertEqual(log["summary"]["l2_regulation_cards_count"], 7)
        self.assertEqual(log["summary"]["l3_circular_communique_cards_count"], 7)
        self.assertEqual(log["summary"]["fully_verified_records_count"], 70)
        self.assertEqual(log["summary"]["pending_verification_records_count"], 3)
        self.assertEqual(log["summary"]["superseded_records_count"], 1)
        self.assertEqual(len(log["entries"]), 74)
        self.assertEqual(log["summary"]["fetched_and_matched_documents_count"], 33)
        self.assertEqual(log["summary"]["pending_ocr_or_live_text_count"], 2)
        self.assertEqual(
            set(log["summary"]["pending_full_text_verification_records"]),
            {"GIB-TEBLIG-332-20251231", "YIBBGK-2021-8-2026-1", "CARD-GIB-332-2026-TARIFE"},
        )
        self.assertEqual(log["external_legal_counsel_signoff_status"], "PENDING_SIGNED_EXTERNAL_ATTESTATION")
        self.assertIn("document_integrity", log["live_document_verification_scope"])


class TestOfficialUrlAndDocumentIntegrity(unittest.TestCase):
    def test_accepts_specific_official_urls(self) -> None:
        valid_urls = [
            "https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=4857&MevzuatTur=1&MevzuatTertip=5",
            "https://www.resmigazete.gov.tr/eskiler/2025/12/20251219-1.htm",
            "https://www.resmigazete.gov.tr/eskiler/2019/05/20190509-6.pdf",
            "https://cdn.gib.gov.tr/api/gibportal-file/file/getFile?objectKey=MEVZUAT_TEBLIGLER/UNIVERSAL/2025/193_Teblig332.pdf",
            "https://mevzuat.adalet.gov.tr/mevzuat/110489",
            "https://www.gib.gov.tr/mevzuat/kanun/651",
        ]
        for url in valid_urls:
            ok, reason = is_specific_official_url(url)
            self.assertTrue(ok, f"Geçerli URL reddedildi ({url}): {reason}")

    def test_rejects_bare_homepages_http_and_unofficial_domains(self) -> None:
        invalid_urls = [
            "https://www.resmigazete.gov.tr/",
            "https://www.resmigazete.gov.tr/eskiler/2025/12/",
            "https://www.gib.gov.tr/mevzuat",
            "https://www.mevzuat.gov.tr/mevzuat",
            "https://karararama.yargitay.gov.tr/",
            "http://www.mevzuat.gov.tr/mevzuat?MevzuatNo=4857&MevzuatTur=1&MevzuatTertip=5",
            "https://www.lexpera.com.tr/mevzuat/kanunlar/is-kanunu-4857",
            "https://example.com/4857-kanun.pdf",
            "https://cdn.gib.gov.tr/api/gibportal-file/file/getFile",
        ]
        for url in invalid_urls:
            ok, _ = is_specific_official_url(url)
            self.assertFalse(ok, f"Geçersiz/ana sayfa URL kabul edildi: {url}")

    def test_document_integrity_follows_mevzuat_wrapper_and_verifies_markers_and_sha(self) -> None:
        wrapper_html = b'<html><body><iframe src="MevzuatMetin/1.5.4857.pdf"></iframe></body></html>'
        doc_bytes = "4857 SAYILI İŞ KANUNU — Madde 19 Fesih bildirimi ve savunma".encode("utf-8")
        expected_sha = compute_sha256(doc_bytes)

        def fake_fetcher(url: str, timeout: int) -> tuple[int, str, bytes]:
            if "MevzuatMetin/1.5.4857.pdf" in url:
                return 200, "text/plain; charset=utf-8", doc_bytes
            return 200, "text/html; charset=utf-8", wrapper_html

        res = verify_official_document(
            "https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=4857&MevzuatTur=1&MevzuatTertip=5",
            expected_markers=["4857", "İŞ KANUNU", "Madde 19"],
            fetcher=fake_fetcher,
            expected_sha256=expected_sha,
        )
        self.assertTrue(res.ok, res.error)
        self.assertEqual(res.resolved_document_url, "https://www.mevzuat.gov.tr/MevzuatMetin/1.5.4857.pdf")
        self.assertEqual(res.content_sha256, expected_sha)

    def test_document_integrity_fails_when_url_opens_wrong_legal_text_or_404(self) -> None:
        def wrong_doc_fetcher(url: str, timeout: int) -> tuple[int, str, bytes]:
            return 200, "text/html; charset=utf-8", "<html><body>İlgisiz duyuru sayfası</body></html>".encode("utf-8")

        res_wrong = verify_official_document(
            "https://www.resmigazete.gov.tr/eskiler/2025/12/20251219-1.htm",
            expected_markers=["7566", "5510", "MADDE 24"],
            fetcher=wrong_doc_fetcher,
        )
        self.assertFalse(res_wrong.ok)
        self.assertEqual(set(res_wrong.missing_markers), {"7566", "5510", "MADDE 24"})

        def not_found_fetcher(url: str, timeout: int) -> tuple[int, str, bytes]:
            return 404, "text/html", b"Not Found"

        res_404 = verify_official_document(
            "https://www.resmigazete.gov.tr/eskiler/2025/12/20251219-1.htm",
            expected_markers=["7566"],
            fetcher=not_found_fetcher,
        )
        self.assertFalse(res_404.ok)
        self.assertEqual(res_404.http_status, 404)


class TestRegistryAdversarialValidation(unittest.TestCase):
    def setUp(self) -> None:
        self.raw_sources = json.loads(SOURCES_PATH.read_text(encoding="utf-8"))
        self.raw_precedents = json.loads(PRECEDENTS_PATH.read_text(encoding="utf-8"))
        self.sources = load_source_registry(SOURCES_PATH, strict=True)

    def test_source_validator_rejects_bare_url_llm_verifier_and_priority_mismatch(self) -> None:
        mutated = copy.deepcopy(self.raw_sources)
        rec = mutated["sources"]["MEVZUAT-4857"]
        rec["source_url"] = "https://www.resmigazete.gov.tr/"
        rec["verified_by"] = "LLM"
        rec["norm_priority"] = 5
        rec["effective_from"] = "2030-01-01"
        rec["effective_to"] = "2020-01-01"

        report = validate_source_registry(mutated)
        self.assertFalse(report.valid)
        codes = {f.code for f in report.flags}
        self.assertIn("INVALID_SOURCE_URL", codes)
        self.assertIn("MISSING_OR_INVALID_VERIFIER", codes)
        self.assertIn("NORM_LAYER_PRIORITY_MISMATCH", codes)
        self.assertIn("INVALID_EFFECTIVE_DATE_RANGE", codes)

    def test_source_validator_enforces_audit_trail_and_original_consolidated_separation(self) -> None:
        mutated = copy.deepcopy(self.raw_sources)
        rec = mutated["sources"]["MEVZUAT-4857"]
        rec["verification_audit"]["audit_log_id"] = "BAD-ID"
        rec["verification_audit"]["retrieved_content_sha256"] = None
        rec["verification_audit"]["retrieved_http_status"] = 500
        rec["original_publication"] = None
        rec["consolidated_text"] = None

        report = validate_source_registry(mutated)
        self.assertFalse(report.valid)
        codes = {f.code for f in report.flags}
        self.assertIn("INVALID_AUDIT_LOG_ID", codes)
        self.assertIn("INCONSISTENT_FETCH_HTTP_STATUS", codes)
        self.assertIn("MISSING_DOCUMENT_SHA256", codes)
        self.assertIn("MISSING_ORIGINAL_PUBLICATION_SEPARATION", codes)
        self.assertIn("MISSING_CONSOLIDATED_TEXT_SEPARATION", codes)

    def test_source_validator_rejects_broken_superseded_by(self) -> None:
        mutated = copy.deepcopy(self.raw_sources)
        mutated["sources"]["RG-9368-20241228"]["superseded_by"] = "NON-EXISTENT-ID"
        report = validate_source_registry(mutated)
        self.assertFalse(report.valid)
        self.assertIn("BROKEN_SUPERSEDED_BY_REFERENCE", {f.code for f in report.flags})

    def test_precedent_validator_enforces_yibbgk_gazette_holding_scope_and_cross_refs(self) -> None:
        mutated = copy.deepcopy(self.raw_precedents)
        rec = mutated["precedents"]["YIBBGK-2017-9-2018-10"]
        rec["official_gazette_no"] = None
        rec["official_gazette_date"] = None
        rec["binding_level"] = "CHAMBER_SETTLED"
        rec["esas_no"] = "E-2017-9"
        rec["related_source_ids"] = ["MEVZUAT-99999"]
        rec["operative_holding"]["verified_against_gazette"] = False
        rec["scope_limitations_detail"]["does_not_apply_to"] = []
        rec["full_text_verification"]["retrieved_content_sha256"] = None

        report = validate_precedent_registry(mutated, source_registry=self.sources)
        self.assertFalse(report.valid)
        codes = {f.code for f in report.flags}
        self.assertIn("YIBBGK_MISSING_OFFICIAL_GAZETTE", codes)
        self.assertIn("YIBBGK_BINDING_MISMATCH", codes)
        self.assertIn("INVALID_ESAS_FORMAT", codes)
        self.assertIn("BROKEN_RELATED_SOURCE_ID", codes)
        self.assertIn("UNVERIFIED_OPERATIVE_HOLDING", codes)
        self.assertIn("MISSING_SCOPE_LIMITATIONS_DETAIL", codes)
        self.assertIn("INCOMPLETE_FULL_TEXT_INTEGRITY", codes)

    def test_temporal_resolution_filters_superseded_cbk_in_2026(self) -> None:
        res_2026 = resolve_effective_sources(self.sources, as_of_date="2026-03-15", include_superseded=True)
        eff_ids = {r.source_id for r in res_2026["effective_sources"]}
        inact_ids = {r.source_id for r in res_2026["inactive_or_superseded_sources"]}
        self.assertIn("RG-10766-20251225", eff_ids)
        self.assertNotIn("RG-9368-20241228", eff_ids)
        self.assertIn("RG-9368-20241228", inact_ids)

    def test_article_level_effective_date_tracking(self) -> None:
        law_7036 = self.sources["MEVZUAT-7036"]
        before = resolve_effective_article(law_7036, "Madde 3", "2017-11-15")
        after = resolve_effective_article(law_7036, "Madde 3", "2018-01-01")
        self.assertFalse(before["is_effective"])
        self.assertEqual(before["granularity"], "ARTICLE_LEVEL_RULE")
        self.assertTrue(after["is_effective"])


class TestCitationAuditor(unittest.TestCase):
    def setUp(self) -> None:
        self.sources = load_source_registry(SOURCES_PATH, strict=True)
        self.precedents = load_precedent_registry(PRECEDENTS_PATH, source_registry=self.sources, strict=True)

    def test_accepts_verified_statutes_yibbgk_and_specific_urls(self) -> None:
        draft = (
            "4857 Sayılı İş Kanunu m.25/I-b kapsamında sağlık raporuna dayalı derhal fesihte "
            "Yargıtay İçtihadı Birleştirme Genel Kurulu (E. 2017/9, K. 2018/10) gereğince "
            "önceden savunma alınması zorunlu değildir. Resmî kaynak: "
            "https://www.resmigazete.gov.tr/eskiler/2019/05/20190509-6.pdf"
        )
        audit = verify_response_citations(
            draft_text=draft,
            as_of_date="2026-05-01",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            cited_source_ids=["MEVZUAT-4857"],
            cited_precedent_ids=["YIBBGK-2017-9-2018-10"],
        )
        self.assertTrue(audit.passed, f"Doğru yanıt reddedildi: {audit.flags}")
        self.assertFalse(audit.requires_counsel_escalation)
        self.assertIn("MEVZUAT-4857", audit.matched_source_ids)
        self.assertIn("YIBBGK-2017-9-2018-10", audit.matched_precedent_ids)

    def test_blocks_article_not_yet_effective_on_event_date(self) -> None:
        # 7036 law published 2017-10-25, but Madde 3 took effect 2018-01-01!
        audit_7036 = verify_response_citations(
            draft_text="7036 Sayılı İş Mahkemeleri Kanunu m.3 uyarınca dava şartı arabuluculuk zorunludur.",
            as_of_date="2017-11-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
        )
        self.assertFalse(audit_7036.passed)
        self.assertIn("ARTICLE_NOT_EFFECTIVE_ON_DATE", audit_7036.blocker_codes)

        # 6698 Madde 6 7499 amendment took effect 2024-06-01
        audit_6698 = verify_response_citations(
            draft_text="6698 m.6 uyarınca 7499 değişikliği kapsamında işleme yapılır.",
            as_of_date="2024-04-10",
            source_registry=self.sources,
            precedent_registry=self.precedents,
        )
        self.assertFalse(audit_6698.passed)
        self.assertIn("ARTICLE_NOT_EFFECTIVE_ON_DATE", audit_6698.blocker_codes)

    def test_blocks_fabricated_yargitay_esas_karar_in_both_formats(self) -> None:
        draft = (
            "Yargıtay 9. Hukuk Dairesi E. 2023/1234, K. 2024/5678 sayılı kararı ile "
            "2022/4500 E., 2023/8900 K. kararına göre fazla çalışma ücreti ödenmelidir."
        )
        audit = verify_response_citations(
            draft_text=draft,
            as_of_date="2026-05-01",
            source_registry=self.sources,
            precedent_registry=self.precedents,
        )
        self.assertFalse(audit.passed)
        self.assertEqual(audit.blocker_codes.count("FABRICATED_PRECEDENT"), 2)

    def test_blocks_expired_9368_cbk_cited_as_active_in_2026(self) -> None:
        draft = (
            "2026 yılı teknokent uzaktan çalışma oranları 9368 Sayılı Cumhurbaşkanı Kararı "
            "uyarınca bilişim personeli için %100 olarak uygulanmaktadır."
        )
        audit = verify_response_citations(
            draft_text=draft,
            as_of_date="2026-03-10",
            source_registry=self.sources,
            precedent_registry=self.precedents,
        )
        self.assertFalse(audit.passed)
        self.assertIn("EXPIRED_OR_REPEALED_STATUTE", audit.blocker_codes)

    def test_allows_historical_disclosure_of_9368_when_paired_with_active_10766(self) -> None:
        draft = (
            "2026 yılında yürürlükte olan 10766 Sayılı Cumhurbaşkanı Kararı "
            "(2025 yılına ait mülga 9368 Sayılı Cumhurbaşkanı Kararı yerine) uygulanır."
        )
        audit = verify_response_citations(
            draft_text=draft,
            as_of_date="2026-03-10",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            cited_source_ids=["RG-10766-20251225"],
        )
        self.assertTrue(audit.passed, f"Tarihsel açıklama yanlışlıkla bloke edildi: {audit.flags}")
        self.assertIn("RG-10766-20251225", audit.matched_source_ids)
        self.assertIn("HISTORICAL_STATUTE_REFERENCE", {f.code for f in audit.flags})

    def test_blocks_expired_source_in_structured_cited_source_ids(self) -> None:
        audit = verify_response_citations(
            draft_text="10766 Sayılı Cumhurbaşkanı Kararı uygulanır.",
            as_of_date="2026-03-10",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            cited_source_ids=["RG-9368-20241228"],
        )
        self.assertFalse(audit.passed)
        self.assertIn("EXPIRED_OR_REPEALED_STATUTE", audit.blocker_codes)

    def test_blocks_fabricated_statute_and_bare_homepage_url(self) -> None:
        draft = (
            "9999 Sayılı İş Güvenliği Kanunu ve 999 Seri No.lu Gelir Vergisi Genel Tebliği gereğince "
            "detaylar https://www.resmigazete.gov.tr/ adresindedir."
        )
        audit = verify_response_citations(
            draft_text=draft,
            as_of_date="2026-03-10",
            source_registry=self.sources,
            precedent_registry=self.precedents,
        )
        self.assertFalse(audit.passed)
        self.assertIn("FABRICATED_STATUTE", audit.blocker_codes)
        self.assertIn("INVALID_SOURCE_URL", audit.blocker_codes)

    def test_blocks_superseded_unverified_and_conflicting_precedents(self) -> None:
        custom_precedents = dict(self.precedents)
        custom_precedents["TEST-SUPERSEDED"] = PrecedentRecord(
            precedent_id="TEST-SUPERSEDED",
            chamber="9_HD",
            binding_level="CHAMBER_SETTLED",
            esas_no="2015/100",
            karar_no="2016/200",
            decision_date="2016-02-01",
            official_source_url="https://karararama.yargitay.gov.tr/karar/2016-200",
            related_source_ids=("MEVZUAT-4857",),
            legal_principle="Eski içtihat ilkesi (test kaydı).",
            scope_limitations="YIBBGK ile aşıldı.",
            verification_status="SUPERSEDED",
            verified_by="TEST_AUDITOR",
            last_verified_at="2026-11-20",
            superseded_by="YIBBGK-2017-9-2018-10",
        )
        custom_precedents["TEST-CONFLICT"] = PrecedentRecord(
            precedent_id="TEST-CONFLICT",
            chamber="9_HD",
            binding_level="CHAMBER_ISOLATED",
            esas_no="2021/300",
            karar_no="2021/400",
            decision_date="2021-05-01",
            official_source_url="https://karararama.yargitay.gov.tr/karar/2021-400",
            related_source_ids=("MEVZUAT-4857",),
            legal_principle="Çelişkili daire görüşü (test kaydı).",
            scope_limitations="Karşı görüş mevcut.",
            verification_status="CONFLICTING",
            verified_by="TEST_AUDITOR",
            last_verified_at="2026-11-20",
            conflicting_precedent_ids=("YIBBGK-2017-10-2019-1",),
        )
        custom_precedents["TEST-UNVERIFIED"] = PrecedentRecord(
            precedent_id="TEST-UNVERIFIED",
            chamber="10_HD",
            binding_level="CHAMBER_ISOLATED",
            esas_no="2022/500",
            karar_no="2022/600",
            decision_date="2022-06-01",
            official_source_url="https://karararama.yargitay.gov.tr/karar/2022-600",
            related_source_ids=("MEVZUAT-5510",),
            legal_principle="Henüz doğrulanmamış karar (test kaydı).",
            scope_limitations="Teyit bekleniyor.",
            verification_status="UNVERIFIED",
            verified_by="TEST_AUDITOR",
            last_verified_at="2026-11-20",
        )

        audit = verify_response_citations(
            draft_text="E. 2015/100, K. 2016/200; E. 2021/300, K. 2021/400; E. 2022/500, K. 2022/600.",
            as_of_date="2026-05-01",
            source_registry=self.sources,
            precedent_registry=custom_precedents,
        )
        self.assertFalse(audit.passed)
        self.assertTrue(audit.requires_counsel_escalation)
        codes = set(audit.blocker_codes)
        self.assertIn("SUPERSEDED_PRECEDENT_CITED", codes)
        self.assertIn("CONFLICTING_PRECEDENT_ESCALATE", codes)
        self.assertIn("UNVERIFIED_PRECEDENT_CITED", codes)

    def test_blocks_overbroad_contextless_legal_claims_kvkk_overtime_code22_and_pre18(self) -> None:
        cases = [
            (
                "6698 m.6 uyarınca adli sicil belgesi her pozisyonda istenebilir.",
                "OVERBROAD_LEGAL_CLAIM_KVKK_CRIMINAL_RECORD",
            ),
            (
                "6698 m.6 kapsamında işin niteliği tek başına adli sicil için yeterlidir.",
                "OVERBROAD_LEGAL_CLAIM_KVKK_CRIMINAL_RECORD",
            ),
            (
                "4857 m.41 gereği fazla çalışma onayı yoksa çalışma yapılamaz.",
                "OVERBROAD_LEGAL_CLAIM_OVERTIME_CONSENT",
            ),
            (
                "4857 m.41 uyarınca yazılı onay olmadan hiçbir koşulda fazla çalışma yaptırılamaz.",
                "OVERBROAD_LEGAL_CLAIM_OVERTIME_CONSENT",
            ),
            (
                "4447 m.51 gereği SGK çıkış kodu 22 tek başına işsizlik ödeneğine engeldir.",
                "OVERBROAD_LEGAL_CLAIM_SGK_CODE_22",
            ),
            (
                "5510 m.38 gereği 18 yaşından önce ödenen prim günleri sayılmaz.",
                "OVERBROAD_LEGAL_CLAIM_PRE_18_INSURANCE",
            ),
        ]
        for draft, expected_code in cases:
            with self.subTest(expected_code=expected_code, draft=draft):
                audit = verify_response_citations(
                    draft_text=draft,
                    as_of_date="2026-05-01",
                    source_registry=self.sources,
                    precedent_registry=self.precedents,
                )
                self.assertFalse(audit.passed, f"Hatalı/eksik bağlamlı ifade geçmemeliydi: {draft}")
                self.assertIn(expected_code, audit.blocker_codes)

    def test_allows_properly_contextualized_kvkk_overtime_code22_and_pre18_statements(self) -> None:
        draft = (
            "4857 Sayılı İş Kanunu m.41 ve Fazla Çalışma Yönetmeliği m.9 uyarınca olağan fazla çalışma için "
            "yazılı onay alınır, özlük dosyasında saklanır ve işçi 30 gün önceden yazılı bildirimle onayını geri alabilir; "
            "normal haftalık çalışma (45 saat) ile 4857 m.42-43 zorunlu/olağanüstü haller saklıdır. "
            "6698 Sayılı Kanun m.6/3 kapsamında adli sicil belgesi her pozisyonda istenemez; işin niteliği tek başına adli sicil için yeterli değildir. "
            "4447 Sayılı Kanun m.51 değerlendirmesinde SGK çıkış kodu 22 tek başına kesin ret sebebi değildir. "
            "5510 Sayılı Kanun m.38/2 uyarınca 18 yaş öncesi sigortalılık süresi 18 yaş ikmalinde başlar, "
            "ancak 18 yaş öncesi ödenen uzun vadeli (MYÖ) prim günleri toplam prim gün sayısına dahil edilir."
        )
        audit = verify_response_citations(
            draft_text=draft,
            as_of_date="2026-05-01",
            source_registry=self.sources,
            precedent_registry=self.precedents,
        )
        self.assertTrue(audit.passed, f"Doğru bağlamlı açıklama yanlışlıkla bloke edildi: {audit.flags}")

    def test_blocks_night_work_m69_conflated_with_reg_m7_overtime_prohibition(self) -> None:
        bad_drafts = [
            "4857 m.69 uyarınca turizm, özel güvenlik ve sağlık hizmetleri sektörlerinde fazla çalışma yasağı tamamen kalkmıştır.",
            "4857 m.69/3 yazılı onay istisnası ile Yönetmelik m.7 fazla çalışma yasağı otomatik olarak kalkar.",
            "Sağlık kuralları bakımından günde en çok 7,5 saat çalışılması gereken işlerde yazılı onayla fazla çalışma yapılabilir.",
        ]
        for draft in bad_drafts:
            with self.subTest(draft=draft):
                audit = verify_response_citations(
                    draft_text=draft,
                    as_of_date="2026-05-01",
                    source_registry=self.sources,
                    precedent_registry=self.precedents,
                )
                self.assertFalse(audit.passed, f"m.69/m.7 birleştirme hatası bloke edilmeliydi: {draft}")
                self.assertIn("OVERBROAD_LEGAL_CLAIM_NIGHT_WORK_M69_VS_M7", audit.blocker_codes)

        good_draft = (
            "4857 Sayılı İş Kanunu m.69/3 uyarınca gece çalışması kural olarak 7,5 saati geçemez; "
            "yalnızca turizm, özel güvenlik, sağlık hizmeti yürütülen işler ve Türk Petrol Kanunu kapsamındaki "
            "petrol araştırma, arama ve sondaj işlerinde işçinin yazılı onayı ile 7,5 saatin üzerinde gece çalışması yaptırılabilir. "
            "Bu istisna yalnızca 7,5 saatlik gece çalışması sınırına ilişkindir; Fazla Çalışma Yönetmeliği m.7 kapsamındaki "
            "fazla çalışma yasaklarını otomatik olarak kaldırmaz."
        )
        audit_ok = verify_response_citations(
            draft_text=good_draft,
            as_of_date="2026-05-01",
            source_registry=self.sources,
            precedent_registry=self.precedents,
        )
        self.assertTrue(audit_ok.passed, f"Doğru m.69/m.7 ayrımı yanlışlıkla bloke edildi: {audit_ok.flags}")

    def test_overbroad_guardrails_handle_indirect_phrasings_and_negated_refutations(self) -> None:
        indirect_bad = [
            (
                "6698 m.6 kapsamında her işe alımda adli sicil belgesi talep edilebilir.",
                "OVERBROAD_LEGAL_CLAIM_KVKK_CRIMINAL_RECORD",
            ),
            (
                "4857 m.41 gereği fazla çalışma onayı alınmadıkça işçi çalıştırılamaz.",
                "OVERBROAD_LEGAL_CLAIM_OVERTIME_CONSENT",
            ),
            (
                "4447 m.51 gereği kod 22 ile çıkanlar otomatik olarak işsizlik ödeneği alamaz.",
                "OVERBROAD_LEGAL_CLAIM_SGK_CODE_22",
            ),
        ]
        for draft, expected_code in indirect_bad:
            with self.subTest(expected_code=expected_code, draft=draft):
                audit = verify_response_citations(
                    draft_text=draft,
                    as_of_date="2026-05-01",
                    source_registry=self.sources,
                    precedent_registry=self.precedents,
                )
                self.assertFalse(audit.passed, f"Dolaylı hatalı ifade bloke edilmeliydi: {draft}")
                self.assertIn(expected_code, audit.blocker_codes)

        refutation_ok = (
            "6698 m.6 kapsamında her işe alımda adli sicil belgesi istenebilir mi? Hayır; açık kanuni yükümlülük aranır. "
            "4857 m.69/3 kapsamında turizm ve sağlık hizmetleri sektörlerinde fazla çalışma yasağı otomatik olarak kalkar denilemez; "
            "4857 m.41 uyarınca fazla çalışma onayı yoksa çalışma yapılamaz denilemez."
        )
        audit_ref = verify_response_citations(
            draft_text=refutation_ok,
            as_of_date="2026-05-01",
            source_registry=self.sources,
            precedent_registry=self.precedents,
        )
        self.assertTrue(audit_ref.passed, f"Olumsuz/reddedici bağlamlı açıklama yanlışlıkla bloke edildi: {audit_ref.flags}")

    def test_blocks_blanket_m42_m43_exception_applied_to_reg_m7_and_allows_narrow_statutory_distinction(self) -> None:
        bad_drafts = [
            "Fazla Çalışma Yönetmeliği m.7 kapsamındaki tüm işlerde 4857 m.42-43 ile otomatik olarak fazla çalışma yaptırılabilir.",
            "Fazla Çalışma Yönetmeliği m.7 metninde 4857 m.42 ve m.43 için açık istisna yazılıdır.",
            "Sağlık kuralları bakımından günde en çok 7,5 saat çalışılması gereken işlerde 4857 m.42-43 kapsamında otomatik fazla çalışma yapılabilir.",
            "Su altı ve tünel işlerinde 4857 m.42-43 ile otomatik olarak fazla çalışma yaptırılabilir.",
        ]
        for draft in bad_drafts:
            with self.subTest(draft=draft):
                audit = verify_response_citations(
                    draft_text=draft,
                    as_of_date="2026-05-01",
                    source_registry=self.sources,
                    precedent_registry=self.precedents,
                )
                self.assertFalse(audit.passed, f"Yönetmelik m.7 / m.42-43 genellemesi bloke edilmeliydi: {draft}")
                self.assertIn("OVERBROAD_LEGAL_CLAIM_REG_M7_AUTO_M42_M43_EXCEPTION", audit.blocker_codes)

        good_draft = (
            "Fazla Çalışma Yönetmeliği m.7 metninde genel bir 4857 m.42-43 istisna cümlesi bulunmamaktadır. "
            "4857 Sayılı İş Kanunu m.41/9-10 açıkça yalnızca yer altında maden işlerinde "
            "4857 m.42-43 hallerinde (haftalık 37,5 saat üzeri en az %100 zamlı) fazla çalışma öngörmüştür. "
            "Maden dışındaki diğer Yönetmelik m.7 yasaklı işlerde 4857 m.42-43 otomatik istisna değildir; hukuk müşaviri incelemesi gerekir."
        )
        audit_ok = verify_response_citations(
            draft_text=good_draft,
            as_of_date="2026-05-01",
            source_registry=self.sources,
            precedent_registry=self.precedents,
        )
        self.assertTrue(audit_ok.passed, f"Doğru m.7 / m.41(9-10) / m.42-43 ayrımı yanlışlıkla bloke edildi: {audit_ok.flags}")


class TestKnowledgeCardLibrary(unittest.TestCase):
    def setUp(self) -> None:
        self.sources = load_source_registry(SOURCES_PATH, strict=True)
        self.precedents = load_precedent_registry(PRECEDENTS_PATH, source_registry=self.sources, strict=True)
        self.central_audit = load_central_audit_index(AUDIT_LOG_PATH)
        self.cards = load_knowledge_cards(
            KB_LAWS_DIR,
            self.sources,
            self.precedents,
            strict=True,
            audit_log_path=AUDIT_LOG_PATH,
        )

    def test_all_nine_core_laws_loaded_and_strictly_valid(self) -> None:
        json_files = sorted(KB_LAWS_DIR.glob("*.json"))
        self.assertEqual(len(json_files), 9)
        expected_laws = {"4857", "1475", "5510", "6331", "6098", "7036", "6356", "4447", "6698"}
        loaded_laws = {c.law_no for c in self.cards.values()}
        self.assertEqual(loaded_laws, expected_laws)
        self.assertEqual(len(self.cards), 25)

    def test_card_cannot_be_verified_without_verified_effective_date(self) -> None:
        raw = json.loads((KB_LAWS_DIR / "01_4857_is_kanunu.json").read_text(encoding="utf-8"))
        mutated = copy.deepcopy(raw)
        mutated["cards"][0]["effective_validity"]["effective_date_verified"] = False
        mutated["cards"][0]["verification_status"] = "VERIFIED"

        report = validate_knowledge_card_file(
            mutated, self.sources, self.precedents, "mutated_4857", central_audit_index=self.central_audit
        )
        self.assertFalse(report.valid)
        self.assertIn("UNVERIFIED_EFFECTIVE_DATE_ON_VERIFIED_CARD", {f.code for f in report.flags})

    def test_card_cannot_be_verified_without_separate_legal_interpretation_and_source_verification(self) -> None:
        raw = json.loads((KB_LAWS_DIR / "01_4857_is_kanunu.json").read_text(encoding="utf-8"))
        mutated = copy.deepcopy(raw)
        mutated["cards"][0]["source_verification"]["status"] = "PENDING"
        mutated["cards"][0]["legal_interpretation_verification"]["status"] = "PENDING_LEGAL_REVIEW"
        mutated["cards"][0]["legal_interpretation_verification"]["checked_aspects"] = ["ARTICLE_TEXT"]
        mutated["cards"][0]["verification_status"] = "VERIFIED"

        report = validate_knowledge_card_file(
            mutated, self.sources, self.precedents, "mutated_dual", central_audit_index=self.central_audit
        )
        self.assertFalse(report.valid)
        codes = {f.code for f in report.flags}
        self.assertIn("UNVERIFIED_SOURCE_ON_VERIFIED_CARD", codes)
        self.assertIn("UNVERIFIED_LEGAL_INTERPRETATION_ON_VERIFIED_CARD", codes)
        self.assertIn("INCOMPLETE_LEGAL_REVIEW_ASPECTS", codes)

    def test_card_missing_or_mismatched_central_audit_log_entry_is_blocked(self) -> None:
        raw = json.loads((KB_LAWS_DIR / "01_4857_is_kanunu.json").read_text(encoding="utf-8"))
        mutated_missing = copy.deepcopy(raw)
        mutated_missing["cards"][0]["verification_audit"]["audit_log_id"] = "AUD-20261120-ORPHANCARD"
        rep_missing = validate_knowledge_card_file(
            mutated_missing, self.sources, self.precedents, "missing_central", central_audit_index=self.central_audit
        )
        self.assertFalse(rep_missing.valid)
        self.assertIn("MISSING_CENTRAL_AUDIT_LOG_ENTRY", {f.code for f in rep_missing.flags})

        mutated_mismatch = copy.deepcopy(raw)
        # Reuse another card's audit_log_id so record_id mismatches
        mutated_mismatch["cards"][0]["verification_audit"]["audit_log_id"] = raw["cards"][1]["verification_audit"]["audit_log_id"]
        rep_mismatch = validate_knowledge_card_file(
            mutated_mismatch, self.sources, self.precedents, "mismatch_central", central_audit_index=self.central_audit
        )
        self.assertFalse(rep_mismatch.valid)
        self.assertIn("CENTRAL_AUDIT_LOG_MISMATCH", {f.code for f in rep_mismatch.flags})

    def test_card_rejects_unverified_or_fabricated_precedent_ref(self) -> None:
        raw = json.loads((KB_LAWS_DIR / "01_4857_is_kanunu.json").read_text(encoding="utf-8"))
        mutated = copy.deepcopy(raw)
        mutated["cards"][0]["related_precedent_ids"] = ["FAKE-9HD-2025-999"]
        report = validate_knowledge_card_file(
            mutated, self.sources, self.precedents, "mutated_prec", central_audit_index=self.central_audit
        )
        self.assertFalse(report.valid)
        self.assertIn("BROKEN_CARD_PRECEDENT_ID", {f.code for f in report.flags})

    def test_4857_m41_card_includes_written_consent_storage_30_day_withdrawal_and_m42_43_context(self) -> None:
        card = self.cards["CARD-4857-M41"]
        scope_l = card.scope_of_application.lower()
        self.assertIn("fazla çalışma yönetmeliği m.9", scope_l)
        self.assertIn("özlük dosyasında saklanması", scope_l)
        self.assertIn("30 gün önceden", scope_l)
        self.assertIn("4857 m.42", scope_l)
        self.assertIn("m.43", scope_l)
        scenario_map = {s["scenario_id"]: s for s in card.application_scenarios}
        self.assertTrue(
            {
                "OVERTIME_ORDINARY_CONSENT_AND_STORAGE",
                "OVERTIME_CONSENT_WITHDRAWAL_30_DAYS",
                "OVERTIME_MANDATORY_OR_EMERGENCY_NO_CONSENT_REQUIRED",
            }.issubset(set(scenario_map.keys()))
        )
        self.assertIn("özlük dosyasında saklanır", scenario_map["OVERTIME_ORDINARY_CONSENT_AND_STORAGE"]["legal_rule"].lower())
        self.assertIn("30 gün önceden", scenario_map["OVERTIME_CONSENT_WITHDRAWAL_30_DAYS"]["legal_rule"].lower())
        self.assertIn("4857 m.42", scenario_map["OVERTIME_MANDATORY_OR_EMERGENCY_NO_CONSENT_REQUIRED"]["statutory_basis"])

    def test_4857_m41_separates_reg_m7_overtime_prohibitions_from_m69_night_work_limit(self) -> None:
        card = self.cards["CARD-4857-M41"]
        # m.7 prohibition bullet must NOT conflate m.69 tourism/security/health exception into overtime bans
        joined_exceptions = " ".join(card.exceptions).lower()
        self.assertIn("fazla çalışma yönetmeliği m.7", joined_exceptions)
        self.assertNotIn("turizm, özel güvenlik, sağlık hizmetleri yazılı onay istisnası hariç", joined_exceptions)

        scenario_map = {s["scenario_id"]: s for s in card.application_scenarios}
        self.assertIn("OVERTIME_PROHIBITED_WORKS_REG_M7", scenario_map)
        self.assertIn("NIGHT_WORK_7_5_HOUR_LIMIT", scenario_map)

        m7 = scenario_map["OVERTIME_PROHIBITED_WORKS_REG_M7"]
        self.assertIn("yönetmeliği m.7", m7["statutory_basis"].lower())
        self.assertIn("sağlık kuralları bakımından", m7["legal_rule"].lower())
        self.assertIn("ayrı değerlendirilir", m7["legal_rule"].lower())

        m69 = scenario_map["NIGHT_WORK_7_5_HOUR_LIMIT"]
        self.assertIn("4857 m.69/3", m69["statutory_basis"])
        m69_rule_l = m69["legal_rule"].lower()
        for expected_token in ("7,5 saati", "turizm", "özel güvenlik", "sağlık hizmeti", "petrol", "yazılı onayı", "otomatik olarak kaldırmaz"):
            self.assertIn(expected_token, m69_rule_l)

    def test_4857_m41_removes_blanket_m42_m43_exception_from_reg_m7_and_models_separate_review_note_and_scenario(self) -> None:
        card = self.cards["CARD-4857-M41"]
        joined_exceptions = " ".join(card.exceptions).lower()
        self.assertNotIn("(4857 m.42-43 hariç)", joined_exceptions)

        scenario_map = {s["scenario_id"]: s for s in card.application_scenarios}
        m7 = scenario_map["OVERTIME_PROHIBITED_WORKS_REG_M7"]
        self.assertNotIn("4857 m.42-43 zorunlu/olağanüstü haller hariç", m7["legal_rule"].lower())
        self.assertIn("genel bir 4857 m.42-43 istisna cümlesi yer almaz", m7["legal_rule"].lower())

        self.assertIn("UNDERGROUND_MINING_STATUTORY_M42_M43_AND_M7_RELATION", scenario_map)
        rel = scenario_map["UNDERGROUND_MINING_STATUTORY_M42_M43_AND_M7_RELATION"]
        rel_rule_l = rel["legal_rule"].lower()
        self.assertIn("4857 m.41/9-10", rel_rule_l)
        self.assertIn("yalnızca yer altında maden işleri", rel_rule_l)
        self.assertIn("otomatik istisna olarak uygulanamaz", rel_rule_l)
        self.assertIn("escalate_to_legal_counsel", rel_rule_l)

        scr = card.special_calculation_rules or {}
        self.assertIn("m42_m43_vs_reg_m7_legal_review_note", scr)
        self.assertIn("statutory_underground_mining_scope", scr)
        self.assertIn("non_mining_reg_m7_escalation_rule", scr)
        self.assertIn("genel bir istisna cümlesi bulunmamaktadır", scr["m42_m43_vs_reg_m7_legal_review_note"].lower())
        self.assertIn("37,5 saat", scr["statutory_underground_mining_scope"].lower())

        # Amendment history must track both 6552 m.4 (36h, 2014-09-11) and 6645 m.34 (37.5h, 2015-04-23 / RG 29335)
        amend_by_law = {a["amending_law_no"]: a for a in card.legal_basis["amendment_history"]}
        self.assertIn("6552", amend_by_law)
        self.assertIn("6645", amend_by_law)
        self.assertEqual(amend_by_law["6552"]["effective_from"], "2014-09-11")
        self.assertIn("36 saat", amend_by_law["6552"]["summary"].lower())
        self.assertEqual(amend_by_law["6645"]["official_gazette_no"], "29335")
        self.assertEqual(amend_by_law["6645"]["effective_from"], "2015-04-23")
        self.assertIn("37,5 saat", amend_by_law["6645"]["summary"].lower())

    def test_5510_card_separates_m81_2pt_and_gecici_m108_5pt_manufacturing_basis(self) -> None:
        card = self.cards["CARD-5510-M81"]
        self.assertIn("Geçici Madde 108", card.article_ref)
        self.assertIn("81/1-ı", card.article_ref)
        self.assertIn("2026/1", card.scope_of_application)
        scenario_map = {s["scenario_id"]: s for s in card.application_scenarios}
        self.assertIn("SGK_2026_GENERAL_NON_MANUFACTURING_2PT", scenario_map)
        self.assertIn("SGK_2026_MANUFACTURING_5PT", scenario_map)
        self.assertIn("81/1-ı", scenario_map["SGK_2026_GENERAL_NON_MANUFACTURING_2PT"]["statutory_basis"])
        self.assertIn("Geçici Madde 108", scenario_map["SGK_2026_MANUFACTURING_5PT"]["statutory_basis"])

    def test_1475_m14_card_separates_retirement_cohorts_and_pre_18_insurance_rules(self) -> None:
        card = self.cards["CARD-1475-M14"]
        scenario_map = {s["scenario_id"]: s for s in card.application_scenarios}
        self.assertEqual(
            set(scenario_map.keys()),
            {
                "RETIREMENT_PRE_1999_09_08",
                "RETIREMENT_1999_09_08_TO_2008_04_30",
                "RETIREMENT_POST_2008_05_01",
                "RETIREMENT_PRE_18_INSURANCE_DISTINCTION",
            },
        )
        all_rules = " ".join(s["legal_rule"] for s in card.application_scenarios)
        for token in ("3600", "4500", "7000", "7200", "5400"):
            self.assertIn(token, all_rules)
        self.assertIn("5510 m.38/2", scenario_map["RETIREMENT_PRE_18_INSURANCE_DISTINCTION"]["statutory_basis"])
        self.assertIsNotNone(card.special_calculation_rules)
        scr = card.special_calculation_rules or {}
        self.assertIn("pre_18_insurance_period_start_rule", scr)
        self.assertIn("pre_18_premium_days_counting_rule", scr)
        self.assertIn("internship_and_apprenticeship_exclusion", scr)
        self.assertIn("sgk_letter_verification_checklist", scr)
        self.assertIn("18 yaşını doldurdukları tarihte", scr["pre_18_insurance_period_start_rule"])
        self.assertIn("DAHİL EDİLİR", scr["pre_18_premium_days_counting_rule"])
        self.assertIn("staj", scr["internship_and_apprenticeship_exclusion"].lower())
        self.assertGreaterEqual(len(scr["sgk_letter_verification_checklist"]), 4)

    def test_4447_card_forbids_absolute_code_22_auto_denial(self) -> None:
        card = self.cards["CARD-4447-M50-M51"]
        self.assertIn("tek başına kesin", card.scope_of_application.lower())
        self.assertIn("4447 m.51", card.scope_of_application)
        self.assertNotIn("ikale (sgk kodu 22) hallerinde işsizlik ödeneğine hak kazanılamaz", " ".join(card.exceptions).lower())
        scenario_ids = {s["scenario_id"] for s in card.application_scenarios}
        self.assertIn("UNEMPLOYMENT_CODE_22_SUBSTANTIVE_REVIEW", scenario_ids)

    def test_6698_card_enforces_separate_health_biometric_and_criminal_controls(self) -> None:
        card = self.cards["CARD-6698-M05-M06-M10"]
        self.assertIn("sınırsız işleme yetkisi vermez", card.scope_of_application.lower())
        ctrl_map = {d["category"]: d for d in card.data_category_controls}
        self.assertEqual(
            set(ctrl_map.keys()),
            {"SAĞLIK_VERİLERİ", "BİYOMETRİK_VERİLER_PDKS", "CEZA_MAHKÛMİYETİ_VE_ADLİ_SİCİL"},
        )
        for ctrl in card.data_category_controls:
            self.assertTrue(ctrl["purpose_and_necessity_limit"])
            self.assertTrue(ctrl["explicit_consent_rule"])
            self.assertTrue(ctrl["proportionality_rule"])
            self.assertTrue(ctrl["access_control"])
            self.assertTrue(ctrl["retention_policy"])

        # Criminal record must reject 'işin niteliği' as standalone m.6/3-f basis and distinguish explicit consent
        crim = ctrl_map["CEZA_MAHKÛMİYETİ_VE_ADLİ_SİCİL"]
        self.assertIn("tek başına m.6/3-f hukuki sebebi sayılmaz", crim["purpose_and_necessity_limit"].lower())
        self.assertIn("m.6/3-a", crim["explicit_consent_rule"].lower())
        self.assertIn("güç dengesizliği", crim["explicit_consent_rule"].lower())

        # Biometric PDKS must evaluate alternative less-intrusive methods and case-specific conditions
        bio = ctrl_map["BİYOMETRİK_VERİLER_PDKS"]
        self.assertIn("alternatif yöntemlerin varlığı", bio["proportionality_rule"].lower())
        self.assertIn("somut olayın koşulları", bio["proportionality_rule"].lower())

        scenario_ids = {s["scenario_id"] for s in card.application_scenarios}
        self.assertEqual(
            scenario_ids,
            {
                "KVKK_CRIMINAL_RECORD_STATUTORY_MANDATE",
                "KVKK_CRIMINAL_RECORD_NO_STATUTORY_MANDATE",
                "KVKK_BIOMETRIC_PDKS_CASE_BY_CASE",
            },
        )

    def test_temporal_knowledge_card_query_respects_article_effective_dates(self) -> None:
        res_2017 = query_knowledge_cards(self.cards, "arabuluculuk dava şartı 7036", as_of_date="2017-11-15", law_no="7036")
        self.assertEqual(res_2017["effective_cards"], [])
        self.assertIn("CARD-7036-M03", [c["card_id"] for c in res_2017["not_effective_on_date_cards"]])

        res_2026 = query_knowledge_cards(self.cards, "arabuluculuk dava şartı 7036", as_of_date="2026-04-01", law_no="7036")
        self.assertIn("CARD-7036-M03", [c["card_id"] for c in res_2026["effective_cards"]])


class TestNormHierarchyResolver(unittest.TestCase):
    def test_hr_procedure_worse_than_law_is_void(self) -> None:
        law = NormReference("4857 Sayılı İş Kanunu m.53 (Asgari 14 Gün Yıllık İzin)", "STATUTORY_LAW", source_id="MEVZUAT-4857")
        proc = NormReference("Şirket İK Prosedürü (10 Gün Yıllık İzin)", "CBA_CONTRACT_AND_HR_PROCEDURE")
        res = resolve_norm_conflict(law, proc, mandatory_type="RELATIVE_EMPLOYEE_FAVORABLE", favors_employee_side="NORM_A")
        self.assertEqual(res.winning_side, "NORM_A")
        self.assertEqual(res.rule_applied, "RELATIVE_MANDATORY_EMPLOYEE_UNFAVORABLE_LOWER_NORM_VOID")
        self.assertFalse(res.requires_counsel_escalation)

    def test_cba_more_favorable_than_statutory_floor_prevails(self) -> None:
        law = NormReference("4857 Sayılı İş Kanunu m.53 (Asgari 14 Gün Yıllık İzin)", "STATUTORY_LAW", source_id="MEVZUAT-4857")
        cba = NormReference("Toplu İş Sözleşmesi (26 Gün Yıllık İzin)", "CBA_CONTRACT_AND_HR_PROCEDURE")
        res = resolve_norm_conflict(law, cba, mandatory_type="RELATIVE_EMPLOYEE_FAVORABLE", favors_employee_side="NORM_B")
        self.assertEqual(res.winning_side, "NORM_B")
        self.assertEqual(res.rule_applied, "RELATIVE_MANDATORY_EMPLOYEE_FAVORABLE_LOWER_NORM_PREVAILS")
        self.assertFalse(res.requires_counsel_escalation)

    def test_absolute_mandatory_rule_cannot_be_overridden_by_contract(self) -> None:
        tbk = NormReference("6098 Sayılı TBK m.420 (İbraname 1 Ay Bekleme Şartı)", "STATUTORY_LAW", source_id="MEVZUAT-6098")
        contract = NormReference("Fesih Günü İmzalı İkale İbraname Maddesi", "CBA_CONTRACT_AND_HR_PROCEDURE")
        res = resolve_norm_conflict(tbk, contract, mandatory_type="ABSOLUTE_MANDATORY", favors_employee_side="NORM_B")
        self.assertEqual(res.winning_side, "NORM_A")
        self.assertEqual(res.rule_applied, "ABSOLUTE_MANDATORY_HIGHER_NORM_PREVAILS")

    def test_yibbgk_prevails_over_chamber_decision(self) -> None:
        chamber = NormReference("9. HD Eski Daire Görüşü", "YARGITAY_PRECEDENT", precedent_level="CHAMBER_SETTLED")
        yibbgk = NormReference(
            "YİBBGK E. 2017/9, K. 2018/10",
            "YARGITAY_PRECEDENT",
            precedent_level="STATUTORY_BINDING_YIBBGK",
            source_id="YIBBGK-2017-9-2018-10",
        )
        res = resolve_norm_conflict(chamber, yibbgk, mandatory_type="ABSOLUTE_MANDATORY")
        self.assertEqual(res.winning_side, "NORM_B")
        self.assertEqual(res.rule_applied, "PRECEDENT_HIERARCHY_YIBBGK_SUPREMACY")
        self.assertFalse(res.requires_counsel_escalation)

    def test_same_level_conflicting_precedents_force_escalation(self) -> None:
        c1 = NormReference("Daire Kararı A", "YARGITAY_PRECEDENT", precedent_level="CHAMBER_SETTLED")
        c2 = NormReference("Daire Kararı B", "YARGITAY_PRECEDENT", precedent_level="CHAMBER_SETTLED")
        res = resolve_norm_conflict(c1, c2, mandatory_type="RELATIVE_EMPLOYEE_FAVORABLE")
        self.assertEqual(res.winning_side, "UNRESOLVED_ESCALATE")
        self.assertTrue(res.requires_counsel_escalation)


class TestToolsRouterRoundTrip(unittest.TestCase):
    def setUp(self) -> None:
        self.router = HukukSGKToolRouter()

    def test_lookup_returns_active_2026_cbk_verified_yibbgk_and_knowledge_cards(self) -> None:
        cbk_res = self.router.dispatch(
            "lookup_verified_source_and_precedent",
            {"query": "uzaktan çalışma 2026 teknokent", "as_of_date": "2026-04-01", "include_superseded": True},
        )
        self.assertEqual(cbk_res["status"], "OK")
        active_ids = [s["source_id"] for s in cbk_res["matched_sources"]]
        superseded_ids = [s["source_id"] for s in cbk_res["superseded_or_inactive_sources"]]
        self.assertIn("RG-10766-20251225", active_ids)
        self.assertNotIn("RG-9368-20241228", active_ids)
        self.assertIn("RG-9368-20241228", superseded_ids)

        prec_res = self.router.dispatch(
            "lookup_verified_source_and_precedent",
            {"query": "sağlık raporu savunma derhal fesih", "as_of_date": "2026-04-01"},
        )
        self.assertIn("YIBBGK-2017-9-2018-10", [p["precedent_id"] for p in prec_res["matched_precedents"]])
        self.assertIn("CARD-4857-M19", [c["card_id"] for c in prec_res["matched_knowledge_cards"]])
        self.assertIsNone(prec_res["no_verified_precedent_notice"])

    def test_lookup_knowledge_card_and_check_article_effective_date(self) -> None:
        card_res = self.router.dispatch(
            "lookup_knowledge_card",
            {"query": "ibraname 1 ay banka", "as_of_date": "2026-04-01", "law_no": "6098"},
        )
        self.assertIn("CARD-6098-M420", [c["card_id"] for c in card_res["effective_cards"]])

        art_res = self.router.dispatch(
            "check_article_effective_date",
            {"source_id": "MEVZUAT-5510", "article_ref": "Madde 82", "as_of_date": "2025-12-20"},
        )
        self.assertFalse(art_res["is_effective"])

    def test_verify_document_integrity_tool_with_mock_fetcher(self) -> None:
        def mock_fetch(url: str, timeout: int) -> tuple[int, str, bytes]:
            return 200, "text/html; charset=utf-8", "<html>7566 Sayılı Kanun 5510 MADDE 24</html>".encode("utf-8")

        router = HukukSGKToolRouter(document_fetcher=mock_fetch)
        res = router.dispatch("verify_document_integrity", {"record_id": "RG-7566-20251219"})
        self.assertTrue(res["ok"])
        self.assertEqual(res["http_status"], 200)

    def test_lookup_warns_when_no_verified_precedent_exists(self) -> None:
        res = self.router.dispatch(
            "lookup_verified_source_and_precedent",
            {"query": "iş kazası 3 iş günü 6331", "as_of_date": "2026-04-01"},
        )
        self.assertEqual(res["matched_precedents"], [])
        self.assertIsNotNone(res["no_verified_precedent_notice"])
        self.assertIn("CARD-6331-M14", [c["card_id"] for c in res["matched_knowledge_cards"]])

    def test_verify_citations_and_escalation_dispatch(self) -> None:
        audit = self.router.dispatch(
            "verify_legal_citations",
            {
                "draft_text": "Yargıtay 9. HD E. 2024/1111, K. 2025/2222 kararına göre fesih geçersizdir.",
                "as_of_date": "2026-04-01",
            },
        )
        self.assertFalse(audit["passed"])
        self.assertIn("FABRICATED_PRECEDENT", audit["blocker_codes"])

        esc = self.router.dispatch(
            "escalate_to_legal_counsel",
            {
                "severity": "CRITICAL_LEGAL_BLOCK",
                "reason": "6 iş günü hak düşürücü süre aşıldı.",
                "affected_employees": ["EMP-1042"],
                "legal_issues": ["4857 m.26 hak düşürücü süre ihlali"],
            },
        )
        self.assertEqual(esc["status"], "ESCALATED_TO_LEGAL_COUNSEL")
        self.assertTrue(esc["payroll_handoff_blocked"])
        self.assertTrue(esc["ticket_id"].startswith("LEGAL-ESC-"))

    def test_planned_v1_1_tool_reports_explicit_status(self) -> None:
        res = self.router.dispatch(
            "check_legal_deadline",
            {"obligation_type": "SGK_EXIT_NOTICE_10_DAYS", "trigger_date": "2026-04-01", "action_date": "2026-04-12"},
        )
        self.assertEqual(res["status"], "NOT_IMPLEMENTED_IN_V1_0_2")


class TestV102bSecondaryLegislationAndPrecedents(unittest.TestCase):
    def setUp(self) -> None:
        self.sources = load_source_registry(SOURCES_PATH, strict=True)
        self.precedents = load_precedent_registry(PRECEDENTS_PATH, source_registry=self.sources, strict=True)
        self.audit_index = load_central_audit_index(AUDIT_LOG_PATH)
        self.router = HukukSGKToolRouter()

    def test_l2_regulations_loaded_strictly_with_mandatory_subordination_and_amendment_history(self) -> None:
        reg_files = sorted(KB_REGULATIONS_DIR.glob("*.json"))
        self.assertEqual(len(reg_files), 6)
        cards = load_knowledge_cards(
            KB_REGULATIONS_DIR,
            source_registry=self.sources,
            precedent_registry=self.precedents,
            strict=True,
            audit_log_path=AUDIT_LOG_PATH,
        )
        self.assertEqual(len(cards), 7)
        for cid, card in cards.items():
            self.assertEqual(card.verification_status, "VERIFIED")
            self.assertIsNotNone(card.statutory_subordination, f"{cid} statutory_subordination eksik")
            self.assertTrue(card.statutory_subordination["cannot_override_parent_law"])
            self.assertTrue(card.statutory_subordination["concretizes_statutory_provisions"])
            self.assertGreaterEqual(len(card.statutory_subordination["hierarchy_note"]), 15)
            self.assertTrue(card.legal_basis["amendment_history"], f"{cid} amendment_history boş olmamalı")

        # Concrete legal assertions for key L2 cards
        uzaktan = cards["CARD-YON-UZAKTAN-CALISMA"]
        self.assertIn("33381", uzaktan.effective_validity["effective_date_basis"])
        self.assertIn("hibrit", uzaktan.topic.lower())
        self.assertIn("2026-09-25", [a["effective_from"] for a in uzaktan.legal_basis["amendment_history"]])

        fazla = cards["CARD-YON-FAZLA-CALISMA"]
        self.assertIn("30 gün", fazla.topic.lower())
        self.assertIn("madde 4/son", fazla.article_ref.lower())

        alt_isv = cards["CARD-YON-ALT-ISVERENLIK"]
        self.assertIn("30 İş Günü", alt_isv.topic)

        calisma = cards["CARD-YON-CALISMA-SURELERI"]
        self.assertIn("4857 m.64", calisma.statutory_subordination["hierarchy_note"])

    def test_l3_communique_circular_and_cbk_cards_loaded_strictly_with_subordination(self) -> None:
        circ_files = sorted(KB_CIRCULARS_DIR.glob("*.json"))
        self.assertEqual(len(circ_files), 7)
        self.assertTrue((KB_CIRCULARS_DIR / "04_ck_10766_2026_uzaktan_calisma.json").exists())
        self.assertFalse((KB_CIRCULARS_DIR / "04_cbk_10766_2026_uzaktan_calisma.json").exists())
        cards = load_knowledge_cards(
            KB_CIRCULARS_DIR,
            source_registry=self.sources,
            precedent_registry=self.precedents,
            strict=True,
            audit_log_path=AUDIT_LOG_PATH,
        )
        self.assertEqual(len(cards), 7)
        expected_ids = {
            "CARD-GIB-319-ASGARI-UCRET",
            "CARD-GIB-331-ARGE-40KAT",
            "CARD-GIB-332-2026-TARIFE",
            "CARD-CK-10766-2026",
            "CARD-SGK-2020-20-ISVEREN",
            "CARD-SGK-2026-1-INDIRIM",
            "CARD-SGK-2026-PEK-SINIR",
        }
        self.assertEqual(set(cards.keys()), expected_ids)
        for cid, card in cards.items():
            if cid == "CARD-GIB-332-2026-TARIFE":
                # Parent GIB-TEBLIG-332-20251231 is PENDING_REVIEW -> card CANNOT be VERIFIED
                self.assertEqual(card.verification_status, "PENDING_LEGAL_REVIEW")
                self.assertFalse(card.effective_validity["effective_date_verified"])
                self.assertEqual(card.source_verification["status"], "PENDING")
                self.assertEqual(card.legal_interpretation_verification["status"], "PENDING_LEGAL_REVIEW")
            else:
                self.assertEqual(card.verification_status, "VERIFIED")
            self.assertIsNotNone(card.statutory_subordination, f"{cid} statutory_subordination eksik")
            self.assertTrue(card.statutory_subordination["cannot_override_parent_law"])
            self.assertTrue(card.legal_basis["amendment_history"])

        self.assertIn("300 TL", cards["CARD-GIB-332-2026-TARIFE"].scope_of_application)
        self.assertIn("158 TL", cards["CARD-GIB-332-2026-TARIFE"].scope_of_application)
        self.assertIn("07-Puantaj", cards["CARD-SGK-2020-20-ISVEREN"].scope_of_application)
        self.assertIn("Geçici m.108", cards["CARD-SGK-2026-1-INDIRIM"].scope_of_application)
        self.assertIn("297.270,00 TL", cards["CARD-SGK-2026-PEK-SINIR"].scope_of_application)

    def test_secondary_legislation_card_blocked_when_missing_subordination_bad_amendment_or_inactive_parent(self) -> None:
        raw = json.loads((KB_REGULATIONS_DIR / "06_uzaktan_calisma_yonetmeligi.json").read_text(encoding="utf-8"))

        # 1. Missing statutory_subordination
        m1 = copy.deepcopy(raw)
        del m1["cards"][0]["statutory_subordination"]
        r1 = validate_knowledge_card_file(m1, self.sources, self.precedents, central_audit_index=self.audit_index)
        self.assertFalse(r1.valid)
        self.assertIn("MISSING_OR_INVALID_STATUTORY_SUBORDINATION", {f.code for f in r1.flags})

        # 2. cannot_override_parent_law = False
        m2 = copy.deepcopy(raw)
        m2["cards"][0]["statutory_subordination"]["cannot_override_parent_law"] = False
        r2 = validate_knowledge_card_file(m2, self.sources, self.precedents, central_audit_index=self.audit_index)
        self.assertFalse(r2.valid)
        self.assertIn("MISSING_OR_INVALID_STATUTORY_SUBORDINATION", {f.code for f in r2.flags})

        # 3. Malformed amendment_history entry
        m3 = copy.deepcopy(raw)
        m3["cards"][0]["legal_basis"]["amendment_history"][0]["effective_from"] = "25.09.2026"
        r3 = validate_knowledge_card_file(m3, self.sources, self.precedents, central_audit_index=self.audit_index)
        self.assertFalse(r3.valid)
        self.assertIn("INVALID_AMENDMENT_HISTORY_ENTRY", {f.code for f in r3.flags})

        # 4. Card effective_from earlier than parent source effective_from
        m4 = copy.deepcopy(raw)
        m4["cards"][0]["effective_validity"]["effective_from"] = "2020-01-01"
        r4 = validate_knowledge_card_file(m4, self.sources, self.precedents, central_audit_index=self.audit_index)
        self.assertFalse(r4.valid)
        self.assertIn("CARD_EFFECTIVE_BEFORE_PARENT_SOURCE", {f.code for f in r4.flags})

        # 5. VERIFIED card bound to SUPERSEDED parent source (RG-9368-20241228)
        raw_ck = json.loads((KB_CIRCULARS_DIR / "04_ck_10766_2026_uzaktan_calisma.json").read_text(encoding="utf-8"))
        m5 = copy.deepcopy(raw_ck)
        m5["source_id"] = "RG-9368-20241228"
        m5["cards"][0]["source_id"] = "RG-9368-20241228"
        m5["cards"][0]["source_verification"]["source_id"] = "RG-9368-20241228"
        m5["cards"][0]["source_verification"]["source_audit_log_id"] = "AUD-20261120-RG936820241228"
        r5 = validate_knowledge_card_file(m5, self.sources, self.precedents, central_audit_index=self.audit_index)
        self.assertFalse(r5.valid)
        self.assertIn("INACTIVE_PARENT_SOURCE_ON_VERIFIED_CARD", {f.code for f in r5.flags})

    def test_citation_auditor_blocks_secondary_legislation_overriding_statute_and_allows_refutation(self) -> None:
        bad_circular = (
            "SGK genelgesi kanundan üstündür ve 5510 Sayılı Kanun hükmünü bertaraf eder."
        )
        res_bad_1 = verify_response_citations(bad_circular, "2026-04-01", self.sources, self.precedents)
        self.assertFalse(res_bad_1.passed)
        self.assertIn("OVERBROAD_LEGAL_CLAIM_SECONDARY_OVERRIDES_STATUTE", res_bad_1.blocker_codes)

        bad_reg = "Yönetmelik hükmü 4857 Sayılı İş Kanunu hükmünü değiştirebilir."
        res_bad_2 = verify_response_citations(bad_reg, "2026-04-01", self.sources, self.precedents)
        self.assertFalse(res_bad_2.passed)
        self.assertIn("OVERBROAD_LEGAL_CLAIM_SECONDARY_OVERRIDES_STATUTE", res_bad_2.blocker_codes)

        good_refute = (
            "Yönetmelik hükmü kanunu bertaraf eder denilemez; 4857 Sayılı İş Kanunu üst normdur "
            "ve ikincil mevzuat yalnızca kanunu somutlaştırır."
        )
        res_good = verify_response_citations(good_refute, "2026-04-01", self.sources, self.precedents)
        self.assertTrue(res_good.passed, f"Beklenmeyen blokaj: {res_good.flags}")

    def test_l4_three_new_yibbgk_precedents_searchable_and_auditable_with_honest_fetch_status(self) -> None:
        # 1. YIBBGK-2023-1-2025-3 (Post-employment non-compete -> Asliye Ticaret Mahkemesi) — VERIFIED
        rec_2025 = self.precedents["YIBBGK-2023-1-2025-3"]
        self.assertEqual(rec_2025.verification_status, "VERIFIED")
        self.assertEqual(rec_2025.verification_audit.document_fetch_status, "FETCHED_AND_MATCHED")
        self.assertTrue(rec_2025.operative_holding["verified_against_gazette"])
        self.assertIn("Asliye Ticaret Mahkemesi", rec_2025.operative_holding["text"])

        # 2. YIBBGK-2017-8-2019-3 (Partial lawsuit partial amendment interest) — VERIFIED
        rec_2019 = self.precedents["YIBBGK-2017-8-2019-3"]
        self.assertEqual(rec_2019.verification_status, "VERIFIED")
        self.assertEqual(rec_2019.verification_audit.document_fetch_status, "FETCHED_AND_MATCHED")
        self.assertTrue(rec_2019.operative_holding["verified_against_gazette"])

        # 3. YIBBGK-2021-8-2026-1 (Honest PENDING_REVIEW for CID PDF: HTTP 200 + SHA-256, NOT VERIFIED)
        rec_2026 = self.precedents["YIBBGK-2021-8-2026-1"]
        self.assertEqual(rec_2026.verification_status, "PENDING_REVIEW")
        self.assertEqual(rec_2026.verification_audit.document_fetch_status, "METADATA_VERIFIED_PENDING_LIVE_FETCH")
        self.assertFalse(rec_2026.operative_holding["verified_against_gazette"])
        self.assertFalse(rec_2026.scope_limitations_detail["verified_by_legal_review"])
        self.assertEqual(rec_2026.full_text_verification["retrieved_http_status"], 200)
        self.assertEqual(len(rec_2026.full_text_verification["retrieved_content_sha256"]), 64)

        # Router lookup and citation auditor accept the 2 fully verified new YIBBGK decisions
        lookup_nc = self.router.dispatch(
            "lookup_verified_source_and_precedent",
            {"query": "rekabet yasağı asliye ticaret mahkemesi", "as_of_date": "2026-10-01"},
        )
        self.assertIn("YIBBGK-2023-1-2025-3", [p["precedent_id"] for p in lookup_nc["matched_precedents"]])

        draft_verified = (
            "6098 Sayılı Türk Borçlar Kanunu kapsamındaki iş sonrası rekabet yasağı uyuşmazlıklarında "
            "YİBBGK E. 2023/1, K. 2025/3 kararına göre Asliye Ticaret Mahkemesi görevlidir. "
            "Faiz talepli kısmi davada miktar artırımında YİBBGK E. 2017/8, K. 2019/3 uygulanır."
        )
        audit_ok = verify_response_citations(draft_verified, "2026-10-01", self.sources, self.precedents)
        self.assertTrue(audit_ok.passed, f"Tam doğrulanmış L4 YİBBGK atıfları reddedilmemeli: {audit_ok.flags}")
        self.assertTrue(
            {"YIBBGK-2023-1-2025-3", "YIBBGK-2017-8-2019-3"}.issubset(set(audit_ok.matched_precedent_ids))
        )

        # Citing PENDING_REVIEW YIBBGK-2021-8-2026-1 as active precedent MUST be blocked
        draft_pending = "Kısmi ıslahla yeni bağımsız talep eklenmesi YİBBGK E. 2021/8, K. 2026/1 uyarınca mümkün değildir."
        audit_pending = verify_response_citations(draft_pending, "2026-10-01", self.sources, self.precedents)
        self.assertFalse(audit_pending.passed)
        self.assertIn("UNVERIFIED_PRECEDENT_CITED", audit_pending.blocker_codes)

    def test_uzaktan_calisma_hybrid_article_effective_date_tracking(self) -> None:
        before = self.router.dispatch(
            "check_article_effective_date",
            {
                "source_id": "YONETMELIK-UZAKTAN-CALISMA-20210310",
                "article_ref": "Madde 9/2",
                "as_of_date": "2026-09-01",
            },
        )
        self.assertFalse(before["is_effective"])

        after = self.router.dispatch(
            "check_article_effective_date",
            {
                "source_id": "YONETMELIK-UZAKTAN-CALISMA-20210310",
                "article_ref": "Madde 9/2",
                "as_of_date": "2026-10-01",
            },
        )
        self.assertTrue(after["is_effective"])

    def test_norm_hierarchy_prevents_circular_or_regulation_from_overriding_statute(self) -> None:
        law = NormReference("4857 Sayılı İş Kanunu m.64 (4 Ay Telafi Süresi)", "STATUTORY_LAW", source_id="MEVZUAT-4857")
        reg = NormReference("Çalışma Süreleri Yönetmeliği m.7 (Eski 2 Ay Metni)", "REGULATION", source_id="YONETMELIK-CALISMA-SURELERI-20040406")
        res = resolve_norm_conflict(law, reg, mandatory_type="ABSOLUTE_MANDATORY")
        self.assertEqual(res.winning_side, "NORM_A")
        self.assertEqual(res.rule_applied, "ABSOLUTE_MANDATORY_HIGHER_NORM_PREVAILS")

        sgk_law = NormReference("5510 Sayılı Kanun m.82 (9 Kat Tavan)", "STATUTORY_LAW", source_id="MEVZUAT-5510")
        circ = NormReference("Eski İdari Duyuru/Genelge Yorumu", "COMMUNIQUE_AND_SGK_CIRCULAR")
        res2 = resolve_norm_conflict(sgk_law, circ, mandatory_type="ABSOLUTE_MANDATORY")
        self.assertEqual(res2.winning_side, "NORM_A")
        self.assertEqual(res2.rule_applied, "ABSOLUTE_MANDATORY_HIGHER_NORM_PREVAILS")

    def test_total_39_cards_across_l1_l2_l3_loaded_in_router(self) -> None:
        self.assertEqual(len(self.router.knowledge_cards), 39)
        l2_res = self.router.dispatch(
            "lookup_knowledge_card",
            {"query": "hibrit çalışma 33381 uzaktan çalışma", "as_of_date": "2026-10-15"},
        )
        self.assertIn("CARD-YON-UZAKTAN-CALISMA", [c["card_id"] for c in l2_res["effective_cards"]])

        l3_res = self.router.dispatch(
            "lookup_knowledge_card",
            {"query": "07 puantaj 2020/20 eksik gün", "as_of_date": "2026-10-15"},
        )
        self.assertIn("CARD-SGK-2020-20-ISVEREN", [c["card_id"] for c in l3_res["effective_cards"]])


class TestV102b1VerificationConsistencyAndPresidentialDecision(unittest.TestCase):
    def setUp(self) -> None:
        self.raw_sources = json.loads(SOURCES_PATH.read_text(encoding="utf-8"))
        self.raw_precedents = json.loads(PRECEDENTS_PATH.read_text(encoding="utf-8"))
        self.raw_audit_log = json.loads(AUDIT_LOG_PATH.read_text(encoding="utf-8"))
        self.sources = load_source_registry(SOURCES_PATH, strict=True)
        self.precedents = load_precedent_registry(PRECEDENTS_PATH, source_registry=self.sources, strict=True)
        self.audit_index = load_central_audit_index(AUDIT_LOG_PATH)
        self.cards = load_knowledge_cards(
            KB_ALL_DIR,
            source_registry=self.sources,
            precedent_registry=self.precedents,
            strict=True,
            audit_log_path=AUDIT_LOG_PATH,
        )
        self.router = HukukSGKToolRouter()

    def test_source_validator_blocks_verified_status_without_fetched_and_matched(self) -> None:
        # Positive: actual GIB-TEBLIG-332-20251231 is PENDING_REVIEW and valid
        self.assertEqual(self.sources["GIB-TEBLIG-332-20251231"].verification_status, "PENDING_REVIEW")

        # Negative: forcing VERIFIED while document_fetch_status is METADATA_VERIFIED_PENDING_LIVE_FETCH MUST fail
        mutated = copy.deepcopy(self.raw_sources)
        mutated["sources"]["GIB-TEBLIG-332-20251231"]["verification_status"] = "VERIFIED"
        report = validate_source_registry(mutated)
        self.assertFalse(report.valid)
        self.assertIn("UNVERIFIED_DOCUMENT_ON_VERIFIED_SOURCE", {f.code for f in report.flags})

    def test_precedent_validator_blocks_verified_or_gazette_claim_without_full_text(self) -> None:
        # Negative 1: marking YIBBGK-2021-8-2026-1 as VERIFIED without FETCHED_AND_MATCHED MUST fail
        m1 = copy.deepcopy(self.raw_precedents)
        m1["precedents"]["YIBBGK-2021-8-2026-1"]["verification_status"] = "VERIFIED"
        r1 = validate_precedent_registry(m1, source_registry=self.sources)
        self.assertFalse(r1.valid)
        self.assertIn("UNVERIFIED_FULL_TEXT_ON_VERIFIED_PRECEDENT", {f.code for f in r1.flags})

        # Negative 2: keeping PENDING_REVIEW but claiming verified_against_gazette=True or verified_by_legal_review=True MUST fail
        m2 = copy.deepcopy(self.raw_precedents)
        m2["precedents"]["YIBBGK-2021-8-2026-1"]["operative_holding"]["verified_against_gazette"] = True
        m2["precedents"]["YIBBGK-2021-8-2026-1"]["scope_limitations_detail"]["verified_by_legal_review"] = True
        r2 = validate_precedent_registry(m2, source_registry=self.sources)
        self.assertFalse(r2.valid)
        codes = {f.code for f in r2.flags}
        self.assertIn("FALSE_GAZETTE_VERIFICATION_CLAIM", codes)
        self.assertIn("FALSE_FULL_VERIFICATION_CLAIM_WITHOUT_FULL_TEXT", codes)

    def test_card_validator_blocks_verified_claims_on_pending_parent_source_and_audit_status_mismatch(self) -> None:
        raw_332 = json.loads((KB_CIRCULARS_DIR / "03_gib_332_2026_tarife_ve_istisnalar.json").read_text(encoding="utf-8"))
        # Positive: honest PENDING_LEGAL_REVIEW card passes validation
        ok_rep = validate_knowledge_card_file(
            raw_332, self.sources, self.precedents, "03_gib_332", central_audit_index=self.audit_index
        )
        self.assertTrue(ok_rep.valid, ok_rep.flags)

        # Negative: claiming VERIFIED / source_verification=VERIFIED / legal_interpretation=VERIFIED / effective_date_verified=True
        # while parent GIB-TEBLIG-332-20251231 is PENDING_REVIEW MUST fail with every consistency blocker
        mutated = copy.deepcopy(raw_332)
        c = mutated["cards"][0]
        c["verification_status"] = "VERIFIED"
        c["effective_validity"]["effective_date_verified"] = True
        c["source_verification"]["status"] = "VERIFIED"
        c["legal_interpretation_verification"]["status"] = "VERIFIED"
        bad_rep = validate_knowledge_card_file(
            mutated, self.sources, self.precedents, "mutated_332", central_audit_index=self.audit_index
        )
        self.assertFalse(bad_rep.valid)
        codes = {f.code for f in bad_rep.flags}
        self.assertIn("INACTIVE_PARENT_SOURCE_ON_VERIFIED_CARD", codes)
        self.assertIn("EFFECTIVE_DATE_VERIFIED_ON_NON_VERIFIED_PARENT", codes)
        self.assertIn("SOURCE_VERIFICATION_CLAIMED_ON_NON_VERIFIED_PARENT", codes)
        self.assertIn("LEGAL_INTERPRETATION_VERIFIED_WITHOUT_VERIFIED_SOURCE", codes)
        self.assertIn("CENTRAL_AUDIT_STATUS_MISMATCH", codes)

    def test_pending_records_excluded_from_active_lookup_and_blocked_in_citation_auditor(self) -> None:
        # 1. GIB-TEBLIG-332-20251231 excluded from effective_sources
        eff = resolve_effective_sources(self.sources, as_of_date="2026-04-01", include_superseded=True)
        self.assertNotIn("GIB-TEBLIG-332-20251231", {s.source_id for s in eff["effective_sources"]})
        self.assertIn("GIB-TEBLIG-332-20251231", {s.source_id for s in eff["inactive_or_superseded_sources"]})

        # 2. CARD-GIB-332-2026-TARIFE excluded from effective_cards and reported in not_effective_on_date_cards
        card_q = query_knowledge_cards(self.cards, "332 tebliğ 300 tl yemek 2026 tarife", as_of_date="2026-04-01")
        self.assertNotIn("CARD-GIB-332-2026-TARIFE", [c["card_id"] for c in card_q["effective_cards"]])
        self.assertIn("CARD-GIB-332-2026-TARIFE", [c["card_id"] for c in card_q["not_effective_on_date_cards"]])

        # 3. YIBBGK-2021-8-2026-1 excluded from matched_precedents even with include_superseded=True
        prec_q = self.router.dispatch(
            "lookup_verified_source_and_precedent",
            {"query": "kısmi ıslah yeni talep 2021/8 2026/1", "as_of_date": "2026-10-01", "include_superseded": True},
        )
        self.assertNotIn("YIBBGK-2021-8-2026-1", [p["precedent_id"] for p in prec_q["matched_precedents"]])
        self.assertIn("YIBBGK-2021-8-2026-1", [p["precedent_id"] for p in prec_q["inactive_or_pending_precedents"]])

        # 4. Citing GIB-TEBLIG-332 in prose or cited_source_ids MUST be blocked with UNVERIFIED_SOURCE_CITED
        audit_text = verify_response_citations(
            "332 Seri No.lu Gelir Vergisi Genel Tebliği uyarınca 2026 yemek istisnası 300 TL'dir.",
            as_of_date="2026-04-01",
            source_registry=self.sources,
            precedent_registry=self.precedents,
        )
        self.assertFalse(audit_text.passed)
        self.assertIn("UNVERIFIED_SOURCE_CITED", audit_text.blocker_codes)

        audit_id = verify_response_citations(
            "193 Sayılı Gelir Vergisi Kanunu kapsamındadır.",
            as_of_date="2026-04-01",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            cited_source_ids=["GIB-TEBLIG-332-20251231"],
        )
        self.assertFalse(audit_id.passed)
        self.assertIn("UNVERIFIED_SOURCE_CITED", audit_id.blocker_codes)

    def test_central_audit_log_separates_74_records_from_70_verified_and_blocks_inconsistencies(self) -> None:
        # Positive: real verification_audit_log.json passes full cross-reference validation
        ok_rep = validate_central_audit_log(self.raw_audit_log, self.sources, self.precedents, self.cards)
        self.assertTrue(ok_rep.valid, ok_rep.flags)
        self.assertEqual(ok_rep.total_records, 74)
        self.assertEqual(ok_rep.verified_count, 70)

        # Negative: falsifying GIB-TEBLIG-332 audit entry to VERIFIED and inflating summary MUST fail
        tampered = copy.deepcopy(self.raw_audit_log)
        for entry in tampered["entries"]:
            if entry["record_id"] == "GIB-TEBLIG-332-20251231":
                entry["record_verification_status"] = "VERIFIED"
        tampered["summary"]["verified_legal_sources_count"] = 29
        bad_rep = validate_central_audit_log(tampered, self.sources, self.precedents, self.cards)
        self.assertFalse(bad_rep.valid)
        codes = {f.code for f in bad_rep.flags}
        self.assertIn("AUDIT_LOG_VERIFIED_WITHOUT_FULL_TEXT", codes)
        self.assertIn("CENTRAL_AUDIT_STATUS_MISMATCH", codes)
        self.assertIn("AUDIT_LOG_SUMMARY_MISMATCH", codes)

    def test_presidential_decision_vs_presidential_decree_hierarchy_and_registry_validation(self) -> None:
        # Positive: normative hierarchy distinguishes PRESIDENTIAL_DECREE (4) vs PRESIDENTIAL_DECISION (5)
        self.assertEqual(NORM_LAYER_PRIORITY["CONSTITUTION"], 1)
        self.assertEqual(NORM_LAYER_PRIORITY["INTERNATIONAL_TREATY_FUNDAMENTAL_RIGHTS"], 2)
        self.assertEqual(NORM_LAYER_PRIORITY["STATUTORY_LAW"], 3)
        self.assertEqual(NORM_LAYER_PRIORITY["INTERNATIONAL_TREATY_GENERAL"], 3)
        self.assertEqual(NORM_LAYER_PRIORITY["PRESIDENTIAL_DECREE"], 4)
        self.assertEqual(NORM_LAYER_PRIORITY["PRESIDENTIAL_DECISION"], 5)
        self.assertEqual(NORM_LAYER_PRIORITY["REGULATION"], 6)
        self.assertEqual(NORM_LAYER_PRIORITY["COMMUNIQUE_AND_SGK_CIRCULAR"], 7)
        self.assertEqual(NORM_LAYER_PRIORITY["CBA_CONTRACT_AND_HR_PROCEDURE"], 8)
        self.assertNotIn("YARGITAY_PRECEDENT", NORM_LAYER_PRIORITY)

        # Conflict resolution: CBK (PRESIDENTIAL_DECREE) prevails over Cumhurbaşkanı Kararı (PRESIDENTIAL_DECISION)
        decree = NormReference("Örnek Cumhurbaşkanlığı Kararnamesi (CBK)", "PRESIDENTIAL_DECREE")
        decision = NormReference("10766 Sayılı Cumhurbaşkanı Kararı", "PRESIDENTIAL_DECISION", source_id="RG-10766-20251225")
        reg = NormReference("Uzaktan Çalışma Yönetmeliği", "REGULATION", source_id="YONETMELIK-UZAKTAN-CALISMA-20210310")
        law = NormReference("5746 Sayılı Kanun", "STATUTORY_LAW", source_id="MEVZUAT-5746")

        r_decree_vs_dec = resolve_norm_conflict(decree, decision, mandatory_type="ABSOLUTE_MANDATORY")
        self.assertEqual(r_decree_vs_dec.winning_side, "NORM_A")

        r_law_vs_dec = resolve_norm_conflict(law, decision, mandatory_type="ABSOLUTE_MANDATORY")
        self.assertEqual(r_law_vs_dec.winning_side, "NORM_A")

        r_dec_vs_reg = resolve_norm_conflict(decision, reg, mandatory_type="ABSOLUTE_MANDATORY")
        self.assertEqual(r_dec_vs_reg.winning_side, "NORM_A")

        # Positive: 10766 and 9368 are classified as PRESIDENTIAL_DECISION (priority 5) and CARD-CK-10766-2026 uses CK-10766
        for sid in ("RG-10766-20251225", "RG-9368-20241228"):
            self.assertEqual(self.sources[sid].source_type, "PRESIDENTIAL_DECISION")
            self.assertEqual(self.sources[sid].norm_layer, "PRESIDENTIAL_DECISION")
            self.assertEqual(self.sources[sid].norm_priority, 5)
            self.assertNotIn("cbk", [k.lower() for k in self.sources[sid].keywords])
        card_ck = self.cards["CARD-CK-10766-2026"]
        self.assertEqual(card_ck.law_no, "CK-10766")
        self.assertEqual(card_ck.verification_audit["audit_log_id"], "AUD-20261120-CARDCK10766")

        # Negative: misclassifying 10766 as PRESIDENTIAL_DECREE MUST be blocked
        mutated = copy.deepcopy(self.raw_sources)
        mutated["sources"]["RG-10766-20251225"]["source_type"] = "PRESIDENTIAL_DECREE"
        mutated["sources"]["RG-10766-20251225"]["norm_layer"] = "PRESIDENTIAL_DECREE"
        mutated["sources"]["RG-10766-20251225"]["norm_priority"] = 4
        bad_rep = validate_source_registry(mutated)
        self.assertFalse(bad_rep.valid)
        self.assertIn("PRESIDENTIAL_NORM_TYPE_MISCLASSIFICATION", {f.code for f in bad_rep.flags})

        # Negative: mismatched source_type vs norm_layer MUST be blocked
        mutated_mismatch = copy.deepcopy(self.raw_sources)
        mutated_mismatch["sources"]["RG-10766-20251225"]["source_type"] = "PRESIDENTIAL_DECREE"
        bad_mismatch = validate_source_registry(mutated_mismatch)
        self.assertFalse(bad_mismatch.valid)
        self.assertIn("SOURCE_TYPE_NORM_LAYER_MISMATCH", {f.code for f in bad_mismatch.flags})

    def test_citation_auditor_blocks_mislabeling_presidential_decision_as_cbk_and_allows_correct_title(self) -> None:
        # Positive: accurate title "10766 Sayılı Cumhurbaşkanı Kararı" passes
        ok_audit = verify_response_citations(
            "2026 yılı teknokent uzaktan çalışma oranları 10766 Sayılı Cumhurbaşkanı Kararı uyarınca uygulanır.",
            as_of_date="2026-04-01",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            cited_source_ids=["RG-10766-20251225"],
        )
        self.assertTrue(ok_audit.passed, ok_audit.flags)
        self.assertIn("RG-10766-20251225", ok_audit.matched_source_ids)

        # Negative: mislabeling 10766 or 9368 as CBK / Cumhurbaşkanlığı Kararnamesi MUST fail
        for bad_draft in (
            "2026 yılında 10766 Sayılı CBK uyarınca bilişim personeli %100 uzaktan çalışır.",
            "10766 Sayılı Cumhurbaşkanlığı Kararnamesi ile 2026 oranları belirlendi.",
            "9368 Sayılı CBK 2025 yılında yürürlükteydi.",
        ):
            with self.subTest(bad_draft=bad_draft):
                res = verify_response_citations(bad_draft, "2026-04-01", self.sources, self.precedents)
                self.assertFalse(res.passed)
                self.assertIn("NORM_TYPE_MISMATCH_DECREE_VS_DECISION", res.blocker_codes)

        # Negative: claiming Cumhurbaşkanı Kararı overrides statutory law MUST fail
        sub_bad = verify_response_citations(
            "Cumhurbaşkanı kararı 5746 Sayılı Kanun hükmünü bertaraf eder.",
            "2026-04-01",
            self.sources,
            self.precedents,
        )
        self.assertFalse(sub_bad.passed)
        self.assertIn("OVERBROAD_LEGAL_CLAIM_SECONDARY_OVERRIDES_STATUTE", sub_bad.blocker_codes)

    def test_schemas_and_taxonomy_enforce_verification_consistency_and_presidential_decision_type(self) -> None:
        src_schema = json.loads(SOURCE_SCHEMA_PATH.read_text(encoding="utf-8"))
        rec_def = src_schema["$defs"]["legalSourceRecord"]
        self.assertIn("PRESIDENTIAL_DECISION", rec_def["properties"]["source_type"]["enum"])
        self.assertIn("PRESIDENTIAL_DECISION", rec_def["properties"]["norm_layer"]["enum"])
        self.assertEqual(rec_def["properties"]["norm_priority"]["maximum"], 8)
        self.assertIn("allOf", rec_def)

        prec_schema = json.loads(PRECEDENT_SCHEMA_PATH.read_text(encoding="utf-8"))
        prec_def = prec_schema["$defs"]["precedentRecord"]
        self.assertIn("PENDING_REVIEW", prec_def["properties"]["verification_status"]["enum"])
        self.assertEqual(len(prec_def.get("allOf", [])), 2)

        card_schema = json.loads(CARD_SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(len(card_schema["$defs"]["knowledgeCard"].get("allOf", [])), 2)

        tax = json.loads(TAXONOMY_PATH.read_text(encoding="utf-8"))
        self.assertEqual(len(tax["norm_hierarchy"]), 9)
        hierarchy_map = {h["layer"]: h["priority"] for h in tax["norm_hierarchy"]}
        self.assertEqual(hierarchy_map["PRESIDENTIAL_DECREE"], 4)
        self.assertEqual(hierarchy_map["PRESIDENTIAL_DECISION"], 5)

        tools = json.loads(TOOLS_SCHEMA_PATH.read_text(encoding="utf-8"))
        resolve_tool = next(t for t in tools["tools"] if t["name"] == "resolve_norm_conflict")
        self.assertIn(
            "PRESIDENTIAL_DECISION",
            resolve_tool["parameters"]["properties"]["norm_a"]["properties"]["norm_layer"]["enum"],
        )


class TestV102b2ConstitutionalHierarchyAndPrecedentApplicationModel(unittest.TestCase):
    def setUp(self) -> None:
        self.raw_sources = json.loads(SOURCES_PATH.read_text(encoding="utf-8"))
        self.sources = load_source_registry(SOURCES_PATH, strict=True)
        self.precedents = load_precedent_registry(PRECEDENTS_PATH, source_registry=self.sources, strict=True)
        self.router = HukukSGKToolRouter()

    def test_constitution_is_strictly_above_all_international_treaties_and_ilo_conventions(self) -> None:
        self.assertNotIn("CONSTITUTION_AND_ILO", NORM_LAYER_PRIORITY)
        self.assertNotIn("CONSTITUTION_AND_ILO", ALL_CONFLICT_EVALUATION_LAYERS)
        self.assertEqual(NORM_LAYER_PRIORITY["CONSTITUTION"], 1)
        self.assertEqual(NORM_LAYER_PRIORITY["INTERNATIONAL_TREATY_FUNDAMENTAL_RIGHTS"], 2)
        self.assertEqual(NORM_LAYER_PRIORITY["STATUTORY_LAW"], 3)
        self.assertEqual(NORM_LAYER_PRIORITY["INTERNATIONAL_TREATY_GENERAL"], 3)

        const = NormReference("Türkiye Cumhuriyeti Anayasası", "CONSTITUTION")
        fund_treaty = NormReference(
            "87 Sayılı ILO Sendika Özgürlüğü Sözleşmesi (Anayasa m.90/son)",
            "INTERNATIONAL_TREATY_FUNDAMENTAL_RIGHTS",
        )
        gen_treaty = NormReference(
            "İkili Sosyal Güvenlik Sözleşmesi / Teknik ILO Sözleşmesi (Anayasa m.90/5)",
            "INTERNATIONAL_TREATY_GENERAL",
        )

        res1 = resolve_norm_conflict(const, fund_treaty, mandatory_type="ABSOLUTE_MANDATORY")
        self.assertEqual(res1.winning_side, "NORM_A")
        self.assertEqual(res1.rule_applied, "CONSTITUTION_SUPREMACY_ANAYASA_M11")
        self.assertFalse(res1.requires_counsel_escalation)

        res2 = resolve_norm_conflict(gen_treaty, const, mandatory_type="ABSOLUTE_MANDATORY")
        self.assertEqual(res2.winning_side, "NORM_B")
        self.assertEqual(res2.rule_applied, "CONSTITUTION_SUPREMACY_ANAYASA_M11")
        self.assertFalse(res2.requires_counsel_escalation)

    def test_anayasa_m90_son_fundamental_rights_treaty_prevails_over_restrictive_statute_and_preserves_more_favorable_statute(self) -> None:
        ilo_87 = NormReference(
            "87 Sayılı ILO Sözleşmesi (Örgütlenme ve Sendika Özgürlüğü — Temel Hak)",
            "INTERNATIONAL_TREATY_FUNDAMENTAL_RIGHTS",
        )
        statute = NormReference("6356 Sayılı Kanun İlgili Hükmü", "STATUTORY_LAW", source_id="MEVZUAT-6356")
        gen_treaty = NormReference("Genel Teknik Uluslararası Antlaşma", "INTERNATIONAL_TREATY_GENERAL")

        # 1. Restrictive domestic statute conflicts with fundamental-rights treaty -> treaty prevails (Anayasa m.90/5 son cümle)
        res_treaty = resolve_norm_conflict(
            ilo_87, statute, mandatory_type="RELATIVE_EMPLOYEE_FAVORABLE", favors_employee_side="NORM_A"
        )
        self.assertEqual(res_treaty.winning_side, "NORM_A")
        self.assertEqual(res_treaty.rule_applied, "ANAYASA_M90_SON_FUNDAMENTAL_RIGHTS_TREATY_PREVAILS")
        self.assertFalse(res_treaty.requires_counsel_escalation)

        # 2. Domestic statute provides HIGHER worker protection than international floor -> domestic statute preserved when explicitly MINIMUM_STANDARD_FLOOR
        res_domestic_better = resolve_norm_conflict(
            ilo_87,
            statute,
            mandatory_type="RELATIVE_EMPLOYEE_FAVORABLE",
            favors_employee_side="NORM_B",
            treaty_provision_nature="MINIMUM_STANDARD_FLOOR",
        )
        self.assertEqual(res_domestic_better.winning_side, "NORM_B")
        self.assertEqual(res_domestic_better.rule_applied, "ANAYASA_M90_MORE_FAVORABLE_DOMESTIC_STATUTE_PRESERVED")
        self.assertFalse(res_domestic_better.requires_counsel_escalation)

        # 3. Fundamental-rights treaty vs general treaty (statutory level) -> fundamental-rights treaty prevails
        res_vs_gen = resolve_norm_conflict(ilo_87, gen_treaty, mandatory_type="ABSOLUTE_MANDATORY")
        self.assertEqual(res_vs_gen.winning_side, "NORM_A")
        self.assertEqual(res_vs_gen.rule_applied, "ANAYASA_M90_SON_FUNDAMENTAL_RIGHTS_TREATY_PREVAILS")

    def test_anayasa_m90_general_international_treaty_is_statutory_level_and_escalates_on_statute_conflict(self) -> None:
        gen_treaty = NormReference(
            "Teknik ILO / İkili Sosyal Güvenlik Antlaşması (Anayasa m.90/5 cümle 1)",
            "INTERNATIONAL_TREATY_GENERAL",
        )
        statute = NormReference("5510 Sayılı SSGSS Kanunu", "STATUTORY_LAW", source_id="MEVZUAT-5510")
        reg = NormReference("Sosyal Sigorta İşlemleri Yönetmeliği", "REGULATION", source_id="YONETMELIK-SSIY-20100512")

        # Negative guard: general treaty does NOT automatically override statute -> escalates for lex specialis/posterior/m.90 review
        res_stat = resolve_norm_conflict(gen_treaty, statute, mandatory_type="ABSOLUTE_MANDATORY")
        self.assertEqual(res_stat.winning_side, "UNRESOLVED_ESCALATE")
        self.assertEqual(res_stat.rule_applied, "ANAYASA_M90_STATUTORY_EQUIVALENT_TREATY_CONFLICT_ESCALATE")
        self.assertTrue(res_stat.requires_counsel_escalation)

        # Positive: general treaty (kanun hükmünde) still prevails over lower regulation
        res_reg = resolve_norm_conflict(gen_treaty, reg, mandatory_type="ABSOLUTE_MANDATORY")
        self.assertEqual(res_reg.winning_side, "NORM_A")
        self.assertEqual(res_reg.rule_applied, "ABSOLUTE_MANDATORY_HIGHER_NORM_PREVAILS")

    def test_source_validator_blocks_treaty_classified_as_constitution_and_precedent_as_legislative_source(self) -> None:
        # Negative 1: ILO / international treaty classified as CONSTITUTION MUST fail
        m1 = copy.deepcopy(self.raw_sources)
        sample = copy.deepcopy(m1["sources"]["MEVZUAT-4857"])
        sample["source_id"] = "ILO-SOZLESME-87"
        sample["source_title"] = "87 Sayılı ILO Sendika Özgürlüğü ve Örgütlenme Hakkı Sözleşmesi"
        sample["legal_reference"] = "87 Sayılı ILO Sözleşmesi"
        sample["source_type"] = "CONSTITUTION"
        sample["norm_layer"] = "CONSTITUTION"
        sample["norm_priority"] = 1
        m1["sources"]["ILO-SOZLESME-87"] = sample
        r1 = validate_source_registry(m1)
        self.assertFalse(r1.valid)
        self.assertIn("TREATY_CLASSIFIED_AS_CONSTITUTION", {f.code for f in r1.flags})

        # Negative 2: YARGITAY_PRECEDENT placed in legal_sources_registry MUST fail
        m2 = copy.deepcopy(self.raw_sources)
        m2["sources"]["MEVZUAT-4857"]["norm_layer"] = "YARGITAY_PRECEDENT"
        r2 = validate_source_registry(m2)
        self.assertFalse(r2.valid)
        self.assertIn("PRECEDENT_CLASSIFIED_AS_LEGISLATIVE_SOURCE", {f.code for f in r2.flags})

    def test_yargitay_precedent_not_in_legislative_hierarchy_and_cannot_auto_beat_cba_or_statute(self) -> None:
        self.assertNotIn("YARGITAY_PRECEDENT", NORM_LAYER_PRIORITY)
        self.assertIn("YARGITAY_PRECEDENT", JUDICIAL_INTERPRETATION_LAYERS)

        yibbgk = NormReference(
            "YİBBGK E. 2017/9, K. 2018/10",
            "YARGITAY_PRECEDENT",
            precedent_level="STATUTORY_BINDING_YIBBGK",
            source_id="YIBBGK-2017-9-2018-10",
        )
        cba = NormReference("Toplu İş Sözleşmesi (m.25/I-b Öncesi Yazılı Savunma Garantisi)", "CBA_CONTRACT_AND_HR_PROCEDURE")
        circular = NormReference("SGK Genelgesi", "COMMUNIQUE_AND_SGK_CIRCULAR")

        # Negative 1: YİBBGK vs CBA MUST NOT declare precedent winner by numeric tier (old buggy 7 > 8)
        r_cba = resolve_norm_conflict(yibbgk, cba, mandatory_type="RELATIVE_EMPLOYEE_FAVORABLE", favors_employee_side="NORM_B")
        self.assertEqual(r_cba.winning_side, "UNRESOLVED_ESCALATE")
        self.assertEqual(r_cba.rule_applied, "PRECEDENT_NOT_LEGISLATIVE_NORM_EVALUATE_UNDERLYING_STATUTE_AND_SCOPE")
        self.assertTrue(r_cba.requires_counsel_escalation)
        self.assertIn("2797", r_cba.explanation)

        # Negative 2: Circular vs YİBBGK MUST NOT declare circular winner by numeric tier (old buggy 6 > 7)
        r_circ = resolve_norm_conflict(circular, yibbgk, mandatory_type="ABSOLUTE_MANDATORY")
        self.assertEqual(r_circ.winning_side, "UNRESOLVED_ESCALATE")
        self.assertEqual(r_circ.rule_applied, "PRECEDENT_NOT_LEGISLATIVE_NORM_EVALUATE_UNDERLYING_STATUTE_AND_SCOPE")
        self.assertTrue(r_circ.requires_counsel_escalation)

        # Positive: Precedent vs Precedent still resolves via 2797 s. Kanun m.45
        chamber = NormReference("9. HD Eski Daire Kararı", "YARGITAY_PRECEDENT", precedent_level="CHAMBER_SETTLED")
        r_prec = resolve_norm_conflict(yibbgk, chamber, mandatory_type="ABSOLUTE_MANDATORY")
        self.assertEqual(r_prec.winning_side, "NORM_A")
        self.assertEqual(r_prec.rule_applied, "PRECEDENT_HIERARCHY_YIBBGK_SUPREMACY")
        self.assertIn("2797", r_prec.explanation)
        self.assertIn("m.45", r_prec.explanation)

    def test_evaluate_precedent_application_preserves_employee_favorable_cba_over_yibbgk_statutory_floor(self) -> None:
        # YİBBGK-2017-9-2018-10 holds 4857 m.25/I-b does not require prior defense by law;
        # however, an employee-favorable TİS clause explicitly requiring written defense & board hearing prevails!
        cba_defense = NormReference(
            "TİS m.42 (4857 m.25/I-b Feshinden Önce Zorunlu Yazılı Savunma ve Disiplin Kurulu)",
            "CBA_CONTRACT_AND_HR_PROCEDURE",
        )
        res = evaluate_precedent_application(
            precedent=self.precedents["YIBBGK-2017-9-2018-10"],
            interpreted_source=self.sources["MEVZUAT-4857"],
            as_of_date="2026-05-01",
            scope_match_status="IN_SCOPE",
            competing_norm=cba_defense,
            mandatory_type="RELATIVE_EMPLOYEE_FAVORABLE",
            favors_employee_side="COMPETING_NORM",
            dispute_context="Sağlık nedeniyle derhal fesihte TİS savunma güvencesi",
        )
        self.assertTrue(res.precedent_applicable_to_statute)
        self.assertEqual(res.binding_nature, "BINDING_JUDICIAL_UNIFICATION_2797_M45")
        self.assertIn("2797", res.binding_basis)
        self.assertEqual(res.effective_outcome, "COMPETING_NORM_PREVAILS")
        self.assertIsNotNone(res.underlying_norm_resolution)
        self.assertEqual(
            res.underlying_norm_resolution.rule_applied,
            "RELATIVE_MANDATORY_EMPLOYEE_FAVORABLE_LOWER_NORM_PREVAILS",
        )
        self.assertFalse(res.requires_counsel_escalation)

    def test_evaluate_precedent_application_enforces_absolute_mandatory_statute_and_router_roundtrip(self) -> None:
        # YİBBGK-2023-1-2025-3 (6098 TBK post-employment non-compete -> Asliye Ticaret Mahkemesi; kamu düzeni / mutlak emredici)
        res = self.router.dispatch(
            "evaluate_precedent_application",
            {
                "precedent_id": "YIBBGK-2023-1-2025-3",
                "interpreted_source_id": "MEVZUAT-6098",
                "as_of_date": "2026-06-01",
                "scope_match_status": "IN_SCOPE",
                "competing_norm": {
                    "title": "İş Sözleşmesi Yetki/Görev Maddesi (İş Mahkemesi)",
                    "norm_layer": "CBA_CONTRACT_AND_HR_PROCEDURE",
                },
                "mandatory_type": "ABSOLUTE_MANDATORY",
                "favors_employee_side": "NEUTRAL",
                "dispute_context": "İş sözleşmesi sonrası rekabet yasağı ihlali davası görevli mahkeme",
            },
        )
        self.assertTrue(res["precedent_applicable_to_statute"])
        self.assertEqual(res["binding_nature"], "BINDING_JUDICIAL_UNIFICATION_2797_M45")
        self.assertEqual(res["effective_outcome"], "UNDERLYING_STATUTE_WITH_PRECEDENT_PREVAILS")
        self.assertEqual(
            res["underlying_norm_resolution"]["rule_applied"],
            "ABSOLUTE_MANDATORY_HIGHER_NORM_PREVAILS",
        )
        self.assertFalse(res["requires_counsel_escalation"])

    def test_evaluate_precedent_application_blocks_unverified_out_of_scope_uncertain_anchor_mismatch_and_post_amendment(self) -> None:
        # 1. Unverified / PENDING_REVIEW precedent (YIBBGK-2021-8-2026-1) -> blocked & escalated
        r_unver = evaluate_precedent_application(
            precedent=self.precedents["YIBBGK-2021-8-2026-1"],
            interpreted_source=self.sources["MEVZUAT-7036"],
            as_of_date="2026-10-01",
            scope_match_status="IN_SCOPE",
        )
        self.assertFalse(r_unver.precedent_applicable_to_statute)
        self.assertEqual(r_unver.binding_nature, "UNVERIFIED_OR_BLOCKED")
        self.assertEqual(r_unver.effective_outcome, "ESCALATE_TO_LEGAL_COUNSEL")
        self.assertTrue(r_unver.requires_counsel_escalation)

        # 2. OUT_OF_SCOPE (applying m.25/I-b YİBBGK to m.18 geçerli fesih) -> NOT applicable
        r_out = evaluate_precedent_application(
            precedent=self.precedents["YIBBGK-2017-9-2018-10"],
            interpreted_source=self.sources["MEVZUAT-4857"],
            as_of_date="2026-05-01",
            scope_match_status="OUT_OF_SCOPE",
        )
        self.assertFalse(r_out.precedent_applicable_to_statute)
        self.assertEqual(r_out.effective_outcome, "PRECEDENT_NOT_APPLICABLE")
        self.assertFalse(r_out.requires_counsel_escalation)

        # 3. UNCERTAIN scope -> escalate
        r_unc = evaluate_precedent_application(
            precedent=self.precedents["YIBBGK-2017-9-2018-10"],
            interpreted_source=self.sources["MEVZUAT-4857"],
            as_of_date="2026-05-01",
            scope_match_status="UNCERTAIN",
        )
        self.assertFalse(r_unc.precedent_applicable_to_statute)
        self.assertEqual(r_unc.effective_outcome, "ESCALATE_TO_LEGAL_COUNSEL")
        self.assertTrue(r_unc.requires_counsel_escalation)

        # 4. Statutory anchor mismatch (MEVZUAT-5510 is not in YIBBGK-2017-9-2018-10.related_source_ids)
        r_anchor = evaluate_precedent_application(
            precedent=self.precedents["YIBBGK-2017-9-2018-10"],
            interpreted_source=self.sources["MEVZUAT-5510"],
            as_of_date="2026-05-01",
            scope_match_status="IN_SCOPE",
        )
        self.assertFalse(r_anchor.precedent_applicable_to_statute)
        self.assertEqual(r_anchor.effective_outcome, "PRECEDENT_NOT_APPLICABLE")
        self.assertTrue(r_anchor.requires_counsel_escalation)

        # 5. Post-decision statutory amendment after 2018-10-19 -> escalate for counsel check
        amended_4857 = replace(
            self.sources["MEVZUAT-4857"],
            amendment_history=self.sources["MEVZUAT-4857"].amendment_history
            + (
                AmendmentRecord(
                    amending_law_no="TEST-9999",
                    official_gazette_no="33999",
                    publication_date="2026-02-01",
                    affected_articles=("Madde 25",),
                    effective_from="2026-03-01",
                    summary="Test amaçlı karar sonrası m.25 değişikliği.",
                ),
            ),
        )
        r_amend = evaluate_precedent_application(
            precedent=self.precedents["YIBBGK-2017-9-2018-10"],
            interpreted_source=amended_4857,
            as_of_date="2026-05-01",
            scope_match_status="IN_SCOPE",
        )
        self.assertFalse(r_amend.precedent_applicable_to_statute)
        self.assertEqual(r_amend.effective_outcome, "ESCALATE_TO_LEGAL_COUNSEL")
        self.assertTrue(r_amend.post_decision_amendments)
        self.assertTrue(r_amend.requires_counsel_escalation)

    def test_citation_auditor_blocks_ilo_equals_constitution_and_precedent_as_legislative_norm_claims(self) -> None:
        bad_cases = [
            (
                "Tüm ILO sözleşmeleri Anayasa ile aynı seviyededir.",
                "OVERBROAD_LEGAL_CLAIM_ILO_EQUALS_CONSTITUTION",
            ),
            (
                "Bütün ILO sözleşmeleri kanunlardan otomatik olarak üstündür.",
                "OVERBROAD_LEGAL_CLAIM_ILO_EQUALS_CONSTITUTION",
            ),
            (
                "Uluslararası sözleşmeler Anayasa ile eşittir.",
                "OVERBROAD_LEGAL_CLAIM_ILO_EQUALS_CONSTITUTION",
            ),
            (
                "YİBBGK kararı kanun veya yönetmelik gibi bir mevzuat katmanıdır.",
                "OVERBROAD_LEGAL_CLAIM_PRECEDENT_AS_LEGISLATIVE_NORM",
            ),
            (
                "YİBBGK kararı işçi lehine TİS hükmünü otomatik olarak geçersiz kılar.",
                "OVERBROAD_LEGAL_CLAIM_PRECEDENT_AS_LEGISLATIVE_NORM",
            ),
        ]
        for draft, expected_code in bad_cases:
            with self.subTest(draft=draft, expected_code=expected_code):
                res = verify_response_citations(draft, "2026-05-01", self.sources, self.precedents)
                self.assertFalse(res.passed)
                self.assertIn(expected_code, res.blocker_codes)

        good_draft = (
            "Tüm ILO sözleşmeleri Anayasa ile aynı seviyededir denilemez; Anayasa m.90/5 uyarınca uluslararası antlaşmalar "
            "kural olarak kanun hükmündedir ve kanunlarla çatışmada özel öncelik yalnızca temel hak ve özgürlüklere ilişkin "
            "antlaşmalar içindir. YİBBGK kararı kanun veya yönetmelik gibi bir mevzuat katmanıdır denilemez; bağlayıcılığı "
            "Yargıtay Kanunu m.45 içtihadı birleştirme etkisinden doğar ve 4857 Sayılı İş Kanunu kapsamıyla birlikte değerlendirilir."
        )
        ok_res = verify_response_citations(good_draft, "2026-05-01", self.sources, self.precedents)
        self.assertTrue(ok_res.passed, ok_res.flags)

    def test_v102b2_schemas_taxonomy_and_tool_schemas_reflect_constitutional_and_precedent_model(self) -> None:
        src_schema = json.loads(SOURCE_SCHEMA_PATH.read_text(encoding="utf-8"))
        rec_def = src_schema["$defs"]["legalSourceRecord"]
        st_enum = rec_def["properties"]["source_type"]["enum"]
        nl_enum = rec_def["properties"]["norm_layer"]["enum"]
        self.assertNotIn("CONSTITUTION_OR_ILO", st_enum)
        self.assertNotIn("CONSTITUTION_AND_ILO", nl_enum)
        self.assertNotIn("YARGITAY_PRECEDENT", nl_enum)
        for expected in ("CONSTITUTION", "INTERNATIONAL_TREATY_FUNDAMENTAL_RIGHTS", "INTERNATIONAL_TREATY_GENERAL"):
            self.assertIn(expected, st_enum)
            self.assertIn(expected, nl_enum)

        tax = json.loads(TAXONOMY_PATH.read_text(encoding="utf-8"))
        tax_layers = [h["layer"] for h in tax["norm_hierarchy"]]
        self.assertNotIn("CONSTITUTION_AND_ILO", tax_layers)
        self.assertNotIn("YARGITAY_PRECEDENT", tax_layers)
        self.assertIn("CONSTITUTION", tax_layers)
        self.assertIn("INTERNATIONAL_TREATY_FUNDAMENTAL_RIGHTS", tax_layers)
        self.assertIn("INTERNATIONAL_TREATY_GENERAL", tax_layers)
        self.assertIn("judicial_precedent_application_model", tax)
        self.assertFalse(tax["judicial_precedent_application_model"]["is_legislative_norm_layer"])
        self.assertIn("2797", tax["judicial_precedent_application_model"]["statutory_binding_basis"])

        tools = json.loads(TOOLS_SCHEMA_PATH.read_text(encoding="utf-8"))
        tool_names = {t["name"] for t in tools["tools"]}
        self.assertIn("evaluate_precedent_application", tool_names)


class TestV102cLegalReasoningAndCarryoverHardening(unittest.TestCase):
    def setUp(self) -> None:
        self.sources = load_source_registry(SOURCES_PATH, strict=True)
        self.precedents = load_precedent_registry(PRECEDENTS_PATH, source_registry=self.sources, strict=True)
        self.cards = load_knowledge_cards(
            KB_ALL_DIR,
            source_registry=self.sources,
            precedent_registry=self.precedents,
            strict=True,
            audit_log_path=AUDIT_LOG_PATH,
        )
        self.router = HukukSGKToolRouter()

    def test_anayasa_m90_treaty_provision_nature_prevents_automatic_domestic_override_when_unspecified_or_direct_rule(self) -> None:
        treaty = NormReference(
            "Temel Haklara İlişkin Uluslararası Sözleşme Hükmü (Anayasa m.90/son)",
            "INTERNATIONAL_TREATY_FUNDAMENTAL_RIGHTS",
        )
        statute = NormReference("4857 Sayılı İş Kanunu İlgili Hükmü", "STATUTORY_LAW", source_id="MEVZUAT-4857")

        # 1. Negative guard: favors_employee_side=NORM_B alone MUST NOT auto-preserve domestic statute when treaty_provision_nature is UNSPECIFIED
        r_unspec = resolve_norm_conflict(
            treaty,
            statute,
            mandatory_type="RELATIVE_EMPLOYEE_FAVORABLE",
            favors_employee_side="NORM_B",
            treaty_provision_nature="UNSPECIFIED",
        )
        self.assertEqual(r_unspec.winning_side, "UNRESOLVED_ESCALATE")
        self.assertEqual(r_unspec.rule_applied, "ANAYASA_M90_TREATY_NATURE_REVIEW_REQUIRED")
        self.assertTrue(r_unspec.requires_counsel_escalation)

        # 2. Negative guard: DIRECT_SUBSTANTIVE_RULE -> Anayasa m.90/son mandates treaty over domestic statute
        r_direct = resolve_norm_conflict(
            treaty,
            statute,
            mandatory_type="RELATIVE_EMPLOYEE_FAVORABLE",
            favors_employee_side="NORM_B",
            treaty_provision_nature="DIRECT_SUBSTANTIVE_RULE",
        )
        self.assertEqual(r_direct.winning_side, "NORM_A")
        self.assertEqual(r_direct.rule_applied, "ANAYASA_M90_SON_FUNDAMENTAL_RIGHTS_TREATY_PREVAILS")
        self.assertFalse(r_direct.requires_counsel_escalation)

        # 3. Positive: MINIMUM_STANDARD_FLOOR -> more favorable domestic statute preserved cleanly
        r_floor = self.router.dispatch(
            "resolve_norm_conflict",
            {
                "norm_a": {"title": treaty.title, "norm_layer": treaty.norm_layer},
                "norm_b": {"title": statute.title, "norm_layer": statute.norm_layer, "source_id": "MEVZUAT-4857"},
                "mandatory_type": "RELATIVE_EMPLOYEE_FAVORABLE",
                "favors_employee_side": "NORM_B",
                "treaty_provision_nature": "MINIMUM_STANDARD_FLOOR",
            },
        )
        self.assertEqual(r_floor["winning_side"], "NORM_B")
        self.assertEqual(r_floor["rule_applied"], "ANAYASA_M90_MORE_FAVORABLE_DOMESTIC_STATUTE_PRESERVED")
        self.assertFalse(r_floor["requires_counsel_escalation"])

    def test_persuasive_hgk_and_chamber_precedents_require_application_rationale_and_isolated_still_escalates(self) -> None:
        base_yibbgk = self.precedents["YIBBGK-2017-9-2018-10"]
        hgk_prec = replace(
            base_yibbgk,
            precedent_id="TEST-HGK-PERSUASIVE",
            chamber="Yargıtay Hukuk Genel Kurulu",
            binding_level="HGK_PERSUASIVE",
        )
        settled_prec = replace(
            base_yibbgk,
            precedent_id="TEST-CHAMBER-SETTLED",
            chamber="Yargıtay 9. Hukuk Dairesi",
            binding_level="CHAMBER_SETTLED",
        )
        isolated_prec = replace(
            base_yibbgk,
            precedent_id="TEST-CHAMBER-ISOLATED",
            chamber="Yargıtay 9. Hukuk Dairesi",
            binding_level="CHAMBER_ISOLATED",
        )

        # Negative: missing or too-short application_rationale on HGK / CHAMBER_SETTLED / CHAMBER_ISOLATED MUST escalate
        for prec in (hgk_prec, settled_prec, isolated_prec):
            with self.subTest(binding_level=prec.binding_level, case="missing_rationale"):
                res_missing = evaluate_precedent_application(
                    precedent=prec,
                    interpreted_source=self.sources["MEVZUAT-4857"],
                    as_of_date="2026-05-01",
                    scope_match_status="IN_SCOPE",
                    application_rationale="Kısa not",
                )
                self.assertFalse(res_missing.precedent_applicable_to_statute)
                self.assertEqual(res_missing.effective_outcome, "ESCALATE_TO_LEGAL_COUNSEL")
                self.assertEqual(res_missing.rationale_requirement_status, "MISSING_PERSUASIVE_PRECEDENT_RATIONALE")
                self.assertTrue(res_missing.requires_counsel_escalation)

        # Positive: explicit >=25-char rationale allows HGK_PERSUASIVE & CHAMBER_SETTLED to apply cleanly
        valid_rationale = (
            "Somut uyuşmazlıktaki olgular 9. HD yerleşik içtihadıyla birebir örtüşmekte olup "
            "karşıt daire görüşü bulunmadığı teyit edilmiştir."
        )
        for prec in (hgk_prec, settled_prec):
            with self.subTest(binding_level=prec.binding_level, case="valid_rationale"):
                res_ok = evaluate_precedent_application(
                    precedent=prec,
                    interpreted_source=self.sources["MEVZUAT-4857"],
                    as_of_date="2026-05-01",
                    scope_match_status="IN_SCOPE",
                    application_rationale=valid_rationale,
                )
                self.assertTrue(res_ok.precedent_applicable_to_statute)
                self.assertEqual(res_ok.effective_outcome, "UNDERLYING_STATUTE_WITH_PRECEDENT_PREVAILS")
                self.assertEqual(res_ok.rationale_requirement_status, "PROVIDED_PERSUASIVE_RATIONALE")
                self.assertFalse(res_ok.requires_counsel_escalation)

        # Negative safeguard: CHAMBER_ISOLATED STILL requires counsel escalation even with valid rationale
        res_iso = evaluate_precedent_application(
            precedent=isolated_prec,
            interpreted_source=self.sources["MEVZUAT-4857"],
            as_of_date="2026-05-01",
            scope_match_status="IN_SCOPE",
            application_rationale=valid_rationale,
        )
        self.assertTrue(res_iso.precedent_applicable_to_statute)
        self.assertEqual(res_iso.effective_outcome, "ESCALATE_TO_LEGAL_COUNSEL")
        self.assertEqual(res_iso.rationale_requirement_status, "PROVIDED_BUT_ISOLATED_CHAMBER_REQUIRES_COUNSEL")
        self.assertTrue(res_iso.requires_counsel_escalation)

        # Positive: YİBBGK still operates under 2797 m.45 without requiring persuasive rationale
        res_yibbgk = evaluate_precedent_application(
            precedent=base_yibbgk,
            interpreted_source=self.sources["MEVZUAT-4857"],
            as_of_date="2026-05-01",
            scope_match_status="IN_SCOPE",
        )
        self.assertEqual(res_yibbgk.rationale_requirement_status, "STATUTORY_BINDING_YIBBGK_2797_M45_DEFAULT")
        self.assertFalse(res_yibbgk.requires_counsel_escalation)

    def test_scenario_termination_validity_missing_info_and_clean_m18_path(self) -> None:
        # 1. Negative: missing core zero-trust facts -> EKSIK_BILGI_TAMAMLANMALI, payroll handoff blocked
        ev_missing = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={"termination_reason_type": "VALID_REASON_M18"},
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_missing.decision_badge, "EKSIK_BILGI_TAMAMLANMALI")
        self.assertGreaterEqual(len(ev_missing.missing_information), 4)
        self.assertFalse(ev_missing.human_approval.payroll_handoff_allowed)
        self.assertTrue(ev_missing.human_approval.required)

        # 2. Positive: complete & verified m.18 procedural facts -> UYGUN_ON_DEGERLENDIRME, payroll handoff allowed with human approval
        ev_clean = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                "termination_reason_type": "VALID_REASON_M18",
                "workplace_total_employees": 120,
                "tenure_months": 24,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": True,
                "written_defense_status": "VERIFIED",
                "last_resort_checked": True,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_clean.decision_badge, "UYGUN_ON_DEGERLENDIRME")
        self.assertEqual(len(ev_clean.missing_information), 0)
        self.assertTrue(ev_clean.human_approval.payroll_handoff_allowed)
        self.assertTrue(ev_clean.structured_findings["job_security_applies"])

    def test_scenario_termination_validity_protected_category_m26_deadline_and_cba_defense_override(self) -> None:
        # 1. 4857 m.26 6-working-day deadline exceeded + union representative -> CRITICAL escalation
        ev_m26 = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                "termination_reason_type": "JUST_CAUSE_M25_II",
                "workplace_total_employees": 80,
                "tenure_months": 30,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": True,
                "discovery_date": "2026-05-01",
                "planned_termination_date": "2026-05-15",
                "is_union_representative": True,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_m26.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertTrue(ev_m26.human_approval.counsel_escalation_required)
        self.assertFalse(ev_m26.human_approval.payroll_handoff_allowed)
        risk_cats = {r.category for r in ev_m26.risks}
        self.assertIn("HAK_DUSURUCU_SURE_ASIMI_M26", risk_cats)
        self.assertIn("KORUMALI_FESIH_KATEGORISI", risk_cats)

        # 2. 4857 m.25/I-b + employee-favorable TİS defense clause without written defense -> HIGH risk & COMPETING_NORM_PREVAILS
        ev_cba = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                "termination_reason_type": "JUST_CAUSE_M25_I_B",
                "workplace_total_employees": 200,
                "tenure_months": 40,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": True,
                "written_defense_status": "NOT_TAKEN",
                "cba_requires_written_defense_for_all_terminations": True,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertIsNotNone(ev_cba.precedent_application_assessment)
        self.assertEqual(ev_cba.precedent_application_assessment.effective_outcome, "COMPETING_NORM_PREVAILS")
        self.assertIn("TIS_ISCI_LEHINE_SAVUNMA_GARANTISI", {r.category for r in ev_cba.risks})
        self.assertTrue(ev_cba.human_approval.counsel_escalation_required)
        self.assertFalse(ev_cba.human_approval.payroll_handoff_allowed)

    def test_scenario_reinstatement_claim_thresholds_and_7036_m3_article_effective_date(self) -> None:
        # 1. Post-2018 eligible worker -> mandatory counsel escalation, 7036 m.3 effective=True
        ev_post = evaluate_hr_legal_scenario(
            scenario_type="REINSTATEMENT_CLAIM",
            facts={
                "workplace_total_employees": 60,
                "tenure_months": 14,
                "contract_term_type": "INDEFINITE",
                "is_employer_representative_m18_end": False,
                "termination_notice_date": "2026-05-01",
                "mediation_application_date": "2026-05-20",
            },
            as_of_date="2026-05-25",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_post.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertTrue(ev_post.structured_findings["reinstatement_eligible"])
        self.assertTrue(ev_post.structured_findings["mandatory_mediation_7036_m3_effective"])
        self.assertFalse(ev_post.human_approval.payroll_handoff_allowed)

        # 2. Pre-2018 historical notice date (2017-11-15) -> 7036 m.3 NOT effective on date!
        ev_pre = evaluate_hr_legal_scenario(
            scenario_type="REINSTATEMENT_CLAIM",
            facts={
                "workplace_total_employees": 20,
                "tenure_months": 14,
                "contract_term_type": "INDEFINITE",
                "is_employer_representative_m18_end": False,
                "termination_notice_date": "2017-11-15",
            },
            as_of_date="2017-11-20",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertFalse(ev_pre.structured_findings["reinstatement_eligible"])
        self.assertFalse(ev_pre.structured_findings["mandatory_mediation_7036_m3_effective"])
        self.assertIn("MADDE_YURURLUK_TARIHI_7036_M3", {r.category for r in ev_pre.risks})

    def test_scenario_severance_and_notice_entitlement_cohorts_and_pre_18_insurance_distinction(self) -> None:
        # 1. Clean m.17/m.18 employer termination (>=36 months -> 8 weeks notice) -> payroll handoff allowed, delegated to @UcretBordro
        ev_clean = evaluate_hr_legal_scenario(
            scenario_type="SEVERANCE_AND_NOTICE",
            facts={
                "tenure_months": 42,
                "termination_reason_type": "EMPLOYER_VALID_OR_NOTICE_M17_M18",
                "notice_period_worked_or_given": False,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_clean.decision_badge, "UYGUN_ON_DEGERLENDIRME")
        self.assertEqual(ev_clean.structured_findings["severance_entitlement"], "ENTITLED")
        self.assertEqual(ev_clean.structured_findings["notice_entitlement"], "ENTITLED_IF_NOT_WORKED")
        self.assertEqual(ev_clean.structured_findings["statutory_minimum_notice_weeks"], 8)
        self.assertEqual(ev_clean.structured_findings["payroll_calculation_delegated_to"], "@UcretBordro")
        self.assertTrue(ev_clean.human_approval.payroll_handoff_allowed)

        # 2. Retirement (1475 m.14) with pre-18 insurance days and missing SGK letter -> EKSIK_BILGI_TAMAMLANMALI + 5510 m.38/2 basis
        ev_ret = evaluate_hr_legal_scenario(
            scenario_type="SEVERANCE_AND_NOTICE",
            facts={
                "tenure_months": 60,
                "termination_reason_type": "RETIREMENT_1475_M14",
                "first_insurance_registration_date": "1998-06-10",
                "has_pre_18_insurance_days": True,
                "sgk_retirement_letter_verified": False,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_ret.decision_badge, "EKSIK_BILGI_TAMAMLANMALI")
        self.assertFalse(ev_ret.human_approval.payroll_handoff_allowed)
        self.assertIn("PRE_1999_09_08", ev_ret.structured_findings["retirement_cohort"])
        self.assertIn("MEVZUAT-5510", {b.source_id for b in ev_ret.legal_bases})

    def test_scenario_overtime_compliance_underground_mining_vs_non_mining_reg_m7_and_270h_cap(self) -> None:
        # 1. Underground mining WITHOUT m.42/43 -> CRITICAL prohibition
        ev_mine_bad = evaluate_hr_legal_scenario(
            scenario_type="OVERTIME_COMPLIANCE",
            facts={
                "work_category": "UNDERGROUND_MINING",
                "is_m42_m43_emergency_or_mandatory": False,
                "projected_annual_overtime_hours": 50,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_mine_bad.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertIn("YER_ALTI_MADEN_OLAGAN_FAZLA_CALISMA_YASAGI", {r.category for r in ev_mine_bad.risks})

        # 2. Underground mining WITH m.42/43 -> 37.5h / 100% statutory special rule
        ev_mine_m42 = evaluate_hr_legal_scenario(
            scenario_type="OVERTIME_COMPLIANCE",
            facts={
                "work_category": "UNDERGROUND_MINING",
                "is_m42_m43_emergency_or_mandatory": True,
                "projected_annual_overtime_hours": 40,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_mine_m42.decision_badge, "UYGUN_ON_DEGERLENDIRME")
        self.assertEqual(ev_mine_m42.structured_findings["underground_mining_weekly_threshold_hours"], 37.5)
        self.assertTrue(any("%100" in a for a in ev_mine_m42.recommended_actions))

        # 3. Non-mining Reg m.7 prohibited work (even if is_m42_m43=True) -> CRITICAL counsel escalation (never auto-approved)
        ev_other_m7 = evaluate_hr_legal_scenario(
            scenario_type="OVERTIME_COMPLIANCE",
            facts={
                "work_category": "OTHER_REG_M7_PROHIBITED",
                "is_m42_m43_emergency_or_mandatory": True,
                "projected_annual_overtime_hours": 30,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_other_m7.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertIn("YONETMELIK_M7_YASAKLI_IS_ESKALASYONU", {r.category for r in ev_other_m7.risks})

        # 4. >270 hours annual cap & >11h daily cap -> HIGH risks
        ev_cap = evaluate_hr_legal_scenario(
            scenario_type="OVERTIME_COMPLIANCE",
            facts={
                "work_category": "GENERAL",
                "written_overtime_consent_in_file": True,
                "projected_annual_overtime_hours": 310,
                "daily_total_hours": 12.5,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        cats = {r.category for r in ev_cap.risks}
        self.assertIn("YILLIK_270_SAAT_TAVAN_ASIMI", cats)
        self.assertIn("GUNLUK_11_SAAT_TAVAN_ASIMI", cats)
        self.assertFalse(ev_cap.human_approval.payroll_handoff_allowed)

    def test_scenario_overtime_compliance_night_work_m69_vs_m7_and_written_consent_withdrawal(self) -> None:
        ev_night = evaluate_hr_legal_scenario(
            scenario_type="OVERTIME_COMPLIANCE",
            facts={
                "work_category": "NIGHT_WORK_M69_EXEMPT_SECTOR",
                "written_overtime_consent_in_file": True,
                "consent_withdrawal_notice_given": True,
                "projected_annual_overtime_hours": 120,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        cats = {r.category for r in ev_night.risks}
        self.assertIn("GECE_CALISMASI_M69_VS_YONETMELIK_M7_AYRIMI", cats)
        self.assertIn("ONAY_GERI_ALMA_30_GUN_YON_M9", cats)
        self.assertEqual(ev_night.decision_badge, "USUL_EKSIGI_DUZELTME_GEREKLI")

    def test_scenario_annual_leave_compliance_age_underground_10day_block_and_favorable_cba(self) -> None:
        # 1. Age 52 + underground miner (2 years tenure) -> 20 (age>=50) + 4 (underground) = 24 statutory min; TİS 26 days prevails
        ev_cba = evaluate_hr_legal_scenario(
            scenario_type="ANNUAL_LEAVE_COMPLIANCE",
            facts={
                "tenure_years": 2,
                "employee_age": 52,
                "is_underground_miner": True,
                "contract_or_cba_leave_days": 26,
                "largest_split_block_days": 12,
                "signed_leave_register_verified": True,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_cba.decision_badge, "UYGUN_ON_DEGERLENDIRME")
        self.assertEqual(ev_cba.structured_findings["statutory_minimum_leave_days"], 24)
        self.assertEqual(ev_cba.structured_findings["effective_leave_days"], 26)
        self.assertIsNotNone(ev_cba.norm_conflict_resolution)
        self.assertEqual(
            ev_cba.norm_conflict_resolution.rule_applied,
            "RELATIVE_MANDATORY_EMPLOYEE_FAVORABLE_LOWER_NORM_PREVAILS",
        )

        # 2. Negative: split block < 10 days + pay-in-lieu while employed + contract below statutory minimum -> HIGH risks
        ev_bad = evaluate_hr_legal_scenario(
            scenario_type="ANNUAL_LEAVE_COMPLIANCE",
            facts={
                "tenure_years": 3,
                "employee_age": 30,
                "contract_or_cba_leave_days": 10,
                "largest_split_block_days": 7,
                "pay_in_lieu_while_employed": True,
                "signed_leave_register_verified": True,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        cats = {r.category for r in ev_bad.risks}
        self.assertIn("ASGARI_YILLIK_IZIN_ALTINA_INILMESI", cats)
        self.assertIn("CALISIRKEN_IZIN_PARAYA_CEVRILME_YASAGI_M53_M59", cats)
        self.assertIn("ON_GUN_BOLUNME_SARTI_IHLALI_M56", cats)
        self.assertEqual(ev_bad.structured_findings["effective_leave_days"], 14)
        self.assertFalse(ev_bad.human_approval.payroll_handoff_allowed)

    def test_scenario_sgk_exit_code_10day_limit_mismatch_and_code22_substantive_review(self) -> None:
        # 1. Code 22 -> substantive review required, NEVER auto-denied
        ev_k22 = evaluate_hr_legal_scenario(
            scenario_type="SGK_EXIT_CODE_AND_UNEMPLOYMENT",
            facts={
                "proposed_sgk_exit_code": "22",
                "actual_termination_reason": "MUTUAL_TERMINATION_IKALE",
                "termination_date": "2026-05-10",
                "sgk_filing_date": "2026-05-15",
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(
            ev_k22.structured_findings["unemployment_benefit_assessment"],
            "SUBSTANTIVE_REVIEW_REQUIRED_NOT_AUTO_DENIED",
        )
        self.assertIn("KOD_22_ESAS_INCELEME_GEREKLILIGI", {r.category for r in ev_k22.risks})

        # 2. Mismatch (m.17/18 termination reported as Code 03) + >10 days filing -> CRITICAL + HIGH
        ev_bad = evaluate_hr_legal_scenario(
            scenario_type="SGK_EXIT_CODE_AND_UNEMPLOYMENT",
            facts={
                "proposed_sgk_exit_code": "03",
                "actual_termination_reason": "EMPLOYER_VALID_OR_NOTICE_M17_M18",
                "termination_date": "2026-05-01",
                "sgk_filing_date": "2026-05-18",
                "last_120_days_service_contract": True,
                "unemployment_premium_days_last_3_years": 900,
            },
            as_of_date="2026-05-18",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_bad.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertTrue(ev_bad.structured_findings["code_reason_mismatch"])
        cats = {r.category for r in ev_bad.risks}
        self.assertIn("SGK_CIKIS_KODU_UYUMSUZLUGU", cats)
        self.assertIn("SGK_10_GUN_BILDIRIM_ASIMI_M9_M102", cats)

        # 3. Repealed Code 29 -> HIGH risk
        ev_k29 = evaluate_hr_legal_scenario(
            scenario_type="SGK_EXIT_CODE_AND_UNEMPLOYMENT",
            facts={
                "proposed_sgk_exit_code": "29",
                "actual_termination_reason": "EMPLOYER_JUST_CAUSE_M25_II",
                "termination_date": "2026-05-10",
                "sgk_filing_date": "2026-05-15",
                "last_120_days_service_contract": True,
                "unemployment_premium_days_last_3_years": 700,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertIn("YURURLUKTEN_KALDIRILMIS_KOD_29", {r.category for r in ev_k29.risks})

    def test_scenario_employee_favorable_norm_comparison_integrates_treaty_nature_and_precedent_rationale(self) -> None:
        # 1. Treaty vs Statute with UNSPECIFIED treaty_provision_nature -> escalates via scenario engine
        ev_treaty = evaluate_hr_legal_scenario(
            scenario_type="EMPLOYEE_FAVORABLE_NORM_COMPARISON",
            facts={
                "norm_a": {
                    "title": "Temel Hak Uluslararası Antlaşması",
                    "norm_layer": "INTERNATIONAL_TREATY_FUNDAMENTAL_RIGHTS",
                },
                "norm_b": {
                    "title": "4857 Sayılı İş Kanunu",
                    "norm_layer": "STATUTORY_LAW",
                    "source_id": "MEVZUAT-4857",
                },
                "mandatory_type": "RELATIVE_EMPLOYEE_FAVORABLE",
                "favors_employee_side": "NORM_B",
                "treaty_provision_nature": "UNSPECIFIED",
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_treaty.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertEqual(
            ev_treaty.norm_conflict_resolution.rule_applied,
            "ANAYASA_M90_TREATY_NATURE_REVIEW_REQUIRED",
        )

        # 2. YİBBGK-2017-9-2018-10 vs employee-favorable TİS clause -> COMPETING_NORM_PREVAILS
        ev_prec = evaluate_hr_legal_scenario(
            scenario_type="EMPLOYEE_FAVORABLE_NORM_COMPARISON",
            facts={
                "precedent_id": "YIBBGK-2017-9-2018-10",
                "interpreted_source_id": "MEVZUAT-4857",
                "scope_match_status": "IN_SCOPE",
                "norm_b": {
                    "title": "TİS m.42 (m.25/I-b Öncesi Yazılı Savunma Garantisi)",
                    "norm_layer": "CBA_CONTRACT_AND_HR_PROCEDURE",
                },
                "mandatory_type": "RELATIVE_EMPLOYEE_FAVORABLE",
                "favors_employee_side": "COMPETING_NORM",
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_prec.decision_badge, "UYGUN_ON_DEGERLENDIRME")
        self.assertEqual(ev_prec.precedent_application_assessment.effective_outcome, "COMPETING_NORM_PREVAILS")

    def test_scenario_employee_favorable_norm_comparison_escalates_on_pending_source_or_precedent(self) -> None:
        # Negative 1: PENDING_REVIEW source GIB-TEBLIG-332-20251231 MUST trigger escalation and NEVER appear in legal_bases
        ev_pending_src = evaluate_hr_legal_scenario(
            scenario_type="EMPLOYEE_FAVORABLE_NORM_COMPARISON",
            facts={
                "norm_a": {
                    "title": "GİB 332 Tebliği",
                    "norm_layer": "COMMUNIQUE_AND_SGK_CIRCULAR",
                    "source_id": "GIB-TEBLIG-332-20251231",
                },
                "norm_b": {
                    "title": "Şirket Yan Hak Prosedürü",
                    "norm_layer": "CBA_CONTRACT_AND_HR_PROCEDURE",
                },
                "mandatory_type": "RELATIVE_EMPLOYEE_FAVORABLE",
                "favors_employee_side": "NORM_B",
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_pending_src.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertIn("DOGRULANMAMIS_VEYA_MULGA_NORM_KAYNAGI", {r.category for r in ev_pending_src.risks})
        self.assertNotIn("GIB-TEBLIG-332-20251231", {b.source_id for b in ev_pending_src.legal_bases})

        # Negative 2: PENDING_REVIEW precedent YIBBGK-2021-8-2026-1 MUST escalate and NEVER appear as verified precedent_id
        ev_pending_prec = evaluate_hr_legal_scenario(
            scenario_type="EMPLOYEE_FAVORABLE_NORM_COMPARISON",
            facts={
                "precedent_id": "YIBBGK-2021-8-2026-1",
                "interpreted_source_id": "MEVZUAT-7036",
                "scope_match_status": "IN_SCOPE",
            },
            as_of_date="2026-10-01",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_pending_prec.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertNotIn("YIBBGK-2021-8-2026-1", {b.precedent_id for b in ev_pending_prec.legal_bases})

    def test_all_seven_scenarios_produce_mandatory_5_reasoning_blocks_via_router_and_never_cite_pending_records(self) -> None:
        sample_calls = {
            "TERMINATION_VALIDITY": {
                "termination_reason_type": "VALID_REASON_M18",
                "workplace_total_employees": 50,
                "tenure_months": 18,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": True,
                "written_defense_status": "VERIFIED",
                "last_resort_checked": True,
            },
            "REINSTATEMENT_CLAIM": {
                "workplace_total_employees": 50,
                "tenure_months": 12,
                "contract_term_type": "INDEFINITE",
                "is_employer_representative_m18_end": False,
                "termination_notice_date": "2026-05-01",
            },
            "SEVERANCE_AND_NOTICE": {
                "tenure_months": 24,
                "termination_reason_type": "EMPLOYER_VALID_OR_NOTICE_M17_M18",
                "notice_period_worked_or_given": True,
            },
            "OVERTIME_COMPLIANCE": {
                "work_category": "GENERAL",
                "written_overtime_consent_in_file": True,
                "projected_annual_overtime_hours": 150,
                "daily_total_hours": 10.0,
            },
            "ANNUAL_LEAVE_COMPLIANCE": {
                "tenure_years": 6,
                "employee_age": 35,
                "largest_split_block_days": 10,
                "signed_leave_register_verified": True,
            },
            "SGK_EXIT_CODE_AND_UNEMPLOYMENT": {
                "proposed_sgk_exit_code": "04",
                "actual_termination_reason": "EMPLOYER_VALID_OR_NOTICE_M17_M18",
                "termination_date": "2026-05-10",
                "sgk_filing_date": "2026-05-15",
                "last_120_days_service_contract": True,
                "unemployment_premium_days_last_3_years": 800,
            },
            "EMPLOYEE_FAVORABLE_NORM_COMPARISON": {
                "norm_a": {"title": "4857 Sayılı İş Kanunu m.17", "norm_layer": "STATUTORY_LAW", "source_id": "MEVZUAT-4857"},
                "norm_b": {"title": "TİS İhbar Süresi (+2 Hafta)", "norm_layer": "CBA_CONTRACT_AND_HR_PROCEDURE"},
                "mandatory_type": "RELATIVE_EMPLOYEE_FAVORABLE",
                "favors_employee_side": "NORM_B",
            },
        }
        self.assertEqual(set(sample_calls.keys()), VALID_SCENARIO_TYPES)
        pending_ids = {"GIB-TEBLIG-332-20251231", "YIBBGK-2021-8-2026-1", "CARD-GIB-332-2026-TARIFE"}

        for scen, facts in sample_calls.items():
            with self.subTest(scenario_type=scen):
                out = self.router.dispatch(
                    "evaluate_hr_legal_scenario",
                    {"scenario_type": scen, "as_of_date": "2026-05-15", "facts": facts},
                )
                self.assertEqual(out["scenario_type"], scen)
                # 5 mandatory blocks present & well-formed
                self.assertGreaterEqual(len(out["legal_bases"]), 1)
                self.assertGreaterEqual(len(out["counter_arguments"]), 1)
                self.assertGreaterEqual(len(out["risks"]), 1)
                self.assertIsInstance(out["missing_information"], list)
                self.assertTrue(out["human_approval"]["required"])
                self.assertEqual(
                    out["human_approval"]["external_counsel_signoff_status"],
                    "PENDING_SIGNED_EXTERNAL_ATTESTATION",
                )
                for b in out["legal_bases"]:
                    self.assertEqual(b["verification_status"], "VERIFIED")
                    self.assertNotIn(b["source_id"], pending_ids)
                    self.assertNotIn(b["card_id"], pending_ids)
                    self.assertNotIn(b["precedent_id"], pending_ids)

    def test_v102c_schemas_taxonomy_and_tool_schemas_include_reasoning_engine_and_carryover_fields(self) -> None:
        scen_schema = json.loads(SCENARIO_SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(set(scen_schema["properties"]["scenario_type"]["enum"]), VALID_SCENARIO_TYPES)
        for req_block in ("legal_bases", "counter_arguments", "risks", "missing_information", "human_approval"):
            self.assertIn(req_block, scen_schema["required"])

        tax = json.loads(TAXONOMY_PATH.read_text(encoding="utf-8"))
        self.assertTrue(tax["schema_version"].startswith(("1.0.2c", "1.0.3", "1.0.4", "1.0.5")))
        self.assertIn("legal_reasoning_engine", tax)
        self.assertEqual(set(tax["legal_reasoning_engine"]["supported_scenarios"]), VALID_SCENARIO_TYPES)
        self.assertTrue(
            tax["verification_infrastructure"]["strict_rules"]["require_treaty_provision_nature_for_anayasa_m90_preservation"]
        )
        self.assertTrue(
            tax["verification_infrastructure"]["strict_rules"]["require_application_rationale_for_persuasive_precedents"]
        )

        tools = json.loads(TOOLS_SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertTrue(tools["schema_version"].startswith(("1.0.2c", "1.0.3", "1.0.4", "1.0.5")))
        by_name = {t["name"]: t for t in tools["tools"]}
        self.assertIn("evaluate_hr_legal_scenario", by_name)
        self.assertIn("treaty_provision_nature", by_name["resolve_norm_conflict"]["parameters"]["properties"])
        self.assertIn("application_rationale", by_name["evaluate_precedent_application"]["parameters"]["properties"])
        self.assertIn("treaty_provision_nature", by_name["evaluate_precedent_application"]["parameters"]["properties"])


class TestV102c1DeadlineNoticeAndHistoricalBasisHardening(unittest.TestCase):
    def setUp(self) -> None:
        self.sources = load_source_registry(SOURCES_PATH, strict=True)
        self.precedents = load_precedent_registry(PRECEDENTS_PATH, source_registry=self.sources, strict=True)
        self.cards = load_knowledge_cards(
            KB_ALL_DIR,
            source_registry=self.sources,
            precedent_registry=self.precedents,
            strict=True,
            audit_log_path=AUDIT_LOG_PATH,
        )
        self.router = HukukSGKToolRouter()

    # --- 1. 4857 m.26 Working Days (UBGT, Weekend, Religious Holidays, 1-Year Cap, Material Gain, Authority) ---

    def test_m26_working_days_excludes_sundays_fixed_ubgt_religious_bayrams_and_optional_saturday(self) -> None:
        # 2026 fixed UBGT (1 Mayıs) + Sunday (3 Mayıs):
        # Discovery = 2026-04-29 (Wed). Days: Apr 30(1), May 1(UBGT skip), May 2(Sat=2), May 3(Sun skip),
        # May 4(3), May 5(4), May 6(5), May 7(6).
        self.assertEqual(_business_days_between(date(2026, 4, 29), date(2026, 5, 7)), 6)
        self.assertEqual(_business_days_between(date(2026, 4, 29), date(2026, 5, 8)), 7)
        self.assertEqual(add_turkish_working_days(date(2026, 4, 29), 6), date(2026, 5, 7))

        # 5-day workplace (saturday_is_working_day=False): contractual non-working Saturday (akdi tatil) is NOT excluded
        # from 4857 m.26 working days! May 2 (Sat) still counts -> 6th working day remains May 7, May 8 is 7th day.
        self.assertEqual(
            _business_days_between(date(2026, 4, 29), date(2026, 5, 8), saturday_is_working_day=False),
            7,
        )
        self.assertEqual(
            add_turkish_working_days(date(2026, 4, 29), 6, saturday_is_working_day=False),
            date(2026, 5, 7),
        )
        # Only when Saturday is legally verified as a statutory weekly rest day (e.g. TİS 2-day statutory weekly rest)
        # is Saturday excluded from 4857 m.26 working days -> 6th working day moves to May 8 (Fri).
        self.assertEqual(
            _business_days_between(
                date(2026, 4, 29),
                date(2026, 5, 8),
                legally_verified_weekly_rest_days=["SATURDAY", "SUNDAY"],
            ),
            6,
        )
        self.assertEqual(
            add_turkish_working_days(
                date(2026, 4, 29),
                6,
                legally_verified_weekly_rest_days=["SATURDAY", "SUNDAY"],
            ),
            date(2026, 5, 8),
        )

        # 2026 Kurban Bayramı (May 27–30, 4 full UBGT days) + Sunday May 31:
        # Discovery = 2026-05-25 (Mon). Days: May 26(1), May 27-30(Bayram skip), May 31(Sun skip),
        # Jun 1(2), Jun 2(3), Jun 3(4), Jun 4(5), Jun 5(6).
        self.assertEqual(add_turkish_working_days(date(2026, 5, 25), 6), date(2026, 6, 5))
        self.assertEqual(_business_days_between(date(2026, 5, 25), date(2026, 6, 5)), 6)
        self.assertEqual(_business_days_between(date(2026, 5, 25), date(2026, 6, 6)), 7)

        # 2026 Ramazan Bayramı (Mar 20–22): Discovery = 2026-03-18 (Wed)
        # Days: Mar 19(1), Mar 20-22(Bayram/Sun skip), Mar 23(2), Mar 24(3), Mar 25(4), Mar 26(5), Mar 27(6)
        self.assertEqual(add_turkish_working_days(date(2026, 3, 18), 6), date(2026, 3, 27))

        # Historical UBGT check: 15 Temmuz became holiday via 6752 (first observed 2017); 1 Mayıs via 5892 (2009)
        self.assertNotIn(date(2016, 7, 15), get_turkish_ubgt_holidays(2016))
        self.assertIn(date(2017, 7, 15), get_turkish_ubgt_holidays(2017))
        self.assertNotIn(date(2008, 5, 1), get_turkish_ubgt_holidays(2008))
        self.assertIn(date(2009, 5, 1), get_turkish_ubgt_holidays(2009))

        # Custom extra_holidays support
        self.assertEqual(
            add_turkish_working_days(date(2026, 6, 1), 6, extra_holidays={date(2026, 6, 3)}),
            date(2026, 6, 9),
        )

        # Edge case: 6th working day expires on Saturday (2026-05-09); action on Sunday (2026-05-10) MUST be EXCEEDED!
        res_sun = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2026-05-02",
            act_date_s="2026-05-01",
            action_date_s="2026-05-10",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
        )
        self.assertEqual(res_sun["six_working_day_deadline_date"], "2026-05-09")
        self.assertEqual(res_sun["six_working_day_status"], "EXCEEDED")
        self.assertTrue(res_sun["requires_counsel_escalation"])

    def test_m26_six_working_day_exact_boundary_day6_passes_and_day7_exceeds_in_scenario(self) -> None:
        base_facts = {
            "termination_reason_type": "JUST_CAUSE_M25_II",
            "workplace_total_employees": 80,
            "tenure_months": 24,
            "contract_term_type": "INDEFINITE",
            "written_notice_with_clear_reason": True,
            "act_date": "2026-04-28",
            "discovery_date": "2026-04-29",
            "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
        }
        # Exact 6th working day (2026-05-07, because 1 Mayıs UBGT & 3 Mayıs Sun excluded) -> WITHIN_LIMIT & clean
        ev_day6 = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={**base_facts, "planned_termination_date": "2026-05-07"},
            as_of_date="2026-05-07",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        m26_6 = ev_day6.structured_findings["m26_deadline_assessment"]
        self.assertEqual(m26_6["working_days_since_discovery"], 6)
        self.assertEqual(m26_6["six_working_day_status"], "WITHIN_LIMIT")
        self.assertEqual(m26_6["one_year_limit_status"], "WITHIN_LIMIT")
        self.assertTrue(any(h["date"] == "2026-05-01" for h in m26_6["excluded_holidays_in_window"]))
        self.assertEqual(ev_day6.decision_badge, "UYGUN_ON_DEGERLENDIRME")
        self.assertTrue(ev_day6.human_approval.payroll_handoff_allowed)

        # 7th working day (2026-05-08) -> EXCEEDED & mandatory counsel escalation
        ev_day7 = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={**base_facts, "planned_termination_date": "2026-05-08"},
            as_of_date="2026-05-08",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        m26_7 = ev_day7.structured_findings["m26_deadline_assessment"]
        self.assertEqual(m26_7["working_days_since_discovery"], 7)
        self.assertEqual(m26_7["six_working_day_status"], "EXCEEDED")
        self.assertEqual(ev_day7.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertIn("HAK_DUSURUCU_SURE_ASIMI_M26", {r.category for r in ev_day7.risks})
        self.assertFalse(ev_day7.human_approval.payroll_handoff_allowed)

    def test_m26_one_year_upper_limit_exact_anniversary_leap_year_and_material_gain_exception(self) -> None:
        base_facts = {
            "termination_reason_type": "JUST_CAUSE_M25_II",
            "workplace_total_employees": 50,
            "tenure_months": 36,
            "contract_term_type": "INDEFINITE",
            "written_notice_with_clear_reason": True,
            "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
        }
        # 1. Exact 1-year anniversary day (2025-05-15 -> 2026-05-15) -> WITHIN_LIMIT
        ev_anniv = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                **base_facts,
                "act_date": "2025-05-15",
                "discovery_date": "2026-05-12",
                "planned_termination_date": "2026-05-15",
                "employee_gained_material_benefit": False,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_anniv.structured_findings["m26_deadline_assessment"]["one_year_limit_status"], "WITHIN_LIMIT")
        self.assertEqual(ev_anniv.decision_badge, "UYGUN_ON_DEGERLENDIRME")

        # 2. Leap-day act_date (2024-02-29 -> 1-year deadline 2025-02-28)
        leap_res = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2025-02-26",
            act_date_s="2024-02-29",
            action_date_s="2025-02-28",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
            employee_gained_material_benefit=False,
        )
        self.assertEqual(leap_res["one_year_deadline_date"], "2025-02-28")
        self.assertEqual(leap_res["one_year_limit_status"], "WITHIN_LIMIT")

        # 3. 1 year + 1 day exceeded with NO material gain -> CRITICAL BIR_YILLIK_UST_SURE_ASIMI_M26 (even within 6 days!)
        ev_over1y = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                **base_facts,
                "act_date": "2025-05-15",
                "discovery_date": "2026-05-14",
                "planned_termination_date": "2026-05-16",
                "employee_gained_material_benefit": False,
            },
            as_of_date="2026-05-16",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_over1y.structured_findings["m26_deadline_assessment"]["six_working_day_status"], "WITHIN_LIMIT")
        self.assertEqual(ev_over1y.structured_findings["m26_deadline_assessment"]["one_year_limit_status"], "EXCEEDED")
        self.assertEqual(ev_over1y.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertIn("BIR_YILLIK_UST_SURE_ASIMI_M26", {r.category for r in ev_over1y.risks})

        # 4. >1 year WITH employee_gained_material_benefit=True & within 6 working days -> 1-year cap waived, proof-burden MEDIUM risk
        ev_gain_ok = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                **base_facts,
                "act_date": "2024-10-01",
                "discovery_date": "2026-05-12",
                "planned_termination_date": "2026-05-15",
                "employee_gained_material_benefit": True,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        m26_gain = ev_gain_ok.structured_findings["m26_deadline_assessment"]
        self.assertEqual(m26_gain["one_year_limit_status"], "WAIVED_BY_MATERIAL_GAIN_EXCEPTION_M26_1_SON")
        self.assertEqual(m26_gain["six_working_day_status"], "WITHIN_LIMIT")
        self.assertNotIn("BIR_YILLIK_UST_SURE_ASIMI_M26", {r.category for r in ev_gain_ok.risks})
        self.assertIn("M26_MADDI_MENFAAT_ISTISNASI_ISPAT_YUKU", {r.category for r in ev_gain_ok.risks})

        # 5. Material gain waives ONLY 1-year cap, NEVER 6-working-day limit!
        ev_gain_late6 = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                **base_facts,
                "act_date": "2024-10-01",
                "discovery_date": "2026-05-01",
                "planned_termination_date": "2026-05-15",
                "employee_gained_material_benefit": True,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_gain_late6.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertIn("HAK_DUSURUCU_SURE_ASIMI_M26", {r.category for r in ev_gain_late6.risks})

        # 6. >1 year with unverified material gain (None) -> escalates & asks missing_information
        ev_gain_unver = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                **base_facts,
                "act_date": "2024-10-01",
                "discovery_date": "2026-05-12",
                "planned_termination_date": "2026-05-15",
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(
            ev_gain_unver.structured_findings["m26_deadline_assessment"]["one_year_limit_status"],
            "EXCEEDED_MATERIAL_GAIN_EXCEPTION_UNVERIFIED",
        )
        self.assertIn("employee_gained_material_benefit", {m.field for m in ev_gain_unver.missing_information})
        self.assertEqual(ev_gain_unver.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")

    def test_m26_missing_dates_uncertain_authority_or_chronology_error_never_auto_clears_and_escalates(self) -> None:
        base_facts = {
            "termination_reason_type": "JUST_CAUSE_M25_II",
            "workplace_total_employees": 80,
            "tenure_months": 24,
            "contract_term_type": "INDEFINITE",
            "written_notice_with_clear_reason": True,
        }
        cases = [
            ("missing_act_date", {"discovery_date": "2026-05-12", "planned_termination_date": "2026-05-15", "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY"}, "act_date"),
            ("missing_discovery_date", {"act_date": "2026-05-10", "planned_termination_date": "2026-05-15", "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY"}, "discovery_date"),
            ("non_authorized_supervisor", {"act_date": "2026-05-10", "discovery_date": "2026-05-12", "planned_termination_date": "2026-05-15", "discovering_authority_status": "NON_AUTHORIZED_SUPERVISOR_ONLY"}, "discovering_authority_status"),
            ("uncertain_authority", {"act_date": "2026-05-10", "discovery_date": "2026-05-12", "planned_termination_date": "2026-05-15", "discovering_authority_status": "UNCERTAIN"}, "discovering_authority_status"),
            ("omitted_authority", {"act_date": "2026-05-10", "discovery_date": "2026-05-12", "planned_termination_date": "2026-05-15"}, "discovering_authority_status"),
        ]
        for label, extra, expected_missing_field in cases:
            with self.subTest(case=label):
                ev = evaluate_hr_legal_scenario(
                    scenario_type="TERMINATION_VALIDITY",
                    facts={**base_facts, **extra},
                    as_of_date="2026-05-15",
                    source_registry=self.sources,
                    precedent_registry=self.precedents,
                    knowledge_cards=self.cards,
                )
                self.assertEqual(ev.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
                self.assertTrue(ev.human_approval.counsel_escalation_required)
                self.assertFalse(ev.human_approval.payroll_handoff_allowed)
                self.assertIn(expected_missing_field, {m.field for m in ev.missing_information})
                self.assertIn("M26_SURE_VEYA_OGRENME_MAKAMI_BELIRSIZLIGI", {r.category for r in ev.risks})

        # Chronological contradiction (act_date after discovery_date)
        ev_chrono = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                **base_facts,
                "act_date": "2026-05-14",
                "discovery_date": "2026-05-10",
                "planned_termination_date": "2026-05-15",
                "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_chrono.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertIn("M26_TARIH_KRONOLOJI_CELISKISI", {r.category for r in ev_chrono.risks})

    # --- 2. 4857 m.19 Written Notice Validity Condition vs. m.25 / m.109 Proof Obligation ---

    def test_m19_written_notice_regime_for_valid_reason_m18_inside_vs_outside_job_security(self) -> None:
        # 1. Inside job security (>=30, >=6m, INDEFINITE) + written_notice=False -> m.19/1 statutory validity violation
        ev_in_bad = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                "termination_reason_type": "VALID_REASON_M18",
                "workplace_total_employees": 50,
                "tenure_months": 12,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": False,
                "written_defense_status": "VERIFIED",
                "last_resort_checked": True,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertTrue(ev_in_bad.structured_findings["m19_1_validity_condition_applies"])
        self.assertEqual(ev_in_bad.structured_findings["written_notice_regime"], "M19_1_STATUTORY_VALIDITY_CONDITION")
        self.assertIn("SEKIL_SARTI_IHLALI_M19", {r.category for r in ev_in_bad.risks})

        # 2. Outside job security (<30 employees) + written_notice=False on 2026-05-15 -> post-7555 m.109 mandatory written termination violation, NEVER m.19/1 invalidity!
        ev_out_bad = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                "termination_reason_type": "VALID_REASON_M18",
                "workplace_total_employees": 15,
                "tenure_months": 12,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": False,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertFalse(ev_out_bad.structured_findings["job_security_applies"])
        self.assertFalse(ev_out_bad.structured_findings["m19_1_validity_condition_applies"])
        self.assertEqual(
            ev_out_bad.structured_findings["written_notice_regime"],
            "POST_7555_M109_MANDATORY_WRITTEN_TERMINATION_OBLIGATION",
        )
        risk_cats = {r.category for r in ev_out_bad.risks}
        self.assertNotIn("SEKIL_SARTI_IHLALI_M19", risk_cats)
        self.assertIn("M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI", risk_cats)

    def test_m19_written_notice_not_auto_applied_to_m25_just_cause_terminations_except_union_rep_6356_m24(self) -> None:
        # Even inside job security (>=30, >=6m, INDEFINITE), 4857 m.25 immediate terminations MUST NOT emit SEKIL_SARTI_IHLALI_M19!
        # On 2026-05-15 (post-24.07.2025 Law No. 7555 m.23), missing written notice separately triggers M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI!
        for m25_type, extra in (
            (
                "JUST_CAUSE_M25_II",
                {
                    "act_date": "2026-05-10",
                    "discovery_date": "2026-05-12",
                    "planned_termination_date": "2026-05-15",
                    "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                },
            ),
            ("JUST_CAUSE_M25_I_B", {}),
            ("JUST_CAUSE_M25_III", {}),
        ):
            with self.subTest(reason_type=m25_type, written_notice=False):
                ev = evaluate_hr_legal_scenario(
                    scenario_type="TERMINATION_VALIDITY",
                    facts={
                        "termination_reason_type": m25_type,
                        "workplace_total_employees": 120,
                        "tenure_months": 36,
                        "contract_term_type": "INDEFINITE",
                        "written_notice_with_clear_reason": False,
                        **extra,
                    },
                    as_of_date="2026-05-15",
                    source_registry=self.sources,
                    precedent_registry=self.precedents,
                    knowledge_cards=self.cards,
                )
                self.assertFalse(ev.structured_findings["m19_1_validity_condition_applies"])
                self.assertEqual(
                    ev.structured_findings["written_notice_regime"],
                    "M25_POST_7555_M109_MANDATORY_WRITTEN_TERMINATION_NOT_M19_VALIDITY",
                )
                cats = {r.category for r in ev.risks}
                self.assertNotIn("SEKIL_SARTI_IHLALI_M19", cats)
                self.assertIn("M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI", cats)

        # Positive: clean m.25/I-b with written_notice=True -> UYGUN_ON_DEGERLENDIRME
        ev_m25_clean = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                "termination_reason_type": "JUST_CAUSE_M25_I_B",
                "workplace_total_employees": 120,
                "tenure_months": 36,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": True,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_m25_clean.decision_badge, "UYGUN_ON_DEGERLENDIRME")

        # Statutory exception: union representative (6356 m.24) requires written clear-cause notice as validity condition!
        ev_union = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                "termination_reason_type": "JUST_CAUSE_M25_II",
                "workplace_total_employees": 120,
                "tenure_months": 36,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": False,
                "is_union_representative": True,
                "act_date": "2026-05-10",
                "discovery_date": "2026-05-12",
                "planned_termination_date": "2026-05-15",
                "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(
            ev_union.structured_findings["written_notice_regime"],
            "STISK_M24_UNION_REP_WRITTEN_VALIDITY_CONDITION",
        )
        self.assertIn("SENDIKA_TEMSILCISI_YAZILI_SEBEP_IHLALI_6356_M24", {r.category for r in ev_union.risks})
        self.assertNotIn("SEKIL_SARTI_IHLALI_M19", {r.category for r in ev_union.risks})

    def test_m19_written_notice_regime_for_m17_notice_ikale_and_employee_resignation(self) -> None:
        # 1. m.17 non-job-security notice termination on 2026-05-15: outside job security -> post-7555 m.109 violation (NOT m.19/1)
        ev_m17_out = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                "termination_reason_type": "NOTICE_TERMINATION_M17_NON_JOB_SECURITY",
                "workplace_total_employees": 12,
                "tenure_months": 10,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": False,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertFalse(ev_m17_out.structured_findings["m19_1_validity_condition_applies"])
        self.assertIn("M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI", {r.category for r in ev_m17_out.risks})
        self.assertNotIn("SEKIL_SARTI_IHLALI_M19", {r.category for r in ev_m17_out.risks})

        # 2. m.17 notice termination attempted on worker INSIDE job security -> flags m.18/m.19 obligation!
        ev_m17_in = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                "termination_reason_type": "NOTICE_TERMINATION_M17_NON_JOB_SECURITY",
                "workplace_total_employees": 60,
                "tenure_months": 18,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": False,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertTrue(ev_m17_in.structured_findings["m19_1_validity_condition_applies"])
        self.assertIn("IS_GUVENCESI_KAPSAMINDA_M18_M19_ZORUNLULUGU", {r.category for r in ev_m17_in.risks})
        self.assertIn("SEKIL_SARTI_IHLALI_M19", {r.category for r in ev_m17_in.risks})

        # 3. İkale (TBK bilateral contract) -> NEVER SEKIL_SARTI_IHLALI_M19
        ev_ikale_bad = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                "termination_reason_type": "MUTUAL_TERMINATION_IKALE",
                "workplace_total_employees": 100,
                "tenure_months": 24,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": False,
                "reasonable_benefit_provided": True,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertFalse(ev_ikale_bad.structured_findings["m19_1_validity_condition_applies"])
        self.assertEqual(ev_ikale_bad.structured_findings["written_notice_regime"], "TBK_BILATERAL_CONTRACT_WRITTEN_PROOF_NOT_M19")
        self.assertIn("IKALE_YAZILI_SOZLESME_ISPAT_RISKI", {r.category for r in ev_ikale_bad.risks})
        self.assertNotIn("SEKIL_SARTI_IHLALI_M19", {r.category for r in ev_ikale_bad.risks})

        # 4. Employee resignation on 2026-05-15 -> post-7555 m.109 written obligation risk, NEVER SEKIL_SARTI_IHLALI_M19
        ev_resign_bad = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                "termination_reason_type": "EMPLOYEE_RESIGNATION",
                "workplace_total_employees": 100,
                "tenure_months": 24,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": False,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertFalse(ev_resign_bad.structured_findings["m19_1_validity_condition_applies"])
        self.assertEqual(
            ev_resign_bad.structured_findings["written_notice_regime"],
            "POST_7555_M109_EMPLOYEE_RESIGNATION_WRITTEN_OBLIGATION_NOT_M19",
        )
        self.assertIn("M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI", {r.category for r in ev_resign_bad.risks})
        self.assertNotIn("SEKIL_SARTI_IHLALI_M19", {r.category for r in ev_resign_bad.risks})

    # --- 3. Historical Validity Separation (legal_bases vs. historical_context + Undeterminable Escalation) ---

    def test_historical_basis_strictly_separated_into_historical_context_never_in_legal_bases(self) -> None:
        # 1. REINSTATEMENT_CLAIM on 2017-12-31 (1 day before 7036 m.3 effective date 2018-01-01)
        ev_pre = evaluate_hr_legal_scenario(
            scenario_type="REINSTATEMENT_CLAIM",
            facts={
                "workplace_total_employees": 20,
                "tenure_months": 14,
                "contract_term_type": "INDEFINITE",
                "is_employer_representative_m18_end": False,
                "termination_notice_date": "2017-12-31",
            },
            as_of_date="2017-12-31",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertTrue(all(b.effective_on_date is True for b in ev_pre.legal_bases))
        self.assertNotIn("MEVZUAT-7036", {b.source_id for b in ev_pre.legal_bases})
        self.assertIn("MEVZUAT-4857", {b.source_id for b in ev_pre.legal_bases})
        self.assertTrue(all(h.effective_on_date is False for h in ev_pre.historical_context))
        self.assertIn("MEVZUAT-7036", {h.source_id for h in ev_pre.historical_context})

        # 2. On exact effective boundary 2018-01-01 -> MEVZUAT-7036 moves into legal_bases, historical_context is empty
        ev_on = evaluate_hr_legal_scenario(
            scenario_type="REINSTATEMENT_CLAIM",
            facts={
                "workplace_total_employees": 20,
                "tenure_months": 14,
                "contract_term_type": "INDEFINITE",
                "is_employer_representative_m18_end": False,
                "termination_notice_date": "2018-01-01",
            },
            as_of_date="2018-01-01",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertIn("MEVZUAT-7036", {b.source_id for b in ev_on.legal_bases})
        self.assertEqual(len(ev_on.historical_context), 0)

        # 3. Future precedent (YIBBGK-2017-9-2018-10 decided 2018-10-19) evaluated on 2018-10-18 -> placed in historical_context!
        ev_pre_prec = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                "termination_reason_type": "JUST_CAUSE_M25_I_B",
                "workplace_total_employees": 50,
                "tenure_months": 24,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": True,
            },
            as_of_date="2018-10-18",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertNotIn("YIBBGK-2017-9-2018-10", {b.precedent_id for b in ev_pre_prec.legal_bases})
        self.assertIn("YIBBGK-2017-9-2018-10", {h.precedent_id for h in ev_pre_prec.historical_context})

    def test_undeterminable_effective_status_and_pre_statute_date_trigger_mandatory_escalation(self) -> None:
        # 1. Source with broken/unparseable effective_from -> YURURLUK_DURUMU_BELIRLENEMEYEN_KAYNAK + escalate
        mut_sources = dict(self.sources)
        mut_sources["MEVZUAT-4857"] = replace(self.sources["MEVZUAT-4857"], effective_from="INVALID-DATE")
        ev_broken_src = evaluate_hr_legal_scenario(
            scenario_type="ANNUAL_LEAVE_COMPLIANCE",
            facts={"tenure_years": 3, "employee_age": 30, "largest_split_block_days": 10, "signed_leave_register_verified": True},
            as_of_date="2026-05-15",
            source_registry=mut_sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_broken_src.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertIn("YURURLUK_DURUMU_BELIRLENEMEYEN_KAYNAK", {r.category for r in ev_broken_src.risks})
        self.assertNotIn("MEVZUAT-4857", {b.source_id for b in ev_broken_src.legal_bases})
        self.assertFalse(ev_broken_src.human_approval.payroll_handoff_allowed)

        # 2. Card with effective_date_verified=False -> YURURLUK_DURUMU_BELIRLENEMEYEN_KAYNAK + escalate
        mut_cards = dict(self.cards)
        orig_card = self.cards["CARD-4857-M53"]
        bad_ev = dict(orig_card.effective_validity)
        bad_ev["effective_date_verified"] = False
        mut_cards["CARD-4857-M53"] = replace(orig_card, effective_validity=bad_ev)
        ev_broken_card = evaluate_hr_legal_scenario(
            scenario_type="ANNUAL_LEAVE_COMPLIANCE",
            facts={"tenure_years": 3, "employee_age": 30, "largest_split_block_days": 10, "signed_leave_register_verified": True},
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=mut_cards,
        )
        self.assertEqual(ev_broken_card.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertIn("YURURLUK_DURUMU_BELIRLENEMEYEN_KAYNAK", {r.category for r in ev_broken_card.risks})
        self.assertNotIn("CARD-4857-M53", {b.card_id for b in ev_broken_card.legal_bases})

        # 3. Unknown source_id referenced in norm comparison -> escalates
        ev_unknown = evaluate_hr_legal_scenario(
            scenario_type="EMPLOYEE_FAVORABLE_NORM_COMPARISON",
            facts={
                "norm_a": {"title": "Bilinmeyen Kanun", "norm_layer": "STATUTORY_LAW", "source_id": "MEVZUAT-UNKNOWN-9999"},
                "norm_b": {"title": "TİS Hükmü", "norm_layer": "CBA_CONTRACT_AND_HR_PROCEDURE"},
                "mandatory_type": "RELATIVE_EMPLOYEE_FAVORABLE",
                "favors_employee_side": "NORM_B",
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_unknown.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertIn("YURURLUK_DURUMU_BELIRLENEMEYEN_KAYNAK", {r.category for r in ev_unknown.risks})

        # 4. Pre-statute date (2000-01-01, before 4857 existed) -> empty legal_bases, historical_context populated, CRITICAL escalation
        ev_2000 = evaluate_hr_legal_scenario(
            scenario_type="ANNUAL_LEAVE_COMPLIANCE",
            facts={"tenure_years": 3, "employee_age": 30, "largest_split_block_days": 10, "signed_leave_register_verified": True},
            as_of_date="2000-01-01",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(len(ev_2000.legal_bases), 0)
        self.assertGreaterEqual(len(ev_2000.historical_context), 2)
        self.assertEqual(ev_2000.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertIn("OLAY_TARIHINDE_YURURLUKTE_DAYANAK_YOK", {r.category for r in ev_2000.risks})
        self.assertFalse(ev_2000.human_approval.payroll_handoff_allowed)

    # --- 4. Boundary-Date Matrix Across All 7 Scenarios ---

    def test_boundary_dates_scenario1_termination_validity_tbk_m420_and_4857_effective_boundaries(self) -> None:
        facts = {
            "termination_reason_type": "MUTUAL_TERMINATION_IKALE",
            "workplace_total_employees": 60,
            "tenure_months": 24,
            "contract_term_type": "INDEFINITE",
            "written_notice_with_clear_reason": True,
            "reasonable_benefit_provided": True,
        }
        # 2012-06-30: 1 day BEFORE TBK 6098 effective date (2012-07-01) -> MEVZUAT-6098 in historical_context!
        ev_before = evaluate_hr_legal_scenario("TERMINATION_VALIDITY", facts, "2012-06-30", self.sources, self.precedents, self.cards)
        self.assertNotIn("MEVZUAT-6098", {b.source_id for b in ev_before.legal_bases})
        self.assertIn("MEVZUAT-6098", {h.source_id for h in ev_before.historical_context})
        self.assertIn("MEVZUAT-4857", {b.source_id for b in ev_before.legal_bases})

        # 2012-07-01: exact TBK effective date -> both MEVZUAT-6098 & MEVZUAT-4857 in legal_bases!
        ev_on = evaluate_hr_legal_scenario("TERMINATION_VALIDITY", facts, "2012-07-01", self.sources, self.precedents, self.cards)
        self.assertIn("MEVZUAT-6098", {b.source_id for b in ev_on.legal_bases})
        self.assertEqual(len(ev_on.historical_context), 0)

    def test_boundary_dates_scenario3_severance_and_notice_4857_and_5510_boundaries(self) -> None:
        # 2003-06-09 (before 4857) vs 2003-06-10 (exact 4857 effective date)
        f_basic = {"tenure_months": 24, "termination_reason_type": "EMPLOYER_VALID_OR_NOTICE_M17_M18", "notice_period_worked_or_given": True}
        ev_pre_4857 = evaluate_hr_legal_scenario("SEVERANCE_AND_NOTICE", f_basic, "2003-06-09", self.sources, self.precedents, self.cards)
        self.assertIn("MEVZUAT-1475", {b.source_id for b in ev_pre_4857.legal_bases})
        self.assertNotIn("MEVZUAT-4857", {b.source_id for b in ev_pre_4857.legal_bases})
        self.assertIn("MEVZUAT-4857", {h.source_id for h in ev_pre_4857.historical_context})

        ev_on_4857 = evaluate_hr_legal_scenario("SEVERANCE_AND_NOTICE", f_basic, "2003-06-10", self.sources, self.precedents, self.cards)
        self.assertIn("MEVZUAT-4857", {b.source_id for b in ev_on_4857.legal_bases})
        self.assertEqual(len(ev_on_4857.historical_context), 0)

        # 2008-09-30 vs 2008-10-01 for MEVZUAT-5510 (has_pre_18_insurance_days=True)
        f_ret = {
            "tenure_months": 60,
            "termination_reason_type": "RETIREMENT_1475_M14",
            "first_insurance_registration_date": "1995-05-01",
            "has_pre_18_insurance_days": True,
            "sgk_retirement_letter_verified": True,
        }
        ev_pre_5510 = evaluate_hr_legal_scenario("SEVERANCE_AND_NOTICE", f_ret, "2008-09-30", self.sources, self.precedents, self.cards)
        self.assertNotIn("MEVZUAT-5510", {b.source_id for b in ev_pre_5510.legal_bases})
        self.assertIn("MEVZUAT-5510", {h.source_id for h in ev_pre_5510.historical_context})

        ev_on_5510 = evaluate_hr_legal_scenario("SEVERANCE_AND_NOTICE", f_ret, "2008-10-01", self.sources, self.precedents, self.cards)
        self.assertIn("MEVZUAT-5510", {b.source_id for b in ev_on_5510.legal_bases})
        self.assertEqual(len(ev_on_5510.historical_context), 0)

    def test_boundary_dates_scenario4_overtime_compliance_regulation_amendment_boundary(self) -> None:
        facts = {
            "work_category": "GENERAL",
            "written_overtime_consent_in_file": True,
            "projected_annual_overtime_hours": 100,
            "daily_total_hours": 10.0,
        }
        # CARD-YON-FAZLA-CALISMA effective_from = 2017-08-25
        ev_before = evaluate_hr_legal_scenario("OVERTIME_COMPLIANCE", facts, "2017-08-24", self.sources, self.precedents, self.cards)
        self.assertIn("MEVZUAT-4857", {b.source_id for b in ev_before.legal_bases})
        self.assertNotIn("YONETMELIK-FAZLA-CALISMA-20040406", {b.source_id for b in ev_before.legal_bases})
        self.assertIn("YONETMELIK-FAZLA-CALISMA-20040406", {h.source_id for h in ev_before.historical_context})

        ev_on = evaluate_hr_legal_scenario("OVERTIME_COMPLIANCE", facts, "2017-08-25", self.sources, self.precedents, self.cards)
        self.assertIn("YONETMELIK-FAZLA-CALISMA-20040406", {b.source_id for b in ev_on.legal_bases})
        self.assertEqual(len(ev_on.historical_context), 0)

    def test_boundary_dates_scenario5_annual_leave_compliance_regulation_amendment_boundary(self) -> None:
        facts = {
            "tenure_years": 4,
            "employee_age": 32,
            "largest_split_block_days": 10,
            "signed_leave_register_verified": True,
        }
        # CARD-YON-YILLIK-IZIN effective_from = 2017-08-18
        ev_before = evaluate_hr_legal_scenario("ANNUAL_LEAVE_COMPLIANCE", facts, "2017-08-17", self.sources, self.precedents, self.cards)
        self.assertIn("MEVZUAT-4857", {b.source_id for b in ev_before.legal_bases})
        self.assertNotIn("YONETMELIK-YILLIK-IZIN-20040303", {b.source_id for b in ev_before.legal_bases})
        self.assertIn("YONETMELIK-YILLIK-IZIN-20040303", {h.source_id for h in ev_before.historical_context})

        ev_on = evaluate_hr_legal_scenario("ANNUAL_LEAVE_COMPLIANCE", facts, "2017-08-18", self.sources, self.precedents, self.cards)
        self.assertIn("YONETMELIK-YILLIK-IZIN-20040303", {b.source_id for b in ev_on.legal_bases})
        self.assertEqual(len(ev_on.historical_context), 0)

    def test_boundary_dates_scenario6_sgk_exit_code_5510_ssiy_and_4447_7161_boundaries(self) -> None:
        facts = {
            "proposed_sgk_exit_code": "04",
            "actual_termination_reason": "EMPLOYER_VALID_OR_NOTICE_M17_M18",
            "termination_date": "2019-01-12",
            "sgk_filing_date": "2019-01-17",
            "last_120_days_service_contract": True,
            "unemployment_premium_days_last_3_years": 800,
        }
        # 2019-01-17: 1 day BEFORE CARD-4447-M50-M51 (7161 s. Kanun 120-day amendment effective 2019-01-18)
        ev_pre_7161 = evaluate_hr_legal_scenario("SGK_EXIT_CODE_AND_UNEMPLOYMENT", facts, "2019-01-17", self.sources, self.precedents, self.cards)
        self.assertNotIn("MEVZUAT-4447", {b.source_id for b in ev_pre_7161.legal_bases})
        self.assertIn("MEVZUAT-4447", {h.source_id for h in ev_pre_7161.historical_context})
        self.assertIn("MEVZUAT-5510", {b.source_id for b in ev_pre_7161.legal_bases})

        # 2019-01-18: exact effective date -> all 4 bases in legal_bases, historical_context empty
        ev_on_7161 = evaluate_hr_legal_scenario(
            "SGK_EXIT_CODE_AND_UNEMPLOYMENT",
            {**facts, "sgk_filing_date": "2019-01-18"},
            "2019-01-18",
            self.sources,
            self.precedents,
            self.cards,
        )
        self.assertIn("MEVZUAT-4447", {b.source_id for b in ev_on_7161.legal_bases})
        self.assertEqual(len(ev_on_7161.historical_context), 0)

        # 2008-09-30: before 5510, SSİY, and 7161-4447 -> empty legal_bases + CRITICAL escalation
        ev_2008 = evaluate_hr_legal_scenario(
            "SGK_EXIT_CODE_AND_UNEMPLOYMENT",
            {**facts, "termination_date": "2008-09-25", "sgk_filing_date": "2008-09-30"},
            "2008-09-30",
            self.sources,
            self.precedents,
            self.cards,
        )
        self.assertEqual(len(ev_2008.legal_bases), 0)
        self.assertEqual(len(ev_2008.historical_context), 4)
        self.assertEqual(ev_2008.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")

    def test_boundary_dates_scenario7_employee_favorable_norm_comparison_10766_effective_window_and_superseded_9368(self) -> None:
        facts_10766 = {
            "norm_a": {
                "title": "10766 Sayılı Cumhurbaşkanı Kararı (2026 Uzaktan Çalışma Oranları)",
                "norm_layer": "PRESIDENTIAL_DECISION",
                "source_id": "RG-10766-20251225",
            },
            "norm_b": {
                "title": "Şirket Uzaktan Çalışma Prosedürü",
                "norm_layer": "CBA_CONTRACT_AND_HR_PROCEDURE",
            },
            "mandatory_type": "ABSOLUTE_MANDATORY",
            "favors_employee_side": "NEUTRAL",
        }
        # Before window (2025-12-31) -> historical_context & escalate
        ev_pre = evaluate_hr_legal_scenario("EMPLOYEE_FAVORABLE_NORM_COMPARISON", facts_10766, "2025-12-31", self.sources, self.precedents, self.cards)
        self.assertEqual(len(ev_pre.legal_bases), 0)
        self.assertIn("RG-10766-20251225", {h.source_id for h in ev_pre.historical_context})
        self.assertEqual(ev_pre.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertIn("OLAY_TARIHINDE_YURURLUKTE_OLMAYAN_NORM_KAYNAGI", {r.category for r in ev_pre.risks})

        # Exact start (2026-01-01) and end (2026-12-31) -> active in legal_bases!
        for d_ok in ("2026-01-01", "2026-12-31"):
            ev_ok = evaluate_hr_legal_scenario("EMPLOYEE_FAVORABLE_NORM_COMPARISON", facts_10766, d_ok, self.sources, self.precedents, self.cards)
            self.assertIn("RG-10766-20251225", {b.source_id for b in ev_ok.legal_bases})
            self.assertEqual(len(ev_ok.historical_context), 0)
            self.assertEqual(ev_ok.decision_badge, "UYGUN_ON_DEGERLENDIRME")

        # After window (2027-01-01) -> historical_context & escalate
        ev_post = evaluate_hr_legal_scenario("EMPLOYEE_FAVORABLE_NORM_COMPARISON", facts_10766, "2027-01-01", self.sources, self.precedents, self.cards)
        self.assertEqual(len(ev_post.legal_bases), 0)
        self.assertIn("RG-10766-20251225", {h.source_id for h in ev_post.historical_context})
        self.assertEqual(ev_post.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")

        # Superseded RG-9368-20241228 -> historical_context & DOGRULANMAMIS_VEYA_MULGA_NORM_KAYNAGI escalation
        facts_9368 = copy.deepcopy(facts_10766)
        facts_9368["norm_a"]["source_id"] = "RG-9368-20241228"
        ev_sup = evaluate_hr_legal_scenario("EMPLOYEE_FAVORABLE_NORM_COMPARISON", facts_9368, "2026-05-15", self.sources, self.precedents, self.cards)
        self.assertEqual(len(ev_sup.legal_bases), 0)
        self.assertIn("RG-9368-20241228", {h.source_id for h in ev_sup.historical_context})
        self.assertIn("DOGRULANMAMIS_VEYA_MULGA_NORM_KAYNAGI", {r.category for r in ev_sup.risks})
        self.assertEqual(ev_sup.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")

    def test_v102c1_schema_taxonomy_and_router_enforce_historical_context_and_v102c1_rules(self) -> None:
        scen_schema = json.loads(SCENARIO_SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertIn("historical_context", scen_schema["required"])
        self.assertIs(scen_schema["properties"]["legal_bases"]["items"]["properties"]["effective_on_date"]["const"], True)
        self.assertIs(scen_schema["properties"]["historical_context"]["items"]["properties"]["effective_on_date"]["const"], False)
        self.assertGreaterEqual(len(scen_schema["allOf"]), 4)

        tax = json.loads(TAXONOMY_PATH.read_text(encoding="utf-8"))
        self.assertTrue(tax["schema_version"].startswith(("1.0.2c", "1.0.3", "1.0.4", "1.0.5")))
        sr = tax["verification_infrastructure"]["strict_rules"]
        self.assertTrue(sr["exclude_turkish_ubgt_holidays_in_m26_working_days"])
        self.assertTrue(sr["separate_m26_six_day_one_year_material_gain_and_authority_checks"])
        self.assertTrue(sr["separate_m19_validity_condition_from_m109_written_notice_obligation"])
        self.assertTrue(sr["separate_effective_legal_bases_from_historical_context"])

        # Router roundtrip includes historical_context cleanly
        out = self.router.dispatch(
            "evaluate_hr_legal_scenario",
            {
                "scenario_type": "REINSTATEMENT_CLAIM",
                "as_of_date": "2017-12-31",
                "facts": {
                    "workplace_total_employees": 20,
                    "tenure_months": 12,
                    "contract_term_type": "INDEFINITE",
                    "is_employer_representative_m18_end": False,
                    "termination_notice_date": "2017-12-31",
                },
            },
        )
        self.assertIn("historical_context", out)
        self.assertEqual(len(out["historical_context"]), 1)
        self.assertEqual(out["historical_context"][0]["source_id"], "MEVZUAT-7036")
        self.assertFalse(out["historical_context"][0]["effective_on_date"])
        self.assertTrue(all(b["effective_on_date"] is True for b in out["legal_bases"]))


class TestV102c2M26SaturdayAndM109Law7555Hardening(unittest.TestCase):
    """Comprehensive v1.0.2c.2 regression tests for:
    1) 4857 m.26 statutory weekly rest day vs. 5-day workplace contractual non-working Saturday (akdi tatil),
    2) 4857 m.109 amended by Law No. 7555 m.23 (effective 2025-07-24) dual historical versioning & mandatory written termination rule,
    3) Gate 5 article-level post-decision amendment precision for Law No. 7555.
    """

    def setUp(self) -> None:
        self.sources = load_source_registry(SOURCES_PATH, strict=True)
        self.precedents = load_precedent_registry(PRECEDENTS_PATH, source_registry=self.sources, strict=True)
        self.cards = load_knowledge_cards(
            KB_ALL_DIR,
            source_registry=self.sources,
            precedent_registry=self.precedents,
            strict=True,
            audit_log_path=AUDIT_LOG_PATH,
        )
        self.router = HukukSGKToolRouter()

    # --- 1. 4857 m.26 Saturday & Statutory Weekly Rest Day Distinction ---

    def test_m26_five_day_workplace_saturday_is_still_counted_as_working_day_in_scenario(self) -> None:
        # 5-day workplace (Monday-Friday; saturday_is_working_day=False), default statutory weekly rest = SUNDAY.
        # Discovery = 2026-04-29 (Wed).
        # Apr 30(1), May 1(1 Mayıs UBGT skip), May 2(Sat=2 — akdi tatil, STILL counted as working day!),
        # May 3(Sun statutory weekly rest skip), May 4(3), May 5(4), May 6(5), May 7(6).
        base_facts = {
            "termination_reason_type": "JUST_CAUSE_M25_II",
            "workplace_total_employees": 120,
            "tenure_months": 30,
            "contract_term_type": "INDEFINITE",
            "written_notice_with_clear_reason": True,
            "notification_channel": "WRITTEN_HAND_OR_NOTARY",
            "act_date": "2026-04-28",
            "discovery_date": "2026-04-29",
            "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
            "saturday_is_working_day": False,
        }
        ev_day6 = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={**base_facts, "planned_termination_date": "2026-05-07"},
            as_of_date="2026-05-07",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        m26_6 = ev_day6.structured_findings["m26_deadline_assessment"]
        self.assertEqual(m26_6["working_days_since_discovery"], 6)
        self.assertEqual(m26_6["six_working_day_deadline_date"], "2026-05-07")
        self.assertEqual(m26_6["six_working_day_status"], "WITHIN_LIMIT")
        self.assertEqual(m26_6["weekly_rest_days"], ["SUNDAY"])
        self.assertFalse(m26_6["saturday_is_working_day"])
        self.assertEqual(
            m26_6["saturday_m26_counting_rule"],
            "COUNTED_AS_WORKING_DAY_CONTRACTUAL_OFF_NOT_STATUTORY_WEEKLY_REST",
        )
        self.assertIn("2026-05-02", m26_6["contractual_non_working_saturdays_counted"])
        self.assertEqual(ev_day6.decision_badge, "UYGUN_ON_DEGERLENDIRME")
        self.assertTrue(ev_day6.human_approval.payroll_handoff_allowed)

        # Day 7 (2026-05-08): MUST be EXCEEDED! (Previously wrongly returned 6 when saturday_is_working_day=False!)
        ev_day7 = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={**base_facts, "planned_termination_date": "2026-05-08"},
            as_of_date="2026-05-08",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        m26_7 = ev_day7.structured_findings["m26_deadline_assessment"]
        self.assertEqual(m26_7["working_days_since_discovery"], 7)
        self.assertEqual(m26_7["six_working_day_deadline_date"], "2026-05-07")
        self.assertEqual(m26_7["six_working_day_status"], "EXCEEDED")
        self.assertEqual(ev_day7.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertIn("HAK_DUSURUCU_SURE_ASIMI_M26", {r.category for r in ev_day7.risks})
        self.assertFalse(ev_day7.human_approval.payroll_handoff_allowed)

    def test_m26_legally_verified_weekly_rest_day_saturday_or_wednesday_or_cba_two_day_rest(self) -> None:
        # 1. Worker whose statutory 4857 m.46 weekly rest day IS Saturday (e.g. retail/shift, works Sunday):
        # Discovery = 2026-04-29 (Wed). Apr 30(1), May 1(UBGT skip), May 2(Sat statutory rest skip),
        # May 3(Sun=2), May 4(3), May 5(4), May 6(5), May 7(6).
        res_sat_rest = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2026-04-29",
            act_date_s="2026-04-28",
            action_date_s="2026-05-07",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
            weekly_rest_day="SATURDAY",
            saturday_is_working_day=False,
        )
        self.assertEqual(res_sat_rest["weekly_rest_days"], ["SATURDAY"])
        self.assertEqual(res_sat_rest["saturday_m26_counting_rule"], "EXCLUDED_AS_LEGALLY_VERIFIED_WEEKLY_REST_DAY")
        self.assertEqual(res_sat_rest["contractual_non_working_saturdays_counted"], [])
        self.assertEqual(res_sat_rest["working_days_since_discovery"], 6)
        self.assertEqual(res_sat_rest["six_working_day_deadline_date"], "2026-05-07")

        # Verify Sunday IS counted when weekly_rest_day="SATURDAY":
        # Discovery = 2026-05-02 (Sat) -> Sun May 3(1), Mon 4(2), Tue 5(3), Wed 6(4), Thu 7(5), Fri 8(6)
        self.assertEqual(add_turkish_working_days(date(2026, 5, 2), 6, weekly_rest_day="SATURDAY"), date(2026, 5, 8))
        # Whereas with default Sunday rest: Discovery = 2026-05-02 (Sat) -> Sun skip, Mon 4(1)..Sat 9(6)
        self.assertEqual(add_turkish_working_days(date(2026, 5, 2), 6), date(2026, 5, 9))

        # 2. Turkish weekday name support (weekly_rest_day="ÇARŞAMBA"):
        # Discovery = 2026-05-04 (Mon) -> Tue 5(1), Wed 6(skip), Thu 7(2), Fri 8(3), Sat 9(4), Sun 10(5), Mon 11(6)
        self.assertEqual(add_turkish_working_days(date(2026, 5, 4), 6, weekly_rest_day="ÇARŞAMBA"), date(2026, 5, 11))

        # 3. Legally verified 2-day statutory weekly rest (e.g. TİS clause explicitly designating Sat+Sun as hafta tatili):
        ev_cba_rest = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                "termination_reason_type": "JUST_CAUSE_M25_II",
                "workplace_total_employees": 120,
                "tenure_months": 30,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": True,
                "act_date": "2026-04-28",
                "discovery_date": "2026-04-29",
                "planned_termination_date": "2026-05-08",
                "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                "saturday_is_working_day": False,
                "legally_verified_weekly_rest_days": ["SATURDAY", "SUNDAY"],
            },
            as_of_date="2026-05-08",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        m26_cba = ev_cba_rest.structured_findings["m26_deadline_assessment"]
        self.assertEqual(m26_cba["weekly_rest_days"], ["SATURDAY", "SUNDAY"])
        self.assertEqual(m26_cba["working_days_since_discovery"], 6)
        self.assertEqual(m26_cba["six_working_day_deadline_date"], "2026-05-08")
        self.assertEqual(m26_cba["six_working_day_status"], "WITHIN_LIMIT")
        self.assertEqual(ev_cba_rest.decision_badge, "UYGUN_ON_DEGERLENDIRME")

        # 4. Invalid weekly_rest_day or unusual >=3 rest days -> escalate!
        res_bad = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2026-05-04",
            act_date_s="2026-05-01",
            action_date_s="2026-05-06",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
            weekly_rest_day="NOT_A_DAY",
        )
        self.assertTrue(res_bad["requires_counsel_escalation"])
        self.assertIn("M26_GECERSIZ_HAFTA_TATILI_TANIMI", {r.category for r in res_bad["_risks"]})

        res_many = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2026-05-04",
            act_date_s="2026-05-01",
            action_date_s="2026-05-06",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
            legally_verified_weekly_rest_days=["FRIDAY", "SATURDAY", "SUNDAY"],
        )
        self.assertTrue(res_many["requires_counsel_escalation"])
        self.assertIn("M26_OLAGANDISI_HAFTA_TATILI_GUN_SAYISI", {r.category for r in res_many["_risks"]})

    # --- 2. 4857 m.109 Amended by Law No. 7555 m.23 (Effective 2025-07-24) ---

    def test_m109_historical_amendment_registry_and_article_effective_date_boundaries(self) -> None:
        m4857 = self.sources["MEVZUAT-4857"]
        self.assertEqual(m4857.consolidated_text["latest_tracked_amendment"], "7555")
        amend_by_law = {a.amending_law_no: a for a in m4857.amendment_history}
        self.assertIn("7555", amend_by_law)
        self.assertEqual(amend_by_law["7555"].effective_from, "2025-07-24")
        self.assertEqual(amend_by_law["7555"].official_gazette_no, "32965")
        self.assertIn("Madde 109", amend_by_law["7555"].affected_articles)

        # Router check_article_effective_date on 2025-07-23 vs 2025-07-24
        pre_post_rule = self.router.dispatch(
            "check_article_effective_date",
            {"source_id": "MEVZUAT-4857", "article_ref": "Madde 109", "as_of_date": "2025-07-23"},
        )
        on_post_rule = self.router.dispatch(
            "check_article_effective_date",
            {"source_id": "MEVZUAT-4857", "article_ref": "Madde 109", "as_of_date": "2025-07-24"},
        )
        self.assertFalse(pre_post_rule["is_effective"])
        self.assertEqual(pre_post_rule["amended_by"], "7555")
        self.assertTrue(on_post_rule["is_effective"])
        self.assertEqual(on_post_rule["effective_from"], "2025-07-24")

        pre_orig_rule = resolve_effective_article(m4857, "Madde 109 (7555 Öncesi İlk Metin)", "2025-07-23")
        post_orig_rule = resolve_effective_article(m4857, "Madde 109 (7555 Öncesi İlk Metin)", "2025-07-24")
        self.assertTrue(pre_orig_rule["is_effective"])
        self.assertEqual(pre_orig_rule["effective_to"], "2025-07-23")
        self.assertFalse(post_orig_rule["is_effective"])

        # RG-7555-20250724 article-level boundaries: m.23 (2025-07-24) vs m.19 (2025-08-01)
        rg7555 = self.sources["RG-7555-20250724"]
        self.assertFalse(resolve_effective_article(rg7555, "Madde 23", "2025-07-23")["is_effective"])
        self.assertTrue(resolve_effective_article(rg7555, "Madde 23", "2025-07-24")["is_effective"])
        self.assertFalse(resolve_effective_article(rg7555, "Madde 19", "2025-07-31")["is_effective"])
        self.assertTrue(resolve_effective_article(rg7555, "Madde 19", "2025-08-01")["is_effective"])

    def test_m109_m25_just_cause_pre_vs_post_2025_07_24_boundary_separation_from_m19(self) -> None:
        for m25_type in ("JUST_CAUSE_M25_II", "JUST_CAUSE_M25_I_B", "JUST_CAUSE_M25_III"):
            # A. 2025-07-23 (1 day BEFORE 7555 m.23): pre-7555 m.109 original text regime
            extra_pre = (
                {
                    "act_date": "2025-07-20",
                    "discovery_date": "2025-07-21",
                    "planned_termination_date": "2025-07-23",
                    "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                }
                if m25_type == "JUST_CAUSE_M25_II"
                else {}
            )
            ev_pre = evaluate_hr_legal_scenario(
                scenario_type="TERMINATION_VALIDITY",
                facts={
                    "termination_reason_type": m25_type,
                    "workplace_total_employees": 120,
                    "tenure_months": 36,
                    "contract_term_type": "INDEFINITE",
                    "written_notice_with_clear_reason": False,
                    **extra_pre,
                },
                as_of_date="2025-07-23",
                source_registry=self.sources,
                precedent_registry=self.precedents,
                knowledge_cards=self.cards,
            )
            with self.subTest(era="PRE_7555_2025_07_23", reason_type=m25_type):
                sf = ev_pre.structured_findings
                self.assertFalse(sf["m19_1_validity_condition_applies"])
                self.assertFalse(sf["m109_7555_effective"])
                self.assertFalse(sf["m109_written_termination_mandatory"])
                self.assertEqual(sf["m109_version_applied"], "PRE_7555_ORIGINAL_M109_2003_06_10_TO_2025_07_23")
                self.assertEqual(
                    sf["written_notice_regime"],
                    "M25_PRE_7555_M109_STATUTORY_WRITTEN_AND_PROOF_NOT_M19_VALIDITY",
                )
                cats = {r.category for r in ev_pre.risks}
                self.assertNotIn("SEKIL_SARTI_IHLALI_M19", cats)
                self.assertNotIn("M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI", cats)
                self.assertIn("YAZILI_BILDIRIM_ISPAT_YUKU_M109", cats)
                self.assertNotIn("RG-7555-20250724", {b.source_id for b in ev_pre.legal_bases})
                self.assertEqual(len(ev_pre.historical_context), 0)

            # B. 2025-07-24 (EXACT effective date of 7555 m.23): mandatory written termination under m.109, STILL separate from m.19/1!
            extra_post = (
                {
                    "act_date": "2025-07-20",
                    "discovery_date": "2025-07-21",
                    "planned_termination_date": "2025-07-24",
                    "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                }
                if m25_type == "JUST_CAUSE_M25_II"
                else {}
            )
            ev_post = evaluate_hr_legal_scenario(
                scenario_type="TERMINATION_VALIDITY",
                facts={
                    "termination_reason_type": m25_type,
                    "workplace_total_employees": 120,
                    "tenure_months": 36,
                    "contract_term_type": "INDEFINITE",
                    "written_notice_with_clear_reason": False,
                    **extra_post,
                },
                as_of_date="2025-07-24",
                source_registry=self.sources,
                precedent_registry=self.precedents,
                knowledge_cards=self.cards,
            )
            with self.subTest(era="POST_7555_2025_07_24", reason_type=m25_type):
                sf = ev_post.structured_findings
                self.assertFalse(sf["m19_1_validity_condition_applies"])
                self.assertTrue(sf["m109_7555_effective"])
                self.assertTrue(sf["m109_written_termination_mandatory"])
                self.assertEqual(sf["m109_version_applied"], "POST_7555_M23_MANDATORY_WRITTEN_TERMINATION_2025_07_24_ONWARDS")
                self.assertEqual(
                    sf["written_notice_regime"],
                    "M25_POST_7555_M109_MANDATORY_WRITTEN_TERMINATION_NOT_M19_VALIDITY",
                )
                cats = {r.category for r in ev_post.risks}
                self.assertNotIn("SEKIL_SARTI_IHLALI_M19", cats)
                self.assertIn("M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI", cats)
                self.assertEqual(ev_post.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
                self.assertTrue(ev_post.human_approval.counsel_escalation_required)
                self.assertFalse(ev_post.human_approval.payroll_handoff_allowed)
                self.assertIn("RG-7555-20250724", {b.source_id for b in ev_post.legal_bases})
                self.assertEqual(len(ev_post.historical_context), 0)

    def test_m109_non_job_security_m17_and_m18_pre_vs_post_2025_07_24_not_mere_proof_advice(self) -> None:
        for rtype in ("VALID_REASON_M18", "NOTICE_TERMINATION_M17_NON_JOB_SECURITY"):
            base_f = {
                "termination_reason_type": rtype,
                "workplace_total_employees": 12,
                "tenure_months": 10,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": False,
            }
            ev_pre = evaluate_hr_legal_scenario("TERMINATION_VALIDITY", base_f, "2025-07-23", self.sources, self.precedents, self.cards)
            ev_post = evaluate_hr_legal_scenario("TERMINATION_VALIDITY", base_f, "2025-07-24", self.sources, self.precedents, self.cards)
            with self.subTest(reason_type=rtype):
                self.assertFalse(ev_pre.structured_findings["m19_1_validity_condition_applies"])
                self.assertEqual(
                    ev_pre.structured_findings["written_notice_regime"],
                    "PRE_7555_M109_STATUTORY_WRITTEN_AND_PROOF_OBLIGATION",
                )
                self.assertIn("YAZILI_BILDIRIM_ISPAT_YUKU_M109", {r.category for r in ev_pre.risks})
                self.assertNotIn("SEKIL_SARTI_IHLALI_M19", {r.category for r in ev_pre.risks})

                self.assertFalse(ev_post.structured_findings["m19_1_validity_condition_applies"])
                self.assertEqual(
                    ev_post.structured_findings["written_notice_regime"],
                    "POST_7555_M109_MANDATORY_WRITTEN_TERMINATION_OBLIGATION",
                )
                self.assertIn("M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI", {r.category for r in ev_post.risks})
                self.assertNotIn("SEKIL_SARTI_IHLALI_M19", {r.category for r in ev_post.risks})
                self.assertEqual(ev_post.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
                self.assertFalse(ev_post.human_approval.payroll_handoff_allowed)

    def test_m109_post_7555_rejects_kep_only_termination_even_when_written_notice_flag_true(self) -> None:
        # 7555 m.23: "İş sözleşmesinin feshi sonucunu doğuracak bildirimler her hâlde yazılı yapılır."
        # Even if caller passes written_notice_with_clear_reason=True, notification_channel="KEP_ONLY" MUST be flagged!
        for rtype, extra in (
            (
                "JUST_CAUSE_M25_II",
                {
                    "workplace_total_employees": 100,
                    "act_date": "2026-05-10",
                    "discovery_date": "2026-05-12",
                    "planned_termination_date": "2026-05-15",
                    "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                },
            ),
            ("JUST_CAUSE_M25_I_B", {"workplace_total_employees": 100}),
            (
                "VALID_REASON_M18",
                {"workplace_total_employees": 100, "written_defense_status": "VERIFIED", "last_resort_checked": True},
            ),
            ("NOTICE_TERMINATION_M17_NON_JOB_SECURITY", {"workplace_total_employees": 12}),
        ):
            with self.subTest(reason_type=rtype, channel="KEP_ONLY"):
                ev_kep = evaluate_hr_legal_scenario(
                    scenario_type="TERMINATION_VALIDITY",
                    facts={
                        "termination_reason_type": rtype,
                        "tenure_months": 24,
                        "contract_term_type": "INDEFINITE",
                        "written_notice_with_clear_reason": True,
                        "notification_channel": "KEP_ONLY",
                        **extra,
                    },
                    as_of_date="2026-05-15",
                    source_registry=self.sources,
                    precedent_registry=self.precedents,
                    knowledge_cards=self.cards,
                )
                cats = {r.category for r in ev_kep.risks}
                self.assertIn("M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI", cats)
                self.assertEqual(ev_kep.structured_findings["notification_channel"], "KEP_ONLY")
                self.assertEqual(ev_kep.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
                self.assertFalse(ev_kep.human_approval.payroll_handoff_allowed)
                m109_risk = next(r for r in ev_kep.risks if r.category == "M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI")
                self.assertIn("KEP", m109_risk.description)

        # Positive control: physical written notice (WRITTEN_HAND_OR_NOTARY) passes cleanly!
        ev_written_ok = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                "termination_reason_type": "JUST_CAUSE_M25_I_B",
                "workplace_total_employees": 100,
                "tenure_months": 24,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": True,
                "notification_channel": "WRITTEN_HAND_OR_NOTARY",
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_written_ok.decision_badge, "UYGUN_ON_DEGERLENDIRME")
        self.assertTrue(ev_written_ok.human_approval.payroll_handoff_allowed)

    def test_m109_job_security_m18_post_7555_emits_both_m19_and_m109_violations_separately(self) -> None:
        facts = {
            "termination_reason_type": "VALID_REASON_M18",
            "workplace_total_employees": 80,
            "tenure_months": 24,
            "contract_term_type": "INDEFINITE",
            "written_notice_with_clear_reason": False,
            "written_defense_status": "VERIFIED",
            "last_resort_checked": True,
        }
        ev_pre = evaluate_hr_legal_scenario("TERMINATION_VALIDITY", facts, "2025-07-23", self.sources, self.precedents, self.cards)
        ev_post = evaluate_hr_legal_scenario("TERMINATION_VALIDITY", facts, "2025-07-24", self.sources, self.precedents, self.cards)

        pre_cats = {r.category for r in ev_pre.risks}
        self.assertIn("SEKIL_SARTI_IHLALI_M19", pre_cats)
        self.assertNotIn("M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI", pre_cats)

        post_cats = {r.category for r in ev_post.risks}
        self.assertIn("SEKIL_SARTI_IHLALI_M19", post_cats)
        self.assertIn("M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI", post_cats)
        self.assertEqual(ev_post.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")

    def test_m109_planned_termination_date_crossing_2025_07_24_boundary_uses_notice_date(self) -> None:
        # Consultation happens on 2025-07-23, but planned termination notice is scheduled for 2025-07-24 (when 7555 m.23 is in force!)
        ev_cross = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                "termination_reason_type": "JUST_CAUSE_M25_II",
                "workplace_total_employees": 100,
                "tenure_months": 24,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": False,
                "act_date": "2025-07-20",
                "discovery_date": "2025-07-21",
                "planned_termination_date": "2025-07-24",
                "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
            },
            as_of_date="2025-07-23",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_cross.structured_findings["m109_evaluation_date"], "2025-07-24")
        self.assertTrue(ev_cross.structured_findings["m109_7555_effective"])
        self.assertIn("M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI", {r.category for r in ev_cross.risks})
        self.assertNotIn("SEKIL_SARTI_IHLALI_M19", {r.category for r in ev_cross.risks})

    def test_m109_employee_resignation_and_ikale_post_7555_distinction(self) -> None:
        # 1. Bilateral ikale under TBK is NOT unilateral m.109 termination notice
        ev_ikale = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                "termination_reason_type": "MUTUAL_TERMINATION_IKALE",
                "workplace_total_employees": 100,
                "tenure_months": 24,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": True,
                "reasonable_benefit_provided": True,
            },
            as_of_date="2026-05-15",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(ev_ikale.structured_findings["m109_version_applied"], "NOT_APPLICABLE_BILATERAL_IKALE")
        self.assertFalse(ev_ikale.structured_findings["m109_written_termination_mandatory"])
        self.assertEqual(ev_ikale.decision_badge, "UYGUN_ON_DEGERLENDIRME")

        # 2. Employee resignation pre-7555 (2025-07-23) vs post-7555 (2025-07-24)
        resign_facts = {
            "termination_reason_type": "EMPLOYEE_RESIGNATION",
            "workplace_total_employees": 100,
            "tenure_months": 24,
            "contract_term_type": "INDEFINITE",
            "written_notice_with_clear_reason": False,
        }
        ev_r_pre = evaluate_hr_legal_scenario("TERMINATION_VALIDITY", resign_facts, "2025-07-23", self.sources, self.precedents, self.cards)
        ev_r_post = evaluate_hr_legal_scenario("TERMINATION_VALIDITY", resign_facts, "2025-07-24", self.sources, self.precedents, self.cards)

        self.assertEqual(ev_r_pre.structured_findings["written_notice_regime"], "PRE_7555_M109_EMPLOYEE_RESIGNATION_PROOF_NOT_M19")
        self.assertIn("ISTIFA_YAZILI_ISPAT_RISKI_M109", {r.category for r in ev_r_pre.risks})
        self.assertNotIn("SEKIL_SARTI_IHLALI_M19", {r.category for r in ev_r_pre.risks})

        self.assertEqual(ev_r_post.structured_findings["written_notice_regime"], "POST_7555_M109_EMPLOYEE_RESIGNATION_WRITTEN_OBLIGATION_NOT_M19")
        self.assertIn("M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI", {r.category for r in ev_r_post.risks})
        self.assertNotIn("SEKIL_SARTI_IHLALI_M19", {r.category for r in ev_r_post.risks})

    def test_m109_pre_4857_date_routes_to_historical_context_and_escalates(self) -> None:
        ev_pre_4857 = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            facts={
                "termination_reason_type": "JUST_CAUSE_M25_I_B",
                "workplace_total_employees": 80,
                "tenure_months": 24,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": True,
            },
            as_of_date="2003-06-09",
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        self.assertEqual(len(ev_pre_4857.legal_bases), 0)
        self.assertEqual(ev_pre_4857.structured_findings["m109_version_applied"], "PRE_4857_NOT_EFFECTIVE")
        self.assertTrue(any("Madde 109" in h.legal_reference for h in ev_pre_4857.historical_context))
        self.assertEqual(ev_pre_4857.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertFalse(ev_pre_4857.human_approval.payroll_handoff_allowed)

    # --- 3. Gate 5 Article-Level Amendment Precision (Law No. 7555 m.109) ---

    def test_norm_hierarchy_gate5_article_level_amendment_precision_for_law_7555_m109(self) -> None:
        # 1. Existing verified YİBBGK precedents interpreting 4857 m.19/25, m.11, and m.34 (plus HMK m.109!)
        # MUST NOT be falsely invalidated by Law No. 7555 amending 4857 Madde 109!
        for pid in ("YIBBGK-2017-9-2018-10", "YIBBGK-2017-10-2019-1", "YIBBGK-2017-8-2019-3"):
            with self.subTest(precedent_id=pid):
                res = evaluate_precedent_application(
                    precedent=self.precedents[pid],
                    interpreted_source=self.sources["MEVZUAT-4857"],
                    as_of_date="2026-05-15",
                    scope_match_status="IN_SCOPE",
                )
                self.assertTrue(res.precedent_applicable_to_statute)
                self.assertEqual(res.post_decision_amendments, ())
                self.assertFalse(res.requires_counsel_escalation)

        # 2. A pre-2025 precedent that DOES interpret 4857 m.109 MUST trigger Gate 5 escalation after 2025-07-24!
        prec_m109 = PrecedentRecord(
            precedent_id="TEST-9HD-2022-M109",
            chamber="9_HD",
            binding_level="CHAMBER_SETTLED",
            esas_no="2022/100",
            karar_no="2022/200",
            decision_date="2022-05-10",
            official_source_url="https://karararama.yargitay.gov.tr/YargitayBilgiBankasiIstemciWeb/test109",
            related_source_ids=("MEVZUAT-4857",),
            legal_principle="4857 sayılı İş Kanunu m.109 yazılı bildirim hükmü m.25 fesihlerinde ispat şartıdır.",
            scope_limitations="4857 m.109 kapsamındaki bildirimler için geçerlidir.",
            scope_limitations_detail={"statutory_anchors": ["4857 m.109"]},
            verification_status="VERIFIED",
            verified_by="CALISORA-HUKUK-01",
            last_verified_at="2026-11-20",
        )
        res_m109 = evaluate_precedent_application(
            precedent=prec_m109,
            interpreted_source=self.sources["MEVZUAT-4857"],
            as_of_date="2026-05-15",
            scope_match_status="IN_SCOPE",
            application_rationale="Somut m.25 feshinde 4857 m.109 yazılı şeklin ispat niteliğini değerlendirmek için incelendi.",
        )
        self.assertFalse(res_m109.precedent_applicable_to_statute)
        self.assertEqual(res_m109.effective_outcome, "ESCALATE_TO_LEGAL_COUNSEL")
        self.assertTrue(res_m109.requires_counsel_escalation)
        self.assertTrue(any("7555" in item and "Madde 109" in item for item in res_m109.post_decision_amendments))

    # --- 4. Release Governance, Audit Integrity & Router Roundtrip (v1.0.2c.2) ---

    def test_v102c2_taxonomy_audit_log_and_router_metadata_consistency(self) -> None:
        tax = json.loads(TAXONOMY_PATH.read_text(encoding="utf-8"))
        self.assertTrue(tax["schema_version"].startswith(("1.0.2c", "1.0.3", "1.0.4", "1.0.5")))
        self.assertTrue(tax["legal_reasoning_engine"]["version"].startswith(("1.0.2c", "1.0.3", "1.0.4", "1.0.5")))
        sr = tax["verification_infrastructure"]["strict_rules"]
        self.assertTrue(sr["distinguish_statutory_weekly_rest_from_contractual_off_saturday_in_m26"])
        self.assertTrue(sr["enforce_m109_law_7555_mandatory_written_termination_from_2025_07_24"])

        audit_log = json.loads(AUDIT_LOG_PATH.read_text(encoding="utf-8"))
        self.assertTrue(audit_log["schema_version"].startswith(("1.0.2c", "1.0.3", "1.0.4", "1.0.5")))
        self.assertEqual(audit_log["summary"]["total_audited_records"], 74)
        self.assertEqual(audit_log["summary"]["fully_verified_records_count"], 70)
        self.assertEqual(audit_log["summary"]["pending_verification_records_count"], 3)
        self.assertEqual(audit_log["summary"]["superseded_records_count"], 1)
        self.assertEqual(len(self.cards), 39)

        # Router roundtrip verifying BOTH fixes together (5-day Saturday + post-7555 KEP-only m.25 termination)
        out = self.router.dispatch(
            "evaluate_hr_legal_scenario",
            {
                "scenario_type": "TERMINATION_VALIDITY",
                "as_of_date": "2026-05-08",
                "facts": {
                    "termination_reason_type": "JUST_CAUSE_M25_II",
                    "workplace_total_employees": 120,
                    "tenure_months": 36,
                    "contract_term_type": "INDEFINITE",
                    "written_notice_with_clear_reason": True,
                    "notification_channel": "KEP_ONLY",
                    "act_date": "2026-04-28",
                    "discovery_date": "2026-04-29",
                    "planned_termination_date": "2026-05-08",
                    "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                    "saturday_is_working_day": False,
                },
            },
        )
        self.assertEqual(out["decision_badge"], "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertFalse(out["human_approval"]["payroll_handoff_allowed"])
        self.assertEqual(out["structured_findings"]["m26_deadline_assessment"]["working_days_since_discovery"], 7)
        cats = {r["category"] for r in out["risks"]}
        self.assertIn("HAK_DUSURUCU_SURE_ASIMI_M26", cats)
        self.assertIn("M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI", cats)
        self.assertNotIn("SEKIL_SARTI_IHLALI_M19", cats)


class TestV102c3HolidayCalendarCoverageAndHalfDayReview(unittest.TestCase):
    """v1.0.2c.3 regression & adversarial tests for 4857 m.26 religious holiday calendar coverage gating, official provenance, and half-day official holiday eve legal review."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.sources = load_source_registry(SOURCES_PATH, strict=True)
        cls.precedents = load_precedent_registry(PRECEDENTS_PATH, source_registry=cls.sources, strict=True)
        cls.cards = load_knowledge_cards(
            KB_ALL_DIR,
            source_registry=cls.sources,
            precedent_registry=cls.precedents,
            strict=True,
            audit_log_path=AUDIT_LOG_PATH,
        )
        cls.router = HukukSGKToolRouter()

    # --- 1. Official Calendar Coverage Metadata & Strict Lookup ---

    def test_holiday_calendar_metadata_coverage_info_and_strict_ubgt_lookup(self) -> None:
        meta = TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA
        self.assertTrue(meta["calendar_version"].startswith(("1.0.2c", "1.0.3", "1.0.4", "1.0.5")))
        self.assertEqual(meta["coverage_start_year"], 2024)
        self.assertEqual(meta["coverage_end_year"], 2027)
        self.assertEqual(meta["covered_years"], [2024, 2025, 2026, 2027])
        self.assertIn("Diyanet", meta["official_source_authority"])
        self.assertEqual(meta["uncovered_year_policy"], "BLOCK_AND_ESCALATE_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
        self.assertEqual(meta["half_day_eve_legal_rule_status"], "PENDING_LEGAL_COUNSEL_RULE_CONFIRMATION")

        for covered_year in (2024, 2025, 2026, 2027):
            info = get_holiday_calendar_coverage_info(covered_year)
            self.assertTrue(info["calendar_complete_for_m26"])
            self.assertTrue(info["religious_holidays_covered"])
            self.assertTrue(info["half_day_eves_covered"])
            self.assertIsNone(info["blocker_code"])
            self.assertTrue(str(info["official_source_url"]).startswith("https://vakithesaplama.diyanet.gov.tr/"))

            hols_strict = get_turkish_ubgt_holidays(covered_year, require_verified_religious_calendar=True)
            eves_strict = get_turkish_half_day_eves(covered_year, require_verified_religious_calendar=True)
            expected_full_days = 13 if covered_year == 2027 else 14  # 7 fixed + 7 religious; 2027-05-19 overlaps 19 Mayıs + Kurban 4. gün
            self.assertEqual(len(hols_strict), expected_full_days)
            if covered_year == 2027:
                self.assertIn("19 Mayıs", hols_strict[date(2027, 5, 19)])
                self.assertIn("Kurban Bayramı", hols_strict[date(2027, 5, 19)])
            self.assertEqual(len(eves_strict), 3)  # 28 Ekim + Ramazan Arifesi + Kurban Arifesi
            report = get_turkish_ubgt_calendar_report(covered_year)
            self.assertTrue(report["calendar_complete_for_m26"])
            self.assertEqual(len(report["religious_full_holidays"]), 7)
            self.assertEqual(len(report["half_day_eves"]), 3)

        # Uncovered years (<= 2023 and >= 2028) MUST explicitly report incomplete coverage and raise in strict mode
        for uncovered_year in (2019, 2023, 2028, 2031):
            info = get_holiday_calendar_coverage_info(uncovered_year)
            self.assertFalse(info["calendar_complete_for_m26"])
            self.assertFalse(info["religious_holidays_covered"])
            self.assertFalse(info["half_day_eves_covered"])
            self.assertEqual(info["blocker_code"], "HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
            self.assertIsNone(info["official_source_url"])

            # Backward-compatible non-strict lookup still returns fixed UBGT holidays (e.g. 1 Ocak, 29 Ekim)
            fixed_only = get_turkish_ubgt_holidays(uncovered_year, require_verified_religious_calendar=False)
            self.assertIn(date(uncovered_year, 1, 1), fixed_only)
            self.assertIn(date(uncovered_year, 10, 29), fixed_only)

            # Strict lookup MUST raise ValueError with HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE
            with self.assertRaisesRegex(ValueError, "HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE"):
                get_turkish_ubgt_holidays(uncovered_year, require_verified_religious_calendar=True)
            with self.assertRaisesRegex(ValueError, "HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE"):
                get_turkish_half_day_eves(uncovered_year, require_verified_religious_calendar=True)

            report = get_turkish_ubgt_calendar_report(uncovered_year)
            self.assertFalse(report["calendar_complete_for_m26"])
            self.assertEqual(report["blocker_code"], "HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
            self.assertEqual(report["religious_full_holidays"], {})

    # --- 2. Out-of-Coverage Years (<= 2023 & >= 2028) Blocker & Escalation ---

    def test_m26_year_2023_and_earlier_blocks_with_holiday_calendar_coverage_incomplete(self) -> None:
        # Case A: 2023 Ramazan Bayramı period (Apr 21-23, 2023) — MUST NOT silently count religious holidays as working days!
        res_2023_bayram = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            as_of_date="2023-04-26",
            facts={
                "termination_reason_type": "JUST_CAUSE_M25_II",
                "workplace_total_employees": 80,
                "tenure_months": 24,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": True,
                "act_date": "2023-04-17",
                "discovery_date": "2023-04-18",
                "planned_termination_date": "2023-04-26",
                "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
            },
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        m26_a = res_2023_bayram.structured_findings["m26_deadline_assessment"]
        self.assertEqual(m26_a["six_working_day_status"], "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
        self.assertIsNone(m26_a["working_days_since_discovery"])
        self.assertIsNone(m26_a["six_working_day_deadline_date"])
        self.assertTrue(m26_a["religious_holiday_calendar_unverified"])
        self.assertFalse(m26_a["holiday_calendar_coverage_complete"])
        self.assertEqual(m26_a["holiday_calendar_coverage_status"], "INCOMPLETE_UNCOVERED_YEARS")
        self.assertEqual(m26_a["uncovered_calendar_years"], [2023])
        self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", m26_a["calendar_blocker_codes"])
        self.assertEqual(res_2023_bayram.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertTrue(res_2023_bayram.human_approval.counsel_escalation_required)
        self.assertFalse(res_2023_bayram.human_approval.payroll_handoff_allowed)
        self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", {r.category for r in res_2023_bayram.risks})
        self.assertIn("verified_religious_holiday_calendar", {m.field for m in res_2023_bayram.missing_information})
        # Never produce an assumed EXCEEDED verdict from missing 2023 religious holidays!
        self.assertNotIn("HAK_DUSURUCU_SURE_ASIMI_M26", {r.category for r in res_2023_bayram.risks})

        # Case B: Even a short 2-day window in 2023 (or 2019) MUST NOT automatically claim complete coverage!
        for act_s, disc_s, term_s, expected_year in (
            ("2023-05-01", "2023-05-02", "2023-05-04", 2023),
            ("2019-08-08", "2019-08-09", "2019-08-15", 2019),
        ):
            m26_old = evaluate_m26_forfeiture_deadlines(
                discovery_date_s=disc_s,
                act_date_s=act_s,
                action_date_s=term_s,
                discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
            )
            self.assertEqual(m26_old["six_working_day_status"], "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
            self.assertEqual(m26_old["uncovered_calendar_years"], [expected_year])
            self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", m26_old["calendar_blocker_codes"])
            self.assertTrue(m26_old["requires_counsel_escalation"])
            self.assertIsNone(m26_old["working_days_since_discovery"])
            self.assertIsNone(m26_old["six_working_day_deadline_date"])

    def test_m26_year_2028_and_later_blocks_with_holiday_calendar_coverage_incomplete(self) -> None:
        # Case A: 2028 Ramazan window (Feb 27-29, 2028) — MUST block with HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE
        res_2028 = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            as_of_date="2028-03-04",
            facts={
                "termination_reason_type": "JUST_CAUSE_M25_II",
                "workplace_total_employees": 150,
                "tenure_months": 36,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": True,
                "notification_channel": "WRITTEN_HAND_OR_NOTARY",
                "act_date": "2028-02-23",
                "discovery_date": "2028-02-24",
                "planned_termination_date": "2028-03-04",
                "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
            },
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        m26_28 = res_2028.structured_findings["m26_deadline_assessment"]
        self.assertEqual(m26_28["six_working_day_status"], "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
        self.assertIsNone(m26_28["working_days_since_discovery"])
        self.assertIsNone(m26_28["six_working_day_deadline_date"])
        self.assertFalse(m26_28["holiday_calendar_coverage_complete"])
        self.assertEqual(m26_28["uncovered_calendar_years"], [2028])
        self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", m26_28["calendar_blocker_codes"])
        self.assertIsNotNone(m26_28["provisional_working_days_without_religious_holidays"])
        self.assertIsNotNone(m26_28["provisional_deadline_without_religious_holidays"])
        self.assertEqual(res_2028.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertTrue(res_2028.human_approval.counsel_escalation_required)
        self.assertFalse(res_2028.human_approval.payroll_handoff_allowed)
        self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", {r.category for r in res_2028.risks})
        self.assertNotIn("HAK_DUSURUCU_SURE_ASIMI_M26", {r.category for r in res_2028.risks})

        # Case B: Non-bayram month in 2028 and 2030 still blocked (uncovered years NEVER assumed complete)
        for disc_s, act_s, term_s, expected_yr in (
            ("2028-11-01", "2028-10-31", "2028-11-03", 2028),
            ("2030-06-03", "2030-06-02", "2030-06-05", 2030),
        ):
            m26_fut = evaluate_m26_forfeiture_deadlines(
                discovery_date_s=disc_s,
                act_date_s=act_s,
                action_date_s=term_s,
                discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
            )
            self.assertEqual(m26_fut["six_working_day_status"], "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
            self.assertEqual(m26_fut["uncovered_calendar_years"], [expected_yr])
            self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", m26_fut["calendar_blocker_codes"])
            self.assertTrue(m26_fut["requires_counsel_escalation"])

    def test_m26_year_boundary_crossing_2027_to_2028_and_2023_to_2024_blocks_incomplete_year(self) -> None:
        # Crossing from covered 2027 into uncovered 2028 (both when action is in 2028 and when 6-day deadline spills into 2028)
        m26_27_28 = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2027-12-29",
            act_date_s="2027-12-28",
            action_date_s="2028-01-05",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
        )
        self.assertEqual(m26_27_28["six_working_day_status"], "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
        self.assertEqual(m26_27_28["uncovered_calendar_years"], [2028])
        self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", m26_27_28["calendar_blocker_codes"])
        self.assertTrue(m26_27_28["requires_counsel_escalation"])

        # Action still in 2027-12-30, yet the 6-working-day deadline extends into uncovered 2028!
        m26_spill = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2027-12-29",
            act_date_s="2027-12-28",
            action_date_s="2027-12-30",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
        )
        self.assertEqual(m26_spill["six_working_day_status"], "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
        self.assertEqual(m26_spill["uncovered_calendar_years"], [2028])

        # Crossing from uncovered 2023 into covered 2024
        m26_23_24 = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2023-12-28",
            act_date_s="2023-12-27",
            action_date_s="2024-01-04",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
        )
        self.assertEqual(m26_23_24["six_working_day_status"], "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
        self.assertEqual(m26_23_24["uncovered_calendar_years"], [2023])
        self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", m26_23_24["calendar_blocker_codes"])

    def test_m26_uncovered_year_external_verification_requires_explicit_flag_and_holiday_list(self) -> None:
        complete_2028_calendar, approvers_reg, att_ledger, _ = _build_signed_external_calendar_bundle(
            {
                "2028": {
                    "year": 2028,
                    "ramazan_arife_date": "2028-02-26",
                    "ramazan_start_date": "2028-02-27",
                    "ramazan_end_date": "2028-02-29",
                    "kurban_arife_date": "2028-05-04",
                    "kurban_start_date": "2028-05-05",
                    "kurban_end_date": "2028-05-08",
                    "official_source_url": "https://vakithesaplama.diyanet.gov.tr/icerik.php?icerik=155",
                    "verified_at": "2027-12-15",
                    "verified_by": "CALISORA-HUKUK-01",
                    "calendar_version": "2028.1",
                }
            }
        )

        # Negative 1: Passing additional_public_holidays or complete calendar WITHOUT religious_calendar_externally_verified=True MUST STILL BLOCK!
        m26_no_flag = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2028-02-24",
            act_date_s="2028-02-23",
            action_date_s="2028-03-04",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
            additional_public_holidays=["2028-02-27", "2028-02-28", "2028-02-29"],
            external_verified_holiday_calendars=complete_2028_calendar,
            religious_calendar_externally_verified=False,
            approvers_registry=approvers_reg,
            attestation_ledger=att_ledger,
        )
        self.assertEqual(m26_no_flag["six_working_day_status"], "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
        self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", m26_no_flag["calendar_blocker_codes"])
        self.assertTrue(m26_no_flag["requires_counsel_escalation"])

        # Negative 2: Passing religious_calendar_externally_verified=True WITHOUT complete yearly calendar (or with flat list alone) MUST STILL BLOCK!
        m26_no_list = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2028-02-24",
            act_date_s="2028-02-23",
            action_date_s="2028-03-04",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
            additional_public_holidays=None,
            religious_calendar_externally_verified=True,
        )
        self.assertEqual(m26_no_list["six_working_day_status"], "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
        self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", m26_no_list["calendar_blocker_codes"])

        # Positive 1: Complete cryptographically attested 2028 yearly record + religious_calendar_externally_verified=True + counsel-confirmed arife rule -> exact calculation (day 6 = 2028-03-04 -> WITHIN_LIMIT!)
        res_ok = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            as_of_date="2028-03-04",
            facts={
                "termination_reason_type": "JUST_CAUSE_M25_II",
                "workplace_total_employees": 100,
                "tenure_months": 24,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": True,
                "notification_channel": "WRITTEN_HAND_OR_NOTARY",
                "act_date": "2028-02-23",
                "discovery_date": "2028-02-24",
                "planned_termination_date": "2028-03-04",
                "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                "external_verified_holiday_calendars": complete_2028_calendar,
                "religious_calendar_externally_verified": True,
                "half_day_eve_legal_rule": "COUNT_AS_WORKING_DAY",
            },
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
            approvers_registry=approvers_reg,
            attestation_ledger=att_ledger,
        )
        m26_ok = res_ok.structured_findings["m26_deadline_assessment"]
        self.assertEqual(m26_ok["six_working_day_status"], "WITHIN_LIMIT")
        self.assertEqual(m26_ok["working_days_since_discovery"], 6)
        self.assertEqual(m26_ok["six_working_day_deadline_date"], "2028-03-04")
        self.assertTrue(m26_ok["holiday_calendar_coverage_complete"])
        self.assertEqual(m26_ok["holiday_calendar_coverage_status"], "EXTERNALLY_VERIFIED_FOR_UNCOVERED_YEAR")
        self.assertEqual(m26_ok["calendar_blocker_codes"], [])
        self.assertEqual(res_ok.decision_badge, "UYGUN_ON_DEGERLENDIRME")

        # Positive 2: Day 7 (2028-03-06, skipping Sun Mar 5) under externally verified 2028 calendar + COUNT_AS_WORKING_DAY -> EXCEEDED!
        m26_exc = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2028-02-24",
            act_date_s="2028-02-23",
            action_date_s="2028-03-06",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
            external_verified_holiday_calendars=complete_2028_calendar,
            religious_calendar_externally_verified=True,
            half_day_eve_legal_rule="COUNT_AS_WORKING_DAY",
            approvers_registry=approvers_reg,
            attestation_ledger=att_ledger,
        )
        self.assertEqual(m26_exc["six_working_day_status"], "EXCEEDED")
        self.assertEqual(m26_exc["working_days_since_discovery"], 7)
        self.assertEqual(m26_exc["six_working_day_deadline_date"], "2028-03-04")

    # --- 3. Half-Day Official Holiday Eves (28 Ekim, Ramazan & Kurban Arifesi) Legal Review Gating ---

    def test_m26_half_day_eve_28_ekim_boundary_never_assumes_until_legal_review_confirms(self) -> None:
        # Discovery: 2026-10-26 (Mon), Termination: 2026-11-04 (Wed)
        # Oct 28 (Wed) is 28 Ekim Cumhuriyet Bayramı Arifesi (13:00+ half-day).
        # If counted as working day -> deadline=2026-11-03 (7 days -> EXCEEDED).
        # If excluded as non-working day -> deadline=2026-11-04 (6 days -> WITHIN_LIMIT).
        base_facts = {
            "termination_reason_type": "JUST_CAUSE_M25_II",
            "workplace_total_employees": 120,
            "tenure_months": 30,
            "contract_term_type": "INDEFINITE",
            "written_notice_with_clear_reason": True,
            "notification_channel": "WRITTEN_HAND_OR_NOTARY",
            "act_date": "2026-10-25",
            "discovery_date": "2026-10-26",
            "planned_termination_date": "2026-11-04",
            "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
        }

        # 1) Default (UNVERIFIED_REQUIRE_LEGAL_REVIEW) -> MUST NOT assume PASS or EXCEEDED; MUST escalate!
        res_unverified = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            as_of_date="2026-11-04",
            facts=base_facts,
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        m26_u = res_unverified.structured_findings["m26_deadline_assessment"]
        self.assertEqual(m26_u["six_working_day_status"], "PENDING_LEGAL_REVIEW_HALF_DAY_HOLIDAY_EVE")
        self.assertIsNone(m26_u["working_days_since_discovery"])
        self.assertIsNone(m26_u["six_working_day_deadline_date"])
        self.assertEqual(m26_u["half_day_eve_legal_rule"], "UNVERIFIED_REQUIRE_LEGAL_REVIEW")
        hd = m26_u["half_day_eve_assessment"]
        self.assertTrue(hd["requires_legal_review"])
        self.assertTrue(hd["outcome_differs_by_half_day_rule"])
        self.assertEqual(hd["deadline_if_counted_as_working_day"], "2026-11-03")
        self.assertEqual(hd["deadline_if_excluded_as_non_working_day"], "2026-11-04")
        self.assertEqual(hd["days_elapsed_if_counted_as_working_day"], 7)
        self.assertEqual(hd["days_elapsed_if_excluded_as_non_working_day"], 6)
        self.assertEqual(len(hd["active_half_day_eves"]), 1)
        self.assertEqual(hd["active_half_day_eves"][0]["date"], "2026-10-28")
        self.assertEqual(res_unverified.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertTrue(res_unverified.human_approval.counsel_escalation_required)
        self.assertFalse(res_unverified.human_approval.payroll_handoff_allowed)
        self.assertIn("M26_YARIM_GUN_TATIL_HUKUKI_INCELEME_GEREKLI", {r.category for r in res_unverified.risks})
        self.assertNotIn("HAK_DUSURUCU_SURE_ASIMI_M26", {r.category for r in res_unverified.risks})
        self.assertIn("half_day_eve_legal_rule", {m.field for m in res_unverified.missing_information})

        # 2) Legal counsel explicitly confirms COUNT_AS_WORKING_DAY -> deterministic EXCEEDED (7 days, deadline 2026-11-03)
        res_counted = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            as_of_date="2026-11-04",
            facts={**base_facts, "half_day_eve_legal_rule": "COUNT_AS_WORKING_DAY"},
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        m26_c = res_counted.structured_findings["m26_deadline_assessment"]
        self.assertEqual(m26_c["six_working_day_status"], "EXCEEDED")
        self.assertEqual(m26_c["working_days_since_discovery"], 7)
        self.assertEqual(m26_c["six_working_day_deadline_date"], "2026-11-03")
        self.assertFalse(m26_c["half_day_eve_assessment"]["requires_legal_review"])
        self.assertIn("HAK_DUSURUCU_SURE_ASIMI_M26", {r.category for r in res_counted.risks})
        self.assertEqual(res_counted.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")

        # 3) Legal counsel explicitly confirms EXCLUDE_AS_NON_WORKING_DAY -> deterministic WITHIN_LIMIT (6 days, deadline 2026-11-04)
        res_excl = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            as_of_date="2026-11-04",
            facts={**base_facts, "half_day_eve_legal_rule": "EXCLUDE_AS_NON_WORKING_DAY"},
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        m26_e = res_excl.structured_findings["m26_deadline_assessment"]
        self.assertEqual(m26_e["six_working_day_status"], "WITHIN_LIMIT")
        self.assertEqual(m26_e["working_days_since_discovery"], 6)
        self.assertEqual(m26_e["six_working_day_deadline_date"], "2026-11-04")
        self.assertFalse(m26_e["half_day_eve_assessment"]["requires_legal_review"])
        self.assertEqual(res_excl.decision_badge, "UYGUN_ON_DEGERLENDIRME")
        self.assertFalse(res_excl.human_approval.counsel_escalation_required)

    def test_m26_half_day_eve_ramazan_and_kurban_arife_boundaries_and_exceeded_under_both_views(self) -> None:
        # Case A: Ramazan Bayramı Arifesi 2026-03-19 (Thu), Discovery=2026-03-18, Action=2026-03-28 (boundary!)
        m26_ram = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2026-03-18",
            act_date_s="2026-03-17",
            action_date_s="2026-03-28",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
        )
        self.assertEqual(m26_ram["six_working_day_status"], "PENDING_LEGAL_REVIEW_HALF_DAY_HOLIDAY_EVE")
        self.assertTrue(m26_ram["half_day_eve_assessment"]["outcome_differs_by_half_day_rule"])
        self.assertEqual(m26_ram["half_day_eve_assessment"]["deadline_if_counted_as_working_day"], "2026-03-27")
        self.assertEqual(m26_ram["half_day_eve_assessment"]["deadline_if_excluded_as_non_working_day"], "2026-03-28")
        self.assertEqual(m26_ram["half_day_eve_assessment"]["active_half_day_eves"][0]["date"], "2026-03-19")
        self.assertTrue(m26_ram["requires_counsel_escalation"])

        # Case B: Kurban Bayramı Arifesi 2026-05-26 (Tue), Discovery=2026-05-25, Action=2026-06-06 (boundary!)
        m26_kurb_b = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2026-05-25",
            act_date_s="2026-05-24",
            action_date_s="2026-06-06",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
        )
        self.assertEqual(m26_kurb_b["six_working_day_status"], "PENDING_LEGAL_REVIEW_HALF_DAY_HOLIDAY_EVE")
        self.assertTrue(m26_kurb_b["half_day_eve_assessment"]["outcome_differs_by_half_day_rule"])
        self.assertEqual(m26_kurb_b["half_day_eve_assessment"]["deadline_if_counted_as_working_day"], "2026-06-05")
        self.assertEqual(m26_kurb_b["half_day_eve_assessment"]["deadline_if_excluded_as_non_working_day"], "2026-06-06")
        self.assertEqual(m26_kurb_b["half_day_eve_assessment"]["active_half_day_eves"][0]["date"], "2026-05-26")

        # Case C: Kurban Bayramı Arifesi exceeded under BOTH interpretations (Action=2026-06-08 -> 8 days counted / 7 days excluded)
        res_both = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            as_of_date="2026-06-08",
            facts={
                "termination_reason_type": "JUST_CAUSE_M25_II",
                "workplace_total_employees": 120,
                "tenure_months": 18,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": True,
                "notification_channel": "WRITTEN_HAND_OR_NOTARY",
                "act_date": "2026-05-24",
                "discovery_date": "2026-05-25",
                "planned_termination_date": "2026-06-08",
                "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
            },
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        m26_both = res_both.structured_findings["m26_deadline_assessment"]
        self.assertEqual(m26_both["six_working_day_status"], "EXCEEDED_UNDER_BOTH_HALF_DAY_INTERPRETATIONS")
        self.assertIsNone(m26_both["working_days_since_discovery"])
        self.assertIsNone(m26_both["six_working_day_deadline_date"])
        self.assertFalse(m26_both["half_day_eve_assessment"]["outcome_differs_by_half_day_rule"])
        self.assertTrue(m26_both["half_day_eve_assessment"]["requires_legal_review"])
        risk_levels = {r.category: r.risk_level for r in res_both.risks}
        self.assertEqual(risk_levels.get("HAK_DUSURUCU_SURE_ASIMI_M26"), "CRITICAL")
        self.assertEqual(risk_levels.get("M26_YARIM_GUN_TATIL_HUKUKI_INCELEME_GEREKLI"), "MEDIUM")
        self.assertEqual(res_both.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")

    def test_m26_half_day_eve_non_boundary_rest_day_overlap_and_invalid_rule(self) -> None:
        # 1) Non-boundary date inside 28 Ekim window (2026-10-30, 3/2 days) STILL refuses to publish an assumed 6-day deadline while unverified
        m26_non_b = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2026-10-26",
            act_date_s="2026-10-25",
            action_date_s="2026-10-30",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
        )
        self.assertEqual(m26_non_b["six_working_day_status"], "PENDING_LEGAL_REVIEW_HALF_DAY_HOLIDAY_EVE")
        self.assertFalse(m26_non_b["half_day_eve_assessment"]["outcome_differs_by_half_day_rule"])
        self.assertTrue(m26_non_b["half_day_eve_assessment"]["requires_legal_review"])
        self.assertIsNone(m26_non_b["six_working_day_deadline_date"])
        self.assertTrue(m26_non_b["requires_counsel_escalation"])

        # 2) Half-day eve falling on worker's statutory weekly rest day (2024-06-15 Sat Kurban Arifesi with weekly_rest_day="SATURDAY")
        # MUST NOT cause a false-positive half-day escalation because Saturday is already excluded!
        m26_rest_overlap = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2024-06-14",
            act_date_s="2024-06-13",
            action_date_s="2024-06-24",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
            weekly_rest_day="SATURDAY",
        )
        self.assertEqual(m26_rest_overlap["six_working_day_status"], "WITHIN_LIMIT")
        self.assertEqual(m26_rest_overlap["working_days_since_discovery"], 4)
        self.assertEqual(m26_rest_overlap["six_working_day_deadline_date"], "2024-06-26")
        self.assertEqual(m26_rest_overlap["half_day_eve_assessment"]["active_half_day_eves"], [])
        self.assertFalse(m26_rest_overlap["half_day_eve_assessment"]["requires_legal_review"])
        self.assertFalse(m26_rest_overlap["requires_counsel_escalation"])

        # 3) Invalid half_day_eve_legal_rule emits M26_GECERSIZ_YARIM_GUN_KURALI and forces escalation (falls back to UNVERIFIED_REQUIRE_LEGAL_REVIEW)
        m26_bad_rule = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2026-10-26",
            act_date_s="2026-10-25",
            action_date_s="2026-11-04",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
            half_day_eve_legal_rule="ASSUME_WORKING_DAY",
        )
        self.assertEqual(m26_bad_rule["half_day_eve_legal_rule"], "UNVERIFIED_REQUIRE_LEGAL_REVIEW")
        self.assertEqual(m26_bad_rule["six_working_day_status"], "PENDING_LEGAL_REVIEW_HALF_DAY_HOLIDAY_EVE")
        self.assertTrue(m26_bad_rule["requires_counsel_escalation"])
        self.assertIn("M26_GECERSIZ_YARIM_GUN_KURALI", {r.category for r in m26_bad_rule["_risks"]})

    # --- 4. Central Audit Log Calendar Provenance & 74/74 Preservation ---

    def test_central_audit_log_records_and_validates_holiday_calendar_provenance_preserving_74_records(self) -> None:
        audit_data = json.loads(AUDIT_LOG_PATH.read_text(encoding="utf-8"))
        self.assertTrue(audit_data["schema_version"].startswith(("1.0.2c", "1.0.3", "1.0.4", "1.0.5")))
        self.assertEqual(audit_data["external_legal_counsel_signoff_status"], "PENDING_SIGNED_EXTERNAL_ATTESTATION")

        # Exact 74/74 L1-L4 audit record preservation!
        summary = audit_data["summary"]
        self.assertEqual(summary["total_audited_records"], 74)
        self.assertEqual(summary["fully_verified_records_count"], 70)
        self.assertEqual(summary["pending_verification_records_count"], 3)
        self.assertEqual(summary["superseded_records_count"], 1)
        self.assertEqual(len(audit_data["entries"]), 74)

        # Calendar provenance block checks
        hca = audit_data["holiday_calendar_audit"]
        self.assertEqual(hca["calendar_id"], TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["calendar_id"])
        self.assertTrue(hca["calendar_version"].startswith(("1.0.2c", "1.0.3", "1.0.4", "1.0.5")))
        self.assertEqual(hca["covered_years"], [2024, 2025, 2026, 2027])
        self.assertEqual(hca["verified_at"], TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["verified_at"])
        self.assertEqual(hca["verified_by"], "CALISORA-HUKUK-01")
        self.assertEqual(hca["uncovered_year_policy"], "BLOCK_AND_ESCALATE_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
        self.assertEqual(hca["half_day_eve_legal_rule_status"], "PENDING_LEGAL_COUNSEL_RULE_CONFIRMATION")
        for yr in ("2024", "2025", "2026", "2027"):
            self.assertTrue(hca["official_source_urls"][yr].startswith("https://vakithesaplama.diyanet.gov.tr/"))

        # Clean central audit log passes validator
        clean_rep = validate_central_audit_log(audit_data, self.sources, self.precedents, self.cards)
        self.assertTrue(clean_rep.valid, clean_rep.flags)
        self.assertEqual(clean_rep.flags, [])
        self.assertEqual(clean_rep.total_records, 74)
        self.assertEqual(clean_rep.verified_count, 70)

        # Negative mutation tests on holiday_calendar_audit
        # 1) Missing official URL for a covered year (2027) -> MUST FAIL validation
        mut_missing_url = copy.deepcopy(audit_data)
        del mut_missing_url["holiday_calendar_audit"]["official_source_urls"]["2027"]
        rep1 = validate_central_audit_log(mut_missing_url, self.sources, self.precedents, self.cards)
        self.assertFalse(rep1.valid)
        self.assertIn("MISSING_HOLIDAY_CALENDAR_OFFICIAL_URL", {f.code for f in rep1.flags})

        # 2) Bad uncovered_year_policy (allowing silent fallback) -> MUST FAIL validation
        mut_bad_policy = copy.deepcopy(audit_data)
        mut_bad_policy["holiday_calendar_audit"]["uncovered_year_policy"] = "ASSUME_COMPLETE"
        rep2 = validate_central_audit_log(mut_bad_policy, self.sources, self.precedents, self.cards)
        self.assertFalse(rep2.valid)
        self.assertIn("INVALID_UNCOVERED_YEAR_POLICY", {f.code for f in rep2.flags})

        # 3) Non-ISO verified_at date -> MUST FAIL validation
        mut_bad_date = copy.deepcopy(audit_data)
        mut_bad_date["holiday_calendar_audit"]["verified_at"] = "20/11/2026"
        rep3 = validate_central_audit_log(mut_bad_date, self.sources, self.precedents, self.cards)
        self.assertFalse(rep3.valid)
        self.assertIn("INVALID_HOLIDAY_CALENDAR_VERIFIED_DATE", {f.code for f in rep3.flags})

    # --- 5. Schema, Taxonomy, Tool Schemas & System Prompt Consistency ---

    def test_v102c3_schemas_taxonomy_tool_schemas_and_prompt_document_calendar_and_half_day_rules(self) -> None:
        tax = json.loads(TAXONOMY_PATH.read_text(encoding="utf-8"))
        self.assertTrue(tax["schema_version"].startswith(("1.0.2c", "1.0.3", "1.0.4", "1.0.5")))
        self.assertTrue(tax["legal_reasoning_engine"]["version"].startswith(("1.0.2c", "1.0.3", "1.0.4", "1.0.5")))
        sr = tax["verification_infrastructure"]["strict_rules"]
        self.assertTrue(sr["block_and_escalate_uncovered_holiday_calendar_years_in_m26"])
        self.assertTrue(sr["require_legal_review_for_half_day_holiday_eves_in_m26"])
        m26_tax = tax["legal_reasoning_engine"]["m26_deadline_engine"]
        self.assertIn("2024–2027", m26_tax["religious_holiday_calendar_coverage"])
        self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", m26_tax["religious_holiday_calendar_coverage"])
        self.assertIn("holiday_calendar_audit", m26_tax["religious_holiday_calendar_coverage"])
        self.assertIn("half_day_eve_legal_rule", m26_tax["half_day_holiday_eve_rule"])
        self.assertIn("M26_YARIM_GUN_TATIL_HUKUKI_INCELEME_GEREKLI", m26_tax["half_day_holiday_eve_rule"])

        # Tool schemas document new optional facts parameters & blocker code
        tools_doc = json.loads(TOOLS_SCHEMA_PATH.read_text(encoding="utf-8"))
        eval_tool = next(t for t in tools_doc["tools"] if t["name"] == "evaluate_hr_legal_scenario")
        facts_desc = eval_tool["parameters"]["properties"]["facts"]["description"]
        self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", eval_tool["description"])
        self.assertIn("religious_calendar_externally_verified", facts_desc)
        self.assertIn("half_day_eve_legal_rule", facts_desc)

        # System prompt documents v1.0.2c calendar & half-day rules
        prompt_text = (PROJECT_ROOT / "agent" / "system_prompt.md").read_text(encoding="utf-8")
        self.assertIn("v1.0.2c", prompt_text)
        self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", prompt_text)
        self.assertIn("half_day_eve_legal_rule", prompt_text)

        # All 4 JSON Schemas reference 1.0.2c
        for sp in (SOURCE_SCHEMA_PATH, PRECEDENT_SCHEMA_PATH, CARD_SCHEMA_PATH, SCENARIO_SCHEMA_PATH):
            s_doc = json.loads(sp.read_text(encoding="utf-8"))
            self.assertTrue("1.0.2c" in s_doc["title"] or "1.0.3" in s_doc["title"] or "1.0.4" in s_doc["title"] or "1.0.5" in s_doc["title"], sp.name)

    # --- 6. End-to-End Router Roundtrip & Backward Compatibility ---

    def test_v102c3_backward_compatibility_m26_saturday_m109_law7555_and_router_roundtrip(self) -> None:
        # 1) Router roundtrip for uncovered 2028 year + KEP_ONLY channel -> BOTH HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE and M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI
        out_2028_kep = self.router.dispatch(
            "evaluate_hr_legal_scenario",
            {
                "scenario_type": "TERMINATION_VALIDITY",
                "as_of_date": "2028-03-04",
                "facts": {
                    "termination_reason_type": "JUST_CAUSE_M25_II",
                    "workplace_total_employees": 90,
                    "tenure_months": 20,
                    "contract_term_type": "INDEFINITE",
                    "written_notice_with_clear_reason": True,
                    "notification_channel": "KEP_ONLY",
                    "act_date": "2028-02-23",
                    "discovery_date": "2028-02-24",
                    "planned_termination_date": "2028-03-04",
                    "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                },
            },
        )
        self.assertEqual(out_2028_kep["decision_badge"], "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertFalse(out_2028_kep["human_approval"]["payroll_handoff_allowed"])
        cats_28 = {r["category"] for r in out_2028_kep["risks"]}
        self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", cats_28)
        self.assertIn("M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI", cats_28)
        self.assertNotIn("SEKIL_SARTI_IHLALI_M19", cats_28)

        # 2) Router roundtrip for 28 Ekim 2026 half-day eve boundary + 5-day workplace Saturday still counted
        out_28_ekim = self.router.dispatch(
            "evaluate_hr_legal_scenario",
            {
                "scenario_type": "TERMINATION_VALIDITY",
                "as_of_date": "2026-11-04",
                "facts": {
                    "termination_reason_type": "JUST_CAUSE_M25_II",
                    "workplace_total_employees": 90,
                    "tenure_months": 20,
                    "contract_term_type": "INDEFINITE",
                    "written_notice_with_clear_reason": True,
                    "notification_channel": "WRITTEN_HAND_OR_NOTARY",
                    "act_date": "2026-10-25",
                    "discovery_date": "2026-10-26",
                    "planned_termination_date": "2026-11-04",
                    "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                    "saturday_is_working_day": False,
                },
            },
        )
        m26_ek = out_28_ekim["structured_findings"]["m26_deadline_assessment"]
        self.assertEqual(m26_ek["six_working_day_status"], "PENDING_LEGAL_REVIEW_HALF_DAY_HOLIDAY_EVE")
        self.assertEqual(
            m26_ek["saturday_m26_counting_rule"],
            "COUNTED_AS_WORKING_DAY_CONTRACTUAL_OFF_NOT_STATUTORY_WEEKLY_REST",
        )
        self.assertIn("2026-10-31", m26_ek["contractual_non_working_saturdays_counted"])
        self.assertEqual(m26_ek["half_day_eve_assessment"]["deadline_if_counted_as_working_day"], "2026-11-03")
        self.assertEqual(m26_ek["half_day_eve_assessment"]["deadline_if_excluded_as_non_working_day"], "2026-11-04")
        self.assertFalse(out_28_ekim["human_approval"]["payroll_handoff_allowed"])


class TestV102c4HolidayCalendarIntegrityAndArifeHardening(unittest.TestCase):
    """v1.0.2c.4 regression & adversarial tests closing external calendar bypass holes, enforcing per-year full+arife+provenance integrity, ingesting external arife dates into get_turkish_half_day_eves(), and making holiday_calendar_audit mandatory in the central audit log."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.sources = load_source_registry(SOURCES_PATH, strict=True)
        cls.precedents = load_precedent_registry(PRECEDENTS_PATH, source_registry=cls.sources, strict=True)
        cls.cards = load_knowledge_cards(
            KB_ALL_DIR,
            source_registry=cls.sources,
            precedent_registry=cls.precedents,
            strict=True,
            audit_log_path=AUDIT_LOG_PATH,
        )
        cls.router = HukukSGKToolRouter()

    @staticmethod
    def _complete_2028_record() -> dict[str, object]:
        return {
            "year": 2028,
            "verification_status": "VERIFIED",
            "ramazan_arife_date": "2028-02-26",
            "ramazan_start_date": "2028-02-27",
            "ramazan_end_date": "2028-02-29",
            "kurban_arife_date": "2028-05-04",
            "kurban_start_date": "2028-05-05",
            "kurban_end_date": "2028-05-08",
            "official_source_url": "https://vakithesaplama.diyanet.gov.tr/icerik.php?icerik=155",
            "verified_at": "2027-12-15",
            "verified_by": "CALISORA-HUKUK-01",
            "calendar_version": "2028.1",
        }

    @staticmethod
    def _complete_2029_record() -> dict[str, object]:
        return {
            "year": 2029,
            "verification_status": "VERIFIED",
            "ramazan_arife_date": "2029-02-14",
            "ramazan_start_date": "2029-02-15",
            "ramazan_end_date": "2029-02-17",
            "kurban_arife_date": "2029-04-23",
            "kurban_start_date": "2029-04-24",
            "kurban_end_date": "2029-04-27",
            "official_source_url": "https://vakithesaplama.diyanet.gov.tr/icerik.php?icerik=156",
            "verified_at": "2028-12-15",
            "verified_by": "CALISORA-HUKUK-01",
            "calendar_version": "2029.1",
        }

    # --- 1. Uncovered-Year Integrity: Empty List, Single Bayram, Multi-Year & Provenance ---

    def test_empty_additional_public_holidays_with_external_verified_flag_true_stays_blocked(self) -> None:
        res = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            as_of_date="2028-03-04",
            facts={
                "termination_reason_type": "JUST_CAUSE_M25_II",
                "workplace_total_employees": 120,
                "tenure_months": 24,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": True,
                "notification_channel": "WRITTEN_HAND_OR_NOTARY",
                "act_date": "2028-02-23",
                "discovery_date": "2028-02-24",
                "planned_termination_date": "2028-03-04",
                "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                "additional_public_holidays": [],
                "religious_calendar_externally_verified": True,
            },
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        m26 = res.structured_findings["m26_deadline_assessment"]
        self.assertEqual(m26["six_working_day_status"], "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
        self.assertIsNone(m26["working_days_since_discovery"])
        self.assertIsNone(m26["six_working_day_deadline_date"])
        self.assertFalse(m26["holiday_calendar_coverage_complete"])
        self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", m26["calendar_blocker_codes"])
        self.assertEqual(m26["unverified_calendar_years"], [2028])
        self.assertIn("2028", m26["external_calendar_validation_errors"])
        self.assertEqual(res.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertFalse(res.human_approval.payroll_handoff_allowed)
        self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", {r.category for r in res.risks})

    def test_flat_additional_public_holidays_or_single_bayram_only_record_stays_blocked(self) -> None:
        # Case A: Flat additional_public_holidays with Ramazan days only (no structured yearly calendar) -> BLOCKED!
        m26_flat = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2028-02-24",
            act_date_s="2028-02-23",
            action_date_s="2028-03-04",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
            additional_public_holidays=["2028-02-27", "2028-02-28", "2028-02-29"],
            religious_calendar_externally_verified=True,
        )
        self.assertEqual(m26_flat["six_working_day_status"], "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
        self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", m26_flat["calendar_blocker_codes"])
        self.assertEqual(m26_flat["unverified_calendar_years"], [2028])

        # Case B: Structured record with ONLY Ramazan Bayramı (Kurban missing!) -> BLOCKED!
        only_ramazan = self._complete_2028_record()
        for k in ("kurban_arife_date", "kurban_start_date", "kurban_end_date"):
            del only_ramazan[k]
        m26_only_ram = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2028-02-24",
            act_date_s="2028-02-23",
            action_date_s="2028-03-04",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
            religious_calendar_externally_verified=True,
            external_verified_holiday_calendars={"2028": only_ramazan},
            half_day_eve_legal_rule="COUNT_AS_WORKING_DAY",
        )
        self.assertEqual(m26_only_ram["six_working_day_status"], "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
        self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", m26_only_ram["calendar_blocker_codes"])
        self.assertTrue(any("kurban" in e.lower() for e in m26_only_ram["external_calendar_validation_errors"]["2028"]))

        # Case C: Structured record with ONLY Kurban Bayramı (Ramazan missing!) -> BLOCKED!
        only_kurban = self._complete_2028_record()
        for k in ("ramazan_arife_date", "ramazan_start_date", "ramazan_end_date"):
            del only_kurban[k]
        m26_only_kurb = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2028-05-03",
            act_date_s="2028-05-02",
            action_date_s="2028-05-12",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
            religious_calendar_externally_verified=True,
            external_verified_holiday_calendars={"2028": only_kurban},
            half_day_eve_legal_rule="COUNT_AS_WORKING_DAY",
        )
        self.assertEqual(m26_only_kurb["six_working_day_status"], "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
        self.assertTrue(any("ramazan" in e.lower() for e in m26_only_kurb["external_calendar_validation_errors"]["2028"]))

        # Case D: Wrong bayram duration (Ramazan 2 days instead of 3, or Kurban 3 days instead of 4) -> BLOCKED!
        short_ram = self._complete_2028_record()
        short_ram["ramazan_end_date"] = "2028-02-28"
        v_short = validate_external_yearly_holiday_calendar(2028, short_ram)
        self.assertFalse(v_short["valid"])
        self.assertFalse(v_short["full_days_valid"])

    def test_multi_uncovered_years_only_one_verified_stays_blocked_until_both_independently_verified(self) -> None:
        # Window crossing TWO uncovered years: 2028-12-28 (Thu) -> 2029-01-05 (Fri)
        signed_2028_only, appr_28, led_28, _ = _build_signed_external_calendar_bundle({"2028": self._complete_2028_record()})
        signed_both, appr_both, led_both, _ = _build_signed_external_calendar_bundle(
            {"2028": self._complete_2028_record(), "2029": self._complete_2029_record()}
        )

        # Step 1: ONLY 2028 verified (2029 missing!) -> MUST REMAIN BLOCKED!
        res_partial = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            as_of_date="2029-01-05",
            facts={
                "termination_reason_type": "JUST_CAUSE_M25_II",
                "workplace_total_employees": 100,
                "tenure_months": 30,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": True,
                "notification_channel": "WRITTEN_HAND_OR_NOTARY",
                "act_date": "2028-12-27",
                "discovery_date": "2028-12-28",
                "planned_termination_date": "2029-01-05",
                "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                "religious_calendar_externally_verified": True,
                "external_verified_holiday_calendars": signed_2028_only,
            },
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
            approvers_registry=appr_28,
            attestation_ledger=led_28,
        )
        m26_p = res_partial.structured_findings["m26_deadline_assessment"]
        self.assertEqual(m26_p["six_working_day_status"], "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
        self.assertEqual(m26_p["uncovered_calendar_years"], [2028, 2029])
        self.assertEqual(m26_p["externally_verified_calendar_years"], [2028])
        self.assertEqual(m26_p["unverified_calendar_years"], [2029])
        self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", m26_p["calendar_blocker_codes"])
        self.assertEqual(res_partial.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertFalse(res_partial.human_approval.payroll_handoff_allowed)

        # Step 2: BOTH 2028 AND 2029 independently verified -> calendar lock opens cleanly!
        # Dec 29 Fri(1), Dec 30 Sat(2), Dec 31 Sun(skip), Jan 1 Yılbaşı(skip), Jan 2 Tue(3), Jan 3 Wed(4), Jan 4 Thu(5), Jan 5 Fri(6) -> WITHIN_LIMIT!
        res_both = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            as_of_date="2029-01-05",
            facts={
                "termination_reason_type": "JUST_CAUSE_M25_II",
                "workplace_total_employees": 100,
                "tenure_months": 30,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": True,
                "notification_channel": "WRITTEN_HAND_OR_NOTARY",
                "act_date": "2028-12-27",
                "discovery_date": "2028-12-28",
                "planned_termination_date": "2029-01-05",
                "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                "religious_calendar_externally_verified": True,
                "external_verified_holiday_calendars": signed_both,
            },
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
            approvers_registry=appr_both,
            attestation_ledger=led_both,
        )
        m26_b = res_both.structured_findings["m26_deadline_assessment"]
        self.assertEqual(m26_b["six_working_day_status"], "WITHIN_LIMIT")
        self.assertEqual(m26_b["working_days_since_discovery"], 6)
        self.assertEqual(m26_b["six_working_day_deadline_date"], "2029-01-05")
        self.assertTrue(m26_b["holiday_calendar_coverage_complete"])
        self.assertEqual(m26_b["externally_verified_calendar_years"], [2028, 2029])
        self.assertEqual(m26_b["unverified_calendar_years"], [])
        self.assertEqual(m26_b["calendar_blocker_codes"], [])
        self.assertEqual(res_both.decision_badge, "UYGUN_ON_DEGERLENDIRME")

    def test_external_calendar_missing_provenance_fields_or_bare_url_or_disallowed_verifier_stays_blocked(self) -> None:
        bad_variants = [
            ("missing_url", {"official_source_url": ""}),
            ("bare_homepage_url", {"official_source_url": "https://vakithesaplama.diyanet.gov.tr/"}),
            ("unofficial_domain", {"official_source_url": "https://example.com/holidays/2028"}),
            ("missing_verified_at", {"verified_at": ""}),
            ("bad_verified_at", {"verified_at": "15.12.2027"}),
            ("missing_verified_by", {"verified_by": ""}),
            ("disallowed_verifier_ai", {"verified_by": "AI"}),
            ("missing_calendar_version", {"calendar_version": ""}),
            ("pending_status", {"verification_status": "PENDING_REVIEW"}),
        ]
        for label, overrides in bad_variants:
            rec = {**self._complete_2028_record(), **overrides}
            chk = validate_external_yearly_holiday_calendar(2028, rec)
            self.assertFalse(chk["valid"], f"Expected invalid for {label}")
            self.assertFalse(chk["provenance_valid"], f"Expected provenance_valid=False for {label}")

            m26 = evaluate_m26_forfeiture_deadlines(
                discovery_date_s="2028-03-13",
                act_date_s="2028-03-12",
                action_date_s="2028-03-18",
                discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
                religious_calendar_externally_verified=True,
                external_verified_holiday_calendars={"2028": rec},
            )
            self.assertEqual(m26["six_working_day_status"], "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", label)
            self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", m26["calendar_blocker_codes"], label)

    # --- 2. Missing Arife vs. Complete Yearly Calendar + External Arife Legal Review Gate ---

    def test_full_days_verified_but_arife_dates_missing_or_invalid_stays_blocked_and_engages_legal_review_gate(self) -> None:
        # Full Ramazan (3d) + Full Kurban (4d) + Provenance ALL valid, ONLY arife dates omitted!
        missing_arife = self._complete_2028_record()
        del missing_arife["ramazan_arife_date"]
        del missing_arife["kurban_arife_date"]

        chk = validate_external_yearly_holiday_calendar(2028, missing_arife)
        self.assertTrue(chk["full_days_valid"])
        self.assertTrue(chk["provenance_valid"])
        self.assertFalse(chk["arife_dates_valid"])
        self.assertFalse(chk["valid"])

        res = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            as_of_date="2028-03-04",
            facts={
                "termination_reason_type": "JUST_CAUSE_M25_II",
                "workplace_total_employees": 100,
                "tenure_months": 24,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": True,
                "notification_channel": "WRITTEN_HAND_OR_NOTARY",
                "act_date": "2028-02-23",
                "discovery_date": "2028-02-24",
                "planned_termination_date": "2028-03-04",
                "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                "religious_calendar_externally_verified": True,
                "external_verified_holiday_calendars": {"2028": missing_arife},
            },
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        m26 = res.structured_findings["m26_deadline_assessment"]
        self.assertEqual(m26["six_working_day_status"], "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
        self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", m26["calendar_blocker_codes"])
        self.assertFalse(m26["half_day_eve_assessment"]["arife_dates_verified"])
        self.assertTrue(m26["half_day_eve_assessment"]["requires_legal_review"])
        self.assertEqual(m26["half_day_eve_assessment"]["half_day_eve_legal_rule"], "UNVERIFIED_REQUIRE_LEGAL_REVIEW")
        cats = {r.category for r in res.risks}
        self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", cats)
        self.assertIn("M26_YARIM_GUN_TATIL_HUKUKI_INCELEME_GEREKLI", cats)
        self.assertEqual(res.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertFalse(res.human_approval.payroll_handoff_allowed)

        # Misaligned arife date (2 days before start instead of 1 day before) MUST also fail!
        bad_arife = self._complete_2028_record()
        bad_arife["ramazan_arife_date"] = "2028-02-25"
        chk_bad = validate_external_yearly_holiday_calendar(2028, bad_arife)
        self.assertFalse(chk_bad["valid"])
        self.assertFalse(chk_bad["arife_dates_valid"])

    def test_complete_yearly_external_calendar_unlocks_calendar_gate_and_triggers_arife_legal_review_gate(self) -> None:
        # 2028 fully cryptographically attested (Ramazan 2028-02-27..29 + Arife 2028-02-26; Kurban 2028-05-05..08 + Arife 2028-05-04 + snapshot + signed legal attestation + ledger).
        # Window: Discovery=2028-02-24 (Thu), Action=2028-03-06 (Mon) — crosses Ramazan Arifesi 2028-02-26 (Sat)!
        #   - If 2028-02-26 counted -> deadline=2028-03-04 (7 days -> EXCEEDED)
        #   - If 2028-02-26 excluded -> deadline=2028-03-06 (6 days -> WITHIN_LIMIT)
        ext_cal, appr_reg, att_led, _ = _build_signed_external_calendar_bundle({"2028": self._complete_2028_record()})
        base_facts = {
            "termination_reason_type": "JUST_CAUSE_M25_II",
            "workplace_total_employees": 120,
            "tenure_months": 24,
            "contract_term_type": "INDEFINITE",
            "written_notice_with_clear_reason": True,
            "notification_channel": "WRITTEN_HAND_OR_NOTARY",
            "act_date": "2028-02-23",
            "discovery_date": "2028-02-24",
            "planned_termination_date": "2028-03-06",
            "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
            "religious_calendar_externally_verified": True,
            "external_verified_holiday_calendars": ext_cal,
        }

        # 1) Default (UNVERIFIED_REQUIRE_LEGAL_REVIEW): Calendar lock OPENS (no HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE!),
        #    AND arife legal review gate FIRES for externally supplied 2028-02-26 Ramazan Arifesi!
        res_pending_arife = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            as_of_date="2028-03-06",
            facts=base_facts,
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
            approvers_registry=appr_reg,
            attestation_ledger=att_led,
        )
        m26_p = res_pending_arife.structured_findings["m26_deadline_assessment"]
        self.assertTrue(m26_p["holiday_calendar_coverage_complete"])
        self.assertEqual(m26_p["holiday_calendar_coverage_status"], "EXTERNALLY_VERIFIED_FOR_UNCOVERED_YEAR")
        self.assertEqual(m26_p["calendar_blocker_codes"], [])
        self.assertEqual(m26_p["externally_verified_calendar_years"], [2028])
        self.assertEqual(m26_p["six_working_day_status"], "PENDING_LEGAL_REVIEW_HALF_DAY_HOLIDAY_EVE")
        self.assertIsNone(m26_p["working_days_since_discovery"])
        self.assertIsNone(m26_p["six_working_day_deadline_date"])
        hd = m26_p["half_day_eve_assessment"]
        self.assertTrue(hd["arife_dates_verified"])
        self.assertTrue(hd["requires_legal_review"])
        self.assertTrue(hd["outcome_differs_by_half_day_rule"])
        self.assertEqual(hd["deadline_if_counted_as_working_day"], "2028-03-04")
        self.assertEqual(hd["deadline_if_excluded_as_non_working_day"], "2028-03-06")
        self.assertEqual(hd["days_elapsed_if_counted_as_working_day"], 7)
        self.assertEqual(hd["days_elapsed_if_excluded_as_non_working_day"], 6)
        self.assertEqual(hd["active_half_day_eves"][0]["date"], "2028-02-26")
        cats_p = {r.category for r in res_pending_arife.risks}
        self.assertNotIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", cats_p)
        self.assertIn("M26_YARIM_GUN_TATIL_HUKUKI_INCELEME_GEREKLI", cats_p)
        self.assertEqual(res_pending_arife.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertFalse(res_pending_arife.human_approval.payroll_handoff_allowed)

        # 2) Counsel confirms EXCLUDE_AS_NON_WORKING_DAY -> 2028-03-06 is Day 6 (WITHIN_LIMIT -> UYGUN_ON_DEGERLENDIRME)
        res_excl = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            as_of_date="2028-03-06",
            facts={**base_facts, "half_day_eve_legal_rule": "EXCLUDE_AS_NON_WORKING_DAY"},
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
            approvers_registry=appr_reg,
            attestation_ledger=att_led,
        )
        m26_e = res_excl.structured_findings["m26_deadline_assessment"]
        self.assertEqual(m26_e["six_working_day_status"], "WITHIN_LIMIT")
        self.assertEqual(m26_e["working_days_since_discovery"], 6)
        self.assertEqual(m26_e["six_working_day_deadline_date"], "2028-03-06")
        self.assertEqual(res_excl.decision_badge, "UYGUN_ON_DEGERLENDIRME")

        # 3) Counsel confirms COUNT_AS_WORKING_DAY -> 2028-03-06 is Day 7 (EXCEEDED -> HAK_DUSURUCU_SURE_ASIMI_M26)
        res_cnt = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            as_of_date="2028-03-06",
            facts={**base_facts, "half_day_eve_legal_rule": "COUNT_AS_WORKING_DAY"},
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
            approvers_registry=appr_reg,
            attestation_ledger=att_led,
        )
        m26_c = res_cnt.structured_findings["m26_deadline_assessment"]
        self.assertEqual(m26_c["six_working_day_status"], "EXCEEDED")
        self.assertEqual(m26_c["working_days_since_discovery"], 7)
        self.assertIn("HAK_DUSURUCU_SURE_ASIMI_M26", {r.category for r in res_cnt.risks})

        # 4) Non-arife week in verified 2028 (2028-03-13..2028-03-18) -> both gates clean automatically!
        res_clean_2028 = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            as_of_date="2028-03-18",
            facts={
                **base_facts,
                "act_date": "2028-03-12",
                "discovery_date": "2028-03-13",
                "planned_termination_date": "2028-03-18",
            },
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
            approvers_registry=appr_reg,
            attestation_ledger=att_led,
        )
        self.assertEqual(res_clean_2028.decision_badge, "UYGUN_ON_DEGERLENDIRME")
        self.assertEqual(res_clean_2028.structured_findings["m26_deadline_assessment"]["six_working_day_status"], "WITHIN_LIMIT")

    def test_get_turkish_half_day_eves_and_ubgt_holidays_ingest_verified_yearly_external_calendars(self) -> None:
        ext, appr_reg, att_led, _ = _build_signed_external_calendar_bundle({"2028": self._complete_2028_record()})

        # Without external calendar, 2028 has ONLY 28 Ekim in non-strict mode and raises in strict mode
        eves_plain = get_turkish_half_day_eves(2028)
        self.assertEqual(set(eves_plain.keys()), {date(2028, 10, 28)})
        with self.assertRaisesRegex(ValueError, "HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE"):
            get_turkish_half_day_eves(2028, require_verified_religious_calendar=True)

        # WITH complete cryptographically attested 2028 external calendar, get_turkish_half_day_eves() returns ALL 3 eves (28 Ekim + Ramazan + Kurban)!
        eves_ext = get_turkish_half_day_eves(
            2028,
            require_verified_religious_calendar=True,
            external_verified_calendars=ext,
            approvers_registry=appr_reg,
            attestation_ledger=att_led,
        )
        self.assertEqual(set(eves_ext.keys()), {date(2028, 2, 26), date(2028, 5, 4), date(2028, 10, 28)})

        # get_turkish_ubgt_holidays() with complete verified 2028 external calendar includes all 7 fixed + 7 religious = 14 days!
        hols_ext = get_turkish_ubgt_holidays(
            2028,
            require_verified_religious_calendar=True,
            external_verified_calendars=ext,
            approvers_registry=appr_reg,
            attestation_ledger=att_led,
        )
        self.assertEqual(len(hols_ext), 14)
        self.assertIn(date(2028, 2, 27), hols_ext)
        self.assertIn(date(2028, 2, 29), hols_ext)
        self.assertIn(date(2028, 5, 5), hols_ext)
        self.assertIn(date(2028, 5, 8), hols_ext)

        # Coverage info and calendar report also reflect EXTERNALLY_VERIFIED_CALENDAR provenance
        cov_ext = get_holiday_calendar_coverage_info(
            2028,
            external_verified_calendars=ext,
            approvers_registry=appr_reg,
            attestation_ledger=att_led,
        )
        self.assertTrue(cov_ext["calendar_complete_for_m26"])
        self.assertEqual(cov_ext["coverage_source"], "EXTERNALLY_VERIFIED_CALENDAR")
        self.assertIsNone(cov_ext["blocker_code"])
        self.assertEqual(cov_ext["verified_by"], "CALISORA-HUKUK-01")
        rep_ext = get_turkish_ubgt_calendar_report(
            2028,
            external_verified_calendars=ext,
            approvers_registry=appr_reg,
            attestation_ledger=att_led,
        )
        self.assertEqual(len(rep_ext["religious_full_holidays"]), 7)
        self.assertEqual(len(rep_ext["half_day_eves"]), 3)

        # Incomplete external calendar (missing arife) MUST NOT populate eves or satisfy strict mode!
        bad_ext = {"2028": {k: v for k, v in self._complete_2028_record().items() if "arife" not in k}}
        with self.assertRaisesRegex(ValueError, "HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE"):
            get_turkish_half_day_eves(2028, require_verified_religious_calendar=True, external_verified_calendars=bad_ext)
        with self.assertRaisesRegex(ValueError, "HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE"):
            get_turkish_ubgt_holidays(2028, require_verified_religious_calendar=True, external_verified_calendars=bad_ext)

    # --- 3. Mandatory Central Audit Log holiday_calendar_audit Checks ---

    def test_central_audit_log_deleted_holiday_calendar_audit_triggers_blocker(self) -> None:
        audit_data = json.loads(AUDIT_LOG_PATH.read_text(encoding="utf-8"))
        del audit_data["holiday_calendar_audit"]
        rep = validate_central_audit_log(audit_data, self.sources, self.precedents, self.cards)
        self.assertFalse(rep.valid)
        blocker_codes = {f.code for f in rep.flags if f.severity == "BLOCKER"}
        self.assertIn("MISSING_HOLIDAY_CALENDAR_AUDIT", blocker_codes)

    def test_central_audit_log_year_range_and_url_contradictions_trigger_blockers(self) -> None:
        audit_data = json.loads(AUDIT_LOG_PATH.read_text(encoding="utf-8"))

        # 1) covered_years vs coverage_end_year contradiction
        m1 = copy.deepcopy(audit_data)
        m1["holiday_calendar_audit"]["coverage_end_year"] = 2028
        r1 = validate_central_audit_log(m1, self.sources, self.precedents, self.cards)
        self.assertFalse(r1.valid)
        self.assertIn("HOLIDAY_CALENDAR_YEAR_RANGE_MISMATCH", {f.code for f in r1.flags})

        # 2) Gap in covered_years ([2024, 2025, 2027])
        m2 = copy.deepcopy(audit_data)
        m2["holiday_calendar_audit"]["covered_years"] = [2024, 2025, 2027]
        r2 = validate_central_audit_log(m2, self.sources, self.precedents, self.cards)
        self.assertFalse(r2.valid)
        codes2 = {f.code for f in r2.flags}
        self.assertIn("HOLIDAY_CALENDAR_YEAR_RANGE_MISMATCH", codes2)
        self.assertIn("HOLIDAY_CALENDAR_URL_CONSISTENCY_MISMATCH", codes2)

        # 3) Extra orphan year URL in official_source_urls not listed in covered_years ("2028")
        m3 = copy.deepcopy(audit_data)
        m3["holiday_calendar_audit"]["official_source_urls"]["2028"] = "https://vakithesaplama.diyanet.gov.tr/icerik.php?icerik=155"
        r3 = validate_central_audit_log(m3, self.sources, self.precedents, self.cards)
        self.assertFalse(r3.valid)
        self.assertIn("HOLIDAY_CALENDAR_URL_CONSISTENCY_MISMATCH", {f.code for f in r3.flags})

        # 4) Yearly record URL disagrees with official_source_urls
        m4 = copy.deepcopy(audit_data)
        m4["holiday_calendar_audit"]["yearly_records"]["2026"]["official_source_url"] = (
            "https://vakithesaplama.diyanet.gov.tr/icerik.php?icerik=999"
        )
        r4 = validate_central_audit_log(m4, self.sources, self.precedents, self.cards)
        self.assertFalse(r4.valid)
        self.assertIn("HOLIDAY_CALENDAR_URL_CONSISTENCY_MISMATCH", {f.code for f in r4.flags})

    def test_central_audit_log_missing_full_or_half_day_coverage_or_unverified_provenance_cannot_be_verified(self) -> None:
        audit_data = json.loads(AUDIT_LOG_PATH.read_text(encoding="utf-8"))

        # 1) Half-day coverage flag set to False in 2026 yearly record -> BLOCKER
        m_half = copy.deepcopy(audit_data)
        m_half["holiday_calendar_audit"]["yearly_records"]["2026"]["half_day_coverage_verified"] = False
        r_half = validate_central_audit_log(m_half, self.sources, self.precedents, self.cards)
        self.assertFalse(r_half.valid)
        self.assertIn("HOLIDAY_CALENDAR_YEARLY_COVERAGE_INCOMPLETE", {f.code for f in r_half.flags})

        # 2) Arife date removed from 2025 yearly record -> BLOCKER
        m_arife = copy.deepcopy(audit_data)
        del m_arife["holiday_calendar_audit"]["yearly_records"]["2025"]["ramazan_arife_date"]
        r_arife = validate_central_audit_log(m_arife, self.sources, self.precedents, self.cards)
        self.assertFalse(r_arife.valid)
        self.assertIn("HOLIDAY_CALENDAR_YEARLY_COVERAGE_INCOMPLETE", {f.code for f in r_arife.flags})

        # 3) Missing verified_by / disallowed verifier "LLM" while verification_status == "VERIFIED" -> BLOCKER
        m_ver = copy.deepcopy(audit_data)
        m_ver["holiday_calendar_audit"]["verified_by"] = "LLM"
        r_ver = validate_central_audit_log(m_ver, self.sources, self.precedents, self.cards)
        self.assertFalse(r_ver.valid)
        codes_ver = {f.code for f in r_ver.flags}
        self.assertIn("INVALID_HOLIDAY_CALENDAR_VERIFIER", codes_ver)
        self.assertIn("HOLIDAY_CALENDAR_VERIFIED_WITHOUT_PROVENANCE", codes_ver)

        # 4) Bare homepage URL in yearly_records.2024 while VERIFIED -> BLOCKER
        m_bare = copy.deepcopy(audit_data)
        m_bare["holiday_calendar_audit"]["yearly_records"]["2024"]["official_source_url"] = "https://vakithesaplama.diyanet.gov.tr/"
        r_bare = validate_central_audit_log(m_bare, self.sources, self.precedents, self.cards)
        self.assertFalse(r_bare.valid)
        self.assertIn("HOLIDAY_CALENDAR_VERIFIED_WITHOUT_PROVENANCE", {f.code for f in r_bare.flags})

        # 5) Date drift between audit log yearly_records and runtime engine table -> BLOCKER
        m_drift = copy.deepcopy(audit_data)
        m_drift["holiday_calendar_audit"]["yearly_records"]["2027"]["ramazan_arife_date"] = "2027-03-07"
        m_drift["holiday_calendar_audit"]["yearly_records"]["2027"]["ramazan_start_date"] = "2027-03-08"
        m_drift["holiday_calendar_audit"]["yearly_records"]["2027"]["ramazan_end_date"] = "2027-03-10"
        r_drift = validate_central_audit_log(m_drift, self.sources, self.precedents, self.cards)
        self.assertFalse(r_drift.valid)
        self.assertIn("HOLIDAY_CALENDAR_ENGINE_SYNC_MISMATCH", {f.code for f in r_drift.flags})

    # --- 4. Backward Compatibility (2024-2027, Weekly Rest Overlap, Saturday, Law 7555 m.109) ---

    def test_backward_compat_2024_2027_builtin_calendar_weekly_rest_overlap_saturday_and_law_7555_m109(self) -> None:
        # 1) 2024-2027 built-in coverage + weekly rest day overlapping 28 Ekim 2026 (Wednesday) -> NO false-positive arife escalation!
        m26_wed_rest = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2026-10-26",
            act_date_s="2026-10-25",
            action_date_s="2026-11-02",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
            weekly_rest_day="WEDNESDAY",
        )
        self.assertTrue(m26_wed_rest["holiday_calendar_coverage_complete"])
        self.assertEqual(m26_wed_rest["six_working_day_status"], "WITHIN_LIMIT")
        self.assertEqual(m26_wed_rest["half_day_eve_assessment"]["active_half_day_eves"], [])
        self.assertFalse(m26_wed_rest["requires_counsel_escalation"])

        # 2) 2024-06-15 (Sat Kurban Arifesi) overlapping weekly_rest_day="SATURDAY" still clean
        m26_sat_overlap = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2024-06-14",
            act_date_s="2024-06-13",
            action_date_s="2024-06-24",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
            weekly_rest_day="SATURDAY",
        )
        self.assertEqual(m26_sat_overlap["six_working_day_status"], "WITHIN_LIMIT")
        self.assertFalse(m26_sat_overlap["requires_counsel_escalation"])

        # 3) 2026-05-08 5-day workplace Saturday still counted + post-7555 KEP-only termination rejected via router
        out = self.router.dispatch(
            "evaluate_hr_legal_scenario",
            {
                "scenario_type": "TERMINATION_VALIDITY",
                "as_of_date": "2026-05-08",
                "facts": {
                    "termination_reason_type": "JUST_CAUSE_M25_II",
                    "workplace_total_employees": 120,
                    "tenure_months": 36,
                    "contract_term_type": "INDEFINITE",
                    "written_notice_with_clear_reason": True,
                    "notification_channel": "KEP_ONLY",
                    "act_date": "2026-04-28",
                    "discovery_date": "2026-04-29",
                    "planned_termination_date": "2026-05-08",
                    "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                    "saturday_is_working_day": False,
                },
            },
        )
        self.assertEqual(out["structured_findings"]["m26_deadline_assessment"]["working_days_since_discovery"], 7)
        cats = {r["category"] for r in out["risks"]}
        self.assertIn("HAK_DUSURUCU_SURE_ASIMI_M26", cats)
        self.assertIn("M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI", cats)
        self.assertNotIn("SEKIL_SARTI_IHLALI_M19", cats)

    # --- 5. Governance, Version 1.0.2c+ & 74/74 Record Preservation ---

    def test_v102c4_governance_taxonomy_schemas_tool_schemas_prompt_and_74_audit_records_consistency(self) -> None:
        self.assertTrue(TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["calendar_version"].startswith(("1.0.2c", "1.0.3", "1.0.4", "1.0.5")))
        self.assertEqual(
            TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["verification_status"],
            "TECHNICAL_VERIFIED_PENDING_LEGAL_ATTESTATION",
        )
        self.assertIn("vakithesaplama.diyanet.gov.tr", OFFICIAL_HOLIDAY_CALENDAR_DOMAINS)

        tax = json.loads(TAXONOMY_PATH.read_text(encoding="utf-8"))
        self.assertTrue(tax["schema_version"].startswith(("1.0.2c", "1.0.3", "1.0.4", "1.0.5")))
        self.assertTrue(tax["legal_reasoning_engine"]["version"].startswith(("1.0.2c", "1.0.3", "1.0.4", "1.0.5")))
        sr = tax["verification_infrastructure"]["strict_rules"]
        self.assertTrue(sr["require_full_yearly_calendar_and_arife_provenance_for_uncovered_years_in_m26"])
        self.assertTrue(sr["require_mandatory_holiday_calendar_audit_in_central_log"])

        audit_data = json.loads(AUDIT_LOG_PATH.read_text(encoding="utf-8"))
        self.assertTrue(audit_data["schema_version"].startswith(("1.0.2c", "1.0.3", "1.0.4", "1.0.5")))
        self.assertEqual(audit_data["external_legal_counsel_signoff_status"], "PENDING_SIGNED_EXTERNAL_ATTESTATION")
        self.assertEqual(audit_data["summary"]["total_audited_records"], 74)
        self.assertEqual(audit_data["summary"]["fully_verified_records_count"], 70)
        self.assertEqual(audit_data["summary"]["pending_verification_records_count"], 3)
        self.assertEqual(audit_data["summary"]["superseded_records_count"], 1)
        self.assertEqual(len(audit_data["entries"]), 74)
        self.assertEqual(len(self.sources), 30)
        self.assertEqual(len(self.precedents), 5)
        self.assertEqual(len(self.cards), 39)
        self.assertEqual(set(audit_data["holiday_calendar_audit"]["yearly_records"].keys()), {"2024", "2025", "2026", "2027"})
        clean_rep = validate_central_audit_log(audit_data, self.sources, self.precedents, self.cards)
        self.assertTrue(clean_rep.valid, clean_rep.flags)

        tools_doc = json.loads(TOOLS_SCHEMA_PATH.read_text(encoding="utf-8"))
        eval_tool = next(t for t in tools_doc["tools"] if t["name"] == "evaluate_hr_legal_scenario")
        self.assertIn("external_verified_holiday_calendars", eval_tool["parameters"]["properties"]["facts"]["description"])

        prompt_text = (PROJECT_ROOT / "agent" / "system_prompt.md").read_text(encoding="utf-8")
        self.assertIn("v1.0.2c", prompt_text)
        self.assertIn("external_verified_holiday_calendars", prompt_text)

        for sp in (SOURCE_SCHEMA_PATH, PRECEDENT_SCHEMA_PATH, CARD_SCHEMA_PATH, SCENARIO_SCHEMA_PATH):
            s_doc = json.loads(sp.read_text(encoding="utf-8"))
            self.assertTrue("1.0.2c" in s_doc["title"] or "1.0.3" in s_doc["title"] or "1.0.4" in s_doc["title"] or "1.0.5" in s_doc["title"], sp.name)


class TestV102c5SourceContentSignatureIdentityAndAuditChain(unittest.TestCase):
    """v1.0.2c.5 security & legal-evidence verification tests covering all 6 mandatory guarantees:
      1. Externally verifiable hash-chained audit ledger + separately signed checkpoints + WORM anchors
      2. Authorized approver temporal, scope, and nuanced compromise vs. non-compromise revocation governance
      3. Immutable versioned official source snapshots (real archived 2024-2027 Diyanet HTMLs) & offline-origin resilience
      4. Strict 9-slot Turkish religious holiday source parser & OCR confidence gate
      5. Ed25519 & RSA-PSS-SHA256 asymmetric signatures over RFC 8785 canonical JSON, replay/nonce protection,
         PRODUCTION vs. TEST_SANDBOX_ONLY separation, zero private keys in repo, Law No. 5070 non-equivalence
      6. Two-stage verification separation (technical source verification vs. authorized legal counsel attestation)
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.sources = load_source_registry(SOURCES_PATH, strict=True)
        cls.precedents = load_precedent_registry(PRECEDENTS_PATH, source_registry=cls.sources, strict=True)
        cls.cards = load_knowledge_cards(
            KB_ALL_DIR,
            source_registry=cls.sources,
            precedent_registry=cls.precedents,
            strict=True,
            audit_log_path=AUDIT_LOG_PATH,
        )
        cls.router = HukukSGKToolRouter()

    @staticmethod
    def _base_2028() -> dict[str, object]:
        return {
            "year": 2028,
            "verification_status": "VERIFIED",
            "ramazan_arife_date": "2028-02-26",
            "ramazan_start_date": "2028-02-27",
            "ramazan_end_date": "2028-02-29",
            "kurban_arife_date": "2028-05-04",
            "kurban_start_date": "2028-05-05",
            "kurban_end_date": "2028-05-08",
            "official_source_url": "https://vakithesaplama.diyanet.gov.tr/icerik.php?icerik=155",
            "verified_at": "2027-12-15",
            "verified_by": "CALISORA-HUKUK-01",
            "calendar_version": "2028.1",
        }

    @staticmethod
    def _base_2029() -> dict[str, object]:
        return {
            "year": 2029,
            "verification_status": "VERIFIED",
            "ramazan_arife_date": "2029-02-14",
            "ramazan_start_date": "2029-02-15",
            "ramazan_end_date": "2029-02-17",
            "kurban_arife_date": "2029-04-23",
            "kurban_start_date": "2029-04-24",
            "kurban_end_date": "2029-04-27",
            "official_source_url": "https://vakithesaplama.diyanet.gov.tr/icerik.php?icerik=156",
            "verified_at": "2028-12-15",
            "verified_by": "CALISORA-HUKUK-01",
            "calendar_version": "2029.1",
        }

    # --- 1. Closing the v1.0.2c.4 Red-Team Bypass (Synthetic 2028 + Arbitrary Verifier + Trust Root Isolation) ---

    def test_red_team_synthetic_2028_record_and_arbitrary_verifier_are_blocked(self) -> None:
        # Exact reproduction of the v1.0.2c.4 red-team bypass: structurally consistent dates, valid Diyanet URL,
        # arbitrary string verified_by='HUKUK-MUSAVIRI-TEST', NO archived source snapshot, NO digital signature!
        synthetic_2028 = self._base_2028()
        synthetic_2028["verified_by"] = "HUKUK-MUSAVIRI-TEST"

        res = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            as_of_date="2028-03-04",
            facts={
                "termination_reason_type": "JUST_CAUSE_M25_II",
                "workplace_total_employees": 100,
                "tenure_months": 24,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": True,
                "notification_channel": "WRITTEN_HAND_OR_NOTARY",
                "act_date": "2028-02-23",
                "discovery_date": "2028-02-24",
                "planned_termination_date": "2028-03-04",
                "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                "religious_calendar_externally_verified": True,
                "external_verified_holiday_calendars": {"2028": synthetic_2028},
                "half_day_eve_legal_rule": "COUNT_AS_WORKING_DAY",
            },
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
        )
        m26 = res.structured_findings["m26_deadline_assessment"]
        self.assertEqual(m26["six_working_day_status"], "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
        self.assertFalse(m26["holiday_calendar_coverage_complete"])
        self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", m26["calendar_blocker_codes"])
        self.assertIn("UNAUTHORIZED_APPROVER", m26["calendar_blocker_codes"])
        self.assertIn("SOURCE_SNAPSHOT_MISSING_OR_MISMATCH", m26["calendar_blocker_codes"])
        self.assertIn("TWO_STAGE_VERIFICATION_INCOMPLETE", m26["calendar_blocker_codes"])
        self.assertEqual(res.decision_badge, "YUKSEK_RISK_AVUKAT_ESKALASYONU")
        self.assertFalse(res.human_approval.payroll_handoff_allowed)

        # Trust-root isolation: attacker attempting to smuggle rogue approvers_registry/ledger/TEST_SANDBOX_ONLY
        # inside untrusted `facts` JSON MUST BE IGNORED by evaluate_hr_legal_scenario and HukukSGKToolRouter!
        rogue_ext, rogue_appr, rogue_led, _ = _build_signed_external_calendar_bundle(
            {"2028": self._base_2028()},
            approver_id="HUKUK-MUSAVIRI-TEST",
            key_trust_tier="TEST_SANDBOX_ONLY",
            environment_restrictions=["TEST_SANDBOX_ONLY"],
        )
        out_rogue = self.router.dispatch(
            "evaluate_hr_legal_scenario",
            {
                "scenario_type": "TERMINATION_VALIDITY",
                "as_of_date": "2028-03-04",
                "facts": {
                    "termination_reason_type": "JUST_CAUSE_M25_II",
                    "workplace_total_employees": 100,
                    "tenure_months": 24,
                    "contract_term_type": "INDEFINITE",
                    "written_notice_with_clear_reason": True,
                    "notification_channel": "WRITTEN_HAND_OR_NOTARY",
                    "act_date": "2028-02-23",
                    "discovery_date": "2028-02-24",
                    "planned_termination_date": "2028-03-04",
                    "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                    "religious_calendar_externally_verified": True,
                    "external_verified_holiday_calendars": rogue_ext,
                    "half_day_eve_legal_rule": "COUNT_AS_WORKING_DAY",
                    # Attempted trust-root smuggling inside facts:
                    "approvers_registry": rogue_appr,
                    "attestation_ledger": rogue_led,
                    "runtime_environment": "TEST_SANDBOX_ONLY",
                },
            },
        )
        m26_rogue = out_rogue["structured_findings"]["m26_deadline_assessment"]
        self.assertEqual(m26_rogue["six_working_day_status"], "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
        self.assertIn("UNAUTHORIZED_APPROVER", m26_rogue["calendar_blocker_codes"])

    # --- 2. Ed25519 & RSA-PSS-SHA256 Canonical Signing, 1-Byte Tamper & Replay/Nonce Protection ---

    def test_ed25519_and_rsa_pss_sha256_canonical_signing_tamper_and_replay_protection(self) -> None:
        # RFC 8785 deterministic canonical JSON invariance across key insertion orders
        p1 = {"b": 2, "a": {"z": True, "a": "ŞĞÜÖÇı"}, "arr": [1, 2, 3]}
        p2 = {"arr": [1, 2, 3], "a": {"a": "ŞĞÜÖÇı", "z": True}, "b": 2}
        self.assertEqual(canonical_json_bytes(p1), canonical_json_bytes(p2))

        for alg in ("ED25519", "RSA-PSS-SHA256"):
            with self.subTest(algorithm=alg):
                ext, appr, led, _ = _build_signed_external_calendar_bundle(
                    {"2028": self._base_2028()},
                    counsel_algorithm=alg,
                )
                chk = validate_external_yearly_holiday_calendar(
                    2028,
                    ext["2028"],
                    approvers_registry=appr,
                    attestation_ledger=led,
                    runtime_environment="PRODUCTION",
                )
                self.assertTrue(chk["valid"], chk["errors"])
                self.assertTrue(chk["technical_source_valid"])
                self.assertTrue(chk["legal_attestation_valid"])
                self.assertTrue(chk["production_use_authorized"])
                self.assertFalse(chk["qualified_e_signature_5070_equivalent"])

                # 1-byte tamper on official_source_url breaks asymmetric signature verification!
                tampered_url = copy.deepcopy(ext["2028"])
                tampered_url["official_source_url"] = "https://vakithesaplama.diyanet.gov.tr/icerik.php?icerik=999"
                chk_url = validate_external_yearly_holiday_calendar(
                    2028,
                    tampered_url,
                    approvers_registry=appr,
                    attestation_ledger=led,
                )
                self.assertFalse(chk_url["valid"])
                self.assertIn("INVALID_ATTESTATION_SIGNATURE", chk_url["error_codes"])

                # 1-byte tamper on Ramazan date breaks BOTH snapshot content match AND digital signature!
                tampered_dt = copy.deepcopy(ext["2028"])
                tampered_dt["ramazan_end_date"] = "2028-02-28"
                chk_dt = validate_external_yearly_holiday_calendar(
                    2028,
                    tampered_dt,
                    approvers_registry=appr,
                    attestation_ledger=led,
                )
                self.assertFalse(chk_dt["valid"])
                self.assertIn("INVALID_ATTESTATION_SIGNATURE", chk_dt["error_codes"])

                # 1-byte tamper on approved_at_utc breaks signature!
                tampered_ts = copy.deepcopy(ext["2028"])
                tampered_ts["legal_attestation"]["approved_at_utc"] = "2027-12-15T10:00:01Z"
                chk_ts = validate_external_yearly_holiday_calendar(
                    2028,
                    tampered_ts,
                    approvers_registry=appr,
                    attestation_ledger=led,
                )
                self.assertFalse(chk_ts["valid"])
                self.assertIn("INVALID_ATTESTATION_SIGNATURE", chk_ts["error_codes"])

                # Replay of 2028 signature onto a different record_id or year -> REJECTED!
                replayed = copy.deepcopy(ext["2028"])
                replayed["record_id"] = "CAL-REC-2028-REPLAY"
                chk_rep = validate_external_yearly_holiday_calendar(
                    2028,
                    replayed,
                    approvers_registry=appr,
                    attestation_ledger=led,
                )
                self.assertFalse(chk_rep["valid"])
                self.assertIn("SIGNATURE_REPLAY_OR_RECORD_MISMATCH", chk_rep["error_codes"])

        # Cross-year nonce replay check (2028 & 2029 reusing same nonce in a single evaluation)
        ext2, appr2, led2, keys2 = _build_signed_external_calendar_bundle(
            {"2028": self._base_2028(), "2029": self._base_2029()}
        )
        shared_nonce = ext2["2028"]["legal_attestation"]["nonce"]
        # Re-sign 2029 with 2028's nonce so signature itself is cryptographically valid, testing nonce replay guard!
        rec29 = copy.deepcopy(ext2["2029"])
        rec29["legal_attestation"]["nonce"] = shared_nonce
        pl29 = build_calendar_attestation_signing_payload(
            record_id=rec29["record_id"],
            nonce=shared_nonce,
            year=2029,
            calendar_record=rec29,
            source_document_sha256=rec29["source_document_sha256"],
            approver_id=rec29["legal_attestation"]["approver_id"],
            approved_at_utc=rec29["legal_attestation"]["approved_at_utc"],
            key_id=rec29["legal_attestation"]["key_id"],
            key_version=rec29["legal_attestation"]["key_version"],
            algorithm=rec29["legal_attestation"]["algorithm"],
        )
        rec29["legal_attestation"]["signature_b64"] = sign_canonical_payload(
            pl29, keys2["counsel_priv"], algorithm="ED25519"
        )
        m26_dup = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2028-12-28",
            act_date_s="2028-12-27",
            action_date_s="2029-01-05",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
            religious_calendar_externally_verified=True,
            external_verified_holiday_calendars={"2028": ext2["2028"], "2029": rec29},
            approvers_registry=appr2,
            attestation_ledger=led2,
        )
        self.assertEqual(m26_dup["six_working_day_status"], "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
        self.assertIn("DUPLICATE_ATTESTATION_NONCE", m26_dup["calendar_blocker_codes"])

    # --- 3. PRODUCTION vs. TEST_SANDBOX_ONLY Separation & Law No. 5070 Non-Equivalence ---

    def test_production_blocks_test_sandbox_keys_and_enforces_law_5070_non_equivalence(self) -> None:
        ext_sbx, appr_sbx, led_sbx, _ = _build_signed_external_calendar_bundle(
            {"2028": self._base_2028()},
            approver_id="CALISORA-SANDBOX-01",
            key_trust_tier="TEST_SANDBOX_ONLY",
            environment_restrictions=["TEST_SANDBOX_ONLY"],
        )

        # In PRODUCTION (default): TEST_SANDBOX_ONLY key MUST BE HARD-BLOCKED!
        m26_prod = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2028-02-24",
            act_date_s="2028-02-23",
            action_date_s="2028-03-04",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
            religious_calendar_externally_verified=True,
            external_verified_holiday_calendars=ext_sbx,
            half_day_eve_legal_rule="COUNT_AS_WORKING_DAY",
            approvers_registry=appr_sbx,
            attestation_ledger=led_sbx,
            runtime_environment="PRODUCTION",
        )
        self.assertEqual(m26_prod["six_working_day_status"], "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
        self.assertIn("PRODUCTION_SIGNING_KEY_REQUIRED", m26_prod["calendar_blocker_codes"])
        self.assertFalse(m26_prod["calendar_production_use_authorized"])
        self.assertFalse(m26_prod["qualified_e_signature_5070_equivalent"])
        self.assertIn("5070", m26_prod["signature_legal_notice"])

        # In explicit TEST_SANDBOX_ONLY mode: signature verifies, BUT calendar_production_use_authorized MUST stay False!
        m26_sbx = evaluate_m26_forfeiture_deadlines(
            discovery_date_s="2028-02-24",
            act_date_s="2028-02-23",
            action_date_s="2028-03-04",
            discovering_authority_status="AUTHORIZED_DISMISSAL_BODY",
            religious_calendar_externally_verified=True,
            external_verified_holiday_calendars=ext_sbx,
            half_day_eve_legal_rule="COUNT_AS_WORKING_DAY",
            approvers_registry=appr_sbx,
            attestation_ledger=led_sbx,
            runtime_environment="TEST_SANDBOX_ONLY",
        )
        self.assertEqual(m26_sbx["six_working_day_status"], "WITHIN_LIMIT")
        self.assertFalse(m26_sbx["calendar_production_use_authorized"])
        self.assertFalse(m26_sbx["qualified_e_signature_5070_equivalent"])

        # False 5070 equivalence claim in central audit log -> BLOCKER!
        bad_5070 = json.loads(AUDIT_LOG_PATH.read_text(encoding="utf-8"))
        bad_5070["holiday_calendar_audit"]["qualified_e_signature_5070_equivalent"] = True
        rep_5070 = validate_central_audit_log(bad_5070, self.sources, self.precedents, self.cards)
        self.assertFalse(rep_5070.valid)
        self.assertIn("INVALID_5070_EQUIVALENCE_CLAIM", {f.code for f in rep_5070.flags})

    # --- 4. Approver Temporal Window, Scope & Key Metadata Governance ---

    def test_approver_temporal_window_scope_and_key_binding_governance(self) -> None:
        # 1) Signed BEFORE valid_from_utc -> APPROVER_NOT_VALID_AT_SIGNING_TIME
        ext_early, appr_early, led_early, _ = _build_signed_external_calendar_bundle(
            {"2028": self._base_2028()},
            valid_from_utc="2028-01-01T00:00:00Z",
            valid_until_utc="2029-12-31T23:59:59Z",
            approved_at_utc="2027-12-15T10:00:00Z",
        )
        chk_early = verify_signed_calendar_attestation(
            2028, ext_early["2028"], approvers_registry=appr_early, attestation_ledger=led_early
        )
        self.assertFalse(chk_early["valid"])
        self.assertIn("APPROVER_NOT_VALID_AT_SIGNING_TIME", chk_early["error_codes"])

        # 2) Signed AFTER valid_until_utc -> APPROVER_NOT_VALID_AT_SIGNING_TIME
        ext_late, appr_late, led_late, _ = _build_signed_external_calendar_bundle(
            {"2028": self._base_2028()},
            valid_from_utc="2026-01-01T00:00:00Z",
            valid_until_utc="2027-06-30T23:59:59Z",
            approved_at_utc="2027-12-15T10:00:00Z",
        )
        chk_late = verify_signed_calendar_attestation(
            2028, ext_late["2028"], approvers_registry=appr_late, attestation_ledger=led_late
        )
        self.assertFalse(chk_late["valid"])
        self.assertIn("APPROVER_NOT_VALID_AT_SIGNING_TIME", chk_late["error_codes"])

        # 3) Out-of-scope year (authorized only 2024-2027, signing 2028) -> APPROVER_OUT_OF_SCOPE
        ext_scope, appr_scope, led_scope, _ = _build_signed_external_calendar_bundle(
            {"2028": self._base_2028()},
            authorized_scopes=["HOLIDAY_CALENDAR_LEGAL_APPROVAL:2024-2027"],
        )
        chk_scope = verify_signed_calendar_attestation(
            2028, ext_scope["2028"], approvers_registry=appr_scope, attestation_ledger=led_scope
        )
        self.assertFalse(chk_scope["valid"])
        self.assertIn("APPROVER_OUT_OF_SCOPE", chk_scope["error_codes"])

        # 4) Wrong operation scope (only AUDIT_CHECKPOINT_SEAL) -> APPROVER_OUT_OF_SCOPE
        ext_op, appr_op, led_op, _ = _build_signed_external_calendar_bundle(
            {"2028": self._base_2028()},
            authorized_scopes=["AUDIT_CHECKPOINT_SEAL"],
        )
        chk_op = verify_signed_calendar_attestation(
            2028, ext_op["2028"], approvers_registry=appr_op, attestation_ledger=led_op
        )
        self.assertFalse(chk_op["valid"])
        self.assertIn("APPROVER_OUT_OF_SCOPE", chk_op["error_codes"])

        # 5) Key version mismatch -> SIGNING_KEY_VERSION_OR_FINGERPRINT_MISMATCH
        ext_kv, appr_kv, led_kv, _ = _build_signed_external_calendar_bundle({"2028": self._base_2028()})
        appr_kv["approvers"]["CALISORA-HUKUK-01"]["key_version"] = "v2"
        chk_kv = verify_signed_calendar_attestation(
            2028, ext_kv["2028"], approvers_registry=appr_kv, attestation_ledger=led_kv
        )
        self.assertFalse(chk_kv["valid"])
        self.assertIn("SIGNING_KEY_VERSION_OR_FINGERPRINT_MISMATCH", chk_kv["error_codes"])

    # --- 5. Nuanced Revocation Semantics (Post-Revocation, Compromise vs. Non-Compromise + Timestamp Trust) ---

    def test_approver_revocation_semantics_post_revocation_compromise_and_trusted_timestamp(self) -> None:
        # Case A: Signature timestamp AFTER revoked_at_utc -> REJECTED (APPROVER_REVOKED_BEFORE_SIGNATURE)
        ext_post, appr_post, led_post, _ = _build_signed_external_calendar_bundle(
            {"2028": self._base_2028()},
            approver_status="REVOKED",
            revoked_at_utc="2027-12-01T00:00:00Z",
            revocation_reason="ROLE_CHANGE",
            approved_at_utc="2027-12-15T10:00:00Z",
            timestamp_trust_level="INDEPENDENT_TSA_VERIFIED",
        )
        chk_post = verify_signed_calendar_attestation(
            2028, ext_post["2028"], approvers_registry=appr_post, attestation_ledger=led_post
        )
        self.assertFalse(chk_post["valid"])
        self.assertIn("APPROVER_REVOKED_BEFORE_SIGNATURE", chk_post["error_codes"])

        # Case B: Pre-revocation signature under KEY_COMPROMISE -> RETROACTIVELY INVALIDATED even with TSA!
        for comp_reason in ("KEY_COMPROMISE", "CA_COMPROMISE"):
            ext_comp, appr_comp, led_comp, _ = _build_signed_external_calendar_bundle(
                {"2028": self._base_2028()},
                approver_status="REVOKED",
                revoked_at_utc="2028-01-10T00:00:00Z",
                revocation_reason=comp_reason,
                approved_at_utc="2027-12-15T10:00:00Z",
                timestamp_trust_level="INDEPENDENT_TSA_VERIFIED",
            )
            chk_comp = verify_signed_calendar_attestation(
                2028, ext_comp["2028"], approvers_registry=appr_comp, attestation_ledger=led_comp
            )
            self.assertFalse(chk_comp["valid"])
            self.assertIn("APPROVER_KEY_COMPROMISED_RETROACTIVE_INVALIDATION", chk_comp["error_codes"])

        # Case C: Pre-revocation signature under ROLE_CHANGE with SELF_ASSERTED_UNTRUSTED -> REJECTED!
        ext_untr, appr_untr, led_untr, _ = _build_signed_external_calendar_bundle(
            {"2028": self._base_2028()},
            approver_status="REVOKED",
            revoked_at_utc="2028-01-10T00:00:00Z",
            revocation_reason="ROLE_CHANGE",
            approved_at_utc="2027-12-15T10:00:00Z",
            timestamp_trust_level="SELF_ASSERTED_UNTRUSTED",
        )
        chk_untr = verify_signed_calendar_attestation(
            2028, ext_untr["2028"], approvers_registry=appr_untr, attestation_ledger=led_untr
        )
        self.assertFalse(chk_untr["valid"])
        self.assertIn("REVOKED_KEY_UNTRUSTED_SIGNING_TIMESTAMP", chk_untr["error_codes"])

        # Case D: Pre-revocation signature under ROLE_CHANGE claiming SIGNED_EXTERNAL_CHECKPOINT_ANCHORED
        #         when the checkpoint was created AFTER revocation -> REJECTED (anti-spoofing)!
        ext_spoof, appr_spoof, led_spoof, _ = _build_signed_external_calendar_bundle(
            {"2028": self._base_2028()},
            approver_status="REVOKED",
            revoked_at_utc="2028-01-10T00:00:00Z",
            revocation_reason="ROLE_CHANGE",
            approved_at_utc="2027-12-15T10:00:00Z",
            checkpoint_created_at_utc="2028-02-01T00:00:00Z",
            timestamp_trust_level="SIGNED_EXTERNAL_CHECKPOINT_ANCHORED",
        )
        chk_spoof = verify_signed_calendar_attestation(
            2028, ext_spoof["2028"], approvers_registry=appr_spoof, attestation_ledger=led_spoof
        )
        self.assertFalse(chk_spoof["valid"])
        self.assertIn("REVOKED_KEY_UNTRUSTED_SIGNING_TIMESTAMP", chk_spoof["error_codes"])

        # Case E: Pre-revocation signature under ROLE_CHANGE WITH genuine pre-revocation signed checkpoint -> VALID with warning!
        ext_ok_cp, appr_ok_cp, led_ok_cp, _ = _build_signed_external_calendar_bundle(
            {"2028": self._base_2028()},
            approver_status="REVOKED",
            revoked_at_utc="2028-01-10T00:00:00Z",
            revocation_reason="ROLE_CHANGE",
            approved_at_utc="2027-12-15T10:00:00Z",
            checkpoint_created_at_utc="2027-12-15T12:00:00Z",
            timestamp_trust_level="SIGNED_EXTERNAL_CHECKPOINT_ANCHORED",
        )
        chk_ok_cp = verify_signed_calendar_attestation(
            2028, ext_ok_cp["2028"], approvers_registry=appr_ok_cp, attestation_ledger=led_ok_cp
        )
        self.assertTrue(chk_ok_cp["valid"], chk_ok_cp["errors"])
        self.assertTrue(any("REVOCATION_PRE_DATE_TRUSTED_TIMESTAMP_VALID" in w for w in chk_ok_cp["warnings"]))

        # Case F: Pre-revocation signature under SUPERSEDED_ROTATION WITH INDEPENDENT_TSA_VERIFIED -> VALID with warning!
        ext_ok_tsa, appr_ok_tsa, led_ok_tsa, _ = _build_signed_external_calendar_bundle(
            {"2028": self._base_2028()},
            approver_status="REVOKED",
            revoked_at_utc="2028-01-10T00:00:00Z",
            revocation_reason="SUPERSEDED_ROTATION",
            approved_at_utc="2027-12-15T10:00:00Z",
            timestamp_trust_level="INDEPENDENT_TSA_VERIFIED",
        )
        chk_ok_tsa = verify_signed_calendar_attestation(
            2028, ext_ok_tsa["2028"], approvers_registry=appr_ok_tsa, attestation_ledger=led_ok_tsa
        )
        self.assertTrue(chk_ok_tsa["valid"], chk_ok_tsa["errors"])
        self.assertTrue(any("REVOCATION_PRE_DATE_TRUSTED_TIMESTAMP_VALID" in w for w in chk_ok_tsa["warnings"]))

    # --- 6. Strict 9-Slot Turkish Religious Holiday Parser (Real Archived 2024-2027 HTMLs + Adversarial Swaps) ---

    def test_strict_turkish_holiday_parser_real_2024_2027_snapshots_and_wrong_bayram_or_day_rejection(self) -> None:
        # Real archived official Diyanet HTML snapshots (2024-2027) MUST parse 9/9 exact slots matching engine tables!
        for yr in (2024, 2025, 2026, 2027):
            snap_path = PROJECT_ROOT / "evidence" / "holiday_snapshots" / f"diyanet_{yr}_v1.html"
            self.assertTrue(snap_path.is_file(), f"Eksik arşiv belgesi: {snap_path}")
            parsed = parse_turkish_religious_holidays_from_source(snap_path.read_bytes(), yr)
            self.assertTrue(parsed["valid"], f"{yr}: {parsed['errors']}")
            slots = parsed["extracted_slots"]
            self.assertEqual(len(slots), 9)
            # Match against engine tables
            engine_full_iso = sorted(date(yr, m, d).isoformat() for (m, d) in TURKISH_RELIGIOUS_FULL_HOLIDAYS[yr])
            engine_eve_iso = sorted(date(yr, m, d).isoformat() for (m, d) in TURKISH_RELIGIOUS_HALF_DAY_EVES[yr])
            parsed_full_iso = sorted(
                slots[k]
                for k in ("ramazan_day_1", "ramazan_day_2", "ramazan_day_3", "kurban_day_1", "kurban_day_2", "kurban_day_3", "kurban_day_4")
            )
            parsed_eve_iso = sorted([slots["ramazan_arife"], slots["kurban_arife"]])
            self.assertEqual(parsed_full_iso, engine_full_iso)
            self.assertEqual(parsed_eve_iso, engine_eve_iso)

        # Negative 1: Wrong bayram swap (Ramazan dates labelled as Kurban Bayramı and vice versa) -> REJECTED!
        good_html = _build_diyanet_html_for_record(self._base_2028())
        swapped_bayram_html = good_html.replace("RAMAZAN BAYRAMI", "TMP_BAYRAM").replace("KURBAN BAYRAMI", "RAMAZAN BAYRAMI").replace("TMP_BAYRAM", "KURBAN BAYRAMI")
        rec_swap = copy.deepcopy(self._base_2028())
        rec_swap["source_document_content"] = swapped_bayram_html
        rec_swap["source_document_sha256"] = compute_sha256(swapped_bayram_html.encode("utf-8"))
        chk_swap = verify_holiday_source_snapshot(2028, rec_swap)
        self.assertFalse(chk_swap["valid"])
        self.assertIn("SOURCE_CONTENT_BAYRAM_OR_ORDER_MISMATCH", chk_swap["error_codes"])

        # Negative 2: Wrong day order (1.Gün and 2.Gün swapped in HTML!) -> REJECTED!
        swapped_day_html = good_html.replace("RAMAZAN BAYRAMI (1.Gün)", "RAMAZAN BAYRAMI (TMP)").replace(
            "RAMAZAN BAYRAMI (2.Gün)", "RAMAZAN BAYRAMI (1.Gün)"
        ).replace("RAMAZAN BAYRAMI (TMP)", "RAMAZAN BAYRAMI (2.Gün)")
        rec_day = copy.deepcopy(self._base_2028())
        rec_day["source_document_content"] = swapped_day_html
        rec_day["source_document_sha256"] = compute_sha256(swapped_day_html.encode("utf-8"))
        chk_day = verify_holiday_source_snapshot(2028, rec_day)
        self.assertFalse(chk_day["valid"])
        self.assertIn("SOURCE_CONTENT_BAYRAM_OR_ORDER_MISMATCH", chk_day["error_codes"])

        # Negative 3: Ambiguous AREFE row without Hicrî month context -> REJECTED (never guessed)!
        ambig_html = good_html.replace("<td>RAMAZAN</td><td>1449</td><td>26</td><td>ŞUBAT-2028</td><td>GÜN</td><td>AREFE</td>", "<td>29</td><td>BELIRSIZ</td><td>1449</td><td>26</td><td>ŞUBAT-2028</td><td>GÜN</td><td>AREFE</td>")
        parsed_ambig = parse_turkish_religious_holidays_from_source(ambig_html.encode("utf-8"), 2028)
        self.assertFalse(parsed_ambig["valid"])
        self.assertIn("SOURCE_CONTENT_BAYRAM_OR_ORDER_MISMATCH", parsed_ambig["error_codes"])
        self.assertTrue(len(parsed_ambig["ambiguous_rows"]) >= 1)

    # --- 7. OCR Confidence & Manual Review Gate ---

    def test_ocr_low_confidence_or_missing_manual_review_never_auto_verifies(self) -> None:
        html_bytes = _build_diyanet_html_for_record(self._base_2028()).encode("utf-8")

        # Missing ocr_confidence -> REJECTED
        p_none = parse_turkish_religious_holidays_from_source(
            html_bytes, 2028, extraction_method="OCR", ocr_confidence=None, manual_ocr_review_confirmed=True
        )
        self.assertFalse(p_none["valid"])
        self.assertIn("OCR_LOW_CONFIDENCE_MANUAL_REVIEW_REQUIRED", p_none["error_codes"])

        # Low ocr_confidence (< 0.95) even with manual_ocr_review_confirmed=True -> REJECTED
        p_low = parse_turkish_religious_holidays_from_source(
            html_bytes, 2028, extraction_method="OCR", ocr_confidence=0.89, manual_ocr_review_confirmed=True
        )
        self.assertFalse(p_low["valid"])
        self.assertIn("OCR_LOW_CONFIDENCE_MANUAL_REVIEW_REQUIRED", p_low["error_codes"])

        # High ocr_confidence (>= 0.95) WITHOUT manual confirmation -> REJECTED
        p_noman = parse_turkish_religious_holidays_from_source(
            html_bytes, 2028, extraction_method="OCR", ocr_confidence=0.98, manual_ocr_review_confirmed=False
        )
        self.assertFalse(p_noman["valid"])
        self.assertIn("OCR_LOW_CONFIDENCE_MANUAL_REVIEW_REQUIRED", p_noman["error_codes"])

        # High ocr_confidence (>= 0.95) WITH manual confirmation -> ACCEPTED for Stage 1!
        p_ok = parse_turkish_religious_holidays_from_source(
            html_bytes, 2028, extraction_method="OCR", ocr_confidence=0.98, manual_ocr_review_confirmed=True
        )
        self.assertTrue(p_ok["valid"], p_ok["errors"])

    # --- 8. Snapshot Immutability, Offline-Origin Resilience & Append-Only Revision History ---

    def test_source_snapshot_immutability_offline_origin_resilience_and_versioned_revision(self) -> None:
        # 1) Offline-origin resilience: local archived 2024-2027 snapshots verify cleanly without any network access!
        snap_report = verify_archived_holiday_snapshots(audit_log_path=AUDIT_LOG_PATH, project_root=PROJECT_ROOT)
        self.assertTrue(snap_report["ok"], snap_report)
        self.assertTrue(snap_report["origin_offline_resilient"])
        self.assertEqual(snap_report["verified_years"], [2024, 2025, 2026, 2027])

        # 2) 1-byte tamper on an archived snapshot file MUST be caught by validate_central_audit_log!
        with tempfile.TemporaryDirectory(prefix="calisora_snap_tamper_") as tmpdir:
            tmp_root = Path(tmpdir)
            shutil.copytree(PROJECT_ROOT / "evidence", tmp_root / "evidence")
            shutil.copytree(PROJECT_ROOT / "config", tmp_root / "config")
            # Tamper 1 byte on archived 2026 Diyanet snapshot
            snap_2026 = tmp_root / "evidence" / "holiday_snapshots" / "diyanet_2026_v1.html"
            snap_2026.write_bytes(snap_2026.read_bytes() + b" ")
            audit_data = json.loads(AUDIT_LOG_PATH.read_text(encoding="utf-8"))
            rep_tamper = validate_central_audit_log(
                audit_data,
                self.sources,
                self.precedents,
                self.cards,
                project_root=tmp_root,
            )
            self.assertFalse(rep_tamper.valid)
            self.assertIn("SOURCE_SNAPSHOT_MISSING_OR_MISMATCH", {f.code for f in rep_tamper.flags})

        # 3) Versioned append-only revision (v1 -> v2) preserves v1; attempting overwrite raises SNAPSHOT_IMMUTABILITY_VIOLATION!
        audit_data = json.loads(AUDIT_LOG_PATH.read_text(encoding="utf-8"))
        v1_hist = audit_data["holiday_calendar_audit"]["yearly_records"]["2026"]["revision_history"]
        v2_sha = "a" * 64
        v2_hist = create_revised_snapshot_entry(
            v1_hist,
            new_snapshot_id="SNAP-DIYANET-2026-V2",
            new_snapshot_version="v2",
            new_snapshot_path="evidence/holiday_snapshots/diyanet_2026_v2.html",
            new_sha256=v2_sha,
            captured_at_utc="2026-11-22T09:00:00Z",
            reason="OFFICIAL_DIYANET_CORRIGENDUM",
        )
        self.assertEqual(len(v2_hist), 2)
        self.assertEqual(v2_hist[0]["snapshot_id"], "SNAP-DIYANET-2026-V1")
        self.assertEqual(v2_hist[1]["supersedes_snapshot_id"], "SNAP-DIYANET-2026-V1")

        # Attempting to overwrite same snapshot_path / snapshot_version / snapshot_id -> SNAPSHOT_IMMUTABILITY_VIOLATION!
        with self.assertRaisesRegex(ValueError, "SNAPSHOT_IMMUTABILITY_VIOLATION"):
            create_revised_snapshot_entry(
                v1_hist,
                new_snapshot_id="SNAP-DIYANET-2026-V2",
                new_snapshot_version="v2",
                new_snapshot_path="evidence/holiday_snapshots/diyanet_2026_v1.html",
                new_sha256=v2_sha,
                captured_at_utc="2026-11-22T09:00:00Z",
                reason="OVERWRITE_ATTEMPT",
            )

    # --- 9. Tamper-Evident Hash Chain, Signed Checkpoints & Full-Chain Rewrite Defeat ---

    def test_hash_chain_tampering_deletion_truncation_and_full_chain_rewrite_detection(self) -> None:
        ext, appr, led, _ = _build_signed_external_calendar_bundle(
            {"2028": self._base_2028(), "2029": self._base_2029()}
        )
        ok_chk = verify_attestation_ledger(led, approvers_registry=appr, require_signed_checkpoints=True)
        self.assertTrue(ok_chk["valid"], ok_chk["errors"])
        self.assertEqual(ok_chk["entry_count"], 4)
        self.assertEqual(ok_chk["verified_checkpoints_count"], 1)
        worm_head = ok_chk["head_entry_hash"]
        worm_count = ok_chk["entry_count"]

        # Attack 1: In-place payload edit -> AUDIT_CHAIN_TAMPERING_DETECTED
        led_edit = copy.deepcopy(led)
        led_edit["entries"][0]["payload"]["technical_verification_status"] = "TAMPERED"
        r1 = verify_attestation_ledger(led_edit, approvers_registry=appr, require_signed_checkpoints=True)
        self.assertFalse(r1["valid"])
        self.assertIn("AUDIT_CHAIN_TAMPERING_DETECTED", r1["error_codes"])

        # Attack 2: Entry deletion (sequence gap / missing middle record) -> AUDIT_CHAIN_TAMPERING_DETECTED
        led_del = copy.deepcopy(led)
        del led_del["entries"][1]
        r2 = verify_attestation_ledger(led_del, approvers_registry=appr, require_signed_checkpoints=True)
        self.assertFalse(r2["valid"])
        self.assertIn("AUDIT_CHAIN_TAMPERING_DETECTED", r2["error_codes"])

        # Attack 3: Tail truncation (deleting last entry after checkpoint) -> AUDIT_CHAIN_TAMPERING_DETECTED
        led_trunc = copy.deepcopy(led)
        led_trunc["entries"].pop()
        r3 = verify_attestation_ledger(led_trunc, approvers_registry=appr, require_signed_checkpoints=True)
        self.assertFalse(r3["valid"])
        self.assertIn("AUDIT_CHAIN_TAMPERING_DETECTED", r3["error_codes"])

        # Attack 4: FULL CHAIN REWRITE / RECALCULATION from scratch (attacker alters entry #1 AND recalculates
        #           EVERY prev_entry_hash & entry_hash cleanly!) -> DEFEATED by signed checkpoint!
        led_rewrite = copy.deepcopy(led)
        led_rewrite["entries"][0]["payload"]["parser_version"] = "attacker_forged_parser"
        rebuilt_entries = []
        tmp_led: dict[str, object] = {"entries": rebuilt_entries}
        for old_e in led_rewrite["entries"]:
            append_ledger_entry(
                tmp_led,
                entry_id=old_e["entry_id"],
                entry_type=old_e["entry_type"],
                recorded_at_utc=old_e["recorded_at_utc"],
                payload=old_e["payload"],
            )
        led_rewrite["entries"] = rebuilt_entries
        # Without checkpoint, internal chain looks self-consistent; WITH signed checkpoint it FAILS!
        r4_cp = verify_attestation_ledger(led_rewrite, approvers_registry=appr, require_signed_checkpoints=True)
        self.assertFalse(r4_cp["valid"])
        self.assertIn("AUDIT_CHAIN_TAMPERING_DETECTED", r4_cp["error_codes"])

        # Attack 5: Even if attacker strips checkpoints, external WORM anchor defeats full chain rewrite!
        led_rewrite_nocp = copy.deepcopy(led_rewrite)
        led_rewrite_nocp["checkpoints"] = []
        r5_worm = verify_attestation_ledger(
            led_rewrite_nocp,
            approvers_registry=appr,
            expected_checkpoint_head_hash=worm_head,
            expected_checkpoint_entry_count=worm_count,
            require_signed_checkpoints=False,
        )
        self.assertFalse(r5_worm["valid"])
        self.assertIn("AUDIT_CHAIN_TAMPERING_DETECTED", r5_worm["error_codes"])

        # End-to-end inside evaluate_hr_legal_scenario: tampered ledger emits CRITICAL AUDIT_CHAIN_TAMPERING_DETECTED!
        res_tamper = evaluate_hr_legal_scenario(
            scenario_type="TERMINATION_VALIDITY",
            as_of_date="2028-03-04",
            facts={
                "termination_reason_type": "JUST_CAUSE_M25_II",
                "workplace_total_employees": 100,
                "tenure_months": 24,
                "contract_term_type": "INDEFINITE",
                "written_notice_with_clear_reason": True,
                "notification_channel": "WRITTEN_HAND_OR_NOTARY",
                "act_date": "2028-02-23",
                "discovery_date": "2028-02-24",
                "planned_termination_date": "2028-03-04",
                "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                "religious_calendar_externally_verified": True,
                "external_verified_holiday_calendars": {"2028": ext["2028"]},
                "half_day_eve_legal_rule": "COUNT_AS_WORKING_DAY",
            },
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.cards,
            approvers_registry=appr,
            attestation_ledger=led_rewrite,
        )
        m26_t = res_tamper.structured_findings["m26_deadline_assessment"]
        self.assertIn("AUDIT_CHAIN_TAMPERING_DETECTED", m26_t["calendar_blocker_codes"])
        crit_cats = {r.category for r in res_tamper.risks if r.risk_level == "CRITICAL"}
        self.assertIn("AUDIT_CHAIN_TAMPERING_DETECTED", crit_cats)
        self.assertFalse(res_tamper.human_approval.payroll_handoff_allowed)

    # --- 10. Two-Stage Verification Separation (Technical vs. Legal Counsel Attestation) ---

    def test_two_stage_verification_separation_rejects_premature_verified_and_production_authorization(self) -> None:
        # Built-in 2024-2027 audit log separates Stage 1 (TECHNICAL_VERIFIED) from Stage 2 (PENDING_SIGNED_EXTERNAL_ATTESTATION)
        audit_data = json.loads(AUDIT_LOG_PATH.read_text(encoding="utf-8"))
        hca = audit_data["holiday_calendar_audit"]
        self.assertEqual(hca["technical_verification_status"], "TECHNICAL_VERIFIED")
        self.assertEqual(hca["legal_attestation_status"], "PENDING_SIGNED_EXTERNAL_ATTESTATION")
        self.assertEqual(hca["verification_status"], "TECHNICAL_VERIFIED_PENDING_LEGAL_ATTESTATION")
        self.assertFalse(hca["production_use_authorized"])

        # Prematurely flipping verification_status='VERIFIED' or production_use_authorized=True without signed legal attestation -> BLOCKER!
        for field, bad_val in (
            ("verification_status", "VERIFIED"),
            ("legal_attestation_status", "SIGNED_LEGAL_ATTESTATION_VERIFIED"),
            ("production_use_authorized", True),
        ):
            mut = copy.deepcopy(audit_data)
            mut["holiday_calendar_audit"][field] = bad_val
            rep = validate_central_audit_log(mut, self.sources, self.precedents, self.cards)
            self.assertFalse(rep.valid, f"{field}={bad_val} reddedilmeliydi")
            self.assertIn("TWO_STAGE_VERIFICATION_INCOMPLETE", {f.code for f in rep.flags})

        # External 2028 record passing ONLY Stage 1 (real HTML snapshot + SHA-256) WITHOUT Stage 2 legal_attestation -> BLOCKED!
        stage1_only = self._base_2028()
        html_2028 = _build_diyanet_html_for_record(stage1_only)
        stage1_only["source_document_content"] = html_2028
        stage1_only["source_document_sha256"] = compute_sha256(html_2028.encode("utf-8"))
        val_s1 = validate_external_yearly_holiday_calendar(2028, stage1_only)
        self.assertTrue(val_s1["technical_source_valid"])
        self.assertFalse(val_s1["legal_attestation_valid"])
        self.assertFalse(val_s1["valid"])
        self.assertFalse(val_s1["production_use_authorized"])
        self.assertIn("TWO_STAGE_VERIFICATION_INCOMPLETE", val_s1["error_codes"])

    # --- 11. Zero Private Keys Anywhere in Repository / Package ---

    def test_zero_private_keys_anywhere_in_repository_and_configs(self) -> None:
        # Build PEM markers dynamically so static secret scanners find zero literal PEM headers in repo/package
        dash = "-----"
        pk = "PRIVATE" + " KEY"
        forbidden_markers = [
            f"{dash}BEGIN {pk}{dash}",
            f"{dash}BEGIN RSA {pk}{dash}",
            f"{dash}BEGIN EC {pk}{dash}",
            f"{dash}BEGIN OPENSSH {pk}{dash}",
            f"{dash}BEGIN ENCRYPTED {pk}{dash}",
        ]
        scanned_files = 0
        for p in sorted(PROJECT_ROOT.rglob("*")):
            if not p.is_file() or "__pycache__" in p.parts or ".git" in p.parts:
                continue
            if p.suffix.lower() in {".pyc", ".zip", ".png", ".jpg", ".pdf"}:
                continue
            scanned_files += 1
            content = p.read_text(encoding="utf-8", errors="ignore")
            for marker in forbidden_markers:
                self.assertNotIn(marker, content, f"Özel anahtar başlığı bulundu: {p}")
        self.assertGreaterEqual(scanned_files, 45)

        # Production config/authorized_approvers.json must have NO test keys in production & NO private keys
        appr_cfg = json.loads(APPROVERS_PATH.read_text(encoding="utf-8"))
        self.assertFalse(appr_cfg["test_sandbox_keys_allowed_in_production"])
        self.assertEqual(appr_cfg["key_management_policy"], "EXTERNAL_KMS_HSM_REQUIRED_NO_PRIVATE_KEYS_IN_REPO")
        for aid, arec in appr_cfg["approvers"].items():
            self.assertNotEqual(arec["key_trust_tier"], "TEST_SANDBOX_ONLY", aid)
            self.assertFalse(arec["qualified_e_signature_5070_equivalent"], aid)
            self.assertIsNone(arec["public_key_pem"], f"Üretim anahtarı henüz kaydedilmemiş olmalı: {aid}")

    # --- 12. Governance, 6 Draft 2020-12 Schemas, Ledger, Real Snapshots & 74/74 Record Preservation ---

    def test_v102c5_governance_6_schemas_ledger_snapshots_and_74_records_preservation(self) -> None:
        self.assertTrue(TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["calendar_version"].startswith(("1.0.2c", "1.0.3", "1.0.4", "1.0.5")))
        self.assertEqual(
            TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["verification_status"],
            "TECHNICAL_VERIFIED_PENDING_LEGAL_ATTESTATION",
        )
        self.assertFalse(TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["production_use_authorized"])
        self.assertFalse(TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["qualified_e_signature_5070_equivalent"])
        self.assertEqual(TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["parser_version"], PARSER_VERSION)

        tax = json.loads(TAXONOMY_PATH.read_text(encoding="utf-8"))
        self.assertTrue(tax["schema_version"].startswith(("1.0.2c", "1.0.3", "1.0.4", "1.0.5")))
        self.assertTrue(tax["legal_reasoning_engine"]["version"].startswith(("1.0.2c", "1.0.3", "1.0.4", "1.0.5")))
        sr = tax["verification_infrastructure"]["strict_rules"]
        for key in (
            "require_archived_source_snapshot_and_9_slot_content_match",
            "require_cryptographic_legal_attestation_for_uncovered_holiday_years",
            "require_externally_verifiable_hash_chained_ledger_with_signed_checkpoints",
            "block_test_sandbox_signing_keys_in_production",
            "separate_technical_source_verification_from_legal_counsel_attestation",
            "forbid_private_keys_in_repository_and_package",
            "disclose_law_5070_non_equivalence_for_asymmetric_signatures",
        ):
            self.assertTrue(sr[key], key)

        # All 6 schemas present & aligned to 1.0.2c+
        for sp in (
            SOURCE_SCHEMA_PATH,
            PRECEDENT_SCHEMA_PATH,
            CARD_SCHEMA_PATH,
            SCENARIO_SCHEMA_PATH,
            APPROVERS_SCHEMA_PATH,
            LEDGER_SCHEMA_PATH,
        ):
            s_doc = json.loads(sp.read_text(encoding="utf-8"))
            self.assertEqual(s_doc["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertTrue("1.0.2c." in s_doc["title"] or "1.0.3" in s_doc["title"] or "1.0.4" in s_doc["title"] or "1.0.5" in s_doc["title"], sp.name)

        # Real unsigned pre-production ledger: mathematically intact, but NEVER trusted immutable without external trust anchor!
        ledger_cfg = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        led_rep = verify_attestation_ledger(ledger_cfg)
        self.assertTrue(led_rep["mathematical_chain_intact"])
        self.assertFalse(led_rep["valid"])
        self.assertFalse(led_rep["externally_verified_immutable"])
        self.assertFalse(led_rep["production_use_authorized"])
        self.assertEqual(led_rep["trust_anchor_status"], "CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR")
        self.assertEqual(led_rep["entry_count"], 4)

        # 74/74 audit log preservation + real snapshot + ledger verification
        audit_data = json.loads(AUDIT_LOG_PATH.read_text(encoding="utf-8"))
        self.assertTrue(audit_data["schema_version"].startswith(("1.0.2c", "1.0.3", "1.0.4", "1.0.5")))
        self.assertEqual(audit_data["external_legal_counsel_signoff_status"], "PENDING_SIGNED_EXTERNAL_ATTESTATION")
        self.assertEqual(audit_data["summary"]["total_audited_records"], 74)
        self.assertEqual(audit_data["summary"]["fully_verified_records_count"], 70)
        self.assertEqual(audit_data["summary"]["pending_verification_records_count"], 3)
        self.assertEqual(audit_data["summary"]["superseded_records_count"], 1)
        clean_rep = validate_central_audit_log(audit_data, self.sources, self.precedents, self.cards)
        self.assertTrue(clean_rep.valid, clean_rep.flags)

        # Router end-to-end with out-of-band signed trust roots accepts valid 2028 record
        ext_28, appr_28, led_28, _ = _build_signed_external_calendar_bundle({"2028": self._base_2028()})
        signed_router = HukukSGKToolRouter(
            approvers_registry=appr_28,
            attestation_ledger=led_28,
            runtime_environment="PRODUCTION",
        )
        out_ok = signed_router.dispatch(
            "evaluate_hr_legal_scenario",
            {
                "scenario_type": "TERMINATION_VALIDITY",
                "as_of_date": "2028-03-04",
                "facts": {
                    "termination_reason_type": "JUST_CAUSE_M25_II",
                    "workplace_total_employees": 100,
                    "tenure_months": 24,
                    "contract_term_type": "INDEFINITE",
                    "written_notice_with_clear_reason": True,
                    "notification_channel": "WRITTEN_HAND_OR_NOTARY",
                    "act_date": "2028-02-23",
                    "discovery_date": "2028-02-24",
                    "planned_termination_date": "2028-03-04",
                    "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                    "religious_calendar_externally_verified": True,
                    "external_verified_holiday_calendars": ext_28,
                    "half_day_eve_legal_rule": "COUNT_AS_WORKING_DAY",
                },
            },
        )
        m26_ok = out_ok["structured_findings"]["m26_deadline_assessment"]
        self.assertEqual(m26_ok["six_working_day_status"], "WITHIN_LIMIT")
        self.assertTrue(m26_ok["calendar_production_use_authorized"])
        self.assertEqual(m26_ok["technical_source_verification_status"], "TECHNICAL_VERIFIED")
        self.assertEqual(m26_ok["legal_attestation_status"], "SIGNED_LEGAL_ATTESTATION_VERIFIED")
        self.assertFalse(m26_ok["qualified_e_signature_5070_equivalent"])

        prompt_text = (PROJECT_ROOT / "agent" / "system_prompt.md").read_text(encoding="utf-8")
        self.assertIn("v1.0.2c.", prompt_text)
        self.assertIn("5070", prompt_text)


class TestV102c6SecurityHardeningAndJCSCompliance(unittest.TestCase):
    """v1.0.2c.6 red-team security hardening and spec-exact RFC 8785 (JCS) test suite:
      1) Safe snapshot path containment (Linux & Windows path traversal, absolute/UNC/drive paths) -> SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT
      2) Symlink file & intermediate directory escape outside project_root -> SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT
      3) Full hash-chain rewrite without external trust anchor NEVER returns valid=True -> CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR
      4) Unsigned checkpoints rejected in PRODUCTION + tail-append attack blocked
      5) Anti-self-anchoring defense (rejects anchor fields injected in ledger or untrusted trust_anchor_source)
      6) Spec-exact RFC 8785 (JCS / ES2015 §7.1.12.1) official number, string, Unicode & UTF-16 sorting test vectors
      7) Cryptographic rejection of non-JCS serialized signatures (Ed25519 & RSA-PSS-SHA256)
      8) End-to-end prohibition on production_use_authorized=True without external trust root
      9) v1.0.2c.6 governance, 6 Draft 2020-12 schemas, 74/74 preservation, and zero private keys.
    """

    def setUp(self) -> None:
        self.sources = load_source_registry(SOURCES_PATH, strict=True)
        self.precedents = load_precedent_registry(PRECEDENTS_PATH, source_registry=self.sources, strict=True)
        self.cards = load_knowledge_cards(
            KB_ALL_DIR,
            source_registry=self.sources,
            precedent_registry=self.precedents,
            strict=True,
            audit_log_path=AUDIT_LOG_PATH,
        )

    @staticmethod
    def _base_2028() -> dict[str, object]:
        return {
            "year": 2028,
            "ramazan_arife_date": "2028-02-26",
            "ramazan_start_date": "2028-02-27",
            "ramazan_end_date": "2028-02-29",
            "kurban_arife_date": "2028-05-04",
            "kurban_start_date": "2028-05-05",
            "kurban_end_date": "2028-05-08",
            "official_source_url": "https://vakithesaplama.diyanet.gov.tr/icerik.php?icerik=155",
            "verified_at": "2027-12-15",
            "verified_by": "CALISORA-HUKUK-01",
            "calendar_version": "2028.1-SIGNED",
        }

    # --- 1. Snapshot Path Traversal Containment (Linux & Windows) ---

    def test_snapshot_path_traversal_linux_and_windows_blocked_even_with_matching_sha256(self) -> None:
        base_2028 = self._base_2028()
        valid_html = _build_diyanet_html_for_record(base_2028)
        html_bytes = valid_html.encode("utf-8")
        matching_sha = compute_sha256(html_bytes)

        with tempfile.TemporaryDirectory(prefix="calisora_path_sec_") as outer_tmp:
            outer = Path(outer_tmp)
            outside_file = outer / "outside_evil_2028.html"
            outside_file.write_bytes(html_bytes)

            proj_root = outer / "workspace" / "calisora_hukuk_sgk"
            snap_dir = proj_root / "evidence" / "holiday_snapshots"
            snap_dir.mkdir(parents=True, exist_ok=True)
            inside_file = snap_dir / "diyanet_2028_v1.html"
            inside_file.write_bytes(html_bytes)

            rel_escape_to_existing = os.path.relpath(str(outside_file), str(proj_root))
            self.assertTrue(rel_escape_to_existing.startswith(".."))

            attack_paths = [
                rel_escape_to_existing,
                f"evidence/holiday_snapshots/../../{rel_escape_to_existing}",
                str(outside_file),
                "/etc/passwd",
                "..\\..\\outside_evil_2028.html",
                "evidence\\holiday_snapshots\\..\\..\\..\\..\\outside_evil_2028.html",
                "evidence/holiday_snapshots/..\\../outside_evil_2028.html",
                "C:\\Windows\\win.ini",
                "C:/tmp/outside_evil_2028.html",
                "d:relative.html",
                "\\\\server\\share\\diyanet_2028.html",
                "//server/share/diyanet_2028.html",
                "\\\\?\\C:\\Windows\\win.ini",
                "evidence/holiday_snapshots/diyanet_2028_v1.html\x00.txt",
                ".",
                "./",
                "",
            ]

            for bad_path in attack_paths:
                with self.subTest(attack_path=bad_path):
                    resolved, err_code, _ = resolve_safe_project_path(bad_path, project_root=proj_root)
                    self.assertIsNone(resolved)
                    self.assertEqual(err_code, "SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT")

                    if bad_path:  # empty snapshot_path triggers missing snapshot; non-empty MUST trigger containment!
                        rec = copy.deepcopy(base_2028)
                        rec["snapshot_path"] = bad_path
                        rec["source_document_sha256"] = matching_sha
                        chk = verify_holiday_source_snapshot(2028, rec, project_root=proj_root)
                        self.assertFalse(chk["valid"], f"Traversal path passed unexpectedly: {bad_path!r}")
                        self.assertIn("SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT", chk["error_codes"])
                        # External file MUST NEVER be read!
                        self.assertIsNone(chk["source_document_sha256"])

            # Smuggled traversal snapshot_path alongside valid inline source_document_content MUST STILL BE BLOCKED!
            rec_smuggle = copy.deepcopy(base_2028)
            rec_smuggle["snapshot_path"] = rel_escape_to_existing
            rec_smuggle["source_document_content"] = valid_html
            rec_smuggle["source_document_sha256"] = matching_sha
            chk_smuggle = verify_holiday_source_snapshot(2028, rec_smuggle, project_root=proj_root)
            self.assertFalse(chk_smuggle["valid"])
            self.assertIn("SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT", chk_smuggle["error_codes"])

            # create_revised_snapshot_entry rejects traversal paths too!
            audit_data = json.loads(AUDIT_LOG_PATH.read_text(encoding="utf-8"))
            v1_hist = audit_data["holiday_calendar_audit"]["yearly_records"]["2026"]["revision_history"]
            with self.assertRaisesRegex(ValueError, "SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT"):
                create_revised_snapshot_entry(
                    v1_hist,
                    new_snapshot_id="SNAP-DIYANET-2026-V2",
                    new_snapshot_version="v2",
                    new_snapshot_path="../../tmp/evil.html",
                    new_sha256=matching_sha,
                    captured_at_utc="2026-11-22T09:00:00Z",
                    reason="TRAVERSAL_ATTEMPT",
                    project_root=proj_root,
                )

            # Positive cross-platform controls: legitimate relative POSIX & Windows-style paths strictly inside project_root PASS!
            for ok_path in (
                "evidence/holiday_snapshots/diyanet_2028_v1.html",
                "evidence\\holiday_snapshots\\diyanet_2028_v1.html",
            ):
                with self.subTest(valid_path=ok_path):
                    rec_ok = copy.deepcopy(base_2028)
                    rec_ok["snapshot_path"] = ok_path
                    rec_ok["source_document_sha256"] = matching_sha
                    chk_ok = verify_holiday_source_snapshot(2028, rec_ok, project_root=proj_root)
                    self.assertTrue(chk_ok["valid"], chk_ok["errors"])
                    self.assertEqual(chk_ok["source_document_sha256"], matching_sha)

    # --- 2. Symlink File & Intermediate Directory Escape Containment ---

    def test_snapshot_symlink_file_and_directory_escape_blocked_outside_project_root(self) -> None:
        base_2028 = self._base_2028()
        valid_html = _build_diyanet_html_for_record(base_2028)
        html_bytes = valid_html.encode("utf-8")
        matching_sha = compute_sha256(html_bytes)

        with tempfile.TemporaryDirectory(prefix="calisora_sym_sec_") as outer_tmp:
            outer = Path(outer_tmp)
            outside_dir = outer / "outside_secret_dir"
            outside_dir.mkdir(parents=True, exist_ok=True)
            outside_html = outside_dir / "diyanet_2028_outside.html"
            outside_html.write_bytes(html_bytes)

            proj_root = outer / "proj"
            snap_dir = proj_root / "evidence" / "holiday_snapshots"
            snap_dir.mkdir(parents=True, exist_ok=True)

            # Attack A: Direct file symlink inside project_root -> outside HTML file
            evil_file_link = snap_dir / "evil_link_2028.html"
            os.symlink(str(outside_html), str(evil_file_link))

            rec_file_link = copy.deepcopy(base_2028)
            rec_file_link["snapshot_path"] = "evidence/holiday_snapshots/evil_link_2028.html"
            rec_file_link["source_document_sha256"] = matching_sha
            chk_fl = verify_holiday_source_snapshot(2028, rec_file_link, project_root=proj_root)
            self.assertFalse(chk_fl["valid"])
            self.assertIn("SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT", chk_fl["error_codes"])
            self.assertIsNone(chk_fl["source_document_sha256"])

            # Attack B: Intermediate directory symlink inside project_root -> outside directory
            evil_dir_link = proj_root / "evidence" / "escaped_dir"
            os.symlink(str(outside_dir), str(evil_dir_link))

            rec_dir_link = copy.deepcopy(base_2028)
            rec_dir_link["snapshot_path"] = "evidence/escaped_dir/diyanet_2028_outside.html"
            rec_dir_link["source_document_sha256"] = matching_sha
            chk_dl = verify_holiday_source_snapshot(2028, rec_dir_link, project_root=proj_root)
            self.assertFalse(chk_dl["valid"])
            self.assertIn("SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT", chk_dl["error_codes"])
            self.assertIsNone(chk_dl["source_document_sha256"])

            # Attack C: End-to-end inside evaluate_hr_legal_scenario -> CRITICAL risk + payroll handoff blocked!
            ext_signed, appr_signed, led_signed, _ = _build_signed_external_calendar_bundle({"2028": base_2028})
            tampered_ext = copy.deepcopy(ext_signed)
            tampered_ext["2028"].pop("source_document_content", None)
            tampered_ext["2028"]["snapshot_path"] = "evidence/holiday_snapshots/evil_link_2028.html"
            ev_sym = evaluate_hr_legal_scenario(
                scenario_type="TERMINATION_VALIDITY",
                as_of_date="2028-03-04",
                facts={
                    "termination_reason_type": "JUST_CAUSE_M25_II",
                    "workplace_total_employees": 100,
                    "tenure_months": 24,
                    "contract_term_type": "INDEFINITE",
                    "written_notice_with_clear_reason": True,
                    "notification_channel": "WRITTEN_HAND_OR_NOTARY",
                    "act_date": "2028-02-23",
                    "discovery_date": "2028-02-24",
                    "planned_termination_date": "2028-03-04",
                    "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                    "religious_calendar_externally_verified": True,
                    "external_verified_holiday_calendars": tampered_ext,
                    "half_day_eve_legal_rule": "COUNT_AS_WORKING_DAY",
                },
                source_registry=self.sources,
                precedent_registry=self.precedents,
                knowledge_cards=self.cards,
                approvers_registry=appr_signed,
                attestation_ledger=led_signed,
                project_root=proj_root,
            )
            m26_sym = ev_sym.structured_findings["m26_deadline_assessment"]
            self.assertEqual(m26_sym["six_working_day_status"], "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
            self.assertIn("SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT", m26_sym["calendar_blocker_codes"])
            crit_cats = {r.category for r in ev_sym.risks if r.risk_level == "CRITICAL"}
            self.assertIn("SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT", crit_cats)
            self.assertFalse(ev_sym.human_approval.payroll_handoff_allowed)

            # Attack D: Central audit log with traversal snapshot_path OR ledger/approvers path -> BLOCKER!
            audit_data = json.loads(AUDIT_LOG_PATH.read_text(encoding="utf-8"))
            mut_snap = copy.deepcopy(audit_data)
            mut_snap["holiday_calendar_audit"]["yearly_records"]["2026"]["snapshot_path"] = "../../../../tmp/evil.html"
            rep_snap = validate_central_audit_log(mut_snap, self.sources, self.precedents, self.cards)
            self.assertFalse(rep_snap.valid)
            self.assertIn("SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT", {f.code for f in rep_snap.flags})

            mut_led_path = copy.deepcopy(audit_data)
            mut_led_path["holiday_calendar_audit"]["attestation_ledger_path"] = "../../etc/passwd"
            rep_lp = validate_central_audit_log(mut_led_path, self.sources, self.precedents, self.cards)
            self.assertFalse(rep_lp.valid)
            self.assertIn("SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT", {f.code for f in rep_lp.flags})

    # --- 3. Full Chain Rewrite Without External Trust Anchor Never Returns valid=True ---

    def test_full_chain_rewrite_without_external_trust_anchor_never_returns_valid_true(self) -> None:
        orig_ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        orig_head = orig_ledger["entries"][-1]["entry_hash"]
        orig_digest = orig_ledger["checkpoints"][0]["chain_digest_sha256"]

        # Exact reproduction of Critical Finding 2 red-team attack:
        # Attacker modifies entry #1, recalculates ALL 4 hashes + prev_entry_hash cleanly,
        # AND rewrites the unsigned checkpoint's head_entry_hash & chain_digest_sha256!
        rewritten = copy.deepcopy(orig_ledger)
        rewritten["entries"][0]["payload"]["technical_verification_status"] = "ATTACKER_FORGED_STATUS"
        rebuilt_entries: list[dict[str, object]] = []
        tmp_led: dict[str, object] = {"entries": rebuilt_entries}
        for old_e in rewritten["entries"]:
            append_ledger_entry(
                tmp_led,
                entry_id=old_e["entry_id"],
                entry_type=old_e["entry_type"],
                recorded_at_utc=old_e["recorded_at_utc"],
                payload=old_e["payload"],
            )
        rewritten["entries"] = rebuilt_entries
        rewritten["checkpoints"] = []
        create_ledger_checkpoint(
            rewritten,
            checkpoint_id="CHK-ATTACKER-REWRITTEN-001",
            checkpoint_scope="ATTACKER_FORGED",
            created_at_utc="2026-11-21T04:00:00Z",
            nonce="CHK-NONCE-ATTACKER-0001",
            signer_approver_id="CALISORA-LEDGER-SEALER-01",
            key_id="KEY-CALISORA-SEALER-01-PENDING",
            key_version="v1",
        )

        # 1) Default call verify_attestation_ledger(rewritten) MUST NOT return valid=True!
        rep_default = verify_attestation_ledger(rewritten)
        self.assertFalse(rep_default["valid"])
        self.assertTrue(rep_default["mathematical_chain_intact"])
        self.assertFalse(rep_default["externally_verified_immutable"])
        self.assertFalse(rep_default["production_use_authorized"])
        self.assertEqual(rep_default["trust_anchor_status"], "CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR")
        self.assertIn("CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR", rep_default["error_codes"])
        self.assertIn("UNSIGNED_CHECKPOINT_REJECTED_IN_PRODUCTION", rep_default["error_codes"])

        # 2) Even if caller explicitly passes require_signed_checkpoints=False (in PRODUCTION or TEST_SANDBOX_ONLY),
        #    without an external WORM/TSA trust anchor, valid MUST STILL BE False!
        for env_name in ("PRODUCTION", "TEST_SANDBOX_ONLY"):
            rep_no_anchor = verify_attestation_ledger(
                rewritten,
                runtime_environment=env_name,
                require_signed_checkpoints=False,
            )
            self.assertFalse(rep_no_anchor["valid"], env_name)
            self.assertFalse(rep_no_anchor["externally_verified_immutable"], env_name)
            self.assertFalse(rep_no_anchor["production_use_authorized"], env_name)
            self.assertEqual(rep_no_anchor["trust_anchor_status"], "CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR")
            self.assertIn("CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR", rep_no_anchor["error_codes"])

        # 3) With out-of-band external WORM anchor from the original chain -> TAMPERED + AUDIT_CHAIN_TAMPERING_DETECTED!
        rep_worm = verify_attestation_ledger(
            rewritten,
            expected_checkpoint_head_hash=orig_head,
            expected_chain_digest_sha256=orig_digest,
            expected_checkpoint_entry_count=4,
            require_signed_checkpoints=False,
            trust_anchor_source="INDEPENDENT_WORM_STORE",
        )
        self.assertFalse(rep_worm["valid"])
        self.assertEqual(rep_worm["trust_anchor_status"], "TAMPERED")
        self.assertIn("AUDIT_CHAIN_TAMPERING_DETECTED", rep_worm["error_codes"])

    # --- 4. Unsigned Checkpoint Rejection in PRODUCTION & Tail-Append Protection ---

    def test_unsigned_checkpoint_rejected_in_production_and_tail_append_blocked(self) -> None:
        orig_ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        orig_head = orig_ledger["entries"][-1]["entry_hash"]
        orig_digest = orig_ledger["checkpoints"][0]["chain_digest_sha256"]

        # Case A: Even with matching out-of-band WORM anchor, an UNSIGNED checkpoint in PRODUCTION is REJECTED!
        rep_unsigned_prod = verify_attestation_ledger(
            orig_ledger,
            runtime_environment="PRODUCTION",
            expected_checkpoint_head_hash=orig_head,
            expected_chain_digest_sha256=orig_digest,
            expected_checkpoint_entry_count=4,
            require_signed_checkpoints=False,
            trust_anchor_source="INDEPENDENT_WORM_STORE",
        )
        self.assertFalse(rep_unsigned_prod["valid"])
        self.assertFalse(rep_unsigned_prod["production_use_authorized"])
        self.assertIn("UNSIGNED_CHECKPOINT_REJECTED_IN_PRODUCTION", rep_unsigned_prod["error_codes"])

        # Case B: Clean ledger with NO unsigned checkpoints + verified out-of-band WORM anchor covering full head -> VALID!
        worm_only_ledger = copy.deepcopy(orig_ledger)
        worm_only_ledger["checkpoints"] = []
        rep_worm_ok = verify_attestation_ledger(
            worm_only_ledger,
            runtime_environment="PRODUCTION",
            expected_checkpoint_head_hash=orig_head,
            expected_chain_digest_sha256=orig_digest,
            expected_checkpoint_entry_count=4,
            require_signed_checkpoints=False,
            trust_anchor_source="INDEPENDENT_WORM_STORE",
        )
        self.assertTrue(rep_worm_ok["valid"], rep_worm_ok["errors"])
        self.assertTrue(rep_worm_ok["externally_verified_immutable"])
        self.assertTrue(rep_worm_ok["external_worm_anchor_verified"])
        self.assertEqual(rep_worm_ok["trust_anchor_status"], "EXTERNALLY_VERIFIED_IMMUTABLE")

        # Case C: Tail-append attack (validly signed checkpoint covers entries 1..2, attacker appends unsigned entry #3)
        _, appr_ok, led_signed, _ = _build_signed_external_calendar_bundle({"2028": self._base_2028()})
        self.assertTrue(verify_attestation_ledger(led_signed, approvers_registry=appr_ok)["valid"])
        led_tail = copy.deepcopy(led_signed)
        append_ledger_entry(
            led_tail,
            entry_id="LED-ATTACKER-TAIL-APPEND-003",
            entry_type="TECHNICAL_SOURCE_VERIFICATION",
            recorded_at_utc="2028-01-01T00:00:00Z",
            payload={"year": 2030, "forged": True},
        )
        rep_tail = verify_attestation_ledger(led_tail, approvers_registry=appr_ok)
        self.assertFalse(rep_tail["valid"])
        self.assertFalse(rep_tail["signed_checkpoint_covers_head"])
        self.assertFalse(rep_tail["production_use_authorized"])
        self.assertEqual(rep_tail["trust_anchor_status"], "CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR")
        self.assertIn("CHAIN_HEAD_NOT_COVERED_BY_TRUST_ANCHOR", rep_tail["error_codes"])
        self.assertIn("CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR", rep_tail["error_codes"])

        # Case D: Central audit log rejects require_production_trust_anchor=True OR false EXTERNALLY_VERIFIED_IMMUTABLE claim!
        audit_data = json.loads(AUDIT_LOG_PATH.read_text(encoding="utf-8"))
        rep_req_prod = validate_central_audit_log(
            audit_data,
            self.sources,
            self.precedents,
            self.cards,
            require_production_trust_anchor=True,
        )
        self.assertFalse(rep_req_prod.valid)
        self.assertIn("EXTERNAL_TRUST_ANCHOR_REQUIRED", {f.code for f in rep_req_prod.flags})

        mut_lie = copy.deepcopy(audit_data)
        mut_lie["holiday_calendar_audit"]["ledger_trust_anchor_status"] = "EXTERNALLY_VERIFIED_IMMUTABLE"
        rep_lie = validate_central_audit_log(mut_lie, self.sources, self.precedents, self.cards)
        self.assertFalse(rep_lie.valid)
        self.assertIn("EXTERNAL_TRUST_ANCHOR_REQUIRED", {f.code for f in rep_lie.flags})

    # --- 5. Anti-Self-Anchoring Defense ---

    def test_anti_self_anchoring_rejects_anchor_fields_injected_in_ledger_or_untrusted_source(self) -> None:
        _, appr_ok, led_ok, _ = _build_signed_external_calendar_bundle({"2028": self._base_2028()})
        good_head = led_ok["entries"][-1]["entry_hash"]
        good_digest = led_ok["checkpoints"][0]["chain_digest_sha256"]

        forbidden_samples = {
            "expected_checkpoint_head_hash": good_head,
            "expected_checkpoint_entry_count": len(led_ok["entries"]),
            "expected_chain_digest_sha256": good_digest,
            "worm_anchor": {"head": good_head},
            "trusted_anchor": good_head,
        }
        for field_name, field_val in forbidden_samples.items():
            # Top-level injection
            with self.subTest(location="ledger_root", field=field_name):
                bad_led = copy.deepcopy(led_ok)
                bad_led[field_name] = field_val
                rep = verify_attestation_ledger(bad_led, approvers_registry=appr_ok)
                self.assertFalse(rep["valid"])
                self.assertEqual(rep["trust_anchor_status"], "TAMPERED")
                self.assertIn("UNTRUSTED_SELF_DECLARED_ANCHOR_IN_LEDGER", rep["error_codes"])
                self.assertIn("AUDIT_CHAIN_TAMPERING_DETECTED", rep["error_codes"])

            # Checkpoint-level injection
            with self.subTest(location="checkpoint", field=field_name):
                bad_cp_led = copy.deepcopy(led_ok)
                bad_cp_led["checkpoints"][0][field_name] = field_val
                rep_cp = verify_attestation_ledger(bad_cp_led, approvers_registry=appr_ok)
                self.assertFalse(rep_cp["valid"])
                self.assertEqual(rep_cp["trust_anchor_status"], "TAMPERED")
                self.assertIn("UNTRUSTED_SELF_DECLARED_ANCHOR_IN_LEDGER", rep_cp["error_codes"])
                self.assertIn("AUDIT_CHAIN_TAMPERING_DETECTED", rep_cp["error_codes"])

        # Untrusted trust_anchor_source value -> REJECTED!
        for bad_src in ("FROM_LEDGER_CONTENT", "USER_FACTS_JSON", "SELF_DECLARED", ""):
            with self.subTest(trust_anchor_source=bad_src):
                rep_src = verify_attestation_ledger(
                    led_ok,
                    approvers_registry=appr_ok,
                    expected_checkpoint_head_hash=good_head,
                    trust_anchor_source=bad_src,
                )
                self.assertFalse(rep_src["valid"])
                self.assertEqual(rep_src["trust_anchor_status"], "TAMPERED")
                self.assertIn("UNTRUSTED_SELF_DECLARED_ANCHOR_IN_LEDGER", rep_src["error_codes"])

        # Central audit log also blocks self-anchored ledger injection!
        audit_data = json.loads(AUDIT_LOG_PATH.read_text(encoding="utf-8"))
        injected_ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        injected_ledger["expected_checkpoint_head_hash"] = injected_ledger["entries"][-1]["entry_hash"]
        rep_aud = validate_central_audit_log(
            audit_data,
            self.sources,
            self.precedents,
            self.cards,
            attestation_ledger=injected_ledger,
        )
        self.assertFalse(rep_aud.valid)
        self.assertIn("UNTRUSTED_SELF_DECLARED_ANCHOR_IN_LEDGER", {f.code for f in rep_aud.flags})
        self.assertIn("AUDIT_CHAIN_TAMPERING_DETECTED", {f.code for f in rep_aud.flags})

    # --- 6. Spec-Exact RFC 8785 (JCS) Number Vectors & Edge Cases ---

    def test_rfc8785_jcs_official_number_vectors_and_edge_cases(self) -> None:
        # Official RFC 8785 §3.2.2.3 / Appendix B & ECMAScript ES2015 §7.1.12.1 boundary vectors
        number_vectors = [
            (0, b"0"),
            (0.0, b"0"),
            (-0.0, b"0"),
            (1, b"1"),
            (-1, b"-1"),
            (4.50, b"4.5"),
            (2e-3, b"0.002"),
            (1e-6, b"0.000001"),
            (-1e-6, b"-0.000001"),
            (1e-7, b"1e-7"),
            (-1e-7, b"-1e-7"),
            (1e-27, b"1e-27"),
            (0.000000000000000000000000001, b"1e-27"),
            (1e20, b"100000000000000000000"),
            (100000000000000000000.0, b"100000000000000000000"),
            (9.999999999999999e20, b"999999999999999900000"),
            (1e21, b"1e+21"),
            (-1e21, b"-1e+21"),
            (1e30, b"1e+30"),
            (333333333.33333329, b"333333333.3333333"),
            (5e-324, b"5e-324"),
            (1.7976931348623157e308, b"1.7976931348623157e+308"),
            ((2**53) - 1, b"9007199254740991"),
            (-((2**53) - 1), b"-9007199254740991"),
        ]
        for val, expected in number_vectors:
            with self.subTest(val=repr(val)):
                self.assertEqual(canonical_json_bytes(val), expected)

        # Official RFC 8785 §3.2.2.3 combined numbers object
        rfc_numbers = {
            "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001],
            "string": "\u20ac$\x0f\nA'B\"\\\\\"/",
            "literals": [None, True, False],
        }
        self.assertEqual(
            canonical_json_bytes(rfc_numbers),
            (
                '{"literals":[null,true,false],'
                '"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
                '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
            ).encode("utf-8"),
        )

        # Reject NaN, Infinity, -Infinity, and unsafe I-JSON integers (> 2^53 - 1)
        for bad_num in (float("nan"), float("inf"), float("-inf"), 2**53, -(2**53)):
            with self.subTest(bad_num=repr(bad_num)):
                with self.assertRaises(ValueError):
                    canonical_json_bytes({"x": bad_num})

    # --- 7. RFC 8785 (JCS) Strings, Control Chars, Turkish Unicode & UTF-16 Key Sorting ---

    def test_rfc8785_jcs_strings_control_chars_unicode_and_utf16_key_sorting(self) -> None:
        # Control characters U+0000..U+001F: named escapes + lowercase \u00xx; '/' NEVER escaped; Turkish UTF-8 preserved
        self.assertEqual(
            canonical_json_bytes("\x00\x01\x07\b\t\n\x0b\f\r\x0e\x1f/\"\\ÇĞİÖŞÜçğıöşü"),
            '"\\u0000\\u0001\\u0007\\b\\t\\n\\u000b\\f\\r\\u000e\\u001f/\\"\\\\ÇĞİÖŞÜçğıöşü"'.encode("utf-8"),
        )

        # Lone UTF-16 surrogates rejected in values AND object keys
        with self.assertRaises(ValueError):
            canonical_json_bytes({"bad_val": "\ud800"})
        with self.assertRaises(ValueError):
            canonical_json_bytes({"\udfff": "bad_key"})

        # Official RFC 8785 §3.2.3 UTF-16 code-unit property sorting vector:
        # U+1F600 (😀 -> UTF-16 0xD83D 0xDE00) MUST sort BEFORE U+FB33 (דּ -> UTF-16 0xFB33)!
        sorting_input = {
            "\u20ac": "Euro Sign",
            "\r": "Carriage Return",
            "1": "One",
            "\u0080": "Control",
            "\ufb33": "Hebrew Letter Dalet With Dagesh",
            "\U0001f600": "Emoji: Grinning Face",
            "\u00f6": "Latin Small Letter O With Diaeresis",
        }
        expected_jcs = (
            '{"\\r":"Carriage Return",'
            '"1":"One",'
            '"\u0080":"Control",'
            '"\u00f6":"Latin Small Letter O With Diaeresis",'
            '"\u20ac":"Euro Sign",'
            '"\U0001f600":"Emoji: Grinning Face",'
            '"\ufb33":"Hebrew Letter Dalet With Dagesh"}'
        ).encode("utf-8")
        self.assertEqual(canonical_json_bytes(sorting_input), expected_jcs)

    # --- 8. Cryptographic Rejection of Non-JCS Serialized Signatures ---

    def test_non_jcs_serialized_signature_rejected_by_verify_asymmetric_signature(self) -> None:
        # Payload where Python's standard json.dumps diverges from RFC 8785 JCS on floats & -0.0
        payload = {
            "z_small": 1e-7,
            "a_fixed": 1e-6,
            "neg_zero": -0.0,
            "big_fixed": 1e20,
            "url": "https://vakithesaplama.diyanet.gov.tr/icerik.php?icerik=153",
            "label": "Ramazan Bayramı",
        }
        jcs_bytes = canonical_json_bytes(payload)
        non_jcs_variants = [
            json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8"),
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
            json.dumps(payload, sort_keys=False, separators=(",", ":"), ensure_ascii=True).encode("utf-8"),
        ]
        for variant in non_jcs_variants:
            self.assertNotEqual(variant, jcs_bytes)

        openssl = shutil.which("openssl")
        self.assertIsNotNone(openssl)

        for alg in ("ED25519", "RSA-PSS-SHA256"):
            priv_pem, pub_pem = generate_ephemeral_keypair(alg)

            # Positive control: JCS-signed payload verifies cleanly
            good_sig = sign_canonical_payload(payload, priv_pem, algorithm=alg)
            ok, msg = verify_asymmetric_signature(payload, good_sig, pub_pem, alg)
            self.assertTrue(ok, f"{alg}: {msg}")

            # Negative: signatures computed over non-JCS JSON bytes MUST BE REJECTED!
            for idx, raw_bytes in enumerate(non_jcs_variants):
                with self.subTest(algorithm=alg, non_jcs_variant=idx):
                    with tempfile.TemporaryDirectory(prefix="calisora_nonjcs_") as tmp:
                        p_priv = Path(tmp) / "priv.pem"
                        p_msg = Path(tmp) / "msg.bin"
                        p_sig = Path(tmp) / "sig.bin"
                        p_priv.write_text(priv_pem, encoding="utf-8")
                        p_msg.write_bytes(raw_bytes)
                        if alg == "ED25519":
                            cmd = [openssl, "pkeyutl", "-sign", "-inkey", str(p_priv), "-rawin", "-in", str(p_msg), "-out", str(p_sig)]
                        else:
                            cmd = [
                                openssl, "dgst", "-sha256",
                                "-sigopt", "rsa_padding_mode:pss",
                                "-sigopt", "rsa_pss_saltlen:32",
                                "-sign", str(p_priv), "-out", str(p_sig), str(p_msg),
                            ]
                        proc = subprocess.run(
                            cmd,
                            stdin=subprocess.DEVNULL,
                            capture_output=True,
                            text=True,
                            timeout=30,
                            check=False,
                        )
                        self.assertEqual(proc.returncode, 0, proc.stderr)
                        bad_sig_b64 = base64.b64encode(p_sig.read_bytes()).decode("ascii")

                    bad_ok, _ = verify_asymmetric_signature(payload, bad_sig_b64, pub_pem, alg)
                    self.assertFalse(bad_ok, f"Non-JCS signature was wrongly accepted for {alg} variant {idx}")

    # --- 9. End-to-End Prohibition on production_use_authorized=True Without External Trust Root ---

    def test_no_production_authorization_without_external_trust_root_end_to_end(self) -> None:
        ext_28, appr_28, led_28, _ = _build_signed_external_calendar_bundle({"2028": self._base_2028()})

        # Strip checkpoint signature so the ledger is mathematically intact + legal counsel signature is valid,
        # BUT there is NO external trust root on the ledger checkpoint!
        unsigned_cp_led = copy.deepcopy(led_28)
        unsigned_cp_led["checkpoints"][0]["checkpoint_signature_b64"] = None
        unsigned_cp_led["checkpoints"][0]["checkpoint_signature_status"] = "PENDING_PRODUCTION_SEALER_KEY_ENROLLMENT"

        chk_no_root = verify_signed_calendar_attestation(
            2028,
            ext_28["2028"],
            approvers_registry=appr_28,
            attestation_ledger=unsigned_cp_led,
            runtime_environment="PRODUCTION",
            require_signed_ledger_checkpoint=False,
        )
        self.assertFalse(chk_no_root["valid"])
        self.assertFalse(chk_no_root["production_use_authorized"])
        self.assertFalse(chk_no_root["externally_verified_immutable"])
        self.assertEqual(chk_no_root["ledger_trust_anchor_status"], "CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR")
        self.assertIn("UNSIGNED_CHECKPOINT_REJECTED_IN_PRODUCTION", chk_no_root["error_codes"])
        self.assertIn("CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR", chk_no_root["error_codes"])

        # Router with mismatched out-of-band expected_chain_digest_sha256 -> blocks with AUDIT_CHAIN_TAMPERING_DETECTED!
        bad_digest_router = HukukSGKToolRouter(
            approvers_registry=appr_28,
            attestation_ledger=led_28,
            runtime_environment="PRODUCTION",
            expected_chain_digest_sha256="f" * 64,
        )
        out_bad = bad_digest_router.dispatch(
            "evaluate_hr_legal_scenario",
            {
                "scenario_type": "TERMINATION_VALIDITY",
                "as_of_date": "2028-03-04",
                "facts": {
                    "termination_reason_type": "JUST_CAUSE_M25_II",
                    "workplace_total_employees": 100,
                    "tenure_months": 24,
                    "contract_term_type": "INDEFINITE",
                    "written_notice_with_clear_reason": True,
                    "notification_channel": "WRITTEN_HAND_OR_NOTARY",
                    "act_date": "2028-02-23",
                    "discovery_date": "2028-02-24",
                    "planned_termination_date": "2028-03-04",
                    "discovering_authority_status": "AUTHORIZED_DISMISSAL_BODY",
                    "religious_calendar_externally_verified": True,
                    "external_verified_holiday_calendars": ext_28,
                    "half_day_eve_legal_rule": "COUNT_AS_WORKING_DAY",
                },
            },
        )
        m26_bad = out_bad["structured_findings"]["m26_deadline_assessment"]
        self.assertEqual(m26_bad["six_working_day_status"], "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
        self.assertFalse(m26_bad["calendar_production_use_authorized"])
        self.assertIn("AUDIT_CHAIN_TAMPERING_DETECTED", m26_bad["calendar_blocker_codes"])
        self.assertFalse(out_bad["human_approval"]["payroll_handoff_allowed"])

    # --- 10. v1.0.2c.6 Governance, 6 Schemas, 74/74 Preservation & Zero Private Keys ---

    def test_v102c6_governance_schemas_taxonomy_prompt_and_74_record_preservation(self) -> None:
        self.assertTrue(TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["calendar_version"].startswith(("1.0.2c.6", "1.0.3", "1.0.4", "1.0.5")))
        self.assertTrue(PARSER_VERSION.startswith(("tr_diyanet_holiday_parser_v1.0.2c.6", "tr_diyanet_holiday_parser_v1.0.3", "tr_diyanet_holiday_parser_v1.0.4", "tr_diyanet_holiday_parser_v1.0.5")))
        self.assertEqual(
            TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["ledger_trust_anchor_status"],
            "CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR",
        )
        self.assertFalse(TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["production_use_authorized"])
        self.assertFalse(TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["qualified_e_signature_5070_equivalent"])

        tax = json.loads(TAXONOMY_PATH.read_text(encoding="utf-8"))
        self.assertTrue(tax["schema_version"].startswith(("1.0.2c.6", "1.0.3", "1.0.4", "1.0.5")))
        self.assertTrue(tax["legal_reasoning_engine"]["version"].startswith(("1.0.2c.6", "1.0.3", "1.0.4", "1.0.5")))
        sr = tax["verification_infrastructure"]["strict_rules"]
        for key in (
            "enforce_snapshot_path_containment_within_project_root",
            "require_external_trust_anchor_for_ledger_immutability",
            "forbid_self_declared_ledger_trust_anchors",
            "reject_unsigned_checkpoints_in_production",
            "require_rfc8785_jcs_canonicalization",
        ):
            self.assertTrue(sr[key], key)

        # All 6 schemas aligned to v1.0.2c.6 & ledger schema strictly forbids additionalProperties (blocks self-anchors)
        for sp in (
            SOURCE_SCHEMA_PATH,
            PRECEDENT_SCHEMA_PATH,
            CARD_SCHEMA_PATH,
            SCENARIO_SCHEMA_PATH,
            APPROVERS_SCHEMA_PATH,
            LEDGER_SCHEMA_PATH,
        ):
            s_doc = json.loads(sp.read_text(encoding="utf-8"))
            self.assertEqual(s_doc["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertTrue("1.0.2c.6" in s_doc["title"] or "1.0.3" in s_doc["title"] or "1.0.4" in s_doc["title"] or "1.0.5" in s_doc["title"], sp.name)

        led_schema = json.loads(LEDGER_SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertIs(led_schema["additionalProperties"], False)
        self.assertIs(led_schema["properties"]["checkpoints"]["items"]["additionalProperties"], False)

        # 74/74 central audit log preserved + honest pending signoff status
        audit_data = json.loads(AUDIT_LOG_PATH.read_text(encoding="utf-8"))
        self.assertTrue(audit_data["schema_version"].startswith(("1.0.2c.6", "1.0.3", "1.0.4", "1.0.5")))
        self.assertEqual(audit_data["external_legal_counsel_signoff_status"], "PENDING_SIGNED_EXTERNAL_ATTESTATION")
        self.assertEqual(
            audit_data["holiday_calendar_audit"]["ledger_trust_anchor_status"],
            "CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR",
        )
        self.assertFalse(audit_data["holiday_calendar_audit"]["production_use_authorized"])
        self.assertEqual(audit_data["summary"]["total_audited_records"], 74)
        self.assertEqual(audit_data["summary"]["fully_verified_records_count"], 70)
        self.assertEqual(audit_data["summary"]["pending_verification_records_count"], 3)
        self.assertEqual(audit_data["summary"]["superseded_records_count"], 1)
        clean_rep = validate_central_audit_log(audit_data, self.sources, self.precedents, self.cards)
        self.assertTrue(clean_rep.valid, clean_rep.flags)

        prompt_text = (PROJECT_ROOT / "agent" / "system_prompt.md").read_text(encoding="utf-8")
        self.assertIn("v1.0.2c.6", prompt_text)
        self.assertIn("SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT", prompt_text)
        self.assertIn("CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR", prompt_text)


if __name__ == "__main__":
    unittest.main()

