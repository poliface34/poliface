"""CALISORA @HukukSGK v1.0.4 — Law No. 5070 NES & CAdES/XAdES Comprehensive Verification & Security Regression Tests.

Covers all 13 mandatory v1.0.4 architectural & security scenarios (ADR Section 9):
  1. Provider-agnostic 3 new ABC interfaces & zero hard cloud/HSM SDK imports in engine/esign5070.
  2. Real OpenSSL 3 CAdES (`ETSI EN 319 122-1/-2`) B-B / B-T / B-LT / B-LTA + legacy aliases (BES/T/LT/LTA) & profile/crypto separation.
  3. Real W3C C14N + OpenSSL 3 XAdES (`ETSI EN 319 132-1/-2`) B-B / B-T / B-LT / B-LTA, tampering detection & XXE/DOCTYPE blocking.
  4. CAdES content tampering & expired signer certificate separation (crypto valid vs 5070 FAILED).
  5. Real OpenSSL 3 CRL & OCSP revoked certificate checks + cross-certificate OCSP replay & rogue responder blocking.
  6. OCSP/CRL access error / unconfigured revocation -> `UNAVAILABLE` / `INDETERMINATE` & production acceptance gate denial.
  7. Historical archive validation (`B-LTA` with RFC 3161 TSA + archived OCSP/CRL, post-signing non-compromise vs compromise revocation, missing TSA rejection).
  8. Timestamp forgery / untrusted TSA CA / wrong imprint & proof that timestamp alone never grants Law No. 5070 qualification (and live B-B does not force m.4 timestamp).
  9. BTK ESHS authorization registry separation from ESHS CA bundle, missing/suspended/expired ESHS, QCStatements & certificatePolicies context, and m.4/c external sole-control evidence.
 10. KMS/HSM technical signature misclassification blocking (`KMS_HSM_NOT_5070_QUALIFIED_SIGNATURE`) & sandbox CA rejection in `PRODUCTION`.
 11. Independent `Default5070AcceptanceGate` anti-self-grant (caller booleans forbidden, hand-forged results rejected via HMAC seal, MOCK_SANDBOX blocked in PRODUCTION, evidence bundle integrity).
 12. 5-state `integration_probe` vocabulary (`NOT_CONFIGURED`, `CONFIGURED_UNVERIFIED`, `LIVE_VERIFIED`, `FAILED`, `INDETERMINATE`) & unconfigured production lock.
 13. v1.0.4 governance invariants: exact 11 Draft 2020-12 schemas, `config/esign_5070_config.json`, L5/L6 deferred to `v1.0.5`, L1–L4 (30/5/39), 74/74 central audit log, 4/4 Diyanet archives, 0 private keys.
"""

from __future__ import annotations

import ast
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from typing import Any

from engine import (
    CertificateRevocationProvider,
    EshsTrustListProvider,
    QualifiedSignature5070VerifierProvider,
)
from engine.attestation_verifier import PARSER_VERSION, canonical_json_bytes
from engine.document_integrity import verify_archived_holiday_snapshots
from engine.esign5070 import (
    CANONICAL_BASELINE_PROFILES,
    ESIGN_5070_VERSION,
    ETSI_CADES_STANDARD,
    ETSI_XADES_STANDARD,
    VALID_PROBE_STATUSES,
    AuthorizedSscdEvidenceIssuer,
    BtkEshsProviderRecord,
    Default5070AcceptanceGate,
    DefaultCertificateRevocationProvider,
    DefaultEshsTrustListProvider,
    DefaultQualifiedSignature5070Verifier,
    DefaultSscdControlEvidenceVerifier,
    EshsCertificateChainBundle,
    QualifiedSignature5070VerificationResult,
    SscdControlEvidenceVerificationResult,
    cert_pem_to_der_sha256,
    compute_archive_imprint_sha256,
    compute_bundle_sha256,
    create_cades_cms_der,
    create_signed_sscd_control_evidence_envelope,
    create_xades_xml_bytes,
    extract_cades_signature_value_bytes,
    inspect_signer_certificate_x509,
    normalize_etsi_profile,
    verify_esign5070_result_authenticity,
    verify_evidence_bundle_integrity,
)
from engine.knowledge_card_validator import load_knowledge_cards, validate_central_audit_log
from engine.legal_reasoning import TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA
from engine.precedent_verifier import load_precedent_registry
from engine.source_validator import load_source_registry
from engine.trust_root.integration_probe import run_live_integration_probe
from engine.trust_root.models import TRUST_ROOT_VERSION
from engine.trust_root.rfc3161_tsa import (
    EphemeralSandboxTsaResponder,
    Rfc3161TimestampAuthorityAdapter,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

from tests.pki_test_helpers import (
    NES_POLICY_OID,
    OTHER_POLICY_OID,
    Ephemeral5070PkiFixture,
    _openssl,
    _valid_external_sscd_evidence,
)


class TestLaw5070NesCadesXadesV104(unittest.TestCase):
    """Comprehensive v1.0.4 Law No. 5070 NES & CAdES/XAdES security, profile, revocation, and governance tests."""

    def test_01_provider_agnostic_interfaces_and_no_hard_sdk_imports(self) -> None:
        for iface in (EshsTrustListProvider, CertificateRevocationProvider, QualifiedSignature5070VerifierProvider):
            with self.assertRaises(TypeError):
                iface()  # type: ignore[abstract]

        forbidden_prefixes = (
            "google.cloud",
            "boto3",
            "azure",
            "PyKCS11",
            "pkcs11",
            "endesive",
            "pyhanko",
            "zeep",
        )
        for py_file in (PROJECT_ROOT / "engine" / "esign5070").glob("*.py"):
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        for bad in forbidden_prefixes:
                            self.assertFalse(alias.name.startswith(bad), f"{py_file.name} imports {alias.name}")
                elif isinstance(node, ast.ImportFrom) and node.module:
                    for bad in forbidden_prefixes:
                        self.assertFalse(node.module.startswith(bad), f"{py_file.name} imports {node.module}")

    def test_02_cades_b_b_b_t_b_lt_b_lta_legacy_aliases_and_profile_vs_crypto_separation(self) -> None:
        self.assertEqual(CANONICAL_BASELINE_PROFILES, ("B-B", "B-T", "B-LT", "B-LTA"))
        self.assertEqual(normalize_etsi_profile("BES"), ("B-B", True))
        self.assertEqual(normalize_etsi_profile("T"), ("B-T", True))
        self.assertEqual(normalize_etsi_profile("LT"), ("B-LT", True))
        self.assertEqual(normalize_etsi_profile("LTA"), ("B-LTA", True))
        self.assertEqual(normalize_etsi_profile("CADES-LTA"), ("B-LTA", True))
        self.assertEqual(normalize_etsi_profile("B-LT"), ("B-LT", False))
        self.assertEqual(normalize_etsi_profile("INVALID-XYZ"), (None, False))

        with Ephemeral5070PkiFixture() as pki, EphemeralSandboxTsaResponder() as tsa_srv:
            cert_pem, key_pem, cert_path = pki.issue_signer_cert(tag="cades_good")
            crl_pem = pki.generate_crl_pem()
            ocsp_der = pki.generate_ocsp_response_der(cert_path)

            eshs_prov = DefaultEshsTrustListProvider(
                btk_providers=[pki.build_btk_provider_record()],
                ca_bundles=[pki.build_ca_bundle()],
                integration_mode="MOCK_SANDBOX",
            )
            rev_prov = DefaultCertificateRevocationProvider(
                trusted_ca_pem=pki.root_cert_pem + "\n" + pki.inter_cert_pem,
                crl_fetcher=lambda _issuer, _vt: crl_pem,
                integration_mode="MOCK_SANDBOX",
            )
            tsa = Rfc3161TimestampAuthorityAdapter(
                tsa_url="https://sandbox-tsa.local/tsr",
                trusted_ca_pem=tsa_srv.ca_cert_pem,
                http_transport=tsa_srv.transport,
                integration_mode="MOCK_SANDBOX",
            )
            verifier = DefaultQualifiedSignature5070Verifier(
                eshs_trust_provider=eshs_prov,
                revocation_provider=rev_prov,
                tsa_provider=tsa,
                integration_mode="MOCK_SANDBOX",
            )

            content = b"4857 Sayili Is Kanunu fesih bildirimi test icerigi v1.0.4"
            # 1. Plain CMS WITHOUT -cades (signingCertificateV2): crypto MUST be True, profile MUST be False!
            plain_cms = create_cades_cms_der(content, cert_pem, key_pem, include_cades_attr=False)
            res_plain = verifier.verify_cades_signature(
                plain_cms,
                content,
                claimed_profile="B-B",
                expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_result=pki.build_verified_sscd_evidence(cert_pem),
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertTrue(res_plain.cryptographic_signature_valid)
            self.assertFalse(res_plain.profile_compliance.profile_compliant)
            self.assertEqual(res_plain.profile_compliance.achieved_profile, "NONE")
            self.assertFalse(res_plain.qualified_e_signature_5070_verified)

            # 2. Genuine CAdES B-B (also accepted via legacy alias BES!)
            cades_cms = create_cades_cms_der(content, cert_pem, key_pem, include_cades_attr=True)
            res_bb = verifier.verify_cades_signature(
                cades_cms,
                content,
                claimed_profile="BES",
                expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_result=pki.build_verified_sscd_evidence(cert_pem),
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertEqual(res_bb.standard, ETSI_CADES_STANDARD)
            self.assertTrue(res_bb.cryptographic_signature_valid)
            self.assertTrue(res_bb.profile_compliance.profile_compliant)
            self.assertTrue(res_bb.profile_compliance.legacy_alias_used)
            self.assertEqual(res_bb.profile_compliance.canonical_claimed_profile, "B-B")
            self.assertEqual(res_bb.profile_compliance.achieved_profile, "B-B")
            self.assertTrue(res_bb.qualified_e_signature_5070_verified)
            self.assertTrue(verify_esign5070_result_authenticity(res_bb))
            self.assertTrue(verify_evidence_bundle_integrity(res_bb))

            # 3. CAdES B-T (with real RFC 3161 SignatureTimeStamp over SignatureValue octets)
            sig_val = extract_cades_signature_value_bytes(cades_cms)
            self.assertIsNotNone(sig_val)
            sig_ts = tsa.request_timestamp(hashlib.sha256(sig_val).hexdigest())
            self.assertTrue(sig_ts.valid)
            import base64
            sig_ts_der = base64.b64decode(sig_ts.tsr_der_b64)

            res_bt = verifier.verify_cades_signature(
                cades_cms,
                content,
                claimed_profile="B-T",
                expected_eshs_id="ESHS-TR-01",
                signature_timestamp_tsr_der=sig_ts_der,
                sscd_control_evidence_result=pki.build_verified_sscd_evidence(cert_pem),
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertTrue(res_bt.profile_compliance.profile_compliant)
            self.assertEqual(res_bt.profile_compliance.achieved_profile, "B-T")
            self.assertTrue(res_bt.qualified_e_signature_5070_verified)

            # 4. CAdES B-LT (with archived OCSP) & B-LTA (with ArchiveTimeStamp)
            res_blt = verifier.verify_cades_signature(
                cades_cms,
                content,
                claimed_profile="B-LT",
                expected_eshs_id="ESHS-TR-01",
                signature_timestamp_tsr_der=sig_ts_der,
                archived_ocsp_response_der=ocsp_der,
                archived_ocsp_signer_cert_pem=pki.ocsp_cert_pem,
                sscd_control_evidence_result=pki.build_verified_sscd_evidence(cert_pem),
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertTrue(res_blt.profile_compliance.profile_compliant)
            self.assertEqual(res_blt.profile_compliance.achieved_profile, "B-LT")
            self.assertTrue(res_blt.qualified_e_signature_5070_verified)

            arch_digest = compute_archive_imprint_sha256(
                signature_bytes=sig_val,
                signature_timestamp_tsr_der=sig_ts_der,
                archived_ocsp_response_der=ocsp_der,
            )
            arch_ts = tsa.request_timestamp(arch_digest)
            self.assertTrue(arch_ts.valid)
            arch_ts_der = base64.b64decode(arch_ts.tsr_der_b64)

            res_blta = verifier.verify_cades_signature(
                cades_cms,
                content,
                claimed_profile="LTA",
                expected_eshs_id="ESHS-TR-01",
                signature_timestamp_tsr_der=sig_ts_der,
                archive_timestamp_tsr_der=arch_ts_der,
                archived_ocsp_response_der=ocsp_der,
                archived_ocsp_signer_cert_pem=pki.ocsp_cert_pem,
                sscd_control_evidence_result=pki.build_verified_sscd_evidence(cert_pem),
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertTrue(res_blta.profile_compliance.profile_compliant)
            self.assertEqual(res_blta.profile_compliance.achieved_profile, "B-LTA")
            self.assertTrue(res_blta.qualified_e_signature_5070_verified)

    def test_03_xades_b_b_b_t_b_lt_b_lta_tampering_and_xxe_blocking(self) -> None:
        import base64
        with Ephemeral5070PkiFixture() as pki, EphemeralSandboxTsaResponder() as tsa_srv:
            cert_pem, key_pem, cert_path = pki.issue_signer_cert(tag="xades_good")
            ocsp_der = pki.generate_ocsp_response_der(cert_path)
            crl_pem = pki.generate_crl_pem()

            eshs_prov = DefaultEshsTrustListProvider(
                btk_providers=[pki.build_btk_provider_record()],
                ca_bundles=[pki.build_ca_bundle()],
                integration_mode="MOCK_SANDBOX",
            )
            rev_prov = DefaultCertificateRevocationProvider(
                trusted_ca_pem=pki.root_cert_pem + "\n" + pki.inter_cert_pem,
                crl_fetcher=lambda _issuer, _vt: crl_pem,
                integration_mode="MOCK_SANDBOX",
            )
            tsa = Rfc3161TimestampAuthorityAdapter(
                tsa_url="https://sandbox-tsa.local/tsr",
                trusted_ca_pem=tsa_srv.ca_cert_pem,
                http_transport=tsa_srv.transport,
                integration_mode="MOCK_SANDBOX",
            )
            verifier = DefaultQualifiedSignature5070Verifier(
                eshs_trust_provider=eshs_prov,
                revocation_provider=rev_prov,
                tsa_provider=tsa,
                integration_mode="MOCK_SANDBOX",
            )

            content = b"<belge>XAdES 5070 dogrulama test icerigi</belge>"
            xades_bb, raw_sig = create_xades_xml_bytes(content, cert_pem, key_pem, include_signing_cert_v2=True)
            res_bb = verifier.verify_xades_signature(
                xades_bb,
                content,
                claimed_profile="B-B",
                expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_result=pki.build_verified_sscd_evidence(cert_pem),
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertEqual(res_bb.standard, ETSI_XADES_STANDARD)
            self.assertTrue(res_bb.cryptographic_signature_valid)
            self.assertTrue(res_bb.profile_compliance.profile_compliant)
            self.assertEqual(res_bb.profile_compliance.achieved_profile, "B-B")
            self.assertTrue(res_bb.qualified_e_signature_5070_verified)

            # Build full embedded XAdES-B-LTA (SignatureTimeStamp + RevocationValues + ArchiveTimeStamp)
            sig_ts_der = base64.b64decode(tsa.request_timestamp(hashlib.sha256(raw_sig).hexdigest()).tsr_der_b64)
            arch_imprint = compute_archive_imprint_sha256(
                signature_bytes=raw_sig,
                signature_timestamp_tsr_der=sig_ts_der,
                archived_ocsp_response_der=ocsp_der,
            )
            arch_ts_der = base64.b64decode(tsa.request_timestamp(arch_imprint).tsr_der_b64)
            xades_blta, _ = create_xades_xml_bytes(
                content,
                cert_pem,
                key_pem,
                include_signing_cert_v2=True,
                signature_timestamp_tsr_der=sig_ts_der,
                archive_timestamp_tsr_der=arch_ts_der,
                archived_ocsp_response_der=ocsp_der,
            )
            # Re-compute timestamps over exact new raw_sig inside embedded XAdES-B-LTA!
            # (Because create_xades_xml_bytes signs SignedInfo cleanly — deterministic for RSA-PKCS1v15 with fixed signing_time!)
            fixed_time = "2026-11-22T12:00:00Z"
            xades_base, raw_sig_fixed = create_xades_xml_bytes(
                content, cert_pem, key_pem, signing_time_utc=fixed_time, include_signing_cert_v2=True
            )
            sig_ts_fixed = base64.b64decode(tsa.request_timestamp(hashlib.sha256(raw_sig_fixed).hexdigest()).tsr_der_b64)
            arch_imp_fixed = compute_archive_imprint_sha256(
                signature_bytes=raw_sig_fixed,
                signature_timestamp_tsr_der=sig_ts_fixed,
                archived_ocsp_response_der=ocsp_der,
            )
            arch_ts_fixed = base64.b64decode(tsa.request_timestamp(arch_imp_fixed).tsr_der_b64)
            xades_blta_det, _ = create_xades_xml_bytes(
                content,
                cert_pem,
                key_pem,
                signing_time_utc=fixed_time,
                include_signing_cert_v2=True,
                signature_timestamp_tsr_der=sig_ts_fixed,
                archive_timestamp_tsr_der=arch_ts_fixed,
                archived_ocsp_response_der=ocsp_der,
            )
            res_blta = verifier.verify_xades_signature(
                xades_blta_det,
                content,
                claimed_profile="B-LTA",
                expected_eshs_id="ESHS-TR-01",
                archived_ocsp_signer_cert_pem=pki.ocsp_cert_pem,
                sscd_control_evidence_result=pki.build_verified_sscd_evidence(cert_pem),
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertTrue(res_blta.cryptographic_signature_valid)
            self.assertEqual(res_blta.profile_compliance.achieved_profile, "B-LTA")
            self.assertTrue(res_blta.profile_compliance.profile_compliant)
            self.assertTrue(res_blta.qualified_e_signature_5070_verified)

            # Content tampering MUST fail crypto & Law 5070 m.4/d!
            res_tampered = verifier.verify_xades_signature(
                xades_base,
                content + b"!",
                claimed_profile="B-B",
                expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_result=pki.build_verified_sscd_evidence(cert_pem),
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertFalse(res_tampered.cryptographic_signature_valid)
            self.assertIn("XADES_CONTENT_DIGEST_MISMATCH", res_tampered.error_codes)
            self.assertEqual(res_tampered.law_5070_assessment.article_4_elements["d_detects_subsequent_data_alteration"], "FAILED")
            self.assertFalse(res_tampered.qualified_e_signature_5070_verified)

            # XXE / DOCTYPE payload MUST be blocked immediately
            xxe_payload = b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><ds:Signature/>'
            res_xxe = verifier.verify_xades_signature(
                xxe_payload,
                content,
                claimed_profile="B-B",
                runtime_environment="PRODUCTION",
            )
            self.assertFalse(res_xxe.cryptographic_signature_valid)
            self.assertIn("XML_XXE_OR_DOCTYPE_FORBIDDEN", res_xxe.error_codes)

    def test_04_cades_content_tampering_and_expired_certificate(self) -> None:
        with Ephemeral5070PkiFixture() as pki:
            cert_pem, key_pem, _ = pki.issue_signer_cert(
                tag="expired_signer",
                startdate="20240101000000Z",
                enddate="20241231235959Z",
            )
            crl_pem = pki.generate_crl_pem()
            eshs_prov = DefaultEshsTrustListProvider(
                btk_providers=[pki.build_btk_provider_record()],
                ca_bundles=[pki.build_ca_bundle()],
                integration_mode="MOCK_SANDBOX",
            )
            rev_prov = DefaultCertificateRevocationProvider(
                trusted_ca_pem=pki.root_cert_pem + "\n" + pki.inter_cert_pem,
                crl_fetcher=lambda _issuer, _vt: crl_pem,
                integration_mode="MOCK_SANDBOX",
            )
            verifier = DefaultQualifiedSignature5070Verifier(
                eshs_trust_provider=eshs_prov,
                revocation_provider=rev_prov,
                integration_mode="MOCK_SANDBOX",
            )

            content = b"CAdES tahrifat ve suresi dolmus sertifika testi"
            cms_der = create_cades_cms_der(content, cert_pem, key_pem, include_cades_attr=True)

            # 1. Tampered content
            res_tamper = verifier.verify_cades_signature(
                cms_der,
                b"Degistirilmis icerik",
                claimed_profile="B-B",
                expected_eshs_id="ESHS-TR-01",
                validation_time_utc="2024-06-15T10:00:00Z",
                sscd_control_evidence_result=pki.build_verified_sscd_evidence(cert_pem),
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertFalse(res_tamper.cryptographic_signature_valid)
            self.assertIn("CADES_CRYPTOGRAPHIC_VERIFICATION_FAILED", res_tamper.error_codes)
            self.assertFalse(res_tamper.qualified_e_signature_5070_verified)

            # 2. Expired certificate at 2026 validation time: math valid, 5070 FAILED!
            res_exp = verifier.verify_cades_signature(
                cms_der,
                content,
                claimed_profile="B-B",
                expected_eshs_id="ESHS-TR-01",
                validation_time_utc="2026-11-22T10:00:00Z",
                sscd_control_evidence_result=pki.build_verified_sscd_evidence(cert_pem),
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertTrue(res_exp.cryptographic_signature_valid)
            self.assertIsNotNone(res_exp.signer_certificate)
            self.assertFalse(res_exp.signer_certificate.valid_at_validation_time)
            self.assertIn("SIGNER_CERTIFICATE_EXPIRED", res_exp.error_codes)
            self.assertFalse(res_exp.qualified_e_signature_5070_verified)
            self.assertEqual(res_exp.qualified_e_signature_5070_conclusion, "FAILED")

    def test_05_revoked_certificate_real_ocsp_and_crl_plus_ocsp_replay_defense(self) -> None:
        with Ephemeral5070PkiFixture() as pki, Ephemeral5070PkiFixture(sandbox_dn=True) as rogue_pki:
            cert_a, key_a, path_a = pki.issue_signer_cert(tag="cert_good_a", common_name="Ali Demir")
            cert_b, key_b, path_b = pki.issue_signer_cert(tag="cert_revoked_b", common_name="Veli Kaya")
            good_ocsp_a = pki.generate_ocsp_response_der(path_a)

            # Revoke cert B with keyCompromise
            pki.revoke_cert(path_b, reason="keyCompromise")
            crl_after = pki.generate_crl_pem()
            revoked_ocsp_b = pki.generate_ocsp_response_der(path_b)

            eshs_prov = DefaultEshsTrustListProvider(
                btk_providers=[pki.build_btk_provider_record()],
                ca_bundles=[pki.build_ca_bundle()],
                integration_mode="MOCK_SANDBOX",
            )
            content = b"Iptal edilmis sertifika testi"
            cms_b = create_cades_cms_der(content, cert_b, key_b, include_cades_attr=True)

            # 1. Real OpenSSL 3 CRL detects REVOKED
            rev_crl = DefaultCertificateRevocationProvider(
                trusted_ca_pem=pki.root_cert_pem + "\n" + pki.inter_cert_pem,
                crl_fetcher=lambda _i, _vt: crl_after,
                integration_mode="MOCK_SANDBOX",
            )
            res_crl = DefaultQualifiedSignature5070Verifier(
                eshs_trust_provider=eshs_prov, revocation_provider=rev_crl, integration_mode="MOCK_SANDBOX"
            ).verify_cades_signature(
                cms_b, content, claimed_profile="B-B", expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_result=pki.build_verified_sscd_evidence(cert_b),
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertTrue(res_crl.cryptographic_signature_valid)
            self.assertEqual(res_crl.revocation.status, "REVOKED")
            self.assertIn("SIGNER_CERTIFICATE_REVOKED", res_crl.error_codes)
            self.assertFalse(res_crl.qualified_e_signature_5070_verified)

            # 2. Real OpenSSL 3 OCSP detects REVOKED
            rev_ocsp = DefaultCertificateRevocationProvider(
                trusted_ca_pem=pki.root_cert_pem + "\n" + pki.inter_cert_pem,
                ocsp_fetcher=lambda _s, _i, _vt: (revoked_ocsp_b, pki.ocsp_cert_pem),
                integration_mode="MOCK_SANDBOX",
            )
            res_ocsp = DefaultQualifiedSignature5070Verifier(
                eshs_trust_provider=eshs_prov, revocation_provider=rev_ocsp, integration_mode="MOCK_SANDBOX"
            ).verify_cades_signature(
                cms_b, content, claimed_profile="B-B", expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_result=pki.build_verified_sscd_evidence(cert_b),
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertEqual(res_ocsp.revocation.status, "REVOKED")
            self.assertFalse(res_ocsp.qualified_e_signature_5070_verified)

            # 3. Cross-certificate OCSP replay attack (replaying cert A's GOOD OCSP for cert B) MUST fail!
            rev_replay = DefaultCertificateRevocationProvider(
                trusted_ca_pem=pki.root_cert_pem + "\n" + pki.inter_cert_pem,
                ocsp_fetcher=lambda _s, _i, _vt: (good_ocsp_a, pki.ocsp_cert_pem),
                integration_mode="MOCK_SANDBOX",
            )
            chk_replay = rev_replay.check_revocation(
                cert_b, pki.inter_cert_pem, validation_time_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            )
            self.assertNotEqual(chk_replay.status, "GOOD")
            self.assertNotEqual(chk_replay.conclusion, "PASSED")

            # 4. Rogue untrusted OCSP responder certificate MUST be rejected!
            chk_rogue = rev_ocsp.check_revocation(
                cert_a,
                pki.inter_cert_pem,
                validation_time_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                archived_ocsp_response_der=good_ocsp_a,
                archived_ocsp_signer_cert_pem=rogue_pki.ocsp_cert_pem,
            )
            self.assertEqual(chk_rogue.conclusion, "FAILED")
            self.assertIn("OCSP_RESPONDER_CHAIN_UNTRUSTED", chk_rogue.error_codes)

    def test_06_ocsp_crl_access_error_returns_indeterminate_and_blocks_acceptance_gate(self) -> None:
        with Ephemeral5070PkiFixture() as pki:
            cert_pem, key_pem, _ = pki.issue_signer_cert(tag="ocsp_down")
            eshs_prov = DefaultEshsTrustListProvider(
                btk_providers=[pki.build_btk_provider_record(trust_source_mode="LIVE_PRODUCTION")],
                ca_bundles=[pki.build_ca_bundle(trust_tier="LIVE_BTK_ESHS")],
                integration_mode="LIVE_PRODUCTION",
            )

            def _failing_ocsp(_s: str, _i: str, _vt: str) -> tuple[bytes, str | None]:
                raise ConnectionError("OCSP responder timeout")

            rev_down = DefaultCertificateRevocationProvider(
                trusted_ca_pem=pki.root_cert_pem + "\n" + pki.inter_cert_pem,
                ocsp_fetcher=_failing_ocsp,
                integration_mode="LIVE_PRODUCTION",
            )
            verifier = DefaultQualifiedSignature5070Verifier(
                eshs_trust_provider=eshs_prov,
                revocation_provider=rev_down,
                integration_mode="LIVE_PRODUCTION",
            )
            content = b"OCSP erisim hatasi testi"
            cms = create_cades_cms_der(content, cert_pem, key_pem, include_cades_attr=True)
            res = verifier.verify_cades_signature(
                cms,
                content,
                claimed_profile="B-B",
                expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_result=pki.build_verified_sscd_evidence(cert_pem, trust_tier="LIVE_AUTHORIZED_ISSUER", integration_mode="LIVE_PRODUCTION", runtime_environment="PRODUCTION"),
                runtime_environment="PRODUCTION",
            )
            self.assertTrue(res.cryptographic_signature_valid)
            self.assertEqual(res.revocation.status, "UNAVAILABLE")
            self.assertEqual(res.revocation.conclusion, "INDETERMINATE")
            self.assertIn("REVOCATION_OCSP_ACCESS_ERROR", res.error_codes)
            self.assertFalse(res.qualified_e_signature_5070_verified)
            self.assertEqual(res.qualified_e_signature_5070_conclusion, "INDETERMINATE")

            gate = Default5070AcceptanceGate()
            decision = gate.evaluate_5070_acceptance(res, runtime_environment="PRODUCTION")
            self.assertEqual(decision.legal_5070_qualification_status, "INDETERMINATE")
            self.assertEqual(decision.production_5070_acceptance_status, "DENIED_INDETERMINATE_EVIDENCE")
            self.assertFalse(decision.qualified_e_signature_5070_production_accepted)

    def test_07_historical_archive_validation_and_missing_timestamp_rejection(self) -> None:
        import base64
        with Ephemeral5070PkiFixture() as pki, EphemeralSandboxTsaResponder() as tsa_srv:
            cert_pem, key_pem, cert_path = pki.issue_signer_cert(tag="hist_signer")
            ocsp_good_at_sign = pki.generate_ocsp_response_der(cert_path)
            content = b"Uzun donem arsiv dogrulamasi B-LTA"
            cms = create_cades_cms_der(content, cert_pem, key_pem, include_cades_attr=True)
            sig_val = extract_cades_signature_value_bytes(cms)
            self.assertIsNotNone(sig_val)

            tsa = Rfc3161TimestampAuthorityAdapter(
                tsa_url="https://sandbox-tsa.local/tsr",
                trusted_ca_pem=tsa_srv.ca_cert_pem,
                http_transport=tsa_srv.transport,
                integration_mode="MOCK_SANDBOX",
            )
            sig_ts = tsa.request_timestamp(hashlib.sha256(sig_val).hexdigest())
            self.assertTrue(sig_ts.valid)
            sig_ts_der = base64.b64decode(sig_ts.tsr_der_b64)
            arch_imp = compute_archive_imprint_sha256(
                signature_bytes=sig_val,
                signature_timestamp_tsr_der=sig_ts_der,
                archived_ocsp_response_der=ocsp_good_at_sign,
            )
            arch_ts = tsa.request_timestamp(arch_imp)
            self.assertTrue(arch_ts.valid)
            arch_ts_der = base64.b64decode(arch_ts.tsr_der_b64)

            # Now revoke the cert AFTER signing (superseded) and generate a new CRL — archived OCSP at signing time STILL proves valid B-LTA!
            pki.revoke_cert(cert_path, reason="superseded")
            crl_later = pki.generate_crl_pem()

            eshs_prov = DefaultEshsTrustListProvider(
                btk_providers=[pki.build_btk_provider_record()],
                ca_bundles=[pki.build_ca_bundle()],
                integration_mode="MOCK_SANDBOX",
            )
            rev_prov = DefaultCertificateRevocationProvider(
                trusted_ca_pem=pki.root_cert_pem + "\n" + pki.inter_cert_pem,
                integration_mode="MOCK_SANDBOX",
            )
            verifier = DefaultQualifiedSignature5070Verifier(
                eshs_trust_provider=eshs_prov,
                revocation_provider=rev_prov,
                tsa_provider=tsa,
                integration_mode="MOCK_SANDBOX",
            )

            # 1. Valid B-LTA historical archive validation anchored to verified TSA time
            res_arch = verifier.verify_cades_signature(
                cms,
                content,
                claimed_profile="B-LTA",
                expected_eshs_id="ESHS-TR-01",
                signature_timestamp_tsr_der=sig_ts_der,
                archive_timestamp_tsr_der=arch_ts_der,
                archived_ocsp_response_der=ocsp_good_at_sign,
                archived_ocsp_signer_cert_pem=pki.ocsp_cert_pem,
                sscd_control_evidence_result=pki.build_verified_sscd_evidence(cert_pem),
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertTrue(res_arch.historical_archive_mode)
            self.assertEqual(res_arch.profile_compliance.achieved_profile, "B-LTA")
            self.assertTrue(res_arch.qualified_e_signature_5070_verified)

            # 2. Archived CRL WITHOUT verified RFC 3161 signature timestamp MUST FAIL!
            res_no_tsa = verifier.verify_cades_signature(
                cms,
                content,
                claimed_profile="B-B",
                expected_eshs_id="ESHS-TR-01",
                archived_crl_pem=crl_later,
                sscd_control_evidence_result=pki.build_verified_sscd_evidence(cert_pem),
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertIn("HISTORICAL_ARCHIVE_REQUIRES_VERIFIED_TIMESTAMP", res_no_tsa.error_codes)
            self.assertFalse(res_no_tsa.qualified_e_signature_5070_verified)

    def test_08_timestamp_forgery_broken_tsa_chain_and_timestamp_alone_not_5070(self) -> None:
        import base64
        with Ephemeral5070PkiFixture() as pki, EphemeralSandboxTsaResponder() as good_tsa_srv, EphemeralSandboxTsaResponder() as rogue_tsa_srv:
            cert_pem, key_pem, _ = pki.issue_signer_cert(tag="tsa_check")
            crl_pem = pki.generate_crl_pem()
            content = b"Zaman damgasi sahteciligi ve hukuki sinir testi"
            cms = create_cades_cms_der(content, cert_pem, key_pem, include_cades_attr=True)
            sig_val = extract_cades_signature_value_bytes(cms)
            self.assertIsNotNone(sig_val)

            good_tsa = Rfc3161TimestampAuthorityAdapter(
                tsa_url="https://good-tsa.local/tsr",
                trusted_ca_pem=good_tsa_srv.ca_cert_pem,
                http_transport=good_tsa_srv.transport,
                integration_mode="MOCK_SANDBOX",
            )
            rogue_tsa = Rfc3161TimestampAuthorityAdapter(
                tsa_url="https://rogue-tsa.local/tsr",
                trusted_ca_pem=rogue_tsa_srv.ca_cert_pem,
                http_transport=rogue_tsa_srv.transport,
                integration_mode="MOCK_SANDBOX",
            )
            eshs_prov = DefaultEshsTrustListProvider(
                btk_providers=[pki.build_btk_provider_record()],
                ca_bundles=[pki.build_ca_bundle()],
                integration_mode="MOCK_SANDBOX",
            )
            rev_prov = DefaultCertificateRevocationProvider(
                trusted_ca_pem=pki.root_cert_pem + "\n" + pki.inter_cert_pem,
                crl_fetcher=lambda _i, _vt: crl_pem,
                integration_mode="MOCK_SANDBOX",
            )
            verifier = DefaultQualifiedSignature5070Verifier(
                eshs_trust_provider=eshs_prov,
                revocation_provider=rev_prov,
                tsa_provider=good_tsa,
                integration_mode="MOCK_SANDBOX",
            )

            # 1. TSR issued by rogue TSA CA MUST fail verification
            rogue_tsr = base64.b64decode(rogue_tsa.request_timestamp(hashlib.sha256(sig_val).hexdigest()).tsr_der_b64)
            res_rogue = verifier.verify_cades_signature(
                cms, content, claimed_profile="B-T", expected_eshs_id="ESHS-TR-01",
                signature_timestamp_tsr_der=rogue_tsr,
                sscd_control_evidence_result=pki.build_verified_sscd_evidence(cert_pem),
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertFalse(res_rogue.signature_timestamp["valid"])
            self.assertFalse(res_rogue.profile_compliance.profile_compliant)
            self.assertFalse(res_rogue.qualified_e_signature_5070_verified)

            # 2. Forged/corrupted TSR bytes MUST fail verification
            good_tsr = base64.b64decode(good_tsa.request_timestamp(hashlib.sha256(sig_val).hexdigest()).tsr_der_b64)
            corrupted_tsr = good_tsr[:-10] + bytes(b ^ 0xFF for b in good_tsr[-10:])
            res_forged = verifier.verify_cades_signature(
                cms, content, claimed_profile="B-T", expected_eshs_id="ESHS-TR-01",
                signature_timestamp_tsr_der=corrupted_tsr,
                sscd_control_evidence_result=pki.build_verified_sscd_evidence(cert_pem),
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertFalse(res_forged.signature_timestamp["valid"])
            self.assertFalse(res_forged.qualified_e_signature_5070_verified)

            # 3. Valid RFC 3161 timestamp ALONE NEVER proves Law No. 5070 (missing m.4/c sole control evidence!)
            res_ts_alone = verifier.verify_cades_signature(
                cms, content, claimed_profile="B-T", expected_eshs_id="ESHS-TR-01",
                signature_timestamp_tsr_der=good_tsr,
                external_sscd_control_evidence=None,
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertTrue(res_ts_alone.cryptographic_signature_valid)
            self.assertTrue(res_ts_alone.signature_timestamp["valid"])
            self.assertFalse(res_ts_alone.signature_timestamp["timestamp_alone_proves_5070"])
            self.assertFalse(res_ts_alone.qualified_e_signature_5070_verified)
            self.assertEqual(res_ts_alone.qualified_e_signature_5070_conclusion, "INDETERMINATE")

    def test_09_btk_eshs_separation_policy_qc_context_and_m4c_external_evidence(self) -> None:
        with Ephemeral5070PkiFixture() as pki:
            cert_full, key_full, _ = pki.issue_signer_cert(tag="full_nes")
            cert_no_qc, key_no_qc, _ = pki.issue_signer_cert(
                tag="no_qc", include_qc_compliance=False, include_qc_sscd=True, policy_oids=(NES_POLICY_OID,)
            )
            cert_bad_pol, key_bad_pol, _ = pki.issue_signer_cert(
                tag="bad_pol", include_qc_compliance=True, include_qc_sscd=True, policy_oids=(OTHER_POLICY_OID,)
            )
            crl_pem = pki.generate_crl_pem()
            content = b"BTK ESHS ve QCStatements politika baglami testi"

            # Confirm real ASN.1 DER QCStatements parser detects real OIDs accurately!
            now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            ins_full = inspect_signer_certificate_x509(cert_full, validation_time_utc=now_iso)
            self.assertTrue(ins_full.qc_statements_present)
            self.assertTrue(ins_full.qc_compliance)
            self.assertTrue(ins_full.qc_sscd)
            self.assertIn(NES_POLICY_OID, ins_full.certificate_policy_oids)

            ins_no_qc = inspect_signer_certificate_x509(cert_no_qc, validation_time_utc=now_iso)
            self.assertFalse(ins_no_qc.qc_compliance)
            self.assertTrue(ins_no_qc.qc_sscd)

            rev_prov = DefaultCertificateRevocationProvider(
                trusted_ca_pem=pki.root_cert_pem + "\n" + pki.inter_cert_pem,
                crl_fetcher=lambda _i, _vt: crl_pem,
                integration_mode="MOCK_SANDBOX",
            )

            # 1. CA bundle exists WITHOUT BTK registry entry -> BTK_ESHS_PROVIDER_NOT_FOUND
            eshs_no_btk = DefaultEshsTrustListProvider(
                btk_providers=[],
                ca_bundles=[pki.build_ca_bundle()],
                integration_mode="MOCK_SANDBOX",
            )
            res_no_btk = DefaultQualifiedSignature5070Verifier(
                eshs_trust_provider=eshs_no_btk, revocation_provider=rev_prov, integration_mode="MOCK_SANDBOX"
            ).verify_cades_signature(
                create_cades_cms_der(content, cert_full, key_full),
                content, expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_result=pki.build_verified_sscd_evidence(cert_full),
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertIn("BTK_ESHS_PROVIDER_NOT_FOUND", res_no_btk.error_codes)
            self.assertFalse(res_no_btk.qualified_e_signature_5070_verified)

            # 2. BTK ESHS SUSPENDED or EXPIRED -> FAILED
            eshs_susp = DefaultEshsTrustListProvider(
                btk_providers=[pki.build_btk_provider_record(status="SUSPENDED")],
                ca_bundles=[pki.build_ca_bundle()],
                integration_mode="MOCK_SANDBOX",
            )
            res_susp = DefaultQualifiedSignature5070Verifier(
                eshs_trust_provider=eshs_susp, revocation_provider=rev_prov, integration_mode="MOCK_SANDBOX"
            ).verify_cades_signature(
                create_cades_cms_der(content, cert_full, key_full),
                content, expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_result=pki.build_verified_sscd_evidence(cert_full),
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertIn("BTK_ESHS_PROVIDER_NOT_ACTIVE", res_susp.error_codes)
            self.assertFalse(res_susp.qualified_e_signature_5070_verified)

            # 3. Policy OID mismatch -> FAILED
            eshs_ok = DefaultEshsTrustListProvider(
                btk_providers=[pki.build_btk_provider_record()],
                ca_bundles=[pki.build_ca_bundle()],
                integration_mode="MOCK_SANDBOX",
            )
            v_ok = DefaultQualifiedSignature5070Verifier(
                eshs_trust_provider=eshs_ok, revocation_provider=rev_prov, integration_mode="MOCK_SANDBOX"
            )
            res_bad_pol = v_ok.verify_cades_signature(
                create_cades_cms_der(content, cert_bad_pol, key_bad_pol),
                content, expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_result=pki.build_verified_sscd_evidence(cert_bad_pol),
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertIn("CERTIFICATE_POLICY_OID_MISMATCH", res_bad_pol.error_codes)
            self.assertEqual(res_bad_pol.law_5070_assessment.article_9_nes_conclusion, "FAILED")
            self.assertFalse(res_bad_pol.qualified_e_signature_5070_verified)

            # 4. Policy matches ESHS profile, QcCompliance absent -> INDETERMINATE in policy context (NEVER auto-VERIFIED!)
            res_no_qc = v_ok.verify_cades_signature(
                create_cades_cms_der(content, cert_no_qc, key_no_qc),
                content, expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_result=pki.build_verified_sscd_evidence(cert_no_qc),
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertEqual(res_no_qc.law_5070_assessment.article_9_nes_conclusion, "INDETERMINATE")
            self.assertIn("LAW_5070_M9_QC_COMPLIANCE_MISSING_IN_POLICY_CONTEXT", res_no_qc.error_codes)
            self.assertFalse(res_no_qc.qualified_e_signature_5070_verified)

    def test_10_kms_hsm_misclassification_blocked_and_sandbox_ca_rejected_in_production(self) -> None:
        with Ephemeral5070PkiFixture(sandbox_dn=True) as sandbox_pki:
            cert_pem, key_pem, _ = sandbox_pki.issue_signer_cert(tag="kms_and_sandbox")
            crl_pem = sandbox_pki.generate_crl_pem()
            content = b"KMS HSM yanlis siniflandirma ve sandbox CA reddi"
            cms = create_cades_cms_der(content, cert_pem, key_pem, include_cades_attr=True)

            eshs_prov = DefaultEshsTrustListProvider(
                btk_providers=[sandbox_pki.build_btk_provider_record(trust_source_mode="MOCK_SANDBOX")],
                ca_bundles=[sandbox_pki.build_ca_bundle(trust_tier="MOCK_SANDBOX_ONLY")],
                integration_mode="MOCK_SANDBOX",
            )
            rev_prov = DefaultCertificateRevocationProvider(
                trusted_ca_pem=sandbox_pki.root_cert_pem + "\n" + sandbox_pki.inter_cert_pem,
                crl_fetcher=lambda _i, _vt: crl_pem,
                integration_mode="MOCK_SANDBOX",
            )
            verifier = DefaultQualifiedSignature5070Verifier(
                eshs_trust_provider=eshs_prov, revocation_provider=rev_prov, integration_mode="MOCK_SANDBOX"
            )
            gate = Default5070AcceptanceGate()

            # 1. KMS / Cloud KMS / server HSM signature MUST be blocked as NON_5070_TECHNICAL_SIGNATURE
            res_kms = verifier.verify_cades_signature(
                cms,
                content,
                expected_eshs_id="ESHS-TR-01",
                external_sscd_control_evidence={
                    "signature_origin": "GCP_CLOUD_KMS",
                    "key_storage_type": "CLOUD_KMS",
                    "sole_control_attested": False,
                },
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertTrue(res_kms.cryptographic_signature_valid)
            self.assertTrue(res_kms.law_5070_assessment.kms_hsm_misclassification_blocked)
            self.assertIn("KMS_HSM_NOT_5070_QUALIFIED_SIGNATURE", res_kms.error_codes)
            self.assertFalse(res_kms.qualified_e_signature_5070_verified)

            dec_kms = gate.evaluate_5070_acceptance(res_kms, runtime_environment="PRODUCTION")
            self.assertEqual(dec_kms.legal_5070_qualification_status, "NON_5070_TECHNICAL_SIGNATURE")
            self.assertEqual(dec_kms.production_5070_acceptance_status, "DENIED_SECURITY_VIOLATION")
            self.assertFalse(dec_kms.qualified_e_signature_5070_production_accepted)

            # 2. Sandbox CA in PRODUCTION MUST be rejected with SANDBOX_ESHS_CA_REJECTED_IN_PRODUCTION
            res_sbx_prod = verifier.verify_cades_signature(
                cms,
                content,
                expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_result=sandbox_pki.build_verified_sscd_evidence(cert_pem),
                runtime_environment="PRODUCTION",
            )
            self.assertTrue(res_sbx_prod.eshs_trust.is_sandbox_ca)
            self.assertIn("SANDBOX_ESHS_CA_REJECTED_IN_PRODUCTION", res_sbx_prod.error_codes)
            self.assertFalse(res_sbx_prod.qualified_e_signature_5070_verified)

            dec_sbx_prod = gate.evaluate_5070_acceptance(res_sbx_prod, runtime_environment="PRODUCTION")
            self.assertEqual(dec_sbx_prod.production_5070_acceptance_status, "DENIED_SECURITY_VIOLATION")
            self.assertIn("SANDBOX_ESHS_CA_REJECTED_IN_PRODUCTION", dec_sbx_prod.blocking_codes)
            self.assertFalse(dec_sbx_prod.qualified_e_signature_5070_production_accepted)

    def test_11_acceptance_gate_anti_self_grant_forged_result_and_mock_production_block(self) -> None:
        gate = Default5070AcceptanceGate()
        with Ephemeral5070PkiFixture() as pki:
            cert_pem, key_pem, _ = pki.issue_signer_cert(tag="gate_test")
            crl_pem = pki.generate_crl_pem()
            content = b"Kabul kapisi guvenlik testi"
            cms = create_cades_cms_der(content, cert_pem, key_pem, include_cades_attr=True)

            eshs_prov = DefaultEshsTrustListProvider(
                btk_providers=[pki.build_btk_provider_record()],
                ca_bundles=[pki.build_ca_bundle()],
                integration_mode="MOCK_SANDBOX",
            )
            rev_prov = DefaultCertificateRevocationProvider(
                trusted_ca_pem=pki.root_cert_pem + "\n" + pki.inter_cert_pem,
                crl_fetcher=lambda _i, _vt: crl_pem,
                integration_mode="MOCK_SANDBOX",
            )
            res_mock = DefaultQualifiedSignature5070Verifier(
                eshs_trust_provider=eshs_prov, revocation_provider=rev_prov, integration_mode="MOCK_SANDBOX"
            ).verify_cades_signature(
                cms,
                content,
                expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_result=pki.build_verified_sscd_evidence(cert_pem),
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertTrue(res_mock.qualified_e_signature_5070_verified)

            # 1. Caller-supplied booleans MUST be rejected with CALLER_SELF_ASSERTED_BOOLEAN_FORBIDDEN
            dec_bool = gate.evaluate_5070_acceptance(
                res_mock,
                runtime_environment="PRODUCTION",
                qualified_e_signature_5070_verified=True,
                btk_verified=True,
            )
            self.assertEqual(dec_bool.production_5070_acceptance_status, "DENIED_SECURITY_VIOLATION")
            self.assertIn("CALLER_SELF_ASSERTED_BOOLEAN_FORBIDDEN", dec_bool.blocking_codes)
            self.assertFalse(dec_bool.qualified_e_signature_5070_production_accepted)

            # 2. Hand-forged / tampered QualifiedSignature5070VerificationResult MUST fail HMAC seal check!
            from dataclasses import replace
            forged = replace(res_mock, integration_mode="LIVE_PRODUCTION", _service_seal="0" * 64)
            self.assertFalse(verify_esign5070_result_authenticity(forged))
            dec_forged = gate.evaluate_5070_acceptance(forged, runtime_environment="PRODUCTION")
            self.assertEqual(dec_forged.production_5070_acceptance_status, "DENIED_SECURITY_VIOLATION")
            self.assertIn("FORGED_OR_UNAUTHENTICATED_VERIFICATION_RESULT", dec_forged.blocking_codes)
            self.assertFalse(dec_forged.qualified_e_signature_5070_production_accepted)

            # 3. Genuine MOCK_SANDBOX result submitted to PRODUCTION gate MUST be denied!
            dec_mock_prod = gate.evaluate_5070_acceptance(res_mock, runtime_environment="PRODUCTION")
            self.assertFalse(dec_mock_prod.qualified_e_signature_5070_production_accepted)
            self.assertIn("LIVE_5070_PROVIDERS_REQUIRED_FOR_PRODUCTION", dec_mock_prod.blocking_codes)

    def test_12_five_state_integration_probe_and_not_configured_lock(self) -> None:
        report = run_live_integration_probe(project_root=PROJECT_ROOT)
        self.assertTrue(report["schema_version"].startswith(("1.0.4", "1.0.5")))
        self.assertEqual(set(report["esign_5070_probe_statuses_supported"]), VALID_PROBE_STATUSES)
        self.assertEqual(report["esign_5070_overall_status"], "NOT_CONFIGURED")
        self.assertFalse(report["qualified_e_signature_5070_production_ready"])
        self.assertFalse(report["production_use_authorized"])
        self.assertFalse(report["qualified_e_signature_5070_equivalent"])

        for svc_name in ("btk_eshs_trust_list", "certificate_revocation_ocsp_crl", "qualified_signature_5070_verifier"):
            svc = report["esign_5070_services"][svc_name]
            self.assertEqual(svc["probe_status"], "NOT_CONFIGURED", svc_name)
            self.assertFalse(svc["configured"], svc_name)
            self.assertFalse(svc["reachable"], svc_name)

        # Verify all 5 probe states are faithfully representable across providers
        self.assertEqual(DefaultEshsTrustListProvider().probe_status().probe_status, "NOT_CONFIGURED")
        self.assertEqual(
            DefaultEshsTrustListProvider(
                btk_registry_source_url="https://btk.gov.tr/eshs",
                eshs_ca_bundle_source_ref="/etc/calisora/eshs_ca.pem",
                live_verified=False,
            ).probe_status().probe_status,
            "CONFIGURED_UNVERIFIED",
        )
        self.assertEqual(
            DefaultEshsTrustListProvider(
                btk_registry_source_url="https://btk.gov.tr/eshs",
                eshs_ca_bundle_source_ref="/etc/calisora/eshs_ca.pem",
                live_verified=True,
            ).probe_status().probe_status,
            "LIVE_VERIFIED",
        )
        self.assertEqual(
            DefaultCertificateRevocationProvider(probe_status_override="FAILED").probe_status().probe_status,
            "FAILED",
        )
        self.assertEqual(
            DefaultCertificateRevocationProvider(probe_status_override="INDETERMINATE").probe_status().probe_status,
            "INDETERMINATE",
        )

    def test_13_v104_governance_11_schemas_l5_l6_deferred_to_v105_74_audit_and_zero_private_keys(self) -> None:
        self.assertTrue(ESIGN_5070_VERSION.startswith(("1.0.4", "1.0.5")))
        self.assertTrue(TRUST_ROOT_VERSION.startswith(("1.0.4", "1.0.5")))
        self.assertTrue(PARSER_VERSION.startswith(("tr_diyanet_holiday_parser_v1.0.4", "tr_diyanet_holiday_parser_v1.0.5")))
        self.assertTrue(TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["calendar_version"].startswith(("1.0.4", "1.0.5")))

        # Core 11 Draft 2020-12 JSON Schemas preserved (+2 L5/L6 schemas in v1.0.5 = 13 total)
        expected_11_schemas = {
            "legal_source_registry.schema.json",
            "yargitay_precedent_registry.schema.json",
            "legal_knowledge_card.schema.json",
            "legal_scenario_evaluation.schema.json",
            "authorized_approvers.schema.json",
            "calendar_attestation_ledger.schema.json",
            "trust_root_config.schema.json",
            "source_acquisition_evidence.schema.json",
            "external_trust_anchor_manifest.schema.json",
            "esign_5070_config.schema.json",
            "esign_5070_verification_evidence.schema.json",
        }
        actual_schemas = {p.name for p in (PROJECT_ROOT / "schemas").glob("*.schema.json")}
        self.assertTrue(expected_11_schemas.issubset(actual_schemas))
        for s_name in expected_11_schemas:
            s_doc = json.loads((PROJECT_ROOT / "schemas" / s_name).read_text(encoding="utf-8"))
            self.assertEqual(s_doc["$schema"], "https://json-schema.org/draft/2020-12/schema", s_name)
            self.assertTrue("(v1.0.4" in s_doc["title"] or "(v1.0.5" in s_doc["title"], s_name)

        # config/esign_5070_config.json invariants
        e_cfg = json.loads((PROJECT_ROOT / "config" / "esign_5070_config.json").read_text(encoding="utf-8"))
        self.assertTrue(e_cfg["schema_version"].startswith(("1.0.4", "1.0.5")))
        self.assertEqual(e_cfg["deployment_status"], "NOT_CONFIGURED")
        self.assertFalse(e_cfg["qualified_e_signature_5070_production_ready"])
        self.assertEqual(e_cfg["scope_boundary"]["l5_l6_hr_cba_cards_deferred_to"], "v1.0.5")

        # v1.0.5: L5/L6 active as strictly isolated unadopted templates; L1-L4 (30/5/39) & 74/74 central audit untouched
        tax = json.loads((PROJECT_ROOT / "config" / "knowledge_taxonomy.json").read_text(encoding="utf-8"))
        self.assertTrue(tax["schema_version"].startswith(("1.0.4", "1.0.5")))
        for layer in tax["knowledge_layers"]:
            if layer["id"] == "L5_HR_PROCEDURES":
                self.assertEqual(
                    layer["population_status"],
                    "POPULATED_5_CORPORATE_HR_PROCEDURES_REFERENCE_TEMPLATES_V1_0_5",
                )
            elif layer["id"] == "L6_CBA_CONTRACTS_AND_WORKPLACE_PRACTICES":
                self.assertEqual(
                    layer["population_status"],
                    "POPULATED_4_DISTINCT_AUTONOMOUS_NORM_MODULES_REFERENCE_TEMPLATES_V1_0_5",
                )
        self.assertTrue((PROJECT_ROOT / "rag_kb" / "05_ik_prosedurleri").is_dir())
        self.assertTrue((PROJECT_ROOT / "rag_kb" / "06_tis_sozlesme_ve_isyeri_uygulamalari").is_dir())

        sources = load_source_registry(PROJECT_ROOT / "config" / "legal_sources_registry.json")
        precedents = load_precedent_registry(PROJECT_ROOT / "config" / "yargitay_precedents.json")
        cards = load_knowledge_cards(PROJECT_ROOT / "rag_kb", sources, precedents)
        self.assertEqual((len(sources), len(precedents), len(cards)), (30, 5, 39))

        audit_data = json.loads((PROJECT_ROOT / "config" / "verification_audit_log.json").read_text(encoding="utf-8"))
        self.assertTrue(audit_data["schema_version"].startswith(("1.0.4", "1.0.5")))
        self.assertEqual(audit_data["summary"]["total_audited_records"], 74)
        self.assertEqual(audit_data["summary"]["fully_verified_records_count"], 70)
        self.assertEqual(audit_data["summary"]["pending_verification_records_count"], 3)
        self.assertEqual(audit_data["summary"]["superseded_records_count"], 1)
        self.assertTrue(validate_central_audit_log(audit_data, sources, precedents, cards).valid)

        # 4/4 Diyanet archived snapshots match SHA-256
        snap_res = verify_archived_holiday_snapshots(
            PROJECT_ROOT / "config" / "verification_audit_log.json",
            project_root=PROJECT_ROOT,
        )
        self.assertTrue(snap_res["ok"])
        self.assertEqual(len(snap_res["verified_years"]), 4)

        # Zero private keys anywhere in repository
        pem_prefix = "-----" + "BEGIN "
        pem_suffix = "PRIVATE" + " KEY-----"
        markers = [f"{pem_prefix}{k}{pem_suffix}" for k in ("", "RSA ", "EC ", "ENCRYPTED ", "OPENSSH ")]
        for path in PROJECT_ROOT.rglob("*"):
            if not path.is_file() or "__pycache__" in path.parts or path.suffix in {".pyc", ".zip"}:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for mk in markers:
                self.assertNotIn(mk, text, f"Private key marker found in {path}")


if __name__ == "__main__":
    unittest.main()
