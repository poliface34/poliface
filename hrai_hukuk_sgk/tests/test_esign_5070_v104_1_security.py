"""CALISORA @HukukSGK v1.0.4.1 — Security Hardening Regression Suite (BLOCKER 1 & BLOCKER 2 Closure).

Directly tests every requirement from the v1.0.4.1 independent security review remediation mandate:
  - BLOCKER 1 (Verified SSCD/QSCD Sole-Control Evidence):
      * Plain caller Python dicts (`external_sscd_control_evidence={...}`) MUST be rejected (`CALLER_UNVERIFIED_SSCD_DICT_FORBIDDEN`).
      * Caller-constructed or tampered `SscdControlEvidenceVerificationResult` objects MUST be rejected (`FORGED_OR_UNAUTHENTICATED_SSCD_EVIDENCE_RESULT`).
      * Signed SSCD envelopes MUST be verified for issuer authority, role, X.509 chain, OCSP/CRL revocation,
        asymmetric signature, validity window, authorized scopes, signer-certificate SHA-256 binding, and sandbox isolation.
  - BLOCKER 2 (Standards-Compliant W3C XMLDSig/C14N & Anti-XSW XAdES Verification):
      * Declared `CanonicalizationMethod` (Inclusive 1.0, Exclusive 1.0 + PrefixList, C14N 1.1) honored and cross-validated against libxml2.
      * Declared `SignatureMethod` (RSA-SHA256/384/512, RSA-PSS-SHA256, ECDSA-SHA256 IEEE P1363) & `DigestMethod` (SHA-256/384/512) honored; SHA-1/HMAC/MD5/key-mismatch fail closed.
      * Standard `Reference` URI & `Transforms` pipeline (`enveloped-signature`, C14N, `base64`); XSLT/XPath/unknown transforms fail closed.
      * Full Anti-XSW & Duplicate-ID defense (duplicate `Id`/`ID`/`id`/`xml:id`, data ref hidden inside `<ds:Signature>`,
        unsigned sibling/wrapper content outside signed scope, external `SignedProperties`, multiple/nested signatures, Target mismatch).
      * Comparative CAdES (attached opaque + detached multi-cert chain) & XAdES (detached, enveloped, enveloping) standards vectors.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest

from engine.attestation_verifier import PARSER_VERSION
from engine.esign5070 import (
    C14N_EXCLUSIVE_10,
    C14N_EXCLUSIVE_10_COMMENTS,
    C14N_INCLUSIVE_10,
    C14N_INCLUSIVE_10_COMMENTS,
    C14N_INCLUSIVE_11,
    ESIGN_5070_VERSION,
    Default5070AcceptanceGate,
    DefaultCertificateRevocationProvider,
    DefaultEshsTrustListProvider,
    DefaultQualifiedSignature5070Verifier,
    SscdControlEvidenceVerificationResult,
    canonicalize_xml_node,
    cert_pem_to_der_sha256,
    create_cades_cms_der,
    create_signed_sscd_control_evidence_envelope,
    create_xades_xml_bytes,
    safe_parse_xml_bytes,
    verify_evidence_bundle_integrity,
    verify_sscd_evidence_result_authenticity,
    verify_xades_xmldsig,
)
from engine.knowledge_card_validator import load_knowledge_cards, validate_central_audit_log
from engine.legal_reasoning import TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA
from engine.precedent_verifier import load_precedent_registry
from engine.source_validator import load_source_registry
from engine.trust_root.integration_probe import run_live_integration_probe
from engine.trust_root.models import TRUST_ROOT_VERSION
from tests.pki_test_helpers import Ephemeral5070PkiFixture

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestLaw5070SecurityHardeningV1041(unittest.TestCase):
    """[SECURITY / BLOCKER-1 / BLOCKER-2] Comprehensive v1.0.4.1 security & standards verification tests."""

    def _build_sandbox_verifier(self, pki: Ephemeral5070PkiFixture, *, crl_pem: str | None = None) -> DefaultQualifiedSignature5070Verifier:
        eff_crl = crl_pem if crl_pem is not None else pki.generate_crl_pem()
        eshs = DefaultEshsTrustListProvider(
            btk_providers=[pki.build_btk_provider_record()],
            ca_bundles=[pki.build_ca_bundle()],
            integration_mode="MOCK_SANDBOX",
        )
        rev = DefaultCertificateRevocationProvider(
            trusted_ca_pem=pki.root_cert_pem + "\n" + pki.inter_cert_pem,
            crl_fetcher=lambda _i, _t: eff_crl,
            integration_mode="MOCK_SANDBOX",
        )
        sscd_ver = pki.build_sscd_evidence_verifier(crl_pem=eff_crl)
        return DefaultQualifiedSignature5070Verifier(
            eshs_trust_provider=eshs,
            revocation_provider=rev,
            sscd_evidence_verifier=sscd_ver,
            integration_mode="MOCK_SANDBOX",
        )

    def test_01_blocker1_plain_caller_dict_strictly_rejected_for_cades_and_xades(self) -> None:
        with Ephemeral5070PkiFixture() as pki:
            cert_pem, key_pem, _ = pki.issue_signer_cert(tag="plain_dict_target")
            verifier = self._build_sandbox_verifier(pki)
            gate = Default5070AcceptanceGate()
            content = b"Duz Python sozlugu ile 5070 m.4/c ve m.6 atlatma girisimi"

            raw_caller_dict = {
                "signature_origin": "QUALIFIED_SIGNER_DEVICE",
                "signing_device_type": "SMART_CARD_QSCD",
                "sole_control_attested": True,
                "pin_or_biometric_activation_verified": True,
                "sscd_device_certified": True,
                "sscd_certification_ref": "UNVERIFIED-CALLER-CLAIM",
            }

            cms = create_cades_cms_der(content, cert_pem, key_pem, include_cades_attr=True)
            res_cades = verifier.verify_cades_signature(
                cms,
                content,
                expected_eshs_id="ESHS-TR-01",
                external_sscd_control_evidence=raw_caller_dict,
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertTrue(res_cades.cryptographic_signature_valid)
            self.assertFalse(res_cades.qualified_e_signature_5070_verified)
            self.assertIn("CALLER_UNVERIFIED_SSCD_DICT_FORBIDDEN", res_cades.error_codes)
            self.assertEqual(res_cades.law_5070_assessment.article_4_elements["c_sole_control_of_signer"], "FAILED")
            self.assertEqual(res_cades.law_5070_assessment.article_6_sscd_conclusion, "FAILED")

            dec_cades = gate.evaluate_5070_acceptance(res_cades, runtime_environment="PRODUCTION")
            self.assertEqual(dec_cades.production_5070_acceptance_status, "DENIED_SECURITY_VIOLATION")
            self.assertIn("CALLER_UNVERIFIED_SSCD_DICT_FORBIDDEN", dec_cades.blocking_codes)
            self.assertFalse(dec_cades.qualified_e_signature_5070_production_accepted)

            xxml, _ = create_xades_xml_bytes(content, cert_pem, key_pem)
            res_xades = verifier.verify_xades_signature(
                xxml,
                content,
                expected_eshs_id="ESHS-TR-01",
                external_sscd_control_evidence=raw_caller_dict,
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertTrue(res_xades.cryptographic_signature_valid)
            self.assertFalse(res_xades.qualified_e_signature_5070_verified)
            self.assertIn("CALLER_UNVERIFIED_SSCD_DICT_FORBIDDEN", res_xades.error_codes)

    def test_02_blocker1_caller_forged_or_tampered_sscd_result_object_rejected(self) -> None:
        with Ephemeral5070PkiFixture() as pki:
            cert_pem, key_pem, _ = pki.issue_signer_cert(tag="forged_sscd_target")
            signer_sha = cert_pem_to_der_sha256(cert_pem)
            verifier = self._build_sandbox_verifier(pki)
            gate = Default5070AcceptanceGate()
            content = b"Elle uretilmis SscdControlEvidenceVerificationResult reddi"
            cms = create_cades_cms_der(content, cert_pem, key_pem, include_cades_attr=True)

            # 1. Hand-crafted unsealed SscdControlEvidenceVerificationResult
            hand_crafted = SscdControlEvidenceVerificationResult(
                valid=True,
                conclusion="VERIFIED",
                evidence_id="FORGED-EV-1",
                issuer_id="TSE-QSCD-CAB-01",
                issuer_name="Fake",
                issuer_role="QSCD_CONFORMITY_ASSESSMENT_BODY",
                issuer_authorized=True,
                issuer_cert_chain_verified=True,
                issuer_cert_serial_number="1001",
                issuer_cert_sha256="a" * 64,
                issuer_revocation_status="GOOD",
                signature_verified=True,
                signature_algorithm="RSA-SHA256",
                scope_verified=True,
                authorized_scopes=("LAW_5070_M4C_SOLE_CONTROL", "LAW_5070_M6_SSCD_CERTIFICATION"),
                valid_from_utc="2020-01-01T00:00:00Z",
                valid_until_utc="2035-12-31T23:59:59Z",
                within_validity_window=True,
                bound_signer_cert_sha256=signer_sha,
                signature_origin="QUALIFIED_SIGNER_DEVICE",
                signing_device_type="SMART_CARD_QSCD",
                sole_control_attested=True,
                pin_or_biometric_activation_verified=True,
                sscd_device_certified=True,
                sscd_certification_ref="FORGED-REF",
                is_sandbox_issuer=False,
                envelope_sha256="b" * 64,
                verifier_service_id="FORGED",
                integration_mode="LIVE_PRODUCTION",
                _service_seal="f" * 64,
            )
            self.assertFalse(verify_sscd_evidence_result_authenticity(hand_crafted))

            res_forged = verifier.verify_cades_signature(
                cms,
                content,
                expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_result=hand_crafted,
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertFalse(res_forged.qualified_e_signature_5070_verified)
            self.assertIn("FORGED_OR_UNAUTHENTICATED_SSCD_EVIDENCE_RESULT", res_forged.error_codes)
            dec_f = gate.evaluate_5070_acceptance(res_forged, runtime_environment="PRODUCTION")
            self.assertEqual(dec_f.production_5070_acceptance_status, "DENIED_SECURITY_VIOLATION")

            # 2. Mutating an authentic sealed result invalidates its HMAC seal immediately
            authentic = pki.build_verified_sscd_evidence(cert_pem)
            self.assertTrue(verify_sscd_evidence_result_authenticity(authentic))
            tampered = replace(authentic, is_sandbox_issuer=False, integration_mode="LIVE_PRODUCTION")
            self.assertFalse(verify_sscd_evidence_result_authenticity(tampered))
            res_tamp = verifier.verify_cades_signature(
                cms,
                content,
                expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_result=tampered,
                runtime_environment="PRODUCTION",
            )
            self.assertIn("FORGED_OR_UNAUTHENTICATED_SSCD_EVIDENCE_RESULT", res_tamp.error_codes)
            self.assertFalse(res_tamp.qualified_e_signature_5070_verified)

    def test_03_blocker1_sscd_envelope_all_cryptographic_and_authority_failure_modes(self) -> None:
        with Ephemeral5070PkiFixture() as pki, Ephemeral5070PkiFixture(sandbox_dn=True) as rogue_pki:
            cert_a, key_a, _ = pki.issue_signer_cert(tag="signer_a", common_name="Signer A")
            cert_b, key_b, _ = pki.issue_signer_cert(tag="signer_b", common_name="Signer B")
            iss_cert, iss_key, iss_path = pki.ensure_sscd_issuer_cert()
            rogue_cert, rogue_key, _ = rogue_pki.issue_signer_cert(tag="rogue_iss", common_name="Rogue CAB")

            sha_a = cert_pem_to_der_sha256(cert_a)
            now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            content = b"SSCD zarf dogrulama negatif senaryolari"
            cms_a = create_cades_cms_der(content, cert_a, key_a, include_cades_attr=True)
            cms_b = create_cades_cms_der(content, cert_b, key_b, include_cades_attr=True)

            # 1. Valid direct RSA-PSS-SHA256 envelope passes in TEST_SANDBOX_ONLY & populates evidence bundle!
            valid_env = create_signed_sscd_control_evidence_envelope(
                evidence_id="SSCD-PSS-001",
                issuer_id="TSE-QSCD-CAB-01",
                issuer_cert_pem=iss_cert,
                issuer_key_pem=iss_key,
                bound_signer_cert_sha256=sha_a,
                issued_at_utc=now_iso,
                valid_from_utc="2020-01-01T00:00:00Z",
                valid_until_utc="2035-12-31T23:59:59Z",
                signature_algorithm="RSA-PSS-SHA256",
            )
            verifier = self._build_sandbox_verifier(pki)
            res_ok = verifier.verify_cades_signature(
                cms_a,
                content,
                expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_envelope=valid_env,
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertTrue(res_ok.qualified_e_signature_5070_verified)
            self.assertIsNotNone(res_ok.sscd_control_evidence)
            self.assertTrue(res_ok.sscd_control_evidence.signature_verified)
            self.assertTrue(any(it.evidence_type == "SSCD_CONTROL_EVIDENCE" for it in res_ok.evidence_bundle.items))
            self.assertTrue(verify_evidence_bundle_integrity(res_ok))

            # 2. Tampered payload breaks cryptographic signature!
            tampered_env = json.loads(json.dumps(valid_env))
            tampered_env["payload"]["sscd_certification_ref"] = "TAMPERED-REF"
            res_bad_sig = verifier.verify_cades_signature(
                cms_a, content, expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_envelope=tampered_env, runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertIn("SSCD_EVIDENCE_SIGNATURE_INVALID", res_bad_sig.error_codes)
            self.assertFalse(res_bad_sig.qualified_e_signature_5070_verified)

            # 3. Expired SSCD evidence window -> REJECTED!
            exp_env = create_signed_sscd_control_evidence_envelope(
                evidence_id="SSCD-EXP-001",
                issuer_id="TSE-QSCD-CAB-01",
                issuer_cert_pem=iss_cert,
                issuer_key_pem=iss_key,
                bound_signer_cert_sha256=sha_a,
                issued_at_utc="2024-01-01T00:00:00Z",
                valid_from_utc="2024-01-01T00:00:00Z",
                valid_until_utc="2024-12-31T23:59:59Z",
            )
            res_exp = verifier.verify_cades_signature(
                cms_a, content, expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_envelope=exp_env, runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertIn("SSCD_EVIDENCE_EXPIRED_OR_NOT_YET_VALID", res_exp.error_codes)
            self.assertFalse(res_exp.qualified_e_signature_5070_verified)

            # 4. Unauthorized / unknown issuer -> REJECTED!
            unauth_env = create_signed_sscd_control_evidence_envelope(
                evidence_id="SSCD-UNAUTH-001",
                issuer_id="UNKNOWN-ROGUE-CAB",
                issuer_cert_pem=rogue_cert,
                issuer_key_pem=rogue_key,
                bound_signer_cert_sha256=sha_a,
                issued_at_utc=now_iso,
                valid_from_utc="2020-01-01T00:00:00Z",
                valid_until_utc="2035-12-31T23:59:59Z",
            )
            res_unauth = verifier.verify_cades_signature(
                cms_a, content, expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_envelope=unauth_env, runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertIn("SSCD_ISSUER_NOT_AUTHORIZED", res_unauth.error_codes)
            self.assertFalse(res_unauth.qualified_e_signature_5070_verified)

            # 5. Registered issuer ID signed with rogue CA cert -> CA chain verification FAILS!
            rogue_chain_env = create_signed_sscd_control_evidence_envelope(
                evidence_id="SSCD-ROGUECHAIN-001",
                issuer_id="TSE-QSCD-CAB-01",
                issuer_cert_pem=rogue_cert,
                issuer_key_pem=rogue_key,
                bound_signer_cert_sha256=sha_a,
                issued_at_utc=now_iso,
                valid_from_utc="2020-01-01T00:00:00Z",
                valid_until_utc="2035-12-31T23:59:59Z",
            )
            res_rchain = verifier.verify_cades_signature(
                cms_a, content, expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_envelope=rogue_chain_env, runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertIn("SSCD_ISSUER_CHAIN_VERIFICATION_FAILED", res_rchain.error_codes)
            self.assertFalse(res_rchain.qualified_e_signature_5070_verified)

            # 6. Missing / unauthorized scope -> REJECTED!
            narrow_env = create_signed_sscd_control_evidence_envelope(
                evidence_id="SSCD-SCOPE-001",
                issuer_id="TSE-QSCD-CAB-01",
                issuer_cert_pem=iss_cert,
                issuer_key_pem=iss_key,
                bound_signer_cert_sha256=sha_a,
                authorized_scopes=("LAW_5070_M4C_SOLE_CONTROL",),  # missing M6!
                issued_at_utc=now_iso,
                valid_from_utc="2020-01-01T00:00:00Z",
                valid_until_utc="2035-12-31T23:59:59Z",
            )
            res_scope = verifier.verify_cades_signature(
                cms_a, content, expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_envelope=narrow_env, runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertIn("SSCD_EVIDENCE_REQUIRED_5070_SCOPES_MISSING", res_scope.error_codes)
            self.assertFalse(res_scope.qualified_e_signature_5070_verified)

            # 7. Cross-signer certificate replay (User A's valid SSCD result used on User B's signature!) -> REJECTED!
            sscd_for_a = pki.build_verified_sscd_evidence(cert_a)
            res_replay = verifier.verify_cades_signature(
                cms_b, content, expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_result=sscd_for_a, runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertIn("SSCD_EVIDENCE_SIGNER_CERT_BINDING_MISMATCH", res_replay.error_codes)
            self.assertFalse(res_replay.qualified_e_signature_5070_verified)

            # 8. Sandbox SSCD issuer in PRODUCTION -> REJECTED!
            res_sbx_prod = verifier.verify_cades_signature(
                cms_a, content, expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_envelope=valid_env, runtime_environment="PRODUCTION",
            )
            self.assertIn("SANDBOX_SSCD_ISSUER_REJECTED_IN_PRODUCTION", res_sbx_prod.error_codes)
            self.assertFalse(res_sbx_prod.qualified_e_signature_5070_verified)

            # 9. Revoked SSCD issuer X.509 certificate (real OpenSSL CRL!) -> REJECTED!
            pki.revoke_cert(iss_path, reason="keyCompromise")
            crl_after_rev = pki.generate_crl_pem()
            verifier_after_rev = self._build_sandbox_verifier(pki, crl_pem=crl_after_rev)
            res_rev_iss = verifier_after_rev.verify_cades_signature(
                cms_a, content, expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_envelope=valid_env, runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertIn("SSCD_ISSUER_CERT_REVOKED", res_rev_iss.error_codes)
            self.assertFalse(res_rev_iss.qualified_e_signature_5070_verified)

    def test_04_blocker2_canonicalization_methods_honored_and_libxml2_cross_checked(self) -> None:
        # 1. Cross-validate Inclusive 1.0, Exclusive 1.0, #WithComments & PrefixList against libxml2 (if installed)
        sample = (
            b'<root xmlns="urn:def" xmlns:a="urn:a" xmlns:b="urn:b">'
            b'<a:wrap xmlns:c="urn:c"><node Id="n1" b:k="2" z="9" a="1"><!-- keep -->text &amp; more<empty/></node></a:wrap>'
            b"</root>"
        )
        dom = safe_parse_xml_bytes(sample)
        node_dom = dom.getElementsByTagName("node")[0]
        inc_bytes = canonicalize_xml_node(node_dom, C14N_INCLUSIVE_10)
        exc_bytes = canonicalize_xml_node(node_dom, C14N_EXCLUSIVE_10)
        self.assertNotEqual(inc_bytes, exc_bytes)
        self.assertIn(b'xmlns:a="urn:a"', inc_bytes)
        self.assertNotIn(b'xmlns:a="urn:a"', exc_bytes)

        try:
            from lxml import etree as LET
            lx = LET.fromstring(sample).xpath(".//*[local-name()='node']")[0]
            self.assertEqual(inc_bytes, LET.tostring(lx, method="c14n", exclusive=False, with_comments=False))
            self.assertEqual(
                canonicalize_xml_node(node_dom, C14N_INCLUSIVE_10_COMMENTS),
                LET.tostring(lx, method="c14n", exclusive=False, with_comments=True),
            )
            self.assertEqual(exc_bytes, LET.tostring(lx, method="c14n", exclusive=True, with_comments=False))
            self.assertEqual(
                canonicalize_xml_node(node_dom, C14N_EXCLUSIVE_10_COMMENTS),
                LET.tostring(lx, method="c14n", exclusive=True, with_comments=True),
            )
            self.assertEqual(
                canonicalize_xml_node(node_dom, C14N_EXCLUSIVE_10, inclusive_prefixes={"a", "c"}),
                LET.tostring(lx, method="c14n", exclusive=True, with_comments=False, inclusive_ns_prefixes=["a", "c"]),
            )
        except ImportError:
            pass

        # 2. Real XAdES signatures under Inclusive 1.0, Exclusive 1.0, and C14N 1.1 ALL verify cleanly,
        #    and swapping C14N URI on an enveloped signature with extra ancestor namespaces BREAKS verification!
        with Ephemeral5070PkiFixture() as pki:
            cert_pem, key_pem, _ = pki.issue_signer_cert(tag="c14n_xades")
            doc_xml = b'<Belge xmlns="urn:calisora:belge" xmlns:ek="urn:ek" Id="Doc-Root"><Metin>Onay</Metin></Belge>'
            for c14n_uri in (C14N_INCLUSIVE_10, C14N_EXCLUSIVE_10, C14N_INCLUSIVE_11):
                signed_xml, _ = create_xades_xml_bytes(
                    doc_xml, cert_pem, key_pem, mode="ENVELOPED", canonicalization_method=c14n_uri
                )
                insp = verify_xades_xmldsig(signed_xml)
                self.assertTrue(insp.crypto_valid, (c14n_uri, insp.error_codes, insp.errors))
                self.assertEqual(insp.xmldsig_details["canonicalization_method"], c14n_uri)

            # Swapping CanonicalizationMethod from Inclusive -> Exclusive MUST fail SignatureValue!
            inc_signed, _ = create_xades_xml_bytes(
                doc_xml, cert_pem, key_pem, mode="ENVELOPED", canonicalization_method=C14N_INCLUSIVE_10
            )
            swapped = inc_signed.replace(C14N_INCLUSIVE_10.encode(), C14N_EXCLUSIVE_10.encode(), 1)
            insp_swap = verify_xades_xmldsig(swapped)
            self.assertFalse(insp_swap.crypto_valid)
            self.assertIn("XADES_SIGNATURE_VALUE_INVALID", insp_swap.error_codes)

            # Unknown CanonicalizationMethod MUST fail closed!
            bad_c14n = inc_signed.replace(C14N_INCLUSIVE_10.encode(), b"http://evil.invalid/custom-c14n", 1)
            insp_bad = verify_xades_xmldsig(bad_c14n)
            self.assertFalse(insp_bad.crypto_valid)
            self.assertIn("XADES_UNSUPPORTED_CANONICALIZATION_METHOD", insp_bad.error_codes)

    def test_05_blocker2_signature_methods_rsa_384_512_pss_ecdsa_and_weak_rejection(self) -> None:
        with Ephemeral5070PkiFixture() as pki:
            rsa_cert, rsa_key, _ = pki.issue_signer_cert(tag="alg_rsa")
            ec_cert, ec_key, _ = pki.issue_ec_signer_cert(tag="alg_ec", curve="prime256v1")
            payload = b"Algoritma cesitliligi testi (RSA-SHA384/512, RSA-PSS, ECDSA-P256)"

            rsa_cases = [
                ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "http://www.w3.org/2001/04/xmlenc#sha256"),
                ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "http://www.w3.org/2001/04/xmldsig-more#sha384"),
                ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "http://www.w3.org/2001/04/xmlenc#sha512"),
                ("http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1", "http://www.w3.org/2001/04/xmlenc#sha256"),
            ]
            for sig_alg, dig_alg in rsa_cases:
                xxml, _ = create_xades_xml_bytes(
                    payload, rsa_cert, rsa_key, signature_method=sig_alg, digest_method=dig_alg
                )
                insp = verify_xades_xmldsig(xxml, payload)
                self.assertTrue(insp.crypto_valid, (sig_alg, insp.error_codes, insp.errors))
                self.assertTrue(insp.has_signing_cert_ref)
                self.assertEqual(insp.xmldsig_details["signature_method"], sig_alg)

            # Genuine W3C XMLDSig 1.1 IEEE P1363 ECDSA-SHA256 (P-256)
            ec_xml, ec_raw_sig = create_xades_xml_bytes(
                payload,
                ec_cert,
                ec_key,
                signature_method="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
                digest_method="http://www.w3.org/2001/04/xmlenc#sha256",
            )
            self.assertEqual(len(ec_raw_sig), 64)  # W3C XMLDSig P1363 P-256 = 32B r || 32B s
            insp_ec = verify_xades_xmldsig(ec_xml, payload)
            self.assertTrue(insp_ec.crypto_valid, (insp_ec.error_codes, insp_ec.errors))
            self.assertTrue(insp_ec.has_signing_cert_ref)

            # Weak / symmetric algorithms MUST fail closed!
            base_xml, _ = create_xades_xml_bytes(payload, rsa_cert, rsa_key)
            for weak_sig in (
                b"http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                b"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
                b"http://unknown.invalid/alg",
            ):
                mutated = base_xml.replace(b"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", weak_sig)
                insp_w = verify_xades_xmldsig(mutated, payload)
                self.assertFalse(insp_w.crypto_valid)
                self.assertIn("XADES_UNSUPPORTED_OR_WEAK_SIGNATURE_METHOD", insp_w.error_codes)

            # Key-type mismatch (declaring ecdsa-sha256 on RSA signer cert) MUST fail closed!
            mismatch = base_xml.replace(
                b"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                b"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
            )
            insp_mm = verify_xades_xmldsig(mismatch, payload)
            self.assertFalse(insp_mm.crypto_valid)
            self.assertIn("XADES_SIGNATURE_METHOD_KEY_MISMATCH", insp_mm.error_codes)

            # Weak SHA-1 DigestMethod MUST fail closed!
            weak_dig = base_xml.replace(
                b"http://www.w3.org/2001/04/xmlenc#sha256",
                b"http://www.w3.org/2000/09/xmldsig#sha1",
                1,
            )
            insp_wd = verify_xades_xmldsig(weak_dig, payload)
            self.assertFalse(insp_wd.crypto_valid)
            self.assertIn("XADES_UNSUPPORTED_OR_WEAK_DIGEST_METHOD", insp_wd.error_codes)

    def test_06_blocker2_enveloped_enveloping_transforms_and_forbidden_xslt_xpath_transforms(self) -> None:
        with Ephemeral5070PkiFixture() as pki:
            cert_pem, key_pem, _ = pki.issue_signer_cert(tag="xform_test")
            doc_xml = b'<FesihBildirimi Id="F-1"><Isci>Ayse Yilmaz</Isci><Tarih>2026-11-22</Tarih></FesihBildirimi>'

            # 1. Enveloped XAdES (URI="" + enveloped-signature + exc-c14n#)
            env_xml, _ = create_xades_xml_bytes(
                doc_xml, cert_pem, key_pem, mode="ENVELOPED", canonicalization_method=C14N_EXCLUSIVE_10
            )
            insp_env = verify_xades_xmldsig(env_xml)
            self.assertTrue(insp_env.crypto_valid, (insp_env.error_codes, insp_env.errors))
            self.assertEqual(insp_env.xmldsig_details["signature_mode"], "ENVELOPED")

            # Tampering enveloped business body fails immediately
            tampered_env = env_xml.replace(b"Ayse Yilmaz", b"Sahte Kisi")
            insp_tamp = verify_xades_xmldsig(tampered_env)
            self.assertFalse(insp_tamp.crypto_valid)
            self.assertIn("XADES_CONTENT_DIGEST_MISMATCH", insp_tamp.error_codes)

            # 2. Enveloping XAdES (URI="#Obj-Data-1")
            enveloping_xml, _ = create_xades_xml_bytes(
                b"Enveloping test payload", cert_pem, key_pem, mode="ENVELOPING"
            )
            insp_enveloping = verify_xades_xmldsig(enveloping_xml)
            self.assertTrue(insp_enveloping.crypto_valid, (insp_enveloping.error_codes, insp_enveloping.errors))
            self.assertEqual(insp_enveloping.xmldsig_details["signature_mode"], "ENVELOPING")

            # 3. Forbidden XSLT & XPath transforms MUST fail closed!
            for bad_xform in (
                b"http://www.w3.org/TR/1999/REC-xslt-19991116",
                b"http://www.w3.org/TR/1999/REC-xpath-19991116",
                b"http://www.w3.org/2002/06/xmldsig-filter2",
                b"http://unknown.invalid/transform",
            ):
                injected = env_xml.replace(
                    b'<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform>',
                    b'<ds:Transform Algorithm="' + bad_xform + b'"></ds:Transform>',
                    1,
                )
                insp_bad = verify_xades_xmldsig(injected)
                self.assertFalse(insp_bad.crypto_valid)
                self.assertIn("XADES_UNSUPPORTED_OR_FORBIDDEN_TRANSFORM", insp_bad.error_codes)

    def test_07_blocker2_anti_xsw_wrapping_attacks_and_duplicate_xml_id_rejection(self) -> None:
        with Ephemeral5070PkiFixture() as pki:
            cert_pem, key_pem, _ = pki.issue_signer_cert(tag="xsw_target")
            verifier = self._build_sandbox_verifier(pki)
            gate = Default5070AcceptanceGate()
            sscd_ok = pki.build_verified_sscd_evidence(cert_pem)

            doc_xml = b'<Belge Id="Doc-1"><Icerik>Gercek Icerik</Icerik></Belge>'
            valid_env, _ = create_xades_xml_bytes(doc_xml, cert_pem, key_pem, mode="ENVELOPED")
            res_ok = verifier.verify_xades_signature(
                valid_env,
                expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_result=sscd_ok,
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertTrue(res_ok.cryptographic_signature_valid)
            self.assertTrue(res_ok.qualified_e_signature_5070_verified)

            # Attack A: Duplicate XML ID anywhere in document (Id="SignedProps-1" cloned onto an evil element)
            dup_id_xml = valid_env.replace(
                b"<Icerik>Gercek Icerik</Icerik>",
                b'<Icerik Id="SignedProps-1">Gercek Icerik</Icerik>',
            )
            res_dup = verifier.verify_xades_signature(
                dup_id_xml, expected_eshs_id="ESHS-TR-01", sscd_control_evidence_result=sscd_ok, runtime_environment="PRODUCTION"
            )
            self.assertFalse(res_dup.cryptographic_signature_valid)
            self.assertIn("XADES_DUPLICATE_XML_ID_DETECTED", res_dup.error_codes)
            dec_dup = gate.evaluate_5070_acceptance(res_dup, runtime_environment="PRODUCTION")
            self.assertEqual(dec_dup.production_5070_acceptance_status, "DENIED_SECURITY_VIOLATION")

            # Attack B: XSW3/XSW4/XSW6 — Signed business node hidden inside <ds:Signature>/<ds:Object> while
            # unsigned evil content sits in the enveloped document root!
            enveloping_xml, _ = create_xades_xml_bytes(b"Hidden signed data", cert_pem, key_pem, mode="ENVELOPING")
            sig_body = enveloping_xml.decode("utf-8").split("?>", 1)[1]
            xsw_hidden = (
                f'<?xml version="1.0" encoding="UTF-8"?><Belge><SahteImzasizOnay>1000000 TL</SahteImzasizOnay>{sig_body}</Belge>'
            ).encode("utf-8")
            res_xsw_hidden = verifier.verify_xades_signature(
                xsw_hidden, expected_eshs_id="ESHS-TR-01", sscd_control_evidence_result=sscd_ok, runtime_environment="PRODUCTION"
            )
            self.assertFalse(res_xsw_hidden.cryptographic_signature_valid)
            self.assertIn("XADES_XSW_DATA_REF_HIDDEN_INSIDE_SIGNATURE", res_xsw_hidden.error_codes)
            self.assertEqual(
                gate.evaluate_5070_acceptance(res_xsw_hidden, runtime_environment="PRODUCTION").production_5070_acceptance_status,
                "DENIED_SECURITY_VIOLATION",
            )

            # Attack C: XSW1/XSW2 — Wrapping signed element alongside an unsigned sibling element outside signed scope!
            import re as _re
            sig_without_obj = _re.sub(r'<ds:Object Id="Obj-Data-1">.*?</ds:Object>', "", sig_body, flags=_re.DOTALL)
            xsw_unsigned_sibling = (
                f'<?xml version="1.0" encoding="UTF-8"?><Kapsayici>'
                f'<SahteImzasizKardes>Imzasiz Sahte Talimat</SahteImzasizKardes>'
                f'<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Obj-Data-1">SGlkZGVuIHNpZ25lZCBkYXRh</ds:Object>'
                f'{sig_without_obj}'
                f'</Kapsayici>'
            ).encode("utf-8")
            insp_xsw_sib = verify_xades_xmldsig(xsw_unsigned_sibling)
            self.assertFalse(insp_xsw_sib.crypto_valid)
            self.assertIn("XADES_XSW_UNSIGNED_CONTENT_OUTSIDE_SIGNED_SCOPE", insp_xsw_sib.error_codes)

            # Attack D: Multiple <ds:Signature> injection -> REJECTED!
            multi_sig = valid_env.replace(
                b"</Belge>",
                b'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Sig-Evil"></ds:Signature></Belge>',
            )
            insp_multi = verify_xades_xmldsig(multi_sig)
            self.assertFalse(insp_multi.crypto_valid)
            self.assertIn("XADES_XSW_MULTIPLE_OR_NESTED_SIGNATURES", insp_multi.error_codes)

            # Attack E: QualifyingProperties/@Target mismatch -> REJECTED!
            bad_target = valid_env.replace(b'Target="#Sig-1"', b'Target="#Sig-Other"')
            insp_tgt = verify_xades_xmldsig(bad_target)
            self.assertFalse(insp_tgt.crypto_valid)
            self.assertIn("XADES_XSW_QUALIFYING_PROPERTIES_TARGET_MISMATCH", insp_tgt.error_codes)

    def test_08_cades_attached_and_multicert_chain_plus_v1041_governance(self) -> None:
        with Ephemeral5070PkiFixture() as pki:
            cert_pem, key_pem, _ = pki.issue_signer_cert(tag="cades_multi")
            verifier = self._build_sandbox_verifier(pki)
            sscd_ok = pki.build_verified_sscd_evidence(cert_pem)
            content = b"Attached ve coklu sertifikali CAdES standart vektor testi"

            # 1. Attached (-nodetach opaque) CAdES-B-B with embedded Root+Inter CA certs
            attached_cms = create_cades_cms_der(
                content,
                cert_pem,
                key_pem,
                include_cades_attr=True,
                detached=False,
                extra_chain_certs_pem=pki.root_cert_pem + "\n" + pki.inter_cert_pem,
            )
            res_att = verifier.verify_cades_signature(
                attached_cms,
                signed_content_bytes=None,  # opaque attached content!
                expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_result=sscd_ok,
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertTrue(res_att.cryptographic_signature_valid)
            self.assertTrue(res_att.profile_compliance.profile_compliant)
            self.assertFalse(res_att.signer_certificate.basic_constraints_ca)
            self.assertTrue(res_att.qualified_e_signature_5070_verified)

        # 2. v1.0.4.x / v1.0.5 governance invariants
        self.assertTrue(ESIGN_5070_VERSION.startswith(("1.0.4.", "1.0.5")))
        self.assertTrue(TRUST_ROOT_VERSION.startswith(("1.0.4.", "1.0.5")))
        self.assertTrue(PARSER_VERSION.startswith(("tr_diyanet_holiday_parser_v1.0.4.", "tr_diyanet_holiday_parser_v1.0.5")))
        self.assertTrue(TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["calendar_version"].startswith(("1.0.4.", "1.0.5")))

        report = run_live_integration_probe(project_root=PROJECT_ROOT)
        self.assertTrue(report["schema_version"].startswith(("1.0.4.", "1.0.5")))
        self.assertEqual(report["overall_live_integration_status"], "NOT_CONFIGURED")
        self.assertEqual(report["esign_5070_overall_status"], "NOT_CONFIGURED")
        self.assertFalse(report["qualified_e_signature_5070_production_ready"])
        self.assertFalse(report["qualified_e_signature_5070_equivalent"])
        self.assertFalse(report["production_use_authorized"])

        schemas = sorted((PROJECT_ROOT / "schemas").glob("*.schema.json"))
        self.assertGreaterEqual(len(schemas), 11)
        for sf in schemas:
            s_doc = json.loads(sf.read_text(encoding="utf-8"))
            self.assertTrue("(v1.0.4." in s_doc["title"] or "(v1.0.5" in s_doc["title"], sf.name)

        sources = load_source_registry(PROJECT_ROOT / "config" / "legal_sources_registry.json")
        precedents = load_precedent_registry(PROJECT_ROOT / "config" / "yargitay_precedents.json")
        cards = load_knowledge_cards(PROJECT_ROOT / "rag_kb", sources, precedents)
        self.assertEqual((len(sources), len(precedents), len(cards)), (30, 5, 39))
        audit_data = json.loads((PROJECT_ROOT / "config" / "verification_audit_log.json").read_text(encoding="utf-8"))
        self.assertTrue(audit_data["schema_version"].startswith(("1.0.4.", "1.0.5")))
        self.assertEqual(audit_data["summary"]["total_audited_records"], 74)
        self.assertTrue(validate_central_audit_log(audit_data, sources, precedents, cards).valid)


if __name__ == "__main__":
    unittest.main()
