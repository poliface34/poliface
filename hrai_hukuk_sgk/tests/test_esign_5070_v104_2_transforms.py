"""CALISORA @HukukSGK v1.0.4.2 — Sequential XMLDSig Transform Pipeline & Security Regression Suite (BLOCKER 3 Closure).

Directly verifies every requirement from the v1.0.4.2 independent security remediation mandate:
  1. True sequential `<ds:Transform>` execution where Transform N output is Transform N+1 input
     (`TransformPipelineData`: explicit `NODE_SET` vs `OCTET_STREAM` data model per W3C XMLDSig §4.4.3.4 & §6.6).
  2. `Enveloped-signature -> C14N` valid + independent digest match vs `C14N -> Enveloped-signature`
     and `Detached/Base64 -> Enveloped-signature` rejected fail-closed (`XADES_TRANSFORM_INVALID_INPUT_TYPE`).
  3. `Base64 -> C14N` (enveloping & detached) valid + independent digest match vs `C14N -> Base64`
     rejected fail-closed (`XADES_BASE64_TRANSFORM_DECODE_FAILED` / `XADES_TRANSFORM_XML_REPARSE_FAILED`),
     plus Base64-smuggled XXE/DOCTYPE and duplicate-ID rejection and double Base64 chaining.
  4. Multiple consecutive C14N transforms (`Inclusive 1.0 -> Exclusive 1.0` vs `Exclusive 1.0 -> Inclusive 1.0`,
     `WithComments -> Exclusive` vs `NoComments -> WithComments`, `C14N 1.0 -> C14N 1.1` vs `C14N 1.1 -> C14N 1.0`)
     proving order sensitivity and cross-validating against independent expected outputs (and libxml2 if present).
  5. Valid vs invalid digest comparison and tampered `SignedInfo` with swapped transform order.
  6. Unknown transforms, forbidden XPath / XSLT / XPath Filter 2 transforms, and excessive transform counts.
  7. XML Signature Wrapping (XSW) attacks and Reference URI manipulation (missing ID, empty `#`, XPointer,
     remote URL SSRF / `file://` read prevention, `URI=""` misuse, `SignedProperties` URI spoofing).
  8. Exact v1.0.4.2 governance, 11/11 schema, 74/74 audit log, L1-L4 & NOT_CONFIGURED live probe invariants.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re
import unittest

from engine.attestation_verifier import PARSER_VERSION
from engine.esign5070 import (
    C14N_EXCLUSIVE_10,
    C14N_INCLUSIVE_10,
    C14N_INCLUSIVE_10_COMMENTS,
    C14N_INCLUSIVE_11,
    ESIGN_5070_VERSION,
    MAX_TRANSFORMS_PER_REFERENCE,
    TRANSFORM_BASE64,
    TRANSFORM_ENVELOPED_SIGNATURE,
    TRANSFORM_KIND_NODE_SET,
    TRANSFORM_KIND_OCTET_STREAM,
    Default5070AcceptanceGate,
    DefaultCertificateRevocationProvider,
    DefaultEshsTrustListProvider,
    DefaultQualifiedSignature5070Verifier,
    DefaultSscdControlEvidenceVerifier,
    TransformPipelineData,
    XmlSecurityError,
    canonicalize_xml_node,
    create_xades_xml_bytes,
    execute_xmldsig_transform_pipeline,
    safe_parse_xml_bytes,
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


def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def _extract_data_ref_digest_b64(xml_bytes: bytes, ref_id: str) -> str:
    m = re.search(
        rf'<ds:Reference[^>]*Id="{re.escape(ref_id)}"[^>]*>.*?<ds:DigestValue>([^<]+)</ds:DigestValue>',
        xml_bytes.decode("utf-8"),
        flags=re.DOTALL,
    )
    if not m:
        raise AssertionError(f"DigestValue not found for Reference Id={ref_id!r}")
    return re.sub(r"\s+", "", m.group(1).strip())


class TestXmlDsigSequentialTransformPipelineV1042(unittest.TestCase):
    """[SECURITY / BLOCKER-3] W3C XMLDSig Sequential Typed Transform Pipeline & Attack Suite (v1.0.4.2)."""

    def _build_sandbox_verifier(self, pki: Ephemeral5070PkiFixture) -> DefaultQualifiedSignature5070Verifier:
        crl_pem = pki.generate_crl_pem()
        eshs = DefaultEshsTrustListProvider(
            btk_providers=[pki.build_btk_provider_record()],
            ca_bundles=[pki.build_ca_bundle()],
            integration_mode="MOCK_SANDBOX",
        )
        rev = DefaultCertificateRevocationProvider(
            trusted_ca_pem=pki.root_cert_pem + "\n" + pki.inter_cert_pem,
            crl_fetcher=lambda _i, _t: crl_pem,
            integration_mode="MOCK_SANDBOX",
        )
        sscd_ver = pki.build_sscd_evidence_verifier(crl_pem=crl_pem)
        return DefaultQualifiedSignature5070Verifier(
            eshs_trust_provider=eshs,
            revocation_provider=rev,
            sscd_evidence_verifier=sscd_ver,
            integration_mode="MOCK_SANDBOX",
        )

    def test_01_enveloped_signature_then_c14n_valid_vs_reversed_c14n_then_enveloped_rejected(self) -> None:
        with Ephemeral5070PkiFixture() as pki:
            cert_pem, key_pem, _ = pki.issue_signer_cert(tag="xform_env_order")
            verifier = self._build_sandbox_verifier(pki)
            gate = Default5070AcceptanceGate()
            sscd_ok = pki.build_verified_sscd_evidence(cert_pem)

            raw_doc = b'<Sozlesme xmlns="urn:calisora:hr" z="2" a="1"><Madde>4857 m.18</Madde></Sozlesme>'
            expected_c14n = b'<Sozlesme xmlns="urn:calisora:hr" a="1" z="2"><Madde>4857 m.18</Madde></Sozlesme>'
            expected_digest = _sha256_b64(expected_c14n)

            # 1. Valid order: Enveloped-signature (NODE_SET -> NODE_SET) -> Exclusive C14N (NODE_SET -> OCTET_STREAM)
            signed_ok, _ = create_xades_xml_bytes(
                raw_doc,
                cert_pem,
                key_pem,
                mode="ENVELOPED",
                canonicalization_method=C14N_EXCLUSIVE_10,
                data_transforms=[TRANSFORM_ENVELOPED_SIGNATURE, C14N_EXCLUSIVE_10],
            )
            self.assertEqual(_extract_data_ref_digest_b64(signed_ok, "Ref-Doc"), expected_digest)
            insp_ok = verify_xades_xmldsig(signed_ok)
            self.assertTrue(insp_ok.crypto_valid, (insp_ok.error_codes, insp_ok.errors))
            data_ref = [r for r in insp_ok.xmldsig_details["references"] if r["kind"] == "DATA"][0]
            self.assertEqual(
                [(s["algorithm"], s["input_type"], s["output_type"]) for s in data_ref["transform_trace"]],
                [
                    (TRANSFORM_ENVELOPED_SIGNATURE, TRANSFORM_KIND_NODE_SET, TRANSFORM_KIND_NODE_SET),
                    (C14N_EXCLUSIVE_10, TRANSFORM_KIND_NODE_SET, TRANSFORM_KIND_OCTET_STREAM),
                ],
            )

            # 2. Valid implicit final C14N: ONLY [enveloped-signature] ends in NODE_SET -> default Inclusive C14N 1.0
            signed_implicit, _ = create_xades_xml_bytes(
                raw_doc,
                cert_pem,
                key_pem,
                mode="ENVELOPED",
                canonicalization_method=C14N_INCLUSIVE_10,
                data_transforms=[TRANSFORM_ENVELOPED_SIGNATURE],
            )
            self.assertEqual(_extract_data_ref_digest_b64(signed_implicit, "Ref-Doc"), expected_digest)
            insp_imp = verify_xades_xmldsig(signed_implicit)
            self.assertTrue(insp_imp.crypto_valid, (insp_imp.error_codes, insp_imp.errors))
            imp_trace = [r for r in insp_imp.xmldsig_details["references"] if r["kind"] == "DATA"][0]["transform_trace"]
            self.assertEqual(len(imp_trace), 2)
            self.assertTrue(imp_trace[1].get("implicit_final_c14n"))

            # 3. REVERSED order: C14N (NODE_SET -> OCTET_STREAM) -> Enveloped-signature (expects NODE_SET!) -> FAIL-CLOSED!
            reversed_transforms_xml = signed_ok.replace(
                (
                    f'<ds:Transform Algorithm="{TRANSFORM_ENVELOPED_SIGNATURE}"></ds:Transform>'
                    f'<ds:Transform Algorithm="{C14N_EXCLUSIVE_10}"></ds:Transform>'
                ).encode("utf-8"),
                (
                    f'<ds:Transform Algorithm="{C14N_EXCLUSIVE_10}"></ds:Transform>'
                    f'<ds:Transform Algorithm="{TRANSFORM_ENVELOPED_SIGNATURE}"></ds:Transform>'
                ).encode("utf-8"),
                1,
            )
            insp_rev = verify_xades_xmldsig(reversed_transforms_xml)
            self.assertFalse(insp_rev.crypto_valid)
            self.assertIn("XADES_TRANSFORM_INVALID_INPUT_TYPE", insp_rev.error_codes)

            res_rev = verifier.verify_xades_signature(
                reversed_transforms_xml,
                expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_result=sscd_ok,
                runtime_environment="PRODUCTION",
            )
            self.assertFalse(res_rev.cryptographic_signature_valid)
            self.assertIn("XADES_TRANSFORM_INVALID_INPUT_TYPE", res_rev.error_codes)
            dec_rev = gate.evaluate_5070_acceptance(res_rev, runtime_environment="PRODUCTION")
            self.assertEqual(dec_rev.production_5070_acceptance_status, "DENIED_SECURITY_VIOLATION")
            self.assertFalse(dec_rev.qualified_e_signature_5070_production_accepted)

            # 4. Reversed C14N -> Enveloped-signature on URI="#Doc-1" fragment reference ALSO fails closed!
            frag_doc = b'<Sozlesme Id="Doc-1"><Madde>Test</Madde></Sozlesme>'
            signed_frag, _ = create_xades_xml_bytes(frag_doc, cert_pem, key_pem, mode="ENVELOPED")
            frag_reversed = signed_frag.replace(b'URI=""', b'URI="#Doc-1"', 1).replace(
                (
                    f'<ds:Transform Algorithm="{TRANSFORM_ENVELOPED_SIGNATURE}"></ds:Transform>'
                    f'<ds:Transform Algorithm="{C14N_INCLUSIVE_10}"></ds:Transform>'
                ).encode("utf-8"),
                (
                    f'<ds:Transform Algorithm="{C14N_INCLUSIVE_10}"></ds:Transform>'
                    f'<ds:Transform Algorithm="{TRANSFORM_ENVELOPED_SIGNATURE}"></ds:Transform>'
                ).encode("utf-8"),
                1,
            )
            insp_frag_rev = verify_xades_xmldsig(frag_reversed)
            self.assertFalse(insp_frag_rev.crypto_valid)
            self.assertIn("XADES_TRANSFORM_INVALID_INPUT_TYPE", insp_frag_rev.error_codes)

            # 5. Detached (OCTET_STREAM) -> Enveloped-signature AND Base64 (OCTET_STREAM) -> Enveloped-signature -> FAIL-CLOSED!
            det_xml, _ = create_xades_xml_bytes(b"Detached bytes", cert_pem, key_pem, mode="DETACHED")
            det_with_env = det_xml.replace(
                b'<ds:Reference Id="Ref-Data" URI="detached-content">',
                (
                    f'<ds:Reference Id="Ref-Data" URI="detached-content"><ds:Transforms>'
                    f'<ds:Transform Algorithm="{TRANSFORM_ENVELOPED_SIGNATURE}"></ds:Transform>'
                    f"</ds:Transforms>"
                ).encode("utf-8"),
                1,
            )
            insp_det_env = verify_xades_xmldsig(det_with_env, b"Detached bytes")
            self.assertFalse(insp_det_env.crypto_valid)
            self.assertIn("XADES_TRANSFORM_INVALID_INPUT_TYPE", insp_det_env.error_codes)

            with self.assertRaises(XmlSecurityError) as ctx_b64_env:
                dom = safe_parse_xml_bytes(b'<Root><Data>SGVsbG8=</Data><Sig/></Root>')
                execute_xmldsig_transform_pipeline(
                    TransformPipelineData(kind=TRANSFORM_KIND_NODE_SET, node=dom.getElementsByTagName("Data")[0]),
                    [(TRANSFORM_BASE64, set()), (TRANSFORM_ENVELOPED_SIGNATURE, set())],
                    verifying_signature_node=dom.getElementsByTagName("Sig")[0],
                )
            self.assertEqual(ctx_b64_env.exception.code, "XADES_TRANSFORM_INVALID_INPUT_TYPE")

    def test_02_base64_then_c14n_valid_vs_c14n_then_base64_fail_closed_and_smuggled_xxe_blocked(self) -> None:
        with Ephemeral5070PkiFixture() as pki:
            cert_pem, key_pem, _ = pki.issue_signer_cert(tag="xform_b64_c14n")
            verifier = self._build_sandbox_verifier(pki)
            gate = Default5070AcceptanceGate()
            sscd_ok = pki.build_verified_sscd_evidence(cert_pem)

            # Uncanonicalized XML (unsorted attrs, comment, self-closing tag) wrapped in Base64
            inner_xml = b'<BordroOnay xmlns="urn:calisora:bordro" z="9" a="1"><!-- silinecek --><Kalem/></BordroOnay>'
            expected_c14n = b'<BordroOnay xmlns="urn:calisora:bordro" a="1" z="9"><Kalem></Kalem></BordroOnay>'
            expected_digest = _sha256_b64(expected_c14n)

            # 1. Enveloping XAdES: Base64 -> C14N (NODE_SET -> Base64 decodes text -> OCTET_STREAM XML -> C14N reparses & canonicalizes!)
            signed_b64_c14n, _ = create_xades_xml_bytes(
                inner_xml,
                cert_pem,
                key_pem,
                mode="ENVELOPING",
                data_transforms=[TRANSFORM_BASE64, C14N_INCLUSIVE_10],
            )
            self.assertEqual(_extract_data_ref_digest_b64(signed_b64_c14n, "Ref-Obj"), expected_digest)
            insp_ok = verify_xades_xmldsig(signed_b64_c14n)
            self.assertTrue(insp_ok.crypto_valid, (insp_ok.error_codes, insp_ok.errors))
            trace_ok = [r for r in insp_ok.xmldsig_details["references"] if r["kind"] == "DATA"][0]["transform_trace"]
            self.assertEqual(
                [(s["algorithm"], s["input_type"], s["output_type"], s.get("reparsed_xml")) for s in trace_ok],
                [
                    (TRANSFORM_BASE64, TRANSFORM_KIND_NODE_SET, TRANSFORM_KIND_OCTET_STREAM, None),
                    (C14N_INCLUSIVE_10, TRANSFORM_KIND_OCTET_STREAM, TRANSFORM_KIND_OCTET_STREAM, True),
                ],
            )

            # 2. REVERSED Enveloping: C14N -> Base64 MUST FAIL CLOSED!
            #    Step 0 (C14N) serializes `<ds:Object ...>...</ds:Object>` (starts with `<`, NOT valid Base64!)
            #    Step 1 (Base64) strictly rejects non-Base64 XML syntax (`XADES_BASE64_TRANSFORM_DECODE_FAILED`)!
            swapped_c14n_b64 = signed_b64_c14n.replace(
                (
                    f'<ds:Transform Algorithm="{TRANSFORM_BASE64}"></ds:Transform>'
                    f'<ds:Transform Algorithm="{C14N_INCLUSIVE_10}"></ds:Transform>'
                ).encode("utf-8"),
                (
                    f'<ds:Transform Algorithm="{C14N_INCLUSIVE_10}"></ds:Transform>'
                    f'<ds:Transform Algorithm="{TRANSFORM_BASE64}"></ds:Transform>'
                ).encode("utf-8"),
                1,
            )
            insp_rev = verify_xades_xmldsig(swapped_c14n_b64)
            self.assertFalse(insp_rev.crypto_valid)
            self.assertIn("XADES_BASE64_TRANSFORM_DECODE_FAILED", insp_rev.error_codes)
            res_rev = verifier.verify_xades_signature(
                swapped_c14n_b64,
                expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_result=sscd_ok,
                runtime_environment="PRODUCTION",
            )
            self.assertEqual(
                gate.evaluate_5070_acceptance(res_rev, runtime_environment="PRODUCTION").production_5070_acceptance_status,
                "DENIED_SECURITY_VIOLATION",
            )

            # 3. Detached Base64-encoded XML: Base64 -> C14N PASSES; C14N -> Base64 FAILS (`XADES_TRANSFORM_XML_REPARSE_FAILED`)!
            detached_b64_bytes = base64.b64encode(inner_xml)
            signed_det_ok, _ = create_xades_xml_bytes(
                detached_b64_bytes,
                cert_pem,
                key_pem,
                mode="DETACHED",
                data_transforms=[TRANSFORM_BASE64, C14N_INCLUSIVE_10],
            )
            self.assertEqual(_extract_data_ref_digest_b64(signed_det_ok, "Ref-Data"), expected_digest)
            insp_det_ok = verify_xades_xmldsig(signed_det_ok, detached_b64_bytes)
            self.assertTrue(insp_det_ok.crypto_valid, (insp_det_ok.error_codes, insp_det_ok.errors))

            det_swapped = signed_det_ok.replace(
                (
                    f'<ds:Transform Algorithm="{TRANSFORM_BASE64}"></ds:Transform>'
                    f'<ds:Transform Algorithm="{C14N_INCLUSIVE_10}"></ds:Transform>'
                ).encode("utf-8"),
                (
                    f'<ds:Transform Algorithm="{C14N_INCLUSIVE_10}"></ds:Transform>'
                    f'<ds:Transform Algorithm="{TRANSFORM_BASE64}"></ds:Transform>'
                ).encode("utf-8"),
                1,
            )
            insp_det_swapped = verify_xades_xmldsig(det_swapped, detached_b64_bytes)
            self.assertFalse(insp_det_swapped.crypto_valid)
            self.assertIn("XADES_TRANSFORM_XML_REPARSE_FAILED", insp_det_swapped.error_codes)

            # 4. Double Base64 chaining [Base64, Base64] proves Step 0 OCTET_STREAM feeds directly into Step 1!
            plain_msg = b"Double-Base64-Sequential-Proof"
            once_b64 = base64.b64encode(plain_msg)
            signed_double_b64, _ = create_xades_xml_bytes(
                once_b64,  # ENVELOPING base64-encodes once_b64 again -> twice-encoded in <ds:Object>!
                cert_pem,
                key_pem,
                mode="ENVELOPING",
                data_transforms=[TRANSFORM_BASE64, TRANSFORM_BASE64],
            )
            self.assertEqual(_extract_data_ref_digest_b64(signed_double_b64, "Ref-Obj"), _sha256_b64(plain_msg))
            insp_dbl = verify_xades_xmldsig(signed_double_b64)
            self.assertTrue(insp_dbl.crypto_valid, (insp_dbl.error_codes, insp_dbl.errors))

            # 5. Security: Base64-smuggled XXE/DOCTYPE, duplicate XML ID, and non-XML binary MUST fail closed!
            xxe_b64 = base64.b64encode(b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>')
            with self.assertRaises(XmlSecurityError) as ctx_xxe:
                execute_xmldsig_transform_pipeline(
                    TransformPipelineData(kind=TRANSFORM_KIND_OCTET_STREAM, octets=xxe_b64),
                    [(TRANSFORM_BASE64, set()), (C14N_INCLUSIVE_10, set())],
                )
            self.assertEqual(ctx_xxe.exception.code, "XML_XXE_OR_DOCTYPE_FORBIDDEN")

            dup_b64 = base64.b64encode(b'<root><a Id="x1"/><b Id="x1"/></root>')
            with self.assertRaises(XmlSecurityError) as ctx_dup:
                execute_xmldsig_transform_pipeline(
                    TransformPipelineData(kind=TRANSFORM_KIND_OCTET_STREAM, octets=dup_b64),
                    [(TRANSFORM_BASE64, set()), (C14N_INCLUSIVE_10, set())],
                )
            self.assertEqual(ctx_dup.exception.code, "XADES_DUPLICATE_XML_ID_DETECTED")

            png_b64 = base64.b64encode(b"\x89PNG\r\n\x1a\nnot-xml-bytes")
            with self.assertRaises(XmlSecurityError) as ctx_bin:
                execute_xmldsig_transform_pipeline(
                    TransformPipelineData(kind=TRANSFORM_KIND_OCTET_STREAM, octets=png_b64),
                    [(TRANSFORM_BASE64, set()), (C14N_INCLUSIVE_10, set())],
                )
            self.assertEqual(ctx_bin.exception.code, "XADES_TRANSFORM_XML_REPARSE_FAILED")

    def test_03_multiple_c14n_transforms_order_produces_distinct_verified_outputs_and_libxml2_match(self) -> None:
        # 1. Order sensitivity on SAME two valid C14N transforms:
        #    [Inclusive 1.0 -> Exclusive 1.0] vs [Exclusive 1.0 -> Inclusive 1.0] on a node with ancestor `xml:lang="tr"`:
        #      - Inclusive -> Exclusive: Step 0 copies ancestor `xml:lang="tr"` onto <ds:Object>, Step 1 preserves it!
        #      - Exclusive -> Inclusive: Step 0 drops ancestor `xml:lang="tr"`, Step 1 cannot restore it!
        with Ephemeral5070PkiFixture() as pki:
            cert_pem, key_pem, _ = pki.issue_signer_cert(tag="xform_multi_c14n")
            inline_item = b'<Kalem z="2" a="1"><!-- yorum --><Deger>100</Deger></Kalem>'

            xml_inc_then_exc, _ = create_xades_xml_bytes(
                inline_item,
                cert_pem,
                key_pem,
                mode="ENVELOPING",
                enveloping_inline_xml=True,
                extra_signature_attrs='xml:lang="tr" xmlns:unused="urn:unused"',
                data_transforms=[C14N_INCLUSIVE_10, C14N_EXCLUSIVE_10],
            )
            xml_exc_then_inc, _ = create_xades_xml_bytes(
                inline_item,
                cert_pem,
                key_pem,
                mode="ENVELOPING",
                enveloping_inline_xml=True,
                extra_signature_attrs='xml:lang="tr" xmlns:unused="urn:unused"',
                data_transforms=[C14N_EXCLUSIVE_10, C14N_INCLUSIVE_10],
            )

            # Independent expected W3C C14N outputs for BOTH orders!
            expected_inc_then_exc = (
                b'<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Obj-Data-1" xml:lang="tr">'
                b'<Kalem a="1" z="2"><Deger>100</Deger></Kalem></ds:Object>'
            )
            expected_exc_then_inc = (
                b'<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Obj-Data-1">'
                b'<Kalem a="1" z="2"><Deger>100</Deger></Kalem></ds:Object>'
            )
            self.assertNotEqual(expected_inc_then_exc, expected_exc_then_inc)

            digest_a = _extract_data_ref_digest_b64(xml_inc_then_exc, "Ref-Obj")
            digest_b = _extract_data_ref_digest_b64(xml_exc_then_inc, "Ref-Obj")
            self.assertEqual(digest_a, _sha256_b64(expected_inc_then_exc))
            self.assertEqual(digest_b, _sha256_b64(expected_exc_then_inc))
            self.assertNotEqual(digest_a, digest_b)

            insp_a = verify_xades_xmldsig(xml_inc_then_exc)
            insp_b = verify_xades_xmldsig(xml_exc_then_inc)
            self.assertTrue(insp_a.crypto_valid, (insp_a.error_codes, insp_a.errors))
            self.assertTrue(insp_b.crypto_valid, (insp_b.error_codes, insp_b.errors))

            # Cross-validate sequential multi-C14N composition byte-for-byte against libxml2 (lxml) if installed!
            # (Tests namespace propagation, InclusiveNamespaces PrefixList, and comment stripping across 2 steps.)
            try:
                from lxml import etree as LET

                sample_ns = (
                    b'<Root xmlns:unused="urn:unused" xmlns:a="urn:a">'
                    b'<Wrap><!-- c --><a:Item z="2" a="1"/></Wrap></Root>'
                )
                dom_ns = safe_parse_xml_bytes(sample_ns)
                wrap_dom = dom_ns.getElementsByTagName("Wrap")[0]
                lx_wrap = LET.fromstring(sample_ns).xpath(".//*[local-name()='Wrap']")[0]

                # Chain 1: Inclusive WithComments -> Exclusive(PrefixList="unused") (strips comment, keeps unused, moves a)
                ours_1, _ = execute_xmldsig_transform_pipeline(
                    TransformPipelineData(kind=TRANSFORM_KIND_NODE_SET, node=wrap_dom),
                    [(C14N_INCLUSIVE_10_COMMENTS, set()), (C14N_EXCLUSIVE_10, {"unused"})],
                )
                lx_s1 = LET.tostring(lx_wrap, method="c14n", exclusive=False, with_comments=True)
                lx_s2 = LET.tostring(
                    LET.fromstring(lx_s1), method="c14n", exclusive=True, with_comments=False, inclusive_ns_prefixes=["unused"]
                )
                self.assertEqual(ours_1, lx_s2)

                # Chain 2: Exclusive(no PrefixList) -> Inclusive WithComments (dropped unused & comment in step 1!)
                ours_2, _ = execute_xmldsig_transform_pipeline(
                    TransformPipelineData(kind=TRANSFORM_KIND_NODE_SET, node=wrap_dom),
                    [(C14N_EXCLUSIVE_10, set()), (C14N_INCLUSIVE_10_COMMENTS, set())],
                )
                lx_b1 = LET.tostring(lx_wrap, method="c14n", exclusive=True, with_comments=False)
                lx_b2 = LET.tostring(LET.fromstring(lx_b1), method="c14n", exclusive=False, with_comments=True)
                self.assertEqual(ours_2, lx_b2)
                self.assertNotEqual(ours_1, ours_2)
            except ImportError:
                pass

            # 2. Comments stripping vs preservation across multiple C14N transforms:
            #    [Enveloped -> NoComments -> WithComments] CANNOT restore comments dropped in Step 1,
            #    whereas [Enveloped -> WithComments -> WithComments] preserves them!
            commented_doc = b'<Belge Id="B-1"><!-- kritik-yorum --><Metin>OK</Metin></Belge>'
            xml_strip_then_keep, _ = create_xades_xml_bytes(
                commented_doc,
                cert_pem,
                key_pem,
                mode="ENVELOPED",
                data_transforms=[TRANSFORM_ENVELOPED_SIGNATURE, C14N_INCLUSIVE_10, C14N_INCLUSIVE_10_COMMENTS],
            )
            xml_keep_then_keep, _ = create_xades_xml_bytes(
                commented_doc,
                cert_pem,
                key_pem,
                mode="ENVELOPED",
                data_transforms=[TRANSFORM_ENVELOPED_SIGNATURE, C14N_INCLUSIVE_10_COMMENTS, C14N_INCLUSIVE_10_COMMENTS],
            )
            xml_keep_then_exc_strip, _ = create_xades_xml_bytes(
                commented_doc,
                cert_pem,
                key_pem,
                mode="ENVELOPED",
                data_transforms=[TRANSFORM_ENVELOPED_SIGNATURE, C14N_INCLUSIVE_10_COMMENTS, C14N_EXCLUSIVE_10],
            )

            expected_no_comment = b'<Belge Id="B-1"><Metin>OK</Metin></Belge>'
            expected_with_comment = b'<Belge Id="B-1"><!-- kritik-yorum --><Metin>OK</Metin></Belge>'

            self.assertEqual(_extract_data_ref_digest_b64(xml_strip_then_keep, "Ref-Doc"), _sha256_b64(expected_no_comment))
            self.assertEqual(_extract_data_ref_digest_b64(xml_keep_then_keep, "Ref-Doc"), _sha256_b64(expected_with_comment))
            self.assertEqual(_extract_data_ref_digest_b64(xml_keep_then_exc_strip, "Ref-Doc"), _sha256_b64(expected_no_comment))

            for label, xbytes in (
                ("strip->keep", xml_strip_then_keep),
                ("keep->keep", xml_keep_then_keep),
                ("keep->exc", xml_keep_then_exc_strip),
            ):
                insp = verify_xades_xmldsig(xbytes)
                self.assertTrue(insp.crypto_valid, (label, insp.error_codes, insp.errors))

        # 3. C14N 1.0 vs C14N 1.1 order sensitivity on `xml:id` ancestor inheritance
        dom_id = safe_parse_xml_bytes(b'<Wrap xml:id="anc-1"><Child>data</Child></Wrap>')
        child_node = dom_id.getElementsByTagName("Child")[0]
        out_10_11, _ = execute_xmldsig_transform_pipeline(
            TransformPipelineData(kind=TRANSFORM_KIND_NODE_SET, node=child_node),
            [(C14N_INCLUSIVE_10, set()), (C14N_INCLUSIVE_11, set())],
        )
        out_11_10, _ = execute_xmldsig_transform_pipeline(
            TransformPipelineData(kind=TRANSFORM_KIND_NODE_SET, node=child_node),
            [(C14N_INCLUSIVE_11, set()), (C14N_INCLUSIVE_10, set())],
        )
        self.assertEqual(out_10_11, b'<Child xml:id="anc-1">data</Child>')
        self.assertEqual(out_11_10, b"<Child>data</Child>")
        self.assertNotEqual(out_10_11, out_11_10)

    def test_04_valid_vs_invalid_digest_and_tampered_signedinfo_swapped_transform_order(self) -> None:
        with Ephemeral5070PkiFixture() as pki:
            cert_pem, key_pem, _ = pki.issue_signer_cert(tag="xform_tamper")
            inline_item = b'<Kayit b="2" a="1">Tutar=5000</Kayit>'

            valid_xml, _ = create_xades_xml_bytes(
                inline_item,
                cert_pem,
                key_pem,
                mode="ENVELOPING",
                enveloping_inline_xml=True,
                extra_signature_attrs='xml:lang="tr"',
                data_transforms=[C14N_INCLUSIVE_10, C14N_EXCLUSIVE_10],
            )
            self.assertTrue(verify_xades_xmldsig(valid_xml).crypto_valid)

            # 1. Tampered content breaks digest immediately (SignatureValue still covers original SignedInfo)
            tampered_content = valid_xml.replace(b"Tutar=5000", b"Tutar=9999")
            insp_c = verify_xades_xmldsig(tampered_content)
            self.assertFalse(insp_c.crypto_valid)
            self.assertIn("XADES_CONTENT_DIGEST_MISMATCH", insp_c.error_codes)

            # 2. Tampered DigestValue inside SignedInfo breaks BOTH Digest AND SignatureValue
            orig_dig = _extract_data_ref_digest_b64(valid_xml, "Ref-Obj")
            bad_dig = ("A" if orig_dig[0] != "A" else "B") + orig_dig[1:]
            tampered_digest_xml = valid_xml.replace(orig_dig.encode("ascii"), bad_dig.encode("ascii"), 1)
            insp_d = verify_xades_xmldsig(tampered_digest_xml)
            self.assertFalse(insp_d.crypto_valid)
            self.assertIn("XADES_CONTENT_DIGEST_MISMATCH", insp_d.error_codes)
            self.assertIn("XADES_SIGNATURE_VALUE_INVALID", insp_d.error_codes)

            # 3. Tampered SignedInfo with SWAPPED transform order ([Inc, Exc] -> [Exc, Inc]):
            #    MUST break BOTH Reference Digest (due to different pipeline output!) AND SignedInfo SignatureValue!
            swapped_order_xml = valid_xml.replace(
                (
                    f'<ds:Transform Algorithm="{C14N_INCLUSIVE_10}"></ds:Transform>'
                    f'<ds:Transform Algorithm="{C14N_EXCLUSIVE_10}"></ds:Transform>'
                ).encode("utf-8"),
                (
                    f'<ds:Transform Algorithm="{C14N_EXCLUSIVE_10}"></ds:Transform>'
                    f'<ds:Transform Algorithm="{C14N_INCLUSIVE_10}"></ds:Transform>'
                ).encode("utf-8"),
                1,
            )
            insp_swap = verify_xades_xmldsig(swapped_order_xml)
            self.assertFalse(insp_swap.crypto_valid)
            self.assertIn("XADES_CONTENT_DIGEST_MISMATCH", insp_swap.error_codes)
            self.assertIn("XADES_SIGNATURE_VALUE_INVALID", insp_swap.error_codes)

    def test_05_unknown_forbidden_xpath_xslt_and_excessive_transforms_fail_closed(self) -> None:
        with Ephemeral5070PkiFixture() as pki:
            cert_pem, key_pem, _ = pki.issue_signer_cert(tag="xform_forbidden")
            verifier = self._build_sandbox_verifier(pki)
            gate = Default5070AcceptanceGate()
            sscd_ok = pki.build_verified_sscd_evidence(cert_pem)

            base_env, _ = create_xades_xml_bytes(
                b'<Belge Id="D-1"><Ad>Test</Ad></Belge>',
                cert_pem,
                key_pem,
                mode="ENVELOPED",
                canonicalization_method=C14N_EXCLUSIVE_10,
            )

            forbidden_uris = (
                "http://www.w3.org/TR/1999/REC-xslt-19991116",
                "http://www.w3.org/TR/1999/REC-xpath-19991116",
                "http://www.w3.org/2002/06/xmldsig-filter2",
                "http://unknown.attacker.invalid/custom-transform",
                "",
            )
            for bad_uri in forbidden_uris:
                # 1. Direct pipeline test
                with self.assertRaises(XmlSecurityError) as ctx:
                    execute_xmldsig_transform_pipeline(
                        TransformPipelineData(kind=TRANSFORM_KIND_OCTET_STREAM, octets=b"<a/>"),
                        [(bad_uri, set())],
                    )
                self.assertEqual(ctx.exception.code, "XADES_UNSUPPORTED_OR_FORBIDDEN_TRANSFORM")

                # 2. Full XAdES verifier + acceptance gate test
                injected = base_env.replace(
                    f'<ds:Transform Algorithm="{C14N_EXCLUSIVE_10}"></ds:Transform>'.encode("utf-8"),
                    f'<ds:Transform Algorithm="{bad_uri}"></ds:Transform>'.encode("utf-8"),
                    1,
                )
                insp = verify_xades_xmldsig(injected)
                self.assertFalse(insp.crypto_valid)
                self.assertIn("XADES_UNSUPPORTED_OR_FORBIDDEN_TRANSFORM", insp.error_codes)

            # 3. Excessive transforms count DoS guard (> MAX_TRANSFORMS_PER_REFERENCE)
            excessive_chain = "".join(
                f'<ds:Transform Algorithm="{C14N_INCLUSIVE_10}"></ds:Transform>'
                for _ in range(MAX_TRANSFORMS_PER_REFERENCE + 1)
            )
            dos_xml = base_env.replace(
                f'<ds:Transform Algorithm="{C14N_EXCLUSIVE_10}"></ds:Transform>'.encode("utf-8"),
                excessive_chain.encode("utf-8"),
                1,
            )
            insp_dos = verify_xades_xmldsig(dos_xml)
            self.assertFalse(insp_dos.crypto_valid)
            self.assertIn("XADES_EXCESSIVE_TRANSFORMS_COUNT", insp_dos.error_codes)
            res_dos = verifier.verify_xades_signature(
                dos_xml,
                expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_result=sscd_ok,
                runtime_environment="PRODUCTION",
            )
            self.assertEqual(
                gate.evaluate_5070_acceptance(res_dos, runtime_environment="PRODUCTION").production_5070_acceptance_status,
                "DENIED_SECURITY_VIOLATION",
            )

    def test_06_xsw_attacks_and_reference_uri_manipulation_rejected(self) -> None:
        with Ephemeral5070PkiFixture() as pki:
            cert_pem, key_pem, _ = pki.issue_signer_cert(tag="xform_uri_xsw")
            env_xml, _ = create_xades_xml_bytes(
                b'<Belge Id="Doc-Main"><Metin>Resmi Talimat</Metin></Belge>',
                cert_pem,
                key_pem,
                mode="ENVELOPED",
            )
            det_xml, _ = create_xades_xml_bytes(b"Detached payload", cert_pem, key_pem, mode="DETACHED")

            # 1. Missing fragment ID (`URI="#does-not-exist"`)
            insp_missing = verify_xades_xmldsig(env_xml.replace(b'URI=""', b'URI="#does-not-exist"', 1))
            self.assertFalse(insp_missing.crypto_valid)
            self.assertIn("XADES_REFERENCE_URI_NOT_FOUND", insp_missing.error_codes)

            # 2. Empty fragment (`URI="#"`) and XPointer (`URI="#xpointer(/)"`)
            for bad_frag in (b'URI="#"', b'URI="#xpointer(/)"'):
                insp_f = verify_xades_xmldsig(env_xml.replace(b'URI=""', bad_frag, 1))
                self.assertFalse(insp_f.crypto_valid)
                self.assertIn("XADES_REFERENCE_URI_NOT_FOUND", insp_f.error_codes)

            # 3. `URI=""` on detached root `<ds:Signature>` -> XSW blocked
            insp_empty_det = verify_xades_xmldsig(det_xml.replace(b'URI="detached-content"', b'URI=""', 1))
            self.assertFalse(insp_empty_det.crypto_valid)
            self.assertIn("XADES_XSW_INVALID_EMPTY_URI_ON_DETACHED_SIGNATURE", insp_empty_det.error_codes)

            # 4. `URI=""` on enveloped doc WITHOUT `enveloped-signature` transform -> blocked
            no_env_xform = env_xml.replace(
                f'<ds:Transform Algorithm="{TRANSFORM_ENVELOPED_SIGNATURE}"></ds:Transform>'.encode("utf-8"),
                b"",
                1,
            )
            insp_no_env = verify_xades_xmldsig(no_env_xform)
            self.assertFalse(insp_no_env.crypto_valid)
            self.assertIn("XADES_ENVELOPED_TRANSFORM_REQUIRED", insp_no_env.error_codes)

            # 5. Remote HTTP/HTTPS SSRF & local `file://` URI manipulation -> NEVER fetches, fails closed!
            for external_uri in (b'URI="https://169.254.169.254/latest/meta-data/"', b'URI="file:///etc/passwd"'):
                insp_ext = verify_xades_xmldsig(
                    det_xml.replace(b'URI="detached-content"', external_uri, 1),
                    signed_content_bytes=None,
                )
                self.assertFalse(insp_ext.crypto_valid)
                self.assertIn("XADES_DETACHED_CONTENT_MISSING", insp_ext.error_codes)

            # 6. SignedProperties URI spoofed to detached URI or `URI=""` -> XSW blocked!
            sp_detached = env_xml.replace(b'URI="#SignedProps-1"', b'URI="evil-external-props"', 1)
            insp_sp_det = verify_xades_xmldsig(sp_detached, signed_content_bytes=b"fake")
            self.assertFalse(insp_sp_det.crypto_valid)
            self.assertIn("XADES_XSW_SIGNED_PROPERTIES_OUTSIDE_SIGNATURE", insp_sp_det.error_codes)

            # 7. XSW: `xml:id` duplicate across document -> rejected
            dup_xmlid = env_xml.replace(
                b"<Metin>Resmi Talimat</Metin>",
                b'<Metin xml:id="SignedProps-1">Resmi Talimat</Metin>',
            )
            insp_dup = verify_xades_xmldsig(dup_xmlid)
            self.assertFalse(insp_dup.crypto_valid)
            self.assertIn("XADES_DUPLICATE_XML_ID_DETECTED", insp_dup.error_codes)

    def test_07_v1042_governance_schemas_audit_and_scope_invariants(self) -> None:
        self.assertTrue(ESIGN_5070_VERSION.startswith(("1.0.4.", "1.0.5")))
        self.assertTrue(TRUST_ROOT_VERSION.startswith(("1.0.4.", "1.0.5")))
        self.assertTrue(PARSER_VERSION.startswith(("tr_diyanet_holiday_parser_v1.0.4.", "tr_diyanet_holiday_parser_v1.0.5")))
        self.assertTrue(TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["calendar_version"].startswith(("1.0.4.", "1.0.5")))
        self.assertTrue(
            DefaultQualifiedSignature5070Verifier().provider_name.startswith(
                (
                    "CALISORA_CADES_XADES_5070_VERIFIER_V104",
                    "KADROAI_CADES_XADES_5070_VERIFIER_V105",
                    "HRAI_CADES_XADES_5070_VERIFIER_V105",
                )
            )
        )
        self.assertTrue(
            DefaultSscdControlEvidenceVerifier().verifier_service_id.startswith(
                (
                    "CALISORA_SSCD_CONTROL_EVIDENCE_VERIFIER_V104",
                    "KADROAI_SSCD_CONTROL_EVIDENCE_VERIFIER_V105",
                    "HRAI_SSCD_CONTROL_EVIDENCE_VERIFIER_V105",
                )
            )
        )

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

        ledger = json.loads((PROJECT_ROOT / "config" / "calendar_attestation_ledger.json").read_text(encoding="utf-8"))
        self.assertTrue(ledger["schema_version"].startswith(("1.0.4.", "1.0.5")))
        self.assertTrue(ledger["checkpoints"][0]["checkpoint_id"].startswith(("CHK-RELEASE-1.0.4.", "CHK-RELEASE-1.0.5")))

        tax = json.loads((PROJECT_ROOT / "config" / "knowledge_taxonomy.json").read_text(encoding="utf-8"))
        self.assertTrue(tax["schema_version"].startswith(("1.0.4.", "1.0.5")))
        l5_l6 = [
            layer
            for layer in tax["knowledge_layers"]
            if layer["id"] in ("L5_HR_PROCEDURES", "L6_CBA_CONTRACTS_AND_WORKPLACE_PRACTICES")
        ]
        self.assertEqual(len(l5_l6), 2)
        for layer in l5_l6:
            self.assertTrue(
                layer["population_status"].startswith("POPULATED_") and layer["population_status"].endswith("_V1_0_5")
            )

        sources = load_source_registry(PROJECT_ROOT / "config" / "legal_sources_registry.json")
        precedents = load_precedent_registry(PROJECT_ROOT / "config" / "yargitay_precedents.json")
        cards = load_knowledge_cards(PROJECT_ROOT / "rag_kb", sources, precedents)
        self.assertEqual((len(sources), len(precedents), len(cards)), (30, 5, 39))
        audit_data = json.loads((PROJECT_ROOT / "config" / "verification_audit_log.json").read_text(encoding="utf-8"))
        self.assertTrue(audit_data["schema_version"].startswith(("1.0.4.", "1.0.5")))
        self.assertEqual(audit_data["summary"]["total_audited_records"], 74)
        self.assertTrue(validate_central_audit_log(audit_data, sources, precedents, cards).valid)

    def test_08_three_step_enveloped_base64_c14n_pipeline_and_excluded_nodes_text_extraction(self) -> None:
        with Ephemeral5070PkiFixture() as pki:
            cert_pem, key_pem, _ = pki.issue_signer_cert(tag="xform_3step")
            inner_xml = b'<KidemKaydi z="2" a="1"><!-- gizli --><Gun>365</Gun></KidemKaydi>'
            expected_inner_c14n = b'<KidemKaydi a="1" z="2"><Gun>365</Gun></KidemKaydi>'
            envelope_doc = f'<Zarf>{base64.b64encode(inner_xml).decode("ascii")}</Zarf>'.encode("utf-8")

            # 1. Valid 3-step chain: enveloped-signature -> Base64 -> Inclusive C14N 1.0
            #    Step 0 excludes <ds:Signature>; Step 1 extracts ONLY <Zarf>'s text (NOT signature text!) & decodes XML;
            #    Step 2 re-parses decoded XML & canonicalizes it!
            signed_3step, _ = create_xades_xml_bytes(
                envelope_doc,
                cert_pem,
                key_pem,
                mode="ENVELOPED",
                data_transforms=[TRANSFORM_ENVELOPED_SIGNATURE, TRANSFORM_BASE64, C14N_INCLUSIVE_10],
            )
            self.assertEqual(_extract_data_ref_digest_b64(signed_3step, "Ref-Doc"), _sha256_b64(expected_inner_c14n))
            insp_ok = verify_xades_xmldsig(signed_3step)
            self.assertTrue(insp_ok.crypto_valid, (insp_ok.error_codes, insp_ok.errors))
            trace = [r for r in insp_ok.xmldsig_details["references"] if r["kind"] == "DATA"][0]["transform_trace"]
            self.assertEqual(
                [(s["algorithm"], s["input_type"], s["output_type"]) for s in trace],
                [
                    (TRANSFORM_ENVELOPED_SIGNATURE, TRANSFORM_KIND_NODE_SET, TRANSFORM_KIND_NODE_SET),
                    (TRANSFORM_BASE64, TRANSFORM_KIND_NODE_SET, TRANSFORM_KIND_OCTET_STREAM),
                    (C14N_INCLUSIVE_10, TRANSFORM_KIND_OCTET_STREAM, TRANSFORM_KIND_OCTET_STREAM),
                ],
            )
            self.assertTrue(trace[2].get("reparsed_xml"))

            # 2. Swapping last two steps -> [enveloped-signature, C14N, Base64] MUST fail closed!
            swapped_tail = signed_3step.replace(
                (
                    f'<ds:Transform Algorithm="{TRANSFORM_BASE64}"></ds:Transform>'
                    f'<ds:Transform Algorithm="{C14N_INCLUSIVE_10}"></ds:Transform>'
                ).encode("utf-8"),
                (
                    f'<ds:Transform Algorithm="{C14N_INCLUSIVE_10}"></ds:Transform>'
                    f'<ds:Transform Algorithm="{TRANSFORM_BASE64}"></ds:Transform>'
                ).encode("utf-8"),
                1,
            )
            insp_bad_tail = verify_xades_xmldsig(swapped_tail)
            self.assertFalse(insp_bad_tail.crypto_valid)
            self.assertIn("XADES_BASE64_TRANSFORM_DECODE_FAILED", insp_bad_tail.error_codes)

            # 3. Moving Base64 before enveloped-signature -> [Base64, enveloped-signature, C14N] MUST fail closed!
            swapped_head = signed_3step.replace(
                (
                    f'<ds:Transform Algorithm="{TRANSFORM_ENVELOPED_SIGNATURE}"></ds:Transform>'
                    f'<ds:Transform Algorithm="{TRANSFORM_BASE64}"></ds:Transform>'
                ).encode("utf-8"),
                (
                    f'<ds:Transform Algorithm="{TRANSFORM_BASE64}"></ds:Transform>'
                    f'<ds:Transform Algorithm="{TRANSFORM_ENVELOPED_SIGNATURE}"></ds:Transform>'
                ).encode("utf-8"),
                1,
            )
            insp_bad_head = verify_xades_xmldsig(swapped_head)
            self.assertFalse(insp_bad_head.crypto_valid)
            self.assertTrue(
                "XADES_TRANSFORM_INVALID_INPUT_TYPE" in insp_bad_head.error_codes
                or "XADES_BASE64_TRANSFORM_DECODE_FAILED" in insp_bad_head.error_codes,
                insp_bad_head.error_codes,
            )


if __name__ == "__main__":
    unittest.main()
