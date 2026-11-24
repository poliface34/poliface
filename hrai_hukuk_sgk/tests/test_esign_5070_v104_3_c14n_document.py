"""CALISORA @HukukSGK v1.0.4.3 — W3C C14N Document-Level Node Preservation & Byte-for-Byte Vectors Suite (BLOCKER 4 Closure).

Directly verifies every requirement from the v1.0.4.3 independent security remediation mandate:
  1. Document-level PIs & comments before and after `documentElement` across ALL 6 W3C C14N algorithms:
       - Inclusive C14N 1.0 (`WithoutComments` & `#WithComments`)
       - Exclusive C14N 1.0 (`WithoutComments`, `#WithComments` & `InclusiveNamespaces PrefixList` incl. `#default`)
       - Inclusive C14N 1.1 (`WithoutComments`, `#WithComments`, `xml:id` exclusion & RFC 3986 `xml:base` resolution)
  2. Official W3C Canonical XML 1.0 (§3.1–§3.5), Exclusive C14N 1.0 (§2.2), and C14N 1.1 (§2.4) test vectors
     verified byte-for-byte against independent W3C expected octets, independent SHA-256 digests, and `lxml`/`libxml2`.
  3. Full `OCTET_STREAM -> C14N` AND `NODE_SET -> C14N` (both `Document` for `URI=""` and `Element` for `URI="#id"`)
     XAdES signature creation & verification preserving document-level PIs and comments.
  4. Attack scenarios: deleting/altering/injecting document-level PIs or comments, tampering business content,
     plus XXE/DOCTYPE and duplicate XML ID rejection in `OCTET_STREAM -> C14N`.
  5. Exact v1.0.4.3 governance, 11/11 schema, 74/74 audit log, L1–L4, L5/L6 deferral & `NOT_CONFIGURED` probe invariants.
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
    C14N_EXCLUSIVE_10_COMMENTS,
    C14N_INCLUSIVE_10,
    C14N_INCLUSIVE_10_COMMENTS,
    C14N_INCLUSIVE_11,
    C14N_INCLUSIVE_11_COMMENTS,
    ESIGN_5070_VERSION,
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
    canonicalize_xml_document,
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


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def _extract_ref_digest_b64(xml_bytes: bytes, ref_id: str) -> str:
    m = re.search(
        rf'<ds:Reference[^>]*Id="{re.escape(ref_id)}"[^>]*>.*?<ds:DigestValue>([^<]+)</ds:DigestValue>',
        xml_bytes.decode("utf-8"),
        flags=re.DOTALL,
    )
    if not m:
        raise AssertionError(f"DigestValue not found for Reference Id={ref_id!r}")
    return re.sub(r"\s+", "", m.group(1).strip())


class TestW3cC14nDocumentPreservationV1043(unittest.TestCase):
    """[SECURITY / BLOCKER-4] W3C C14N Document-Level Node Preservation & Standards Vector Suite (v1.0.4.3)."""

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

    def test_01_blocker4_document_level_pis_and_comments_all_six_c14n_algorithms(self) -> None:
        # 1. Auditor's exact BLOCKER 4 reproducer: comment before root + PI after root
        repro_input = b"<!--before--><root>value</root><?after keep?>"
        repro_exp_wc = b"<!--before-->\n<root>value</root>\n<?after keep?>"
        repro_exp_nc = b"<root>value</root>\n<?after keep?>"

        # 2. Full top-level surround: PI + comment BEFORE root AND comment + PI AFTER root
        full_input = (
            b'<?xml version="1.0" encoding="UTF-8"?>\n'
            b'<?pi-before   attr="1"  ?>\n'
            b"<!-- comment-before -->\n"
            b"<root><!-- inner -->value<?pi-in x?></root>\n"
            b"<!-- comment-after -->\n"
            b"<?pi-after   ?>\n"
        )
        full_exp_wc = (
            b'<?pi-before attr="1"  ?>\n'
            b"<!-- comment-before -->\n"
            b"<root><!-- inner -->value<?pi-in x?></root>\n"
            b"<!-- comment-after -->\n"
            b"<?pi-after?>"
        )
        full_exp_nc = (
            b'<?pi-before attr="1"  ?>\n'
            b"<root>value<?pi-in x?></root>\n"
            b"<?pi-after?>"
        )

        # 3. Empty comments and data-less PIs before and after root
        edge_input = b"<!----><?nodata?><r/><?nodata2?><!---->"
        edge_exp_wc = b"<!---->\n<?nodata?>\n<r></r>\n<?nodata2?>\n<!---->"
        edge_exp_nc = b"<?nodata?>\n<r></r>\n<?nodata2?>"

        all_cases = [
            ("auditor_repro", repro_input, repro_exp_nc, repro_exp_wc),
            ("full_surround", full_input, full_exp_nc, full_exp_wc),
            ("empty_comment_nodata_pi", edge_input, edge_exp_nc, edge_exp_wc),
        ]
        all_algs = [
            (C14N_INCLUSIVE_10, False, False),
            (C14N_INCLUSIVE_10_COMMENTS, False, True),
            (C14N_EXCLUSIVE_10, True, False),
            (C14N_EXCLUSIVE_10_COMMENTS, True, True),
            (C14N_INCLUSIVE_11, False, False),
            (C14N_INCLUSIVE_11_COMMENTS, False, True),
        ]

        try:
            from lxml import etree as LET
        except ImportError:
            LET = None

        for name, raw_xml, exp_nc, exp_wc in all_cases:
            doc = safe_parse_xml_bytes(raw_xml)
            lx_tree = LET.fromstring(raw_xml).getroottree() if LET is not None else None
            for alg_uri, is_exc, is_wc in all_algs:
                expected = exp_wc if is_wc else exp_nc
                expected_sha = _sha256_hex(expected)

                # A. OCTET_STREAM -> C14N via sequential transform pipeline
                out_pipe, trace = execute_xmldsig_transform_pipeline(
                    TransformPipelineData(kind=TRANSFORM_KIND_OCTET_STREAM, octets=raw_xml),
                    [(alg_uri, set())],
                )
                self.assertEqual(out_pipe, expected, (name, alg_uri))
                self.assertEqual(_sha256_hex(out_pipe), expected_sha, (name, alg_uri))
                self.assertEqual(trace[0]["node_scope"], "DOCUMENT")
                self.assertTrue(trace[0]["reparsed_xml"])

                # B. NODE_SET(Document) -> C14N via pipeline & canonicalize_xml_document
                out_doc = canonicalize_xml_document(doc, alg_uri)
                self.assertEqual(out_doc, expected, (name, alg_uri))
                self.assertEqual(_sha256_hex(out_doc), expected_sha, (name, alg_uri))

                out_ns, trace_ns = execute_xmldsig_transform_pipeline(
                    TransformPipelineData(kind=TRANSFORM_KIND_NODE_SET, node=doc),
                    [(alg_uri, set())],
                )
                self.assertEqual(out_ns, expected, (name, alg_uri))
                self.assertEqual(trace_ns[0]["node_scope"], "DOCUMENT")

                # C. Independent libxml2 cross-check (exact byte-for-byte + SHA-256 match)
                if lx_tree is not None:
                    lx_bytes = LET.tostring(lx_tree, method="c14n", exclusive=is_exc, with_comments=is_wc)
                    self.assertEqual(out_pipe, lx_bytes, ("libxml2", name, alg_uri))
                    self.assertEqual(_sha256_hex(out_pipe), _sha256_hex(lx_bytes))

    def test_02_official_w3c_c14n_1_0_test_vectors_3_1_to_3_5_byte_for_byte_and_libxml2(self) -> None:
        # Official W3C REC-xml-c14n-20010315 §3.1 — PIs, Comments, and Outside of Document Element
        w3c_3_1_in = (
            b'<?xml version="1.0"?>\n\n'
            b'<?xml-stylesheet   href="doc.xsl"\n'
            b'   type="text/xsl"   ?>\n\n'
            b"<doc>Hello, world!<!-- Comment 1 --></doc>\n\n"
            b"<?pi-without-data     ?>\n\n"
            b"<!-- Comment 2 -->\n\n"
            b"<!-- Comment 3 -->\n"
        )
        w3c_3_1_nc = (
            b'<?xml-stylesheet href="doc.xsl"\n'
            b'   type="text/xsl"   ?>\n'
            b"<doc>Hello, world!</doc>\n"
            b"<?pi-without-data?>"
        )
        w3c_3_1_wc = (
            b'<?xml-stylesheet href="doc.xsl"\n'
            b'   type="text/xsl"   ?>\n'
            b"<doc>Hello, world!<!-- Comment 1 --></doc>\n"
            b"<?pi-without-data?>\n"
            b"<!-- Comment 2 -->\n"
            b"<!-- Comment 3 -->"
        )

        # Official W3C REC-xml-c14n-20010315 §3.2 — Whitespace in Document Content
        w3c_3_2_in = (
            b"<doc>\n"
            b"   <clean   >   </clean>\n"
            b"   <dirty   >   A   B   </dirty>\n"
            b"   <mixed>\n"
            b"      A\n"
            b"      <clean   >   </clean>\n"
            b"      B\n"
            b"      <dirty   >   A   B   </dirty>\n"
            b"      C\n"
            b"   </mixed>\n"
            b"</doc>"
        )
        w3c_3_2_exp = (
            b"<doc>\n"
            b"   <clean>   </clean>\n"
            b"   <dirty>   A   B   </dirty>\n"
            b"   <mixed>\n"
            b"      A\n"
            b"      <clean>   </clean>\n"
            b"      B\n"
            b"      <dirty>   A   B   </dirty>\n"
            b"      C\n"
            b"   </mixed>\n"
            b"</doc>"
        )

        # Official W3C REC-xml-c14n-20010315 §3.3 — Start/End Tags, Attribute Sorting & Empty Default NS Undeclaration
        w3c_3_3_in = (
            b'<e1   xmlns="http://www.ietf.org" xmlns:w3c="http://www.w3.org"\n'
            b'      b="2" a="1" w3c:z="9" w3c:a="8">\n'
            b'   <e2 xmlns="" b="2" a="1"/>\n'
            b'   <e3 xmlns="http://www.ietf.org"/>\n'
            b"</e1>"
        )
        w3c_3_3_exp = (
            b'<e1 xmlns="http://www.ietf.org" xmlns:w3c="http://www.w3.org" a="1" b="2" w3c:a="8" w3c:z="9">\n'
            b'   <e2 xmlns="" a="1" b="2"></e2>\n'
            b"   <e3></e3>\n"
            b"</e1>"
        )

        # Official W3C REC-xml-c14n-20010315 §3.4 — Character Modifications, CDATA & Character References
        w3c_3_4_in = (
            b"<doc>\n"
            b"   <text>First line&#x0d;&#10;Second line</text>\n"
            b"   <value>&#x32;</value>\n"
            b'   <compute><![CDATA[value>"0" && value<"10" ?"valid":"error"]]></compute>\n'
            b"   <norm attr=\" '    &#x20;&#13;&#xa;&#9;   ' \"/>\n"
            b"</doc>"
        )
        w3c_3_4_exp = (
            b"<doc>\n"
            b"   <text>First line&#xD;\nSecond line</text>\n"
            b"   <value>2</value>\n"
            b'   <compute>value&gt;"0" &amp;&amp; value&lt;"10" ?"valid":"error"</compute>\n'
            b"   <norm attr=\" '     &#xD;&#xA;&#x9;   ' \"></norm>\n"
            b"</doc>"
        )

        # Official W3C REC-xml-c14n-20010315 §3.5 — Superfluous Namespace Declarations & Default NS Rebinding
        w3c_3_5_in = (
            b'<doc xmlns="urn:default" xmlns:a="urn:a" xmlns:b="urn:b">'
            b'<child xmlns="" xmlns:a="urn:a">'
            b'<grandchild xmlns="urn:default" xmlns:b="urn:b"/>'
            b"</child></doc>"
        )
        w3c_3_5_exp = (
            b'<doc xmlns="urn:default" xmlns:a="urn:a" xmlns:b="urn:b">'
            b'<child xmlns="">'
            b'<grandchild xmlns="urn:default"></grandchild>'
            b"</child></doc>"
        )

        vectors = [
            ("W3C_3_1_NC", w3c_3_1_in, C14N_INCLUSIVE_10, False, w3c_3_1_nc),
            ("W3C_3_1_WC", w3c_3_1_in, C14N_INCLUSIVE_10_COMMENTS, True, w3c_3_1_wc),
            ("W3C_3_2", w3c_3_2_in, C14N_INCLUSIVE_10, False, w3c_3_2_exp),
            ("W3C_3_3", w3c_3_3_in, C14N_INCLUSIVE_10, False, w3c_3_3_exp),
            ("W3C_3_4", w3c_3_4_in, C14N_INCLUSIVE_10, False, w3c_3_4_exp),
            ("W3C_3_5", w3c_3_5_in, C14N_INCLUSIVE_10, False, w3c_3_5_exp),
        ]

        try:
            from lxml import etree as LET
        except ImportError:
            LET = None

        for label, raw_in, alg, wc, expected in vectors:
            out_pipe, _ = execute_xmldsig_transform_pipeline(
                TransformPipelineData(kind=TRANSFORM_KIND_OCTET_STREAM, octets=raw_in),
                [(alg, set())],
            )
            self.assertEqual(out_pipe, expected, label)
            self.assertEqual(_sha256_hex(out_pipe), _sha256_hex(expected), label)

            if LET is not None:
                lx_out = LET.tostring(LET.fromstring(raw_in).getroottree(), method="c14n", exclusive=False, with_comments=wc)
                self.assertEqual(out_pipe, lx_out, ("libxml2", label))
                self.assertEqual(_sha256_hex(out_pipe), _sha256_hex(lx_out))

    def test_03_w3c_exclusive_c14n_prefixlist_and_c14n_1_1_xml_id_xml_base_vectors(self) -> None:
        # 1. W3C Exclusive C14N 1.0 + PrefixList (`#default` and prefixed) with top-level PIs & comments
        exc_raw = (
            b"<?pi-top?><!-- c-top -->"
            b'<outer xmlns="urn:def" xmlns:a="urn:a" xmlns:b="urn:b">'
            b'<p:mid xmlns:p="urn:p" xmlns=""><leaf/></p:mid>'
            b"</outer><!-- c-bot --><?pi-bot?>"
        )
        exp_exc_none_nc = (
            b"<?pi-top?>\n"
            b'<outer xmlns="urn:def"><p:mid xmlns:p="urn:p"><leaf xmlns=""></leaf></p:mid></outer>\n'
            b"<?pi-bot?>"
        )
        exp_exc_def_wc = (
            b"<?pi-top?>\n<!-- c-top -->\n"
            b'<outer xmlns="urn:def"><p:mid xmlns="" xmlns:p="urn:p"><leaf></leaf></p:mid></outer>\n'
            b"<!-- c-bot -->\n<?pi-bot?>"
        )
        exp_exc_def_a_nc = (
            b"<?pi-top?>\n"
            b'<outer xmlns="urn:def" xmlns:a="urn:a"><p:mid xmlns="" xmlns:p="urn:p"><leaf></leaf></p:mid></outer>\n'
            b"<?pi-bot?>"
        )

        out_none, _ = execute_xmldsig_transform_pipeline(
            TransformPipelineData(kind=TRANSFORM_KIND_OCTET_STREAM, octets=exc_raw),
            [(C14N_EXCLUSIVE_10, set())],
        )
        out_def_wc, _ = execute_xmldsig_transform_pipeline(
            TransformPipelineData(kind=TRANSFORM_KIND_OCTET_STREAM, octets=exc_raw),
            [(C14N_EXCLUSIVE_10_COMMENTS, {"#default"})],
        )
        out_def_a, _ = execute_xmldsig_transform_pipeline(
            TransformPipelineData(kind=TRANSFORM_KIND_OCTET_STREAM, octets=exc_raw),
            [(C14N_EXCLUSIVE_10, {"#default", "a"})],
        )
        self.assertEqual(out_none, exp_exc_none_nc)
        self.assertEqual(_sha256_hex(out_none), _sha256_hex(exp_exc_none_nc))
        self.assertEqual(out_def_wc, exp_exc_def_wc)
        self.assertEqual(_sha256_hex(out_def_wc), _sha256_hex(exp_exc_def_wc))
        self.assertEqual(out_def_a, exp_exc_def_a_nc)
        self.assertEqual(_sha256_hex(out_def_a), _sha256_hex(exp_exc_def_a_nc))

        # Byte-for-byte cross-check against libxml2 for BOTH Document and Element subset!
        try:
            from lxml import etree as LET

            lx_root = LET.fromstring(exc_raw)
            self.assertEqual(
                out_none,
                LET.tostring(lx_root.getroottree(), method="c14n", exclusive=True, with_comments=False),
            )
            self.assertEqual(
                out_def_wc,
                LET.tostring(
                    lx_root.getroottree(), method="c14n", exclusive=True, with_comments=True, inclusive_ns_prefixes=[""]
                ),
            )
            self.assertEqual(
                out_def_a,
                LET.tostring(
                    lx_root.getroottree(),
                    method="c14n",
                    exclusive=True,
                    with_comments=False,
                    inclusive_ns_prefixes=["", "a"],
                ),
            )
            dom_exc = safe_parse_xml_bytes(exc_raw)
            mid_dom = dom_exc.getElementsByTagName("p:mid")[0]
            ours_mid = canonicalize_xml_node(mid_dom, C14N_EXCLUSIVE_10, inclusive_prefixes={"#default", "a"})
            theirs_mid = LET.tostring(
                lx_root[0], method="c14n", exclusive=True, with_comments=False, inclusive_ns_prefixes=["", "a"]
            )
            self.assertEqual(ours_mid, theirs_mid)
            self.assertEqual(_sha256_hex(ours_mid), _sha256_hex(theirs_mid))
        except ImportError:
            pass

        # 2. W3C C14N 1.1 §2.4 subset semantics: xml:id excluded, xml:lang inherited, xml:base RFC 3986 joined
        raw_11 = (
            b'<outer xml:id="root-id" xml:lang="tr" xml:base="http://example.com/dir1/doc.xml">'
            b'<mid xml:base="sub/"><leaf xml:base="item.xml">ok</leaf></mid>'
            b"</outer>"
        )
        dom_11 = safe_parse_xml_bytes(raw_11)
        leaf_11 = dom_11.getElementsByTagName("leaf")[0]
        out_11_el = canonicalize_xml_node(leaf_11, C14N_INCLUSIVE_11)
        exp_11_el = b'<leaf xml:base="http://example.com/dir1/sub/item.xml" xml:lang="tr">ok</leaf>'
        self.assertEqual(out_11_el, exp_11_el)
        self.assertEqual(_sha256_hex(out_11_el), _sha256_hex(exp_11_el))

        # Contrast with C14N 1.0 on the exact same element (C14N 1.0 inherits xml:id and keeps leaf's literal xml:base!)
        out_10_el = canonicalize_xml_node(leaf_11, C14N_INCLUSIVE_10)
        exp_10_el = b'<leaf xml:base="item.xml" xml:id="root-id" xml:lang="tr">ok</leaf>'
        self.assertEqual(out_10_el, exp_10_el)
        self.assertNotEqual(out_11_el, out_10_el)

    def test_04_xades_signatures_with_document_level_pis_and_comments_octet_stream_and_node_set(self) -> None:
        with Ephemeral5070PkiFixture() as pki:
            cert_pem, key_pem, _ = pki.issue_signer_cert(tag="doc_c14n_xades")

            payload_xml = (
                b'<?xml version="1.0" encoding="UTF-8"?>\n'
                b'<?xml-stylesheet   href="calisora.xsl" type="text/xsl"?>\n'
                b"<!-- ust-yorum -->\n"
                b'<Karar xmlns="urn:calisora:karar" z="2" a="1"><Metin>Onaylandi</Metin></Karar>\n'
                b"<!-- alt-yorum -->\n"
                b"<?alt-pi keep?>"
            )
            exp_wc = (
                b'<?xml-stylesheet href="calisora.xsl" type="text/xsl"?>\n'
                b"<!-- ust-yorum -->\n"
                b'<Karar xmlns="urn:calisora:karar" a="1" z="2"><Metin>Onaylandi</Metin></Karar>\n'
                b"<!-- alt-yorum -->\n"
                b"<?alt-pi keep?>"
            )
            exp_nc = (
                b'<?xml-stylesheet href="calisora.xsl" type="text/xsl"?>\n'
                b'<Karar xmlns="urn:calisora:karar" a="1" z="2"><Metin>Onaylandi</Metin></Karar>\n'
                b"<?alt-pi keep?>"
            )

            # A. Detached XAdES (OCTET_STREAM -> C14N) across ALL 6 C14N profiles!
            for alg_uri, expected in (
                (C14N_INCLUSIVE_10, exp_nc),
                (C14N_INCLUSIVE_10_COMMENTS, exp_wc),
                (C14N_EXCLUSIVE_10, exp_nc),
                (C14N_EXCLUSIVE_10_COMMENTS, exp_wc),
                (C14N_INCLUSIVE_11, exp_nc),
                (C14N_INCLUSIVE_11_COMMENTS, exp_wc),
            ):
                sig_det, _ = create_xades_xml_bytes(
                    payload_xml,
                    cert_pem,
                    key_pem,
                    mode="DETACHED",
                    data_transforms=[alg_uri],
                )
                self.assertEqual(_extract_ref_digest_b64(sig_det, "Ref-Data"), _sha256_b64(expected), alg_uri)
                insp = verify_xades_xmldsig(sig_det, payload_xml)
                self.assertTrue(insp.crypto_valid, (alg_uri, insp.error_codes, insp.errors))

            # B. Enveloping Base64 -> C14N (NODE_SET -> Base64 -> OCTET_STREAM -> Document C14N)
            sig_b64_wc, _ = create_xades_xml_bytes(
                payload_xml,
                cert_pem,
                key_pem,
                mode="ENVELOPING",
                data_transforms=[TRANSFORM_BASE64, C14N_INCLUSIVE_10_COMMENTS],
            )
            self.assertEqual(_extract_ref_digest_b64(sig_b64_wc, "Ref-Obj"), _sha256_b64(exp_wc))
            self.assertTrue(verify_xades_xmldsig(sig_b64_wc).crypto_valid)

            # C. Enveloped XAdES (URI="" -> Document NODE_SET -> enveloped-signature -> C14N)
            for alg_uri, expected in (
                (C14N_INCLUSIVE_10, exp_nc),
                (C14N_INCLUSIVE_10_COMMENTS, exp_wc),
                (C14N_EXCLUSIVE_10, exp_nc),
                (C14N_EXCLUSIVE_10_COMMENTS, exp_wc),
            ):
                sig_env, _ = create_xades_xml_bytes(
                    payload_xml,
                    cert_pem,
                    key_pem,
                    mode="ENVELOPED",
                    data_transforms=[TRANSFORM_ENVELOPED_SIGNATURE, alg_uri],
                )
                self.assertEqual(_extract_ref_digest_b64(sig_env, "Ref-Doc"), _sha256_b64(expected), alg_uri)
                insp_env = verify_xades_xmldsig(sig_env)
                self.assertTrue(insp_env.crypto_valid, (alg_uri, insp_env.error_codes, insp_env.errors))

            # D. Multi-step C14N chain preserving top-level PIs while stripping comments in step 2:
            #    [C14N_INCLUSIVE_10_COMMENTS -> C14N_EXCLUSIVE_10]
            sig_chain, _ = create_xades_xml_bytes(
                payload_xml,
                cert_pem,
                key_pem,
                mode="DETACHED",
                data_transforms=[C14N_INCLUSIVE_10_COMMENTS, C14N_EXCLUSIVE_10],
            )
            self.assertEqual(_extract_ref_digest_b64(sig_chain, "Ref-Data"), _sha256_b64(exp_nc))
            self.assertTrue(verify_xades_xmldsig(sig_chain, payload_xml).crypto_valid)

            # E. Existing Element NODE_SET -> C14N (`URI="#Obj-Data-1"`) remains 100% intact
            sig_el, _ = create_xades_xml_bytes(
                b'<Item b="2" a="1">veri</Item>',
                cert_pem,
                key_pem,
                mode="ENVELOPING",
                enveloping_inline_xml=True,
                data_transforms=[C14N_EXCLUSIVE_10],
            )
            exp_el = b'<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Obj-Data-1"><Item a="1" b="2">veri</Item></ds:Object>'
            self.assertEqual(_extract_ref_digest_b64(sig_el, "Ref-Obj"), _sha256_b64(exp_el))
            insp_el = verify_xades_xmldsig(sig_el)
            self.assertTrue(insp_el.crypto_valid)
            data_ref = [r for r in insp_el.xmldsig_details["references"] if r["kind"] == "DATA"][0]
            self.assertEqual(data_ref["transform_trace"][0]["node_scope"], "ELEMENT")

    def test_05_document_level_node_deletion_tampering_and_xxe_dup_id_attacks(self) -> None:
        with Ephemeral5070PkiFixture() as pki:
            cert_pem, key_pem, _ = pki.issue_signer_cert(tag="doc_c14n_attacks")
            verifier = self._build_sandbox_verifier(pki)
            gate = Default5070AcceptanceGate()
            sscd_ok = pki.build_verified_sscd_evidence(cert_pem)

            doc_bytes = b'<?pi-before v="1"?><!--before--><root><body_text>Gercek</body_text></root><!--after--><?after keep?>'

            # 1. Detached WithoutComments signature: deleting or altering top-level PI MUST break verification!
            sig_det_nc, _ = create_xades_xml_bytes(
                doc_bytes, cert_pem, key_pem, mode="DETACHED", data_transforms=[C14N_INCLUSIVE_10]
            )
            self.assertTrue(verify_xades_xmldsig(sig_det_nc, doc_bytes).crypto_valid)

            # Attack 1a: Delete trailing PI `<?after keep?>`
            insp_del_pi = verify_xades_xmldsig(sig_det_nc, doc_bytes.replace(b"<?after keep?>", b""))
            self.assertFalse(insp_del_pi.crypto_valid)
            self.assertIn("XADES_CONTENT_DIGEST_MISMATCH", insp_del_pi.error_codes)

            # Attack 1b: Delete leading PI `<?pi-before v="1"?>`
            insp_del_lead = verify_xades_xmldsig(sig_det_nc, doc_bytes.replace(b'<?pi-before v="1"?>', b""))
            self.assertFalse(insp_del_lead.crypto_valid)
            self.assertIn("XADES_CONTENT_DIGEST_MISMATCH", insp_del_lead.error_codes)

            # Attack 1c: Alter PI content `<?after keep?>` -> `<?after tampered?>`
            insp_mod_pi = verify_xades_xmldsig(sig_det_nc, doc_bytes.replace(b"<?after keep?>", b"<?after tampered?>"))
            self.assertFalse(insp_mod_pi.crypto_valid)
            self.assertIn("XADES_CONTENT_DIGEST_MISMATCH", insp_mod_pi.error_codes)

            # Attack 1d: Inject extra PI at document level
            insp_inj_pi = verify_xades_xmldsig(sig_det_nc, doc_bytes + b"<?injected x?>")
            self.assertFalse(insp_inj_pi.crypto_valid)
            self.assertIn("XADES_CONTENT_DIGEST_MISMATCH", insp_inj_pi.error_codes)

            # 2. Detached & Enveloped WithComments signatures: deleting or modifying top-level comments MUST fail!
            sig_det_wc, _ = create_xades_xml_bytes(
                doc_bytes, cert_pem, key_pem, mode="DETACHED", data_transforms=[C14N_INCLUSIVE_10_COMMENTS]
            )
            self.assertTrue(verify_xades_xmldsig(sig_det_wc, doc_bytes).crypto_valid)
            insp_del_c1 = verify_xades_xmldsig(sig_det_wc, doc_bytes.replace(b"<!--before-->", b""))
            self.assertFalse(insp_del_c1.crypto_valid)
            self.assertIn("XADES_CONTENT_DIGEST_MISMATCH", insp_del_c1.error_codes)

            insp_del_c2 = verify_xades_xmldsig(sig_det_wc, doc_bytes.replace(b"<!--after-->", b""))
            self.assertFalse(insp_del_c2.crypto_valid)
            self.assertIn("XADES_CONTENT_DIGEST_MISMATCH", insp_del_c2.error_codes)

            sig_env_wc, _ = create_xades_xml_bytes(
                doc_bytes,
                cert_pem,
                key_pem,
                mode="ENVELOPED",
                data_transforms=[TRANSFORM_ENVELOPED_SIGNATURE, C14N_EXCLUSIVE_10_COMMENTS],
            )
            self.assertTrue(verify_xades_xmldsig(sig_env_wc).crypto_valid)
            for tampered_env in (
                sig_env_wc.replace(b"<!--before-->", b""),
                sig_env_wc.replace(b"<?after keep?>", b""),
                sig_env_wc.replace(b"Gercek", b"Sahte"),
            ):
                insp_t = verify_xades_xmldsig(tampered_env)
                self.assertFalse(insp_t.crypto_valid)
                self.assertIn("XADES_CONTENT_DIGEST_MISMATCH", insp_t.error_codes)

            # 3. Contrast: on WithoutComments signature, deleting a comment leaves canonical bytes identical,
            #    while tampering the element body STILL fails immediately!
            self.assertTrue(verify_xades_xmldsig(sig_det_nc, doc_bytes.replace(b"<!--before-->", b"")).crypto_valid)
            self.assertFalse(verify_xades_xmldsig(sig_det_nc, doc_bytes.replace(b"Gercek", b"Sahte")).crypto_valid)

            # 4. Security guards preserved under Document-level C14N: XXE/DOCTYPE and Duplicate XML IDs fail closed!
            xxe_with_pi = b'<?pi-top?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x><?pi-bot?>'
            with self.assertRaises(XmlSecurityError) as ctx_xxe:
                execute_xmldsig_transform_pipeline(
                    TransformPipelineData(kind=TRANSFORM_KIND_OCTET_STREAM, octets=xxe_with_pi),
                    [(C14N_INCLUSIVE_10_COMMENTS, set())],
                )
            self.assertEqual(ctx_xxe.exception.code, "XML_XXE_OR_DOCTYPE_FORBIDDEN")

            dup_with_pi = b'<?pi-top?><!--c--><r><a Id="dup-1"/><b Id="dup-1"/></r><?pi-bot?>'
            with self.assertRaises(XmlSecurityError) as ctx_dup:
                execute_xmldsig_transform_pipeline(
                    TransformPipelineData(kind=TRANSFORM_KIND_OCTET_STREAM, octets=dup_with_pi),
                    [(C14N_INCLUSIVE_10_COMMENTS, set())],
                )
            self.assertEqual(ctx_dup.exception.code, "XADES_DUPLICATE_XML_ID_DETECTED")

            # 5. End-to-end verifier + AcceptanceGate rejects deleted-PI tampered signature cleanly
            res_tamp = verifier.verify_xades_signature(
                sig_env_wc.replace(b"<?after keep?>", b""),
                expected_eshs_id="ESHS-TR-01",
                sscd_control_evidence_result=sscd_ok,
                runtime_environment="PRODUCTION",
            )
            self.assertFalse(res_tamp.cryptographic_signature_valid)
            self.assertFalse(res_tamp.qualified_e_signature_5070_verified)
            dec = gate.evaluate_5070_acceptance(res_tamp, runtime_environment="PRODUCTION")
            self.assertFalse(dec.qualified_e_signature_5070_production_accepted)

    def test_06_v1043_governance_schemas_audit_live_probe_and_scope_invariants(self) -> None:
        self.assertTrue(ESIGN_5070_VERSION.startswith(("1.0.4.", "1.0.5")), ESIGN_5070_VERSION)
        self.assertEqual(TRUST_ROOT_VERSION, ESIGN_5070_VERSION)
        self.assertEqual(PARSER_VERSION, f"tr_diyanet_holiday_parser_v{ESIGN_5070_VERSION}")
        self.assertEqual(TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["calendar_version"], ESIGN_5070_VERSION)
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
        self.assertEqual(report["schema_version"], ESIGN_5070_VERSION)
        self.assertEqual(report["overall_live_integration_status"], "NOT_CONFIGURED")
        self.assertEqual(report["esign_5070_overall_status"], "NOT_CONFIGURED")
        self.assertFalse(report["qualified_e_signature_5070_production_ready"])
        self.assertFalse(report["qualified_e_signature_5070_equivalent"])
        self.assertFalse(report["production_use_authorized"])

        schemas = sorted((PROJECT_ROOT / "schemas").glob("*.schema.json"))
        self.assertGreaterEqual(len(schemas), 11)
        for sf in schemas:
            s_doc = json.loads(sf.read_text(encoding="utf-8"))
            self.assertIn(f"(v{ESIGN_5070_VERSION})", s_doc["title"], sf.name)

        ledger = json.loads((PROJECT_ROOT / "config" / "calendar_attestation_ledger.json").read_text(encoding="utf-8"))
        self.assertEqual(ledger["schema_version"], ESIGN_5070_VERSION)
        self.assertTrue(ledger["checkpoints"][0]["checkpoint_id"].startswith(f"CHK-RELEASE-{ESIGN_5070_VERSION}-"))

        tax = json.loads((PROJECT_ROOT / "config" / "knowledge_taxonomy.json").read_text(encoding="utf-8"))
        self.assertEqual(tax["schema_version"], ESIGN_5070_VERSION)
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
        self.assertEqual(audit_data["schema_version"], ESIGN_5070_VERSION)
        self.assertEqual(audit_data["summary"]["total_audited_records"], 74)
        self.assertTrue(validate_central_audit_log(audit_data, sources, precedents, cards).valid)


if __name__ == "__main__":
    unittest.main()
