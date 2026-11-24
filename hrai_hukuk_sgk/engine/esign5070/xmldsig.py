"""Standards-Compliant W3C XMLDSig & ETSI EN 319 132 XAdES Canonicalization, Sequential Transform Pipeline & Anti-XSW Engine (v1.0.4.4).

Closes BLOCKER 2 (v1.0.4.1), BLOCKER 3 (v1.0.4.2) & BLOCKER 4 (v1.0.4.3) from the independent security reviews
using ZERO external pip dependencies (Python stdlib `xml.dom.minidom` + `xml.dom.expatbuilder` + OpenSSL 3):
  1. Spec-exact W3C Canonicalization (`CanonicalizationMethod`) at BOTH XML `Document` AND `Element` levels:
       - Inclusive C14N 1.0 (`http://www.w3.org/TR/2001/REC-xml-c14n-20010315`, `#WithComments`)
       - Exclusive C14N 1.0 (`http://www.w3.org/2001/10/xml-exc-c14n#`, `#WithComments`, including `PrefixList`)
       - Inclusive C14N 1.1 (`http://www.w3.org/2006/12/xml-c14n11`, `#WithComments`, `xml:id` exclusion & `xml:base` join)
       - Preserves document-level Processing Instructions before (`<?pi?>\n`) and after (`\n<?pi?>`) the root element
         in ALL C14N profiles, preserves document-level comments in `#WithComments` profiles, and strips comments
         while retaining PIs in non-comment profiles (W3C C14N 1.0 §2.3 & §3.1 — BLOCKER 4 Closure).
     Unsupported or missing `CanonicalizationMethod` URIs fail closed.
  2. Declared `SignatureMethod` cryptographic verification (NO hardcoded SHA-256):
       - RSA PKCS#1 v1.5: `rsa-sha256`, `rsa-sha384`, `rsa-sha512`
       - RSA-PSS (RFC 6931/9231): `sha256-rsa-MGF1`, `sha384-rsa-MGF1`, `sha512-rsa-MGF1`
       - ECDSA (IEEE P1363 `r||s` per W3C XMLDSig 1.1 §6.4.2): `ecdsa-sha256`, `ecdsa-sha384`, `ecdsa-sha512`
     Weak/legacy/symmetric algorithms (`rsa-sha1`, `dsa-sha1`, `hmac-*`, `md5`, unknown) fail closed, and
     key-type mismatches (e.g., EC key with RSA SignatureMethod) fail closed.
  3. True Sequential Typed `Transforms` Pipeline (W3C XMLDSig §4.4.3.4 & §6.6, v1.0.4.2 BLOCKER 3 + v1.0.4.3 BLOCKER 4):
       - Every `<ds:Transform>` executes strictly in declared XML document order where the output of
         Transform N becomes the exact input of Transform N+1 (`TransformPipelineData`: `NODE_SET` vs `OCTET_STREAM`).
       - `enveloped-signature`: requires `NODE_SET` input (fails closed on `OCTET_STREAM` with
         `XADES_TRANSFORM_INVALID_INPUT_TYPE`), excludes only the verifying `<ds:Signature>`, outputs `NODE_SET`.
       - C14N transforms: serialize `NODE_SET` (`Document` or `Element`) -> `OCTET_STREAM`, or safely re-parse
         `OCTET_STREAM` via `safe_parse_xml_bytes` (with XXE/DOCTYPE & duplicate-ID guards) -> canonicalize the
         FULL `Document` (preserving top-level PIs & `#WithComments` comments) -> `OCTET_STREAM`.
       - `base64` transform: per W3C XMLDSig §6.6.2, extracts text nodes from `NODE_SET` (skipping excluded
         nodes) or decodes `OCTET_STREAM` strictly (`validate=True`) -> `OCTET_STREAM`.
       - XSLT, XPath, XPath Filter 2, unknown transforms, invalid input-type transitions, and excessive
         transform counts fail closed.
  4. Strict Anti-XML Signature Wrapping (XSW) & Duplicate-ID Defense:
       - Global scan rejecting ANY duplicate `Id`/`ID`/`id`/`xml:id` anywhere in the document (`XADES_DUPLICATE_XML_ID_DETECTED`).
       - Rejects multiple or nested `<ds:Signature>` elements (`XADES_XSW_MULTIPLE_OR_NESTED_SIGNATURES`).
       - Rejects data references hidden inside `<ds:Signature>` on enveloped documents (`XADES_XSW_DATA_REF_HIDDEN_INSIDE_SIGNATURE`).
       - Rejects unsigned sibling/ancestor business content outside the verified signed node scope (`XADES_XSW_UNSIGNED_CONTENT_OUTSIDE_SIGNED_SCOPE`).
       - Ensures `<xades:SignedProperties>` resides strictly inside the verifying `<ds:Signature>/<ds:Object>/<xades:QualifyingProperties>` and is covered by a verified `<ds:Reference>`.
       - Blocks DOCTYPE/ENTITY/XXE at both raw-byte and Expat parser levels (`XML_XXE_OR_DOCTYPE_FORBIDDEN`).
"""

from __future__ import annotations

import base64
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any
from urllib.parse import urljoin
from xml.dom import Node
from xml.dom.expatbuilder import ExpatBuilderNS
from xml.dom.minidom import Document, Element

DS_NS = "http://www.w3.org/2000/09/xmldsig#"
XADES_NS = "http://uri.etsi.org/01903/v1.3.2#"
XADES141_NS = "http://uri.etsi.org/01903/v1.4.1#"
EC_NS = "http://www.w3.org/2001/10/xml-exc-c14n#"
XML_NS = "http://www.w3.org/XML/1998/namespace"
XMLNS_NS = "http://www.w3.org/2000/xmlns/"

C14N_INCLUSIVE_10 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
C14N_INCLUSIVE_10_COMMENTS = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
C14N_EXCLUSIVE_10 = "http://www.w3.org/2001/10/xml-exc-c14n#"
C14N_EXCLUSIVE_10_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
C14N_INCLUSIVE_11 = "http://www.w3.org/2006/12/xml-c14n11"
C14N_INCLUSIVE_11_COMMENTS = "http://www.w3.org/2006/12/xml-c14n11#WithComments"

TRANSFORM_ENVELOPED_SIGNATURE = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
TRANSFORM_BASE64 = "http://www.w3.org/2000/09/xmldsig#base64"

TRANSFORM_KIND_NODE_SET = "NODE_SET"
TRANSFORM_KIND_OCTET_STREAM = "OCTET_STREAM"
MAX_TRANSFORMS_PER_REFERENCE = 16

SUPPORTED_C14N_METHODS: dict[str, dict[str, Any]] = {
    C14N_INCLUSIVE_10: {"exclusive": False, "with_comments": False, "v11": False},
    C14N_INCLUSIVE_10_COMMENTS: {"exclusive": False, "with_comments": True, "v11": False},
    C14N_EXCLUSIVE_10: {"exclusive": True, "with_comments": False, "v11": False},
    C14N_EXCLUSIVE_10_COMMENTS: {"exclusive": True, "with_comments": True, "v11": False},
    C14N_INCLUSIVE_11: {"exclusive": False, "with_comments": False, "v11": True},
    C14N_INCLUSIVE_11_COMMENTS: {"exclusive": False, "with_comments": True, "v11": True},
}

SUPPORTED_DIGEST_METHODS: dict[str, str] = {
    "http://www.w3.org/2001/04/xmlenc#sha256": "sha256",
    "http://www.w3.org/2001/04/xmldsig-more#sha384": "sha384",
    "http://www.w3.org/2001/04/xmlenc#sha512": "sha512",
}

SUPPORTED_SIGNATURE_METHODS: dict[str, dict[str, Any]] = {
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": {
        "family": "RSA", "hash": "sha256", "pss": False,
    },
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": {
        "family": "RSA", "hash": "sha384", "pss": False,
    },
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": {
        "family": "RSA", "hash": "sha512", "pss": False,
    },
    "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1": {
        "family": "RSA", "hash": "sha256", "pss": True, "saltlen": 32,
    },
    "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1": {
        "family": "RSA", "hash": "sha384", "pss": True, "saltlen": 48,
    },
    "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1": {
        "family": "RSA", "hash": "sha512", "pss": True, "saltlen": 64,
    },
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": {
        "family": "EC", "hash": "sha256", "coord_len": 32,
    },
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": {
        "family": "EC", "hash": "sha384", "coord_len": 48,
    },
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": {
        "family": "EC", "hash": "sha512", "coord_len": 66,
    },
}

_ID_ATTR_LOCAL_NAMES: frozenset[str] = frozenset({"Id", "ID", "id"})


class XmlSecurityError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _openssl_exe() -> str:
    exe = shutil.which("openssl")
    if not exe:
        raise RuntimeError("OpenSSL CLI bulunamadı; XMLDSig/XAdES doğrulaması çalıştırılamaz.")
    return exe


def _extract_clean_cert_pem(cert_pem: str) -> str:
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", cert_pem, flags=re.DOTALL)
    if not m:
        raise ValueError("Geçerli X.509 CERTIFICATE PEM bloğu bulunamadı.")
    return m.group(0).strip() + "\n"


def _cert_pem_der_bytes(cert_pem: str) -> bytes:
    clean = _extract_clean_cert_pem(cert_pem)
    b64 = "".join(ln.strip() for ln in clean.splitlines() if ln.strip() and not ln.strip().startswith("-----"))
    return base64.b64decode(b64)


def _compute_digest(data: bytes, digest_alg_uri: str) -> bytes:
    name = SUPPORTED_DIGEST_METHODS.get(digest_alg_uri)
    if not name:
        raise XmlSecurityError(
            "XADES_UNSUPPORTED_OR_WEAK_DIGEST_METHOD",
            f"Desteklenmeyen veya zayıf DigestMethod algoritması reddedildi: {digest_alg_uri!r}.",
        )
    return hashlib.new(name, data).digest()


def _der_encode_int(val_bytes: bytes) -> bytes:
    trimmed = val_bytes.lstrip(b"\x00") or b"\x00"
    if trimmed[0] & 0x80:
        trimmed = b"\x00" + trimmed
    return b"\x02" + _der_encode_len(len(trimmed)) + trimmed


def _der_encode_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    enc = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(enc)]) + enc


def ecdsa_p1363_to_der(p1363_sig: bytes, coord_len: int) -> bytes:
    """Convert W3C XMLDSig IEEE P1363 raw `r || s` ECDSA signature to ASN.1 DER for OpenSSL."""
    if len(p1363_sig) != 2 * coord_len:
        raise ValueError(f"ECDSA P1363 imza uzunluğu geçersiz: beklenen={2 * coord_len}, gelen={len(p1363_sig)}.")
    r = p1363_sig[:coord_len]
    s = p1363_sig[coord_len:]
    body = _der_encode_int(r) + _der_encode_int(s)
    return b"\x30" + _der_encode_len(len(body)) + body


def ecdsa_der_to_p1363(der_sig: bytes, coord_len: int) -> bytes:
    """Convert OpenSSL ASN.1 DER ECDSA signature (`SEQUENCE { INTEGER r, INTEGER s }`) to W3C XMLDSig P1363 `r || s`."""
    idx = 0
    if idx >= len(der_sig) or der_sig[idx] != 0x30:
        raise ValueError("Geçersiz DER ECDSA SEQUENCE başlığı.")
    idx += 1
    # Read outer length
    first_len = der_sig[idx]
    idx += 1
    if first_len & 0x80:
        nbytes = first_len & 0x7F
        idx += nbytes

    def _read_int(pos: int) -> tuple[bytes, int]:
        if pos >= len(der_sig) or der_sig[pos] != 0x02:
            raise ValueError("Geçersiz DER ECDSA INTEGER etiketi.")
        pos += 1
        ln = der_sig[pos]
        pos += 1
        if ln & 0x80:
            nb = ln & 0x7F
            ln = int.from_bytes(der_sig[pos : pos + nb], "big")
            pos += nb
        raw = der_sig[pos : pos + ln]
        pos += ln
        raw_stripped = raw.lstrip(b"\x00")
        if len(raw_stripped) > coord_len:
            raise ValueError("ECDSA koordinatı hedef eğri boyutunu aşıyor.")
        return raw_stripped.rjust(coord_len, b"\x00"), pos

    r_pad, idx = _read_int(idx)
    s_pad, _ = _read_int(idx)
    return r_pad + s_pad


def safe_parse_xml_bytes(xml_bytes: bytes) -> Document:
    """Parse XML safely into a namespace-preserving DOM Document, blocking DOCTYPE/ENTITY/XXE at both byte and Expat levels."""
    if not xml_bytes or not xml_bytes.strip():
        raise XmlSecurityError("XADES_PAYLOAD_EMPTY", "XAdES XML verisi boştur.")
    raw_upper = xml_bytes.decode("utf-8", errors="replace").upper()
    if "<!DOCTYPE" in raw_upper or "<!ENTITY" in raw_upper:
        raise XmlSecurityError("XML_XXE_OR_DOCTYPE_FORBIDDEN", "XML girişinde DOCTYPE/ENTITY bildirimi (XXE riski) yasaktır.")

    class _SafeExpatBuilder(ExpatBuilderNS):
        def install(self, parser: Any) -> None:
            super().install(parser)

            def _forbid_doctype(*_args: Any) -> None:
                raise XmlSecurityError("XML_XXE_OR_DOCTYPE_FORBIDDEN", "XML DOCTYPE bildirimi engellendi.")

            def _forbid_entity(*_args: Any) -> None:
                raise XmlSecurityError("XML_XXE_OR_DOCTYPE_FORBIDDEN", "XML ENTITY bildirimi engellendi.")

            def _forbid_ext(*_args: Any) -> int:
                raise XmlSecurityError("XML_XXE_OR_DOCTYPE_FORBIDDEN", "Harici XML varlık başvurusu engellendi.")

            parser.StartDoctypeDeclHandler = _forbid_doctype
            parser.EntityDeclHandler = _forbid_entity
            parser.UnparsedEntityDeclHandler = _forbid_entity
            parser.ExternalEntityRefHandler = _forbid_ext

    builder = _SafeExpatBuilder()
    return builder.parseString(xml_bytes)


def _escape_text_c14n(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\r", "&#xD;")
    )


def _escape_attr_c14n(val: str) -> str:
    return (
        val.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace('"', "&quot;")
        .replace("\t", "&#x9;")
        .replace("\n", "&#xA;")
        .replace("\r", "&#xD;")
    )


def _get_element_ns_decls(elem: Element) -> dict[str, str]:
    """Return explicit `xmlns` / `xmlns:prefix` declarations present directly on `elem`."""
    decls: dict[str, str] = {}
    if not elem.attributes:
        return decls
    for idx in range(elem.attributes.length):
        attr = elem.attributes.item(idx)
        if attr.name == "xmlns":
            # Python's ExpatBuilderNS stores `xmlns=""` as attr.value = None!
            decls[""] = attr.value or ""
        elif attr.name.startswith("xmlns:"):
            decls[attr.name.split(":", 1)[1]] = attr.value or ""
    return decls


def _join_xml_base_c14n11(base_uri: str, rel_uri: str) -> str:
    """Resolve chained `xml:base` values per W3C C14N 1.1 §2.4 (RFC 3986 relative URI resolution)."""
    if not base_uri:
        return rel_uri
    if not rel_uri:
        return base_uri
    return urljoin(base_uri, rel_uri)


def _collect_ancestor_context(
    elem: Element,
    *,
    v11: bool,
) -> tuple[dict[str, str], dict[str, tuple[str, str, str, str]]]:
    """Collect inherited namespace map and inheritable `xml:*` attributes `(ns_uri, localName, qname, value)` above `elem`."""
    ancestors: list[Element] = []
    cur = elem.parentNode
    while cur is not None and cur.nodeType == Node.ELEMENT_NODE:
        ancestors.append(cur)
        cur = cur.parentNode
    ancestors.reverse()

    ns_map: dict[str, str] = {}
    xml_attrs: dict[str, tuple[str, str, str, str]] = {}
    accumulated_xml_base: str | None = None
    for anc in ancestors:
        ns_map.update(_get_element_ns_decls(anc))
        if anc.attributes:
            for idx in range(anc.attributes.length):
                attr = anc.attributes.item(idx)
                if attr.namespaceURI == XML_NS or attr.name.startswith("xml:"):
                    loc = attr.localName or attr.name.split(":", 1)[-1]
                    val = attr.value or ""
                    if v11 and loc == "id":
                        continue
                    if v11 and loc == "base":
                        accumulated_xml_base = (
                            val if accumulated_xml_base is None else _join_xml_base_c14n11(accumulated_xml_base, val)
                        )
                        xml_attrs["base"] = (attr.namespaceURI or XML_NS, "base", attr.name, accumulated_xml_base)
                    else:
                        xml_attrs[loc] = (attr.namespaceURI or XML_NS, loc, attr.name, val)
    return ns_map, xml_attrs


def canonicalize_xml_node(
    target_elem: Document | Element,
    algorithm_uri: str,
    *,
    inclusive_prefixes: set[str] | None = None,
    excluded_node: Element | None = None,
    excluded_nodes: Sequence[Element] | None = None,
) -> bytes:
    """Spec-exact pure-stdlib W3C C14N 1.0 (Inclusive & Exclusive) and C14N 1.1 serializer for `Document` and `Element`."""
    spec = SUPPORTED_C14N_METHODS.get(algorithm_uri)
    if spec is None:
        raise XmlSecurityError(
            "XADES_UNSUPPORTED_CANONICALIZATION_METHOD",
            f"Desteklenmeyen W3C kanonikleştirme algoritması reddedildi: {algorithm_uri!r}.",
        )
    if target_elem.nodeType not in (Node.DOCUMENT_NODE, Node.ELEMENT_NODE):
        raise XmlSecurityError(
            "XADES_UNSUPPORTED_CANONICALIZATION_METHOD",
            f"C14N yalnızca XML Document veya Element düğümleri üzerinde çalıştırılabilir (gelen nodeType={target_elem.nodeType}).",
        )

    exclusive: bool = spec["exclusive"]
    with_comments: bool = spec["with_comments"]
    v11: bool = spec["v11"]
    inc_pref_set: set[str] = set()
    if inclusive_prefixes:
        for p in inclusive_prefixes:
            inc_pref_set.add("" if p == "#default" else p)

    excl_list: list[Element] = []
    if excluded_node is not None:
        excl_list.append(excluded_node)
    if excluded_nodes:
        for ex in excluded_nodes:
            if not any(ex is existing for existing in excl_list):
                excl_list.append(ex)

    if target_elem.nodeType == Node.ELEMENT_NODE:
        ancestor_ns, ancestor_xml_attrs = _collect_ancestor_context(target_elem, v11=v11)
    else:
        ancestor_ns, ancestor_xml_attrs = {}, {}

    out_parts: list[str] = []

    def _serialize(
        node: Any,
        in_scope_ns: dict[str, str],
        rendered_ns: dict[str, str],
        is_subtree_root: bool,
    ) -> None:
        if excl_list and any(node is ex for ex in excl_list):
            return

        ntype = node.nodeType
        if ntype == Node.TEXT_NODE or ntype == Node.CDATA_SECTION_NODE:
            out_parts.append(_escape_text_c14n(node.data))
            return
        if ntype == Node.COMMENT_NODE:
            if with_comments:
                out_parts.append(f"<!--{node.data}-->")
            return
        if ntype == Node.PROCESSING_INSTRUCTION_NODE:
            if node.data:
                out_parts.append(f"<?{node.target} {node.data}?>")
            else:
                out_parts.append(f"<?{node.target}?>")
            return
        if ntype != Node.ELEMENT_NODE:
            return

        elem: Element = node
        own_decls = _get_element_ns_decls(elem)
        new_in_scope = dict(in_scope_ns)
        new_in_scope.update(own_decls)

        new_rendered = dict(rendered_ns)
        ns_to_emit: list[tuple[str, str]] = []

        # Collect non-namespace attributes on elem
        reg_attrs: list[tuple[str, str, str, str]] = []  # (ns_uri, localName, qname, value)
        present_xml_locals: set[str] = set()
        if elem.attributes:
            for idx in range(elem.attributes.length):
                attr = elem.attributes.item(idx)
                if attr.name == "xmlns" or attr.name.startswith("xmlns:"):
                    continue
                val = attr.value or ""
                loc = attr.localName or attr.name
                if attr.namespaceURI == XML_NS or attr.name.startswith("xml:"):
                    present_xml_locals.add(loc)
                    # W3C C14N 1.1 §2.4: resolve subtree root's relative xml:base against omitted ancestor xml:base
                    if is_subtree_root and not exclusive and v11 and loc == "base" and "base" in ancestor_xml_attrs:
                        val = _join_xml_base_c14n11(ancestor_xml_attrs["base"][3], val)
                reg_attrs.append((attr.namespaceURI or "", loc, attr.name, val))

        # Inclusive C14N inherits ancestor xml:* attributes onto the canonicalized subtree root
        if is_subtree_root and not exclusive and ancestor_xml_attrs:
            for loc_name, anc_tuple in ancestor_xml_attrs.items():
                if loc_name not in present_xml_locals:
                    reg_attrs.append(anc_tuple)

        if exclusive:
            visibly_used: set[str] = set()
            # Element's own prefix (or "" if unprefixed)
            elem_prefix = elem.prefix or ""
            visibly_used.add(elem_prefix)
            # Prefixed attributes visibly utilize their prefix; unprefixed attrs do NOT utilize ""
            for ns_u, _loc, qn, _val in reg_attrs:
                if ":" in qn:
                    apref = qn.split(":", 1)[0]
                    if apref != "xml":
                        visibly_used.add(apref)
            # InclusiveNamespaces PrefixList
            for p in inc_pref_set:
                if p in new_in_scope:
                    visibly_used.add(p)

            for p in sorted(visibly_used, key=lambda x: ("" if x == "" else "1" + x)):
                if p == "xml":
                    continue
                uri = new_in_scope.get(p, "")
                if p == "" and uri == "" and new_rendered.get("", "") == "":
                    continue
                if p != "" and uri == "":
                    continue
                if new_rendered.get(p) != uri:
                    ns_to_emit.append((p, uri))
                    new_rendered[p] = uri
        else:
            # Inclusive C14N: emit all in-scope namespaces differing from rendered_ns
            for p in sorted(new_in_scope.keys(), key=lambda x: ("" if x == "" else "1" + x)):
                if p == "xml":
                    continue
                uri = new_in_scope[p]
                if p == "" and uri == "" and new_rendered.get("", "") == "":
                    continue
                if p != "" and uri == "":
                    continue
                if new_rendered.get(p) != uri:
                    ns_to_emit.append((p, uri))
                    new_rendered[p] = uri

        # Sort regular attributes by (namespaceURI, localName)
        reg_attrs.sort(key=lambda t: (t[0], t[1]))

        out_parts.append(f"<{elem.tagName}")
        for p, uri in ns_to_emit:
            if p == "":
                out_parts.append(f' xmlns="{_escape_attr_c14n(uri)}"')
            else:
                out_parts.append(f' xmlns:{p}="{_escape_attr_c14n(uri)}"')
        for _ns_u, _loc, qn, val in reg_attrs:
            out_parts.append(f' {qn}="{_escape_attr_c14n(val)}"')
        out_parts.append(">")

        for child in elem.childNodes:
            _serialize(child, new_in_scope, new_rendered, is_subtree_root=False)

        out_parts.append(f"</{elem.tagName}>")

    initial_rendered: dict[str, str] = {"": "", "xml": XML_NS}

    if target_elem.nodeType == Node.DOCUMENT_NODE:
        # W3C C14N 1.0 §2.3 & §3.1 / Exc-C14N §3 / C14N 1.1 §2.3:
        # Preserve document-level PIs (always) and comments (when with_comments=True) in exact document order:
        #   - Outside & BEFORE documentElement -> trailing `\n` (`#xA`)
        #   - Outside & AFTER documentElement  -> leading `\n` (`#xA`)
        seen_doc_element = False
        for child in target_elem.childNodes:
            if excl_list and any(child is ex for ex in excl_list):
                continue
            ctype = child.nodeType
            if ctype == Node.ELEMENT_NODE:
                seen_doc_element = True
                _serialize(child, {}, dict(initial_rendered), is_subtree_root=True)
            elif ctype == Node.PROCESSING_INSTRUCTION_NODE:
                pi_str = f"<?{child.target} {child.data}?>" if child.data else f"<?{child.target}?>"
                out_parts.append(f"\n{pi_str}" if seen_doc_element else f"{pi_str}\n")
            elif ctype == Node.COMMENT_NODE:
                if with_comments:
                    cm_str = f"<!--{child.data}-->"
                    out_parts.append(f"\n{cm_str}" if seen_doc_element else f"{cm_str}\n")
        return "".join(out_parts).encode("utf-8")

    _serialize(target_elem, ancestor_ns, initial_rendered, is_subtree_root=True)
    return "".join(out_parts).encode("utf-8")


def canonicalize_xml_document(
    doc: Document,
    algorithm_uri: str,
    *,
    inclusive_prefixes: set[str] | None = None,
    excluded_node: Element | None = None,
    excluded_nodes: Sequence[Element] | None = None,
) -> bytes:
    """Canonicalize a full XML `Document` (preserving top-level PIs and, for `#WithComments`, top-level comments)."""
    if doc.nodeType != Node.DOCUMENT_NODE:
        raise XmlSecurityError(
            "XADES_UNSUPPORTED_CANONICALIZATION_METHOD",
            "canonicalize_xml_document yalnızca XML Document düğümü kabul eder.",
        )
    return canonicalize_xml_node(
        doc,
        algorithm_uri,
        inclusive_prefixes=inclusive_prefixes,
        excluded_node=excluded_node,
        excluded_nodes=excluded_nodes,
    )


def _direct_children_ns(parent: Element, ns_uri: str, local_name: str) -> list[Element]:
    out: list[Element] = []
    for child in parent.childNodes:
        if child.nodeType == Node.ELEMENT_NODE and child.namespaceURI == ns_uri and child.localName == local_name:
            out.append(child)
    return out


def _descendants_ns(root: Node, ns_uri: str, local_name: str) -> list[Element]:
    out: list[Element] = []

    def _walk(node: Node) -> None:
        if node.nodeType == Node.ELEMENT_NODE and node.namespaceURI == ns_uri and node.localName == local_name:
            out.append(node)
        for ch in node.childNodes:
            _walk(ch)

    _walk(root)
    return out


def _is_descendant_of(node: Node, ancestor: Node) -> bool:
    cur = node
    while cur is not None:
        if cur is ancestor:
            return True
        cur = cur.parentNode
    return False


def _collect_all_xml_ids(doc: Document) -> tuple[dict[str, Element], list[str]]:
    """Scan EVERY element in the document for `Id`/`ID`/`id`/`xml:id`; report any duplicate IDs immediately."""
    id_map: dict[str, Element] = {}
    duplicates: list[str] = []

    def _walk(node: Node) -> None:
        if node.nodeType == Node.ELEMENT_NODE and node.attributes:
            elem_ids_seen: set[str] = set()
            for idx in range(node.attributes.length):
                attr = node.attributes.item(idx)
                loc = attr.localName or attr.name
                if loc in _ID_ATTR_LOCAL_NAMES and (not attr.namespaceURI or attr.namespaceURI == XML_NS):
                    val = attr.value.strip()
                    if not val:
                        continue
                    if val in id_map or val in elem_ids_seen:
                        duplicates.append(val)
                    else:
                        id_map[val] = node
                        elem_ids_seen.add(val)
        for ch in node.childNodes:
            _walk(ch)

    _walk(doc.documentElement)
    return id_map, sorted(set(duplicates))


def _element_text(elem: Element) -> str:
    parts: list[str] = []
    for ch in elem.childNodes:
        if ch.nodeType in (Node.TEXT_NODE, Node.CDATA_SECTION_NODE):
            parts.append(ch.data)
    return "".join(parts)


def _get_inclusive_prefixes(transform_or_c14n_elem: Element) -> set[str]:
    prefixes: set[str] = set()
    for child in transform_or_c14n_elem.childNodes:
        if child.nodeType == Node.ELEMENT_NODE and child.localName == "InclusiveNamespaces":
            plist = child.getAttribute("PrefixList") or ""
            for tok in plist.split():
                if tok.strip():
                    prefixes.add(tok.strip())
    return prefixes


@dataclass(frozen=True)
class TransformPipelineData:
    """Typed intermediate state flowing between sequential W3C XMLDSig `<ds:Transform>` steps.

    Per W3C XMLDSig 1.0/1.1 §4.4.3.4, each transform receives either a `NODE_SET`
    (an XML DOM `Document` or `Element` plus immutable excluded subtrees) or an `OCTET_STREAM`
    (raw bytes), and passes its exact output to the next transform in declared XML order.
    """

    kind: str  # TRANSFORM_KIND_NODE_SET | TRANSFORM_KIND_OCTET_STREAM
    node: Document | Element | None = None
    excluded_nodes: tuple[Element, ...] = ()
    octets: bytes | None = None

    def __post_init__(self) -> None:
        if self.kind == TRANSFORM_KIND_NODE_SET:
            if self.node is None or self.octets is not None:
                raise ValueError("NODE_SET pipeline state requires `node` and `octets=None`.")
        elif self.kind == TRANSFORM_KIND_OCTET_STREAM:
            if self.octets is None or self.node is not None:
                raise ValueError("OCTET_STREAM pipeline state requires `octets` and `node=None`.")
        else:
            raise ValueError(f"Desteklenmeyen transform pipeline veri türü: {self.kind!r}")


def _extract_nodeset_text(target_elem: Document | Element, excluded_nodes: Sequence[Element] = ()) -> str:
    """Concatenate descendant text/CDATA nodes in document order skipping excluded subtrees (W3C XMLDSig §6.6.2)."""
    parts: list[str] = []

    def _walk(node: Any) -> None:
        if excluded_nodes and any(node is ex for ex in excluded_nodes):
            return
        if node.nodeType in (Node.TEXT_NODE, Node.CDATA_SECTION_NODE):
            parts.append(node.data)
            return
        for ch in node.childNodes:
            _walk(ch)

    _walk(target_elem)
    return "".join(parts)


def _strict_base64_decode(raw: str | bytes) -> bytes:
    """Strictly decode RFC 4648 / W3C XMLDSig Base64 input (rejects non-Base64 characters like XML tags)."""
    if isinstance(raw, bytes):
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise XmlSecurityError(
                "XADES_BASE64_TRANSFORM_DECODE_FAILED",
                f"Base64 transform girişi geçerli ASCII bayt dizisi değildir: {exc}",
            ) from exc
    else:
        text = raw
    cleaned = re.sub(r"[ \t\r\n]+", "", text)
    if not cleaned:
        raise XmlSecurityError(
            "XADES_BASE64_TRANSFORM_DECODE_FAILED",
            "Base64 transform girişi boş olduğundan çözümlenemedi.",
        )
    if len(cleaned) % 4 != 0:
        raise XmlSecurityError(
            "XADES_BASE64_TRANSFORM_DECODE_FAILED",
            "Base64 transform giriş uzunluğu 4'ün katı değildir (geçersiz Base64).",
        )
    try:
        return base64.b64decode(cleaned, validate=True)
    except Exception as exc:
        raise XmlSecurityError(
            "XADES_BASE64_TRANSFORM_DECODE_FAILED",
            f"Base64 transform çözümlemesi başarısız (geçersiz karakter veya dolgu): {exc}",
        ) from exc


def execute_xmldsig_transform_pipeline(
    initial_data: TransformPipelineData,
    transform_steps: Sequence[tuple[str, set[str]]],
    *,
    verifying_signature_node: Element | None = None,
) -> tuple[bytes, list[dict[str, Any]]]:
    """Execute W3C XMLDSig `<ds:Transform>` steps strictly sequentially (Transform N output -> Transform N+1 input).

    Returns `(final_octets_for_digest, execution_trace)`. Fails closed on:
      - Unknown / forbidden transforms (XSLT, XPath, XPath Filter 2, empty/unknown URI)
      - Excessive transform counts (`> MAX_TRANSFORMS_PER_REFERENCE`)
      - Invalid input-type transitions (e.g. `OCTET_STREAM -> enveloped-signature`, such as after C14N or Base64)
      - Invalid Base64 payloads (`XADES_BASE64_TRANSFORM_DECODE_FAILED`, e.g. `C14N -> Base64` on serialized XML)
      - Invalid XML / XXE / duplicate XML IDs when re-parsing an `OCTET_STREAM` for a subsequent C14N transform
    """
    if len(transform_steps) > MAX_TRANSFORMS_PER_REFERENCE:
        raise XmlSecurityError(
            "XADES_EXCESSIVE_TRANSFORMS_COUNT",
            f"<ds:Reference> içinde izin verilen azami transform sayısı ({MAX_TRANSFORMS_PER_REFERENCE}) aşıldı.",
        )

    data = initial_data
    trace: list[dict[str, Any]] = []

    for step_idx, (raw_alg, raw_inc_prefixes) in enumerate(transform_steps):
        t_uri = (raw_alg or "").strip()
        inc_prefs = set(raw_inc_prefixes or ())

        if t_uri not in SUPPORTED_C14N_METHODS and t_uri not in (TRANSFORM_ENVELOPED_SIGNATURE, TRANSFORM_BASE64):
            raise XmlSecurityError(
                "XADES_UNSUPPORTED_OR_FORBIDDEN_TRANSFORM",
                f"Desteklenmeyen veya güvensiz XMLDSig Transform reddedildi: {t_uri!r}.",
            )

        in_kind = data.kind

        if t_uri == TRANSFORM_ENVELOPED_SIGNATURE:
            if data.kind != TRANSFORM_KIND_NODE_SET or data.node is None:
                raise XmlSecurityError(
                    "XADES_TRANSFORM_INVALID_INPUT_TYPE",
                    f"enveloped-signature transformu yalnızca NODE_SET giriş kabul eder; "
                    f"adım {step_idx} için gelen veri türü '{data.kind}' reddedildi (ör. C14N/Base64 sonrası veya ayrık referans).",
                )
            if verifying_signature_node is None:
                raise XmlSecurityError(
                    "XADES_TRANSFORM_INVALID_INPUT_TYPE",
                    "enveloped-signature transformu için doğrulanmakta olan <ds:Signature> düğümü gereklidir.",
                )
            new_excl = list(data.excluded_nodes)
            if not any(verifying_signature_node is ex for ex in new_excl):
                new_excl.append(verifying_signature_node)
            data = TransformPipelineData(
                kind=TRANSFORM_KIND_NODE_SET,
                node=data.node,
                excluded_nodes=tuple(new_excl),
            )
            trace.append(
                {
                    "step_index": step_idx,
                    "algorithm": t_uri,
                    "input_type": in_kind,
                    "output_type": data.kind,
                }
            )

        elif t_uri in SUPPORTED_C14N_METHODS:
            if data.kind == TRANSFORM_KIND_NODE_SET:
                assert data.node is not None
                node_scope = "DOCUMENT" if data.node.nodeType == Node.DOCUMENT_NODE else "ELEMENT"
                out_octets = canonicalize_xml_node(
                    data.node,
                    t_uri,
                    inclusive_prefixes=inc_prefs,
                    excluded_nodes=data.excluded_nodes,
                )
                reparsed = False
            else:
                # Per W3C XMLDSig §4.4.3.4 & W3C C14N §2.3/§3.1 (v1.0.4.3 BLOCKER 4 Closure):
                # OCTET_STREAM entering a C14N transform MUST be safely parsed as a full XML Document
                # and canonicalized at Document level so top-level PIs (always) and top-level comments
                # (in #WithComments profiles) before/after documentElement are preserved byte-for-byte!
                assert data.octets is not None
                try:
                    sub_doc = safe_parse_xml_bytes(data.octets)
                except XmlSecurityError:
                    raise
                except Exception as exc:
                    raise XmlSecurityError(
                        "XADES_TRANSFORM_XML_REPARSE_FAILED",
                        f"Transform adımı {step_idx} ({t_uri}) OCTET_STREAM girişini geçerli XML olarak ayrıştıramadı: {exc}",
                    ) from exc
                try:
                    if sub_doc.documentElement is None:
                        raise XmlSecurityError(
                            "XADES_TRANSFORM_XML_REPARSE_FAILED",
                            f"Transform adımı {step_idx} ({t_uri}) yeniden ayrıştırılan XML içinde kök öğe bulamadı.",
                        )
                    _, sub_dups = _collect_all_xml_ids(sub_doc)
                    if sub_dups:
                        raise XmlSecurityError(
                            "XADES_DUPLICATE_XML_ID_DETECTED",
                            f"Transform adımı {step_idx} içinde yeniden ayrıştırılan XML'de yinelenen ID ({sub_dups}) tespit edildi.",
                        )
                    node_scope = "DOCUMENT"
                    out_octets = canonicalize_xml_node(
                        sub_doc,
                        t_uri,
                        inclusive_prefixes=inc_prefs,
                    )
                finally:
                    sub_doc.unlink()
                reparsed = True

            data = TransformPipelineData(kind=TRANSFORM_KIND_OCTET_STREAM, octets=out_octets)
            trace.append(
                {
                    "step_index": step_idx,
                    "algorithm": t_uri,
                    "input_type": in_kind,
                    "output_type": data.kind,
                    "node_scope": node_scope,
                    "reparsed_xml": reparsed,
                    "inclusive_prefixes": sorted(inc_prefs),
                }
            )

        elif t_uri == TRANSFORM_BASE64:
            if data.kind == TRANSFORM_KIND_NODE_SET:
                assert data.node is not None
                raw_text = _extract_nodeset_text(data.node, data.excluded_nodes)
                decoded_octets = _strict_base64_decode(raw_text)
            else:
                assert data.octets is not None
                decoded_octets = _strict_base64_decode(data.octets)

            data = TransformPipelineData(kind=TRANSFORM_KIND_OCTET_STREAM, octets=decoded_octets)
            trace.append(
                {
                    "step_index": step_idx,
                    "algorithm": t_uri,
                    "input_type": in_kind,
                    "output_type": data.kind,
                }
            )

    # Final conversion per W3C XMLDSig §4.4.3.2: if pipeline terminates in NODE_SET, apply default Inclusive C14N 1.0
    if data.kind == TRANSFORM_KIND_NODE_SET:
        assert data.node is not None
        final_octets = canonicalize_xml_node(
            data.node,
            C14N_INCLUSIVE_10,
            excluded_nodes=data.excluded_nodes,
        )
        trace.append(
            {
                "step_index": len(transform_steps),
                "algorithm": C14N_INCLUSIVE_10,
                "input_type": TRANSFORM_KIND_NODE_SET,
                "output_type": TRANSFORM_KIND_OCTET_STREAM,
                "implicit_final_c14n": True,
            }
        )
        return final_octets, trace

    assert data.octets is not None
    return data.octets, trace


def _normalize_transform_steps(
    transforms: Sequence[str | tuple[str, set[str] | list[str] | tuple[str, ...]]],
) -> list[tuple[str, set[str]]]:
    steps: list[tuple[str, set[str]]] = []
    for item in transforms:
        if isinstance(item, str):
            steps.append((item.strip(), set()))
        else:
            alg_uri, prefs = item
            steps.append((str(alg_uri).strip(), {str(p).strip() for p in prefs if str(p).strip()}))
    return steps


def _render_transforms_xml(steps: Sequence[tuple[str, set[str]]]) -> str:
    if not steps:
        return ""
    parts: list[str] = ["<ds:Transforms>"]
    for alg_uri, inc_prefs in steps:
        if inc_prefs:
            plist = " ".join(sorted(inc_prefs))
            parts.append(
                f'<ds:Transform Algorithm="{alg_uri}">'
                f'<ec:InclusiveNamespaces xmlns:ec="{EC_NS}" PrefixList="{plist}"></ec:InclusiveNamespaces>'
                f"</ds:Transform>"
            )
        else:
            parts.append(f'<ds:Transform Algorithm="{alg_uri}"></ds:Transform>')
    parts.append("</ds:Transforms>")
    return "".join(parts)


def _check_pubkey_matches_sig_family(openssl: str, cert_path: Path, expected_family: str) -> bool:
    p = subprocess.run(
        [openssl, "x509", "-in", str(cert_path), "-noout", "-text"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if p.returncode != 0:
        return False
    m = re.search(r"Public Key Algorithm:\s*([^\n]+)", p.stdout)
    alg_text = (m.group(1).lower() if m else "")
    if expected_family == "RSA":
        return "rsa" in alg_text
    if expected_family == "EC":
        return "ec" in alg_text or "id-ecpublickey" in alg_text
    return False


def _sign_bytes_xmldsig(data_bytes: bytes, signer_key_pem: str, signature_method_uri: str) -> bytes:
    """Sign canonicalized SignedInfo bytes using declared W3C XMLDSig SignatureMethod via OpenSSL 3."""
    spec = SUPPORTED_SIGNATURE_METHODS.get(signature_method_uri)
    if spec is None:
        raise ValueError(f"Desteklenmeyen XMLDSig SignatureMethod: {signature_method_uri!r}")
    openssl = _openssl_exe()
    with tempfile.TemporaryDirectory(prefix="calisora_xmldsig_sign_") as tmp:
        key_path = Path(tmp) / "signer.key"
        in_path = Path(tmp) / "signedinfo.c14n"
        sig_path = Path(tmp) / "sig.bin"
        key_path.write_text(signer_key_pem.strip() + "\n", encoding="utf-8")
        in_path.write_bytes(data_bytes)

        cmd = [openssl, "dgst", f"-{spec['hash']}", "-sign", str(key_path)]
        if spec["family"] == "RSA" and spec.get("pss"):
            cmd.extend(
                [
                    "-sigopt", "rsa_padding_mode:pss",
                    "-sigopt", f"rsa_pss_saltlen:{spec['saltlen']}",
                    "-sigopt", f"rsa_mgf1_md:{spec['hash']}",
                ]
            )
        cmd.extend(["-out", str(sig_path), str(in_path)])
        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"XMLDSig imzası üretilemedi: {proc.stderr.strip()}")
        raw = sig_path.read_bytes()
        if spec["family"] == "EC":
            return ecdsa_der_to_p1363(raw, int(spec["coord_len"]))
        return raw


def _verify_bytes_xmldsig(
    data_bytes: bytes,
    sig_bytes: bytes,
    signer_cert_pem: str,
    signature_method_uri: str,
) -> tuple[bool, str | None, str | None]:
    """Verify XMLDSig SignatureValue over canonicalized SignedInfo according to declared SignatureMethod URI."""
    spec = SUPPORTED_SIGNATURE_METHODS.get(signature_method_uri)
    if spec is None:
        return False, "XADES_UNSUPPORTED_OR_WEAK_SIGNATURE_METHOD", (
            f"Desteklenmeyen veya zayıf XMLDSig SignatureMethod algoritması reddedildi: {signature_method_uri!r}."
        )
    openssl = _openssl_exe()
    with tempfile.TemporaryDirectory(prefix="calisora_xmldsig_ver_") as tmp:
        cert_path = Path(tmp) / "signer.pem"
        pub_path = Path(tmp) / "pub.pem"
        in_path = Path(tmp) / "signedinfo.c14n"
        sig_path = Path(tmp) / "sig.bin"
        cert_path.write_text(signer_cert_pem.strip() + "\n", encoding="utf-8")
        in_path.write_bytes(data_bytes)

        if not _check_pubkey_matches_sig_family(openssl, cert_path, spec["family"]):
            return False, "XADES_SIGNATURE_METHOD_KEY_MISMATCH", (
                f"SignatureMethod ({signature_method_uri}) imzacı sertifikasının açık anahtar türü ile uyuşmuyor."
            )

        p_pub = subprocess.run(
            [openssl, "x509", "-in", str(cert_path), "-pubkey", "-noout", "-out", str(pub_path)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if p_pub.returncode != 0:
            return False, "XADES_SIGNER_PUBKEY_EXTRACT_FAILED", "İmzacı sertifikasından açık anahtar çıkarılamadı."

        verify_sig = sig_bytes
        if spec["family"] == "EC":
            try:
                verify_sig = ecdsa_p1363_to_der(sig_bytes, int(spec["coord_len"]))
            except ValueError as exc:
                return False, "XADES_SIGNATURE_VALUE_INVALID", str(exc)
        sig_path.write_bytes(verify_sig)

        cmd = [openssl, "dgst", f"-{spec['hash']}", "-verify", str(pub_path)]
        if spec["family"] == "RSA" and spec.get("pss"):
            cmd.extend(
                [
                    "-sigopt", "rsa_padding_mode:pss",
                    "-sigopt", f"rsa_pss_saltlen:{spec['saltlen']}",
                    "-sigopt", f"rsa_mgf1_md:{spec['hash']}",
                ]
            )
        cmd.extend(["-signature", str(sig_path), str(in_path)])
        p_ver = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if p_ver.returncode == 0 and "Verified OK" in p_ver.stdout:
            return True, None, None
        return False, "XADES_SIGNATURE_VALUE_INVALID", (
            f"XAdES SignatureValue kriptografik doğrulaması ({signature_method_uri}) başarısız: "
            f"{(p_ver.stderr or p_ver.stdout).strip()}"
        )


@dataclass(frozen=True)
class XadesXmlDsigInspection:
    crypto_valid: bool
    has_signing_cert_ref: bool
    signer_cert_pem: str | None
    signature_value_bytes: bytes | None
    embedded_sig_ts_der: bytes | None
    embedded_archive_ts_der: bytes | None
    embedded_ocsp_der: bytes | None
    embedded_crl_pem: str | None
    xmldsig_details: dict[str, Any]
    error_codes: tuple[str, ...]
    errors: tuple[str, ...]


def verify_xades_xmldsig(
    xades_xml_bytes: bytes,
    signed_content_bytes: bytes | None = None,
) -> XadesXmlDsigInspection:
    """Standards-compliant W3C XMLDSig + ETSI EN 319 132 XAdES cryptographic, transform & anti-XSW verifier."""
    empty_details: dict[str, Any] = {
        "canonicalization_method": None,
        "signature_method": None,
        "references": [],
        "verified_signed_node_ids": [],
        "signature_mode": None,
        "duplicate_xml_ids_found": [],
    }
    try:
        doc = safe_parse_xml_bytes(xades_xml_bytes)
    except XmlSecurityError as exc:
        return XadesXmlDsigInspection(
            crypto_valid=False,
            has_signing_cert_ref=False,
            signer_cert_pem=None,
            signature_value_bytes=None,
            embedded_sig_ts_der=None,
            embedded_archive_ts_der=None,
            embedded_ocsp_der=None,
            embedded_crl_pem=None,
            xmldsig_details=empty_details,
            error_codes=(exc.code,),
            errors=(exc.message,),
        )
    except Exception as exc:
        return XadesXmlDsigInspection(
            crypto_valid=False,
            has_signing_cert_ref=False,
            signer_cert_pem=None,
            signature_value_bytes=None,
            embedded_sig_ts_der=None,
            embedded_archive_ts_der=None,
            embedded_ocsp_der=None,
            embedded_crl_pem=None,
            xmldsig_details=empty_details,
            error_codes=("XADES_XML_PARSE_FAILED",),
            errors=(f"XAdES XML belgesi ayrıştırılamadı: {exc}",),
        )
    try:
        return _verify_xades_xmldsig_parsed(doc, signed_content_bytes)
    finally:
        doc.unlink()


def _verify_xades_xmldsig_parsed(
    doc: Document,
    signed_content_bytes: bytes | None = None,
) -> XadesXmlDsigInspection:
    codes: list[str] = []
    errors: list[str] = []
    details: dict[str, Any] = {
        "canonicalization_method": None,
        "signature_method": None,
        "references": [],
        "verified_signed_node_ids": [],
        "signature_mode": None,
        "duplicate_xml_ids_found": [],
    }

    signer_cert_pem: str | None = None
    sig_val_bytes: bytes | None = None
    emb_sig_ts: bytes | None = None
    emb_arch_ts: bytes | None = None
    emb_ocsp: bytes | None = None
    emb_crl: str | None = None
    has_signing_cert_ref = False

    def _fail() -> XadesXmlDsigInspection:
        return XadesXmlDsigInspection(
            crypto_valid=False,
            has_signing_cert_ref=has_signing_cert_ref,
            signer_cert_pem=signer_cert_pem,
            signature_value_bytes=sig_val_bytes,
            embedded_sig_ts_der=emb_sig_ts,
            embedded_archive_ts_der=emb_arch_ts,
            embedded_ocsp_der=emb_ocsp,
            embedded_crl_pem=emb_crl,
            xmldsig_details=details,
            error_codes=tuple(sorted(set(codes))),
            errors=tuple(errors),
        )

    # 1. Global duplicate XML ID check (anti-XSW)
    id_map, dup_ids = _collect_all_xml_ids(doc)
    details["duplicate_xml_ids_found"] = dup_ids
    if dup_ids:
        codes.append("XADES_DUPLICATE_XML_ID_DETECTED")
        errors.append(
            f"XML belgesinde aynı ID değeri ({dup_ids}) birden fazla düğümde kullanılmıştır (XML Signature Wrapping reddi)."
        )
        return _fail()

    # 2. Locate <ds:Signature> and reject multiple/nested signatures
    signatures = _descendants_ns(doc.documentElement, DS_NS, "Signature")
    if len(signatures) == 0:
        codes.append("XADES_MALFORMED_STRUCTURE")
        errors.append("XML belgesinde geçerli <ds:Signature> öğesi bulunamadı.")
        return _fail()
    if len(signatures) > 1:
        codes.append("XADES_XSW_MULTIPLE_OR_NESTED_SIGNATURES")
        errors.append(
            f"Belgede birden fazla veya iç içe <ds:Signature> öğesi tespit edildi (adet={len(signatures)}); XSW koruması gereği reddedildi."
        )
        return _fail()

    sig_elem = signatures[0]
    sig_is_doc_root = sig_elem is doc.documentElement
    sig_id = sig_elem.getAttribute("Id") or sig_elem.getAttribute("ID") or sig_elem.getAttribute("id") or ""

    # 3. Extract direct <ds:SignedInfo>, <ds:SignatureValue>, <ds:KeyInfo>/<ds:X509Data>/<ds:X509Certificate>
    si_list = _direct_children_ns(sig_elem, DS_NS, "SignedInfo")
    sv_list = _direct_children_ns(sig_elem, DS_NS, "SignatureValue")
    ki_list = _direct_children_ns(sig_elem, DS_NS, "KeyInfo")
    if len(si_list) != 1 or len(sv_list) != 1:
        codes.append("XADES_MALFORMED_STRUCTURE")
        errors.append("<ds:Signature> içinde tekil <ds:SignedInfo> ve <ds:SignatureValue> zorunludur.")
        return _fail()

    signed_info = si_list[0]
    sig_val_elem = sv_list[0]

    # Extract X509Certificate from direct KeyInfo
    if ki_list:
        x509_elems = _descendants_ns(ki_list[0], DS_NS, "X509Certificate")
        if x509_elems:
            b64_clean = re.sub(r"\s+", "", _element_text(x509_elems[0]).strip())
            if b64_clean:
                lines = [b64_clean[i : i + 64] for i in range(0, len(b64_clean), 64)]
                signer_cert_pem = "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"

    if not signer_cert_pem:
        codes.append("XADES_MALFORMED_STRUCTURE")
        errors.append("<ds:KeyInfo>/<ds:X509Data>/<ds:X509Certificate> imzacı sertifikası eksiktir.")
        return _fail()

    try:
        sig_val_bytes = base64.b64decode(re.sub(r"\s+", "", _element_text(sig_val_elem).strip()), validate=True)
    except Exception as exc:
        codes.append("XADES_SIGNATURE_VALUE_INVALID")
        errors.append(f"<ds:SignatureValue> Base64 çözümlenemedi: {exc}")
        return _fail()

    # 4. Validate CanonicalizationMethod & SignatureMethod from <ds:SignedInfo>
    c14n_elems = _direct_children_ns(signed_info, DS_NS, "CanonicalizationMethod")
    sm_elems = _direct_children_ns(signed_info, DS_NS, "SignatureMethod")
    if len(c14n_elems) != 1:
        codes.append("XADES_UNSUPPORTED_CANONICALIZATION_METHOD")
        errors.append("<ds:SignedInfo> içinde tekil <ds:CanonicalizationMethod> zorunludur.")
        return _fail()
    if len(sm_elems) != 1:
        codes.append("XADES_UNSUPPORTED_OR_WEAK_SIGNATURE_METHOD")
        errors.append("<ds:SignedInfo> içinde tekil <ds:SignatureMethod> zorunludur.")
        return _fail()

    c14n_uri = c14n_elems[0].getAttribute("Algorithm").strip()
    c14n_inc_prefixes = _get_inclusive_prefixes(c14n_elems[0])
    sig_method_uri = sm_elems[0].getAttribute("Algorithm").strip()
    details["canonicalization_method"] = c14n_uri
    details["signature_method"] = sig_method_uri

    if c14n_uri not in SUPPORTED_C14N_METHODS:
        codes.append("XADES_UNSUPPORTED_CANONICALIZATION_METHOD")
        errors.append(f"Desteklenmeyen CanonicalizationMethod algoritması reddedildi: {c14n_uri!r}.")
        return _fail()
    if sig_method_uri not in SUPPORTED_SIGNATURE_METHODS:
        codes.append("XADES_UNSUPPORTED_OR_WEAK_SIGNATURE_METHOD")
        errors.append(f"Desteklenmeyen veya zayıf SignatureMethod algoritması reddedildi: {sig_method_uri!r}.")
        return _fail()

    # 5. Locate genuine <xades:QualifyingProperties> inside THIS <ds:Signature>/<ds:Object>
    obj_children = _direct_children_ns(sig_elem, DS_NS, "Object")
    qp_list: list[Element] = []
    for obj_el in obj_children:
        qp_list.extend(_direct_children_ns(obj_el, XADES_NS, "QualifyingProperties"))
    sig_signed_props_elems: list[Element] = []
    for qp_el in qp_list:
        qp_target = qp_el.getAttribute("Target").strip()
        if qp_target and sig_id and qp_target != f"#{sig_id}":
            codes.append("XADES_XSW_QUALIFYING_PROPERTIES_TARGET_MISMATCH")
            errors.append(
                f"<xades:QualifyingProperties Target='{qp_target}'> imza kimliği ('#{sig_id}') ile uyuşmuyor."
            )
            return _fail()
        sig_signed_props_elems.extend(_direct_children_ns(qp_el, XADES_NS, "SignedProperties"))
    if len(sig_signed_props_elems) > 1:
        codes.append("XADES_MALFORMED_STRUCTURE")
        errors.append("<xades:QualifyingProperties> içinde birden fazla <xades:SignedProperties> bulunamaz.")
        return _fail()
    expected_signed_props = sig_signed_props_elems[0] if sig_signed_props_elems else None

    # 6. Verify ALL <ds:Reference> elements with exact URI resolution, Transforms pipeline, DigestMethod & Anti-XSW!
    refs = _direct_children_ns(signed_info, DS_NS, "Reference")
    if not refs:
        codes.append("XADES_DATA_REFERENCE_MISSING")
        errors.append("<ds:SignedInfo> içinde hiçbir <ds:Reference> bulunamadı.")
        return _fail()

    digests_ok = True
    data_ref_count = 0
    signed_props_ref_verified = False
    verified_data_nodes: list[Element] = []
    covers_full_document_root = False
    detached_ref_used = False

    for ref in refs:
        ref_uri = ref.getAttribute("URI")
        ref_has_uri = ref.hasAttribute("URI")
        ref_type = ref.getAttribute("Type").strip()
        dm_list = _direct_children_ns(ref, DS_NS, "DigestMethod")
        dv_list = _direct_children_ns(ref, DS_NS, "DigestValue")
        if len(dm_list) != 1 or len(dv_list) != 1:
            digests_ok = False
            codes.append("XADES_MALFORMED_STRUCTURE")
            errors.append("<ds:Reference> içinde tekil DigestMethod ve DigestValue zorunludur.")
            continue

        dm_uri = dm_list[0].getAttribute("Algorithm").strip()
        if dm_uri not in SUPPORTED_DIGEST_METHODS:
            digests_ok = False
            codes.append("XADES_UNSUPPORTED_OR_WEAK_DIGEST_METHOD")
            errors.append(f"Desteklenmeyen veya zayıf DigestMethod reddedildi: {dm_uri!r}.")
            continue

        expected_digest_b64 = re.sub(r"\s+", "", _element_text(dv_list[0]).strip())
        transforms_containers = _direct_children_ns(ref, DS_NS, "Transforms")
        transform_elems: list[Element] = []
        for tc in transforms_containers:
            transform_elems.extend(_direct_children_ns(tc, DS_NS, "Transform"))
        transform_steps: list[tuple[str, set[str]]] = [
            (t.getAttribute("Algorithm").strip(), _get_inclusive_prefixes(t))
            for t in transform_elems
        ]
        transform_uris = [alg for alg, _ in transform_steps]

        is_signed_props_ref = (
            ref_type == "http://uri.etsi.org/01903#SignedProperties"
            or (
                expected_signed_props is not None
                and ref_uri.startswith("#")
                and id_map.get(ref_uri[1:]) is expected_signed_props
            )
        )

        ref_record: dict[str, Any] = {
            "uri": ref_uri if ref_has_uri else None,
            "type": ref_type or None,
            "digest_method": dm_uri,
            "transforms": transform_uris,
            "transform_trace": [],
            "kind": "SIGNED_PROPERTIES" if is_signed_props_ref else "DATA",
            "verified": False,
        }

        if len(transform_steps) > MAX_TRANSFORMS_PER_REFERENCE:
            digests_ok = False
            codes.append("XADES_EXCESSIVE_TRANSFORMS_COUNT")
            errors.append(
                f"<ds:Reference> içinde izin verilen azami transform sayısı ({MAX_TRANSFORMS_PER_REFERENCE}) aşıldı."
            )
            details["references"].append(ref_record)
            continue

        # Validate every transform URI against strict allowlist (fail-closed on XSLT, XPath, XPath Filter 2, unknown!)
        bad_transform = False
        for t_uri in transform_uris:
            if t_uri not in SUPPORTED_C14N_METHODS and t_uri not in (TRANSFORM_ENVELOPED_SIGNATURE, TRANSFORM_BASE64):
                digests_ok = False
                bad_transform = True
                codes.append("XADES_UNSUPPORTED_OR_FORBIDDEN_TRANSFORM")
                errors.append(f"Desteklenmeyen veya güvensiz XMLDSig Transform reddedildi: {t_uri!r}.")
        if bad_transform:
            details["references"].append(ref_record)
            continue

        # Resolve URI target into typed TransformPipelineData (NODE_SET vs OCTET_STREAM)
        initial_data: TransformPipelineData | None = None
        if not ref_has_uri or (ref_uri != "" and not ref_uri.startswith("#")):
            # Detached content reference — NEVER fetch remote URLs or local filesystem paths!
            if is_signed_props_ref:
                digests_ok = False
                codes.append("XADES_XSW_SIGNED_PROPERTIES_OUTSIDE_SIGNATURE")
                errors.append("SignedProperties referansı ayrık (detached) URI kullanamaz (XSW engellendi).")
                details["references"].append(ref_record)
                continue
            detached_ref_used = True
            data_ref_count += 1
            if signed_content_bytes is None:
                digests_ok = False
                codes.append("XADES_DETACHED_CONTENT_MISSING")
                errors.append(f"Ayrık XAdES referansı ('{ref_uri}') için imzalı içerik baytları zorunludur.")
                details["references"].append(ref_record)
                continue
            initial_data = TransformPipelineData(kind=TRANSFORM_KIND_OCTET_STREAM, octets=signed_content_bytes)
        elif ref_uri == "":
            # Whole-document enveloped reference (URI="") -> starts as NODE_SET rooted at documentElement
            if is_signed_props_ref:
                digests_ok = False
                codes.append("XADES_XSW_SIGNED_PROPERTIES_OUTSIDE_SIGNATURE")
                errors.append("SignedProperties referansı URI='' tüm belge referansı olamaz (XSW engellendi).")
                details["references"].append(ref_record)
                continue
            if sig_is_doc_root:
                digests_ok = False
                codes.append("XADES_XSW_INVALID_EMPTY_URI_ON_DETACHED_SIGNATURE")
                errors.append("Kök öğe <ds:Signature> iken URI='' enveloped referans kullanılamaz.")
                details["references"].append(ref_record)
                continue
            data_ref_count += 1
            if TRANSFORM_ENVELOPED_SIGNATURE not in transform_uris:
                digests_ok = False
                codes.append("XADES_ENVELOPED_TRANSFORM_REQUIRED")
                errors.append("URI='' enveloped referansı için enveloped-signature transformu zorunludur.")
                details["references"].append(ref_record)
                continue
            # Whole-document enveloped reference (URI="") -> starts as NODE_SET rooted at full XML Document!
            initial_data = TransformPipelineData(kind=TRANSFORM_KIND_NODE_SET, node=doc)
            verified_data_nodes.append(doc.documentElement)
            covers_full_document_root = True
        else:
            # Same-document fragment URI="#<id>" -> starts as NODE_SET rooted at unique target_node
            target_id = ref_uri[1:]
            target_node = id_map.get(target_id)
            if target_node is None:
                digests_ok = False
                if not is_signed_props_ref:
                    data_ref_count += 1
                codes.append("XADES_REFERENCE_URI_NOT_FOUND")
                errors.append(f"XAdES Reference URI '{ref_uri}' belgede hiçbir benzersiz ID ile eşleşmedi.")
                details["references"].append(ref_record)
                continue

            if is_signed_props_ref:
                # Anti-XSW: SignedProperties MUST be the exact element inside THIS Signature's QualifyingProperties!
                if expected_signed_props is None or target_node is not expected_signed_props:
                    digests_ok = False
                    codes.append("XADES_XSW_SIGNED_PROPERTIES_OUTSIDE_SIGNATURE")
                    errors.append(
                        f"SignedProperties referansı ('{ref_uri}') doğrulanan <ds:Signature>/<ds:Object>/<xades:QualifyingProperties> dışındaki bir düğüme işaret ediyor (XSW engellendi)."
                    )
                    details["references"].append(ref_record)
                    continue
            else:
                data_ref_count += 1
                # Anti-XSW: Data reference checks!
                if not sig_is_doc_root and _is_descendant_of(target_node, sig_elem):
                    # Classic XSW3/XSW4/XSW6: signed business element moved inside <ds:Signature>/<ds:Object> while unsigned evil payload sits at root!
                    digests_ok = False
                    codes.append("XADES_XSW_DATA_REF_HIDDEN_INSIDE_SIGNATURE")
                    errors.append(
                        f"Veri referansı ('{ref_uri}') enveloped belgede <ds:Signature> içine gizlenmiş bir düğüme işaret ediyor (XML Signature Wrapping saldırısı reddedildi)."
                    )
                    details["references"].append(ref_record)
                    continue
                if sig_is_doc_root and not _is_descendant_of(target_node, sig_elem):
                    digests_ok = False
                    codes.append("XADES_XSW_DATA_REF_OUTSIDE_ENVELOPING_SIGNATURE")
                    errors.append("Enveloping imza referansı imza dışına işaret ediyor.")
                    details["references"].append(ref_record)
                    continue
                if target_node is doc.documentElement:
                    covers_full_document_root = True
                verified_data_nodes.append(target_node)
                details["verified_signed_node_ids"].append(target_id)

            initial_data = TransformPipelineData(kind=TRANSFORM_KIND_NODE_SET, node=target_node)

        # Execute ALL <ds:Transform> steps strictly sequentially: Transform N output -> Transform N+1 input!
        try:
            octets_to_hash, transform_trace = execute_xmldsig_transform_pipeline(
                initial_data,
                transform_steps,
                verifying_signature_node=sig_elem,
            )
            ref_record["transform_trace"] = transform_trace
        except XmlSecurityError as exc:
            digests_ok = False
            codes.append(exc.code)
            errors.append(exc.message)
            ref_record["transform_error_code"] = exc.code
            details["references"].append(ref_record)
            continue

        actual_digest_b64 = base64.b64encode(_compute_digest(octets_to_hash, dm_uri)).decode("ascii")
        if hmac.compare_digest(actual_digest_b64, expected_digest_b64):
            ref_record["verified"] = True
            if is_signed_props_ref:
                signed_props_ref_verified = True
        else:
            digests_ok = False
            if is_signed_props_ref:
                codes.append("XADES_SIGNED_PROPERTIES_DIGEST_MISMATCH")
                errors.append("XAdES SignedProperties özet doğrulaması başarısızdır (tahrifat tespit edildi).")
            else:
                codes.append("XADES_CONTENT_DIGEST_MISMATCH")
                errors.append(f"XAdES veri referansı ('{ref_uri}') özet doğrulaması başarısızdır (içerik tahrifatı tespit edildi).")
        details["references"].append(ref_record)

    if data_ref_count == 0:
        digests_ok = False
        if not codes:
            codes.append("XADES_DATA_REFERENCE_MISSING")
            errors.append("XAdES SignedInfo içinde doğrulanmış veri referansı bulunamadı.")

    # Anti-XSW: If <xades:SignedProperties> exists, it MUST have been signed by a verified <ds:Reference>!
    if expected_signed_props is not None and not signed_props_ref_verified:
        digests_ok = False
        if "XADES_SIGNED_PROPERTIES_DIGEST_MISMATCH" not in codes:
            codes.append("XADES_SIGNED_PROPERTIES_NOT_SIGNED")
            errors.append("<xades:SignedProperties> öğesi <ds:SignedInfo> referansı ile imzalanmamıştır.")

    # Anti-XSW Enveloped Document Coverage Invariant:
    # When the XML document has an enveloping wrapper / business root (doc.documentElement != <ds:Signature>),
    # unsigned business sibling/ancestor elements OUTSIDE the signed subtree MUST NOT masquerade as signed content!
    if not sig_is_doc_root and not detached_ref_used:
        details["signature_mode"] = "ENVELOPED"
        if not covers_full_document_root and verified_data_nodes:
            # Verify no unsigned business element siblings exist alongside the signed node(s) and <ds:Signature>!
            root_children_elems = [
                ch for ch in doc.documentElement.childNodes
                if ch.nodeType == Node.ELEMENT_NODE and ch is not sig_elem
            ]
            unsigned_siblings = [
                ch for ch in root_children_elems
                if not any(_is_descendant_of(ch, vn) or ch is vn for vn in verified_data_nodes)
            ]
            # Also check if verified_data_nodes are buried deeper inside an unsigned wrapper element!
            buried_in_unsigned_wrapper = any(
                vn.parentNode is not doc.documentElement and vn is not doc.documentElement
                for vn in verified_data_nodes
            )
            if unsigned_siblings or buried_in_unsigned_wrapper:
                digests_ok = False
                codes.append("XADES_XSW_UNSIGNED_CONTENT_OUTSIDE_SIGNED_SCOPE")
                errors.append(
                    "XML belgesinde imzalı referans kapsamı dışında kalan imzasız içerik/kardeş düğüm tespit edildi "
                    "(XML Signature Wrapping koruması gereği reddedildi)."
                )
    elif sig_is_doc_root and verified_data_nodes:
        details["signature_mode"] = "ENVELOPING"
    else:
        details["signature_mode"] = "DETACHED"

    # 7. Canonicalize <ds:SignedInfo> using its EXACT declared CanonicalizationMethod and verify SignatureValue
    #    using its EXACT declared SignatureMethod!
    signed_info_c14n = canonicalize_xml_node(
        signed_info,
        c14n_uri,
        inclusive_prefixes=c14n_inc_prefixes,
    )
    sig_ok, sig_err_code, sig_err_msg = _verify_bytes_xmldsig(
        signed_info_c14n,
        sig_val_bytes,
        signer_cert_pem,
        sig_method_uri,
    )
    if not sig_ok:
        if sig_err_code:
            codes.append(sig_err_code)
        if sig_err_msg:
            errors.append(sig_err_msg)

    crypto_valid = bool(digests_ok and sig_ok and len(codes) == 0)

    # 8. Verify XAdES B-B SigningCertificateV2 (or SigningCertificate) CertDigest using its declared DigestMethod!
    if crypto_valid and expected_signed_props is not None and signed_props_ref_verified:
        sc_list = _descendants_ns(expected_signed_props, XADES_NS, "SigningCertificateV2")
        if not sc_list:
            sc_list = _descendants_ns(expected_signed_props, XADES_NS, "SigningCertificate")
        if sc_list:
            cd_elems = _descendants_ns(sc_list[0], XADES_NS, "CertDigest")
            if cd_elems:
                cd_dm = _direct_children_ns(cd_elems[0], DS_NS, "DigestMethod")
                cd_dv = _direct_children_ns(cd_elems[0], DS_NS, "DigestValue")
                if cd_dm and cd_dv:
                    cd_alg = cd_dm[0].getAttribute("Algorithm").strip()
                    if cd_alg in SUPPORTED_DIGEST_METHODS:
                        cert_der = _cert_pem_der_bytes(signer_cert_pem)
                        exp_b64 = base64.b64encode(_compute_digest(cert_der, cd_alg)).decode("ascii")
                        act_b64 = re.sub(r"\s+", "", _element_text(cd_dv[0]).strip())
                        has_signing_cert_ref = hmac.compare_digest(exp_b64, act_b64)

    # 9. Extract embedded unsigned properties strictly from THIS Signature's QualifyingProperties
    for qp_el in qp_list:
        usp_list = _descendants_ns(qp_el, XADES_NS, "UnsignedSignatureProperties")
        for usp in usp_list:
            sts_list = _direct_children_ns(usp, XADES_NS, "SignatureTimeStamp")
            if sts_list and emb_sig_ts is None:
                enc = _descendants_ns(sts_list[0], XADES_NS, "EncapsulatedTimeStamp")
                if enc:
                    emb_sig_ts = base64.b64decode(re.sub(r"\s+", "", _element_text(enc[0]).strip()))
            ats_list = _direct_children_ns(usp, XADES141_NS, "ArchiveTimeStamp") + _direct_children_ns(
                usp, XADES_NS, "ArchiveTimeStamp"
            )
            if ats_list and emb_arch_ts is None:
                enc = _descendants_ns(ats_list[0], XADES_NS, "EncapsulatedTimeStamp")
                if enc:
                    emb_arch_ts = base64.b64decode(re.sub(r"\s+", "", _element_text(enc[0]).strip()))
            rv_list = _direct_children_ns(usp, XADES_NS, "RevocationValues")
            for rv in rv_list:
                if emb_ocsp is None:
                    ocsp_els = _descendants_ns(rv, XADES_NS, "EncapsulatedOCSPValue")
                    if ocsp_els:
                        emb_ocsp = base64.b64decode(re.sub(r"\s+", "", _element_text(ocsp_els[0]).strip()))
                if emb_crl is None:
                    crl_els = _descendants_ns(rv, XADES_NS, "EncapsulatedCRLValue")
                    if crl_els:
                        emb_crl = base64.b64decode(re.sub(r"\s+", "", _element_text(crl_els[0]).strip())).decode("utf-8")

    return XadesXmlDsigInspection(
        crypto_valid=crypto_valid,
        has_signing_cert_ref=has_signing_cert_ref,
        signer_cert_pem=signer_cert_pem,
        signature_value_bytes=sig_val_bytes,
        embedded_sig_ts_der=emb_sig_ts,
        embedded_archive_ts_der=emb_arch_ts,
        embedded_ocsp_der=emb_ocsp,
        embedded_crl_pem=emb_crl,
        xmldsig_details=details,
        error_codes=tuple(sorted(set(codes))),
        errors=tuple(errors),
    )


def create_xades_xml_bytes_v2(
    content_bytes: bytes,
    signer_cert_pem: str,
    signer_key_pem: str,
    *,
    mode: str = "DETACHED",  # DETACHED | ENVELOPED | ENVELOPING
    canonicalization_method: str = C14N_INCLUSIVE_10,
    signature_method: str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    digest_method: str = "http://www.w3.org/2001/04/xmlenc#sha256",
    data_transforms: Sequence[str | tuple[str, set[str] | list[str] | tuple[str, ...]]] | None = None,
    signed_props_transforms: Sequence[str | tuple[str, set[str] | list[str] | tuple[str, ...]]] | None = None,
    enveloping_inline_xml: bool = False,
    extra_signature_attrs: str = "",
    include_signing_cert_v2: bool = True,
    signing_time_utc: str | None = None,
    signature_timestamp_tsr_der: bytes | None = None,
    archive_timestamp_tsr_der: bytes | None = None,
    archived_ocsp_response_der: bytes | None = None,
    archived_crl_pem: str | None = None,
) -> tuple[bytes, bytes]:
    """Create a standards-compliant W3C XMLDSig + ETSI EN 319 132 XAdES XML signature (returns `(xml_bytes, raw_sig_bytes)`)."""
    if canonicalization_method not in SUPPORTED_C14N_METHODS:
        raise ValueError(f"Desteklenmeyen C14N: {canonicalization_method!r}")
    if signature_method not in SUPPORTED_SIGNATURE_METHODS:
        raise ValueError(f"Desteklenmeyen SignatureMethod: {signature_method!r}")
    if digest_method not in SUPPORTED_DIGEST_METHODS:
        raise ValueError(f"Desteklenmeyen DigestMethod: {digest_method!r}")

    mode_norm = mode.upper().strip()
    signing_time = signing_time_utc or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    clean_cert = _extract_clean_cert_pem(signer_cert_pem)
    cert_der = _cert_pem_der_bytes(clean_cert)
    cert_b64 = base64.b64encode(cert_der).decode("ascii")
    cert_digest_b64 = base64.b64encode(_compute_digest(cert_der, digest_method)).decode("ascii")

    cert_v2_xml = (
        f"<xades:SigningCertificateV2><xades:Cert><xades:CertDigest>"
        f'<ds:DigestMethod Algorithm="{digest_method}"></ds:DigestMethod>'
        f"<ds:DigestValue>{cert_digest_b64}</ds:DigestValue>"
        f"</xades:CertDigest></xades:Cert></xades:SigningCertificateV2>"
        if include_signing_cert_v2
        else ""
    )

    signed_props_inner = (
        f'<xades:SignedProperties Id="SignedProps-1">'
        f"<xades:SignedSignatureProperties>"
        f"<xades:SigningTime>{signing_time}</xades:SigningTime>"
        f"{cert_v2_xml}"
        f"</xades:SignedSignatureProperties>"
        f"</xades:SignedProperties>"
    )

    # Build unsigned properties XML
    unsigned_parts: list[str] = []
    if signature_timestamp_tsr_der:
        unsigned_parts.append(
            f"<xades:SignatureTimeStamp><xades:EncapsulatedTimeStamp>"
            f"{base64.b64encode(signature_timestamp_tsr_der).decode('ascii')}"
            f"</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp>"
        )
    rev_inner: list[str] = []
    if archived_ocsp_response_der:
        rev_inner.append(
            f"<xades:OCSPValues><xades:EncapsulatedOCSPValue>"
            f"{base64.b64encode(archived_ocsp_response_der).decode('ascii')}"
            f"</xades:EncapsulatedOCSPValue></xades:OCSPValues>"
        )
    if archived_crl_pem:
        rev_inner.append(
            f"<xades:CRLValues><xades:EncapsulatedCRLValue>"
            f"{base64.b64encode(archived_crl_pem.encode('utf-8')).decode('ascii')}"
            f"</xades:EncapsulatedCRLValue></xades:CRLValues>"
        )
    if rev_inner:
        unsigned_parts.append(f"<xades:RevocationValues>{''.join(rev_inner)}</xades:RevocationValues>")
    if archive_timestamp_tsr_der:
        unsigned_parts.append(
            f'<xades141:ArchiveTimeStamp xmlns:xades141="{XADES141_NS}"><xades:EncapsulatedTimeStamp>'
            f"{base64.b64encode(archive_timestamp_tsr_der).decode('ascii')}"
            f"</xades:EncapsulatedTimeStamp></xades141:ArchiveTimeStamp>"
        )
    unsigned_xml = (
        f"<xades:UnsignedProperties><xades:UnsignedSignatureProperties>{''.join(unsigned_parts)}"
        f"</xades:UnsignedSignatureProperties></xades:UnsignedProperties>"
        if unsigned_parts
        else ""
    )

    if data_transforms is not None:
        effective_data_steps = _normalize_transform_steps(data_transforms)
    elif mode_norm == "DETACHED":
        effective_data_steps = []
    elif mode_norm == "ENVELOPED":
        effective_data_steps = [
            (TRANSFORM_ENVELOPED_SIGNATURE, set()),
            (canonicalization_method, set()),
        ]
    elif mode_norm == "ENVELOPING":
        effective_data_steps = [(canonicalization_method, set())]
    else:
        raise ValueError(f"Desteklenmeyen XAdES modu: {mode!r}")

    if signed_props_transforms is not None:
        effective_props_steps = _normalize_transform_steps(signed_props_transforms)
    else:
        effective_props_steps = [(canonicalization_method, set())]

    data_transforms_xml = _render_transforms_xml(effective_data_steps)
    props_transforms_xml = _render_transforms_xml(effective_props_steps)

    # First pass: assemble document skeleton with placeholder DigestValues & SignatureValue so exact ancestor
    # namespace context is identical during canonicalization AND final verification!
    if mode_norm == "DETACHED":
        data_ref_xml = (
            f'<ds:Reference Id="Ref-Data" URI="detached-content">'
            f"{data_transforms_xml}"
            f'<ds:DigestMethod Algorithm="{digest_method}"></ds:DigestMethod>'
            f"<ds:DigestValue>PLACEHOLDER_DATA</ds:DigestValue>"
            f"</ds:Reference>"
        )
        enveloping_obj_xml = ""
    elif mode_norm == "ENVELOPED":
        data_ref_xml = (
            f'<ds:Reference Id="Ref-Doc" URI="">'
            f"{data_transforms_xml}"
            f'<ds:DigestMethod Algorithm="{digest_method}"></ds:DigestMethod>'
            f"<ds:DigestValue>PLACEHOLDER_DATA</ds:DigestValue>"
            f"</ds:Reference>"
        )
        enveloping_obj_xml = ""
    elif mode_norm == "ENVELOPING":
        if enveloping_inline_xml:
            obj_payload = re.sub(r"^\s*<\?xml(?=\s)[^?]*\?>\s*", "", content_bytes.decode("utf-8").strip(), count=1)
        else:
            obj_payload = base64.b64encode(content_bytes).decode("ascii")
        data_ref_xml = (
            f'<ds:Reference Id="Ref-Obj" URI="#Obj-Data-1">'
            f"{data_transforms_xml}"
            f'<ds:DigestMethod Algorithm="{digest_method}"></ds:DigestMethod>'
            f"<ds:DigestValue>PLACEHOLDER_DATA</ds:DigestValue>"
            f"</ds:Reference>"
        )
        enveloping_obj_xml = f'<ds:Object Id="Obj-Data-1">{obj_payload}</ds:Object>'
    else:
        raise ValueError(f"Desteklenmeyen XAdES modu: {mode!r}")

    props_ref_xml = (
        f'<ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#SignedProps-1">'
        f"{props_transforms_xml}"
        f'<ds:DigestMethod Algorithm="{digest_method}"></ds:DigestMethod>'
        f"<ds:DigestValue>PLACEHOLDER_PROPS</ds:DigestValue>"
        f"</ds:Reference>"
    )

    extra_attrs = (" " + extra_signature_attrs.strip()) if extra_signature_attrs.strip() else ""
    sig_skeleton = (
        f'<ds:Signature xmlns:ds="{DS_NS}" xmlns:xades="{XADES_NS}"{extra_attrs} Id="Sig-1">'
        f"<ds:SignedInfo>"
        f'<ds:CanonicalizationMethod Algorithm="{canonicalization_method}"></ds:CanonicalizationMethod>'
        f'<ds:SignatureMethod Algorithm="{signature_method}"></ds:SignatureMethod>'
        f"{data_ref_xml}"
        f"{props_ref_xml}"
        f"</ds:SignedInfo>"
        f'<ds:SignatureValue Id="SigVal-1">PLACEHOLDER_SIG</ds:SignatureValue>'
        f"<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"
        f"{enveloping_obj_xml}"
        f"<ds:Object>"
        f'<xades:QualifyingProperties Target="#Sig-1">'
        f"{signed_props_inner}"
        f"{unsigned_xml}"
        f"</xades:QualifyingProperties>"
        f"</ds:Object>"
        f"</ds:Signature>"
    )

    if mode_norm == "ENVELOPED":
        # Embed <ds:Signature> directly inside caller's XML document root while preserving ALL
        # document-level PIs (e.g. <?xml-stylesheet ...?>) and comments before/after documentElement!
        pre_doc = safe_parse_xml_bytes(content_bytes)
        try:
            if pre_doc.documentElement is None:
                raise ValueError("ENVELOPED XAdES için geçerli bir kök öğeye sahip XML belgesi gereklidir.")
            root_tag = pre_doc.documentElement.tagName
        finally:
            pre_doc.unlink()
        inner_doc_str = re.sub(r"^\s*<\?xml(?=\s)[^?]*\?>\s*", "", content_bytes.decode("utf-8").strip(), count=1)
        close_token = f"</{root_tag}>"
        close_idx = inner_doc_str.rfind(close_token)
        if close_idx != -1:
            embedded_doc = inner_doc_str[:close_idx] + sig_skeleton + inner_doc_str[close_idx:]
        else:
            # Handle self-closing root element `<root .../>` cleanly
            m_self = re.search(rf"<{re.escape(root_tag)}\b([^>]*?)/>", inner_doc_str)
            if not m_self:
                raise ValueError("ENVELOPED XAdES için geçerli bir kök öğeye sahip XML belgesi gereklidir.")
            embedded_doc = (
                inner_doc_str[: m_self.start()]
                + f"<{root_tag}{m_self.group(1)}>{sig_skeleton}</{root_tag}>"
                + inner_doc_str[m_self.end() :]
            )
        skeleton_full = '<?xml version="1.0" encoding="UTF-8"?>' + embedded_doc
    else:
        skeleton_full = '<?xml version="1.0" encoding="UTF-8"?>' + sig_skeleton

    # Parse skeleton in exact final namespace context to compute true sequential transform digests
    doc = safe_parse_xml_bytes(skeleton_full.encode("utf-8"))
    try:
        sig_el = _descendants_ns(doc.documentElement, DS_NS, "Signature")[0]
        sp_el = _descendants_ns(sig_el, XADES_NS, "SignedProperties")[0]

        sp_octets, _ = execute_xmldsig_transform_pipeline(
            TransformPipelineData(kind=TRANSFORM_KIND_NODE_SET, node=sp_el),
            effective_props_steps,
            verifying_signature_node=sig_el,
        )
        props_digest_b64 = base64.b64encode(_compute_digest(sp_octets, digest_method)).decode("ascii")

        if mode_norm == "DETACHED":
            data_initial = TransformPipelineData(kind=TRANSFORM_KIND_OCTET_STREAM, octets=content_bytes)
        elif mode_norm == "ENVELOPED":
            data_initial = TransformPipelineData(kind=TRANSFORM_KIND_NODE_SET, node=doc)
        else:
            id_map, _ = _collect_all_xml_ids(doc)
            data_initial = TransformPipelineData(kind=TRANSFORM_KIND_NODE_SET, node=id_map["Obj-Data-1"])

        data_octets, _ = execute_xmldsig_transform_pipeline(
            data_initial,
            effective_data_steps,
            verifying_signature_node=sig_el,
        )
        data_digest_b64 = base64.b64encode(_compute_digest(data_octets, digest_method)).decode("ascii")
    finally:
        doc.unlink()

    with_digests = (
        skeleton_full.replace("PLACEHOLDER_DATA", data_digest_b64)
        .replace("PLACEHOLDER_PROPS", props_digest_b64)
    )

    # Re-parse with real DigestValues and canonicalize <ds:SignedInfo> in exact final document context!
    doc2 = safe_parse_xml_bytes(with_digests.encode("utf-8"))
    try:
        sig_el2 = _descendants_ns(doc2.documentElement, DS_NS, "Signature")[0]
        si_el2 = _direct_children_ns(sig_el2, DS_NS, "SignedInfo")[0]
        si_c14n = canonicalize_xml_node(si_el2, canonicalization_method)
    finally:
        doc2.unlink()

    raw_sig = _sign_bytes_xmldsig(si_c14n, signer_key_pem, signature_method)
    sig_b64 = base64.b64encode(raw_sig).decode("ascii")
    final_xml = with_digests.replace("PLACEHOLDER_SIG", sig_b64).encode("utf-8")
    return final_xml, raw_sig
