"""hrAI @HukukSGK v1.0.5.1 — Strict DER SET/SET OF Canonical Ordering, Strict ASN.1 Character Strings & hrAI Brand Transition Test Suite.

Covers all v1.0.5.1 independent audit remediations while preserving all 230 baseline tests,
L1-L4 74/74 statutory core, L5/L6 autonomous norm architecture, OpenSSL 3 cryptographic
verifications, and byte-identical `engine/esign5070/xmldsig.py`:
  1. ITU-T X.690 §11.5 (`SET` canonical tag order, no duplicate tags) & §11.6 (`SET OF` ascending
     octet order with trailing 0x00 comparison padding) at both primitive and full-certificate levels.
  2. Strict per-type ASN.1 character string decoding (`UTF8String`, `PrintableString`, `NumericString`,
     `IA5String`, `VisibleString`, `GraphicString`, `GeneralString`, `TeletexString`, `VideotexString`,
     `BMPString` UCS-2 without surrogates, `UniversalString` UTF-32-BE) with zero lossy replacement
     fallback and fail-closed zero partial metadata on any invalid certificate encoding.
  3. Positive boundary X.509 certificates generated via OpenSSL 3 (Turkish UTF-8 DN, multi-valued
     RDN `SET OF`, PrintableString punctuation, SAN `dNSName`/`rfc822Name`/`URI`/`dirName`,
     valid `BMPString` & `UniversalString`, Ed25519, RSA-PSS, leap-day UTCTime & GeneralizedTime).
  4. Backward-compatible `hrAI` / `@hrAI` / `@HukukSGK` / `www.insenai.com.tr` brand transition,
     `hrAI-HukukSGK/1.0.5.1 (SourceAcquisition)` User-Agent, preservation of historical `CALISORA-*`
     and `AUD-20261120-*` records, and closed production / 5070 / KVKK gates.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from engine.attestation_verifier import PARSER_VERSION, verify_attestation_ledger
from engine.autonomous_norms import (
    AUTONOMOUS_NORMS_VERSION,
    load_l5_hr_procedures,
    load_l6_cba_contract_practices,
    validate_autonomous_norms_audit_log,
)
from engine.esign5070 import (
    ESIGN_5070_VERSION,
    DefaultQualifiedSignature5070Verifier,
    DefaultSscdControlEvidenceVerifier,
    DerParseError,
    inspect_signer_certificate_x509,
    parse_x509_certificate_metadata,
    parse_x509_certificate_metadata_der,
)
from engine.esign5070 import x509_metadata as x509_mod
from engine.knowledge_card_validator import load_knowledge_cards, validate_central_audit_log
from engine.legal_reasoning import TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA
from engine.precedent_verifier import load_precedent_registry
from engine.source_validator import load_source_registry
from engine.tools_router import HukukSGKToolRouter
from engine.trust_root import TRUST_ROOT_VERSION, run_live_integration_probe
from tests.pki_test_helpers import Ephemeral5070PkiFixture

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_XMLDSIG_SHA256 = "b16207b5fb71d7c0d0372838411c7795459ac460c2ff232766ae230b9cbacf85"


def _pem_to_der(pem_text: str) -> bytes:
    lines = [ln.strip() for ln in pem_text.strip().splitlines() if not ln.startswith("-----")]
    return base64.b64decode("".join(lines).encode("ascii"))


def _der_to_pem(der_bytes: bytes) -> str:
    b64 = base64.b64encode(der_bytes).decode("ascii")
    body = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"


def _encode_der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: bytes, val: bytes) -> bytes:
    return tag + _encode_der_len(len(val)) + val


def _rebuild_cert_with_subject(base_cert_der: bytes, new_subject_seq_der: bytes) -> bytes:
    """Rebuild an X.509 Certificate DER replacing TBSCertificate.subject with `new_subject_seq_der`."""
    _, c_vs, c_ve, _ = x509_mod._read_tlv(base_cert_der, 0, len(base_cert_der))
    cert_spans = x509_mod._iter_children_with_spans(base_cert_der, c_vs, c_ve)
    tbs_s, _, tbs_vs, tbs_ve, _ = cert_spans[0]
    sigalg_s, _, _, _, sigalg_nxt = cert_spans[1]
    sigval_s, _, _, _, sigval_nxt = cert_spans[2]

    tbs_spans = x509_mod._iter_children_with_spans(base_cert_der, tbs_vs, tbs_ve)
    idx = 1 if tbs_spans[0][1] == 0xA0 else 0
    # TBSCertificate order after optional version: serial(0), sigAlg(1), issuer(2), validity(3), subject(4), spki(5), ...
    subject_idx = idx + 4
    parts: list[bytes] = []
    for i, (fs, _ft, _fvs, _fve, fnxt) in enumerate(tbs_spans):
        if i == subject_idx:
            parts.append(new_subject_seq_der)
        else:
            parts.append(base_cert_der[fs:fnxt])
    new_tbs = _tlv(b"\x30", b"".join(parts))
    return _tlv(
        b"\x30",
        new_tbs + base_cert_der[sigalg_s:sigalg_nxt] + base_cert_der[sigval_s:sigval_nxt],
    )


def _rebuild_cert_appending_extension(base_cert_der: bytes, ext_oid_der: bytes, ext_val_der: bytes) -> bytes:
    """Rebuild an X.509 v3 Certificate DER appending a custom extension TLV inside [3] extensions."""
    _, c_vs, c_ve, _ = x509_mod._read_tlv(base_cert_der, 0, len(base_cert_der))
    cert_spans = x509_mod._iter_children_with_spans(base_cert_der, c_vs, c_ve)
    _, _, tbs_vs, tbs_ve, _ = cert_spans[0]
    sigalg_s, _, _, _, sigalg_nxt = cert_spans[1]
    sigval_s, _, _, _, sigval_nxt = cert_spans[2]

    tbs_spans = x509_mod._iter_children_with_spans(base_cert_der, tbs_vs, tbs_ve)
    new_ext = _tlv(b"\x30", _tlv(b"\x06", ext_oid_der) + _tlv(b"\x04", ext_val_der))

    parts: list[bytes] = []
    added = False
    for fs, ft, fvs, fve, fnxt in tbs_spans:
        if ft == 0xA3:
            _, es_vs, es_ve, _ = x509_mod._read_tlv(base_cert_der, fvs, fve)
            existing_exts = base_cert_der[es_vs:es_ve]
            new_ext_seq = _tlv(b"\x30", existing_exts + new_ext)
            parts.append(_tlv(b"\xa3", new_ext_seq))
            added = True
        else:
            parts.append(base_cert_der[fs:fnxt])
    if not added:
        parts.append(_tlv(b"\xa3", _tlv(b"\x30", new_ext)))
    new_tbs = _tlv(b"\x30", b"".join(parts))
    return _tlv(
        b"\x30",
        new_tbs + base_cert_der[sigalg_s:sigalg_nxt] + base_cert_der[sigval_s:sigval_nxt],
    )


class TestHrAiV1051DerSetStringsAndBrand(unittest.TestCase):
    """[V1.0.5.1 / X.690 DER SET & SET OF / STRICT ASN.1 STRINGS / HRAI BRAND] Independent audit remediation suite."""

    def test_01_der_set_and_set_of_x690_canonical_ordering_primitives_and_full_certs(self) -> None:
        # 1. Explicit DER SET canonical tag order (ITU-T X.690 §11.5 / X.680 §8.6)
        #    Order: UNIVERSAL (0) < APPLICATION (1) < CONTEXT-SPECIFIC (2) < PRIVATE (3), then ascending tag number
        valid_set_classes = (
            _tlv(b"\x02", b"\x01")      # UNIVERSAL 2 (INTEGER)
            + _tlv(b"\x40", b"\x01")    # APPLICATION 0
            + _tlv(b"\x80", b"\x01")    # CONTEXT-SPECIFIC 0
            + _tlv(b"\xc0", b"\x01")    # PRIVATE 0
        )
        self.assertEqual(len(x509_mod._validate_der_set_order(valid_set_classes, 0, len(valid_set_classes))), 4)

        # Swapped classes: APPLICATION before UNIVERSAL -> rejected
        bad_set_class = _tlv(b"\x40", b"\x01") + _tlv(b"\x02", b"\x01")
        with self.assertRaises(DerParseError):
            x509_mod._validate_der_set_order(bad_set_class, 0, len(bad_set_class))

        # Constructed [0] (0xA0) MUST precede Primitive [1] (0x81) under X.690 §11.5 (P/C bit ignored!)
        valid_set_pc = _tlv(b"\xa0", _tlv(b"\x02", b"\x01")) + _tlv(b"\x81", b"\x02")
        self.assertEqual(len(x509_mod._validate_der_set_order(valid_set_pc, 0, len(valid_set_pc))), 2)
        bad_set_pc = _tlv(b"\x81", b"\x02") + _tlv(b"\xa0", _tlv(b"\x02", b"\x01"))
        with self.assertRaises(DerParseError):
            x509_mod._validate_der_set_order(bad_set_pc, 0, len(bad_set_pc))

        # High-tag-number ordering: tag 30 (0x1E) < tag 31 (0x1F 0x1F) < tag 32 (0x1F 0x20)
        valid_high_tags = (
            _tlv(b"\x1e", b"\x00A")
            + _tlv(b"\x1f\x1f", b"\x01")
            + _tlv(b"\x1f\x20", b"\x02")
        )
        self.assertEqual(len(x509_mod._validate_der_set_order(valid_high_tags, 0, len(valid_high_tags))), 3)
        bad_high_tags = _tlv(b"\x1f\x20", b"\x02") + _tlv(b"\x1f\x1f", b"\x01")
        with self.assertRaises(DerParseError):
            x509_mod._validate_der_set_order(bad_high_tags, 0, len(bad_high_tags))

        # Duplicate tags in SET -> rejected (X.680 §27.3 / X.690 §11.5)
        dup_set = _tlv(b"\x02", b"\x01") + _tlv(b"\x02", b"\x02")
        with self.assertRaises(DerParseError):
            x509_mod._validate_der_set_order(dup_set, 0, len(dup_set))

        # 2. Explicit DER SET OF canonical ascending octet order (ITU-T X.690 §11.6)
        self.assertEqual(x509_mod._compare_der_set_of_octets(b"\x04\x01\x05", b"\x04\x01\x05\x00"), 0)
        self.assertEqual(x509_mod._compare_der_set_of_octets(b"\x30\x0a\xff", b"\x30\x0c\x00"), -1)
        self.assertEqual(x509_mod._compare_der_set_of_octets(b"\x30\x0c\x00", b"\x30\x0a\xff"), 1)

        elem_small = _tlv(b"\x0c", b"aaa")
        elem_large = _tlv(b"\x0c", b"bbb")
        valid_set_of = elem_small + elem_large
        self.assertEqual(len(x509_mod._validate_der_set_of_order(valid_set_of, 0, len(valid_set_of))), 2)
        # Non-decreasing equal elements permitted in SET OF
        equal_set_of = elem_small + elem_small
        self.assertEqual(len(x509_mod._validate_der_set_of_order(equal_set_of, 0, len(equal_set_of))), 2)
        # Out-of-order SET OF -> rejected
        bad_set_of = elem_large + elem_small
        with self.assertRaises(DerParseError):
            x509_mod._validate_der_set_of_order(bad_set_of, 0, len(bad_set_of))

        # Generic 0x31 container validation inside `_validate_and_collect_oids`
        bad_set_of_tlv = _tlv(b"\x31", bad_set_of)
        with self.assertRaises(DerParseError):
            x509_mod._validate_and_collect_oids(bad_set_of_tlv, 0, len(bad_set_of_tlv), set(), depth=0)
        bad_set_tlv = _tlv(b"\x31", bad_set_pc)
        with self.assertRaises(DerParseError):
            x509_mod._validate_and_collect_oids(bad_set_tlv, 0, len(bad_set_tlv), set(), depth=0)

        # 3. Full X.509 certificate: multi-valued RDN (SET OF AttributeTypeAndValue) positive + swapped negative
        openssl = shutil.which("openssl")
        self.assertIsNotNone(openssl)
        val_t = "2026-11-24T00:00:00Z"
        with tempfile.TemporaryDirectory(prefix="hrai_v1051_rdn_") as td:
            tdp = Path(td)
            key_p = tdp / "leaf.key"
            crt_p = tdp / "leaf.crt"
            subprocess.run(
                [openssl, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key_p)],
                stdin=subprocess.DEVNULL, check=True, capture_output=True, timeout=30,
            )
            subprocess.run(
                [
                    openssl, "req", "-x509", "-new", "-key", str(key_p), "-out", str(crt_p),
                    "-days", "365", "-multivalue-rdn",
                    "-subj", "/C=TR/O=hrAI+CN=Imzaci+OU=HukukSGK/serialNumber=TR-9001",
                ],
                stdin=subprocess.DEVNULL, check=True, capture_output=True, timeout=30,
            )
            valid_pem = crt_p.read_text(encoding="utf-8")
            valid_der = _pem_to_der(valid_pem)
            meta = parse_x509_certificate_metadata_der(valid_der)
            self.assertEqual(meta.signer_common_name, "Imzaci")
            self.assertEqual(meta.signer_serial_identifier, "TR-9001")
            self.assertEqual(meta.issuer_country, "TR")

            # Locate the multi-valued RDN SET in TBSCertificate.subject and reverse its AVAs
            _, c_vs, c_ve, _ = x509_mod._read_tlv(valid_der, 0, len(valid_der))
            _, tbs_vs, tbs_ve, _ = x509_mod._read_tlv(valid_der, c_vs, c_ve)
            tbs_spans = x509_mod._iter_children_with_spans(valid_der, tbs_vs, tbs_ve)
            idx = 1 if tbs_spans[0][1] == 0xA0 else 0
            _, _, sub_vs, sub_ve, _ = tbs_spans[idx + 4]
            rdn_spans = x509_mod._iter_children_with_spans(valid_der, sub_vs, sub_ve)
            swapped_rdns: list[bytes] = []
            swapped_any = False
            for rs, rt, rvs, rve, rnxt in rdn_spans:
                ava_spans = x509_mod._iter_children_with_spans(valid_der, rvs, rve)
                if len(ava_spans) >= 2:
                    ava_raws = [valid_der[s:n] for s, _, _, _, n in ava_spans]
                    ava_raws.reverse()
                    swapped_rdns.append(_tlv(b"\x31", b"".join(ava_raws)))
                    swapped_any = True
                else:
                    swapped_rdns.append(valid_der[rs:rnxt])
            self.assertTrue(swapped_any)
            unsorted_rdn_cert = _rebuild_cert_with_subject(valid_der, _tlv(b"\x30", b"".join(swapped_rdns)))

            # Fail-closed: MUST raise DerParseError and NEVER return partial metadata!
            with self.assertRaises(DerParseError):
                parse_x509_certificate_metadata_der(unsorted_rdn_cert)
            self.assertIsNone(parse_x509_certificate_metadata(_der_to_pem(unsorted_rdn_cert)))
            insp_unsorted = inspect_signer_certificate_x509(_der_to_pem(unsorted_rdn_cert), validation_time_utc=val_t)
            self.assertFalse(insp_unsorted.valid_x509)
            self.assertEqual(insp_unsorted.subject, "")
            self.assertEqual(insp_unsorted.issuer, "")
            self.assertEqual(insp_unsorted.serial_number, "")
            self.assertEqual(insp_unsorted.not_before_utc, "")
            self.assertEqual(insp_unsorted.not_after_utc, "")

            # 4. Unsorted SET / SET OF embedded inside a certificate extension (SubjectDirectoryAttributes 2.5.29.9)
            sda_oid = bytes([0x55, 0x1D, 0x09])  # 2.5.29.9
            unsorted_ext_val = _tlv(
                b"\x30",
                _tlv(b"\x30", _tlv(b"\x06", bytes([0x55, 0x04, 0x03])) + _tlv(b"\x31", elem_large + elem_small)),
            )
            bad_ext_cert = _rebuild_cert_appending_extension(valid_der, sda_oid, unsorted_ext_val)
            with self.assertRaises(DerParseError):
                parse_x509_certificate_metadata_der(bad_ext_cert)
            self.assertIsNone(parse_x509_certificate_metadata(_der_to_pem(bad_ext_cert)))

            unsorted_set_ext_val = _tlv(b"\x31", bad_set_pc)
            bad_set_ext_cert = _rebuild_cert_appending_extension(valid_der, sda_oid, unsorted_set_ext_val)
            with self.assertRaises(DerParseError):
                parse_x509_certificate_metadata_der(bad_set_ext_cert)

            # Sorted SubjectDirectoryAttributes extension -> accepted cleanly!
            sorted_ext_val = _tlv(
                b"\x30",
                _tlv(b"\x30", _tlv(b"\x06", bytes([0x55, 0x04, 0x03])) + _tlv(b"\x31", elem_small + elem_large)),
            )
            good_ext_cert = _rebuild_cert_appending_extension(valid_der, sda_oid, sorted_ext_val)
            self.assertEqual(parse_x509_certificate_metadata_der(good_ext_cert).signer_common_name, "Imzaci")

    def test_02_strict_asn1_character_strings_no_replace_and_fail_closed_cert_mutations(self) -> None:
        # 1. Static source audit: zero lossy errors="replace" / errors="ignore" anywhere in x509_metadata.py
        x509_src = (PROJECT_ROOT / "engine" / "esign5070" / "x509_metadata.py").read_text(encoding="utf-8")
        self.assertNotIn('errors="replace"', x509_src)
        self.assertNotIn("errors='replace'", x509_src)
        self.assertNotIn('errors="ignore"', x509_src)
        self.assertNotIn("errors='ignore'", x509_src)

        # 2. Direct per-type strict ASN.1 character string positive & negative vectors
        # UTF8String (0x0C)
        self.assertEqual(x509_mod._decode_asn1_string(0x0C, "hrAI — ÇĞİÖŞÜçğıöşü €🔐".encode("utf-8")), "hrAI — ÇĞİÖŞÜçğıöşü €🔐")
        for bad_utf8 in (b"\x80", b"\xc3", b"\xc0\xaf", b"\xed\xa0\x80", b"\xff\xfe"):
            with self.assertRaises(DerParseError, msg=f"Bad UTF8String {bad_utf8!r}"):
                x509_mod._decode_asn1_string(0x0C, bad_utf8)

        # PrintableString (0x13 — ITU-T X.680 Table 10)
        printable_all = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?"
        self.assertEqual(x509_mod._decode_asn1_string(0x13, printable_all.encode("ascii")), printable_all)
        for bad_pr in (b"a@b.tr", b"under_score", b"star*", b"excl!", b"semi;", b"nul\x00x", "ç".encode("utf-8")):
            with self.assertRaises(DerParseError, msg=f"Bad PrintableString {bad_pr!r}"):
                x509_mod._decode_asn1_string(0x13, bad_pr)

        # NumericString (0x12)
        self.assertEqual(x509_mod._decode_asn1_string(0x12, b"0123456789 "), "0123456789 ")
        with self.assertRaises(DerParseError):
            x509_mod._decode_asn1_string(0x12, b"123A")

        # IA5String (0x16 — strict 7-bit ASCII)
        self.assertEqual(x509_mod._decode_asn1_string(0x16, b"hukuk@insenai.com.tr"), "hukuk@insenai.com.tr")
        for bad_ia5 in (b"\x80", b"test\xc3\xb6.tr", b"\xff"):
            with self.assertRaises(DerParseError, msg=f"Bad IA5String {bad_ia5!r}"):
                x509_mod._decode_asn1_string(0x16, bad_ia5)

        # VisibleString (0x1A) & GraphicString (0x19)
        self.assertEqual(x509_mod._decode_asn1_string(0x1A, b"hrAI ~!@#$%^&*()"), "hrAI ~!@#$%^&*()")
        self.assertEqual(x509_mod._decode_asn1_string(0x19, b"hrAI Graphic"), "hrAI Graphic")
        for bad_vis in (b"\x00", b"\x1f", b"\x7f", b"\x80"):
            with self.assertRaises(DerParseError):
                x509_mod._decode_asn1_string(0x1A, bad_vis)
            with self.assertRaises(DerParseError):
                x509_mod._decode_asn1_string(0x19, bad_vis)

        # GeneralString (0x1B), TeletexString (0x14), VideotexString (0x15)
        self.assertEqual(x509_mod._decode_asn1_string(0x1B, b"hrAI General"), "hrAI General")
        self.assertEqual(x509_mod._decode_asn1_string(0x14, b"hrAI Legacy T61"), "hrAI Legacy T61")
        self.assertEqual(x509_mod._decode_asn1_string(0x15, b"hrAI Videotex"), "hrAI Videotex")
        with self.assertRaises(DerParseError):
            x509_mod._decode_asn1_string(0x1B, b"bad\x80")
        for bad_t61 in (b"\x00", b"\x7f", b"\x85", b"\xa0", b"\xff"):
            with self.assertRaises(DerParseError):
                x509_mod._decode_asn1_string(0x14, bad_t61)

        # BMPString (0x1E — strict 2-byte UCS-2 BMP, NO surrogates, NO odd lengths)
        bmp_tr = "hrAI İstanbul ĞÜŞİÖÇ €"
        self.assertEqual(x509_mod._decode_asn1_string(0x1E, bmp_tr.encode("utf-16-be")), bmp_tr)
        for bad_bmp in (
            b"\x00A\x00",            # odd length
            b"\xd8\x00",             # lone high surrogate
            b"\xdc\x00",             # lone low surrogate
            b"\xd8\x3d\xde\x00",     # UTF-16 surrogate pair (U+1F600 outside BMP — illegal in BMPString!)
        ):
            with self.assertRaises(DerParseError, msg=f"Bad BMPString {bad_bmp!r}"):
                x509_mod._decode_asn1_string(0x1E, bad_bmp)

        # UniversalString (0x1C — strict 4-byte UTF-32-BE)
        uni_str = "hrAI ŞĞİ 🔐"
        self.assertEqual(x509_mod._decode_asn1_string(0x1C, uni_str.encode("utf-32-be")), uni_str)
        for bad_uni in (
            b"\x00\x00\x41",         # length 3 (not multiple of 4)
            b"\x00\x00\xd8\x00",     # surrogate code point
            b"\x00\x11\x00\x00",     # > U+10FFFF
            b"\xff\xff\xff\xff",     # out of range
        ):
            with self.assertRaises(DerParseError, msg=f"Bad UniversalString {bad_uni!r}"):
                x509_mod._decode_asn1_string(0x1C, bad_uni)

        # Constructed primitive-only tags (X.690 §10.2) & unsupported string tags -> rejected
        for bad_tag in (0x02, 0x04, 0x2C, 0x33, 0x36, 0x3C, 0x3E):
            with self.assertRaises(DerParseError):
                x509_mod._decode_asn1_string(bad_tag, b"abc")
        constructed_utf8 = _tlv(b"\x2c", _tlv(b"\x0c", b"abc"))
        with self.assertRaises(DerParseError):
            x509_mod._validate_and_collect_oids(constructed_utf8, 0, len(constructed_utf8), set(), depth=0)
        non_empty_null = _tlv(b"\x05", b"\x00")
        with self.assertRaises(DerParseError):
            x509_mod._validate_and_collect_oids(non_empty_null, 0, len(non_empty_null), set(), depth=0)

        # 3. Full X.509 certificate mutations for invalid ASN.1 strings -> fail-closed, ZERO partial metadata!
        val_t = "2026-11-24T00:00:00Z"
        cn_oid = bytes([0x55, 0x04, 0x03])  # 2.5.4.3 CN
        email_oid = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01])  # emailAddress
        with Ephemeral5070PkiFixture() as pki:
            base_pem, _, _ = pki.issue_signer_cert(tag="str_strict", include_qc_compliance=True, include_qc_sscd=True)
            base_der = _pem_to_der(base_pem)

            bad_subject_cases = [
                ("invalid_utf8", cn_oid, b"\x0c", b"hrAI\xff\xfe"),
                ("invalid_printable", cn_oid, b"\x13", b"hrAI_invalid@tag"),
                ("invalid_ia5", email_oid, b"\x16", b"hukuk@\xc3\xb6rnek.tr"),
                ("invalid_bmp_odd", cn_oid, b"\x1e", b"\x00h\x00r\x00"),
                ("invalid_bmp_surrogate", cn_oid, b"\x1e", b"\xd8\x3d\xde\x00"),
                ("invalid_universal_range", cn_oid, b"\x1c", b"\x00\x11\x00\x00"),
                ("invalid_universal_len", cn_oid, b"\x1c", b"\x00\x00A"),
                ("embedded_nul_utf8", cn_oid, b"\x0c", b"www.insenai.com.tr\x00.evil"),
                ("constructed_utf8_in_dn", cn_oid, b"\x2c", _tlv(b"\x0c", b"hrAI")),
            ]
            for label, oid_b, str_tag, str_val in bad_subject_cases:
                bad_subj = _tlv(b"\x30", _tlv(b"\x31", _tlv(b"\x30", _tlv(b"\x06", oid_b) + _tlv(str_tag, str_val))))
                mut_der = _rebuild_cert_with_subject(base_der, bad_subj)
                with self.assertRaises(DerParseError, msg=f"Should reject {label}"):
                    parse_x509_certificate_metadata_der(mut_der)
                self.assertIsNone(parse_x509_certificate_metadata(_der_to_pem(mut_der)), label)
                insp = inspect_signer_certificate_x509(_der_to_pem(mut_der), validation_time_utc=val_t)
                self.assertFalse(insp.valid_x509, label)
                self.assertEqual(insp.subject, "", label)
                self.assertEqual(insp.issuer, "", label)
                self.assertEqual(insp.serial_number, "", label)
                self.assertEqual(insp.not_before_utc, "", label)
                self.assertEqual(insp.not_after_utc, "", label)
                self.assertFalse(insp.qc_compliance, label)
                self.assertFalse(insp.qc_sscd, label)

    def test_03_valid_certificate_positive_boundary_tests_strings_rdns_and_extensions(self) -> None:
        openssl = shutil.which("openssl")
        self.assertIsNotNone(openssl)

        with tempfile.TemporaryDirectory(prefix="hrai_v1051_pos_bounds_") as td:
            tdp = Path(td)

            # 1. OpenSSL 3 Turkish UTF-8 DN + PrintableString punctuation + IA5String email + SAN (DNS/email/URI/dirName)
            ca_key = tdp / "ca.key"
            ca_crt = tdp / "ca.crt"
            leaf_key = tdp / "leaf.key"
            leaf_csr = tdp / "leaf.csr"
            leaf_crt = tdp / "leaf.crt"
            leaf_ext = tdp / "leaf.ext"
            leaf_ext.write_text(
                "\n".join(
                    [
                        "basicConstraints=critical,CA:FALSE",
                        "keyUsage=critical,digitalSignature,nonRepudiation",
                        "subjectAltName=DNS:www.insenai.com.tr,DNS:hrai.insenai.com.tr,email:hukuk@insenai.com.tr,URI:https://www.insenai.com.tr,dirName:dir_sect",
                        "[dir_sect]",
                        "C=TR",
                        "O=hrAI (Insenai) + Hukuk-SGK",
                        "CN=hrAI DirName",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            subprocess.run(
                [openssl, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ca_key)],
                stdin=subprocess.DEVNULL, check=True, capture_output=True, timeout=30,
            )
            subprocess.run(
                [
                    openssl, "req", "-x509", "-new", "-utf8", "-key", str(ca_key), "-out", str(ca_crt),
                    "-days", "365",
                    "-subj", "/C=TR/O=hrAI İnsenai Kök CA/CN=hrAI Güven Kökü",
                    "-addext", "basicConstraints=critical,CA:TRUE",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                ],
                stdin=subprocess.DEVNULL, check=True, capture_output=True, timeout=30,
            )
            subprocess.run(
                [openssl, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(leaf_key)],
                stdin=subprocess.DEVNULL, check=True, capture_output=True, timeout=30,
            )
            subprocess.run(
                [
                    openssl, "req", "-new", "-utf8", "-multivalue-rdn",
                    "-key", str(leaf_key), "-out", str(leaf_csr),
                    "-subj", "/C=TR/ST=İstanbul/O=hrAI (Insenai) A.Ş.+OU=Hukuk-SGK:2026/CN=Av. Çağrı Özdemir — ĞÜŞİÖÇ/emailAddress=hukuk@insenai.com.tr/serialNumber=TR-9051",
                ],
                stdin=subprocess.DEVNULL, check=True, capture_output=True, timeout=30,
            )
            subprocess.run(
                [
                    openssl, "x509", "-req", "-in", str(leaf_csr), "-CA", str(ca_crt), "-CAkey", str(ca_key),
                    "-CAcreateserial", "-days", "365", "-extfile", str(leaf_ext), "-out", str(leaf_crt),
                ],
                stdin=subprocess.DEVNULL, check=True, capture_output=True, timeout=30,
            )
            leaf_pem = leaf_crt.read_text(encoding="utf-8")
            meta = parse_x509_certificate_metadata(leaf_pem)
            self.assertIsNotNone(meta)
            assert meta is not None
            self.assertEqual(meta.signer_common_name, "Av. Çağrı Özdemir — ĞÜŞİÖÇ")
            self.assertEqual(meta.signer_serial_identifier, "TR-9051")
            self.assertEqual(meta.issuer_country, "TR")
            self.assertIn("www.insenai.com.tr", meta.san_dns_names)
            self.assertIn("hrai.insenai.com.tr", meta.san_dns_names)
            self.assertIn("Digital Signature", meta.key_usage)
            self.assertIn("Non Repudiation", meta.key_usage)

            # 2. Valid BMPString (0x1E) + UniversalString (0x1C) + PrintableString + IA5String in Subject DN
            c_oid = bytes([0x55, 0x04, 0x06])
            o_oid = bytes([0x55, 0x04, 0x0A])
            ou_oid = bytes([0x55, 0x04, 0x0B])
            cn_oid = bytes([0x55, 0x04, 0x03])
            email_oid = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01])
            rich_subj = _tlv(
                b"\x30",
                _tlv(b"\x31", _tlv(b"\x30", _tlv(b"\x06", c_oid) + _tlv(b"\x13", b"TR")))
                + _tlv(b"\x31", _tlv(b"\x30", _tlv(b"\x06", o_oid) + _tlv(b"\x1e", "hrAI İstanbul A.Ş.".encode("utf-16-be"))))
                + _tlv(b"\x31", _tlv(b"\x30", _tlv(b"\x06", ou_oid) + _tlv(b"\x1c", "HukukSGK — ĞÜŞİÖÇ".encode("utf-32-be"))))
                + _tlv(b"\x31", _tlv(b"\x30", _tlv(b"\x06", cn_oid) + _tlv(b"\x0c", "hrAI Uzman İmzacı".encode("utf-8"))))
                + _tlv(b"\x31", _tlv(b"\x30", _tlv(b"\x06", email_oid) + _tlv(b"\x16", b"hukuk@insenai.com.tr"))),
            )
            rich_der = _rebuild_cert_with_subject(_pem_to_der(leaf_pem), rich_subj)
            rich_meta = parse_x509_certificate_metadata_der(rich_der)
            self.assertEqual(rich_meta.signer_common_name, "hrAI Uzman İmzacı")
            self.assertIn("O=hrAI İstanbul A.Ş.", rich_meta.subject)
            self.assertIn("OU=HukukSGK — ĞÜŞİÖÇ", rich_meta.subject)
            self.assertIn("emailAddress=hukuk@insenai.com.tr", rich_meta.subject)

            # 3. Valid Ed25519 certificate (AlgorithmIdentifier with NO parameters)
            ed_key = tdp / "ed25519.key"
            ed_crt = tdp / "ed25519.crt"
            subprocess.run(
                [openssl, "genpkey", "-algorithm", "ED25519", "-out", str(ed_key)],
                stdin=subprocess.DEVNULL, check=True, capture_output=True, timeout=30,
            )
            subprocess.run(
                [
                    openssl, "req", "-x509", "-new", "-key", str(ed_key), "-out", str(ed_crt),
                    "-days", "365", "-subj", "/C=TR/O=hrAI/CN=hrAI Ed25519 Boundary",
                ],
                stdin=subprocess.DEVNULL, check=True, capture_output=True, timeout=30,
            )
            ed_meta = parse_x509_certificate_metadata(ed_crt.read_text(encoding="utf-8"))
            self.assertIsNotNone(ed_meta)
            assert ed_meta is not None
            self.assertEqual(ed_meta.public_key_algorithm, "ED25519")
            self.assertEqual(ed_meta.signature_algorithm, "ED25519")
            self.assertEqual(ed_meta.signer_common_name, "hrAI Ed25519 Boundary")

            # 4. Valid RSA-PSS certificate (AlgorithmIdentifier with constructed SEQUENCE parameters)
            pss_key = tdp / "rsa.key"
            pss_crt = tdp / "rsa_pss.crt"
            subprocess.run(
                [openssl, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(pss_key)],
                stdin=subprocess.DEVNULL, check=True, capture_output=True, timeout=30,
            )
            subprocess.run(
                [
                    openssl, "req", "-x509", "-new", "-key", str(pss_key), "-out", str(pss_crt),
                    "-days", "365", "-sha256",
                    "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32",
                    "-subj", "/C=TR/O=hrAI/CN=hrAI RSA-PSS Boundary",
                ],
                stdin=subprocess.DEVNULL, check=True, capture_output=True, timeout=30,
            )
            pss_meta = parse_x509_certificate_metadata(pss_crt.read_text(encoding="utf-8"))
            self.assertIsNotNone(pss_meta)
            assert pss_meta is not None
            self.assertEqual(pss_meta.signature_algorithm, "rsassaPss")
            self.assertEqual(pss_meta.public_key_algorithm, "rsaEncryption")
            self.assertEqual(pss_meta.signer_common_name, "hrAI RSA-PSS Boundary")

    def test_04_hrai_brand_transition_website_user_agent_and_historical_preservation(self) -> None:
        # 1. Exact v1.0.5.1 versions & hrAI service IDs
        self.assertEqual(ESIGN_5070_VERSION, "1.0.5.1")
        self.assertEqual(TRUST_ROOT_VERSION, "1.0.5.1")
        self.assertEqual(AUTONOMOUS_NORMS_VERSION, "1.0.5.1")
        self.assertEqual(PARSER_VERSION, "tr_diyanet_holiday_parser_v1.0.5.1")
        self.assertEqual(TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["calendar_version"], "1.0.5.1")
        self.assertEqual(DefaultQualifiedSignature5070Verifier().provider_name, "HRAI_CADES_XADES_5070_VERIFIER_V1051")
        self.assertEqual(
            DefaultSscdControlEvidenceVerifier().verifier_service_id,
            "HRAI_SSCD_CONTROL_EVIDENCE_VERIFIER_V1051",
        )

        # 2. HTTP User-Agent exact value
        src_acq_text = (PROJECT_ROOT / "engine" / "trust_root" / "source_acquisition.py").read_text(encoding="utf-8")
        self.assertIn('f"hrAI-HukukSGK/{TRUST_ROOT_VERSION} (SourceAcquisition)"', src_acq_text)
        self.assertEqual(
            f"hrAI-HukukSGK/{TRUST_ROOT_VERSION} (SourceAcquisition)",
            "hrAI-HukukSGK/1.0.5.1 (SourceAcquisition)",
        )

        # 3. Live integration probe reports hrAI / @hrAI / @HukukSGK / www.insenai.com.tr & ALL gates CLOSED
        report = run_live_integration_probe(project_root=PROJECT_ROOT)
        self.assertEqual(report["product_brand"], "hrAI")
        self.assertEqual(report["coordinator_agent"], "@hrAI")
        self.assertEqual(report["specialist_agent"], "@HukukSGK")
        self.assertEqual(report["product_website"], "https://www.insenai.com.tr")
        self.assertEqual(report["schema_version"], "1.0.5.1")
        self.assertEqual(report["overall_live_integration_status"], "NOT_CONFIGURED")
        self.assertEqual(report["esign_5070_overall_status"], "NOT_CONFIGURED")
        self.assertFalse(report["production_use_authorized"])
        self.assertFalse(report["qualified_e_signature_5070_production_ready"])
        self.assertFalse(report["qualified_e_signature_5070_equivalent"])
        self.assertEqual(
            report["production_authorization_decision"]["kvkk_data_residency_status"],
            "PENDING_KVKK_M9_DATA_RESIDENCY_ASSESSMENT",
        )
        self.assertFalse(report["production_authorization_decision"]["checks"]["kvkk_data_residency_approved"])

        # 4. Router autonomous norm lookup & conflict responses carry hrAI / @hrAI / @HukukSGK / www.insenai.com.tr
        router = HukukSGKToolRouter()
        lkp = router.dispatch("lookup_autonomous_norm_guidance", {"query": "disiplin", "layer": "L5"})
        self.assertEqual(lkp["product_brand"], "hrAI")
        self.assertEqual(lkp["coordinator_agent"], "@hrAI")
        self.assertEqual(lkp["specialist_agent"], "@HukukSGK")
        self.assertEqual(lkp["product_website"], "https://www.insenai.com.tr")
        cnf = router.dispatch(
            "evaluate_autonomous_norm_conflict",
            {"rule_id": "RULE-L5-03-IHBAR-VE-PIP-SURESI", "proposed_change_direction": "EMPLOYEE_FAVORABLE"},
        )
        self.assertEqual(cnf["product_brand"], "hrAI")
        self.assertEqual(cnf["coordinator_agent"], "@hrAI")
        self.assertEqual(cnf["specialist_agent"], "@HukukSGK")
        self.assertEqual(cnf["product_website"], "https://www.insenai.com.tr")

        # 5. All 13 Draft 2020-12 JSON Schemas updated to hrAI @HukukSGK (v1.0.5.1); L5/L6 $id under insenai.com.tr
        schemas = sorted((PROJECT_ROOT / "schemas").glob("*.schema.json"))
        self.assertEqual(len(schemas), 13)
        for sf in schemas:
            s_doc = json.loads(sf.read_text(encoding="utf-8"))
            self.assertEqual(s_doc["$schema"], "https://json-schema.org/draft/2020-12/schema", sf.name)
            self.assertIn("hrAI @HukukSGK", s_doc["title"], sf.name)
            self.assertIn("(v1.0.5.1)", s_doc["title"], sf.name)
        l5_schema = json.loads((PROJECT_ROOT / "schemas" / "corporate_hr_procedure_card.schema.json").read_text(encoding="utf-8"))
        l6_schema = json.loads((PROJECT_ROOT / "schemas" / "cba_contract_practice_card.schema.json").read_text(encoding="utf-8"))
        self.assertIn("www.insenai.com.tr", l5_schema["$id"])
        self.assertIn("www.insenai.com.tr", l6_schema["$id"])
        self.assertEqual(l5_schema["properties"]["product_brand"]["const"], "hrAI")
        self.assertEqual(l6_schema["properties"]["product_brand"]["const"], "hrAI")

        # 6. L5/L6 autonomous norms & independent audit log carry hrAI brand while preserving L5/L6 norm architecture
        sources = load_source_registry(PROJECT_ROOT / "config" / "legal_sources_registry.json")
        precedents = load_precedent_registry(PROJECT_ROOT / "config" / "yargitay_precedents.json")
        cards = load_knowledge_cards(PROJECT_ROOT / "rag_kb", sources, precedents)
        self.assertEqual((len(sources), len(precedents), len(cards)), (30, 5, 39))
        l5_mods = load_l5_hr_procedures(PROJECT_ROOT / "rag_kb", sources, cards, precedents, strict=True)
        l6_mods = load_l6_cba_contract_practices(PROJECT_ROOT / "rag_kb", sources, cards, precedents, strict=True)
        self.assertEqual((len(l5_mods), len(l6_mods)), (5, 4))
        an_audit = json.loads((PROJECT_ROOT / "config" / "autonomous_norms_audit_log.json").read_text(encoding="utf-8"))
        self.assertEqual(an_audit["audit_registry_id"], "HRAI-L5-L6-AUTONOMOUS-NORMS-AUDIT-LOG")
        self.assertEqual(an_audit["product_brand"], "hrAI")
        self.assertEqual(an_audit["product_website"], "https://www.insenai.com.tr")
        self.assertTrue(validate_autonomous_norms_audit_log(an_audit, l5_mods, l6_mods)["valid"])

        # 7. Historical CALISORA-* records, past audit IDs (AUD-20261120-*), & ledger hash chain integrity preserved
        appr = json.loads((PROJECT_ROOT / "config" / "authorized_approvers.json").read_text(encoding="utf-8"))
        self.assertIn("CALISORA-HUKUK-01", appr["approvers"])
        self.assertIn("CALISORA-LEDGER-SEALER-01", appr["approvers"])
        self.assertEqual(appr["approvers"]["CALISORA-HUKUK-01"]["key_id"], "KEY-CALISORA-HUKUK-01-PENDING")
        self.assertEqual(appr["approvers"]["CALISORA-LEDGER-SEALER-01"]["key_id"], "KEY-CALISORA-SEALER-01-PENDING")

        ledger = json.loads((PROJECT_ROOT / "config" / "calendar_attestation_ledger.json").read_text(encoding="utf-8"))
        self.assertEqual(ledger["ledger_id"], "CALISORA-HOLIDAY-CALENDAR-ATTESTATION-LEDGER")
        self.assertEqual(ledger["checkpoints"][0]["checkpoint_id"], "CHK-RELEASE-1.0.5.1-20261124")
        self.assertEqual(ledger["checkpoints"][0]["signer_approver_id"], "CALISORA-LEDGER-SEALER-01")
        led_res = verify_attestation_ledger(ledger, approvers_registry=appr, require_signed_checkpoints=False)
        self.assertTrue(led_res["mathematical_chain_intact"], led_res)
        self.assertEqual(led_res["trust_anchor_status"], "CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR")
        self.assertFalse(led_res["production_use_authorized"])

        esign_cfg = json.loads((PROJECT_ROOT / "config" / "esign_5070_config.json").read_text(encoding="utf-8"))
        self.assertEqual(esign_cfg["btk_eshs_registry"]["env_var_registry_url"], "CALISORA_BTK_ESHS_REGISTRY_URL")
        self.assertEqual(esign_cfg["eshs_ca_certificate_bundles"]["env_var_bundle_path"], "CALISORA_ESHS_CA_BUNDLE_PATH")

        audit_log = json.loads((PROJECT_ROOT / "config" / "verification_audit_log.json").read_text(encoding="utf-8"))
        self.assertEqual(audit_log["summary"]["total_audited_records"], 74)
        self.assertTrue(validate_central_audit_log(audit_log, sources, precedents, cards).valid)
        self.assertTrue(
            any(str(e.get("audit_log_id", "")).startswith("AUD-20261120-") for e in audit_log["entries"])
        )
        self.assertTrue(any(e.get("verifier_id") == "CALISORA-HUKUK-01" for e in audit_log["entries"]))

        # 8. engine/esign5070/xmldsig.py byte-identical SHA-256 preserved!
        xmldsig_sha = hashlib.sha256((PROJECT_ROOT / "engine" / "esign5070" / "xmldsig.py").read_bytes()).hexdigest()
        self.assertEqual(xmldsig_sha, EXPECTED_XMLDSIG_SHA256)

        # 9. System prompt & README reflect hrAI / @hrAI / @HukukSGK / www.insenai.com.tr
        sys_prompt = (PROJECT_ROOT / "agent" / "system_prompt.md").read_text(encoding="utf-8")
        self.assertIn("hrAI", sys_prompt)
        self.assertIn("@hrAI", sys_prompt)
        self.assertIn("www.insenai.com.tr", sys_prompt)
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("hrai_hukuk_sgk_v1.0.5.1.zip", readme)
        self.assertIn("www.insenai.com.tr", readme)

    def test_05_san_extensions_and_issuer_dn_fail_closed_zero_partial_metadata(self) -> None:
        """Verify invalid IA5String in SAN, invalid UTF8String in CertificatePolicies, and unsorted RDN in Issuer DN all fail closed."""
        val_t = "2026-11-24T00:00:00Z"
        with Ephemeral5070PkiFixture() as pki:
            base_pem, _, _ = pki.issue_signer_cert(tag="san_iss_neg", include_qc_compliance=True, include_qc_sscd=True)
            base_der = _pem_to_der(base_pem)

            # 1. Invalid IA5String (non-ASCII 0x80) inside SAN dNSName [2] (OID 2.5.29.17)
            san_oid = bytes([0x55, 0x1D, 0x11])
            bad_san_dns = _tlv(b"\x30", _tlv(b"\x82", b"bad-\x80.insenai.com.tr"))
            cert_bad_san_dns = _rebuild_cert_appending_extension(base_der, san_oid, bad_san_dns)

            # 2. Embedded NUL inside SAN rfc822Name [1]
            bad_san_email = _tlv(b"\x30", _tlv(b"\x81", b"hukuk\x00@insenai.com.tr"))
            cert_bad_san_email = _rebuild_cert_appending_extension(base_der, san_oid, bad_san_email)

            # 3. Unsorted RDN SET OF inside SAN directoryName [4] EXPLICIT Name
            cn_oid = bytes([0x55, 0x04, 0x03])
            ou_oid = bytes([0x55, 0x04, 0x0B])
            ava_cn = _tlv(b"\x30", _tlv(b"\x06", cn_oid) + _tlv(b"\x0c", b"Zebra"))
            ava_ou = _tlv(b"\x30", _tlv(b"\x06", ou_oid) + _tlv(b"\x0c", b"Alpha"))
            # Force descending order (ava_ou > ava_cn since OID 2.5.4.11 > 2.5.4.3 and equal lengths)
            self.assertGreater(ava_ou, ava_cn)
            bad_san_dirname = _tlv(b"\x30", _tlv(b"\xa4", _tlv(b"\x30", _tlv(b"\x31", ava_ou + ava_cn))))
            cert_bad_san_dir = _rebuild_cert_appending_extension(base_der, san_oid, bad_san_dirname)

            # 4. Invalid UTF8String inside CertificatePolicies (OID 2.5.29.32) UserNotice/DisplayText
            cp_oid = bytes([0x55, 0x1D, 0x20])
            policy_id = bytes([0x55, 0x1D, 0x20, 0x00])  # anyPolicy
            bad_cp_val = _tlv(
                b"\x30",
                _tlv(
                    b"\x30",
                    _tlv(b"\x06", policy_id)
                    + _tlv(b"\x30", _tlv(b"\x30", _tlv(b"\x06", bytes([0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02])) + _tlv(b"\x0c", b"bad\xffutf8"))),
                ),
            )
            cert_bad_cp = _rebuild_cert_appending_extension(base_der, cp_oid, bad_cp_val)

            # 5. Unsorted RDN SET OF inside TBSCertificate.issuer Name
            _, c_vs, c_ve, _ = x509_mod._read_tlv(base_der, 0, len(base_der))
            cert_spans = x509_mod._iter_children_with_spans(base_der, c_vs, c_ve)
            _, _, tbs_vs, tbs_ve, _ = cert_spans[0]
            sigalg_s, _, _, _, sigalg_nxt = cert_spans[1]
            sigval_s, _, _, _, sigval_nxt = cert_spans[2]
            tbs_spans = x509_mod._iter_children_with_spans(base_der, tbs_vs, tbs_ve)
            idx = 1 if tbs_spans[0][1] == 0xA0 else 0
            issuer_idx = idx + 2
            bad_issuer = _tlv(b"\x30", _tlv(b"\x31", ava_ou + ava_cn))
            tbs_parts = [
                bad_issuer if i == issuer_idx else base_der[fs:fnxt]
                for i, (fs, _ft, _fvs, _fve, fnxt) in enumerate(tbs_spans)
            ]
            cert_bad_issuer = _tlv(
                b"\x30",
                _tlv(b"\x30", b"".join(tbs_parts))
                + base_der[sigalg_s:sigalg_nxt]
                + base_der[sigval_s:sigval_nxt],
            )

            for label, bad_der in (
                ("san_bad_ia5_dns", cert_bad_san_dns),
                ("san_nul_email", cert_bad_san_email),
                ("san_unsorted_dirname_rdn", cert_bad_san_dir),
                ("cert_policies_bad_utf8", cert_bad_cp),
                ("issuer_unsorted_rdn", cert_bad_issuer),
            ):
                with self.assertRaises(DerParseError, msg=f"Should reject {label}"):
                    parse_x509_certificate_metadata_der(bad_der)
                self.assertIsNone(parse_x509_certificate_metadata(_der_to_pem(bad_der)), label)
                insp = inspect_signer_certificate_x509(_der_to_pem(bad_der), validation_time_utc=val_t)
                self.assertFalse(insp.valid_x509, label)
                self.assertEqual(insp.subject, "", label)
                self.assertEqual(insp.issuer, "", label)
                self.assertEqual(insp.serial_number, "", label)
                self.assertFalse(insp.qc_compliance, label)
                self.assertFalse(insp.qc_sscd, label)


if __name__ == "__main__":
    unittest.main()
