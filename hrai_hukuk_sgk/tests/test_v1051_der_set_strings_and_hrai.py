"""hrAI @HukukSGK v1.0.5.1 — Strict DER SET/SET OF Canonical Ordering, Strict ASN.1 Character Strings & hrAI Brand Transition Test Suite.

Covers all v1.0.5.1 independent audit remediations while preserving all 230 baseline tests,
L1-L4 74/74 statutory core, L5/L6 autonomous norm architecture, OpenSSL 3 cryptographic
verifications, and byte-identical `engine/esign5070/xmldsig.py`:
  1. Schema-context ITU-T X.690 §11.5 (`SET` canonical tag order, no duplicate tags) & §11.6 (`SET OF`
     and differently-tagged `SET OF CHOICE` ascending complete DER TLV octet order with trailing 0x00
     comparison padding), plus the explicit schema-less boundary for unknown X.509 extensions.
  2. Strict per-type ASN.1 character string decoding (`UTF8String`, `PrintableString`, `NumericString`,
     `IA5String`, `VisibleString`, `BMPString` UCS-2 without surrogates, `UniversalString` UTF-32-BE)
     with zero lossy replacement fallback and zero Latin-1 misdecoding; legacy ISO-2022/T.61/Videotex
     string tags (`TeletexString` 0x14, `VideotexString` 0x15, `GraphicString` 0x19, `GeneralString`
     0x1B) are explicitly fail-closed rejected with zero partial metadata.
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

        # Schema-less 0x31 container validation inside `_validate_and_collect_oids`:
        # rejects anything invalid under BOTH X.690 §11.5 (SET) AND X.690 §11.6 (SET OF)
        bad_set_of_tlv = _tlv(b"\x31", bad_set_of)
        with self.assertRaises(DerParseError):
            x509_mod._validate_and_collect_oids(bad_set_of_tlv, 0, len(bad_set_of_tlv), set(), depth=0)
        bad_both_tlv = _tlv(b"\x31", _tlv(b"\x13", b"aaa") + _tlv(b"\x0c", b"zzz"))  # fails both §11.5 & §11.6
        with self.assertRaises(DerParseError):
            x509_mod._validate_and_collect_oids(bad_both_tlv, 0, len(bad_both_tlv), set(), depth=0)
        bad_class_tlv = _tlv(b"\x31", bad_set_class)  # fails both §11.5 & §11.6
        with self.assertRaises(DerParseError):
            x509_mod._validate_and_collect_oids(bad_class_tlv, 0, len(bad_class_tlv), set(), depth=0)

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

            # 4. Schema-known SubjectDirectoryAttributes (2.5.29.9) SET OF AttributeValue ordering
            sda_oid = bytes([0x55, 0x1D, 0x09])  # 2.5.29.9
            unsorted_ext_val = _tlv(
                b"\x30",
                _tlv(b"\x30", _tlv(b"\x06", bytes([0x55, 0x04, 0x03])) + _tlv(b"\x31", elem_large + elem_small)),
            )
            bad_ext_cert = _rebuild_cert_appending_extension(valid_der, sda_oid, unsorted_ext_val)
            with self.assertRaises(DerParseError):
                parse_x509_certificate_metadata_der(bad_ext_cert)
            self.assertIsNone(parse_x509_certificate_metadata(_der_to_pem(bad_ext_cert)))

            # Malformed SubjectDirectoryAttributes (not SEQUENCE OF Attribute) -> rejected
            bad_sda_shape = _tlv(b"\x31", bad_set_pc)
            bad_set_ext_cert = _rebuild_cert_appending_extension(valid_der, sda_oid, bad_sda_shape)
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
        # 1. Static source audit: zero lossy replacement/ignore AND zero latin-1 misdecoding in x509_metadata.py
        x509_src = (PROJECT_ROOT / "engine" / "esign5070" / "x509_metadata.py").read_text(encoding="utf-8")
        self.assertNotIn('errors="replace"', x509_src)
        self.assertNotIn("errors='replace'", x509_src)
        self.assertNotIn('errors="ignore"', x509_src)
        self.assertNotIn("errors='ignore'", x509_src)
        self.assertNotIn('"latin-1"', x509_src)
        self.assertNotIn("'latin-1'", x509_src)

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

        # VisibleString (0x1A — strict ISO-IR-6 0x20..0x7E)
        self.assertEqual(x509_mod._decode_asn1_string(0x1A, b"hrAI ~!@#$%^&*()"), "hrAI ~!@#$%^&*()")
        for bad_vis in (b"\x00", b"\x1f", b"\x7f", b"\x80"):
            with self.assertRaises(DerParseError):
                x509_mod._decode_asn1_string(0x1A, bad_vis)

        # Unsupported legacy T.61 / Videotex / ISO-2022 string tags -> ALWAYS fail-closed rejected (never latin-1!)
        for legacy_tag in (0x14, 0x15, 0x19, 0x1B):
            for sample_bytes in (b"hrAI", b"\xc2e", b"\xcbc", b"\xc8u", b"\x1b(Btest", b"\x00"):
                with self.assertRaises(DerParseError, msg=f"Legacy tag 0x{legacy_tag:02x} {sample_bytes!r}"):
                    x509_mod._decode_asn1_string(legacy_tag, sample_bytes)

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

        # 3. Full X.509 certificate mutations for invalid / unsupported ASN.1 strings -> fail-closed, ZERO partial metadata!
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
                ("unsupported_teletex_ascii", cn_oid, b"\x14", b"hrAI T61"),
                ("unsupported_teletex_accented", cn_oid, b"\x14", b"\xcbcagri \xc8uz"),
                ("unsupported_videotex", cn_oid, b"\x15", b"hrAI Videotex"),
                ("unsupported_graphic", cn_oid, b"\x19", b"hrAI Graphic"),
                ("unsupported_general", cn_oid, b"\x1b", b"hrAI General"),
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

    def test_06_set_of_choice_schema_context_and_legacy_t61_videotex_fail_closed(self) -> None:
        """PR #1 review remediation: schema-context SET/SET OF CHOICE, schema-less 0x31 boundary, IAN & legacy strings."""
        val_t = "2026-11-24T00:00:00Z"

        # 1. Cross-P/C-bit divergence between SET (X.690 §11.5) and differently-tagged SET OF CHOICE (X.690 §11.6)
        pr_alpha = _tlv(b"\x13", b"alpha")          # UNIVERSAL 19 (PrintableString), first octet 0x13
        seq_one = _tlv(b"\x30", _tlv(b"\x02", b"\x01"))  # UNIVERSAL 16 (SEQUENCE), first octet 0x30
        seq_two = _tlv(b"\x30", _tlv(b"\x02", b"\x02"))  # UNIVERSAL 16 (SEQUENCE), first octet 0x30 (> seq_one)
        ctx_p1 = _tlv(b"\x81", b"b")                # CONTEXT [1] PRIMITIVE, first octet 0x81
        ctx_c0 = _tlv(b"\xa0", _tlv(b"\x02", b"\x01"))   # CONTEXT [0] CONSTRUCTED, first octet 0xA0

        # [0x13, 0x30] and [0x81, 0xA0]: VALID as SET OF CHOICE (§11.6), INVALID as SET (§11.5)
        valid_soc_univ = pr_alpha + seq_one
        valid_soc_ctx = ctx_p1 + ctx_c0
        self.assertEqual(len(x509_mod._validate_der_set_of_order(valid_soc_univ, 0, len(valid_soc_univ))), 2)
        self.assertEqual(len(x509_mod._validate_der_set_of_order(valid_soc_ctx, 0, len(valid_soc_ctx))), 2)
        with self.assertRaises(DerParseError):
            x509_mod._validate_der_set_order(valid_soc_univ, 0, len(valid_soc_univ))
        with self.assertRaises(DerParseError):
            x509_mod._validate_der_set_order(valid_soc_ctx, 0, len(valid_soc_ctx))

        # [0x30, 0x13] and [0xA0, 0x81]: VALID as SET (§11.5), INVALID as SET OF CHOICE (§11.6)
        valid_set_univ = seq_one + pr_alpha
        valid_set_ctx = ctx_c0 + ctx_p1
        self.assertEqual(len(x509_mod._validate_der_set_order(valid_set_univ, 0, len(valid_set_univ))), 2)
        self.assertEqual(len(x509_mod._validate_der_set_order(valid_set_ctx, 0, len(valid_set_ctx))), 2)
        with self.assertRaises(DerParseError):
            x509_mod._validate_der_set_of_order(valid_set_univ, 0, len(valid_set_univ))
        with self.assertRaises(DerParseError):
            x509_mod._validate_der_set_of_order(valid_set_ctx, 0, len(valid_set_ctx))

        # 3-element mixed SET OF CHOICE: [0x13, 0x30(1), 0x30(2)] valid under §11.6; swapped variants invalid
        valid_soc_mixed3 = pr_alpha + seq_one + seq_two
        bad_soc_mixed3_interleaved = seq_one + pr_alpha + seq_two
        bad_soc_mixed3_unsorted = pr_alpha + seq_two + seq_one
        self.assertEqual(len(x509_mod._validate_der_set_of_order(valid_soc_mixed3, 0, len(valid_soc_mixed3))), 3)
        for bad_mixed in (bad_soc_mixed3_interleaved, bad_soc_mixed3_unsorted):
            with self.assertRaises(DerParseError):
                x509_mod._validate_der_set_of_order(bad_mixed, 0, len(bad_mixed))
            with self.assertRaises(DerParseError):
                x509_mod._validate_schema_unknown_der_set(bad_mixed, 0, len(bad_mixed))

        with Ephemeral5070PkiFixture() as pki:
            base_pem, _, _ = pki.issue_signer_cert(tag="soc_ctx_test", include_qc_compliance=True, include_qc_sscd=True)
            base_der = _pem_to_der(base_pem)

            # Helper: wrap Attribute.values 0x31 payload inside RFC 5280 SubjectDirectoryAttributes (2.5.29.9)
            sda_oid = bytes([0x55, 0x1D, 0x09])  # 2.5.29.9
            attr_oid = bytes([0x2A, 0x03, 0x04, 0x05, 0x01])  # 1.2.3.4.5.1
            unk_ext_oid = bytes([0x2A, 0x03, 0x04, 0x05, 0x63])  # 1.2.3.4.5.99 (schema-less custom extension)
            ian_oid = bytes([0x55, 0x1D, 0x12])  # 2.5.29.18 IssuerAltName

            def _sda_ext(set_of_inner: bytes) -> bytes:
                return _tlv(b"\x30", _tlv(b"\x30", _tlv(b"\x06", attr_oid) + _tlv(b"\x31", set_of_inner)))

            # 2. Schema-known SubjectDirectoryAttributes (2.5.29.9): strictly enforces SET OF (§11.6)
            for label, valid_inner in (
                ("sda_soc_univ_0x13_0x30", valid_soc_univ),
                ("sda_soc_ctx_0x81_0xA0", valid_soc_ctx),
                ("sda_soc_mixed3", valid_soc_mixed3),
            ):
                cert_ok = _rebuild_cert_appending_extension(base_der, sda_oid, _sda_ext(valid_inner))
                meta_ok = parse_x509_certificate_metadata_der(cert_ok)
                self.assertTrue(meta_ok.qc_compliance, label)

            for label, bad_inner in (
                ("sda_reject_set_ordered_0x30_0x13", valid_set_univ),
                ("sda_reject_set_ordered_0xA0_0x81", valid_set_ctx),
                ("sda_reject_mixed3_interleaved", bad_soc_mixed3_interleaved),
                ("sda_reject_mixed3_unsorted", bad_soc_mixed3_unsorted),
                ("sda_reject_empty_values", b""),
            ):
                cert_bad = _rebuild_cert_appending_extension(base_der, sda_oid, _sda_ext(bad_inner))
                with self.assertRaises(DerParseError, msg=f"SubjectDirectoryAttributes must reject {label}"):
                    parse_x509_certificate_metadata_der(cert_bad)
                self.assertIsNone(parse_x509_certificate_metadata(_der_to_pem(cert_bad)), label)
                insp = inspect_signer_certificate_x509(_der_to_pem(cert_bad), validation_time_utc=val_t)
                self.assertFalse(insp.valid_x509, label)
                self.assertEqual(insp.subject, "", label)
                self.assertFalse(insp.qc_compliance, label)

            # 3. Schema-less unknown extension (1.2.3.4.5.99): accepts valid SET AND valid SET OF CHOICE,
            #    never guesses from tag repetition, and rejects any 0x31 invalid under BOTH §11.5 and §11.6
            for label, ok_unknown_set in (
                ("unk_valid_set_0xA0_0x81", valid_set_ctx),
                ("unk_valid_set_0x30_0x13", valid_set_univ),
                ("unk_valid_soc_0x81_0xA0", valid_soc_ctx),
                ("unk_valid_soc_0x13_0x30", valid_soc_univ),
                ("unk_valid_soc_mixed3", valid_soc_mixed3),
            ):
                cert_ok = _rebuild_cert_appending_extension(base_der, unk_ext_oid, _tlv(b"\x31", ok_unknown_set))
                meta_ok = parse_x509_certificate_metadata_der(cert_ok)
                self.assertTrue(meta_ok.qc_compliance, label)

            for label, bad_unknown_set in (
                ("unk_bad_both_0x13_0x0C", _tlv(b"\x13", b"a") + _tlv(b"\x0c", b"z")),
                ("unk_bad_both_app_before_univ", _tlv(b"\x40", b"\x01") + _tlv(b"\x02", b"\x01")),
                ("unk_bad_both_ctx2_before_ctx0", _tlv(b"\x82", b"b") + _tlv(b"\x80", b"a")),
                ("unk_bad_same_tag_unsorted", _tlv(b"\x0c", b"bbb") + _tlv(b"\x0c", b"aaa")),
                ("unk_bad_mixed3_unsorted", bad_soc_mixed3_unsorted),
                ("unk_bad_mixed3_interleaved", bad_soc_mixed3_interleaved),
            ):
                cert_bad = _rebuild_cert_appending_extension(base_der, unk_ext_oid, _tlv(b"\x31", bad_unknown_set))
                with self.assertRaises(DerParseError, msg=f"Unknown extension must reject {label}"):
                    parse_x509_certificate_metadata_der(cert_bad)
                self.assertIsNone(parse_x509_certificate_metadata(_der_to_pem(cert_bad)), label)
                insp = inspect_signer_certificate_x509(_der_to_pem(cert_bad), validation_time_utc=val_t)
                self.assertFalse(insp.valid_x509, label)
                self.assertEqual(insp.subject, "", label)
                self.assertFalse(insp.qc_sscd, label)

            # 4. Schema-known IssuerAltName (2.5.29.18): positive + unsorted directoryName / bad IA5 / constructed dNSName
            cn_oid = bytes([0x55, 0x04, 0x03])
            ou_oid = bytes([0x55, 0x04, 0x0B])
            ava_cn = _tlv(b"\x30", _tlv(b"\x06", cn_oid) + _tlv(b"\x0c", b"Zebra"))
            ava_ou = _tlv(b"\x30", _tlv(b"\x06", ou_oid) + _tlv(b"\x0c", b"Alpha"))
            self.assertLess(ava_cn, ava_ou)

            good_ian = _tlv(
                b"\x30",
                _tlv(b"\x82", b"ca.insenai.com.tr")
                + _tlv(b"\xa4", _tlv(b"\x30", _tlv(b"\x31", ava_cn + ava_ou))),
            )
            self.assertTrue(
                parse_x509_certificate_metadata_der(
                    _rebuild_cert_appending_extension(base_der, ian_oid, good_ian)
                ).qc_compliance
            )

            for label, bad_ian in (
                ("ian_unsorted_dirname_rdn", _tlv(b"\x30", _tlv(b"\xa4", _tlv(b"\x30", _tlv(b"\x31", ava_ou + ava_cn))))),
                ("ian_bad_ia5_dns", _tlv(b"\x30", _tlv(b"\x82", b"ca-\xff.insenai.com.tr"))),
                ("ian_constructed_dns", _tlv(b"\x30", _tlv(b"\xa2", _tlv(b"\x16", b"ca.insenai.com.tr")))),
                ("ian_primitive_dirname", _tlv(b"\x30", _tlv(b"\x84", b"invalid"))),
            ):
                cert_bad = _rebuild_cert_appending_extension(base_der, ian_oid, bad_ian)
                with self.assertRaises(DerParseError, msg=f"IssuerAltName must reject {label}"):
                    parse_x509_certificate_metadata_der(cert_bad)
                self.assertIsNone(parse_x509_certificate_metadata(_der_to_pem(cert_bad)), label)

            # 5. Extension-embedded legacy TeletexString (0x14), VideotexString (0x15), GraphicString (0x19),
            #    GeneralString (0x1B) -> ALWAYS fail-closed rejected with zero partial metadata!
            legacy_ext_payloads = [
                ("ext_teletex_ascii", _tlv(b"\x14", b"hrAI T61")),
                ("ext_teletex_t61_accented", _tlv(b"\x14", b"\xcbcagri \xc2e")),
                ("ext_videotex_ascii", _tlv(b"\x15", b"hrAI Videotex")),
                ("ext_videotex_accented", _tlv(b"\x15", b"\xc8u\xcbc")),
                ("ext_graphic", _tlv(b"\x19", b"hrAI Graphic")),
                ("ext_general", _tlv(b"\x1b", b"\x1b(BhrAI")),
            ]
            for label, legacy_tlv in legacy_ext_payloads:
                for ctx_name, ext_oid_b, ext_body in (
                    ("sda", sda_oid, _sda_ext(legacy_tlv)),
                    ("unknown_ext", unk_ext_oid, _tlv(b"\x30", legacy_tlv)),
                ):
                    cert_bad = _rebuild_cert_appending_extension(base_der, ext_oid_b, ext_body)
                    with self.assertRaises(DerParseError, msg=f"Must reject {label} in {ctx_name}"):
                        parse_x509_certificate_metadata_der(cert_bad)
                    self.assertIsNone(parse_x509_certificate_metadata(_der_to_pem(cert_bad)), f"{label}/{ctx_name}")
                    insp = inspect_signer_certificate_x509(_der_to_pem(cert_bad), validation_time_utc=val_t)
                    self.assertFalse(insp.valid_x509, f"{label}/{ctx_name}")
                    self.assertEqual(insp.subject, "", f"{label}/{ctx_name}")
                    self.assertEqual(insp.issuer, "", f"{label}/{ctx_name}")
                    self.assertFalse(insp.qc_compliance, f"{label}/{ctx_name}")
                    self.assertFalse(insp.qc_sscd, f"{label}/{ctx_name}")

    def test_07_general_name_rfc5280_pc_bit_and_schema_validation_real_certs(self) -> None:
        """PR #1 second review remediation: RFC 5280 GeneralName P/C-bit & ASN.1 schema validation on real X.509 DER certs."""
        val_t = "2026-11-24T00:00:00Z"
        san_oid = bytes([0x55, 0x1D, 0x11])  # 2.5.29.17 SubjectAltName
        ian_oid = bytes([0x55, 0x1D, 0x12])  # 2.5.29.18 IssuerAltName
        upn_oid = bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03])  # 1.3.6.1.4.1.311.20.2.3

        # --- Valid RFC 5280 constructed GeneralName payloads ---
        # 1. otherName [0] (0xA0): OtherName ::= SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
        valid_other_name = _tlv(
            b"\xa0",
            _tlv(b"\x06", upn_oid) + _tlv(b"\xa0", _tlv(b"\x0c", "uzman@insenai.com.tr".encode("utf-8"))),
        )

        # 2. x400Address [3] (0xA3): full RFC 5280 ORAddress (BSA + PersonalName SET + BDDA + sorted ExtensionAttributes SET OF)
        valid_bsa = _tlv(
            b"\x30",
            _tlv(b"\x61", _tlv(b"\x13", b"TR"))                              # country-name (ISO-3166 alpha-2)
            + _tlv(b"\x62", _tlv(b"\x13", b"hrAI"))                          # administration-domain-name
            + _tlv(b"\x80", b"902120001")                                    # network-address (NumericString)
            + _tlv(b"\x81", b"TERM-01")                                      # terminal-identifier (PrintableString)
            + _tlv(b"\xa2", _tlv(b"\x13", b"Insenai"))                       # private-domain-name
            + _tlv(b"\x83", b"hrAI Insenai A.S.")                            # organization-name
            + _tlv(b"\x84", b"1051001")                                      # numeric-user-identifier
            + _tlv(                                                          # personal-name (SET: 0x80 < 0x81 < 0x82)
                b"\xa5",
                _tlv(b"\x80", b"Yilmaz") + _tlv(b"\x81", b"Ali") + _tlv(b"\x82", b"AY"),
            )
            + _tlv(b"\xa6", _tlv(b"\x13", b"HukukSGK") + _tlv(b"\x13", b"Uyum")),  # organizational-unit-names
        )
        valid_bdda = _tlv(b"\x30", _tlv(b"\x30", _tlv(b"\x13", b"DEPT") + _tlv(b"\x13", b"HukukSGK")))
        ea_1 = _tlv(b"\x30", _tlv(b"\x80", b"\x01") + _tlv(b"\xa1", _tlv(b"\x13", b"Alpha")))
        ea_2 = _tlv(b"\x30", _tlv(b"\x80", b"\x02") + _tlv(b"\xa1", _tlv(b"\x0c", "İstanbul".encode("utf-8"))))
        self.assertLess(ea_1, ea_2)
        valid_ext_attrs = _tlv(b"\x31", ea_1 + ea_2)
        valid_x400_full = _tlv(b"\xa3", valid_bsa + valid_bdda + valid_ext_attrs)

        # 3. ediPartyName [5] (0xA5): both (nameAssigner + partyName) and (partyName-only) forms
        valid_edi_both = _tlv(
            b"\xa5",
            _tlv(b"\xa0", _tlv(b"\x0c", "hrAI İnsenai".encode("utf-8")))
            + _tlv(b"\xa1", _tlv(b"\x13", b"HukukSGK-EDI")),
        )
        valid_edi_party_only = _tlv(b"\xa5", _tlv(b"\xa1", _tlv(b"\x1e", "hrAI EDI".encode("utf-16-be"))))

        # 4. Positive real OpenSSL 3-signed X.509 certificate carrying ALL constructed + primitive GeneralName types
        openssl = shutil.which("openssl")
        self.assertIsNotNone(openssl)
        combined_san = _tlv(
            b"\x30",
            valid_other_name
            + _tlv(b"\x81", b"hukuk@insenai.com.tr")
            + _tlv(b"\x82", b"www.insenai.com.tr")
            + valid_x400_full
            + valid_edi_both
            + valid_edi_party_only
            + _tlv(b"\x86", b"https://www.insenai.com.tr")
            + _tlv(b"\x87", bytes([192, 0, 2, 10]))               # IPv4 (4 octets)
            + _tlv(b"\x87", bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [1]))  # IPv6 (16 octets)
            + _tlv(b"\x88", bytes([0x2A, 0x03, 0x04, 0x05])),     # registeredID 1.2.3.4.5
        )
        with tempfile.TemporaryDirectory(prefix="hrai_v1051_gn_") as td:
            tdp = Path(td)
            key_p = tdp / "gn.key"
            crt_p = tdp / "gn.crt"
            cfg_p = tdp / "gn.cnf"
            cfg_p.write_text(
                "\n".join(
                    [
                        "[req]",
                        "distinguished_name = dn",
                        "x509_extensions = v3_ext",
                        "prompt = no",
                        "[dn]",
                        "C = TR",
                        "O = hrAI",
                        "CN = GeneralName Real Cert",
                        "[v3_ext]",
                        "basicConstraints = critical,CA:FALSE",
                        "keyUsage = critical,digitalSignature",
                        f"subjectAltName = DER:{combined_san.hex()}",
                        f"issuerAltName = DER:{combined_san.hex()}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            subprocess.run(
                [openssl, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key_p)],
                stdin=subprocess.DEVNULL, check=True, capture_output=True, timeout=30,
            )
            subprocess.run(
                [
                    openssl, "req", "-x509", "-new", "-key", str(key_p), "-config", str(cfg_p),
                    "-days", "365", "-out", str(crt_p),
                ],
                stdin=subprocess.DEVNULL, check=True, capture_output=True, timeout=30,
            )
            real_pem = crt_p.read_text(encoding="utf-8")
            real_meta = parse_x509_certificate_metadata(real_pem)
            self.assertIsNotNone(real_meta)
            assert real_meta is not None
            self.assertEqual(real_meta.signer_common_name, "GeneralName Real Cert")
            self.assertEqual(real_meta.san_dns_names, ("www.insenai.com.tr",))

            # Independent OpenSSL 3 text + PEM/DER asn1parse verification on the same real certificate
            der_p = tdp / "gn.der"
            x509_txt = subprocess.check_output(
                [openssl, "x509", "-in", str(crt_p), "-noout", "-text"],
                stdin=subprocess.DEVNULL, text=True, timeout=30,
            )
            self.assertIn("othername: UPN::uzman@insenai.com.tr", x509_txt)
            self.assertIn("email:hukuk@insenai.com.tr", x509_txt)
            self.assertIn("DNS:www.insenai.com.tr", x509_txt)
            self.assertIn("URI:https://www.insenai.com.tr", x509_txt)
            self.assertIn("IP Address:192.0.2.10", x509_txt)
            self.assertIn("IP Address:2001:DB8:0:0:0:0:0:1", x509_txt)
            self.assertIn("Registered ID:1.2.3.4.5", x509_txt)
            subprocess.run(
                [openssl, "x509", "-in", str(crt_p), "-outform", "DER", "-out", str(der_p)],
                stdin=subprocess.DEVNULL, check=True, capture_output=True, timeout=30,
            )
            pem_asn1 = subprocess.check_output(
                [openssl, "asn1parse", "-in", str(crt_p), "-inform", "PEM", "-i"],
                stdin=subprocess.DEVNULL, text=True, timeout=30,
            )
            der_asn1 = subprocess.check_output(
                [openssl, "asn1parse", "-in", str(der_p), "-inform", "DER", "-i"],
                stdin=subprocess.DEVNULL, text=True, timeout=30,
            )
            self.assertEqual(pem_asn1, der_asn1)
            self.assertIn("X509v3 Subject Alternative Name", der_asn1)
            self.assertIn("X509v3 Issuer Alternative Name", der_asn1)

        # 5. Negative real X.509 DER certificate mutations (BOTH SAN 2.5.29.17 AND IAN 2.5.29.18)
        with Ephemeral5070PkiFixture() as pki:
            base_pem, _, _ = pki.issue_signer_cert(tag="gn_neg_real", include_qc_compliance=True, include_qc_sscd=True)
            base_der = _pem_to_der(base_pem)

            # Positive sanity on Ephemeral5070PkiFixture real cert with each of the 3 constructed alternatives individually
            for label, valid_gn in (
                ("pos_other_name", valid_other_name),
                ("pos_x400_full", valid_x400_full),
                ("pos_edi_both", valid_edi_both),
                ("pos_edi_party_only", valid_edi_party_only),
            ):
                for ext_oid_b in (san_oid, ian_oid):
                    ok_der = _rebuild_cert_appending_extension(base_der, ext_oid_b, _tlv(b"\x30", valid_gn))
                    ok_meta = parse_x509_certificate_metadata_der(ok_der)
                    self.assertTrue(ok_meta.qc_compliance, label)
                    self.assertTrue(ok_meta.qc_sscd, label)

            # Negative GeneralName payloads (primitive P/C violations + schema violations for 0xA0, 0xA3, 0xA5 + GeneralNames bounds)
            bad_general_names: list[tuple[str, bytes]] = [
                # --- Primitive encodings of constructed-only GeneralName alternatives (0x80, 0x83, 0x84, 0x85) ---
                ("prim_otherName_0x80", _tlv(b"\x80", b"raw-other-name")),
                ("prim_x400Address_0x83", _tlv(b"\x83", b"raw-x400-address")),
                ("prim_directoryName_0x84", _tlv(b"\x84", b"raw-dir-name")),
                ("prim_ediPartyName_0x85", _tlv(b"\x85", b"raw-edi-party")),
                # --- Constructed encodings of primitive-only GeneralName alternatives (0xA1, 0xA2, 0xA6, 0xA7, 0xA8) ---
                ("constr_rfc822_0xA1", _tlv(b"\xa1", _tlv(b"\x16", b"hukuk@insenai.com.tr"))),
                ("constr_dns_0xA2", _tlv(b"\xa2", _tlv(b"\x16", b"www.insenai.com.tr"))),
                ("constr_uri_0xA6", _tlv(b"\xa6", _tlv(b"\x16", b"https://www.insenai.com.tr"))),
                ("constr_ip_0xA7", _tlv(b"\xa7", _tlv(b"\x04", bytes([192, 0, 2, 1])))),
                ("constr_rid_0xA8", _tlv(b"\xa8", _tlv(b"\x06", bytes([0x2A, 0x03, 0x04])))),
                # --- Malformed constructed otherName [0] (0xA0) ---
                ("otherName_empty", _tlv(b"\xa0", b"")),
                ("otherName_missing_value", _tlv(b"\xa0", _tlv(b"\x06", upn_oid))),
                ("otherName_first_not_oid", _tlv(b"\xa0", _tlv(b"\x0c", b"not-oid") + _tlv(b"\xa0", _tlv(b"\x0c", b"v")))),
                ("otherName_value_primitive_0x80", _tlv(b"\xa0", _tlv(b"\x06", upn_oid) + _tlv(b"\x80", b"raw"))),
                ("otherName_value_empty_explicit", _tlv(b"\xa0", _tlv(b"\x06", upn_oid) + _tlv(b"\xa0", b""))),
                (
                    "otherName_value_two_tlvs",
                    _tlv(b"\xa0", _tlv(b"\x06", upn_oid) + _tlv(b"\xa0", _tlv(b"\x0c", b"a") + _tlv(b"\x0c", b"b"))),
                ),
                ("otherName_value_bad_utf8", _tlv(b"\xa0", _tlv(b"\x06", upn_oid) + _tlv(b"\xa0", _tlv(b"\x0c", b"bad\xff\xfe")))),
                (
                    "otherName_value_legacy_teletex",
                    _tlv(b"\xa0", _tlv(b"\x06", upn_oid) + _tlv(b"\xa0", _tlv(b"\x14", b"\xcbcagri"))),
                ),
                # --- Malformed constructed x400Address [3] (0xA3 / ORAddress) ---
                ("x400_empty", _tlv(b"\xa3", b"")),
                ("x400_first_not_bsa_seq", _tlv(b"\xa3", _tlv(b"\x02", b"\x01"))),
                ("x400_empty_bsa_only", _tlv(b"\xa3", _tlv(b"\x30", b""))),
                ("x400_country_bad_len", _tlv(b"\xa3", _tlv(b"\x30", _tlv(b"\x61", _tlv(b"\x13", b"TUR"))))),
                (
                    "x400_bsa_out_of_order",
                    _tlv(b"\xa3", _tlv(b"\x30", _tlv(b"\x62", _tlv(b"\x13", b"hrAI")) + _tlv(b"\x61", _tlv(b"\x13", b"TR")))),
                ),
                (
                    "x400_personal_name_unsorted_set",
                    _tlv(b"\xa3", _tlv(b"\x30", _tlv(b"\xa5", _tlv(b"\x81", b"Ali") + _tlv(b"\x80", b"Yilmaz")))),
                ),
                (
                    "x400_personal_name_missing_surname",
                    _tlv(b"\xa3", _tlv(b"\x30", _tlv(b"\xa5", _tlv(b"\x81", b"Ali")))),
                ),
                (
                    "x400_bdda_bad_printable",
                    _tlv(
                        b"\xa3",
                        _tlv(b"\x30", _tlv(b"\x83", b"hrAI"))
                        + _tlv(b"\x30", _tlv(b"\x30", _tlv(b"\x13", b"BAD@") + _tlv(b"\x13", b"Val"))),
                    ),
                ),
                (
                    "x400_ext_attrs_unsorted_set_of",
                    _tlv(b"\xa3", _tlv(b"\x30", _tlv(b"\x83", b"hrAI")) + _tlv(b"\x31", ea_2 + ea_1)),
                ),
                (
                    "x400_ext_attr_prim_value_0x81",
                    _tlv(
                        b"\xa3",
                        _tlv(b"\x30", _tlv(b"\x83", b"hrAI"))
                        + _tlv(b"\x31", _tlv(b"\x30", _tlv(b"\x80", b"\x01") + _tlv(b"\x81", b"raw"))),
                    ),
                ),
                (
                    "x400_ext_attr_legacy_teletex",
                    _tlv(
                        b"\xa3",
                        _tlv(b"\x30", _tlv(b"\x83", b"hrAI"))
                        + _tlv(b"\x31", _tlv(b"\x30", _tlv(b"\x80", b"\x01") + _tlv(b"\xa1", _tlv(b"\x14", b"\xc2e")))),
                    ),
                ),
                # --- Malformed constructed ediPartyName [5] (0xA5 / EDIPartyName) ---
                ("edi_empty", _tlv(b"\xa5", b"")),
                ("edi_missing_party_name", _tlv(b"\xa5", _tlv(b"\xa0", _tlv(b"\x0c", b"OnlyAssigner")))),
                (
                    "edi_reversed_fields",
                    _tlv(b"\xa5", _tlv(b"\xa1", _tlv(b"\x13", b"Party")) + _tlv(b"\xa0", _tlv(b"\x13", b"Assigner"))),
                ),
                ("edi_prim_party_tag_0x81", _tlv(b"\xa5", _tlv(b"\x81", b"ImplicitParty"))),
                ("edi_prim_assigner_tag_0x80", _tlv(b"\xa5", _tlv(b"\x80", b"Imp") + _tlv(b"\xa1", _tlv(b"\x13", b"P")))),
                ("edi_empty_directory_string", _tlv(b"\xa5", _tlv(b"\xa1", _tlv(b"\x0c", b"")))),
                ("edi_non_directory_string_ia5", _tlv(b"\xa5", _tlv(b"\xa1", _tlv(b"\x16", b"not-dirstr")))),
                ("edi_legacy_teletex", _tlv(b"\xa5", _tlv(b"\xa1", _tlv(b"\x14", b"\xcbc")))),
                (
                    "edi_invalid_utf8_assigner",
                    _tlv(b"\xa5", _tlv(b"\xa0", _tlv(b"\x0c", b"bad\xff")) + _tlv(b"\xa1", _tlv(b"\x13", b"Party"))),
                ),
                ("edi_embedded_nul", _tlv(b"\xa5", _tlv(b"\xa1", _tlv(b"\x0c", b"hrAI\x00EDI")))),
                # --- Other GeneralNames boundary violations ---
                ("invalid_ip_len_3", _tlv(b"\x87", bytes([192, 0, 2]))),
                ("unknown_general_name_tag_0x89", _tlv(b"\x89", b"unknown")),
            ]

            def _assert_zero_partial_metadata(mut_der: bytes, tag_msg: str) -> None:
                cache_key = (hashlib.sha256(mut_der).hexdigest(), len(mut_der))
                with self.assertRaises(DerParseError, msg=f"Must reject {tag_msg}"):
                    parse_x509_certificate_metadata_der(mut_der)
                self.assertNotIn(cache_key, x509_mod._METADATA_CACHE, f"cache polluted: {tag_msg}")
                mut_pem = _der_to_pem(mut_der)
                self.assertIsNone(parse_x509_certificate_metadata(mut_pem), tag_msg)
                self.assertNotIn(cache_key, x509_mod._METADATA_CACHE, f"cache polluted: {tag_msg}")
                insp = inspect_signer_certificate_x509(mut_pem, validation_time_utc=val_t)
                self.assertFalse(insp.valid_x509, tag_msg)
                self.assertEqual(insp.subject, "", tag_msg)
                self.assertEqual(insp.issuer, "", tag_msg)
                self.assertEqual(insp.serial_number, "", tag_msg)
                self.assertEqual(insp.not_before_utc, "", tag_msg)
                self.assertEqual(insp.not_after_utc, "", tag_msg)
                self.assertEqual(insp.cert_sha256, "", tag_msg)
                self.assertEqual(insp.signature_algorithm, "", tag_msg)
                self.assertEqual(insp.public_key_algorithm, "", tag_msg)
                self.assertFalse(insp.basic_constraints_ca, tag_msg)
                self.assertEqual(insp.key_usage, (), tag_msg)
                self.assertFalse(insp.qc_statements_present, tag_msg)
                self.assertFalse(insp.qc_compliance, tag_msg)
                self.assertFalse(insp.qc_sscd, tag_msg)
                self.assertEqual(insp.certificate_policy_oids, (), tag_msg)
                self.assertIsNone(insp.signer_common_name, tag_msg)
                self.assertIsNone(insp.signer_serial_identifier, tag_msg)
                self.assertIsNone(insp.issuer_country, tag_msg)
                self.assertFalse(insp.valid_at_validation_time, tag_msg)

            for label, bad_gn in bad_general_names:
                san_val = _tlv(b"\x30", bad_gn)
                for ctx_name, ext_oid_b in (("SAN", san_oid), ("IAN", ian_oid)):
                    mut_der = _rebuild_cert_appending_extension(base_der, ext_oid_b, san_val)
                    _assert_zero_partial_metadata(mut_der, f"{ctx_name}/{label}")

            # Empty GeneralNames SEQUENCE (30 00) in SAN & IAN -> fail-closed, zero partial metadata
            for ctx_name, ext_oid_b in (("SAN", san_oid), ("IAN", ian_oid)):
                mut_der = _rebuild_cert_appending_extension(base_der, ext_oid_b, _tlv(b"\x30", b""))
                _assert_zero_partial_metadata(mut_der, f"{ctx_name}/empty_general_names")

    def test_08_general_name_exhaustive_boundaries_der_canonicality_and_cache_safety(self) -> None:
        """Exhaustive real-cert boundary tests: DNS/email/URI syntax, ORAddress/EDI/OtherName cardinalities & bounds, DER canonicality, NUL uniformity, cache safety."""
        val_t = "2026-11-24T00:00:00Z"
        san_oid = bytes([0x55, 0x1D, 0x11])
        ian_oid = bytes([0x55, 0x1D, 0x12])
        upn_oid = bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03])

        # 1. Consistent NUL (U+0000) rejection across ALL ASN.1 string types
        for bad_tag, bad_bytes in (
            (0x0C, b"hrAI\x00evil"),
            (0x16, b"hrAI\x00evil"),
            (0x1E, "hrAI\x00evil".encode("utf-16-be")),
            (0x1C, "hrAI\x00evil".encode("utf-32-be")),
            (0x13, b"hrAI\x00"),
            (0x12, b"123\x00"),
            (0x1A, b"hrAI\x00"),
        ):
            with self.assertRaises(DerParseError, msg=f"NUL must fail for tag 0x{bad_tag:02x}"):
                x509_mod._decode_asn1_string(bad_tag, bad_bytes)

        with Ephemeral5070PkiFixture() as pki:
            base_pem, _, _ = pki.issue_signer_cert(tag="gn_bounds_real", include_qc_compliance=True, include_qc_sscd=True)
            base_der = _pem_to_der(base_pem)

            # 2. Positive boundary GeneralNames on real cert (wildcard DNS, numeric CountryName 3-digit, max bounds, all 4 PersonalName fields)
            pos_bsa_bounds = _tlv(
                b"\x30",
                _tlv(b"\x61", _tlv(b"\x12", b"286"))                  # numeric CountryName (exact len 3)
                + _tlv(b"\x62", _tlv(b"\x13", b""))                    # empty ADMD (RFC 5280 SIZE 0..16 allowed)
                + _tlv(b"\x80", b"1" * 16)                             # network-address max 16
                + _tlv(b"\x81", b"T" * 24)                             # terminal-identifier max 24
                + _tlv(b"\xa2", _tlv(b"\x12", b"9" * 16))              # private-domain-name numeric max 16
                + _tlv(b"\x83", b"O" * 64)                             # organization-name max 64
                + _tlv(b"\x84", b"7" * 32)                             # numeric-user-identifier max 32
                + _tlv(
                    b"\xa5",
                    _tlv(b"\x80", b"S" * 40)                           # surname max 40
                    + _tlv(b"\x81", b"G" * 16)                         # given-name max 16
                    + _tlv(b"\x82", b"I" * 5)                          # initials max 5
                    + _tlv(b"\x83", b"JR."),                           # generation-qualifier max 3
                )
                + _tlv(b"\xa6", b"".join(_tlv(b"\x13", b"U" * 32) for _ in range(4))),  # 4 OUs max 32 each
            )
            pos_bdda_4 = _tlv(
                b"\x30",
                b"".join(_tlv(b"\x30", _tlv(b"\x13", f"T{i}".encode()) + _tlv(b"\x13", b"V" * 128)) for i in range(4)),
            )
            pos_ext_256 = _tlv(b"\x31", _tlv(b"\x30", _tlv(b"\x80", b"\x01\x00") + _tlv(b"\xa1", _tlv(b"\x02", b"\x00"))))
            pos_san_bounds = _tlv(
                b"\x30",
                _tlv(b"\x82", b"*.insenai.com.tr")
                + _tlv(b"\x82", b"localhost")
                + _tlv(b"\x81", b"hukuk+sgk@insenai.com.tr")
                + _tlv(b"\x86", b"https://www.insenai.com.tr/path?a=1%20b#top")
                + _tlv(b"\xa3", pos_bsa_bounds + pos_bdda_4 + pos_ext_256),
            )
            for ext_oid_b in (san_oid, ian_oid):
                pos_der = _rebuild_cert_appending_extension(base_der, ext_oid_b, pos_san_bounds)
                pos_meta = parse_x509_certificate_metadata_der(pos_der)
                self.assertTrue(pos_meta.qc_compliance)
                if ext_oid_b == san_oid:
                    self.assertEqual(pos_meta.san_dns_names, ("*.insenai.com.tr", "localhost"))

            # 3. Exhaustive negative real-cert mutations: extra/duplicate fields, bounds, bad OIDs, DNS/email/URI syntax, DER canonicality
            ea_ok = _tlv(b"\x30", _tlv(b"\x80", b"\x01") + _tlv(b"\xa1", _tlv(b"\x13", b"OK")))
            bdda_ok = _tlv(b"\x30", _tlv(b"\x30", _tlv(b"\x13", b"T1") + _tlv(b"\x13", b"V1")))
            bsa_min = _tlv(b"\x30", _tlv(b"\x83", b"hrAI"))

            exhaustive_bad_gns: list[tuple[str, bytes]] = [
                # --- DNS syntax & control char violations ---
                ("dns_empty", _tlv(b"\x82", b"")),
                ("dns_space", _tlv(b"\x82", b"www.insenai.com.tr ")),
                ("dns_crlf", _tlv(b"\x82", b"www.insenai.com.tr\r\n")),
                ("dns_leading_hyphen", _tlv(b"\x82", b"-bad.insenai.com.tr")),
                ("dns_trailing_dot", _tlv(b"\x82", b"www.insenai.com.tr.")),
                ("dns_double_dot", _tlv(b"\x82", b"www..insenai.com.tr")),
                ("dns_bad_wildcard_pos", _tlv(b"\x82", b"a.*.insenai.com.tr")),
                ("dns_solo_wildcard", _tlv(b"\x82", b"*")),
                ("dns_label_64", _tlv(b"\x82", (b"a" * 64) + b".tr")),
                ("dns_invalid_char_dollar", _tlv(b"\x82", b"evil$host.tr")),
                # --- rfc822Name syntax & control char violations ---
                ("email_no_at", _tlv(b"\x81", b"hukuk.insenai.com.tr")),
                ("email_double_at", _tlv(b"\x81", b"a@b@insenai.com.tr")),
                ("email_space", _tlv(b"\x81", b"hukuk @insenai.com.tr")),
                ("email_ctrl_lf", _tlv(b"\x81", b"hukuk@insenai.com.tr\n")),
                ("email_local_65", _tlv(b"\x81", (b"a" * 65) + b"@insenai.com.tr")),
                ("email_wildcard_domain", _tlv(b"\x81", b"hukuk@*.insenai.com.tr")),
                # --- URI syntax & control char violations ---
                ("uri_empty", _tlv(b"\x86", b"")),
                ("uri_relative_no_scheme", _tlv(b"\x86", b"/relative/path")),
                ("uri_scheme_only", _tlv(b"\x86", b"https:")),
                ("uri_space", _tlv(b"\x86", b"https://www.insenai.com.tr/bad path")),
                ("uri_bad_pct_escape", _tlv(b"\x86", b"https://www.insenai.com.tr/%ZZ")),
                ("uri_ctrl_tab", _tlv(b"\x86", b"https://www.insenai.com.tr/\t")),
                ("uri_nul", _tlv(b"\x86", b"https://www.insenai.com.tr/\x00")),
                # --- registeredID & OtherName OID / extra / NUL / DER canonicality violations ---
                ("rid_empty_oid", _tlv(b"\x88", b"")),
                ("rid_non_minimal_oid_0x80", _tlv(b"\x88", bytes([0x2A, 0x80, 0x03]))),
                ("otherName_non_minimal_oid", _tlv(b"\xa0", _tlv(b"\x06", bytes([0x2A, 0x80, 0x03])) + _tlv(b"\xa0", _tlv(b"\x0c", b"v")))),
                (
                    "otherName_extra_3rd_field",
                    _tlv(b"\xa0", _tlv(b"\x06", upn_oid) + _tlv(b"\xa0", _tlv(b"\x0c", b"v")) + _tlv(b"\x05", b"")),
                ),
                ("otherName_embedded_nul_utf8", _tlv(b"\xa0", _tlv(b"\x06", upn_oid) + _tlv(b"\xa0", _tlv(b"\x0c", b"u\x00x")))),
                # Non-minimal long-form DER length (0x81 0x03 for length 3) inside OtherName value
                ("otherName_non_minimal_der_len", _tlv(b"\xa0", _tlv(b"\x06", upn_oid) + _tlv(b"\xa0", b"\x0c\x81\x03abc"))),
                # Non-minimal high-tag-number (0x1F 0x05 for tag 5 < 31) inside OtherName value
                ("otherName_non_minimal_high_tag", _tlv(b"\xa0", _tlv(b"\x06", upn_oid) + _tlv(b"\xa0", b"\x1f\x05\x00"))),
                # Indefinite BER length (0x80) inside OtherName value
                ("otherName_indefinite_ber_len", _tlv(b"\xa0", _tlv(b"\x06", upn_oid) + _tlv(b"\xa0", b"\x30\x80\x00\x00"))),
                # --- EDIPartyName extra, duplicate, multi-TLV, empty EXPLICIT ---
                (
                    "edi_extra_3rd_field",
                    _tlv(
                        b"\xa5",
                        _tlv(b"\xa0", _tlv(b"\x13", b"A"))
                        + _tlv(b"\xa1", _tlv(b"\x13", b"P"))
                        + _tlv(b"\xa1", _tlv(b"\x13", b"Extra")),
                    ),
                ),
                ("edi_duplicate_party", _tlv(b"\xa5", _tlv(b"\xa1", _tlv(b"\x13", b"P1")) + _tlv(b"\xa1", _tlv(b"\x13", b"P2")))),
                ("edi_empty_explicit_party", _tlv(b"\xa5", _tlv(b"\xa1", b""))),
                ("edi_multi_tlv_in_party", _tlv(b"\xa5", _tlv(b"\xa1", _tlv(b"\x13", b"P1") + _tlv(b"\x13", b"P2")))),
                # --- ORAddress duplicate, reversed, extra, P/C-bit, & exact RFC 5280 length bounds ---
                ("x400_duplicate_org", _tlv(b"\xa3", _tlv(b"\x30", _tlv(b"\x83", b"A") + _tlv(b"\x83", b"B")))),
                ("x400_ext_before_bdda", _tlv(b"\xa3", bsa_min + _tlv(b"\x31", ea_ok) + bdda_ok)),
                ("x400_duplicate_bdda", _tlv(b"\xa3", bsa_min + bdda_ok + bdda_ok)),
                ("x400_4th_extra_component", _tlv(b"\xa3", bsa_min + bdda_ok + _tlv(b"\x31", ea_ok) + _tlv(b"\x05", b""))),
                ("x400_prim_country_0x41", _tlv(b"\xa3", _tlv(b"\x30", _tlv(b"\x41", b"TR")))),
                ("x400_prim_personal_0x85", _tlv(b"\xa3", _tlv(b"\x30", _tlv(b"\x85", b"Yilmaz")))),
                ("x400_country_num_len_2", _tlv(b"\xa3", _tlv(b"\x30", _tlv(b"\x61", _tlv(b"\x12", b"90"))))),
                ("x400_net_addr_len_17", _tlv(b"\xa3", _tlv(b"\x30", _tlv(b"\x80", b"1" * 17)))),
                ("x400_term_id_len_25", _tlv(b"\xa3", _tlv(b"\x30", _tlv(b"\x81", b"T" * 25)))),
                ("x400_prmd_empty", _tlv(b"\xa3", _tlv(b"\x30", _tlv(b"\xa2", _tlv(b"\x13", b""))))),
                ("x400_org_len_65", _tlv(b"\xa3", _tlv(b"\x30", _tlv(b"\x83", b"O" * 65)))),
                ("x400_num_uid_len_33", _tlv(b"\xa3", _tlv(b"\x30", _tlv(b"\x84", b"7" * 33)))),
                ("x400_personal_dup_surname", _tlv(b"\xa3", _tlv(b"\x30", _tlv(b"\xa5", _tlv(b"\x80", b"A") + _tlv(b"\x80", b"B"))))),
                ("x400_personal_unknown_tag_0x84", _tlv(b"\xa3", _tlv(b"\x30", _tlv(b"\xa5", _tlv(b"\x80", b"A") + _tlv(b"\x84", b"X"))))),
                ("x400_personal_gen_qual_len_4", _tlv(b"\xa3", _tlv(b"\x30", _tlv(b"\xa5", _tlv(b"\x80", b"A") + _tlv(b"\x83", b"ABCD"))))),
                ("x400_ous_count_5", _tlv(b"\xa3", _tlv(b"\x30", _tlv(b"\xa6", b"".join(_tlv(b"\x13", b"U") for _ in range(5)))))),
                ("x400_ou_len_33", _tlv(b"\xa3", _tlv(b"\x30", _tlv(b"\xa6", _tlv(b"\x13", b"U" * 33))))),
                (
                    "x400_bdda_count_5",
                    _tlv(b"\xa3", bsa_min + _tlv(b"\x30", b"".join(_tlv(b"\x30", _tlv(b"\x13", b"T") + _tlv(b"\x13", b"V")) for _ in range(5)))),
                ),
                ("x400_bdda_type_len_9", _tlv(b"\xa3", bsa_min + _tlv(b"\x30", _tlv(b"\x30", _tlv(b"\x13", b"T" * 9) + _tlv(b"\x13", b"V"))))),
                ("x400_ext_attr_type_257", _tlv(b"\xa3", bsa_min + _tlv(b"\x31", _tlv(b"\x30", _tlv(b"\x80", b"\x01\x01") + _tlv(b"\xa1", _tlv(b"\x02", b"\x01")))))),
                ("x400_ext_attr_type_neg", _tlv(b"\xa3", bsa_min + _tlv(b"\x31", _tlv(b"\x30", _tlv(b"\x80", b"\xff") + _tlv(b"\xa1", _tlv(b"\x02", b"\x01")))))),
                ("x400_ext_attr_empty_val", _tlv(b"\xa3", bsa_min + _tlv(b"\x31", _tlv(b"\x30", _tlv(b"\x80", b"\x01") + _tlv(b"\xa1", b""))))),
                (
                    "x400_ext_attr_two_tlvs",
                    _tlv(b"\xa3", bsa_min + _tlv(b"\x31", _tlv(b"\x30", _tlv(b"\x80", b"\x01") + _tlv(b"\xa1", _tlv(b"\x02", b"\x01") + _tlv(b"\x02", b"\x02"))))),
                ),
                ("dirName_empty_explicit", _tlv(b"\xa4", b"")),
                ("ip_len_5", _tlv(b"\x87", bytes([192, 0, 2, 1, 0]))),
            ]

            for label, bad_gn in exhaustive_bad_gns:
                san_val = _tlv(b"\x30", bad_gn)
                for ctx_name, ext_oid_b in (("SAN", san_oid), ("IAN", ian_oid)):
                    mut_der = _rebuild_cert_appending_extension(base_der, ext_oid_b, san_val)
                    cache_key = (hashlib.sha256(mut_der).hexdigest(), len(mut_der))
                    with self.assertRaises(DerParseError, msg=f"{ctx_name} must reject {label}"):
                        parse_x509_certificate_metadata_der(mut_der)
                    self.assertNotIn(cache_key, x509_mod._METADATA_CACHE, f"cache polluted: {ctx_name}/{label}")
                    mut_pem = _der_to_pem(mut_der)
                    self.assertIsNone(parse_x509_certificate_metadata(mut_pem), f"{ctx_name}/{label}")
                    insp = inspect_signer_certificate_x509(mut_pem, validation_time_utc=val_t)
                    self.assertFalse(insp.valid_x509, f"{ctx_name}/{label}")
                    self.assertEqual(insp.subject, "", f"{ctx_name}/{label}")
                    self.assertEqual(insp.issuer, "", f"{ctx_name}/{label}")
                    self.assertEqual(insp.serial_number, "", f"{ctx_name}/{label}")
                    self.assertEqual(insp.cert_sha256, "", f"{ctx_name}/{label}")
                    self.assertEqual(insp.signature_algorithm, "", f"{ctx_name}/{label}")
                    self.assertEqual(insp.public_key_algorithm, "", f"{ctx_name}/{label}")
                    self.assertFalse(insp.qc_compliance, f"{ctx_name}/{label}")
                    self.assertFalse(insp.qc_sscd, f"{ctx_name}/{label}")
                    self.assertNotIn(cache_key, x509_mod._METADATA_CACHE, f"cache polluted after inspect: {ctx_name}/{label}")


if __name__ == "__main__":
    unittest.main()
