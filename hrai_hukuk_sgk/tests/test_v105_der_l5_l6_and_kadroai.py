"""KadroAI @HukukSGK v1.0.5 — Strict ITU-T X.690 DER Canonicality, L5/L6 Autonomous Norms & Brand Transition Test Suite.

Covers all 4 approved architectural decisions for KadroAI @HukukSGK v1.0.5:
  1. Karar 1 — Strict ITU-T X.690 DER Canonicality (`x509_metadata.py`, `MAX_ASN1_DEPTH = 32`,
     malformed DER/PEM/Base64 fail-closed with zero partial metadata, valid boundary certificates,
     and cache collision raw-DER byte-equality enforcement).
  2. Karar 2 — L5 (5 Corporate HR Procedures) & L6 (4 distinct Autonomous Norm modules) strictly
     isolated from L1–L4 (74/74 untouched), carrying all 7 mandatory per-rule fields, no flat
     `priority: 8` supremacy, unadopted reference-template guardrails, independent audit registry
     (`config/autonomous_norms_audit_log.json`), and nuanced Turkish labor law conflict resolution
     (ABSOLUTE_MANDATORY vs RELATIVE_MANDATORY_FLOOR vs SUPPLEMENTARY_DEFAULT, TİS 6356 m.36, 4857 m.22).
  3. Karar 3 — Backward-compatible `KadroAI` / `@KadroAI` / `@HukukSGK` brand transition
     (new v1.0.5 service IDs & `KadroAI-HukukSGK/1.0.5` User-Agent while preserving historical audit IDs).
  4. Karar 4 — `engine/esign5070/xmldsig.py` byte-identical to v1.0.4.4/v1.0.4.5, exact 13 Draft 2020-12
     schemas, exact 9 `config/` JSON files, and fail-closed production/5070 locks.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from engine.autonomous_norms import (
    EXPECTED_L6_SOURCE_KINDS,
    REQUIRED_RULE_FIELDS,
    evaluate_autonomous_norm_conflict,
    load_l5_hr_procedures,
    load_l6_cba_contract_practices,
    validate_autonomous_norms_audit_log,
)
from engine.esign5070 import (
    ESIGN_5070_VERSION,
    MAX_ASN1_DEPTH,
    DefaultQualifiedSignature5070Verifier,
    DefaultSscdControlEvidenceVerifier,
    DerParseError,
    inspect_signer_certificate_x509,
    parse_x509_certificate_metadata,
    parse_x509_certificate_metadata_der,
)
from engine.esign5070 import x509_metadata as x509_mod
from engine.knowledge_card_validator import load_knowledge_cards, validate_central_audit_log
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


class TestKadroAiV105DerL5L6AndGovernance(unittest.TestCase):
    """[V1.0.5 / DER X.690 / L5-L6 AUTONOMOUS NORMS / KADROAI BRAND] Comprehensive v1.0.5 verification suite."""

    def test_01_strict_der_canonicality_negatives_depth_limit_and_zero_partial_metadata(self) -> None:
        self.assertEqual(MAX_ASN1_DEPTH, 32)

        # 1. Primitive & TLV-level ITU-T X.690 canonicality rejections
        # 1a. Indefinite length (0x80)
        with self.assertRaises(DerParseError):
            x509_mod._read_tlv(b"\x30\x80\x00\x00", 0, 4)
        # 1b. Reserved length byte (0xFF)
        with self.assertRaises(DerParseError):
            x509_mod._read_tlv(b"\x30\xff\x01", 0, 3)
        # 1c. Non-minimal long-form length (<128 encoded as 0x81 0x05)
        with self.assertRaises(DerParseError):
            x509_mod._read_tlv(b"\x04\x81\x05hello", 0, 8)
        # 1d. Leading zero in long-form length (0x82 0x00 0x80)
        with self.assertRaises(DerParseError):
            x509_mod._read_tlv(b"\x04\x82\x00\x80" + b"a" * 128, 0, 132)
        # 1e. High-tag-number < 31 (non-canonical) and leading 0x80 in base-128 tag
        with self.assertRaises(DerParseError):
            x509_mod._read_tlv(b"\x1f\x05\x00", 0, 3)
        with self.assertRaises(DerParseError):
            x509_mod._read_tlv(b"\x1f\x80\x20\x00", 0, 4)
        # 1f. Non-DER BOOLEAN (0x01 instead of 0x00 / 0xFF)
        with self.assertRaises(DerParseError):
            x509_mod._decode_der_boolean(b"\x01")
        with self.assertRaises(DerParseError):
            x509_mod._decode_der_boolean(b"\x00\x00")
        self.assertFalse(x509_mod._decode_der_boolean(b"\x00"))
        self.assertTrue(x509_mod._decode_der_boolean(b"\xff"))
        # 1g. Non-minimal INTEGER (leading 0x00 with MSB=0, leading 0xFF with MSB=1)
        with self.assertRaises(DerParseError):
            x509_mod._validate_der_integer(b"\x00\x01")
        with self.assertRaises(DerParseError):
            x509_mod._validate_der_integer(b"\xff\x80")
        # Valid minimal positive INTEGER with MSB=1 padded by single 0x00
        x509_mod._validate_der_integer(b"\x00\x80")
        # 1h. Non-minimal OID (leading 0x80 base-128 subidentifier)
        with self.assertRaises(DerParseError):
            x509_mod._decode_oid(b"\x2a\x80\x01")
        # 1i. BIT STRING invalid unused (>7), empty non-zero unused, non-zero trailing pad bits
        with self.assertRaises(DerParseError):
            x509_mod._validate_der_bit_string(b"\x08\x00")
        with self.assertRaises(DerParseError):
            x509_mod._validate_der_bit_string(b"\x01")
        with self.assertRaises(DerParseError):
            x509_mod._validate_der_bit_string(b"\x03\x01")  # lowest 3 bits must be 0!
        x509_mod._validate_der_bit_string(b"\x03\x08")  # lowest 3 bits are 0 -> valid
        # 1j. Invalid RFC 5280 UTCTime / GeneralizedTime
        for tag_byte, bad_time in (
            (0x17, b"260230120000Z"),      # impossible calendar day Feb 30
            (0x17, b"260501120000+0300"),  # timezone offset forbidden in DER
            (0x18, b"20260501120000.5Z"),  # fractional seconds forbidden in DER
            (0x18, b"20260501120000z"),    # lowercase z forbidden
            (0x18, b"20261301120000Z"),    # month 13 invalid
        ):
            with self.assertRaises(DerParseError, msg=f"Should reject {bad_time!r}"):
                x509_mod._decode_x509_time(tag_byte, bad_time)
        # 1k. MAX_ASN1_DEPTH = 32 exceeded (33 nested SEQUENCE tags -> DerParseError)
        deep_der = b"\x05\x00"  # NULL
        for _ in range(MAX_ASN1_DEPTH + 1):
            deep_der = _tlv(b"\x30", deep_der)
        with self.assertRaises(DerParseError):
            x509_mod._validate_and_collect_oids(deep_der, 0, len(deep_der), set(), depth=0)

        # 2. Full certificate DER mutation tests: malformed DER NEVER returns partial metadata,
        #    while the unmodified valid certificate remains 100% intact!
        val_t = "2026-11-24T00:00:00Z"
        with Ephemeral5070PkiFixture() as pki:
            cert_pem, _, _ = pki.issue_signer_cert(tag="der_strict", include_qc_compliance=True, include_qc_sscd=True)
            valid_der = _pem_to_der(cert_pem)
            good_meta = parse_x509_certificate_metadata_der(valid_der)
            self.assertTrue(good_meta.qc_compliance)
            self.assertTrue(good_meta.qc_sscd)
            self.assertFalse(good_meta.basic_constraints_ca)

            # 2a. Trailing garbage bytes appended to outer DER cert
            bad_trailing = valid_der + b"\x00"
            with self.assertRaises(DerParseError):
                parse_x509_certificate_metadata_der(bad_trailing)
            self.assertIsNone(parse_x509_certificate_metadata(_der_to_pem(bad_trailing)))
            insp_bad = inspect_signer_certificate_x509(_der_to_pem(bad_trailing), validation_time_utc=val_t)
            self.assertFalse(insp_bad.valid_x509)
            self.assertEqual(insp_bad.subject, "")
            self.assertEqual(insp_bad.issuer, "")
            self.assertEqual(insp_bad.serial_number, "")
            self.assertEqual(insp_bad.not_before_utc, "")
            self.assertEqual(insp_bad.not_after_utc, "")
            self.assertFalse(insp_bad.qc_compliance)
            self.assertFalse(insp_bad.qc_sscd)

            # 2b. Non-DER BOOLEAN (0x01) inside a CA cert's BasicConstraints (01 01 ff -> 01 01 01)
            ca_der = _pem_to_der(pki.root_cert_pem)
            bc_true_pattern = b"\x06\x03\x55\x1d\x13"  # OID 2.5.29.19 BasicConstraints
            idx = ca_der.find(bc_true_pattern)
            self.assertGreater(idx, 0)
            bool_idx = ca_der.find(b"\x01\x01\xff", idx)
            self.assertGreater(bool_idx, idx)
            bad_bool_der = ca_der[:bool_idx] + b"\x01\x01\x01" + ca_der[bool_idx + 3 :]
            with self.assertRaises(DerParseError):
                parse_x509_certificate_metadata_der(bad_bool_der)
            insp_bad_bool = inspect_signer_certificate_x509(_der_to_pem(bad_bool_der), validation_time_utc=val_t)
            self.assertFalse(insp_bad_bool.valid_x509)
            self.assertEqual(insp_bad_bool.subject, "")
            self.assertFalse(insp_bad_bool.basic_constraints_ca)

            # 2c. Negative serialNumber in TBSCertificate (flip MSB of first serial byte)
            _, cert_vs, cert_ve, _ = x509_mod._read_tlv(valid_der, 0, len(valid_der))
            _, tbs_vs, tbs_ve, _ = x509_mod._read_tlv(valid_der, cert_vs, cert_ve)
            tbs_children = x509_mod._iter_children(valid_der, tbs_vs, tbs_ve)
            ser_tag, ser_vs, ser_ve, _ = tbs_children[1]  # index 0 is [0] version, index 1 is serialNumber INTEGER
            self.assertEqual(ser_tag, 0x02)
            neg_serial_der = bytearray(valid_der)
            neg_serial_der[ser_vs] |= 0x80  # force negative two's complement (or non-minimal if 0x00 -> 0x80)
            with self.assertRaises(DerParseError):
                parse_x509_certificate_metadata_der(bytes(neg_serial_der))

            # 2d. Re-verify unmodified valid cert metadata is 100% preserved & untouched!
            recheck = parse_x509_certificate_metadata(cert_pem)
            self.assertEqual(recheck, good_meta)

    def test_02_strict_pem_base64_and_valid_boundary_certificates(self) -> None:
        openssl = shutil.which("openssl")
        self.assertIsNotNone(openssl)
        val_t = "2026-11-24T00:00:00Z"

        with Ephemeral5070PkiFixture() as pki:
            cert_a, _, _ = pki.issue_signer_cert(tag="pem_a")
            cert_b, _, _ = pki.issue_signer_cert(tag="pem_b")

            # 1. Malformed PEM / Base64 negatives MUST fail closed (None metadata & valid_x509=False, zero partial fields)
            malformed_pems = [
                cert_a + "\n" + cert_b,                             # multiple PEM blocks concatenated
                "EXTRA LEADING TEXT\n" + cert_a,                    # unexpected leading text
                cert_a + "\nEXTRA TRAILING TEXT\n",                 # unexpected trailing text
                "-----BEGIN CERTIFICATE-----\n!!!INVALID!!!\n-----END CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE-----\nMIIB XX==\n-----END CERTIFICATE-----\n",  # internal space in Base64
            ]
            for bad_pem in malformed_pems:
                self.assertIsNone(parse_x509_certificate_metadata(bad_pem))
                insp = inspect_signer_certificate_x509(bad_pem, validation_time_utc=val_t)
                self.assertFalse(insp.valid_x509)
                self.assertEqual(insp.subject, "")
                self.assertEqual(insp.serial_number, "")

            # 2a. Valid boundary dates via OpenSSL 3 CA: leap day UTCTime (2028-02-29) & GeneralizedTime (>=2050)
            bound_pem, _, _ = pki.issue_signer_cert(
                tag="bound_dates",
                startdate="20280229120000Z",
                enddate="20550615083000Z",
            )
            bound_meta = parse_x509_certificate_metadata(bound_pem)
            self.assertIsNotNone(bound_meta)
            assert bound_meta is not None
            self.assertEqual(bound_meta.not_before_utc, "2028-02-29T12:00:00Z")
            self.assertEqual(bound_meta.not_after_utc, "2055-06-15T08:30:00Z")
            self.assertFalse(bound_meta.basic_constraints_ca)

            # 2b. Valid ECDSA P-256 certificate with 20-byte MSB=1 positive serial (requires single leading 0x00 DER pad)
            with tempfile.TemporaryDirectory(prefix="kadroai_v105_bounds_") as td:
                tdp = Path(td)
                key_ec = tdp / "ec.key"
                csr_ec = tdp / "ec.csr"
                crt_ec = tdp / "ec.crt"
                ca_key = tdp / "ca.key"
                ca_crt = tdp / "ca.crt"
                ee_ext = tdp / "ee.ext"
                ee_ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation\n", encoding="utf-8")

                subprocess.run(
                    [openssl, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ca_key)],
                    stdin=subprocess.DEVNULL, check=True, capture_output=True, timeout=30,
                )
                subprocess.run(
                    [openssl, "req", "-x509", "-new", "-key", str(ca_key), "-out", str(ca_crt), "-days", "365",
                     "-subj", "/C=TR/O=KadroAI Boundary CA/CN=KadroAI Boundary CA",
                     "-addext", "basicConstraints=critical,CA:TRUE",
                     "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
                    stdin=subprocess.DEVNULL, check=True, capture_output=True, timeout=30,
                )
                subprocess.run(
                    [openssl, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key_ec)],
                    stdin=subprocess.DEVNULL, check=True, capture_output=True, timeout=30,
                )
                subprocess.run(
                    [openssl, "req", "-new", "-key", str(key_ec), "-out", str(csr_ec),
                     "-subj", "/C=TR/O=KadroAI Boundary Org/CN=Boundary EC Leaf"],
                    stdin=subprocess.DEVNULL, check=True, capture_output=True, timeout=30,
                )
                serial_20b = "9F112233445566778899AABBCCDDEEFF00112233"
                subprocess.run(
                    [
                        openssl, "x509", "-req", "-in", str(csr_ec), "-CA", str(ca_crt), "-CAkey", str(ca_key),
                        "-set_serial", f"0x{serial_20b}",
                        "-days", "365",
                        "-extfile", str(ee_ext),
                        "-out", str(crt_ec),
                    ],
                    stdin=subprocess.DEVNULL, check=True, capture_output=True, timeout=30,
                )
                leaf_pem = crt_ec.read_text(encoding="utf-8")
                meta = parse_x509_certificate_metadata(leaf_pem)
                self.assertIsNotNone(meta)
                assert meta is not None
                self.assertEqual(meta.serial_number, serial_20b)
                self.assertFalse(meta.basic_constraints_ca)
                self.assertEqual(meta.public_key_algorithm, "id-ecPublicKey")
                self.assertIn("Digital Signature", meta.key_usage)
                self.assertIn("Non Repudiation", meta.key_usage)

                # Cross-check exact serial against OpenSSL 3 CLI
                ossl_ser = subprocess.run(
                    [openssl, "x509", "-in", str(crt_ec), "-noout", "-serial"],
                    stdin=subprocess.DEVNULL, check=True, capture_output=True, text=True, timeout=30,
                ).stdout.strip().split("=", 1)[1].upper()
                self.assertEqual(meta.serial_number, ossl_ser)

    def test_03_cache_collision_verifies_raw_der_byte_equality(self) -> None:
        with Ephemeral5070PkiFixture() as pki:
            cert_a_pem, _, _ = pki.issue_signer_cert(tag="cache_a")
            cert_b_pem, _, _ = pki.issue_signer_cert(tag="cache_b")
            der_a = _pem_to_der(cert_a_pem)
            der_b = _pem_to_der(cert_b_pem)
            self.assertNotEqual(der_a, der_b)

            meta_a_true = parse_x509_certificate_metadata_der(der_a)
            meta_b_true = parse_x509_certificate_metadata_der(der_b)
            self.assertNotEqual(meta_a_true.serial_number, meta_b_true.serial_number)

            # Poison cache key for cert_a with cert_b's raw bytes & metadata (simulating hash+length collision!)
            key_a = (hashlib.sha256(der_a).hexdigest(), len(der_a))
            with x509_mod._CACHE_LOCK:
                x509_mod._METADATA_CACHE[key_a] = (der_b, meta_b_true)

            # Parser MUST compare raw DER bytes (`hit[0] == raw`), reject mismatch, and return cert_a's real metadata!
            res_a = parse_x509_certificate_metadata_der(der_a)
            self.assertEqual(res_a.serial_number, meta_a_true.serial_number)
            self.assertEqual(res_a.subject, meta_a_true.subject)
            self.assertNotEqual(res_a.serial_number, meta_b_true.serial_number)

            # Confirm cache now holds exact raw der_a bytes and cert_b remains intact
            with x509_mod._CACHE_LOCK:
                stored_raw, stored_meta = x509_mod._METADATA_CACHE[key_a]
                self.assertEqual(stored_raw, der_a)
                self.assertEqual(stored_meta.serial_number, meta_a_true.serial_number)
            self.assertEqual(parse_x509_certificate_metadata_der(der_b).serial_number, meta_b_true.serial_number)

    def test_04_l5_and_l6_isolation_7_fields_cross_refs_non_adoption_and_audit_log(self) -> None:
        sources = load_source_registry(PROJECT_ROOT / "config" / "legal_sources_registry.json")
        precedents = load_precedent_registry(PROJECT_ROOT / "config" / "yargitay_precedents.json")
        cards = load_knowledge_cards(PROJECT_ROOT / "rag_kb", sources, precedents)
        # Official L1-L4 statutory core MUST remain completely untouched (30/5/39, 74/74)
        self.assertEqual((len(sources), len(precedents), len(cards)), (30, 5, 39))

        l5_mods = load_l5_hr_procedures(PROJECT_ROOT / "rag_kb", sources, cards, precedents, strict=True)
        l6_mods = load_l6_cba_contract_practices(PROJECT_ROOT / "rag_kb", sources, cards, precedents, strict=True)
        self.assertEqual(len(l5_mods), 5)
        self.assertEqual(len(l6_mods), 4)
        self.assertEqual({m.autonomous_source_kind for m in l6_mods.values()}, EXPECTED_L6_SOURCE_KINDS)

        all_rules = [r for m in (*l5_mods.values(), *l6_mods.values()) for r in m.rules]
        self.assertEqual(len(all_rules), 19)
        for mod in (*l5_mods.values(), *l6_mods.values()):
            self.assertEqual(mod.adoption_status, "REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION")
            self.assertTrue(mod.template_only_not_binding_company_policy)
            self.assertTrue(mod.no_flat_priority_supremacy)
            for rule in mod.rules:
                rdict = rule.to_dict()
                for req_field in REQUIRED_RULE_FIELDS:
                    self.assertIn(req_field, rdict, f"{rule.rule_id} missing {req_field}")
                self.assertEqual(rule.adoption_status, "REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION")
                self.assertFalse(rule.is_binding_company_policy)
                self.assertTrue(rule.human_review_required)

        # Independent L5/L6 audit log validates cleanly
        auto_audit = json.loads((PROJECT_ROOT / "config" / "autonomous_norms_audit_log.json").read_text(encoding="utf-8"))
        ares = validate_autonomous_norms_audit_log(auto_audit, l5_mods, l6_mods)
        self.assertTrue(ares["valid"], ares)
        self.assertEqual(ares["total_autonomous_modules"], 9)
        self.assertEqual(ares["total_autonomous_rules"], 19)

        # Negative loader tests: fake legal_basis_id & human_review_required=False on unadopted template MUST fail!
        with tempfile.TemporaryDirectory(prefix="kadroai_l5_neg_") as td:
            l5_tmp = Path(td) / "05_ik_prosedurleri"
            l5_tmp.mkdir(parents=True)
            sample = json.loads(
                (PROJECT_ROOT / "rag_kb" / "05_ik_prosedurleri" / "01_ise_alim_ve_ozluk_dosyasi_proseduru.json").read_text(
                    encoding="utf-8"
                )
            )
            bad_basis = copy.deepcopy(sample)
            bad_basis["rules"][0]["legal_basis_ids"].append("MEVZUAT-FAKE-9999")
            (l5_tmp / "bad.json").write_text(json.dumps(bad_basis, ensure_ascii=False), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_l5_hr_procedures(td, sources, cards, precedents, strict=True)

            bad_hr = copy.deepcopy(sample)
            bad_hr["rules"][0]["human_review_required"] = False
            (l5_tmp / "bad.json").write_text(json.dumps(bad_hr, ensure_ascii=False), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_l5_hr_procedures(td, sources, cards, precedents, strict=True)

    def test_05_l5_l6_norm_conflict_employee_favorability_and_router_dispatch(self) -> None:
        router = HukukSGKToolRouter()
        self.assertEqual(len(router.l5_hr_procedures), 5)
        self.assertEqual(len(router.l6_cba_contract_practices), 4)

        # 1. Lookup tool returns unadopted reference templates with mandatory disclaimer
        lkp = router.dispatch("lookup_autonomous_norm_guidance", {"query": "disiplin savunma tutanak", "layer": "L5"})
        self.assertEqual(lkp["status"], "OK")
        self.assertEqual(lkp["product_brand"], "hrAI")
        self.assertEqual(lkp["coordinator_agent"], "@hrAI")
        self.assertEqual(lkp["specialist_agent"], "@HukukSGK")
        self.assertGreaterEqual(lkp["match_count"], 1)
        self.assertTrue(lkp["all_builtin_templates_pending_company_adoption"])
        self.assertIsNotNone(lkp["matches"][0]["template_only_notice"])

        # 2. ABSOLUTE_MANDATORY cannot be altered even in employee's favor
        d_abs = router.dispatch(
            "evaluate_autonomous_norm_conflict",
            {
                "rule_id": "RULE-L5-02-M26-SURE",
                "proposed_change_direction": "EMPLOYEE_FAVORABLE",
                "competing_norm_type": "CORPORATE_HR_PROCEDURE",
            },
        )
        self.assertFalse(d_abs["permitted"])
        self.assertEqual(d_abs["outcome"], "REJECTED_STATUTORY_ABSOLUTE_PREVAILS")
        self.assertIn("ABSOLUTE_MANDATORY_CANNOT_BE_ALTERED", d_abs["error_codes"])
        self.assertFalse(d_abs["binding_company_policy"])
        self.assertTrue(d_abs["human_review_required"])

        # 3. RELATIVE_MANDATORY_FLOOR permits employee-favorable, rejects below-floor
        d_rel_ok = router.dispatch(
            "evaluate_autonomous_norm_conflict",
            {
                "rule_id": "RULE-L5-03-IHBAR-VE-PIP-SURESI",
                "proposed_change_direction": "EMPLOYEE_FAVORABLE",
            },
        )
        self.assertTrue(d_rel_ok["permitted"])
        self.assertEqual(d_rel_ok["outcome"], "PERMITTED_EMPLOYEE_FAVORABLE_ABOVE_FLOOR")
        self.assertFalse(d_rel_ok["binding_company_policy"])
        self.assertTrue(d_rel_ok["human_review_required"])

        d_rel_bad = router.dispatch(
            "evaluate_autonomous_norm_conflict",
            {
                "rule_id": "RULE-L5-03-IHBAR-VE-PIP-SURESI",
                "proposed_change_direction": "BELOW_STATUTORY_FLOOR",
            },
        )
        self.assertFalse(d_rel_bad["permitted"])
        self.assertIn("DEROGATION_BELOW_STATUTORY_FLOOR_INVALID", d_rel_bad["error_codes"])

        # 4. SUPPLEMENTARY_DEFAULT permits lawful variation (not every statute is equally immutable!)
        d_supp = router.dispatch(
            "evaluate_autonomous_norm_conflict",
            {
                "rule_id": "RULE-L6-02-UZAKTAN-HIBRIT-TAMAMLAYICI",
                "proposed_change_direction": "SUPPLEMENTARY_VARIATION",
                "competing_norm_type": "INDIVIDUAL_EMPLOYMENT_CONTRACT",
            },
        )
        self.assertTrue(d_supp["permitted"])
        self.assertEqual(d_supp["outcome"], "PERMITTED_SUPPLEMENTARY_VARIATION_WITHIN_STATUTORY_LIMITS")

        # 5. TİS (6356 m.36) vs Individual Employment Contract (non-reducible, distinct conflict rules!)
        d_tis_less = router.dispatch(
            "evaluate_autonomous_norm_conflict",
            {
                "rule_id": "RULE-L6-01-TIS-DOGRUDAN-ETKI",
                "proposed_change_direction": "EMPLOYER_UNILATERAL_DOWNGRADE",
                "competing_norm_type": "INDIVIDUAL_EMPLOYMENT_CONTRACT",
            },
        )
        self.assertFalse(d_tis_less["permitted"])
        self.assertEqual(d_tis_less["prevailing_norm"], "COLLECTIVE_BARGAINING_AGREEMENT")
        self.assertIn("CBA_OVERRIDES_LESS_FAVORABLE_INDIVIDUAL_CONTRACT_6356_M36", d_tis_less["error_codes"])

        d_tis_more = router.dispatch(
            "evaluate_autonomous_norm_conflict",
            {
                "rule_id": "RULE-L6-01-TIS-DOGRUDAN-ETKI",
                "proposed_change_direction": "EMPLOYEE_FAVORABLE",
                "competing_norm_type": "INDIVIDUAL_EMPLOYMENT_CONTRACT",
                "cba_expressly_forbids_individual_improvement": False,
            },
        )
        self.assertTrue(d_tis_more["permitted"])
        self.assertEqual(d_tis_more["prevailing_norm"], "INDIVIDUAL_EMPLOYMENT_CONTRACT")

        d_tis_forbid = router.dispatch(
            "evaluate_autonomous_norm_conflict",
            {
                "rule_id": "RULE-L6-01-TIS-DOGRUDAN-ETKI",
                "proposed_change_direction": "EMPLOYEE_FAVORABLE",
                "competing_norm_type": "INDIVIDUAL_EMPLOYMENT_CONTRACT",
                "cba_expressly_forbids_individual_improvement": True,
            },
        )
        self.assertFalse(d_tis_forbid["permitted"])
        self.assertEqual(d_tis_forbid["prevailing_norm"], "COLLECTIVE_BARGAINING_AGREEMENT")
        self.assertIn("CBA_EXPRESSLY_FORBIDS_INDIVIDUAL_DEVIATION_6356_M36", d_tis_forbid["error_codes"])

        # 6. Unilateral HR Procedure downgrade against Established Workplace Practice -> 4857 m.22 written consent required!
        d_prac_no_consent = router.dispatch(
            "evaluate_autonomous_norm_conflict",
            {
                "rule_id": "RULE-L6-04-PRIM-IKRAMIYE-BAGLAYICILIK",
                "proposed_change_direction": "EMPLOYER_UNILATERAL_DOWNGRADE",
                "competing_norm_type": "CORPORATE_HR_PROCEDURE",
                "written_employee_consent_4857_m22": False,
            },
        )
        self.assertFalse(d_prac_no_consent["permitted"])
        self.assertIn("ESSENTIAL_CHANGE_4857_M22_WRITTEN_CONSENT_REQUIRED", d_prac_no_consent["error_codes"])

        d_prac_consent = router.dispatch(
            "evaluate_autonomous_norm_conflict",
            {
                "rule_id": "RULE-L6-04-PRIM-IKRAMIYE-BAGLAYICILIK",
                "proposed_change_direction": "EMPLOYER_UNILATERAL_DOWNGRADE",
                "competing_norm_type": "CORPORATE_HR_PROCEDURE",
                "written_employee_consent_4857_m22": True,
            },
        )
        self.assertTrue(d_prac_consent["permitted"])
        self.assertTrue(d_prac_consent["human_review_required"])

        # 7. Unadopted template warning always present; counsel-verified adopted rule sets binding_company_policy=True
        adopted_rule = {
            "norm_type": "CORPORATE_HR_PROCEDURE",
            "adoption_status": "COMPANY_ADOPTED_COUNSEL_VERIFIED",
            "employee_favorable_check": {"statutory_floor_nature": "RELATIVE_MANDATORY_FLOOR"},
            "human_review_required": False,
        }
        d_adopted = evaluate_autonomous_norm_conflict(adopted_rule, proposed_change_direction="EMPLOYEE_FAVORABLE")
        self.assertTrue(d_adopted.permitted)
        self.assertTrue(d_adopted.binding_company_policy)
        self.assertFalse(d_adopted.human_review_required)
        self.assertEqual(d_adopted.warnings, ())

    def test_06_kadroai_brand_backward_compat_xmldsig_byte_identity_and_v105_governance(self) -> None:
        # 1. Exact version & hrAI service IDs
        self.assertEqual(ESIGN_5070_VERSION, "1.0.5.1")
        self.assertEqual(TRUST_ROOT_VERSION, "1.0.5.1")
        self.assertEqual(DefaultQualifiedSignature5070Verifier().provider_name, "HRAI_CADES_XADES_5070_VERIFIER_V1051")
        self.assertEqual(
            DefaultSscdControlEvidenceVerifier().verifier_service_id,
            "HRAI_SSCD_CONTROL_EVIDENCE_VERIFIER_V1051",
        )

        # 2. HTTP User-Agent updated to hrAI-HukukSGK/1.0.5.1
        src_acq_text = (PROJECT_ROOT / "engine" / "trust_root" / "source_acquisition.py").read_text(encoding="utf-8")
        self.assertIn('f"hrAI-HukukSGK/{TRUST_ROOT_VERSION} (SourceAcquisition)"', src_acq_text)

        # 3. engine/esign5070/xmldsig.py MUST be 100% byte-identical to v1.0.4.4 / v1.0.4.5 / v1.0.5!
        xmldsig_sha = hashlib.sha256((PROJECT_ROOT / "engine" / "esign5070" / "xmldsig.py").read_bytes()).hexdigest()
        self.assertEqual(xmldsig_sha, EXPECTED_XMLDSIG_SHA256)

        # 4. Live integration probe reports hrAI brand & keeps ALL production / 5070 locks CLOSED
        report = run_live_integration_probe(project_root=PROJECT_ROOT)
        self.assertEqual(report["product_brand"], "hrAI")
        self.assertEqual(report["coordinator_agent"], "@hrAI")
        self.assertEqual(report["specialist_agent"], "@HukukSGK")
        self.assertEqual(report["schema_version"], "1.0.5.1")
        self.assertEqual(report["overall_live_integration_status"], "NOT_CONFIGURED")
        self.assertEqual(report["esign_5070_overall_status"], "NOT_CONFIGURED")
        self.assertFalse(report["production_use_authorized"])
        self.assertFalse(report["qualified_e_signature_5070_production_ready"])
        self.assertFalse(report["qualified_e_signature_5070_equivalent"])

        # 5. Exact 13 Draft 2020-12 schemas with hrAI branding & (v1.0.5.1) titles
        schemas = sorted((PROJECT_ROOT / "schemas").glob("*.schema.json"))
        self.assertEqual(len(schemas), 13)
        for sf in schemas:
            s_doc = json.loads(sf.read_text(encoding="utf-8"))
            self.assertEqual(s_doc["$schema"], "https://json-schema.org/draft/2020-12/schema", sf.name)
            self.assertIn("hrAI @HukukSGK", s_doc["title"], sf.name)
            self.assertIn("(v1.0.5.1)", s_doc["title"], sf.name)

        # 6. Exact 9 config/*.json files (6 schema-validated + 3 engine/audit-validated)
        cfg_files = sorted(p.name for p in (PROJECT_ROOT / "config").glob("*.json"))
        self.assertEqual(len(cfg_files), 9)

        # 7. Historical audit IDs preserved for backward compatibility
        appr = json.loads((PROJECT_ROOT / "config" / "authorized_approvers.json").read_text(encoding="utf-8"))
        self.assertIn("CALISORA-HUKUK-01", appr["approvers"])
        self.assertIn("CALISORA-LEDGER-SEALER-01", appr["approvers"])
        ledger = json.loads((PROJECT_ROOT / "config" / "calendar_attestation_ledger.json").read_text(encoding="utf-8"))
        self.assertEqual(ledger["checkpoints"][0]["checkpoint_id"], "CHK-RELEASE-1.0.5.1-20261124")
        self.assertEqual(ledger["checkpoints"][0]["signer_approver_id"], "CALISORA-LEDGER-SEALER-01")

        # 8. Taxonomy, prompt, tool_schemas reflect hrAI / @hrAI / @HukukSGK & autonomous_norm_evaluation_model
        tax = json.loads((PROJECT_ROOT / "config" / "knowledge_taxonomy.json").read_text(encoding="utf-8"))
        self.assertEqual(tax["product_brand"], "hrAI")
        self.assertEqual(tax["coordinator_agent"], "@hrAI")
        self.assertEqual(tax["specialist_agent"], "@HukukSGK")
        self.assertTrue(tax["autonomous_norm_evaluation_model"]["no_flat_priority_supremacy"])
        self.assertEqual(len(tax["verification_infrastructure"]["schemas"]), 13)

        tools = json.loads((PROJECT_ROOT / "agent" / "tool_schemas.json").read_text(encoding="utf-8"))
        self.assertEqual(tools["product_brand"], "hrAI")
        self.assertEqual(tools["coordinator_agent"], "@hrAI")
        self.assertEqual(tools["specialist_agent"], "@HukukSGK")
        tool_names = {t["name"] for t in tools["tools"]}
        self.assertIn("lookup_autonomous_norm_guidance", tool_names)
        self.assertIn("evaluate_autonomous_norm_conflict", tool_names)

        # 9. Official 74/74 L1-L4 central audit log strictly preserved
        sources = load_source_registry(PROJECT_ROOT / "config" / "legal_sources_registry.json")
        precedents = load_precedent_registry(PROJECT_ROOT / "config" / "yargitay_precedents.json")
        cards = load_knowledge_cards(PROJECT_ROOT / "rag_kb", sources, precedents)
        audit_data = json.loads((PROJECT_ROOT / "config" / "verification_audit_log.json").read_text(encoding="utf-8"))
        self.assertEqual(audit_data["summary"]["total_audited_records"], 74)
        self.assertTrue(validate_central_audit_log(audit_data, sources, precedents, cards).valid)


if __name__ == "__main__":
    unittest.main()
