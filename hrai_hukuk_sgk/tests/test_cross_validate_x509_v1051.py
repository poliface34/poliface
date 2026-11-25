"""Unit tests for hrAI @HukukSGK v1.0.5.1 X.509 Cross-Validation Tool (`tests/cross_validate_x509.py`).

Covers:
  1. Independent OpenSSL result classification (`x509 -noout -text`, `asn1parse -inform PEM`,
     `asn1parse -inform DER`, `pem_der_asn1_match` gating for positive `ACCEPTED`, `ASN1_PARSE_FAILED`,
     `PEM_DER_ASN1_MISMATCH`, `UNSUPPORTED_BY_PARSER`, `BER_PERMISSIVE_ACCEPT`, and real `REJECTED`).
  2. `offline` execution mode (`hrAI`-only, `INDEPENDENT_CROSS_VALIDATION=NOT_PERFORMED`, zero
     conflation with `NOT_INSTALLED` or `REJECTED`, exit code 0 on clean fixtures).
  3. `strict` execution mode fail-closed gates: missing external parsers (`exit_code = 2`),
     external positive/negative threshold failures (`exit_code = 1`), and non-conflation of
     `NOT_INSTALLED`, `UNSUPPORTED_BY_PARSER`, `BER_PERMISSIVE_ACCEPT`, `ASN1_PARSE_FAILED`,
     `PEM_DER_ASN1_MISMATCH`, and `REJECTED`.
  4. Real 22-vector fixed public DER/PEM fixture corpus evaluation in `strict` mode (9 positive +
     13 negative vectors, zero private keys).
"""

from __future__ import annotations

import copy
import unittest

from tests import cross_validate_x509 as cv


class TestCrossValidateX509V1051(unittest.TestCase):
    """[V1.0.5.1 / CROSS-VALIDATION] OpenSSL classification & strict/offline mode unit tests."""

    def test_01_openssl_classification_independent_commands_and_asn1_gating(self) -> None:
        ver = "OpenSSL 3.0.13 30 Jan 2024"
        ok_x509 = "X509v3 Subject Alternative Name:\n    DNS:www.insenai.com.tr\n"
        ok_asn1 = "    0:d=0  hl=4 l= 500 cons: SEQUENCE\n    4:d=1  hl=4 l= 400 cons: SEQUENCE\n"
        diff_asn1 = "    0:d=0  hl=4 l= 501 cons: SEQUENCE\n"

        # 1. Positive vector: x509 OK + PEM/DER asn1parse OK + exact match -> ACCEPTED
        res_ok = cv._classify_openssl_result(
            openssl_ver=ver,
            expected_der_verdict="ACCEPT",
            x509_rc=0,
            x509_stdout=ok_x509,
            x509_stderr="",
            pem_asn1_rc=0,
            pem_asn1_stdout=ok_asn1,
            pem_asn1_stderr="",
            der_asn1_rc=0,
            der_asn1_stdout=ok_asn1,
            der_asn1_stderr="",
        )
        self.assertEqual(res_ok["status"], "ACCEPTED")
        self.assertTrue(res_ok["pem_der_asn1_match"])
        self.assertFalse(res_ok["ber_permissive_not_der_proof"])
        self.assertEqual(res_ok["asn1_verification"]["status"], "VERIFIED")
        self.assertEqual(res_ok["commands"]["x509_text"]["exit_code"], 0)
        self.assertEqual(res_ok["commands"]["x509_text"]["parser_version"], ver)
        self.assertEqual(res_ok["commands"]["asn1parse_pem"]["exit_code"], 0)
        self.assertEqual(res_ok["commands"]["asn1parse_der"]["exit_code"], 0)
        self.assertIn("DNS:www.insenai.com.tr", res_ok["commands"]["x509_text"]["stdout_summary"])

        # 2. Positive vector: x509 OK BUT PEM asn1parse fails -> ASN1_PARSE_FAILED (NEVER ACCEPTED!)
        res_pem_fail = cv._classify_openssl_result(
            openssl_ver=ver,
            expected_der_verdict="ACCEPT",
            x509_rc=0,
            x509_stdout=ok_x509,
            x509_stderr="",
            pem_asn1_rc=1,
            pem_asn1_stdout="",
            pem_asn1_stderr="Error reading PEM",
            der_asn1_rc=0,
            der_asn1_stdout=ok_asn1,
            der_asn1_stderr="",
        )
        self.assertEqual(res_pem_fail["status"], "ASN1_PARSE_FAILED")
        self.assertFalse(res_pem_fail["pem_der_asn1_match"])
        self.assertEqual(res_pem_fail["asn1_verification"]["status"], "ASN1_PARSE_FAILED")
        self.assertEqual(res_pem_fail["commands"]["asn1parse_pem"]["status"], "FAILED")
        self.assertEqual(res_pem_fail["commands"]["asn1parse_pem"]["exit_code"], 1)
        self.assertIn("Error reading PEM", res_pem_fail["commands"]["asn1parse_pem"]["stderr_summary"])

        # 3. Positive vector: x509 OK BUT DER asn1parse fails -> ASN1_PARSE_FAILED (NEVER ACCEPTED!)
        res_der_fail = cv._classify_openssl_result(
            openssl_ver=ver,
            expected_der_verdict="ACCEPT",
            x509_rc=0,
            x509_stdout=ok_x509,
            x509_stderr="",
            pem_asn1_rc=0,
            pem_asn1_stdout=ok_asn1,
            pem_asn1_stderr="",
            der_asn1_rc=1,
            der_asn1_stdout="",
            der_asn1_stderr="DER parse error",
        )
        self.assertEqual(res_der_fail["status"], "ASN1_PARSE_FAILED")
        self.assertEqual(res_der_fail["commands"]["asn1parse_der"]["status"], "FAILED")

        # 4. Positive vector: x509 OK + both asn1parse rc=0 BUT outputs diverge -> PEM_DER_ASN1_MISMATCH!
        res_mismatch = cv._classify_openssl_result(
            openssl_ver=ver,
            expected_der_verdict="ACCEPT",
            x509_rc=0,
            x509_stdout=ok_x509,
            x509_stderr="",
            pem_asn1_rc=0,
            pem_asn1_stdout=ok_asn1,
            pem_asn1_stderr="",
            der_asn1_rc=0,
            der_asn1_stdout=diff_asn1,
            der_asn1_stderr="",
        )
        self.assertEqual(res_mismatch["status"], "PEM_DER_ASN1_MISMATCH")
        self.assertFalse(res_mismatch["pem_der_asn1_match"])
        self.assertEqual(res_mismatch["asn1_verification"]["status"], "PEM_DER_ASN1_MISMATCH")

        # 5. Positive vector: unsupported GeneralName (<unsupported>) with valid vs failed ASN.1 parse
        unsup_x509 = "X509v3 Subject Alternative Name:\n    X400Name:<unsupported>\n"
        res_unsup = cv._classify_openssl_result(
            openssl_ver=ver,
            expected_der_verdict="ACCEPT",
            x509_rc=0,
            x509_stdout=unsup_x509,
            x509_stderr="",
            pem_asn1_rc=0,
            pem_asn1_stdout=ok_asn1,
            pem_asn1_stderr="",
            der_asn1_rc=0,
            der_asn1_stdout=ok_asn1,
            der_asn1_stderr="",
        )
        self.assertEqual(res_unsup["status"], "UNSUPPORTED_BY_PARSER")
        res_unsup_bad_asn1 = cv._classify_openssl_result(
            openssl_ver=ver,
            expected_der_verdict="ACCEPT",
            x509_rc=0,
            x509_stdout=unsup_x509,
            x509_stderr="",
            pem_asn1_rc=1,
            pem_asn1_stdout="",
            pem_asn1_stderr="ASN1 err",
            der_asn1_rc=0,
            der_asn1_stdout=ok_asn1,
            der_asn1_stderr="",
        )
        self.assertEqual(res_unsup_bad_asn1["status"], "ASN1_PARSE_FAILED")

        # 6. Negative vector: BER-permissive OpenSSL parse -> BER_PERMISSIVE_ACCEPT (NEVER DER proof!)
        ber_x509 = "X509v3 Subject Alternative Name:\n    othername: UPN::abc\n"
        res_ber = cv._classify_openssl_result(
            openssl_ver=ver,
            expected_der_verdict="REJECT",
            x509_rc=0,
            x509_stdout=ber_x509,
            x509_stderr="",
            pem_asn1_rc=0,
            pem_asn1_stdout=ok_asn1,
            pem_asn1_stderr="",
            der_asn1_rc=0,
            der_asn1_stdout=ok_asn1,
            der_asn1_stderr="",
        )
        self.assertEqual(res_ber["status"], "BER_PERMISSIVE_ACCEPT")
        self.assertTrue(res_ber["ber_permissive_not_der_proof"])
        self.assertEqual(res_ber["commands"]["x509_text"]["status"], "BER_PERMISSIVE_ACCEPT")

        # 7. Negative vector: OpenSSL raw hex fallback ("0...raw") or non-zero rc -> real REJECTED
        raw_x509 = "X509v3 Subject Alternative Name:\n    0...raw\n"
        res_rej = cv._classify_openssl_result(
            openssl_ver=ver,
            expected_der_verdict="REJECT",
            x509_rc=0,
            x509_stdout=raw_x509,
            x509_stderr="",
            pem_asn1_rc=0,
            pem_asn1_stdout=ok_asn1,
            pem_asn1_stderr="",
            der_asn1_rc=0,
            der_asn1_stdout=ok_asn1,
            der_asn1_stderr="",
        )
        self.assertEqual(res_rej["status"], "REJECTED")
        self.assertFalse(res_rej["ber_permissive_not_der_proof"])

    def test_02_offline_mode_runs_hrai_only_and_marks_not_performed(self) -> None:
        report = cv.run_cross_validation(mode="offline")
        self.assertEqual(report["mode"], "offline")
        self.assertEqual(report["independent_cross_validation"], "NOT_PERFORMED")
        self.assertEqual(report["independent_cross_validation_tag"], "INDEPENDENT_CROSS_VALIDATION=NOT_PERFORMED")
        self.assertEqual(report["ci_audit"]["exit_code"], 0)
        self.assertEqual(report["ci_audit"]["failure_reasons"], [])
        self.assertEqual(report["summary"]["total_vectors"], 22)
        self.assertEqual(report["summary"]["positive_vectors"], 9)
        self.assertEqual(report["summary"]["negative_vectors"], 13)
        self.assertTrue(report["summary"]["authoritative_hrai_strict_der_all_matched"])

        counts = report["summary"]["per_parser_counts"]
        self.assertEqual(counts["hrai"]["positive_accepted"], 9)
        self.assertEqual(counts["hrai"]["negative_rejected"], 13)
        self.assertEqual(counts["hrai"]["negative_ber_permissive_accepted"], 0)
        for ext_key in ("openssl", "pyasn1_rfc5280", "cryptography"):
            self.assertEqual(counts[ext_key]["not_performed_offline"], 22, ext_key)
            self.assertEqual(counts[ext_key]["not_installed"], 0, ext_key)
            self.assertEqual(counts[ext_key]["negative_rejected"], 0, ext_key)

    def test_03_strict_mode_policy_missing_parsers_thresholds_and_status_separation(self) -> None:
        # Build synthetic 4-vector set (2 positive + 2 negative) to test every strict policy branch deterministically
        base_rows = [
            {
                "vector_id": "p1",
                "expected_der_verdict": "ACCEPT",
                "parsers": {
                    "openssl": {"status": "ACCEPTED"},
                    "pyasn1_rfc5280": {"status": "ACCEPTED"},
                    "cryptography": {"status": "ACCEPTED"},
                    "hrai": {"status": "ACCEPTED", "matches_expected_der": True},
                },
                "authoritative_der_canonicality_decision": {"strict_external_confirmations": ["openssl", "pyasn1_rfc5280", "cryptography"]},
            },
            {
                "vector_id": "p2_x400",
                "expected_der_verdict": "ACCEPT",
                "parsers": {
                    "openssl": {"status": "UNSUPPORTED_BY_PARSER"},
                    "pyasn1_rfc5280": {"status": "ACCEPTED"},
                    "cryptography": {"status": "UNSUPPORTED_BY_PARSER"},
                    "hrai": {"status": "ACCEPTED", "matches_expected_der": True},
                },
                "authoritative_der_canonicality_decision": {"strict_external_confirmations": ["pyasn1_rfc5280"]},
            },
            {
                "vector_id": "n1",
                "expected_der_verdict": "REJECT",
                "parsers": {
                    "openssl": {"status": "REJECTED"},
                    "pyasn1_rfc5280": {"status": "REJECTED"},
                    "cryptography": {"status": "REJECTED"},
                    "hrai": {"status": "REJECTED", "matches_expected_der": True},
                },
                "authoritative_der_canonicality_decision": {"strict_external_confirmations": ["openssl", "pyasn1_rfc5280", "cryptography"]},
            },
            {
                "vector_id": "n2_ber",
                "expected_der_verdict": "REJECT",
                "parsers": {
                    "openssl": {"status": "BER_PERMISSIVE_ACCEPT"},
                    "pyasn1_rfc5280": {"status": "BER_PERMISSIVE_ACCEPT"},
                    "cryptography": {"status": "REJECTED"},
                    "hrai": {"status": "REJECTED", "matches_expected_der": True},
                },
                "authoritative_der_canonicality_decision": {"strict_external_confirmations": ["cryptography"]},
            },
        ]
        all_versions = {
            "openssl": "OpenSSL 3.0.13",
            "pyasn1_rfc5280": "pyasn1=0.4.8, pyasn1_modules=0.2.8",
            "cryptography": "50.0.2",
            "hrai": "1.0.5.1",
        }
        counts = {k: cv._summarize_parser(base_rows, k) for k in all_versions}

        # 1. All parsers present & thresholds met -> exit_code 0, PASSED; UNSUPPORTED & BER_PERMISSIVE counted separately
        ci_ok = cv._evaluate_run_policy(
            mode="strict",
            rows=base_rows,
            parser_versions=all_versions,
            per_parser_counts=counts,
        )
        self.assertEqual(ci_ok["exit_code"], 0)
        self.assertEqual(ci_ok["independent_cross_validation"], "PASSED")
        self.assertEqual(counts["openssl"]["positive_unsupported"], 1)
        self.assertEqual(counts["openssl"]["negative_ber_permissive_accepted"], 1)
        self.assertEqual(counts["openssl"]["negative_rejected"], 1)

        # 2. Missing parser (NOT_INSTALLED) in strict mode -> exit_code 2, FAILED_MISSING_PARSERS
        missing_versions = dict(all_versions, cryptography="NOT_INSTALLED")
        rows_missing = copy.deepcopy(base_rows)
        for r in rows_missing:
            r["parsers"]["cryptography"] = {"status": "NOT_INSTALLED"}
        counts_missing = {k: cv._summarize_parser(rows_missing, k) for k in missing_versions}
        self.assertEqual(counts_missing["cryptography"]["not_installed"], 4)
        self.assertEqual(counts_missing["cryptography"]["negative_rejected"], 0)
        ci_missing = cv._evaluate_run_policy(
            mode="strict",
            rows=rows_missing,
            parser_versions=missing_versions,
            per_parser_counts=counts_missing,
        )
        self.assertEqual(ci_missing["exit_code"], 2)
        self.assertEqual(ci_missing["independent_cross_validation"], "FAILED_MISSING_PARSERS")
        self.assertEqual(ci_missing["missing_parsers"], ["cryptography"])

        # 3. Positive vector ASN.1 parse failure (x509 OK, asn1parse failed) -> strict mode fails (exit_code 1)!
        rows_asn1_fail = copy.deepcopy(base_rows)
        rows_asn1_fail[0]["parsers"]["openssl"] = {"status": "ASN1_PARSE_FAILED"}
        counts_asn1_fail = {k: cv._summarize_parser(rows_asn1_fail, k) for k in all_versions}
        self.assertEqual(counts_asn1_fail["openssl"]["positive_asn1_failed"], 1)
        self.assertEqual(counts_asn1_fail["openssl"]["positive_accepted"], 0)
        ci_asn1_fail = cv._evaluate_run_policy(
            mode="strict",
            rows=rows_asn1_fail,
            parser_versions=all_versions,
            per_parser_counts=counts_asn1_fail,
        )
        self.assertEqual(ci_asn1_fail["exit_code"], 1)
        self.assertEqual(ci_asn1_fail["independent_cross_validation"], "FAILED_THRESHOLD")

        # 4. External negative confirmation below threshold -> exit_code 1, FAILED_THRESHOLD
        rows_low_neg = copy.deepcopy(base_rows)
        rows_low_neg[3]["parsers"]["cryptography"] = {"status": "UNSUPPORTED_BY_PARSER"}
        rows_low_neg[3]["authoritative_der_canonicality_decision"]["strict_external_confirmations"] = []
        counts_low_neg = {k: cv._summarize_parser(rows_low_neg, k) for k in all_versions}
        ci_low_neg = cv._evaluate_run_policy(
            mode="strict",
            rows=rows_low_neg,
            parser_versions=all_versions,
            per_parser_counts=counts_low_neg,
        )
        self.assertEqual(ci_low_neg["exit_code"], 1)
        self.assertEqual(ci_low_neg["independent_cross_validation"], "FAILED_THRESHOLD")
        self.assertFalse(ci_low_neg["verification_thresholds"]["external_negative_strict_confirmed"]["passed"])

    def test_04_strict_mode_real_22_vector_fixture_corpus_positive_and_negative(self) -> None:
        report = cv.run_cross_validation(mode="strict")
        self.assertEqual(report["mode"], "strict")
        self.assertEqual(report["summary"]["total_vectors"], 22)
        self.assertEqual(report["summary"]["positive_vectors"], 9)
        self.assertEqual(report["summary"]["negative_vectors"], 13)
        self.assertTrue(report["summary"]["authoritative_hrai_strict_der_all_matched"])
        self.assertTrue(report["fixture_integrity"]["manifest_verified"])
        self.assertFalse(report["fixture_integrity"]["private_keys_stored"])

        ci = report["ci_audit"]
        self.assertIn("parser_versions", ci)
        self.assertIn("missing_parsers", ci)
        self.assertIn("verification_thresholds", ci)

        # Every positive vector evaluated by OpenSSL carries independent command + asn1_verification blocks
        if ci["missing_parsers"] == []:
            self.assertEqual(ci["exit_code"], 0)
            self.assertEqual(ci["independent_cross_validation"], "PASSED")
            self.assertEqual(ci["independent_cross_validation_tag"], "INDEPENDENT_CROSS_VALIDATION=PASSED")
            ossl_counts = report["summary"]["per_parser_counts"]["openssl"]
            self.assertEqual(ossl_counts["positive_accepted"], 7)
            self.assertEqual(ossl_counts["positive_unsupported"], 2)
            self.assertEqual(ossl_counts["positive_asn1_failed"], 0)
            self.assertEqual(ossl_counts["positive_pem_der_mismatch"], 0)
            self.assertEqual(ossl_counts["negative_rejected"], 9)
            self.assertEqual(ossl_counts["negative_ber_permissive_accepted"], 2)
            self.assertEqual(ossl_counts["negative_unsupported"], 2)
            for row in report["vectors"]:
                ossl = row["parsers"]["openssl"]
                self.assertIn("asn1_verification", ossl)
                self.assertIn("commands", ossl)
                for cmd_key in ("x509_text", "asn1parse_pem", "asn1parse_der"):
                    cmd = ossl["commands"][cmd_key]
                    self.assertIn("exit_code", cmd)
                    self.assertIn("stdout_summary", cmd)
                    self.assertIn("stderr_summary", cmd)
                    self.assertIn("parser_version", cmd)
        else:
            # Fail-closed contract if optional external parsers are absent in a minimal sandbox
            self.assertEqual(ci["exit_code"], 2)
            self.assertEqual(ci["independent_cross_validation"], "FAILED_MISSING_PARSERS")


if __name__ == "__main__":
    unittest.main()
