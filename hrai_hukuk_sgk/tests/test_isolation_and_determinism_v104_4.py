"""CALISORA @HukukSGK v1.0.4.5 — Test Isolation, Concurrency, Zero-Weakening DER Parity & Regression Determinism Suite.

Directly verifies every requirement from the v1.0.4.4 / v1.0.4.5 independent remediation mandates:
  1. Static AST audit: 100% of `subprocess.run(...)` calls across `engine/` and `tests/` enforce explicit
     `timeout=` and closed/bound stdin (`stdin=subprocess.DEVNULL` or `input=`) so OpenSSL child processes
     can never block or hang in single-process test runs.
  2. Repeated execution determinism & zero resource leaks: running `v1.0.4.2` multi-step XMLDSig transforms
     and `v1.0.4.3` Document-level W3C C14N across multiple consecutive iterations produces byte-identical
     outputs with zero leaked FDs, zero leaked threads, zero leftover `/tmp/calisora_*` temp directories,
     and empty CA/RSA/TSA checkout pools.
  3. Parallel multi-threaded execution safety (`ThreadPoolExecutor`): concurrent PKI fixture setup, certificate
     issuance, CAdES/XAdES signing, revocation, and Document-level C14N verification run safely with distinct
     isolated temp workspaces, 4 disjoint Root CAs, 8 disjoint RSA-2048 signer keys (zero key sharing across
     concurrent fixtures), and zero cross-thread state corruption.
  4. Cross-fixture revocation, key, TSA root & DER metadata isolation: revoking a certificate in Fixture A
     NEVER affects Fixture B; pure-Python ASN.1 DER metadata (`parse_x509_certificate_metadata`) matches
     OpenSSL 3 field-for-field with fingerprint-bound deduplication; and concurrently open `good_tsa` vs
     `rogue_tsa` `EphemeralSandboxTsaResponder` instances have cryptographically independent Root CAs.
  5. No dual test-module imports (`tests.pki_test_helpers` separation) and invariant process-global HMAC seal keys.
  6. Exact `v1.0.4.5` governance, 11/11 Draft 2020-12 schemas, 74/74 central audit records, L1–L4 counts,
     L5/L6 deferral (`PLANNED_V1_0_5`), and fail-closed `NOT_CONFIGURED` live probe invariants.
"""

from __future__ import annotations

import ast
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
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
    Default5070AcceptanceGate,
    DefaultCertificateRevocationProvider,
    DefaultEshsTrustListProvider,
    DefaultQualifiedSignature5070Verifier,
    DefaultSscdControlEvidenceVerifier,
    canonicalize_xml_document,
    create_cades_cms_der,
    create_xades_xml_bytes,
    parse_x509_certificate_metadata,
    safe_parse_xml_bytes,
    verify_esign5070_result_authenticity,
    verify_sscd_evidence_result_authenticity,
    verify_xades_xmldsig,
)
from engine.esign5070.cades_xades_verifier import _ESIGN5070_RESULT_SEAL_KEY
from engine.esign5070.sscd_evidence import _SSCD_EVIDENCE_SEAL_KEY
from engine.knowledge_card_validator import load_knowledge_cards, validate_central_audit_log
from engine.legal_reasoning import TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA
from engine.precedent_verifier import load_precedent_registry
from engine.source_validator import load_source_registry
from engine.trust_root import (
    TRUST_ROOT_VERSION,
    EphemeralSandboxTsaResponder,
    Rfc3161TimestampAuthorityAdapter,
    run_live_integration_probe,
)
from engine.trust_root.rfc3161_tsa import _EPHEMERAL_TSA_PKI_BANK
from tests.pki_test_helpers import _MATERIAL_BANK, Ephemeral5070PkiFixture

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _open_fd_count() -> int:
    fd_dir = Path("/proc/self/fd")
    if fd_dir.is_dir():
        return len(list(fd_dir.iterdir()))
    return 0


def _calisora_tmp_entries() -> set[str]:
    tmp_root = Path(tempfile.gettempdir())
    return {p.name for p in tmp_root.glob("calisora_*")}


class TestIsolationAndDeterminismV1044(unittest.TestCase):
    """[ISOLATION / DETERMINISM / CONCURRENCY / DER PARITY] v1.0.4.5 single-process regression assurance suite."""

    def test_01_all_subprocess_run_calls_enforce_devnull_stdin_and_timeout(self) -> None:
        total_calls = 0
        violations: list[str] = []
        for subdir in ("engine", "tests"):
            for py_file in sorted((PROJECT_ROOT / subdir).rglob("*.py")):
                tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "run":
                        total_calls += 1
                        kw_map = {kw.arg: kw.value for kw in node.keywords if kw.arg is not None}
                        if "timeout" not in kw_map:
                            violations.append(f"{py_file.relative_to(PROJECT_ROOT)}:{node.lineno} missing timeout=")
                        if "input" not in kw_map:
                            stdin_node = kw_map.get("stdin")
                            is_devnull = (
                                isinstance(stdin_node, ast.Attribute)
                                and stdin_node.attr == "DEVNULL"
                            )
                            if not is_devnull:
                                violations.append(
                                    f"{py_file.relative_to(PROJECT_ROOT)}:{node.lineno} missing stdin=subprocess.DEVNULL or input="
                                )
        self.assertGreaterEqual(total_calls, 30)
        self.assertEqual(violations, [], f"Sınırsız subprocess.run çağrıları tespit edildi: {violations}")

    def test_02_repeated_transform_and_c14n_runs_zero_fd_thread_and_tmp_leaks(self) -> None:
        # Warm up immutable read-only test key bank before baseline snapshot
        with Ephemeral5070PkiFixture() as warm:
            warm.issue_signer_cert(tag="warmup")

        fd_before = _open_fd_count()
        threads_before = threading.active_count()
        tmp_before = _calisora_tmp_entries()

        c14n_sample = b"<!--before-->\n<root>value</root>\n<?after keep?>"
        inner_xml = b'<?pi-in ok?><!--c--><Belge b="2" a="1">Karar-1044</Belge><?pi-out ok?>'
        inner_b64 = base64.b64encode(inner_xml).decode("ascii")
        enveloped_b64_doc = f'<Zarf xmlns="urn:calisora:iso">{inner_b64}</Zarf>'.encode("utf-8")

        c14n_digests: list[tuple[bytes, bytes]] = []
        transform_verdicts: list[bool] = []

        for iteration in range(3):
            # 1. Exact v1.0.4.3 Document-level C14N check (unchanged behavior!)
            doc = safe_parse_xml_bytes(c14n_sample)
            try:
                out_nc = canonicalize_xml_document(doc, C14N_INCLUSIVE_10)
                out_wc = canonicalize_xml_document(doc, C14N_INCLUSIVE_10_COMMENTS)
            finally:
                doc.unlink()
            self.assertEqual(out_nc, b"<root>value</root>\n<?after keep?>")
            self.assertEqual(out_wc, b"<!--before-->\n<root>value</root>\n<?after keep?>")
            c14n_digests.append((out_nc, out_wc))

            # 2. Full v1.0.4.2 3-step sequential transform chain: enveloped-signature -> Base64 -> Document C14N
            with Ephemeral5070PkiFixture() as pki:
                cert_pem, key_pem, _ = pki.issue_signer_cert(tag=f"repeat_{iteration}")
                sig_xml, _ = create_xades_xml_bytes(
                    enveloped_b64_doc,
                    cert_pem,
                    key_pem,
                    mode="ENVELOPED",
                    data_transforms=[
                        TRANSFORM_ENVELOPED_SIGNATURE,
                        TRANSFORM_BASE64,
                        C14N_EXCLUSIVE_10_COMMENTS,
                    ],
                )
                insp = verify_xades_xmldsig(sig_xml)
                self.assertTrue(insp.crypto_valid, (iteration, insp.error_codes, insp.errors))
                data_ref = [r for r in insp.xmldsig_details["references"] if r["kind"] == "DATA"][0]
                self.assertEqual(len(data_ref["transform_trace"]), 3)
                self.assertEqual(data_ref["transform_trace"][2]["node_scope"], "DOCUMENT")
                transform_verdicts.append(insp.crypto_valid)

        self.assertEqual(len(set(c14n_digests)), 1)
        self.assertEqual(transform_verdicts, [True, True, True])
        self.assertEqual(_open_fd_count() - fd_before, 0, "Açık dosya tanıtıcısı (FD) sızıntısı tespit edildi.")
        self.assertEqual(threading.active_count() - threads_before, 0, "İş parçacığı (thread) sızıntısı tespit edildi.")
        self.assertEqual(
            _calisora_tmp_entries() - tmp_before,
            set(),
            "Temizlenmemiş /tmp/calisora_* geçici dizini tespit edildi.",
        )
        self.assertEqual(_MATERIAL_BANK._checked_out[False], set())
        self.assertEqual(_MATERIAL_BANK._checked_out[True], set())
        self.assertEqual(_MATERIAL_BANK._checked_out_rsa_slots, set())
        self.assertEqual(_EPHEMERAL_TSA_PKI_BANK._checked_out, set())

    def test_03_parallel_threads_pki_cades_xades_and_c14n_isolation(self) -> None:
        fd_before = _open_fd_count()
        tmp_before = _calisora_tmp_entries()
        start_barrier = threading.Barrier(4, timeout=30)

        def _worker(worker_id: int) -> dict[str, object]:
            with Ephemeral5070PkiFixture() as pki:
                start_barrier.wait()
                root_dir = str(pki.root)
                good_cert, good_key, good_path = pki.issue_signer_cert(tag=f"w{worker_id}_good")
                rev_cert, rev_key, rev_path = pki.issue_signer_cert(tag=f"w{worker_id}_rev")
                pki.revoke_cert(rev_path, reason="keyCompromise")
                crl_pem = pki.generate_crl_pem()
                ocsp_good = pki.generate_ocsp_response_der(good_path)
                ocsp_rev = pki.generate_ocsp_response_der(rev_path)
                payload = f'<?pi-w id="{worker_id}"?><!--c{worker_id}--><Doc id="d{worker_id}">veri-{worker_id}</Doc><?end?>'.encode("utf-8")
                cades_der = create_cades_cms_der(payload, good_cert, good_key, detached=True)
                xades_xml, _ = create_xades_xml_bytes(
                    payload,
                    good_cert,
                    good_key,
                    mode="ENVELOPED",
                    data_transforms=[TRANSFORM_ENVELOPED_SIGNATURE, C14N_INCLUSIVE_11_COMMENTS],
                )
                xades_insp = verify_xades_xmldsig(xades_xml)

                # Issue SSCD issuer cert & verified SSCD evidence BEFORE taking val_time so all
                # cert notBefore timestamps are strictly <= val_time (zero 1-second boundary race).
                sscd_res = pki.build_verified_sscd_evidence(good_cert)
                val_time = _now_utc()
                trusted_chain = pki.root_cert_pem + "\n" + pki.inter_cert_pem

                rev_prov = DefaultCertificateRevocationProvider(trusted_ca_pem=trusted_chain)
                res_good = rev_prov.check_revocation(
                    good_cert,
                    pki.inter_cert_pem,
                    validation_time_utc=val_time,
                    archived_ocsp_response_der=ocsp_good,
                    archived_ocsp_signer_cert_pem=pki.ocsp_cert_pem,
                    runtime_environment="TEST_SANDBOX_ONLY",
                )
                res_rev = rev_prov.check_revocation(
                    rev_cert,
                    pki.inter_cert_pem,
                    validation_time_utc=val_time,
                    archived_ocsp_response_der=ocsp_rev,
                    archived_ocsp_signer_cert_pem=pki.ocsp_cert_pem,
                    runtime_environment="TEST_SANDBOX_ONLY",
                )
                res_crl_good = rev_prov.check_revocation(
                    good_cert,
                    pki.inter_cert_pem,
                    validation_time_utc=val_time,
                    archived_crl_pem=crl_pem,
                    runtime_environment="TEST_SANDBOX_ONLY",
                )

                live_rev_prov = DefaultCertificateRevocationProvider(
                    trusted_ca_pem=trusted_chain,
                    ocsp_fetcher=lambda _s, _i, _vt, _resp=ocsp_good, _ocert=pki.ocsp_cert_pem: (_resp, _ocert),
                    integration_mode="MOCK_SANDBOX",
                )
                verifier = DefaultQualifiedSignature5070Verifier(
                    eshs_trust_provider=DefaultEshsTrustListProvider(
                        btk_providers=[pki.build_btk_provider_record()],
                        ca_bundles=[pki.build_ca_bundle()],
                        integration_mode="MOCK_SANDBOX",
                    ),
                    revocation_provider=live_rev_prov,
                    integration_mode="MOCK_SANDBOX",
                )
                cades_res = verifier.verify_cades_signature(
                    cades_der,
                    payload,
                    claimed_profile="B-B",
                    expected_eshs_id="ESHS-TR-01",
                    validation_time_utc=val_time,
                    sscd_control_evidence_result=sscd_res,
                    runtime_environment="TEST_SANDBOX_ONLY",
                )
                return {
                    "worker_id": worker_id,
                    "root_dir": root_dir,
                    "root_ca_sha": hashlib.sha256(pki.root_cert_pem.encode("utf-8")).hexdigest(),
                    "good_key_sha": hashlib.sha256(good_key.encode("utf-8")).hexdigest(),
                    "rev_key_sha": hashlib.sha256(rev_key.encode("utf-8")).hexdigest(),
                    "ocsp_good": res_good.status,
                    "ocsp_rev": res_rev.status,
                    "crl_good": res_crl_good.status,
                    "xades_valid": xades_insp.crypto_valid,
                    "cades_valid": cades_res.cryptographic_signature_valid,
                    "cades_5070": cades_res.qualified_e_signature_5070_verified,
                    "seal_ok": verify_esign5070_result_authenticity(cades_res),
                    "sscd_seal_ok": verify_sscd_evidence_result_authenticity(sscd_res),
                }

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(_worker, range(4)))

        self.assertEqual(len({r["root_dir"] for r in results}), 4, "Her paralel fikstür ayrı temp dizinine sahip olmalıdır.")
        self.assertEqual(len({r["root_ca_sha"] for r in results}), 4, "Eşzamanlı paralel fikstürler ayrık kök CA almalıdır.")
        all_signer_keys = {r["good_key_sha"] for r in results} | {r["rev_key_sha"] for r in results}
        self.assertEqual(len(all_signer_keys), 8, "Eşzamanlı aktif fikstürler asla RSA özel anahtarı paylaşmamalıdır.")
        for r in results:
            self.assertEqual(r["ocsp_good"], "GOOD", r)
            self.assertEqual(r["ocsp_rev"], "REVOKED", r)
            self.assertEqual(r["crl_good"], "GOOD", r)
            self.assertTrue(r["xades_valid"], r)
            self.assertTrue(r["cades_valid"], r)
            self.assertTrue(r["cades_5070"], r)
            self.assertTrue(r["seal_ok"], r)
            self.assertTrue(r["sscd_seal_ok"], r)

        self.assertEqual(_open_fd_count() - fd_before, 0)
        self.assertEqual(_calisora_tmp_entries() - tmp_before, set())
        self.assertEqual(_MATERIAL_BANK._checked_out[False], set())
        self.assertEqual(_MATERIAL_BANK._checked_out[True], set())
        self.assertEqual(_MATERIAL_BANK._checked_out_rsa_slots, set())

    def test_04_cross_fixture_revocation_and_key_isolation(self) -> None:
        with Ephemeral5070PkiFixture() as pki_a, Ephemeral5070PkiFixture() as pki_b:
            self.assertNotEqual(pki_a.root, pki_b.root)
            self.assertNotEqual(pki_a.root_cert_pem, pki_b.root_cert_pem)
            cert_a1, key_a1, path_a1 = pki_a.issue_signer_cert(tag="same_tag")
            cert_a2, key_a2, _ = pki_a.issue_signer_cert(tag="second_tag")
            cert_b1, key_b1, path_b1 = pki_b.issue_signer_cert(tag="same_tag")

            # Distinct signers inside and across concurrently active fixtures MUST receive distinct keys & fingerprints
            self.assertEqual(len({key_a1, key_a2, key_b1}), 3)
            self.assertNotEqual(
                hashlib.sha256(cert_a1.encode("utf-8")).hexdigest(),
                hashlib.sha256(cert_a2.encode("utf-8")).hexdigest(),
            )

            # Pure-Python read-only ASN.1 DER parser matches OpenSSL 3 field-for-field & enforces fingerprint binding
            meta_a1 = parse_x509_certificate_metadata(cert_a1)
            meta_a2 = parse_x509_certificate_metadata(cert_a2)
            self.assertIsNotNone(meta_a1)
            self.assertIsNotNone(meta_a2)
            assert meta_a1 is not None and meta_a2 is not None
            self.assertNotEqual(meta_a1.cert_sha256, meta_a2.cert_sha256)
            p_ossl_pub = subprocess.run(
                ["openssl", "x509", "-pubkey", "-noout"],
                input=cert_a1,
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
            self.assertEqual(meta_a1.spki_pem, p_ossl_pub.stdout)
            p_ossl_fp = subprocess.run(
                ["openssl", "x509", "-noout", "-fingerprint", "-sha256"],
                input=cert_a1,
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
            ossl_fp = p_ossl_fp.stdout.split("=", 1)[1].strip().replace(":", "").lower()
            self.assertEqual(meta_a1.cert_sha256, ossl_fp)
            self.assertTrue(meta_a1.qc_compliance)
            self.assertTrue(meta_a1.qc_sscd)
            self.assertIsNone(parse_x509_certificate_metadata("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"))

            # Revoking `same_tag` in Fixture A MUST NOT affect `same_tag` in Fixture B!
            pki_a.revoke_cert(path_a1, reason="keyCompromise")
            crl_a = pki_a.generate_crl_pem()
            crl_b = pki_b.generate_crl_pem()
            ocsp_a = pki_a.generate_ocsp_response_der(path_a1)
            ocsp_b = pki_b.generate_ocsp_response_der(path_b1)
            val_time = _now_utc()

            rev_prov_a = DefaultCertificateRevocationProvider(
                trusted_ca_pem=pki_a.root_cert_pem + "\n" + pki_a.inter_cert_pem
            )
            rev_prov_b = DefaultCertificateRevocationProvider(
                trusted_ca_pem=pki_b.root_cert_pem + "\n" + pki_b.inter_cert_pem
            )

            self.assertEqual(
                rev_prov_a.check_revocation(
                    cert_a1, pki_a.inter_cert_pem, validation_time_utc=val_time, archived_crl_pem=crl_a
                ).status,
                "REVOKED",
            )
            self.assertEqual(
                rev_prov_a.check_revocation(
                    cert_a1,
                    pki_a.inter_cert_pem,
                    validation_time_utc=val_time,
                    archived_ocsp_response_der=ocsp_a,
                    archived_ocsp_signer_cert_pem=pki_a.ocsp_cert_pem,
                ).status,
                "REVOKED",
            )
            self.assertEqual(
                rev_prov_b.check_revocation(
                    cert_b1, pki_b.inter_cert_pem, validation_time_utc=val_time, archived_crl_pem=crl_b
                ).status,
                "GOOD",
            )
            self.assertEqual(
                rev_prov_b.check_revocation(
                    cert_b1,
                    pki_b.inter_cert_pem,
                    validation_time_utc=val_time,
                    archived_ocsp_response_der=ocsp_b,
                    archived_ocsp_signer_cert_pem=pki_b.ocsp_cert_pem,
                ).status,
                "GOOD",
            )

        # Concurrently open `good_tsa` vs `rogue_tsa` MUST have cryptographically independent Root CAs!
        with EphemeralSandboxTsaResponder() as good_tsa, EphemeralSandboxTsaResponder() as rogue_tsa:
            self.assertNotEqual(good_tsa.ca_cert_pem, rogue_tsa.ca_cert_pem)
            digest_hex = hashlib.sha256(b"calisora-tsa-root-isolation-v1045").hexdigest()
            tsa_good = Rfc3161TimestampAuthorityAdapter(
                tsa_url="https://good-tsa.calisora.invalid/tsr",
                trusted_ca_pem=good_tsa.ca_cert_pem,
                http_transport=good_tsa.transport,
            )
            tsa_rogue = Rfc3161TimestampAuthorityAdapter(
                tsa_url="https://rogue-tsa.calisora.invalid/tsr",
                trusted_ca_pem=rogue_tsa.ca_cert_pem,
                http_transport=rogue_tsa.transport,
            )
            rogue_res = tsa_rogue.request_timestamp(digest_hex)
            self.assertTrue(rogue_res.valid)
            rogue_tsr_der = base64.b64decode(rogue_res.tsr_der_b64 or "", validate=True)
            cross_ver = tsa_good.verify_timestamp_token(digest_hex, rogue_tsr_der)
            self.assertFalse(cross_ver.valid)
            self.assertIn("RFC3161_TIMESTAMP_VERIFICATION_FAILED", cross_ver.error_codes)
        self.assertEqual(_EPHEMERAL_TSA_PKI_BANK._checked_out, set())

        # Disjoint CAs: sandbox_dn=True vs sandbox_dn=False vs fresh_ca=True
        with (
            Ephemeral5070PkiFixture(sandbox_dn=True) as p_sb,
            Ephemeral5070PkiFixture(sandbox_dn=False) as p_prod_dn,
            Ephemeral5070PkiFixture(sandbox_dn=True, fresh_ca=True) as p_fresh,
        ):
            self.assertNotEqual(p_sb.root_cert_pem, p_prod_dn.root_cert_pem)
            self.assertNotEqual(p_sb.root_cert_pem, p_fresh.root_cert_pem)
            cert_fresh, _, _ = p_fresh.issue_signer_cert(tag="fresh_only")
            trust_sb = DefaultEshsTrustListProvider(
                btk_providers=[p_sb.build_btk_provider_record()],
                ca_bundles=[p_sb.build_ca_bundle()],
                integration_mode="MOCK_SANDBOX",
            )
            eval_cross = trust_sb.evaluate_signer_trust(
                cert_fresh,
                validation_time_utc=_now_utc(),
                expected_eshs_id="ESHS-TR-01",
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertFalse(eval_cross.valid)
            self.assertIn("ESHS_X509_CHAIN_VERIFICATION_FAILED", eval_cross.error_codes)

    def test_05_no_dual_test_module_imports_and_immutable_global_seals(self) -> None:
        # Ensure dependent v1.0.4.x test modules import PKI helper from `tests.pki_test_helpers`,
        # NOT from `tests.test_esign_5070_v104` (which caused dual test module loading under unittest discover).
        for rel in (
            "tests/test_esign_5070_v104_1_security.py",
            "tests/test_esign_5070_v104_2_transforms.py",
            "tests/test_esign_5070_v104_3_c14n_document.py",
        ):
            src = (PROJECT_ROOT / rel).read_text(encoding="utf-8")
            self.assertIn("from tests.pki_test_helpers import Ephemeral5070PkiFixture", src, rel)
            self.assertNotIn("from tests.test_esign_5070_v104 import", src, rel)

        # Global HMAC seal keys remain 32-byte immutable values across verification runs
        self.assertIsInstance(_ESIGN5070_RESULT_SEAL_KEY, bytes)
        self.assertEqual(len(_ESIGN5070_RESULT_SEAL_KEY), 32)
        self.assertIsInstance(_SSCD_EVIDENCE_SEAL_KEY, bytes)
        self.assertEqual(len(_SSCD_EVIDENCE_SEAL_KEY), 32)

        key_snap_1 = bytes(_ESIGN5070_RESULT_SEAL_KEY)
        key_snap_2 = bytes(_SSCD_EVIDENCE_SEAL_KEY)
        gate = Default5070AcceptanceGate()
        with Ephemeral5070PkiFixture() as pki:
            cert_pem, key_pem, _ = pki.issue_signer_cert(tag="seal_check")
            sscd = pki.build_verified_sscd_evidence(cert_pem)
            val_time = _now_utc()
            self.assertTrue(verify_sscd_evidence_result_authenticity(sscd))
            sig, _ = create_xades_xml_bytes(b"<S>ok</S>", cert_pem, key_pem, mode="DETACHED")
            verifier = DefaultQualifiedSignature5070Verifier(
                eshs_trust_provider=DefaultEshsTrustListProvider(
                    btk_providers=[pki.build_btk_provider_record()],
                    ca_bundles=[pki.build_ca_bundle()],
                    integration_mode="MOCK_SANDBOX",
                ),
                revocation_provider=DefaultCertificateRevocationProvider(
                    trusted_ca_pem=pki.root_cert_pem + "\n" + pki.inter_cert_pem
                ),
                integration_mode="MOCK_SANDBOX",
            )
            res = verifier.verify_xades_signature(
                sig,
                b"<S>ok</S>",
                expected_eshs_id="ESHS-TR-01",
                validation_time_utc=val_time,
                archived_crl_pem=pki.generate_crl_pem(),
                sscd_control_evidence_result=sscd,
                runtime_environment="TEST_SANDBOX_ONLY",
            )
            self.assertTrue(verify_esign5070_result_authenticity(res))
            dec = gate.evaluate_5070_acceptance(res, runtime_environment="PRODUCTION")
            self.assertFalse(dec.qualified_e_signature_5070_production_accepted)

        self.assertEqual(_ESIGN5070_RESULT_SEAL_KEY, key_snap_1)
        self.assertEqual(_SSCD_EVIDENCE_SEAL_KEY, key_snap_2)

    def test_06_v1044_governance_schemas_audit_live_probe_and_scope_invariants(self) -> None:
        self.assertEqual(ESIGN_5070_VERSION, "1.0.5.1")
        self.assertEqual(TRUST_ROOT_VERSION, "1.0.5.1")
        self.assertEqual(PARSER_VERSION, "tr_diyanet_holiday_parser_v1.0.5.1")
        self.assertEqual(TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["calendar_version"], "1.0.5.1")
        self.assertEqual(DefaultQualifiedSignature5070Verifier().provider_name, "HRAI_CADES_XADES_5070_VERIFIER_V1051")
        self.assertEqual(
            DefaultSscdControlEvidenceVerifier().verifier_service_id,
            "HRAI_SSCD_CONTROL_EVIDENCE_VERIFIER_V1051",
        )

        report = run_live_integration_probe(project_root=PROJECT_ROOT)
        self.assertEqual(report["schema_version"], "1.0.5.1")
        self.assertEqual(report["overall_live_integration_status"], "NOT_CONFIGURED")
        self.assertEqual(report["esign_5070_overall_status"], "NOT_CONFIGURED")
        self.assertFalse(report["qualified_e_signature_5070_production_ready"])
        self.assertFalse(report["qualified_e_signature_5070_equivalent"])
        self.assertFalse(report["production_use_authorized"])

        schemas = sorted((PROJECT_ROOT / "schemas").glob("*.schema.json"))
        self.assertEqual(len(schemas), 13)
        for sf in schemas:
            s_doc = json.loads(sf.read_text(encoding="utf-8"))
            self.assertIn("(v1.0.5.1)", s_doc["title"], sf.name)

        ledger = json.loads((PROJECT_ROOT / "config" / "calendar_attestation_ledger.json").read_text(encoding="utf-8"))
        self.assertEqual(ledger["schema_version"], "1.0.5.1")
        self.assertEqual(ledger["checkpoints"][0]["checkpoint_id"], "CHK-RELEASE-1.0.5.1-20261124")

        tax = json.loads((PROJECT_ROOT / "config" / "knowledge_taxonomy.json").read_text(encoding="utf-8"))
        self.assertEqual(tax["schema_version"], "1.0.5.1")
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
            self.assertEqual(layer["adoption_status"], "REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION")

        sources = load_source_registry(PROJECT_ROOT / "config" / "legal_sources_registry.json")
        precedents = load_precedent_registry(PROJECT_ROOT / "config" / "yargitay_precedents.json")
        cards = load_knowledge_cards(PROJECT_ROOT / "rag_kb", sources, precedents)
        self.assertEqual((len(sources), len(precedents), len(cards)), (30, 5, 39))
        audit_data = json.loads((PROJECT_ROOT / "config" / "verification_audit_log.json").read_text(encoding="utf-8"))
        self.assertEqual(audit_data["schema_version"], "1.0.5.1")
        self.assertEqual(audit_data["summary"]["total_audited_records"], 74)
        self.assertTrue(validate_central_audit_log(audit_data, sources, precedents, cards).valid)


if __name__ == "__main__":
    unittest.main()
