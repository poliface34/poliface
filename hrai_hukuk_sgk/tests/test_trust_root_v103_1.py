"""CALISORA @HukukSGK v1.0.3.1 Hardened Production Authorization Gate & Real HTTPS/TLS Regression Tests.

Directly verifies the v1.0.3.1 acceptance criterion:
  "No application caller can self-grant verification authority."

Covers every security requirement from the v1.0.3 independent audit:
  1. Caller-supplied `legal_counsel_attestation_verified=True` & plain status cannot authorize production (`CALLER_SELF_ASSERTED_BOOLEAN_FORBIDDEN`).
  2. Hand-forged `*VerificationResult(valid=True, ...)` objects rejected (`FORGED_OR_UNAUTHENTICATED_VERIFICATION_RESULT`).
  3. Unsigned, tampered, revoked, expired, unauthorized-role, and unavailable-verifier legal attestations rejected.
  4. Valid legal counsel signature bound to a DIFFERENT calendar version / calendar SHA-256 / HukukSGK version rejected.
  5. Omitting source acquisition fails closed (`SOURCE_ACQUISITION_EVIDENCE_MISSING`); passing `source_acquisition_verified=True`,
     `technical_verification_passed=True`, or `kvkk_data_residency_approved=True` triggers `CALLER_SELF_ASSERTED_BOOLEAN_FORBIDDEN`.
  6. Fake / unverifiable / contradictory TLS certificate metadata rejected (`TLS_FAKE_OR_UNVERIFIABLE_METADATA`),
     and `MOCK_CALLBACK` fetcher rejected in `PRODUCTION` (`CALLBACK_FETCHER_NOT_ALLOWED_IN_PRODUCTION`).
  7. Real local TLS 1.2+/1.3 HTTPS server tests (`LiveHttpsSourceFetcher` over real sockets):
     - Valid trusted CA + matching SAN/hostname + valid period -> PASS (`fetcher_mode="LIVE_HTTPS"`, `production_tls_verified=True`,
       `tls_alone_proves_historical_content=False`)
     - Wrong hostname / SAN -> REJECTED (`TLS_HOSTNAME_OR_SAN_MISMATCH`)
     - Expired certificate -> REJECTED (`TLS_CERTIFICATE_EXPIRED_OR_NOT_YET_VALID`)
     - Untrusted CA -> REJECTED (`TLS_UNTRUSTED_CA_OR_CHAIN_INVALID`)
  8. Real HTTPS redirect security tests:
     - HTTPS -> HTTP downgrade redirect -> BLOCKED (`HTTPS_DOWNGRADE_REDIRECT_BLOCKED`)
     - HTTPS -> Disallowed official domain -> BLOCKED (`DISALLOWED_OFFICIAL_SOURCE_DOMAIN`)
     - Safe HTTPS -> HTTPS redirect within allowlisted domain -> PASS with full `redirect_chain`
  9. Unconfigured live environment & v1.0.3.1 governance invariants (9 schemas, 74/74 audit log, 30/5/39 L1-L4, 0 private keys).
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest

from engine.attestation_verifier import (
    PARSER_VERSION,
    compute_public_key_fingerprint,
    generate_ephemeral_keypair,
    sign_canonical_payload,
)
from engine.knowledge_card_validator import load_knowledge_cards, validate_central_audit_log
from engine.legal_reasoning import TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA
from engine.precedent_verifier import load_precedent_registry
from engine.source_validator import load_source_registry
from engine.trust_root import (
    DEFAULT_ALLOWED_OFFICIAL_DOMAINS,
    DefaultProductionAuthorizationProvider,
    DefaultSourceAcquisitionProvider,
    EphemeralSandboxTsaResponder,
    GcpCloudKmsSignerAdapter,
    GcpCloudStorageWormAdapter,
    GcpExternalTrustAnchorProvider,
    InMemoryMockGcpKmsBackend,
    InMemoryMockGcpWormBackend,
    KvkkDataResidencyVerificationResult,
    KvkkDataResidencyVerifier,
    LegalCounselAttestationVerificationResult,
    LegalCounselAttestationVerifier,
    LiveHttpsSourceFetcher,
    Rfc3161TimestampAuthorityAdapter,
    SourceAcquisitionVerificationResult,
    TechnicalVerificationResult,
    TechnicalVerificationService,
    TlsCertificateInfo,
    build_kvkk_m9_assessment_signing_payload,
    create_signed_legal_counsel_attestation_envelope,
    run_live_integration_probe,
    verify_tls_peer_certificate_chain,
)

from tests.pki_test_helpers import _MATERIAL_BANK

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _generate_ephemeral_pki_bundle(
    root: Path,
    *,
    san_dns: str,
    expired: bool = False,
    ca_cn: str = "CALISORA-TEST-ROOT-CA",
    prefix: str = "srv",
    checked_out_slots: list[int] | None = None,
) -> dict[str, Path]:
    """Generate ephemeral strict RFC 5280 CA + server X.509 cert/key in an isolated temp directory (never persisted in repo)."""
    sub = root / prefix
    sub.mkdir(parents=True, exist_ok=True)
    ca_key, ca_cert = sub / "ca.key", sub / "ca.pem"
    srv_key, srv_csr, srv_cert = sub / "srv.key", sub / "srv.csr", sub / "srv.pem"
    ca_req_cnf = sub / "ca_req.cnf"
    ca_req_cnf.write_text(
        "[req]\n"
        "distinguished_name = dn\n"
        "x509_extensions = v3_ca\n"
        "prompt = no\n"
        "[dn]\n"
        f"CN = {ca_cn}\n"
        "O = CALISORA-TEST-PKI\n"
        "[v3_ca]\n"
        "subjectKeyIdentifier = hash\n"
        "authorityKeyIdentifier = keyid:always,issuer\n"
        "basicConstraints = critical, CA:TRUE\n"
        "keyUsage = critical, keyCertSign, cRLSign\n",
        encoding="utf-8",
    )

    local_slots: list[int] = []
    try:
        ca_slot, ca_key_bytes = _MATERIAL_BANK.acquire_rsa_key_slot()
        local_slots.append(ca_slot)
        srv_slot, srv_key_bytes = _MATERIAL_BANK.acquire_rsa_key_slot()
        local_slots.append(srv_slot)
        ca_key.write_bytes(ca_key_bytes)
        srv_key.write_bytes(srv_key_bytes)

        p_ca = subprocess.run(
            [
                "openssl", "req", "-x509", "-key", str(ca_key),
                "-config", str(ca_req_cnf), "-extensions", "v3_ca",
                "-out", str(ca_cert), "-days", "30",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if p_ca.returncode != 0:
            raise RuntimeError(p_ca.stderr)

        p_csr = subprocess.run(
            [
                "openssl", "req", "-new", "-key", str(srv_key),
                "-out", str(srv_csr),
                "-subj", f"/CN={san_dns}",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if p_csr.returncode != 0:
            raise RuntimeError(p_csr.stderr)

        leaf_ext_body = (
            "subjectKeyIdentifier = hash\n"
            "authorityKeyIdentifier = keyid,issuer\n"
            "basicConstraints = critical, CA:FALSE\n"
            "keyUsage = critical, digitalSignature, keyEncipherment\n"
            "extendedKeyUsage = serverAuth\n"
            f"subjectAltName = DNS:{san_dns}\n"
        )

        if expired:
            (sub / "index.txt").write_text("", encoding="utf-8")
            (sub / "serial").write_text("01\n", encoding="utf-8")
            (sub / "newcerts").mkdir(exist_ok=True)
            ca_cnf = sub / "ca.cnf"
            ca_cnf.write_text(
                f"[ca]\ndefault_ca = CA_default\n[CA_default]\ndir = {sub}\n"
                f"database = $dir/index.txt\nnew_certs_dir = $dir/newcerts\n"
                f"certificate = {ca_cert}\nprivate_key = {ca_key}\nserial = $dir/serial\n"
                f"default_md = sha256\npolicy = policy_any\nx509_extensions = v3_leaf\n"
                f"[policy_any]\ncommonName = supplied\n[v3_leaf]\n"
                + leaf_ext_body,
                encoding="utf-8",
            )
            p_sign = subprocess.run(
                [
                    "openssl", "ca", "-batch", "-config", str(ca_cnf),
                    "-startdate", "20200101000000Z", "-enddate", "20200102000000Z",
                    "-in", str(srv_csr), "-out", str(srv_cert),
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        else:
            ext = sub / "leaf.ext"
            ext.write_text(leaf_ext_body, encoding="utf-8")
            p_sign = subprocess.run(
                [
                    "openssl", "x509", "-req", "-in", str(srv_csr),
                    "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
                    "-out", str(srv_cert), "-days", "30", "-extfile", str(ext),
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        if p_sign.returncode != 0:
            raise RuntimeError(p_sign.stderr)

        if checked_out_slots is not None:
            checked_out_slots.extend(local_slots)
            local_slots.clear()
        return {"ca_cert": ca_cert, "srv_cert": srv_cert, "srv_key": srv_key}
    finally:
        for slot in local_slots:
            _MATERIAL_BANK.release_rsa_key_slot(slot)


class _EphemeralTlsPkiScope:
    """Holds exclusive RSA-2048 key slots across multiple concurrently active TLS PKI bundles until exit."""

    def __init__(self) -> None:
        self._slots: list[int] = []

    def create_bundle(
        self,
        root: Path,
        *,
        san_dns: str,
        expired: bool = False,
        ca_cn: str = "CALISORA-TEST-ROOT-CA",
        prefix: str = "srv",
    ) -> dict[str, Path]:
        return _generate_ephemeral_pki_bundle(
            root,
            san_dns=san_dns,
            expired=expired,
            ca_cn=ca_cn,
            prefix=prefix,
            checked_out_slots=self._slots,
        )

    def __enter__(self) -> "_EphemeralTlsPkiScope":
        return self

    def __exit__(self, *_exc: object) -> None:
        slots = list(self._slots)
        self._slots.clear()
        for slot in slots:
            _MATERIAL_BANK.release_rsa_key_slot(slot)


class _ReusableLocalHTTPServer(HTTPServer):
    allow_reuse_address = True

    def handle_error(self, request: object, client_address: object) -> None:
        # Suppress expected TLS handshake rejection tracebacks during negative-TLS tests
        return


class _LocalHttpsTestServer:
    """Ephemeral real TLS 1.2+/1.3 HTTPS server bound to 127.0.0.1:0 for offline live-socket TLS tests."""

    def __init__(self, cert_path: Path, key_path: Path, routes: dict[str, tuple[int, dict[str, str], bytes]]) -> None:
        self.routes = routes
        self.cert_path = cert_path
        self.key_path = key_path
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port: int = 0

    def __enter__(self) -> "_LocalHttpsTestServer":
        routes = self.routes

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                status, headers, body = routes.get(self.path, (404, {"Content-Type": "text/plain"}, b"not found"))
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

        srv = _ReusableLocalHTTPServer(("127.0.0.1", 0), Handler)
        srv.socket.settimeout(2.0)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=str(self.cert_path), keyfile=str(self.key_path))
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        self._server = srv
        self.port = srv.server_address[1]
        self._thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None


class TestV1031HardenedProductionGateAndRealTls(unittest.TestCase):
    """[MOCK / LOCAL-TLS / GOVERNANCE] v1.0.3.1 anti-self-grant & real HTTPS/TLS verification tests."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.ledger = json.loads((PROJECT_ROOT / "config" / "calendar_attestation_ledger.json").read_text(encoding="utf-8"))
        cls.approvers = json.loads((PROJECT_ROOT / "config" / "authorized_approvers.json").read_text(encoding="utf-8"))
        cls.tr_cfg = json.loads((PROJECT_ROOT / "config" / "production_trust_root_config.json").read_text(encoding="utf-8"))
        cls.tech_res = TechnicalVerificationService().verify_repository_technical_integrity(project_root=PROJECT_ROOT)
        assert cls.tech_res.valid, cls.tech_res.errors

    def _build_enrolled_counsel_fixture(self) -> tuple[dict, str, str]:
        priv, pub = generate_ephemeral_keypair("ED25519")
        fp = compute_public_key_fingerprint(pub)
        reg = deepcopy(self.approvers)
        reg["approvers"]["CALISORA-HUKUK-01"].update(
            {
                "enrollment_status": "ENROLLED",
                "key_id": "KEY-COUNSEL-V1031-TEST",
                "key_version": "v1",
                "key_algorithm": "ED25519",
                "public_key_pem": pub,
                "public_key_fingerprint_sha256": fp,
                "authorized_scopes": [
                    "HOLIDAY_CALENDAR_LEGAL_APPROVAL:2024-2030",
                    "KVKK_M9_DATA_RESIDENCY_APPROVAL",
                ],
            }
        )
        return reg, priv, fp

    def test_01_caller_supplied_legal_counsel_boolean_and_forged_result_rejected(self) -> None:
        gate = DefaultProductionAuthorizationProvider(
            kms_signer=GcpCloudKmsSignerAdapter(),
            tsa_provider=Rfc3161TimestampAuthorityAdapter(),
            worm_storage=GcpCloudStorageWormAdapter(),
            trust_anchor_provider=GcpExternalTrustAnchorProvider(),
            trust_root_config=self.tr_cfg,
            project_root=PROJECT_ROOT,
        )

        # Attack 1A: Caller passes legal_counsel_attestation_verified=True & SIGNED_LEGAL_ATTESTATION_VERIFIED
        dec = gate.evaluate_production_authorization(
            ledger=self.ledger,
            approvers_registry=self.approvers,
            technical_verification_result=self.tech_res,
            legal_counsel_attestation_verified=True,
            external_legal_counsel_signoff_status="SIGNED_LEGAL_ATTESTATION_VERIFIED",
            runtime_environment="PRODUCTION",
        )
        self.assertFalse(dec.production_use_authorized)
        self.assertEqual(dec.production_authorization_status, "DENIED_SECURITY_VIOLATION")
        self.assertEqual(dec.legal_counsel_attestation_status, "PENDING_SIGNED_EXTERNAL_ATTESTATION")
        self.assertEqual(dec.external_legal_counsel_signoff_status, "PENDING_SIGNED_EXTERNAL_ATTESTATION")
        self.assertIn("CALLER_SELF_ASSERTED_BOOLEAN_FORBIDDEN", dec.blocking_codes)
        self.assertIn("EXTERNAL_LEGAL_COUNSEL_ATTESTATION_REQUIRED", dec.blocking_codes)
        self.assertFalse(dec.checks["no_caller_self_asserted_booleans"])
        self.assertFalse(dec.checks["legal_counsel_attestation_verified"])

        # Attack 1B: Caller manually instantiates a forged LegalCounselAttestationVerificationResult(valid=True, ...)
        forged_legal = LegalCounselAttestationVerificationResult(
            valid=True,
            status="SIGNED_LEGAL_ATTESTATION_VERIFIED",
            approver_id="CALISORA-HUKUK-01",
            approver_role="EXTERNAL_LEGAL_COUNSEL",
            key_id="FORGED-KEY",
            key_version="v1",
            algorithm="ED25519",
            signed_at_utc="2026-11-21T10:00:00Z",
            certificate_status="ACTIVE_VERIFIED",
            authorized_scope_verified=True,
            calendar_version=self.tech_res.calendar_version,
            calendar_sha256=self.tech_res.calendar_sha256,
            hukuk_sgk_version=self.tech_res.hukuk_sgk_version,
            signature_verified=True,
            verifier_service_id="FAKE_CALLER",
            _service_seal="0" * 64,
        )
        dec_forged = gate.evaluate_production_authorization(
            ledger=self.ledger,
            approvers_registry=self.approvers,
            technical_verification_result=self.tech_res,
            legal_counsel_attestation_result=forged_legal,
            runtime_environment="PRODUCTION",
        )
        self.assertFalse(dec_forged.production_use_authorized)
        self.assertEqual(dec_forged.production_authorization_status, "DENIED_SECURITY_VIOLATION")
        self.assertIn("FORGED_OR_UNAUTHENTICATED_VERIFICATION_RESULT", dec_forged.blocking_codes)
        self.assertFalse(dec_forged.checks["legal_counsel_attestation_verified"])

    def test_02_unsigned_tampered_revoked_expired_and_unauthorized_legal_attestations_rejected(self) -> None:
        verifier = LegalCounselAttestationVerifier()
        reg, priv, fp = self._build_enrolled_counsel_fixture()

        valid_env = create_signed_legal_counsel_attestation_envelope(
            attestation_id="ATT-V1031-BASE-001",
            nonce="NONCE-V1031-BASE-0001",
            approver_id="CALISORA-HUKUK-01",
            key_id="KEY-COUNSEL-V1031-TEST",
            key_version="v1",
            algorithm="ED25519",
            signed_at_utc="2026-11-21T10:00:00Z",
            calendar_version=self.tech_res.calendar_version,
            calendar_sha256=self.tech_res.calendar_sha256,
            hukuk_sgk_version=self.tech_res.hukuk_sgk_version,
            authorized_scope="HOLIDAY_CALENDAR_LEGAL_APPROVAL:2024-2030",
            private_key_pem=priv,
            public_key_fingerprint_sha256=fp,
        )
        ok_res = verifier.verify_attestation_envelope(
            valid_env,
            approvers_registry=reg,
            expected_calendar_version=self.tech_res.calendar_version,
            expected_calendar_sha256=self.tech_res.calendar_sha256,
            expected_hukuk_sgk_version=self.tech_res.hukuk_sgk_version,
        )
        self.assertTrue(ok_res.valid, ok_res.errors)
        self.assertEqual(ok_res.status, "SIGNED_LEGAL_ATTESTATION_VERIFIED")
        self.assertEqual(ok_res.certificate_status, "ACTIVE_VERIFIED")
        self.assertFalse(ok_res.qualified_e_signature_5070_equivalent)

        # Unsigned envelope -> rejected
        unsigned_env = deepcopy(valid_env)
        unsigned_env["signature_b64"] = ""
        res_unsigned = verifier.verify_attestation_envelope(
            unsigned_env,
            approvers_registry=reg,
            expected_calendar_version=self.tech_res.calendar_version,
            expected_calendar_sha256=self.tech_res.calendar_sha256,
            expected_hukuk_sgk_version=self.tech_res.hukuk_sgk_version,
        )
        self.assertFalse(res_unsigned.valid)
        self.assertEqual(res_unsigned.status, "ATTESTATION_REJECTED")
        self.assertIn("MISSING_ATTESTATION_SIGNATURE", res_unsigned.error_codes)

        # Tampered signature -> rejected
        tampered_env = deepcopy(valid_env)
        tampered_env["nonce"] = "NONCE-V1031-TAMPERED!"
        res_tampered = verifier.verify_attestation_envelope(
            tampered_env,
            approvers_registry=reg,
            expected_calendar_version=self.tech_res.calendar_version,
            expected_calendar_sha256=self.tech_res.calendar_sha256,
            expected_hukuk_sgk_version=self.tech_res.hukuk_sgk_version,
        )
        self.assertFalse(res_tampered.valid)
        self.assertIn("INVALID_LEGAL_COUNSEL_SIGNATURE", res_tampered.error_codes)

        # Revoked (KEY_COMPROMISE) approver -> rejected
        revoked_reg = deepcopy(reg)
        revoked_reg["approvers"]["CALISORA-HUKUK-01"]["status"] = "REVOKED"
        revoked_reg["approvers"]["CALISORA-HUKUK-01"]["revoked_at_utc"] = "2026-11-21T11:00:00Z"
        revoked_reg["approvers"]["CALISORA-HUKUK-01"]["revocation_reason"] = "KEY_COMPROMISE"
        res_revoked = verifier.verify_attestation_envelope(
            valid_env,
            approvers_registry=revoked_reg,
            expected_calendar_version=self.tech_res.calendar_version,
            expected_calendar_sha256=self.tech_res.calendar_sha256,
            expected_hukuk_sgk_version=self.tech_res.hukuk_sgk_version,
        )
        self.assertFalse(res_revoked.valid)
        self.assertEqual(res_revoked.certificate_status, "REVOKED")

        # Expired validity window -> rejected
        expired_reg = deepcopy(reg)
        expired_reg["approvers"]["CALISORA-HUKUK-01"]["valid_until_utc"] = "2026-06-01T00:00:00Z"
        res_expired = verifier.verify_attestation_envelope(
            valid_env,
            approvers_registry=expired_reg,
            expected_calendar_version=self.tech_res.calendar_version,
            expected_calendar_sha256=self.tech_res.calendar_sha256,
            expected_hukuk_sgk_version=self.tech_res.hukuk_sgk_version,
        )
        self.assertFalse(res_expired.valid)
        self.assertEqual(res_expired.certificate_status, "EXPIRED")

        # Unauthorized role (sealer trying to sign legal counsel approval) -> rejected
        wrong_role_reg = deepcopy(reg)
        wrong_role_reg["approvers"]["CALISORA-HUKUK-01"]["role"] = "AUDIT_LEDGER_CHECKPOINT_SIGNER"
        res_role = verifier.verify_attestation_envelope(
            valid_env,
            approvers_registry=wrong_role_reg,
            expected_calendar_version=self.tech_res.calendar_version,
            expected_calendar_sha256=self.tech_res.calendar_sha256,
            expected_hukuk_sgk_version=self.tech_res.hukuk_sgk_version,
        )
        self.assertFalse(res_role.valid)
        self.assertIn("UNAUTHORIZED_APPROVER_ROLE", res_role.error_codes)

        # Unavailable KMS verifier when kms_key_resource_id is requested -> fail closed
        kms_env = deepcopy(valid_env)
        kms_env["kms_key_resource_id"] = "projects/calisora-sec-prod/locations/europe-west3/keyRings/r1/cryptoKeys/k1/cryptoKeyVersions/1"
        res_unavail = verifier.verify_attestation_envelope(
            kms_env,
            approvers_registry=reg,
            expected_calendar_version=self.tech_res.calendar_version,
            expected_calendar_sha256=self.tech_res.calendar_sha256,
            expected_hukuk_sgk_version=self.tech_res.hukuk_sgk_version,
            kms_signer=GcpCloudKmsSignerAdapter(),  # NOT_CONFIGURED
        )
        self.assertFalse(res_unavail.valid)
        self.assertIn("LEGAL_ATTESTATION_VERIFIER_UNAVAILABLE", res_unavail.error_codes)

    def test_03_valid_signature_for_other_calendar_version_or_sha256_rejected(self) -> None:
        verifier = LegalCounselAttestationVerifier()
        reg, priv, fp = self._build_enrolled_counsel_fixture()

        # Genuine cryptographically valid signature issued for OLD calendar version "1.0.2c.6"
        old_ver_env = create_signed_legal_counsel_attestation_envelope(
            attestation_id="ATT-OLD-CAL-001",
            nonce="NONCE-OLD-CAL-0001",
            approver_id="CALISORA-HUKUK-01",
            key_id="KEY-COUNSEL-V1031-TEST",
            key_version="v1",
            algorithm="ED25519",
            signed_at_utc="2026-11-21T10:00:00Z",
            calendar_version="1.0.2c.6",
            calendar_sha256=self.tech_res.calendar_sha256,
            hukuk_sgk_version="1.0.2c.6",
            authorized_scope="HOLIDAY_CALENDAR_LEGAL_APPROVAL:2024-2030",
            private_key_pem=priv,
            public_key_fingerprint_sha256=fp,
        )

        # Direct gate verification rejects version mismatch!
        gate = DefaultProductionAuthorizationProvider(
            kms_signer=GcpCloudKmsSignerAdapter(),
            tsa_provider=Rfc3161TimestampAuthorityAdapter(),
            worm_storage=GcpCloudStorageWormAdapter(),
            trust_anchor_provider=GcpExternalTrustAnchorProvider(),
            trust_root_config=self.tr_cfg,
            project_root=PROJECT_ROOT,
        )
        dec_old = gate.evaluate_production_authorization(
            ledger=self.ledger,
            approvers_registry=reg,
            technical_verification_result=self.tech_res,
            legal_counsel_attestation_envelope=old_ver_env,
            runtime_environment="PRODUCTION",
        )
        self.assertFalse(dec_old.production_use_authorized)
        self.assertEqual(dec_old.legal_counsel_attestation_status, "ATTESTATION_REJECTED")
        self.assertIn("ATTESTATION_CALENDAR_VERSION_MISMATCH", dec_old.blocking_codes)
        self.assertIn("ATTESTATION_HUKUK_SGK_VERSION_MISMATCH", dec_old.blocking_codes)

        # Even if verified honestly against "1.0.2c.6" first, replaying that sealed result to a v1.0.3.1 gate MUST fail!
        old_verified_res = verifier.verify_attestation_envelope(
            old_ver_env,
            approvers_registry=reg,
            expected_calendar_version="1.0.2c.6",
            expected_calendar_sha256=self.tech_res.calendar_sha256,
            expected_hukuk_sgk_version="1.0.2c.6",
        )
        self.assertTrue(old_verified_res.valid, old_verified_res.errors)
        dec_replay = gate.evaluate_production_authorization(
            ledger=self.ledger,
            approvers_registry=reg,
            technical_verification_result=self.tech_res,
            legal_counsel_attestation_result=old_verified_res,
            runtime_environment="PRODUCTION",
        )
        self.assertFalse(dec_replay.production_use_authorized)
        self.assertIn("ATTESTATION_CALENDAR_VERSION_MISMATCH", dec_replay.blocking_codes)
        self.assertIn("ATTESTATION_HUKUK_SGK_VERSION_MISMATCH", dec_replay.blocking_codes)

        # Genuine signature for a DIFFERENT calendar SHA-256 digest -> rejected!
        wrong_sha_env = create_signed_legal_counsel_attestation_envelope(
            attestation_id="ATT-WRONG-SHA-001",
            nonce="NONCE-WRONG-SHA-0001",
            approver_id="CALISORA-HUKUK-01",
            key_id="KEY-COUNSEL-V1031-TEST",
            key_version="v1",
            algorithm="ED25519",
            signed_at_utc="2026-11-21T10:00:00Z",
            calendar_version=self.tech_res.calendar_version,
            calendar_sha256="b" * 64,
            hukuk_sgk_version=self.tech_res.hukuk_sgk_version,
            authorized_scope="HOLIDAY_CALENDAR_LEGAL_APPROVAL:2024-2030",
            private_key_pem=priv,
            public_key_fingerprint_sha256=fp,
        )
        dec_sha = gate.evaluate_production_authorization(
            ledger=self.ledger,
            approvers_registry=reg,
            technical_verification_result=self.tech_res,
            legal_counsel_attestation_envelope=wrong_sha_env,
            runtime_environment="PRODUCTION",
        )
        self.assertFalse(dec_sha.production_use_authorized)
        self.assertIn("ATTESTATION_CALENDAR_SHA256_MISMATCH", dec_sha.blocking_codes)

    def test_04_missing_source_acquisition_fails_closed_and_all_caller_booleans_blocked(self) -> None:
        gate = DefaultProductionAuthorizationProvider(
            kms_signer=GcpCloudKmsSignerAdapter(),
            tsa_provider=Rfc3161TimestampAuthorityAdapter(),
            worm_storage=GcpCloudStorageWormAdapter(),
            trust_anchor_provider=GcpExternalTrustAnchorProvider(),
            trust_root_config=self.tr_cfg,
            project_root=PROJECT_ROOT,
        )

        # Omitting source acquisition completely MUST fail closed (no default True!)
        dec_missing = gate.evaluate_production_authorization(
            ledger=self.ledger,
            approvers_registry=self.approvers,
            technical_verification_result=self.tech_res,
            runtime_environment="PRODUCTION",
        )
        self.assertFalse(dec_missing.production_use_authorized)
        self.assertFalse(dec_missing.checks["source_acquisition_verified"])
        self.assertIn("SOURCE_ACQUISITION_EVIDENCE_MISSING", dec_missing.blocking_codes)

        # Passing source_acquisition_verified=True, technical_verification_passed=True, kvkk_data_residency_approved=True -> rejected!
        dec_bools = gate.evaluate_production_authorization(
            ledger=self.ledger,
            approvers_registry=self.approvers,
            technical_verification_passed=True,
            source_acquisition_verified=True,
            kvkk_data_residency_approved=True,
            runtime_environment="PRODUCTION",
        )
        self.assertFalse(dec_bools.production_use_authorized)
        self.assertEqual(dec_bools.production_authorization_status, "DENIED_SECURITY_VIOLATION")
        self.assertIn("CALLER_SELF_ASSERTED_BOOLEAN_FORBIDDEN", dec_bools.blocking_codes)
        self.assertIn("SOURCE_ACQUISITION_EVIDENCE_MISSING", dec_bools.blocking_codes)
        self.assertIn("KVKK_DATA_RESIDENCY_ASSESSMENT_PENDING", dec_bools.blocking_codes)

        # Hand-forged SourceAcquisitionVerificationResult / TechnicalVerificationResult / KvkkDataResidencyVerificationResult -> rejected!
        forged_acq = SourceAcquisitionVerificationResult(
            valid=True, status="SOURCE_ACQUISITION_VERIFIED", acquisition_id="ACQ-FAKE", source_id="DIYANET-2026",
            raw_bytes_sha256="a" * 64, worm_verified=True, tsa_verified=True, signature_verified=True,
            tls_verified=True, production_tls_verified=True, fetcher_mode="LIVE_HTTPS", verifier_service_id="FAKE",
        )
        forged_tech = TechnicalVerificationResult(
            valid=True, status="TECHNICAL_VERIFIED", calendar_version="1.0.3.1", calendar_sha256="a" * 64,
            hukuk_sgk_version="1.0.3.1", verified_years=(2024, 2025, 2026, 2027), audit_log_valid=True,
            snapshots_verified=True, verifier_service_id="FAKE",
        )
        forged_kvkk = KvkkDataResidencyVerificationResult(
            valid=True, status="APPROVED", primary_region="europe-west3", assessment_reference="FAKE",
            approved_by_approver_id="CALISORA-HUKUK-01", approved_at_utc="2026-11-21T10:00:00Z",
            signature_verified=True, verifier_service_id="FAKE",
        )
        dec_forged = gate.evaluate_production_authorization(
            ledger=self.ledger,
            approvers_registry=self.approvers,
            technical_verification_result=forged_tech,
            source_acquisition_result=forged_acq,
            kvkk_residency_result=forged_kvkk,
            runtime_environment="PRODUCTION",
        )
        self.assertFalse(dec_forged.production_use_authorized)
        self.assertEqual(dec_forged.production_authorization_status, "DENIED_SECURITY_VIOLATION")
        self.assertIn("FORGED_OR_UNAUTHENTICATED_VERIFICATION_RESULT", dec_forged.blocking_codes)
        self.assertFalse(dec_forged.checks["technical_verification_passed"])
        self.assertFalse(dec_forged.checks["source_acquisition_verified"])
        self.assertFalse(dec_forged.checks["kvkk_data_residency_approved"])

    def test_05_fake_tls_metadata_and_callback_fetcher_rejected_for_production(self) -> None:
        raw_html = (PROJECT_ROOT / "evidence" / "holiday_snapshots" / "diyanet_2026_v1.html").read_bytes()
        kms_backend = InMemoryMockGcpKmsBackend(default_region="europe-west3")
        key_ref = "projects/calisora-sec-prod/locations/europe-west3/keyRings/r1/cryptoKeys/k1/cryptoKeyVersions/1"
        kms_backend.enroll_ephemeral_key(key_ref, algorithm="ED25519", protection_level="HSM")
        kms = GcpCloudKmsSignerAdapter(project_id="calisora-sec-prod", region="europe-west3", key_ring="r1", mock_backend=kms_backend)
        worm = GcpCloudStorageWormAdapter(
            mock_backend=InMemoryMockGcpWormBackend(
                project_id="calisora-sec-prod", bucket_name="calisora-worm", region="europe-west3",
                retention_period_seconds=315360000, retention_policy_locked=True,
            )
        )

        # Case A: Fake TLS certificate dict with NO real X.509 PEM -> rejected with TLS_FAKE_OR_UNVERIFIABLE_METADATA!
        with EphemeralSandboxTsaResponder() as tsa_resp:
            tsa = Rfc3161TimestampAuthorityAdapter(
                tsa_url="https://mock-tsa.calisora.invalid/tsr",
                trusted_ca_pem=tsa_resp.ca_cert_pem,
                http_transport=tsa_resp.transport,
            )
            fake_tls_acq = DefaultSourceAcquisitionProvider(
                worm_storage=worm, tsa_provider=tsa, kms_signer=kms, signing_key_ref=key_ref,
                mock_fetcher=lambda u: {
                    "raw_bytes": raw_html,
                    "final_url": u,
                    "redirect_chain": [u],
                    "http_status": 200,
                    "http_headers": {"Content-Type": "text/html"},
                    "tls_certificate_info": TlsCertificateInfo(
                        tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384",
                        server_hostname="vakithesaplama.diyanet.gov.tr",
                        peer_subject="CN=vakithesaplama.diyanet.gov.tr", peer_issuer="CN=Fake CA",
                        san_dns_names=("vakithesaplama.diyanet.gov.tr",), serial_number="0x01",
                        not_before_utc="2026-01-01T00:00:00Z", not_after_utc="2027-01-01T00:00:00Z",
                        leaf_cert_sha256="f" * 64, leaf_cert_pem=None,
                    ),
                },
            )
            fake_env = fake_tls_acq.acquire_and_seal_source(
                "DIYANET-2026", "https://vakithesaplama.diyanet.gov.tr/icerik.php?icerik=153"
            )
            self.assertFalse(fake_env.valid)
            self.assertIn("TLS_FAKE_OR_UNVERIFIABLE_METADATA", fake_env.error_codes)

            # Case B: Real X.509 PEM with contradictory declared leaf_cert_sha256 -> TLS_FAKE_OR_UNVERIFIABLE_METADATA!
            with tempfile.TemporaryDirectory(prefix="calisora_tls_meta_") as tmp:
                pki = _generate_ephemeral_pki_bundle(Path(tmp), san_dns="vakithesaplama.diyanet.gov.tr")
                ca_pem = pki["ca_cert"].read_text(encoding="utf-8")
                leaf_pem = pki["srv_cert"].read_text(encoding="utf-8")
                tls_chk, _ = verify_tls_peer_certificate_chain(
                    leaf_pem,
                    server_hostname="vakithesaplama.diyanet.gov.tr",
                    trusted_ca_pem=ca_pem,
                    declared_tls_info={"leaf_cert_sha256": "0" * 64},
                    fetcher_mode="MOCK_CALLBACK",
                )
                self.assertFalse(tls_chk.verified)
                self.assertFalse(tls_chk.metadata_consistent_with_x509)
                self.assertIn("TLS_FAKE_OR_UNVERIFIABLE_METADATA", tls_chk.error_codes)

                # Case C: Valid mock callback acquisition NEVER counts as LIVE_HTTPS production TLS in ProductionAuthorizationProvider!
                cb_acq = DefaultSourceAcquisitionProvider(
                    worm_storage=worm, tsa_provider=tsa, kms_signer=kms, signing_key_ref=key_ref,
                    mock_fetcher=lambda u: {
                        "raw_bytes": raw_html, "final_url": u, "redirect_chain": [u], "http_status": 200,
                        "http_headers": {"Content-Type": "text/html"},
                        "tls_certificate_info": {
                            "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384",
                            "server_hostname": "vakithesaplama.diyanet.gov.tr", "leaf_cert_pem": leaf_pem,
                        },
                    },
                    trusted_ca_pem=ca_pem,
                )
                cb_env = cb_acq.acquire_and_seal_source(
                    "DIYANET-2026-CB", "https://vakithesaplama.diyanet.gov.tr/icerik.php?icerik=153"
                )
                self.assertTrue(cb_env.valid, cb_env.errors)
                self.assertEqual(cb_env.fetcher_mode, "MOCK_CALLBACK")
                self.assertFalse(cb_env.production_tls_verified)

                cb_res = cb_acq.verify_acquisition_evidence_result(cb_env, expected_raw_bytes=raw_html)
                gate = DefaultProductionAuthorizationProvider(
                    kms_signer=kms, tsa_provider=tsa, worm_storage=worm,
                    trust_anchor_provider=GcpExternalTrustAnchorProvider(),
                    source_acquisition_provider=cb_acq,
                    trust_root_config=self.tr_cfg,
                    project_root=PROJECT_ROOT,
                )
                dec = gate.evaluate_production_authorization(
                    ledger=self.ledger,
                    approvers_registry=self.approvers,
                    technical_verification_result=self.tech_res,
                    source_acquisition_result=cb_res,
                    runtime_environment="PRODUCTION",
                )
                self.assertFalse(dec.production_use_authorized)
                self.assertFalse(dec.checks["source_acquisition_verified"])
                self.assertIn("CALLBACK_FETCHER_NOT_ALLOWED_IN_PRODUCTION", dec.blocking_codes)

    def test_06_live_https_real_tls_valid_wrong_hostname_expired_and_untrusted_ca(self) -> None:
        raw_html = (PROJECT_ROOT / "evidence" / "holiday_snapshots" / "diyanet_2026_v1.html").read_bytes()
        kms_backend = InMemoryMockGcpKmsBackend(default_region="europe-west3")
        key_ref = "projects/calisora-sec-prod/locations/europe-west3/keyRings/r1/cryptoKeys/k1/cryptoKeyVersions/1"
        kms_backend.enroll_ephemeral_key(key_ref, algorithm="ED25519", protection_level="HSM")
        kms = GcpCloudKmsSignerAdapter(project_id="calisora-sec-prod", region="europe-west3", key_ring="r1", mock_backend=kms_backend)
        worm = GcpCloudStorageWormAdapter(
            mock_backend=InMemoryMockGcpWormBackend(
                project_id="calisora-sec-prod", bucket_name="calisora-live-tls-worm", region="europe-west3",
                retention_period_seconds=315360000, retention_policy_locked=True,
            )
        )

        with (
            tempfile.TemporaryDirectory(prefix="calisora_live_https_") as tmp,
            EphemeralSandboxTsaResponder() as tsa_resp,
            _EphemeralTlsPkiScope() as pki_scope,
        ):
            tmp_path = Path(tmp)
            tsa = Rfc3161TimestampAuthorityAdapter(
                tsa_url="https://mock-tsa.calisora.invalid/tsr",
                trusted_ca_pem=tsa_resp.ca_cert_pem,
                http_transport=tsa_resp.transport,
            )

            # 1. Valid real TLS 1.2+/1.3 server (strict RFC 5280 CA trusted, SAN=localhost, valid period)
            valid_pki = pki_scope.create_bundle(tmp_path, san_dns="localhost", prefix="valid")
            # Verify CA & server cert profiles explicitly under OpenSSL 3 -x509_strict
            ca_txt = subprocess.run(
                ["openssl", "x509", "-in", str(valid_pki["ca_cert"]), "-noout", "-text"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            ).stdout
            self.assertIn("CA:TRUE", ca_txt)
            self.assertIn("Certificate Sign", ca_txt)
            self.assertIn("CRL Sign", ca_txt)
            srv_txt = subprocess.run(
                ["openssl", "x509", "-in", str(valid_pki["srv_cert"]), "-noout", "-text"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            ).stdout
            self.assertIn("CA:FALSE", srv_txt)
            self.assertIn("Digital Signature", srv_txt)
            self.assertIn("Key Encipherment", srv_txt)
            self.assertIn("DNS:localhost", srv_txt)
            strict_chk = subprocess.run(
                ["openssl", "verify", "-x509_strict", "-no-CApath", "-CAfile", str(valid_pki["ca_cert"]), str(valid_pki["srv_cert"])],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(strict_chk.returncode, 0, strict_chk.stderr + strict_chk.stdout)
            self.assertIn(": OK", strict_chk.stdout)

            with _LocalHttpsTestServer(
                valid_pki["srv_cert"],
                valid_pki["srv_key"],
                {"/diyanet2026": (200, {"Content-Type": "text/html; charset=utf-8"}, raw_html)},
            ) as srv:
                live_fetcher = LiveHttpsSourceFetcher(
                    allowed_domains={"localhost"},
                    trusted_ca_pem_path=valid_pki["ca_cert"],
                )
                acq = DefaultSourceAcquisitionProvider(
                    worm_storage=worm, tsa_provider=tsa, kms_signer=kms, signing_key_ref=key_ref,
                    live_https_fetcher=live_fetcher,
                )
                self.assertEqual(acq.fetcher_mode, "LIVE_HTTPS")
                env = acq.acquire_and_seal_source("DIYANET-2026-LIVE", f"https://localhost:{srv.port}/diyanet2026")
                self.assertTrue(env.valid, env.errors)
                self.assertEqual(env.fetcher_mode, "LIVE_HTTPS")
                self.assertTrue(env.production_tls_verified)
                self.assertFalse(env.tls_alone_proves_historical_content)
                self.assertIsNotNone(env.tls_verification_result)
                self.assertTrue(env.tls_verification_result["ca_chain_verified"])  # type: ignore[index]
                self.assertTrue(env.tls_verification_result["hostname_san_verified"])  # type: ignore[index]
                self.assertTrue(env.tls_verification_result["validity_period_verified"])  # type: ignore[index]

                res = acq.verify_acquisition_evidence_result(env, expected_raw_bytes=raw_html)
                self.assertTrue(res.valid, res.errors)
                self.assertTrue(res.tls_verified)
                self.assertTrue(res.production_tls_verified)
                self.assertEqual(res.fetcher_mode, "LIVE_HTTPS")

            # 2. Wrong hostname / SAN mismatch -> TLS_HOSTNAME_OR_SAN_MISMATCH
            wrong_host_pki = pki_scope.create_bundle(tmp_path, san_dns="wrong-host.example.invalid", prefix="wrong_host")
            with _LocalHttpsTestServer(
                wrong_host_pki["srv_cert"],
                wrong_host_pki["srv_key"],
                {"/doc": (200, {"Content-Type": "text/html"}, raw_html)},
            ) as srv:
                live_fetcher = LiveHttpsSourceFetcher(
                    allowed_domains={"localhost"},
                    trusted_ca_pem_path=wrong_host_pki["ca_cert"],
                )
                acq = DefaultSourceAcquisitionProvider(
                    worm_storage=worm, tsa_provider=tsa, kms_signer=kms, signing_key_ref=key_ref,
                    live_https_fetcher=live_fetcher,
                )
                env_wh = acq.acquire_and_seal_source("WRONG-HOST", f"https://localhost:{srv.port}/doc")
                self.assertFalse(env_wh.valid)
                self.assertIn("TLS_HOSTNAME_OR_SAN_MISMATCH", env_wh.error_codes)

            # 3. Expired certificate (2020-01-01 .. 2020-01-02) -> TLS_CERTIFICATE_EXPIRED_OR_NOT_YET_VALID
            expired_pki = pki_scope.create_bundle(tmp_path, san_dns="localhost", expired=True, prefix="expired")
            with _LocalHttpsTestServer(
                expired_pki["srv_cert"],
                expired_pki["srv_key"],
                {"/doc": (200, {"Content-Type": "text/html"}, raw_html)},
            ) as srv:
                live_fetcher = LiveHttpsSourceFetcher(
                    allowed_domains={"localhost"},
                    trusted_ca_pem_path=expired_pki["ca_cert"],
                )
                acq = DefaultSourceAcquisitionProvider(
                    worm_storage=worm, tsa_provider=tsa, kms_signer=kms, signing_key_ref=key_ref,
                    live_https_fetcher=live_fetcher,
                )
                env_exp = acq.acquire_and_seal_source("EXPIRED-CERT", f"https://localhost:{srv.port}/doc")
                self.assertFalse(env_exp.valid)
                self.assertIn("TLS_CERTIFICATE_EXPIRED_OR_NOT_YET_VALID", env_exp.error_codes)

            # 4. Untrusted CA (server cert signed by rogue CA not matching client's trusted CA) -> TLS_UNTRUSTED_CA_OR_CHAIN_INVALID
            rogue_pki = pki_scope.create_bundle(tmp_path, san_dns="localhost", ca_cn="ROGUE-CA", prefix="rogue")
            with _LocalHttpsTestServer(
                rogue_pki["srv_cert"],
                rogue_pki["srv_key"],
                {"/doc": (200, {"Content-Type": "text/html"}, raw_html)},
            ) as srv:
                live_fetcher = LiveHttpsSourceFetcher(
                    allowed_domains={"localhost"},
                    trusted_ca_pem_path=valid_pki["ca_cert"],  # Does NOT trust rogue_pki CA!
                )
                acq = DefaultSourceAcquisitionProvider(
                    worm_storage=worm, tsa_provider=tsa, kms_signer=kms, signing_key_ref=key_ref,
                    live_https_fetcher=live_fetcher,
                )
                env_ca = acq.acquire_and_seal_source("UNTRUSTED-CA", f"https://localhost:{srv.port}/doc")
                self.assertFalse(env_ca.valid)
                self.assertIn("TLS_UNTRUSTED_CA_OR_CHAIN_INVALID", env_ca.error_codes)

    def test_07_live_https_redirect_downgrade_to_http_and_disallowed_domain_blocked(self) -> None:
        raw_html = b"<html><body>Resmi Belge</body></html>"
        kms_backend = InMemoryMockGcpKmsBackend(default_region="europe-west3")
        key_ref = "projects/calisora-sec-prod/locations/europe-west3/keyRings/r1/cryptoKeys/k1/cryptoKeyVersions/1"
        kms_backend.enroll_ephemeral_key(key_ref, algorithm="ED25519", protection_level="HSM")
        kms = GcpCloudKmsSignerAdapter(project_id="calisora-sec-prod", region="europe-west3", key_ring="r1", mock_backend=kms_backend)
        worm = GcpCloudStorageWormAdapter(
            mock_backend=InMemoryMockGcpWormBackend(
                project_id="calisora-sec-prod", bucket_name="calisora-redir-worm", region="europe-west3",
                retention_period_seconds=315360000, retention_policy_locked=True,
            )
        )

        with (
            tempfile.TemporaryDirectory(prefix="calisora_redir_") as tmp,
            EphemeralSandboxTsaResponder() as tsa_resp,
            _EphemeralTlsPkiScope() as pki_scope,
        ):
            pki = pki_scope.create_bundle(Path(tmp), san_dns="localhost", prefix="redir")
            rogue_pki = pki_scope.create_bundle(Path(tmp), san_dns="localhost", ca_cn="ROGUE-REDIR-CA", prefix="redir_rogue")
            tsa = Rfc3161TimestampAuthorityAdapter(
                tsa_url="https://mock-tsa.calisora.invalid/tsr",
                trusted_ca_pem=tsa_resp.ca_cert_pem,
                http_transport=tsa_resp.transport,
            )
            routes: dict[str, tuple[int, dict[str, str], bytes]] = {}
            with _LocalHttpsTestServer(pki["srv_cert"], pki["srv_key"], routes) as srv:
                routes["/downgrade"] = (302, {"Location": f"http://localhost:{srv.port}/plain"}, b"")
                routes["/evil_domain"] = (302, {"Location": "https://evil-untrusted.example.com/steal"}, b"")
                routes["/safe_start"] = (302, {"Location": f"https://localhost:{srv.port}/safe_final"}, b"")
                routes["/safe_final"] = (200, {"Content-Type": "text/html"}, raw_html)

                live_fetcher = LiveHttpsSourceFetcher(
                    allowed_domains={"localhost"},
                    trusted_ca_pem_path=pki["ca_cert"],
                )
                acq = DefaultSourceAcquisitionProvider(
                    worm_storage=worm, tsa_provider=tsa, kms_signer=kms, signing_key_ref=key_ref,
                    live_https_fetcher=live_fetcher,
                )

                # HTTPS -> HTTP downgrade redirect MUST be blocked after valid trusted TLS handshake!
                env_down = acq.acquire_and_seal_source("DOWNGRADE", f"https://localhost:{srv.port}/downgrade")
                self.assertFalse(env_down.valid)
                self.assertIn("HTTPS_DOWNGRADE_REDIRECT_BLOCKED", env_down.error_codes)

                # HTTPS -> Disallowed domain redirect MUST be blocked!
                env_evil = acq.acquire_and_seal_source("EVIL-REDIR", f"https://localhost:{srv.port}/evil_domain")
                self.assertFalse(env_evil.valid)
                self.assertIn("DISALLOWED_OFFICIAL_SOURCE_DOMAIN", env_evil.error_codes)

                # Direct request to disallowed domain with default official allowlist MUST be blocked!
                acq_official = DefaultSourceAcquisitionProvider(
                    worm_storage=worm, tsa_provider=tsa, kms_signer=kms, signing_key_ref=key_ref,
                    live_https_fetcher=LiveHttpsSourceFetcher(allowed_domains=DEFAULT_ALLOWED_OFFICIAL_DOMAINS),
                )
                env_non_off = acq_official.acquire_and_seal_source("NON-OFFICIAL", "https://example.com/fake-gazette")
                self.assertFalse(env_non_off.valid)
                self.assertIn("DISALLOWED_OFFICIAL_SOURCE_DOMAIN", env_non_off.error_codes)

                # Safe HTTPS -> HTTPS redirect within allowlisted domain succeeds with full redirect_chain!
                env_safe = acq.acquire_and_seal_source("SAFE-REDIR", f"https://localhost:{srv.port}/safe_start")
                self.assertTrue(env_safe.valid, env_safe.errors)
                self.assertEqual(
                    env_safe.redirect_chain,
                    (f"https://localhost:{srv.port}/safe_start", f"https://localhost:{srv.port}/safe_final"),
                )
                self.assertTrue(env_safe.production_tls_verified)

                # TLS verification errors MUST block BEFORE redirect processing (never bypassed!)
                acq_untrusted = DefaultSourceAcquisitionProvider(
                    worm_storage=worm, tsa_provider=tsa, kms_signer=kms, signing_key_ref=key_ref,
                    live_https_fetcher=LiveHttpsSourceFetcher(
                        allowed_domains={"localhost"},
                        trusted_ca_pem_path=rogue_pki["ca_cert"],
                    ),
                )
                env_tls_fail = acq_untrusted.acquire_and_seal_source("TLS-FAIL-REDIR", f"https://localhost:{srv.port}/safe_start")
                self.assertFalse(env_tls_fail.valid)
                self.assertIn("TLS_UNTRUSTED_CA_OR_CHAIN_INVALID", env_tls_fail.error_codes)

    def test_08_unconfigured_live_environment_and_v1031_governance_invariants(self) -> None:
        self.assertTrue(TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["calendar_version"].startswith(("1.0.3", "1.0.4", "1.0.5")))
        self.assertTrue(PARSER_VERSION.startswith(("tr_diyanet_holiday_parser_v1.0.3", "tr_diyanet_holiday_parser_v1.0.4", "tr_diyanet_holiday_parser_v1.0.5")))

        # Live integration probe stays closed & honest when real services are unconfigured
        report = run_live_integration_probe(project_root=PROJECT_ROOT)
        self.assertTrue(report["schema_version"].startswith(("1.0.3", "1.0.4", "1.0.5")))
        self.assertEqual(report["overall_live_integration_status"], "NOT_CONFIGURED")
        self.assertFalse(report["production_use_authorized"])
        self.assertEqual(report["external_legal_counsel_signoff_status"], "PENDING_SIGNED_EXTERNAL_ATTESTATION")
        self.assertFalse(report["qualified_e_signature_5070_equivalent"])
        dec = report["production_authorization_decision"]
        self.assertEqual(dec["technical_verification_status"], "TECHNICAL_VERIFIED")
        self.assertEqual(dec["legal_counsel_attestation_status"], "PENDING_SIGNED_EXTERNAL_ATTESTATION")
        self.assertEqual(dec["kvkk_data_residency_status"], "PENDING_KVKK_M9_DATA_RESIDENCY_ASSESSMENT")
        self.assertEqual(dec["production_authorization_status"], "DENIED_MOCK_OR_UNCONFIGURED_PROVIDER")
        self.assertIn("SOURCE_ACQUISITION_EVIDENCE_MISSING", dec["blocking_codes"])

        # All Draft 2020-12 schemas (>=9) aligned to v1.0.3+ / v1.0.4 / v1.0.5
        schemas_dir = PROJECT_ROOT / "schemas"
        schema_files = sorted(schemas_dir.glob("*.schema.json"))
        self.assertGreaterEqual(len(schema_files), 9)
        for sf in schema_files:
            s_doc = json.loads(sf.read_text(encoding="utf-8"))
            self.assertEqual(s_doc["$schema"], "https://json-schema.org/draft/2020-12/schema", sf.name)
            self.assertTrue("(v1.0.3" in s_doc["title"] or "(v1.0.4" in s_doc["title"] or "(v1.0.5" in s_doc["title"], sf.name)

        # 74/74 central audit log & L1-L4 (30/5/39) preserved
        sources = load_source_registry(PROJECT_ROOT / "config" / "legal_sources_registry.json")
        precedents = load_precedent_registry(PROJECT_ROOT / "config" / "yargitay_precedents.json")
        cards = load_knowledge_cards(PROJECT_ROOT / "rag_kb", sources, precedents)
        self.assertEqual((len(sources), len(precedents), len(cards)), (30, 5, 39))

        audit_data = json.loads((PROJECT_ROOT / "config" / "verification_audit_log.json").read_text(encoding="utf-8"))
        self.assertTrue(audit_data["schema_version"].startswith(("1.0.3", "1.0.4", "1.0.5")))
        self.assertEqual(audit_data["summary"]["total_audited_records"], 74)
        self.assertEqual(audit_data["summary"]["fully_verified_records_count"], 70)
        self.assertEqual(audit_data["summary"]["pending_verification_records_count"], 3)
        self.assertEqual(audit_data["summary"]["superseded_records_count"], 1)
        self.assertTrue(validate_central_audit_log(audit_data, sources, precedents, cards).valid)


if __name__ == "__main__":
    unittest.main()
