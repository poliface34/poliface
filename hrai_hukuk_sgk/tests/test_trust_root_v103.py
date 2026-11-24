"""CALISORA @HukukSGK v1.0.3 Production Trust Root Integration Tests.

Explicitly separates:
  - `[MOCK]` offline provider, security, WORM, RFC 3161 TSA, external trust anchor, source acquisition,
    and 3-way production authorization gate tests (using ephemeral in-memory / OpenSSL 3 sandbox backends).
  - `[LIVE / NOT_CONFIGURED]` honest real-service integration probe tests verifying that absent GCP/TSA/WORM
    credentials NEVER produce false LIVE claims or `production_use_authorized=True`.
  - `[GOVERNANCE]` v1.0.3 scope boundary (no L5/L6 cards, no 5070 NES), 9 Draft 2020-12 schemas, 74/74 audit
    record preservation, and zero private keys across the repository.
"""

from __future__ import annotations

import ast
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from engine.attestation_verifier import (
    PARSER_VERSION,
    append_ledger_entry,
    build_calendar_attestation_signing_payload,
    compute_public_key_fingerprint,
    create_ledger_checkpoint,
    generate_ephemeral_keypair,
    sign_canonical_payload,
    verify_attestation_ledger_with_provider,
)
from engine.legal_reasoning import TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA
from engine.tools_router import HukukSGKToolRouter
from engine.trust_root import (
    DEFAULT_GCP_REGION,
    KVKK_DATA_RESIDENCY_NOTICE,
    LAW_5070_V103_BOUNDARY_NOTICE,
    TLS_NON_HISTORICAL_PROOF_NOTICE,
    DefaultProductionAuthorizationProvider,
    DefaultSourceAcquisitionProvider,
    EphemeralSandboxTsaResponder,
    ExternalTrustAnchorProvider,
    GcpCloudKmsSignerAdapter,
    GcpCloudStorageWormAdapter,
    GcpExternalTrustAnchorProvider,
    ImmutableEvidenceStorageProvider,
    InMemoryMockGcpKmsBackend,
    InMemoryMockGcpWormBackend,
    InMemoryMockPkcs11Session,
    KeySignerProvider,
    KvkkDataResidencyVerifier,
    LegalCounselAttestationVerifier,
    Pkcs11HsmSignerAdapter,
    ProductionAuthorizationProvider,
    Rfc3161TimestampAuthorityAdapter,
    SourceAcquisitionProvider,
    TechnicalVerificationService,
    TimestampAuthorityProvider,
    TlsCertificateInfo,
    build_and_seal_external_trust_anchor_manifest,
    build_kvkk_m9_assessment_signing_payload,
    compute_calendar_bundle_sha256,
    create_signed_legal_counsel_attestation_envelope,
    run_live_integration_probe,
)
from engine.knowledge_card_validator import load_knowledge_cards, validate_central_audit_log
from engine.precedent_verifier import load_precedent_registry
from engine.source_validator import load_source_registry

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestV103MockTrustRootProviders(unittest.TestCase):
    """[MOCK] Deterministic offline contract, cryptography, WORM, TSA & fail-closed security tests."""

    def test_01_mock_six_provider_agnostic_interfaces_and_zero_core_cloud_sdk_imports(self) -> None:
        # All 6 required provider-agnostic abstract interfaces are exported cleanly
        expected_interfaces = (
            KeySignerProvider,
            TimestampAuthorityProvider,
            ImmutableEvidenceStorageProvider,
            ExternalTrustAnchorProvider,
            SourceAcquisitionProvider,
            ProductionAuthorizationProvider,
        )
        for iface in expected_interfaces:
            self.assertTrue(hasattr(iface, "__abstractmethods__"), iface.__name__)
            self.assertGreater(len(iface.__abstractmethods__), 0, iface.__name__)

        # Core @HukukSGK engine modules MUST NOT contain any hard top-level imports of cloud/HSM SDKs
        forbidden_prefixes = ("google", "boto3", "botocore", "azure", "pkcs11", "PyKCS11")
        for py_file in sorted((PROJECT_ROOT / "engine").glob("*.py")):
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertFalse(
                            alias.name.startswith(forbidden_prefixes),
                            f"{py_file.name} doğrudan bulut/HSM SDK içe aktaramaz: {alias.name}",
                        )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    self.assertFalse(
                        node.module.startswith(forbidden_prefixes),
                        f"{py_file.name} doğrudan bulut/HSM SDK içe aktaramaz: {node.module}",
                    )

    def test_02_mock_gcp_cloud_kms_hsm_ed25519_rsa_pss_and_software_rejection(self) -> None:
        # Unconfigured GCP Cloud KMS honestly reports NOT_CONFIGURED
        unconf = GcpCloudKmsSignerAdapter()
        self.assertEqual(unconf.integration_mode, "NOT_CONFIGURED")
        hc_unconf = unconf.health_check()
        self.assertFalse(hc_unconf.configured)
        self.assertEqual(hc_unconf.integration_mode, "NOT_CONFIGURED")
        self.assertEqual(hc_unconf.region, DEFAULT_GCP_REGION)

        # Mock GCP Cloud KMS HSM backend (Frankfurt europe-west3)
        backend = InMemoryMockGcpKmsBackend(default_region="europe-west3")
        ed_key = "projects/calisora-sec-prod/locations/europe-west3/keyRings/trust-ring/cryptoKeys/ed-hsm/cryptoKeyVersions/1"
        rsa_key = "projects/calisora-sec-prod/locations/europe-west3/keyRings/trust-ring/cryptoKeys/rsa-hsm/cryptoKeyVersions/1"
        sw_key = "projects/calisora-sec-prod/locations/europe-west3/keyRings/trust-ring/cryptoKeys/sw-key/cryptoKeyVersions/1"

        backend.enroll_ephemeral_key(ed_key, algorithm="ED25519", protection_level="HSM")
        backend.enroll_ephemeral_key(rsa_key, algorithm="RSA-PSS-SHA256", protection_level="HSM")
        backend.enroll_ephemeral_key(sw_key, algorithm="ED25519", protection_level="SOFTWARE")

        kms = GcpCloudKmsSignerAdapter(
            project_id="calisora-sec-prod",
            region="europe-west3",
            key_ring="trust-ring",
            mock_backend=backend,
            require_hsm_in_production=True,
        )
        self.assertEqual(kms.integration_mode, "MOCK_SANDBOX")
        self.assertTrue(isinstance(kms, KeySignerProvider))

        sample_payload = {"schema": "TEST_V103", "year": 2028, "value": 1e-6}
        for key_ref, alg in ((ed_key, "ED25519"), (rsa_key, "RSA-PSS-SHA256")):
            env = kms.sign_canonical_json(sample_payload, key_ref, algorithm=alg, runtime_environment="PRODUCTION")
            self.assertTrue(env.valid, env.errors)
            self.assertEqual(env.protection_level, "HSM")
            self.assertEqual(env.canonicalization_standard, "RFC-8785-JCS")
            self.assertFalse(env.qualified_e_signature_5070_equivalent)
            self.assertEqual(env.integration_mode, "MOCK_SANDBOX")

            ok, msg, meta = kms.verify_canonical_json(
                sample_payload,
                env.signature_b64 or "",
                key_ref,
                algorithm=alg,
                runtime_environment="PRODUCTION",
            )
            self.assertTrue(ok, msg)
            self.assertIsNotNone(meta)
            self.assertTrue(meta.hsm_backed)  # type: ignore[union-attr]

            # Tampered payload must fail verification
            bad_ok, _, _ = kms.verify_canonical_json(
                {**sample_payload, "year": 2029},
                env.signature_b64 or "",
                key_ref,
                algorithm=alg,
                runtime_environment="PRODUCTION",
            )
            self.assertFalse(bad_ok)

        # SOFTWARE protection level MUST be rejected in PRODUCTION
        sw_env = kms.sign_canonical_json(sample_payload, sw_key, algorithm="ED25519", runtime_environment="PRODUCTION")
        self.assertFalse(sw_env.valid)
        self.assertIn("KMS_HSM_PROTECTION_REQUIRED_IN_PRODUCTION", sw_env.error_codes)

    def test_03_mock_pkcs11_hsm_alternative_adapter_and_not_configured_state(self) -> None:
        unconf = Pkcs11HsmSignerAdapter()
        self.assertEqual(unconf.integration_mode, "NOT_CONFIGURED")
        self.assertFalse(unconf.health_check().configured)

        sess = InMemoryMockPkcs11Session(token_label="CALISORA-TR-HSM-01", slot_id=1)
        ed_meta = sess.enroll_key_in_token("CALISORA-COUNSEL-ED25519", algorithm="ED25519")
        rsa_meta = sess.enroll_key_in_token("CALISORA-SEALER-RSAPSS", algorithm="RSA-PSS-SHA256")

        adapter = Pkcs11HsmSignerAdapter(mock_session=sess)
        self.assertEqual(adapter.integration_mode, "MOCK_SANDBOX")
        self.assertTrue(isinstance(adapter, KeySignerProvider))

        payload = {"doc": "CALISORA_PKCS11_PORTABILITY", "year": 2028}
        for key_ref, alg in ((ed_meta.key_resource_id, "ED25519"), (rsa_meta.key_resource_id, "RSA-PSS-SHA256")):
            env = adapter.sign_canonical_json(payload, key_ref, algorithm=alg, runtime_environment="PRODUCTION")
            self.assertTrue(env.valid, env.errors)
            self.assertEqual(env.protection_level, "HSM")
            self.assertFalse(env.qualified_e_signature_5070_equivalent)
            ok, msg, meta = adapter.verify_canonical_json(payload, env.signature_b64 or "", key_ref, algorithm=alg)
            self.assertTrue(ok, msg)
            self.assertIsNotNone(meta)
            self.assertTrue(meta.hsm_backed)  # type: ignore[union-attr]

    def test_04_mock_rfc3161_real_openssl_asn1_timestamp_and_tamper_rejection(self) -> None:
        # Unconfigured TSA honestly reports NOT_CONFIGURED
        unconf_tsa = Rfc3161TimestampAuthorityAdapter()
        self.assertEqual(unconf_tsa.integration_mode, "NOT_CONFIGURED")
        unconf_res = unconf_tsa.request_timestamp("a" * 64)
        self.assertFalse(unconf_res.valid)
        self.assertEqual(unconf_res.status, "NOT_CONFIGURED")

        # Real ASN.1 DER RFC 3161 TimeStampReq / TimeStampResp via OpenSSL 3 sandbox responder
        with EphemeralSandboxTsaResponder() as responder:
            tsa = Rfc3161TimestampAuthorityAdapter(
                tsa_url="https://mock-tsa.calisora.invalid/tsr",
                trusted_ca_pem=responder.ca_cert_pem,
                policy_oid=responder.policy_oid,
                http_transport=responder.transport,
            )
            self.assertEqual(tsa.integration_mode, "MOCK_SANDBOX")
            self.assertTrue(isinstance(tsa, TimestampAuthorityProvider))

            digest = hashlib.sha256(b"CALISORA_V103_RFC3161_EVIDENCE_PAYLOAD").hexdigest()
            res = tsa.request_timestamp(digest)
            self.assertTrue(res.valid, res.errors)
            self.assertEqual(res.status, "INDEPENDENT_TSA_VERIFIED")
            self.assertEqual(res.message_imprint_sha256, digest)
            self.assertIsNotNone(res.gen_time_utc)
            self.assertIsNotNone(res.serial_number)
            self.assertIsNotNone(res.tsr_der_b64)
            self.assertIsNotNone(res.tsa_cert_fingerprint_sha256)

            # 1-byte altered digest MUST fail OpenSSL ts -verify
            tsr_bytes = base64.b64decode(res.tsr_der_b64 or "", validate=True)
            wrong_digest = hashlib.sha256(b"CALISORA_V103_RFC3161_EVIDENCE_PAYLOAE").hexdigest()
            tampered_res = tsa.verify_timestamp_token(wrong_digest, tsr_bytes)
            self.assertFalse(tampered_res.valid)
            self.assertEqual(tampered_res.status, "TSA_FAILED")
            self.assertIn("RFC3161_TIMESTAMP_VERIFICATION_FAILED", tampered_res.error_codes)

    def test_05_mock_gcs_worm_bucket_lock_irreversible_guard_and_immutability(self) -> None:
        # Unconfigured WORM adapter honestly reports NOT_CONFIGURED
        unconf_worm = GcpCloudStorageWormAdapter()
        self.assertEqual(unconf_worm.integration_mode, "NOT_CONFIGURED")
        self.assertFalse(unconf_worm.health_check().configured)

        # Region policy mismatch rejected
        wrong_region_backend = InMemoryMockGcpWormBackend(
            project_id="calisora-sec-prod",
            bucket_name="calisora-worm-us",
            region="us-central1",
        )
        wrong_region_worm = GcpCloudStorageWormAdapter(
            mock_backend=wrong_region_backend,
            enforce_region="europe-west3",
        )
        bad_reg_rcpt = wrong_region_worm.put_immutable_object("evidence/a.bin", b"abc")
        self.assertFalse(bad_reg_rcpt.stored)
        self.assertIn("GCP_REGION_POLICY_MISMATCH", bad_reg_rcpt.error_codes)

        # Frankfurt (europe-west3) mock WORM bucket
        worm_backend = InMemoryMockGcpWormBackend(
            project_id="calisora-sec-prod",
            bucket_name="calisora-evidence-worm-eu-west3",
            region="europe-west3",
            retention_period_seconds=315360000,
            retention_policy_locked=False,
        )
        worm = GcpCloudStorageWormAdapter(mock_backend=worm_backend, enforce_region="europe-west3")
        self.assertTrue(isinstance(worm, ImmutableEvidenceStorageProvider))

        # Bucket Lock MUST refuse without explicit legal approval, approval reference & irreversible confirmation
        refuse_1 = worm.lock_retention_policy(315360000)
        self.assertFalse(refuse_1["locked"])
        self.assertEqual(refuse_1["error_code"], "BUCKET_LOCK_LEGAL_APPROVAL_REQUIRED")

        refuse_2 = worm.lock_retention_policy(
            315360000,
            confirm_irreversible_bucket_lock=True,
            legal_retention_policy_approved=False,
            approval_reference="HUKUK-RET-2026-01",
        )
        self.assertFalse(refuse_2["locked"])
        self.assertEqual(refuse_2["error_code"], "BUCKET_LOCK_LEGAL_APPROVAL_REQUIRED")

        # Put before Bucket Lock -> stored, but worm_immutable_verified is False until locked!
        rcpt_pre = worm.put_immutable_object("evidence/test_pre.raw", b"initial-bytes")
        self.assertTrue(rcpt_pre.stored)
        self.assertFalse(rcpt_pre.worm_immutable_verified)

        # Apply irreversible Bucket Lock with full legal approval
        locked_ok = worm.lock_retention_policy(
            315360000,
            confirm_irreversible_bucket_lock=True,
            legal_retention_policy_approved=True,
            approval_reference="HUKUK-RET-2026-01",
        )
        self.assertTrue(locked_ok["locked"])
        self.assertTrue(locked_ok["irreversible"])

        # Shortening locked retention policy MUST be rejected
        shorten = worm.lock_retention_policy(
            86400,
            confirm_irreversible_bucket_lock=True,
            legal_retention_policy_approved=True,
            approval_reference="HUKUK-RET-2026-02",
        )
        self.assertFalse(shorten["locked"])
        self.assertEqual(shorten["error_code"], "BUCKET_LOCK_CANNOT_SHORTEN_RETENTION")

        # Verify immutability after Bucket Lock
        ver = worm.verify_object_immutability(
            rcpt_pre.object_uri or "",
            expected_sha256=hashlib.sha256(b"initial-bytes").hexdigest(),
        )
        self.assertTrue(ver.worm_immutable_verified, ver.errors)

        # Overwrite MUST fail with WORM_IMMUTABILITY_VIOLATION
        overwrite = worm.put_immutable_object("evidence/test_pre.raw", b"tampered-bytes")
        self.assertFalse(overwrite.stored)
        self.assertIn("WORM_IMMUTABILITY_VIOLATION", overwrite.error_codes)

        # Delete MUST fail with WORM_IMMUTABILITY_VIOLATION
        with self.assertRaises(PermissionError) as ctx:
            worm_backend.delete_object("evidence/test_pre.raw")
        self.assertIn("WORM_IMMUTABILITY_VIOLATION", str(ctx.exception))

    def test_06_mock_external_trust_anchor_separate_project_negative_attacks_and_router_wiring(self) -> None:
        # Build a sealed 2028 attestation + signed checkpoint ledger in memory
        ledger = {
            "schema_version": "1.0.3",
            "ledger_id": "CALISORA-HOLIDAY-CALENDAR-ATTESTATION-LEDGER",
            "hash_algorithm": "SHA-256",
            "canonicalization_standard": "RFC-8785-JCS",
            "worm_storage_policy": "WORM_AND_INDEPENDENT_TSA_REQUIRED_FOR_PRODUCTION",
            "external_legal_counsel_signoff_status": "PENDING_SIGNED_EXTERNAL_ATTESTATION",
            "entries": [],
            "checkpoints": [],
        }
        counsel_priv, counsel_pub = generate_ephemeral_keypair("ED25519")
        sealer_priv, sealer_pub = generate_ephemeral_keypair("RSA-PSS-SHA256")
        approvers_reg = {
            "schema_version": "1.0.3",
            "key_management_policy": "EXTERNAL_KMS_HSM_REQUIRED_NO_PRIVATE_KEYS_IN_REPO",
            "test_sandbox_keys_allowed_in_production": False,
            "approvers": {
                "CALISORA-HUKUK-01": {
                    "approver_id": "CALISORA-HUKUK-01",
                    "display_name": "Yetkili İş Hukuku Müşaviri (Mock)",
                    "role": "EXTERNAL_LEGAL_COUNSEL",
                    "status": "ACTIVE",
                    "enrollment_status": "ENROLLED",
                    "key_trust_tier": "PRODUCTION_QUALIFIED_COUNSEL",
                    "key_management_mode": "EXTERNAL_KMS_HSM_REQUIRED",
                    "key_id": "KEY-COUNSEL-MOCK-1",
                    "key_version": "v1",
                    "key_algorithm": "ED25519",
                    "public_key_pem": counsel_pub,
                    "public_key_fingerprint_sha256": compute_public_key_fingerprint(counsel_pub),
                    "valid_from_utc": "2026-01-01T00:00:00Z",
                    "valid_until_utc": "2030-12-31T23:59:59Z",
                    "revoked_at_utc": None,
                    "revocation_reason": "NONE",
                    "authorized_scopes": ["HOLIDAY_CALENDAR_LEGAL_APPROVAL:2024-2030"],
                    "environment_restrictions": ["PRODUCTION", "STAGING"],
                    "qualified_e_signature_5070_equivalent": False,
                },
                "CALISORA-LEDGER-SEALER-01": {
                    "approver_id": "CALISORA-LEDGER-SEALER-01",
                    "display_name": "Denetim Zinciri Mühürleyici (Mock)",
                    "role": "AUDIT_LEDGER_CHECKPOINT_SIGNER",
                    "status": "ACTIVE",
                    "enrollment_status": "ENROLLED",
                    "key_trust_tier": "PRODUCTION_AUDIT_SEALER",
                    "key_management_mode": "EXTERNAL_KMS_HSM_REQUIRED",
                    "key_id": "KEY-SEALER-MOCK-1",
                    "key_version": "v1",
                    "key_algorithm": "RSA-PSS-SHA256",
                    "public_key_pem": sealer_pub,
                    "public_key_fingerprint_sha256": compute_public_key_fingerprint(sealer_pub),
                    "valid_from_utc": "2026-01-01T00:00:00Z",
                    "valid_until_utc": "2030-12-31T23:59:59Z",
                    "revoked_at_utc": None,
                    "revocation_reason": "NONE",
                    "authorized_scopes": ["AUDIT_CHECKPOINT_SEAL"],
                    "environment_restrictions": ["PRODUCTION", "STAGING"],
                    "qualified_e_signature_5070_equivalent": False,
                },
            },
        }
        append_ledger_entry(
            ledger,
            entry_id="LED-TEST-1",
            entry_type="TECHNICAL_SOURCE_VERIFICATION",
            payload={"year": 2028, "snapshot_id": "SNAP-2028-V1"},
            recorded_at_utc="2026-11-21T08:00:00Z",
        )
        cp = create_ledger_checkpoint(
            ledger,
            checkpoint_id="CHK-ANCHOR-TEST-1",
            checkpoint_scope="TEST_ANCHOR",
            nonce="NONCE-ANCHOR-TEST-0001",
            signer_approver_id="CALISORA-LEDGER-SEALER-01",
            key_id="KEY-SEALER-MOCK-1",
            key_version="v1",
            algorithm="RSA-PSS-SHA256",
            private_key_pem=sealer_priv,
            public_key_pem=sealer_pub,
            created_at_utc="2026-11-21T08:01:00Z",
        )

        # Configure mock separate-security-project KMS HSM + WORM + RFC 3161 TSA
        kms_backend = InMemoryMockGcpKmsBackend(default_region="europe-west3")
        anchor_key_ref = (
            "projects/calisora-sec-prod/locations/europe-west3/keyRings/anchor-ring/"
            "cryptoKeys/anchor-hsm/cryptoKeyVersions/1"
        )
        kms_backend.enroll_ephemeral_key(anchor_key_ref, algorithm="ED25519", protection_level="HSM")
        kms_signer = GcpCloudKmsSignerAdapter(
            project_id="calisora-sec-prod",
            region="europe-west3",
            key_ring="anchor-ring",
            mock_backend=kms_backend,
        )

        worm_backend = InMemoryMockGcpWormBackend(
            project_id="calisora-sec-prod",
            bucket_name="calisora-sec-trust-anchor-worm",
            region="europe-west3",
            retention_period_seconds=315360000,
            retention_policy_locked=True,
        )
        worm = GcpCloudStorageWormAdapter(mock_backend=worm_backend, enforce_region="europe-west3")

        with EphemeralSandboxTsaResponder() as tsa_resp:
            tsa = Rfc3161TimestampAuthorityAdapter(
                tsa_url="https://mock-tsa.calisora.invalid/tsr",
                trusted_ca_pem=tsa_resp.ca_cert_pem,
                http_transport=tsa_resp.transport,
            )

            # Same-project manifest creation MUST be rejected immediately
            with self.assertRaises(ValueError) as sp_err:
                build_and_seal_external_trust_anchor_manifest(
                    manifest_id="MAN-BAD-SAME-PROJ",
                    security_project_id="calisora-app-prod",
                    app_project_id="calisora-app-prod",
                    ledger_id=ledger["ledger_id"],
                    expected_checkpoint_head_hash=cp["head_entry_hash"],
                    expected_checkpoint_entry_count=cp["entry_count"],
                    expected_chain_digest_sha256=cp["chain_digest_sha256"],
                    independent_audit_log_ref="projects/calisora-app-prod/logs/audit-01",
                    object_name="anchors/bad.json",
                    nonce="NONCE-SAME-PROJ-0001",
                    signer=kms_signer,
                    signing_key_ref=anchor_key_ref,
                    worm_storage=worm,
                    tsa_provider=tsa,
                )
            self.assertIn("TRUST_ANCHOR_SAME_PROJECT_VIOLATION", str(sp_err.exception))

            # Positive separate security project manifest
            manifest, rcpt = build_and_seal_external_trust_anchor_manifest(
                manifest_id="MAN-V103-TRUST-ANCHOR-001",
                security_project_id="calisora-sec-prod",
                app_project_id="calisora-app-prod",
                ledger_id=ledger["ledger_id"],
                expected_checkpoint_head_hash=cp["head_entry_hash"],
                expected_checkpoint_entry_count=cp["entry_count"],
                expected_chain_digest_sha256=cp["chain_digest_sha256"],
                independent_audit_log_ref="projects/calisora-sec-prod/logs/cloudaudit.googleapis.com%2Factivity/entry-001",
                object_name="anchors/v103_trust_anchor.json",
                nonce="NONCE-ANCHOR-MANIFEST-0001",
                signer=kms_signer,
                signing_key_ref=anchor_key_ref,
                worm_storage=worm,
                tsa_provider=tsa,
            )
            self.assertTrue(rcpt["worm_immutable_verified"])
            self.assertTrue(manifest["read_only"])

            anchor_provider = GcpExternalTrustAnchorProvider(
                manifest_uri=rcpt["object_uri"],
                security_project_id="calisora-sec-prod",
                app_project_id="calisora-app-prod",
                worm_storage=worm,
                kms_signer=kms_signer,
                tsa_provider=tsa,
                require_tsa=True,
            )
            self.assertTrue(isinstance(anchor_provider, ExternalTrustAnchorProvider))

            rec = anchor_provider.fetch_and_verify_trust_anchor(
                ledger["ledger_id"],
                expected_app_project_id="calisora-app-prod",
                runtime_environment="PRODUCTION",
            )
            self.assertTrue(rec.valid, rec.errors)
            self.assertTrue(rec.read_only)
            self.assertTrue(rec.separate_security_project)
            self.assertTrue(rec.kms_signed)
            self.assertEqual(rec.kms_protection_level, "HSM")
            self.assertTrue(rec.worm_protected)
            self.assertTrue(rec.independent_audit_logged)
            self.assertTrue(rec.tsa_verified)

            # Verify ledger via verify_attestation_ledger_with_provider -> valid in MOCK, yet production_use_authorized=False!
            led_res = verify_attestation_ledger_with_provider(
                ledger,
                external_trust_anchor_provider=anchor_provider,
                approvers_registry=approvers_reg,
                runtime_environment="PRODUCTION",
                expected_app_project_id="calisora-app-prod",
            )
            self.assertTrue(led_res["valid"], led_res["errors"])
            self.assertTrue(led_res["externally_verified_immutable"])
            self.assertEqual(led_res["provider_integration_mode"], "MOCK_SANDBOX")
            self.assertFalse(led_res["production_use_authorized"])

            # Negative 1: In-app local JSON path MUST be rejected with TRUST_ANCHOR_IN_APP_JSON_FORBIDDEN
            local_anchor = GcpExternalTrustAnchorProvider(
                manifest_uri="config/calendar_attestation_ledger.json",
                security_project_id="calisora-sec-prod",
                app_project_id="calisora-app-prod",
                worm_storage=worm,
                kms_signer=kms_signer,
            )
            local_rec = local_anchor.fetch_and_verify_trust_anchor(ledger["ledger_id"])
            self.assertFalse(local_rec.valid)
            self.assertIn("TRUST_ANCHOR_IN_APP_JSON_FORBIDDEN", local_rec.error_codes)
            self.assertIn("EXTERNAL_TRUST_ANCHOR_UNAVAILABLE_OR_INVALID", local_rec.error_codes)

            # Negative 2: Unavailable / NOT_CONFIGURED trust anchor fails closed
            missing_anchor = GcpExternalTrustAnchorProvider()
            miss_res = verify_attestation_ledger_with_provider(
                ledger,
                external_trust_anchor_provider=missing_anchor,
                approvers_registry=approvers_reg,
            )
            self.assertFalse(miss_res["valid"])
            self.assertIn("EXTERNAL_TRUST_ANCHOR_UNAVAILABLE_OR_INVALID", miss_res["error_codes"])
            self.assertFalse(miss_res["production_use_authorized"])

            # Negative 3: Tampered manifest fields inside WORM object (read_only=False, missing audit log, bad KMS sig)
            tampered_man = deepcopy(manifest)
            tampered_man["read_only"] = False
            tampered_man["independent_audit_log_ref"] = "short"
            worm_backend.put_object(
                "anchors/tampered.json",
                json.dumps(tampered_man).encode("utf-8"),
                content_type="application/json",
            )
            tampered_anchor = GcpExternalTrustAnchorProvider(
                manifest_uri="gs://calisora-sec-trust-anchor-worm/anchors/tampered.json",
                security_project_id="calisora-sec-prod",
                app_project_id="calisora-app-prod",
                worm_storage=worm,
                kms_signer=kms_signer,
                tsa_provider=tsa,
            )
            tamp_rec = tampered_anchor.fetch_and_verify_trust_anchor(ledger["ledger_id"])
            self.assertFalse(tamp_rec.valid)
            self.assertIn("TRUST_ANCHOR_NOT_READ_ONLY", tamp_rec.error_codes)
            self.assertIn("TRUST_ANCHOR_MISSING_INDEPENDENT_AUDIT_LOG", tamp_rec.error_codes)
            self.assertIn("TRUST_ANCHOR_INVALID_KMS_SIGNATURE", tamp_rec.error_codes)

            # Negative 4: Unlocked WORM bucket rejected (TRUST_ANCHOR_NOT_WORM_PROTECTED)
            unlocked_backend = InMemoryMockGcpWormBackend(
                project_id="calisora-sec-prod",
                bucket_name="calisora-unlocked-bucket",
                region="europe-west3",
                retention_period_seconds=86400,
                retention_policy_locked=False,
            )
            unlocked_worm = GcpCloudStorageWormAdapter(mock_backend=unlocked_backend)
            unlocked_backend.put_object(
                "anchors/unlocked.json",
                json.dumps(manifest).encode("utf-8"),
                content_type="application/json",
            )
            unlocked_anchor = GcpExternalTrustAnchorProvider(
                manifest_uri="gs://calisora-unlocked-bucket/anchors/unlocked.json",
                security_project_id="calisora-sec-prod",
                app_project_id="calisora-app-prod",
                worm_storage=unlocked_worm,
                kms_signer=kms_signer,
                tsa_provider=tsa,
            )
            unl_rec = unlocked_anchor.fetch_and_verify_trust_anchor(ledger["ledger_id"])
            self.assertFalse(unl_rec.valid)
            self.assertIn("TRUST_ANCHOR_NOT_WORM_PROTECTED", unl_rec.error_codes)

            # End-to-end HukukSGKToolRouter fail-closed wiring with unconfigured external trust anchor
            router_fail_closed = HukukSGKToolRouter(
                external_trust_anchor_provider=missing_anchor,
                expected_app_project_id="calisora-app-prod",
            )
            snap_2028_html = (
                "<table><tr><th>Tarih</th><th>Gün</th></tr>"
                "<tr><td>26 Şubat 2028</td><td>Ramazan Bayramı Arifesi</td></tr>"
                "<tr><td>27 Şubat 2028</td><td>Ramazan Bayramı 1. Gün</td></tr>"
                "<tr><td>28 Şubat 2028</td><td>Ramazan Bayramı 2. Gün</td></tr>"
                "<tr><td>29 Şubat 2028</td><td>Ramazan Bayramı 3. Gün</td></tr>"
                "<tr><td>04 Mayıs 2028</td><td>Kurban Bayramı Arifesi</td></tr>"
                "<tr><td>05 Mayıs 2028</td><td>Kurban Bayramı 1. Gün</td></tr>"
                "<tr><td>06 Mayıs 2028</td><td>Kurban Bayramı 2. Gün</td></tr>"
                "<tr><td>07 Mayıs 2028</td><td>Kurban Bayramı 3. Gün</td></tr>"
                "<tr><td>08 Mayıs 2028</td><td>Kurban Bayramı 4. Gün</td></tr></table>"
            )
            snap_sha = hashlib.sha256(snap_2028_html.encode("utf-8")).hexdigest()
            cal_2028 = {
                "year": 2028,
                "official_source_url": "https://vakithesaplama.diyanet.gov.tr/icerik.php?icerik=155",
                "verified_at": "2026-11-21",
                "verified_by": "CALISORA-HUKUK-01",
                "calendar_version": "1.0.3",
                "source_document_sha256": snap_sha,
                "source_document_content": snap_2028_html,
                "ramazan_arife_date": "2028-02-26",
                "ramazan_start_date": "2028-02-27",
                "ramazan_end_date": "2028-02-29",
                "kurban_arife_date": "2028-05-04",
                "kurban_start_date": "2028-05-05",
                "kurban_end_date": "2028-05-08",
            }
            sig_payload = build_calendar_attestation_signing_payload(
                record_id="ATT-2028-ROUTER-1",
                nonce="NONCE-ROUTER-2028-0001",
                year=2028,
                calendar_record=cal_2028,
                source_document_sha256=snap_sha,
                approver_id="CALISORA-HUKUK-01",
                approved_at_utc="2026-11-21T08:00:00Z",
                key_id="KEY-COUNSEL-MOCK-1",
                key_version="v1",
                algorithm="ED25519",
            )
            sig_b64 = sign_canonical_payload(sig_payload, counsel_priv, algorithm="ED25519")
            cal_2028["legal_attestation"] = {
                "record_id": "ATT-2028-ROUTER-1",
                "nonce": "NONCE-ROUTER-2028-0001",
                "approver_id": "CALISORA-HUKUK-01",
                "approved_at_utc": "2026-11-21T08:00:00Z",
                "key_id": "KEY-COUNSEL-MOCK-1",
                "key_version": "v1",
                "algorithm": "ED25519",
                "public_key_fingerprint_sha256": compute_public_key_fingerprint(counsel_pub),
                "signature_b64": sig_b64,
                "ledger_entry_id": "LED-TEST-1",
                "qualified_e_signature_5070_equivalent": False,
            }
            ev = router_fail_closed.dispatch(
                "evaluate_hr_legal_scenario",
                {
                    "scenario_type": "TERMINATION_VALIDITY",
                    "as_of_date": "2028-03-05",
                    "facts": {
                        "termination_reason_type": "JUST_CAUSE_M25_II",
                        "workplace_total_employees": 120,
                        "tenure_months": 24,
                        "contract_term_type": "INDEFINITE",
                        "act_date": "2028-02-20",
                        "discovery_date": "2028-02-24",
                        "planned_termination_date": "2028-03-05",
                        "discovering_authority_status": "AUTHORIZED_TO_TERMINATE",
                        "written_notice_with_clear_reason": True,
                        "notification_channel": "WRITTEN_HAND_OR_NOTARY",
                        "external_verified_holiday_calendars": {"2028": cal_2028},
                        "authorized_approvers_registry": approvers_reg,
                        "calendar_attestation_ledger": ledger,
                        "runtime_environment": "PRODUCTION",
                    },
                },
            )
            self.assertTrue(ev["human_approval"]["counsel_escalation_required"])
            self.assertFalse(ev["human_approval"]["payroll_handoff_allowed"])
            all_risk_cats = [r["category"] for r in ev["risks"]]
            self.assertIn("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE", all_risk_cats)

    @staticmethod
    def _generate_ephemeral_test_ca_and_leaf(san_dns: str) -> tuple[str, str]:
        """Generate an ephemeral strict RFC 5280 CA cert PEM + leaf cert PEM in a temp dir for mock TLS verification."""
        from tests.pki_test_helpers import _MATERIAL_BANK

        slots: list[int] = []
        try:
            ca_slot, ca_key_bytes = _MATERIAL_BANK.acquire_rsa_key_slot()
            slots.append(ca_slot)
            leaf_slot, leaf_key_bytes = _MATERIAL_BANK.acquire_rsa_key_slot()
            slots.append(leaf_slot)
            with tempfile.TemporaryDirectory(prefix="calisora_test_x509_") as tmp:
                root = Path(tmp)
                ca_key, ca_cert = root / "ca.key", root / "ca.pem"
                leaf_key, leaf_csr, leaf_cert = root / "leaf.key", root / "leaf.csr", root / "leaf.pem"
                ca_key.write_bytes(ca_key_bytes)
                leaf_key.write_bytes(leaf_key_bytes)
                ca_cnf = root / "ca_req.cnf"
                ca_cnf.write_text(
                    "[req]\ndistinguished_name = dn\nx509_extensions = v3_ca\nprompt = no\n"
                    "[dn]\nCN = CALISORA-MOCK-ROOT-CA\nO = CALISORA-TEST-PKI\n"
                    "[v3_ca]\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid:always,issuer\n"
                    "basicConstraints = critical, CA:TRUE\nkeyUsage = critical, keyCertSign, cRLSign\n",
                    encoding="utf-8",
                )
                ext = root / "leaf.ext"
                ext.write_text(
                    "subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid,issuer\n"
                    "basicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature, keyEncipherment\n"
                    f"extendedKeyUsage = serverAuth\nsubjectAltName = DNS:{san_dns}\n",
                    encoding="utf-8",
                )
                cmds = [
                    ["openssl", "req", "-x509", "-key", str(ca_key),
                     "-config", str(ca_cnf), "-extensions", "v3_ca",
                     "-out", str(ca_cert), "-days", "30"],
                    ["openssl", "req", "-new", "-key", str(leaf_key),
                     "-out", str(leaf_csr), "-subj", f"/CN={san_dns}"],
                    ["openssl", "x509", "-req", "-in", str(leaf_csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
                     "-CAcreateserial", "-out", str(leaf_cert), "-days", "30", "-extfile", str(ext)],
                ]
                for cmd in cmds:
                    proc = subprocess.run(
                        cmd,
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                    if proc.returncode != 0:
                        raise RuntimeError(proc.stderr)
                return ca_cert.read_text(encoding="utf-8"), leaf_cert.read_text(encoding="utf-8")
        finally:
            for s in slots:
                _MATERIAL_BANK.release_rsa_key_slot(s)

    def test_07_mock_source_acquisition_evidence_envelope_and_tls_non_historical_proof_rule(self) -> None:
        # Use real archived 2026 Diyanet HTML snapshot bytes + real ephemeral X.509 CA/Leaf cert chain
        diyanet_2026_path = PROJECT_ROOT / "evidence" / "holiday_snapshots" / "diyanet_2026_v1.html"
        raw_html = diyanet_2026_path.read_bytes()
        ca_pem, leaf_pem = self._generate_ephemeral_test_ca_and_leaf("vakithesaplama.diyanet.gov.tr")

        kms_backend = InMemoryMockGcpKmsBackend(default_region="europe-west3")
        acq_key_ref = (
            "projects/calisora-sec-prod/locations/europe-west3/keyRings/acq-ring/"
            "cryptoKeys/source-acq-hsm/cryptoKeyVersions/1"
        )
        kms_backend.enroll_ephemeral_key(acq_key_ref, algorithm="ED25519", protection_level="HSM")
        kms_signer = GcpCloudKmsSignerAdapter(
            project_id="calisora-sec-prod",
            region="europe-west3",
            key_ring="acq-ring",
            mock_backend=kms_backend,
        )

        worm_backend = InMemoryMockGcpWormBackend(
            project_id="calisora-sec-prod",
            bucket_name="calisora-source-evidence-worm",
            region="europe-west3",
            retention_period_seconds=315360000,
            retention_policy_locked=True,
        )
        worm = GcpCloudStorageWormAdapter(mock_backend=worm_backend, enforce_region="europe-west3")

        def mock_diyanet_fetcher(url: str) -> dict:
            return {
                "raw_bytes": raw_html,
                "final_url": url,
                "redirect_chain": [url],
                "http_status": 200,
                "http_headers": {
                    "Content-Type": "text/html; charset=utf-8",
                    "Server": "diyanet-web",
                    "Date": "Sat, 21 Nov 2026 08:00:00 GMT",
                },
                "tls_certificate_info": {
                    "tls_version": "TLSv1.3",
                    "cipher_suite": "TLS_AES_256_GCM_SHA384",
                    "server_hostname": "vakithesaplama.diyanet.gov.tr",
                    "leaf_cert_pem": leaf_pem,
                },
                "acquired_at_utc": "2026-11-21T08:00:00Z",
            }

        with EphemeralSandboxTsaResponder() as tsa_resp:
            tsa = Rfc3161TimestampAuthorityAdapter(
                tsa_url="https://mock-tsa.calisora.invalid/tsr",
                trusted_ca_pem=tsa_resp.ca_cert_pem,
                http_transport=tsa_resp.transport,
            )
            acq = DefaultSourceAcquisitionProvider(
                worm_storage=worm,
                tsa_provider=tsa,
                kms_signer=kms_signer,
                signing_key_ref=acq_key_ref,
                algorithm="ED25519",
                mock_fetcher=mock_diyanet_fetcher,
                trusted_ca_pem=ca_pem,
            )
            self.assertTrue(isinstance(acq, SourceAcquisitionProvider))
            self.assertEqual(acq.integration_mode, "MOCK_SANDBOX")
            self.assertEqual(acq.fetcher_mode, "MOCK_CALLBACK")

            env = acq.acquire_and_seal_source(
                "DIYANET-2026",
                "https://vakithesaplama.diyanet.gov.tr/icerik.php?icerik=153",
                runtime_environment="PRODUCTION",
            )
            self.assertTrue(env.valid, env.errors)
            self.assertTrue(env.signature_verified)
            self.assertEqual(env.fetcher_mode, "MOCK_CALLBACK")
            self.assertFalse(env.production_tls_verified)
            self.assertEqual(env.raw_bytes_sha256, hashlib.sha256(raw_html).hexdigest())
            self.assertFalse(env.tls_alone_proves_historical_content)
            self.assertEqual(env.tls_non_historical_proof_notice, TLS_NON_HISTORICAL_PROOF_NOTICE)
            self.assertIsNotNone(env.worm_object_uri)
            self.assertIsNotNone(env.tsa_result)
            self.assertEqual(env.tsa_result["status"], "INDEPENDENT_TSA_VERIFIED")  # type: ignore[index]

            # Tampered raw bytes MUST fail verification
            bad_bytes_ver = acq.verify_acquisition_evidence(env, expected_raw_bytes=raw_html + b"x")
            self.assertFalse(bad_bytes_ver["valid"])
            self.assertIn("SOURCE_ACQUISITION_RAW_BYTES_MISMATCH", bad_bytes_ver["error_codes"])

            # Claiming TLS alone proves historical content MUST be rejected!
            bad_tls_dict = env.to_dict()
            bad_tls_dict["tls_alone_proves_historical_content"] = True
            bad_tls_ver = acq.verify_acquisition_evidence(bad_tls_dict, expected_raw_bytes=raw_html)
            self.assertFalse(bad_tls_ver["valid"])
            self.assertIn("INVALID_TLS_HISTORICAL_PROOF_CLAIM", bad_tls_ver["error_codes"])

            # Tampered TSA token MUST be rejected
            bad_tsa_dict = env.to_dict()
            bad_tsa_dict["tsa_result"]["tsr_der_b64"] = base64.b64encode(b"not-a-valid-tsr").decode("ascii")
            bad_tsa_ver = acq.verify_acquisition_evidence(bad_tsa_dict, expected_raw_bytes=raw_html)
            self.assertFalse(bad_tsa_ver["valid"])
            self.assertIn("SOURCE_ACQUISITION_TSA_MISSING_OR_INVALID", bad_tsa_ver["error_codes"])

    def test_08_mock_production_authorization_gate_three_way_separation_and_mock_denial(self) -> None:
        ledger = json.loads((PROJECT_ROOT / "config" / "calendar_attestation_ledger.json").read_text(encoding="utf-8"))
        approvers = json.loads((PROJECT_ROOT / "config" / "authorized_approvers.json").read_text(encoding="utf-8"))
        tr_cfg = json.loads((PROJECT_ROOT / "config" / "production_trust_root_config.json").read_text(encoding="utf-8"))
        tech_res = TechnicalVerificationService().verify_repository_technical_integrity(project_root=PROJECT_ROOT)
        self.assertTrue(tech_res.valid, tech_res.errors)

        # Case A: Unconfigured providers & no signed attestation -> TECHNICAL_VERIFIED + PENDING_SIGNED_EXTERNAL_ATTESTATION + DENIED
        gate_unconf = DefaultProductionAuthorizationProvider(
            kms_signer=GcpCloudKmsSignerAdapter(),
            tsa_provider=Rfc3161TimestampAuthorityAdapter(),
            worm_storage=GcpCloudStorageWormAdapter(),
            trust_anchor_provider=GcpExternalTrustAnchorProvider(),
            trust_root_config=tr_cfg,
            project_root=PROJECT_ROOT,
        )
        self.assertTrue(isinstance(gate_unconf, ProductionAuthorizationProvider))
        dec_a = gate_unconf.evaluate_production_authorization(
            ledger=ledger,
            approvers_registry=approvers,
            technical_verification_result=tech_res,
            legal_counsel_attestation_envelope=None,
            source_acquisition_envelope=None,
            kvkk_assessment_envelope=None,
            runtime_environment="PRODUCTION",
        )
        self.assertEqual(dec_a.technical_verification_status, "TECHNICAL_VERIFIED")
        self.assertEqual(dec_a.legal_counsel_attestation_status, "PENDING_SIGNED_EXTERNAL_ATTESTATION")
        self.assertEqual(dec_a.production_authorization_status, "DENIED_MOCK_OR_UNCONFIGURED_PROVIDER")
        self.assertFalse(dec_a.production_use_authorized)
        self.assertEqual(dec_a.external_legal_counsel_signoff_status, "PENDING_SIGNED_EXTERNAL_ATTESTATION")
        self.assertFalse(dec_a.qualified_e_signature_5070_equivalent)
        self.assertEqual(dec_a.kvkk_data_residency_status, "PENDING_KVKK_M9_DATA_RESIDENCY_ASSESSMENT")
        self.assertIn("LIVE_PRODUCTION_PROVIDERS_REQUIRED", dec_a.blocking_codes)
        self.assertIn("EXTERNAL_LEGAL_COUNSEL_ATTESTATION_REQUIRED", dec_a.blocking_codes)
        self.assertIn("SOURCE_ACQUISITION_EVIDENCE_MISSING", dec_a.blocking_codes)
        self.assertIn("KVKK_DATA_RESIDENCY_ASSESSMENT_PENDING", dec_a.blocking_codes)

        # Case B: Even with genuine cryptographically verified counsel attestation & KVKK approval, MOCK_SANDBOX providers NEVER authorize production!
        counsel_priv, counsel_pub = generate_ephemeral_keypair("ED25519")
        counsel_fp = compute_public_key_fingerprint(counsel_pub)
        mock_approvers = deepcopy(approvers)
        mock_approvers["approvers"]["CALISORA-HUKUK-01"].update(
            {
                "enrollment_status": "ENROLLED",
                "key_id": "KEY-COUNSEL-V103-MOCK",
                "public_key_pem": counsel_pub,
                "public_key_fingerprint_sha256": counsel_fp,
                "authorized_scopes": [
                    "HOLIDAY_CALENDAR_LEGAL_APPROVAL:2024-2030",
                    "KVKK_M9_DATA_RESIDENCY_APPROVAL",
                ],
            }
        )
        signed_legal_env = create_signed_legal_counsel_attestation_envelope(
            attestation_id="ATT-REL-MOCK-001",
            nonce="NONCE-REL-MOCK-0001",
            approver_id="CALISORA-HUKUK-01",
            key_id="KEY-COUNSEL-V103-MOCK",
            key_version="v1",
            algorithm="ED25519",
            signed_at_utc="2026-11-21T10:00:00Z",
            calendar_version=tech_res.calendar_version,
            calendar_sha256=tech_res.calendar_sha256,
            hukuk_sgk_version=tech_res.hukuk_sgk_version,
            authorized_scope="HOLIDAY_CALENDAR_LEGAL_APPROVAL:2024-2030",
            private_key_pem=counsel_priv,
            public_key_fingerprint_sha256=counsel_fp,
        )
        kvkk_payload = build_kvkk_m9_assessment_signing_payload(
            assessment_reference="KVKK-M9-2026-MOCK-01",
            nonce="NONCE-KVKK-MOCK-0001",
            primary_region="europe-west3",
            kvkk_m9_decision="APPROVED",
            approver_id="CALISORA-HUKUK-01",
            key_id="KEY-COUNSEL-V103-MOCK",
            key_version="v1",
            algorithm="ED25519",
            approved_at_utc="2026-11-21T10:00:00Z",
        )
        kvkk_env = {
            **kvkk_payload,
            "signature_b64": sign_canonical_payload(kvkk_payload, counsel_priv, algorithm="ED25519"),
        }
        tr_cfg_mock_approved = deepcopy(tr_cfg)
        tr_cfg_mock_approved["kvkk_and_data_residency"]["kvkk_m9_assessment_approved"] = True

        kms_backend = InMemoryMockGcpKmsBackend()
        key_ref = "projects/calisora-sec-prod/locations/europe-west3/keyRings/r1/cryptoKeys/k1/cryptoKeyVersions/1"
        kms_backend.enroll_ephemeral_key(key_ref, algorithm="ED25519", protection_level="HSM")
        kms_mock = GcpCloudKmsSignerAdapter(project_id="calisora-sec-prod", key_ring="r1", mock_backend=kms_backend)
        worm_mock = GcpCloudStorageWormAdapter(
            mock_backend=InMemoryMockGcpWormBackend(
                project_id="calisora-sec-prod",
                bucket_name="b1",
                region="europe-west3",
                retention_period_seconds=86400,
                retention_policy_locked=True,
            )
        )
        with EphemeralSandboxTsaResponder() as tsa_resp:
            tsa_mock = Rfc3161TimestampAuthorityAdapter(
                tsa_url="https://mock-tsa.calisora.invalid/tsr",
                trusted_ca_pem=tsa_resp.ca_cert_pem,
                http_transport=tsa_resp.transport,
            )
            anchor_mock = GcpExternalTrustAnchorProvider(
                manifest_uri="gs://b1/m.json",
                security_project_id="calisora-sec-prod",
                app_project_id="calisora-app-prod",
                worm_storage=worm_mock,
                kms_signer=kms_mock,
                tsa_provider=tsa_mock,
            )
            gate_mock = DefaultProductionAuthorizationProvider(
                kms_signer=kms_mock,
                tsa_provider=tsa_mock,
                worm_storage=worm_mock,
                trust_anchor_provider=anchor_mock,
                trust_root_config=tr_cfg_mock_approved,
                project_root=PROJECT_ROOT,
            )
            dec_b = gate_mock.evaluate_production_authorization(
                ledger=ledger,
                approvers_registry=mock_approvers,
                technical_verification_result=tech_res,
                legal_counsel_attestation_envelope=signed_legal_env,
                source_acquisition_envelope=None,
                kvkk_assessment_envelope=kvkk_env,
                runtime_environment="PRODUCTION",
            )
            self.assertEqual(dec_b.technical_verification_status, "TECHNICAL_VERIFIED")
            self.assertEqual(dec_b.legal_counsel_attestation_status, "SIGNED_LEGAL_ATTESTATION_VERIFIED")
            self.assertEqual(dec_b.kvkk_data_residency_status, "APPROVED")
            self.assertEqual(dec_b.production_authorization_status, "DENIED_MOCK_OR_UNCONFIGURED_PROVIDER")
            self.assertFalse(dec_b.production_use_authorized)
            self.assertFalse(dec_b.qualified_e_signature_5070_equivalent)
            self.assertIn("LIVE_PRODUCTION_PROVIDERS_REQUIRED", dec_b.blocking_codes)


class TestV103LiveIntegrationProbeAndGovernance(unittest.TestCase):
    """[LIVE / NOT_CONFIGURED] Honest live probe & [GOVERNANCE] v1.0.3+ boundary/schema/74-record verification."""

    def test_09_live_integration_probe_honestly_reports_not_configured(self) -> None:
        report = run_live_integration_probe(project_root=PROJECT_ROOT)
        self.assertTrue(report["schema_version"].startswith(("1.0.3", "1.0.4", "1.0.5")))
        self.assertEqual(report["region"], "europe-west3")
        self.assertEqual(report["overall_live_integration_status"], "NOT_CONFIGURED")
        self.assertFalse(report["production_use_authorized"])
        self.assertEqual(report["external_legal_counsel_signoff_status"], "PENDING_SIGNED_EXTERNAL_ATTESTATION")
        self.assertFalse(report["qualified_e_signature_5070_equivalent"])
        self.assertEqual(report["law_5070_boundary_notice"], LAW_5070_V103_BOUNDARY_NOTICE)
        self.assertEqual(report["kvkk_data_residency_notice"], KVKK_DATA_RESIDENCY_NOTICE)

        # Every live service MUST honestly report NOT_CONFIGURED when real credentials/endpoints are absent
        for svc_name, svc_info in report["live_services"].items():
            self.assertEqual(svc_info["integration_mode"], "NOT_CONFIGURED", svc_name)
            self.assertFalse(svc_info["configured"], svc_name)

        dec = report["production_authorization_decision"]
        self.assertEqual(dec["technical_verification_status"], "TECHNICAL_VERIFIED")
        self.assertEqual(dec["legal_counsel_attestation_status"], "PENDING_SIGNED_EXTERNAL_ATTESTATION")
        self.assertEqual(dec["production_authorization_status"], "DENIED_MOCK_OR_UNCONFIGURED_PROVIDER")
        self.assertFalse(dec["production_use_authorized"])

    def test_10_governance_v103_9_schemas_scope_boundary_74_records_and_zero_private_keys(self) -> None:
        self.assertTrue(TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["calendar_version"].startswith(("1.0.3", "1.0.4", "1.0.5")))
        self.assertTrue(PARSER_VERSION.startswith(("tr_diyanet_holiday_parser_v1.0.3", "tr_diyanet_holiday_parser_v1.0.4", "tr_diyanet_holiday_parser_v1.0.5")))

        # Core 9 Draft 2020-12 JSON Schemas preserved and aligned to v1.0.3+ / v1.0.4 / v1.0.5
        expected_schemas = {
            "legal_source_registry.schema.json",
            "yargitay_precedent_registry.schema.json",
            "legal_knowledge_card.schema.json",
            "legal_scenario_evaluation.schema.json",
            "authorized_approvers.schema.json",
            "calendar_attestation_ledger.schema.json",
            "trust_root_config.schema.json",
            "source_acquisition_evidence.schema.json",
            "external_trust_anchor_manifest.schema.json",
        }
        actual_schemas = {p.name for p in (PROJECT_ROOT / "schemas").glob("*.schema.json")}
        self.assertTrue(expected_schemas.issubset(actual_schemas))
        for s_name in expected_schemas:
            s_doc = json.loads((PROJECT_ROOT / "schemas" / s_name).read_text(encoding="utf-8"))
            self.assertEqual(s_doc["$schema"], "https://json-schema.org/draft/2020-12/schema", s_name)
            self.assertTrue("(v1.0.3" in s_doc["title"] or "(v1.0.4" in s_doc["title"] or "(v1.0.5" in s_doc["title"], s_name)

        # production_trust_root_config.json checks
        tr_cfg = json.loads((PROJECT_ROOT / "config" / "production_trust_root_config.json").read_text(encoding="utf-8"))
        self.assertTrue(tr_cfg["schema_version"].startswith(("1.0.3", "1.0.4", "1.0.5")))
        self.assertEqual(tr_cfg["deployment_status"], "NOT_CONFIGURED")
        self.assertEqual(tr_cfg["gcp_primary"]["region"], "europe-west3")
        self.assertEqual(tr_cfg["gcp_primary"]["cloud_kms"]["protection_level"], "HSM")
        self.assertFalse(tr_cfg["gcp_primary"]["cloud_storage_worm"]["bucket_lock_applied"])
        self.assertFalse(tr_cfg["gcp_primary"]["cloud_storage_worm"]["legal_retention_policy_approved"])
        self.assertFalse(tr_cfg["kvkk_and_data_residency"]["kvkk_m9_assessment_approved"])
        self.assertFalse(tr_cfg["law_5070_scope_boundary"]["qualified_e_signature_5070_equivalent"])
        self.assertEqual(tr_cfg["law_5070_scope_boundary"]["nes_cades_xades_target_release"], "1.0.4")
        self.assertFalse(tr_cfg["production_authorization_policy"]["production_use_authorized"])
        self.assertEqual(
            tr_cfg["production_authorization_policy"]["external_legal_counsel_signoff_status"],
            "PENDING_SIGNED_EXTERNAL_ATTESTATION",
        )
        self.assertFalse(tr_cfg["production_authorization_policy"]["tls_alone_proves_historical_content"])

        # v1.0.5: L5/L6 active as strictly separated unadopted templates; L1-L4 30/5/39 and 74/74 untouched
        tax = json.loads((PROJECT_ROOT / "config" / "knowledge_taxonomy.json").read_text(encoding="utf-8"))
        self.assertTrue(tax["schema_version"].startswith(("1.0.3", "1.0.4", "1.0.5")))
        for layer in tax["knowledge_layers"]:
            if layer["id"] == "L5_HR_PROCEDURES":
                self.assertEqual(
                    layer["population_status"],
                    "POPULATED_5_CORPORATE_HR_PROCEDURES_REFERENCE_TEMPLATES_V1_0_5",
                )
            elif layer["id"] == "L6_CBA_CONTRACTS_AND_WORKPLACE_PRACTICES":
                self.assertEqual(
                    layer["population_status"],
                    "POPULATED_4_DISTINCT_AUTONOMOUS_NORM_MODULES_REFERENCE_TEMPLATES_V1_0_5",
                )
        self.assertTrue((PROJECT_ROOT / "rag_kb" / "05_ik_prosedurleri").is_dir())
        self.assertTrue((PROJECT_ROOT / "rag_kb" / "06_tis_sozlesme_ve_isyeri_uygulamalari").is_dir())

        sources = load_source_registry(PROJECT_ROOT / "config" / "legal_sources_registry.json")
        precedents = load_precedent_registry(PROJECT_ROOT / "config" / "yargitay_precedents.json")
        cards = load_knowledge_cards(PROJECT_ROOT / "rag_kb", sources, precedents)
        self.assertEqual(len(sources), 30)
        self.assertEqual(len(precedents), 5)
        self.assertEqual(len(cards), 39)

        audit_data = json.loads((PROJECT_ROOT / "config" / "verification_audit_log.json").read_text(encoding="utf-8"))
        self.assertTrue(audit_data["schema_version"].startswith(("1.0.3", "1.0.4", "1.0.5")))
        self.assertEqual(audit_data["summary"]["total_audited_records"], 74)
        self.assertEqual(audit_data["summary"]["fully_verified_records_count"], 70)
        self.assertEqual(audit_data["summary"]["pending_verification_records_count"], 3)
        self.assertEqual(audit_data["summary"]["superseded_records_count"], 1)
        rep = validate_central_audit_log(audit_data, sources, precedents, cards)
        self.assertTrue(rep.valid, rep.flags)

        # Zero private keys anywhere in repository (markers built dynamically across separate tokens)
        pem_prefix = "-----" + "BEGIN "
        pem_suffix = "PRIVATE" + " KEY-----"
        priv_markers = [
            f"{pem_prefix}{kind}{pem_suffix}"
            for kind in ("", "RSA ", "EC ", "ENCRYPTED ", "OPENSSH ")
        ]
        for path in PROJECT_ROOT.rglob("*"):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            if path.suffix.lower() in {".py", ".json", ".md", ".html", ".txt", ".pem", ".key"}:
                content = path.read_text(encoding="utf-8", errors="ignore")
                for marker in priv_markers:
                    self.assertNotIn(marker, content, f"Özel anahtar izi tespit edildi: {path}")


if __name__ == "__main__":
    unittest.main()
