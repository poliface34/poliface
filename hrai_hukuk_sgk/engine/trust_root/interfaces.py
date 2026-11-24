"""Provider-agnostic abstract interfaces for CALISORA @HukukSGK v1.0.3.1 Production Trust Root Integration.

The 6 core provider-agnostic interfaces keep `@HukukSGK` completely decoupled from cloud or HSM SDKs:
  1. KeySignerProvider               (Primary: GCP Cloud KMS HSM; Alternative: PKCS#11 HSM)
  2. TimestampAuthorityProvider      (Independent RFC 3161 TSA)
  3. ImmutableEvidenceStorageProvider (Primary: GCP Cloud Storage + Bucket Lock WORM)
  4. ExternalTrustAnchorProvider     (Separate security project, read-only, KMS-signed, WORM-backed, audit-logged)
  5. SourceAcquisitionProvider       (Diyanet / Official Gazette real HTTPS/TLS + WORM + TSA + KMS evidence)
  6. ProductionAuthorizationProvider (Fail-closed 3-way gate consuming ONLY cryptographic verification results, NEVER caller booleans)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from .models import (
    ExternalTrustAnchorRecord,
    KeyMetadata,
    KvkkDataResidencyVerificationResult,
    LegalCounselAttestationVerificationResult,
    ProductionAuthorizationDecision,
    ProviderHealthStatus,
    SignatureEnvelope,
    SourceAcquisitionEvidenceEnvelope,
    SourceAcquisitionVerificationResult,
    TechnicalVerificationResult,
    TimestampTokenResult,
    WormObjectReceipt,
)


class KeySignerProvider(ABC):
    """Provider-agnostic asymmetric signing & verification interface (Ed25519 / RSA-PSS-SHA256 over RFC 8785 JCS).

    Private key material MUST NEVER leave the KMS/HSM boundary into application memory or files.
    KMS/HSM signatures are technical integrity/authentication proofs and are NEVER equivalent to
    Law No. 5070 Qualified Electronic Signatures (NES).
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human/audit identifier of this signer backend."""

    @property
    @abstractmethod
    def integration_mode(self) -> str:
        """One of `LIVE_PRODUCTION`, `MOCK_SANDBOX`, or `NOT_CONFIGURED`."""

    @abstractmethod
    def health_check(self) -> ProviderHealthStatus:
        """Report honest configuration/reachability status without fabricating live connectivity."""

    @abstractmethod
    def get_key_metadata(self, key_ref: str) -> KeyMetadata | None:
        """Return public key PEM, SHA-256 fingerprint, algorithm, and HSM protection level."""

    @abstractmethod
    def sign_canonical_json(
        self,
        payload: dict[str, Any],
        key_ref: str,
        algorithm: str = "ED25519",
        *,
        runtime_environment: str = "PRODUCTION",
    ) -> SignatureEnvelope:
        """Sign RFC 8785 (JCS) canonical JSON bytes inside KMS/HSM and return a structured SignatureEnvelope."""

    @abstractmethod
    def verify_canonical_json(
        self,
        payload: dict[str, Any],
        signature_b64: str,
        key_ref: str,
        algorithm: str = "ED25519",
        *,
        runtime_environment: str = "PRODUCTION",
    ) -> tuple[bool, str, KeyMetadata | None]:
        """Verify an asymmetric signature over RFC 8785 (JCS) canonical JSON bytes against KMS/HSM public key."""


class TimestampAuthorityProvider(ABC):
    """Provider-agnostic independent RFC 3161 Time-Stamp Authority (TSA) interface."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Identifier of the TSA provider."""

    @property
    @abstractmethod
    def integration_mode(self) -> str:
        """One of `LIVE_PRODUCTION`, `MOCK_SANDBOX`, or `NOT_CONFIGURED`."""

    @abstractmethod
    def health_check(self) -> ProviderHealthStatus:
        """Report honest configuration/reachability status."""

    @abstractmethod
    def build_timestamp_request(self, digest_sha256_hex: str, *, nonce_bytes: bytes | None = None) -> tuple[bytes, str]:
        """Build a DER-encoded RFC 3161 TimeStampReq for a 64-char SHA-256 hex digest; returns `(tsq_der, nonce_hex)`."""

    @abstractmethod
    def request_timestamp(self, digest_sha256_hex: str) -> TimestampTokenResult:
        """Request and cryptographically verify an RFC 3161 TimeStampResp for the given SHA-256 digest."""

    @abstractmethod
    def verify_timestamp_token(
        self,
        digest_sha256_hex: str,
        tsr_der_bytes: bytes,
        *,
        trusted_ca_pem: str | None = None,
        expected_nonce_hex: str | None = None,
    ) -> TimestampTokenResult:
        """Cryptographically verify a DER-encoded RFC 3161 TimeStampResp against a trusted TSA CA bundle."""


class ImmutableEvidenceStorageProvider(ABC):
    """Provider-agnostic WORM (Write Once Read Many) immutable evidence storage interface."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Identifier of the immutable storage provider."""

    @property
    @abstractmethod
    def integration_mode(self) -> str:
        """One of `LIVE_PRODUCTION`, `MOCK_SANDBOX`, or `NOT_CONFIGURED`."""

    @abstractmethod
    def health_check(self) -> ProviderHealthStatus:
        """Report honest configuration/reachability/retention-lock status."""

    @abstractmethod
    def put_immutable_object(
        self,
        object_name: str,
        data: bytes,
        *,
        content_type: str = "application/octet-stream",
        metadata: dict[str, str] | None = None,
    ) -> WormObjectReceipt:
        """Write an immutable evidence object; MUST reject overwrites on existing immutable objects."""

    @abstractmethod
    def get_object_bytes(self, object_uri_or_name: str) -> tuple[bytes | None, WormObjectReceipt | None, str | None]:
        """Retrieve immutable object bytes along with its WORM receipt metadata."""

    @abstractmethod
    def verify_object_immutability(
        self,
        object_uri_or_name: str,
        *,
        expected_sha256: str | None = None,
    ) -> WormObjectReceipt:
        """Verify object existence, SHA-256 integrity, and active WORM/retention immutability."""

    @abstractmethod
    def lock_retention_policy(
        self,
        retention_period_seconds: int,
        *,
        confirm_irreversible_bucket_lock: bool = False,
        legal_retention_policy_approved: bool = False,
        approval_reference: str | None = None,
    ) -> dict[str, Any]:
        """Permanently lock bucket retention policy ONLY with explicit legal approval & irreversible confirmation."""


class ExternalTrustAnchorProvider(ABC):
    """Provider-agnostic out-of-band external trust anchor reader & verifier.

    Checkpoint anchors (`expected_checkpoint_head_hash`, `expected_checkpoint_entry_count`,
    `expected_chain_digest_sha256`) MUST NEVER be read from mutable in-application JSON files.
    Must fail closed if the external trust root is unavailable or fails verification.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Identifier of the external trust anchor provider."""

    @property
    @abstractmethod
    def integration_mode(self) -> str:
        """One of `LIVE_PRODUCTION`, `MOCK_SANDBOX`, or `NOT_CONFIGURED`."""

    @abstractmethod
    def health_check(self) -> ProviderHealthStatus:
        """Report honest configuration/reachability status."""

    @abstractmethod
    def fetch_and_verify_trust_anchor(
        self,
        ledger_id: str,
        *,
        expected_app_project_id: str | None = None,
        runtime_environment: str = "PRODUCTION",
    ) -> ExternalTrustAnchorRecord:
        """Fetch and cryptographically verify the read-only, KMS-signed, WORM-stored manifest from a separate security project."""


class SourceAcquisitionProvider(ABC):
    """Provider-agnostic official source acquisition evidence collector & verifier (Diyanet / Resmî Gazete)."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Identifier of the acquisition provider."""

    @property
    @abstractmethod
    def integration_mode(self) -> str:
        """One of `LIVE_PRODUCTION`, `MOCK_SANDBOX`, or `NOT_CONFIGURED`."""

    @abstractmethod
    def health_check(self) -> ProviderHealthStatus:
        """Report honest configuration/reachability status."""

    @abstractmethod
    def acquire_and_seal_source(
        self,
        source_id: str,
        source_url: str,
        *,
        runtime_environment: str = "PRODUCTION",
    ) -> SourceAcquisitionEvidenceEnvelope:
        """Acquire raw bytes + HTTPS-only redirect chain + HTTP headers + real X.509 TLS verification, store in WORM, TSA-timestamp, and KMS-sign."""

    @abstractmethod
    def verify_acquisition_evidence_result(
        self,
        envelope: SourceAcquisitionEvidenceEnvelope | dict[str, Any],
        *,
        expected_raw_bytes: bytes | None = None,
        runtime_environment: str = "PRODUCTION",
    ) -> SourceAcquisitionVerificationResult:
        """Return an unforgeable service-sealed `SourceAcquisitionVerificationResult` after verifying raw bytes, WORM, TSA, KMS, and TLS."""

    @abstractmethod
    def verify_acquisition_evidence(
        self,
        envelope: SourceAcquisitionEvidenceEnvelope | dict[str, Any],
        *,
        expected_raw_bytes: bytes | None = None,
        runtime_environment: str = "PRODUCTION",
    ) -> dict[str, Any]:
        """Independently verify raw bytes SHA-256, WORM integrity, RFC 3161 TSA token, KMS signature, and TLS verification."""


class ProductionAuthorizationProvider(ABC):
    """Provider-agnostic 3-way production authorization gate consuming ONLY verified cryptographic results (NEVER caller booleans)."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Identifier of the authorization gate provider."""

    @property
    @abstractmethod
    def integration_mode(self) -> str:
        """One of `LIVE_PRODUCTION`, `MOCK_SANDBOX`, or `NOT_CONFIGURED`."""

    @abstractmethod
    def evaluate_production_authorization(
        self,
        *,
        ledger: dict[str, Any],
        approvers_registry: dict[str, Any] | None,
        technical_verification_result: TechnicalVerificationResult | None = None,
        legal_counsel_attestation_envelope: dict[str, Any] | None = None,
        legal_counsel_attestation_result: LegalCounselAttestationVerificationResult | None = None,
        source_acquisition_envelope: SourceAcquisitionEvidenceEnvelope | dict[str, Any] | None = None,
        source_acquisition_expected_raw_bytes: bytes | None = None,
        source_acquisition_result: SourceAcquisitionVerificationResult | None = None,
        kvkk_assessment_envelope: dict[str, Any] | None = None,
        kvkk_residency_result: KvkkDataResidencyVerificationResult | None = None,
        runtime_environment: str = "PRODUCTION",
        expected_app_project_id: str | None = None,
        **forbidden_caller_claims: Any,
    ) -> ProductionAuthorizationDecision:
        """Compute explicit 3-way production authorization decision; fails closed on any unmet check or caller-supplied boolean claim."""
