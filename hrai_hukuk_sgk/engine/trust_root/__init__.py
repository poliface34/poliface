"""CALISORA @HukukSGK v1.0.3.1 — Provider-Agnostic Production Trust Root Integration Package.

Exports the 6 core provider-agnostic interfaces, primary GCP Frankfurt (`europe-west3`) adapters,
alternative PKCS#11 HSM adapter, independent RFC 3161 TSA adapter, real HTTPS/TLS source acquisition
provider, external trust anchor provider, unforgeable cryptographic verification services, hardened
3-way production authorization gate, and live integration probe.
"""

from .external_trust_anchor import (
    GcpExternalTrustAnchorProvider,
    build_and_seal_external_trust_anchor_manifest,
    build_trust_anchor_manifest_signing_payload,
)
from .gcp_adapters import (
    GCP_KMS_KEY_VERSION_RE,
    GCS_URI_RE,
    GcpCloudKmsSignerAdapter,
    GcpCloudStorageWormAdapter,
    InMemoryMockGcpKmsBackend,
    InMemoryMockGcpWormBackend,
)
from .interfaces import (
    ExternalTrustAnchorProvider,
    ImmutableEvidenceStorageProvider,
    KeySignerProvider,
    ProductionAuthorizationProvider,
    SourceAcquisitionProvider,
    TimestampAuthorityProvider,
)
from .models import (
    DEFAULT_GCP_REGION,
    KVKK_DATA_RESIDENCY_NOTICE,
    LAW_5070_V103_BOUNDARY_NOTICE,
    TLS_NON_HISTORICAL_PROOF_NOTICE,
    TRUST_ROOT_VERSION,
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
    TlsCertificateInfo,
    TlsVerificationResult,
    WormObjectReceipt,
)
from .pkcs11_adapter import InMemoryMockPkcs11Session, Pkcs11HsmSignerAdapter
from .production_gate import DefaultProductionAuthorizationProvider
from .rfc3161_tsa import EphemeralSandboxTsaResponder, Rfc3161TimestampAuthorityAdapter
from .source_acquisition import (
    DEFAULT_ALLOWED_OFFICIAL_DOMAINS,
    DefaultSourceAcquisitionProvider,
    LiveHttpsSourceFetcher,
    SourceAcquisitionSecurityError,
    build_acquisition_signing_payload,
    validate_official_https_url,
    verify_tls_peer_certificate_chain,
)
from .verification_services import (
    KvkkDataResidencyVerifier,
    LegalCounselAttestationVerifier,
    TechnicalVerificationService,
    build_kvkk_m9_assessment_signing_payload,
    build_legal_counsel_release_attestation_signing_payload,
    compute_calendar_bundle_sha256,
    create_signed_legal_counsel_attestation_envelope,
    verify_service_result_authenticity,
)

__all__ = [
    "DEFAULT_ALLOWED_OFFICIAL_DOMAINS",
    "DEFAULT_GCP_REGION",
    "GCP_KMS_KEY_VERSION_RE",
    "GCS_URI_RE",
    "KVKK_DATA_RESIDENCY_NOTICE",
    "LAW_5070_V103_BOUNDARY_NOTICE",
    "TLS_NON_HISTORICAL_PROOF_NOTICE",
    "TRUST_ROOT_VERSION",
    "DefaultProductionAuthorizationProvider",
    "DefaultSourceAcquisitionProvider",
    "EphemeralSandboxTsaResponder",
    "ExternalTrustAnchorProvider",
    "ExternalTrustAnchorRecord",
    "GcpCloudKmsSignerAdapter",
    "GcpCloudStorageWormAdapter",
    "GcpExternalTrustAnchorProvider",
    "ImmutableEvidenceStorageProvider",
    "InMemoryMockGcpKmsBackend",
    "InMemoryMockGcpWormBackend",
    "InMemoryMockPkcs11Session",
    "KeyMetadata",
    "KeySignerProvider",
    "KvkkDataResidencyVerificationResult",
    "KvkkDataResidencyVerifier",
    "LegalCounselAttestationVerificationResult",
    "LegalCounselAttestationVerifier",
    "LiveHttpsSourceFetcher",
    "Pkcs11HsmSignerAdapter",
    "ProductionAuthorizationDecision",
    "ProductionAuthorizationProvider",
    "ProviderHealthStatus",
    "Rfc3161TimestampAuthorityAdapter",
    "SignatureEnvelope",
    "SourceAcquisitionEvidenceEnvelope",
    "SourceAcquisitionProvider",
    "SourceAcquisitionSecurityError",
    "SourceAcquisitionVerificationResult",
    "TechnicalVerificationResult",
    "TechnicalVerificationService",
    "TimestampAuthorityProvider",
    "TimestampTokenResult",
    "TlsCertificateInfo",
    "TlsVerificationResult",
    "WormObjectReceipt",
    "build_acquisition_signing_payload",
    "build_and_seal_external_trust_anchor_manifest",
    "build_kvkk_m9_assessment_signing_payload",
    "build_legal_counsel_release_attestation_signing_payload",
    "build_trust_anchor_manifest_signing_payload",
    "compute_calendar_bundle_sha256",
    "create_signed_legal_counsel_attestation_envelope",
    "run_live_integration_probe",
    "validate_official_https_url",
    "verify_service_result_authenticity",
    "verify_tls_peer_certificate_chain",
]


def __getattr__(name: str):
    if name == "run_live_integration_probe":
        from .integration_probe import run_live_integration_probe

        return run_live_integration_probe
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
