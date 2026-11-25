"""Domain models, constants, and epistemic/legal notices for CALISORA @HukukSGK v1.0.3.1 Production Trust Root Integration.

Provider-agnostic data contracts separating:
  1. Technical verification (`TechnicalVerificationResult` -> `technical_verification_status`)
  2. External legal counsel cryptographic attestation (`LegalCounselAttestationVerificationResult` -> `legal_counsel_attestation_status`)
  3. Source acquisition & TLS verification (`SourceAcquisitionVerificationResult`, `TlsVerificationResult`)
  4. KVKK m.9 data residency verification (`KvkkDataResidencyVerificationResult`)
  5. Production authorization (`ProductionAuthorizationDecision` -> `production_authorization_status` / `production_use_authorized`)
  6. Execution mode (`LIVE_PRODUCTION` vs. `MOCK_SANDBOX` vs. `NOT_CONFIGURED`) & Fetcher mode (`LIVE_HTTPS` vs. `MOCK_CALLBACK`)
  7. Law No. 5070 non-equivalence (`qualified_e_signature_5070_equivalent = False` strictly in v1.0.3.x; NES/CAdES/XAdES is v1.0.4)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ..attestation_verifier import SIGNATURE_5070_NON_EQUIVALENCE_NOTICE

TRUST_ROOT_VERSION = "1.0.5.1"
DEFAULT_GCP_REGION = "europe-west3"

VALID_INTEGRATION_MODES: set[str] = {
    "LIVE_PRODUCTION",
    "MOCK_SANDBOX",
    "NOT_CONFIGURED",
}

VALID_FETCHER_MODES: set[str] = {
    "LIVE_HTTPS",
    "MOCK_CALLBACK",
    "UNSPECIFIED",
}

VALID_PROTECTION_LEVELS: set[str] = {
    "HSM",
    "SOFTWARE",
    "EXTERNAL",
}

VALID_TSA_STATUSES: set[str] = {
    "INDEPENDENT_TSA_VERIFIED",
    "TSA_FAILED",
    "NOT_CONFIGURED",
}

TLS_NON_HISTORICAL_PROOF_NOTICE = (
    "TLS sertifika zinciri ve el sıkışma bilgileri yalnızca indirme/bağlantı anındaki sunucu kimliğini "
    "destekler; tek başına geçmişte sunucunun bu belge içeriğini yayımladığının kesin kanıtı değildir. "
    "Tarihsel kaynak bütünlüğü için ham HTTP baytları SHA-256 özeti, bağımsız RFC 3161 zaman damgası (TSA), "
    "KMS/HSM edinim imzası ve WORM saklama birlikte değerlendirilir."
)

KVKK_DATA_RESIDENCY_NOTICE = (
    "GCP Frankfurt (europe-west3) bölgesinde tutulacak kanıt zarfları, denetim kayıtları ve operasyonel "
    "veriler için 6698 sayılı KVKK m.9 yurt dışına veri aktarımı ve veri yerleşimi hukuki değerlendirmesi "
    "ayrıca tamamlanmalıdır."
)

LAW_5070_V103_BOUNDARY_NOTICE = (
    "KMS/HSM teknik imzası ve bağımsız RFC 3161 zaman damgası altyapısı hiçbir koşulda 5070 sayılı Elektronik "
    "İmza Kanunu kapsamında Güvenli Elektronik İmza / Nitelikli Elektronik Sertifika (NES) eşdeğeri değildir "
    "(qualified_e_signature_5070_equivalent: false). 5070 sayılı Kanun kapsamındaki NES ve CAdES/XAdES "
    "doğrulaması v1.0.4 engine/esign5070 modülü ve bağımsız 5070 güvenlik/hukuki kabul kapısı üzerinden ayrı yürütülür."
)


@dataclass(frozen=True)
class ProviderHealthStatus:
    provider_name: str
    provider_type: str
    backend: str
    integration_mode: str
    configured: bool
    reachable: bool
    region: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class KeyMetadata:
    key_resource_id: str
    key_version: str
    algorithm: str
    protection_level: str
    public_key_pem: str | None
    public_key_fingerprint_sha256: str | None
    provider_backend: str
    integration_mode: str
    region: str | None = None
    hsm_backed: bool = False
    qualified_e_signature_5070_equivalent: bool = False
    signature_legal_notice: str = SIGNATURE_5070_NON_EQUIVALENCE_NOTICE

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SignatureEnvelope:
    valid: bool
    algorithm: str
    key_resource_id: str
    key_version: str
    protection_level: str
    public_key_fingerprint_sha256: str | None
    payload_sha256: str
    signature_b64: str | None
    canonicalization_standard: str
    signed_at_utc: str
    provider_backend: str
    integration_mode: str
    qualified_e_signature_5070_equivalent: bool = False
    signature_legal_notice: str = SIGNATURE_5070_NON_EQUIVALENCE_NOTICE
    error_codes: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["error_codes"] = list(self.error_codes)
        d["errors"] = list(self.errors)
        return d


@dataclass(frozen=True)
class TimestampTokenResult:
    valid: bool
    status: str
    tsa_url: str | None
    digest_algorithm: str
    message_imprint_sha256: str
    gen_time_utc: str | None
    serial_number: str | None
    policy_oid: str | None
    nonce_hex: str | None
    tsq_der_b64: str | None
    tsr_der_b64: str | None
    tsa_cert_subject: str | None
    tsa_cert_fingerprint_sha256: str | None
    provider_backend: str
    integration_mode: str
    error_codes: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["error_codes"] = list(self.error_codes)
        d["errors"] = list(self.errors)
        return d


@dataclass(frozen=True)
class WormObjectReceipt:
    stored: bool
    object_uri: str | None
    bucket_name: str | None
    object_name: str
    region: str | None
    generation: str | None
    content_sha256: str | None
    byte_length: int
    stored_at_utc: str | None
    retention_policy_seconds: int | None
    retention_policy_locked: bool
    event_based_hold: bool
    temporary_hold: bool
    worm_immutable_verified: bool
    project_id: str | None
    provider_backend: str
    integration_mode: str
    error_codes: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["error_codes"] = list(self.error_codes)
        d["errors"] = list(self.errors)
        return d


@dataclass(frozen=True)
class ExternalTrustAnchorRecord:
    valid: bool
    manifest_id: str | None
    security_project_id: str | None
    app_project_id: str | None
    ledger_id: str | None
    expected_checkpoint_head_hash: str | None
    expected_checkpoint_entry_count: int | None
    expected_chain_digest_sha256: str | None
    read_only: bool
    separate_security_project: bool
    kms_signed: bool
    kms_protection_level: str | None
    worm_protected: bool
    independent_audit_logged: bool
    independent_audit_log_ref: str | None
    manifest_uri: str | None
    tsa_verified: bool
    trust_anchor_source: str
    provider_backend: str
    integration_mode: str
    error_codes: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["error_codes"] = list(self.error_codes)
        d["errors"] = list(self.errors)
        return d


@dataclass(frozen=True)
class TlsCertificateInfo:
    tls_version: str
    cipher_suite: str
    server_hostname: str
    peer_subject: str
    peer_issuer: str
    san_dns_names: tuple[str, ...]
    serial_number: str
    not_before_utc: str
    not_after_utc: str
    leaf_cert_sha256: str
    chain_subjects: tuple[str, ...] = ()
    leaf_cert_pem: str | None = None
    chain_certs_pem: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["san_dns_names"] = list(self.san_dns_names)
        d["chain_subjects"] = list(self.chain_subjects)
        d["chain_certs_pem"] = list(self.chain_certs_pem)
        return d


@dataclass(frozen=True)
class TlsVerificationResult:
    verified: bool
    ca_chain_verified: bool
    hostname_san_verified: bool
    validity_period_verified: bool
    metadata_consistent_with_x509: bool
    trusted_ca_source: str
    fetcher_mode: str
    production_tls_verified: bool
    verified_at_utc: str
    server_hostname: str
    matched_san_or_cn: str | None = None
    leaf_cert_sha256: str | None = None
    tls_alone_proves_historical_content: bool = False
    error_codes: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["error_codes"] = list(self.error_codes)
        d["errors"] = list(self.errors)
        return d


@dataclass(frozen=True)
class SourceAcquisitionEvidenceEnvelope:
    schema_version: str
    acquisition_id: str
    source_id: str
    source_url: str
    final_url: str
    redirect_chain: tuple[str, ...]
    http_status: int
    http_headers: dict[str, str]
    tls_certificate_info: TlsCertificateInfo | None
    acquired_at_utc: str
    raw_bytes_sha256: str
    raw_bytes_length: int
    worm_object_uri: str | None
    worm_receipt: dict[str, Any] | None
    tsa_result: dict[str, Any] | None
    acquisition_signature: dict[str, Any] | None
    signature_verified: bool
    fetcher_mode: str = "UNSPECIFIED"
    tls_verification_result: dict[str, Any] | None = None
    production_tls_verified: bool = False
    tls_alone_proves_historical_content: bool = False
    tls_non_historical_proof_notice: str = TLS_NON_HISTORICAL_PROOF_NOTICE
    provider_backend: str = "DEFAULT_SOURCE_ACQUISITION"
    integration_mode: str = "NOT_CONFIGURED"
    valid: bool = False
    error_codes: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["redirect_chain"] = list(self.redirect_chain)
        if self.tls_certificate_info is not None:
            d["tls_certificate_info"] = self.tls_certificate_info.to_dict()
        d["error_codes"] = list(self.error_codes)
        d["errors"] = list(self.errors)
        return d


@dataclass(frozen=True)
class LegalCounselAttestationVerificationResult:
    """Service-issued cryptographic verification result for external legal counsel attestation.

    Cannot be self-granted by callers: `DefaultProductionAuthorizationProvider` verifies the
    runtime service seal (`_service_seal`) and cross-checks calendar/version bindings.
    """

    valid: bool
    status: str
    approver_id: str | None
    approver_role: str | None
    key_id: str | None
    key_version: str | None
    algorithm: str | None
    signed_at_utc: str | None
    certificate_status: str
    authorized_scope_verified: bool
    calendar_version: str | None
    calendar_sha256: str | None
    hukuk_sgk_version: str | None
    signature_verified: bool
    verifier_service_id: str
    qualified_e_signature_5070_equivalent: bool = False
    signature_legal_notice: str = SIGNATURE_5070_NON_EQUIVALENCE_NOTICE
    error_codes: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    _service_seal: str = field(default="", repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("_service_seal", None)
        d["error_codes"] = list(self.error_codes)
        d["errors"] = list(self.errors)
        return d


@dataclass(frozen=True)
class SourceAcquisitionVerificationResult:
    """Service-issued verification result for official source acquisition evidence."""

    valid: bool
    status: str
    acquisition_id: str | None
    source_id: str | None
    raw_bytes_sha256: str | None
    worm_verified: bool
    tsa_verified: bool
    signature_verified: bool
    tls_verified: bool
    production_tls_verified: bool
    fetcher_mode: str
    verifier_service_id: str
    tls_alone_proves_historical_content: bool = False
    tls_non_historical_proof_notice: str = TLS_NON_HISTORICAL_PROOF_NOTICE
    error_codes: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    _service_seal: str = field(default="", repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("_service_seal", None)
        d["error_codes"] = list(self.error_codes)
        d["errors"] = list(self.errors)
        return d


@dataclass(frozen=True)
class TechnicalVerificationResult:
    """Service-issued verification result for Stage-1 technical snapshot & audit log integrity."""

    valid: bool
    status: str
    calendar_version: str
    calendar_sha256: str
    hukuk_sgk_version: str
    verified_years: tuple[int, ...]
    audit_log_valid: bool
    snapshots_verified: bool
    verifier_service_id: str
    error_codes: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    _service_seal: str = field(default="", repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("_service_seal", None)
        d["verified_years"] = list(self.verified_years)
        d["error_codes"] = list(self.error_codes)
        d["errors"] = list(self.errors)
        return d


@dataclass(frozen=True)
class KvkkDataResidencyVerificationResult:
    """Service-issued verification result for KVKK m.9 (GCP Frankfurt europe-west3) data residency assessment."""

    valid: bool
    status: str
    primary_region: str
    assessment_reference: str | None
    approved_by_approver_id: str | None
    approved_at_utc: str | None
    signature_verified: bool
    verifier_service_id: str
    notice: str = KVKK_DATA_RESIDENCY_NOTICE
    error_codes: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    _service_seal: str = field(default="", repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("_service_seal", None)
        d["error_codes"] = list(self.error_codes)
        d["errors"] = list(self.errors)
        return d


@dataclass(frozen=True)
class ProductionAuthorizationDecision:
    technical_verification_status: str
    legal_counsel_attestation_status: str
    production_authorization_status: str
    production_use_authorized: bool
    external_legal_counsel_signoff_status: str
    qualified_e_signature_5070_equivalent: bool
    signature_legal_notice: str
    kvkk_data_residency_status: str
    kvkk_data_residency_notice: str
    runtime_environment: str
    integration_modes: dict[str, str]
    checks: dict[str, bool]
    blocking_codes: tuple[str, ...]
    blocking_reasons: tuple[str, ...]
    legal_attestation_verification: dict[str, Any] | None = None
    source_acquisition_verification: dict[str, Any] | None = None
    technical_verification: dict[str, Any] | None = None
    kvkk_residency_verification: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["blocking_codes"] = list(self.blocking_codes)
        d["blocking_reasons"] = list(self.blocking_reasons)
        return d
