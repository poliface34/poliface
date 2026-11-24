"""Domain models, ETSI EN 319 122/132 Baseline profiles, and Law No. 5070 data contracts for hrAI @HukukSGK v1.0.5.1.

Strict Architectural Boundaries:
  1. Separates `cryptographic_signature_valid` from `qualified_e_signature_5070_verified`.
     Mathematical signature validity alone NEVER proves Law No. 5070 qualified e-signature status.
  2. Uses modern ETSI Baseline profile names (`B-B`, `B-T`, `B-LT`, `B-LTA`) for CAdES (ETSI EN 319 122-1/-2)
     and XAdES (ETSI EN 319 132-1/-2), while supporting legacy aliases (`BES`, `T`, `LT`, `LTA`) cleanly.
  3. Separates BTK ESHS authorization/activity registry (`BtkEshsProviderRecord`) from ESHS CA root/intermediate
     certificates and certificate policies (`EshsCertificateChainBundle`).
  4. Separates technical signature verification, Law No. 5070 Articles 4/6/9 legal assessment, and production
     acceptance gate decisions.
  5. KMS/HSM technical signatures can NEVER be classified as Law No. 5070 qualified electronic signatures.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

ESIGN_5070_VERSION = "1.0.5.1"

ETSI_CADES_STANDARD = "ETSI EN 319 122-1/-2"
ETSI_XADES_STANDARD = "ETSI EN 319 132-1/-2"

CANONICAL_BASELINE_PROFILES: tuple[str, ...] = ("B-B", "B-T", "B-LT", "B-LTA")

LEGACY_PROFILE_ALIASES: dict[str, str] = {
    "B-B": "B-B",
    "B-T": "B-T",
    "B-LT": "B-LT",
    "B-LTA": "B-LTA",
    "BES": "B-B",
    "T": "B-T",
    "LT": "B-LT",
    "LTA": "B-LTA",
    "CADES-B-B": "B-B",
    "CADES-B-T": "B-T",
    "CADES-B-LT": "B-LT",
    "CADES-B-LTA": "B-LTA",
    "CADES-BES": "B-B",
    "CADES-T": "B-T",
    "CADES-LT": "B-LT",
    "CADES-LTA": "B-LTA",
    "XADES-B-B": "B-B",
    "XADES-B-T": "B-T",
    "XADES-B-LT": "B-LT",
    "XADES-B-LTA": "B-LTA",
    "XADES-BES": "B-B",
    "XADES-T": "B-T",
    "XADES-LT": "B-LT",
    "XADES-LTA": "B-LTA",
}

PROFILE_RANK: dict[str, int] = {
    "NONE": 0,
    "B-B": 1,
    "B-T": 2,
    "B-LT": 3,
    "B-LTA": 4,
}

VALID_PROBE_STATUSES: frozenset[str] = frozenset(
    {
        "NOT_CONFIGURED",
        "CONFIGURED_UNVERIFIED",
        "LIVE_VERIFIED",
        "FAILED",
        "INDETERMINATE",
    }
)

VALID_REVOCATION_STATUSES: frozenset[str] = frozenset(
    {
        "GOOD",
        "REVOKED",
        "UNKNOWN",
        "UNAVAILABLE",
    }
)

# Real ASN.1 OIDs for ETSI Qualified Certificate Statements & Certificate Policies
OID_QC_STATEMENTS = "1.3.6.1.5.5.7.1.3"
OID_ETSI_QC_COMPLIANCE = "0.4.0.1862.1.1"
OID_ETSI_QC_SSCD = "0.4.0.1862.1.4"
OID_CERTIFICATE_POLICIES = "2.5.29.32"

LAW_5070_SEPARATION_NOTICE = (
    "5070 sayılı Elektronik İmza Kanunu m.4, m.6 ve m.9 uyarınca bir imzanın kriptografik olarak "
    "doğrulanması (cryptographic_signature_valid) tek başına güvenli elektronik imza niteliğini "
    "(qualified_e_signature_5070_verified) kanıtlamaz. BTK yetkili ESHS durumu, ESHS kök/ara sertifika "
    "zinciri, sertifika politikaları, iptal kanıtı (OCSP/CRL), güvenli imza oluşturma aracı (m.6) ve "
    "imza sahibinin münhasır kontrolüne ilişkin kanıtlar ayrı değerlendirilir; KMS/HSM teknik imzaları "
    "hiçbir koşulda 5070 güvenli elektronik imza eşdeğeri kabul edilmez."
)


def normalize_etsi_profile(raw_profile: str | None) -> tuple[str | None, bool]:
    """Normalize ETSI baseline profile name (`B-B`/`B-T`/`B-LT`/`B-LTA`), accepting legacy aliases (`BES`/`T`/`LT`/`LTA`).

    Returns `(canonical_profile, used_legacy_alias)`.
    """
    if not raw_profile or not isinstance(raw_profile, str):
        return None, False
    cleaned = raw_profile.strip().upper()
    canonical = LEGACY_PROFILE_ALIASES.get(cleaned)
    if canonical is None:
        return None, False
    used_alias = cleaned not in CANONICAL_BASELINE_PROFILES
    return canonical, used_alias


@dataclass(frozen=True)
class Esign5070ProbeStatus:
    service_name: str
    provider_type: str
    probe_status: str
    integration_mode: str
    configured: bool
    reachable: bool
    details: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class BtkEshsProviderRecord:
    """Official BTK ESHS authorization/activity registry entry (distinct from CA certificate chain bundle)."""

    eshs_id: str
    provider_name: str
    authorization_status: str  # ACTIVE | SUSPENDED | REVOKED | EXPIRED
    authorized_from_utc: str
    authorized_until_utc: str
    btk_registry_ref: str
    btk_list_version: str
    permitted_policy_oids: tuple[str, ...]
    country_code: str = "TR"
    trust_source_mode: str = "MOCK_SANDBOX"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["permitted_policy_oids"] = list(self.permitted_policy_oids)
        return d


@dataclass(frozen=True)
class EshsCertificateChainBundle:
    """Separate ESHS root/intermediate CA certificate chain & certificate policy input (distinct from BTK registry list)."""

    eshs_id: str
    bundle_id: str
    root_ca_pems: tuple[str, ...]
    intermediate_ca_pems: tuple[str, ...] = ()
    certificate_policy_oids: tuple[str, ...] = ()
    cps_urls: tuple[str, ...] = ()
    bundle_sha256: str = ""
    acquired_at_utc: str = ""
    valid_from_utc: str = ""
    valid_until_utc: str = ""
    trust_tier: str = "MOCK_SANDBOX_ONLY"  # LIVE_BTK_ESHS | MOCK_SANDBOX_ONLY

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["root_ca_pems"] = list(self.root_ca_pems)
        d["intermediate_ca_pems"] = list(self.intermediate_ca_pems)
        d["certificate_policy_oids"] = list(self.certificate_policy_oids)
        d["cps_urls"] = list(self.cps_urls)
        return d


@dataclass(frozen=True)
class EshsTrustEvaluationResult:
    valid: bool
    conclusion: str  # PASSED | FAILED | INDETERMINATE
    eshs_id: str | None
    btk_provider_authorized: bool
    btk_authorization_status: str | None
    btk_list_version: str | None
    ca_chain_verified: bool
    policy_evaluated: bool
    policy_matched: bool
    matched_policy_oids: tuple[str, ...]
    is_sandbox_ca: bool
    bundle_sha256: str | None
    issuer_ca_pem: str | None = None
    provider_backend: str = "DEFAULT_ESHS_TRUST_LIST"
    integration_mode: str = "NOT_CONFIGURED"
    error_codes: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["matched_policy_oids"] = list(self.matched_policy_oids)
        d["error_codes"] = list(self.error_codes)
        d["errors"] = list(self.errors)
        return d


@dataclass(frozen=True)
class RevocationEvidenceResult:
    status: str  # GOOD | REVOKED | UNKNOWN | UNAVAILABLE
    conclusion: str  # PASSED | FAILED | INDETERMINATE
    method: str  # OCSP | CRL | ARCHIVED_OCSP | ARCHIVED_CRL | NONE
    checked_at_utc: str
    validation_time_utc: str
    certificate_serial_number: str | None = None
    revoked_at_utc: str | None = None
    revocation_reason: str | None = None
    this_update_utc: str | None = None
    next_update_utc: str | None = None
    responder_or_issuer: str | None = None
    evidence_sha256: str | None = None
    historical_archive_evidence: bool = False
    provider_backend: str = "DEFAULT_REVOCATION_PROVIDER"
    integration_mode: str = "NOT_CONFIGURED"
    error_codes: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["error_codes"] = list(self.error_codes)
        d["errors"] = list(self.errors)
        return d


@dataclass(frozen=True)
class SignerCertificateInspection:
    valid_x509: bool
    subject: str
    issuer: str
    serial_number: str
    not_before_utc: str
    not_after_utc: str
    cert_sha256: str
    signature_algorithm: str
    public_key_algorithm: str
    basic_constraints_ca: bool
    key_usage: tuple[str, ...]
    qc_statements_present: bool
    qc_compliance: bool
    qc_sscd: bool
    certificate_policy_oids: tuple[str, ...]
    signer_common_name: str | None
    signer_serial_identifier: str | None
    issuer_country: str | None
    valid_at_validation_time: bool
    error_codes: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["key_usage"] = list(self.key_usage)
        d["certificate_policy_oids"] = list(self.certificate_policy_oids)
        d["error_codes"] = list(self.error_codes)
        d["errors"] = list(self.errors)
        return d


@dataclass(frozen=True)
class ProfileComplianceResult:
    signature_format: str  # CADES | XADES
    standard: str  # ETSI EN 319 122-1/-2 | ETSI EN 319 132-1/-2
    claimed_profile_raw: str
    canonical_claimed_profile: str
    legacy_alias_used: bool
    achieved_profile: str  # B-B | B-T | B-LT | B-LTA | NONE
    profile_compliant: bool
    has_signing_certificate_ref: bool
    has_signature_timestamp: bool
    has_validation_data_embedded: bool
    has_archive_timestamp: bool
    error_codes: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["error_codes"] = list(self.error_codes)
        d["errors"] = list(self.errors)
        return d


@dataclass(frozen=True)
class Law5070ArticleAssessment:
    """Structured legal assessment matrix for Law No. 5070 Articles 4, 6, and 9."""

    article_4_elements: dict[str, str]
    article_4_conclusion: str  # PASSED | FAILED | INDETERMINATE
    article_6_sscd_conclusion: str  # PASSED | FAILED | INDETERMINATE
    article_6_details: dict[str, Any]
    article_9_nes_conclusion: str  # PASSED | FAILED | INDETERMINATE
    article_9_details: dict[str, Any]
    kms_hsm_misclassification_blocked: bool
    overall_5070_conclusion: str  # VERIFIED | FAILED | INDETERMINATE
    missing_external_evidences: tuple[str, ...] = ()
    legal_notes: tuple[str, ...] = ()
    error_codes: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["missing_external_evidences"] = list(self.missing_external_evidences)
        d["legal_notes"] = list(self.legal_notes)
        d["error_codes"] = list(self.error_codes)
        d["errors"] = list(self.errors)
        return d


@dataclass(frozen=True)
class EvidenceItem:
    evidence_id: str
    evidence_type: str
    source: str
    provider: str
    acquired_at_utc: str
    valid_from_utc: str | None
    valid_until_utc: str | None
    sha256: str
    certificate_serial_number: str | None
    algorithm: str | None
    profile: str | None
    verification_result: str
    trust_list_version: str | None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class VerificationEvidenceBundle:
    schema_version: str
    bundle_id: str
    created_at_utc: str
    trust_list_version: str | None
    items: tuple[EvidenceItem, ...]
    ocsp_crl_evidences: tuple[dict[str, Any], ...]
    timestamp_evidences: tuple[dict[str, Any], ...]
    bundle_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "bundle_id": self.bundle_id,
            "created_at_utc": self.created_at_utc,
            "trust_list_version": self.trust_list_version,
            "items": [it.to_dict() for it in self.items],
            "ocsp_crl_evidences": list(self.ocsp_crl_evidences),
            "timestamp_evidences": list(self.timestamp_evidences),
            "bundle_sha256": self.bundle_sha256,
        }


@dataclass(frozen=True)
class AuthorizedSscdEvidenceIssuer:
    """Authorized external issuer of Law No. 5070 m.4/c sole-control & m.6 SSCD/QSCD attestation envelopes."""

    issuer_id: str
    issuer_name: str
    issuer_role: str  # QSCD_CONFORMITY_ASSESSMENT_BODY | BTK_AUTHORIZED_ESHS_QSCD_AUTHORITY | CERTIFIED_REMOTE_QSCD_AUDITOR
    authorized_scopes: tuple[str, ...]
    root_ca_pems: tuple[str, ...]
    intermediate_ca_pems: tuple[str, ...] = ()
    authorized_from_utc: str = ""
    authorized_until_utc: str = ""
    status: str = "ACTIVE"  # ACTIVE | SUSPENDED | REVOKED | EXPIRED
    trust_tier: str = "MOCK_SANDBOX_ONLY"  # LIVE_AUTHORIZED_ISSUER | MOCK_SANDBOX_ONLY

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["authorized_scopes"] = list(self.authorized_scopes)
        d["root_ca_pems"] = list(self.root_ca_pems)
        d["intermediate_ca_pems"] = list(self.intermediate_ca_pems)
        return d


@dataclass(frozen=True)
class SscdControlEvidenceVerificationResult:
    """Cryptographically verified, service-sealed Law No. 5070 m.4/c sole-control & m.6 SSCD/QSCD evidence result.

    Plain caller dicts or caller-constructed instances are NEVER trusted; this object MUST be produced by
    `DefaultSscdControlEvidenceVerifier` after verifying issuer authority, X.509 chain, revocation status,
    asymmetric cryptographic signature, validity window, authorized scope, and signer certificate SHA-256 binding.
    """

    valid: bool
    conclusion: str  # VERIFIED | FAILED | INDETERMINATE
    evidence_id: str
    issuer_id: str | None
    issuer_name: str | None
    issuer_role: str | None
    issuer_authorized: bool
    issuer_cert_chain_verified: bool
    issuer_cert_serial_number: str | None
    issuer_cert_sha256: str | None
    issuer_revocation_status: str  # GOOD | REVOKED | UNKNOWN | UNAVAILABLE
    signature_verified: bool
    signature_algorithm: str | None
    scope_verified: bool
    authorized_scopes: tuple[str, ...]
    valid_from_utc: str | None
    valid_until_utc: str | None
    within_validity_window: bool
    bound_signer_cert_sha256: str | None
    signature_origin: str | None
    signing_device_type: str | None
    sole_control_attested: bool
    pin_or_biometric_activation_verified: bool
    sscd_device_certified: bool
    sscd_certification_ref: str | None
    is_sandbox_issuer: bool
    envelope_sha256: str
    verifier_service_id: str
    integration_mode: str
    error_codes: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    _service_seal: str = field(default="", repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "conclusion": self.conclusion,
            "evidence_id": self.evidence_id,
            "issuer_id": self.issuer_id,
            "issuer_name": self.issuer_name,
            "issuer_role": self.issuer_role,
            "issuer_authorized": self.issuer_authorized,
            "issuer_cert_chain_verified": self.issuer_cert_chain_verified,
            "issuer_cert_serial_number": self.issuer_cert_serial_number,
            "issuer_cert_sha256": self.issuer_cert_sha256,
            "issuer_revocation_status": self.issuer_revocation_status,
            "signature_verified": self.signature_verified,
            "signature_algorithm": self.signature_algorithm,
            "scope_verified": self.scope_verified,
            "authorized_scopes": list(self.authorized_scopes),
            "valid_from_utc": self.valid_from_utc,
            "valid_until_utc": self.valid_until_utc,
            "within_validity_window": self.within_validity_window,
            "bound_signer_cert_sha256": self.bound_signer_cert_sha256,
            "signature_origin": self.signature_origin,
            "signing_device_type": self.signing_device_type,
            "sole_control_attested": self.sole_control_attested,
            "pin_or_biometric_activation_verified": self.pin_or_biometric_activation_verified,
            "sscd_device_certified": self.sscd_device_certified,
            "sscd_certification_ref": self.sscd_certification_ref,
            "is_sandbox_issuer": self.is_sandbox_issuer,
            "envelope_sha256": self.envelope_sha256,
            "verifier_service_id": self.verifier_service_id,
            "integration_mode": self.integration_mode,
            "error_codes": list(self.error_codes),
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class QualifiedSignature5070VerificationResult:
    """Service-issued verification result strictly separating cryptographic validity from Law No. 5070 qualification."""

    schema_version: str
    signature_format: str
    standard: str
    cryptographic_signature_valid: bool
    qualified_e_signature_5070_verified: bool
    qualified_e_signature_5070_conclusion: str  # VERIFIED | FAILED | INDETERMINATE
    profile_compliance: ProfileComplianceResult
    signer_certificate: SignerCertificateInspection | None
    eshs_trust: EshsTrustEvaluationResult
    revocation: RevocationEvidenceResult
    signature_timestamp: dict[str, Any] | None
    archive_timestamp: dict[str, Any] | None
    law_5070_assessment: Law5070ArticleAssessment
    evidence_bundle: VerificationEvidenceBundle
    validation_time_utc: str
    historical_archive_mode: bool
    provider_backend: str
    integration_mode: str
    verifier_service_id: str
    sscd_control_evidence: SscdControlEvidenceVerificationResult | None = None
    xmldsig_details: dict[str, Any] | None = None
    legal_separation_notice: str = LAW_5070_SEPARATION_NOTICE
    error_codes: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    _service_seal: str = field(default="", repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        d = {
            "schema_version": self.schema_version,
            "signature_format": self.signature_format,
            "standard": self.standard,
            "cryptographic_signature_valid": self.cryptographic_signature_valid,
            "qualified_e_signature_5070_verified": self.qualified_e_signature_5070_verified,
            "qualified_e_signature_5070_conclusion": self.qualified_e_signature_5070_conclusion,
            "profile_compliance": self.profile_compliance.to_dict(),
            "signer_certificate": self.signer_certificate.to_dict() if self.signer_certificate else None,
            "eshs_trust": self.eshs_trust.to_dict(),
            "revocation": self.revocation.to_dict(),
            "signature_timestamp": self.signature_timestamp,
            "archive_timestamp": self.archive_timestamp,
            "law_5070_assessment": self.law_5070_assessment.to_dict(),
            "evidence_bundle": self.evidence_bundle.to_dict(),
            "validation_time_utc": self.validation_time_utc,
            "historical_archive_mode": self.historical_archive_mode,
            "provider_backend": self.provider_backend,
            "integration_mode": self.integration_mode,
            "verifier_service_id": self.verifier_service_id,
            "sscd_control_evidence": (
                self.sscd_control_evidence.to_dict() if self.sscd_control_evidence is not None else None
            ),
            "xmldsig_details": self.xmldsig_details,
            "legal_separation_notice": self.legal_separation_notice,
            "error_codes": list(self.error_codes),
            "errors": list(self.errors),
        }
        return d


@dataclass(frozen=True)
class AcceptanceGate5070Decision:
    """Separate Security & Legal Acceptance Gate decision for Law No. 5070 NES signatures."""

    cryptographic_signature_valid: bool
    profile_compliant: bool
    technical_5070_security_status: str  # SECURITY_VERIFIED | SECURITY_INDETERMINATE | SECURITY_FAILED
    legal_5070_qualification_status: str  # QUALIFIED_5070_VERIFIED | INDETERMINATE | REJECTED | NON_5070_TECHNICAL_SIGNATURE
    production_5070_acceptance_status: str
    qualified_e_signature_5070_verified: bool
    qualified_e_signature_5070_production_accepted: bool
    runtime_environment: str
    integration_mode: str
    checks: dict[str, bool]
    blocking_codes: tuple[str, ...]
    blocking_reasons: tuple[str, ...]
    verification_result: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["blocking_codes"] = list(self.blocking_codes)
        d["blocking_reasons"] = list(self.blocking_reasons)
        return d
