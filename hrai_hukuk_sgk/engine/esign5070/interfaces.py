"""Provider-agnostic abstract interfaces for CALISORA @HukukSGK v1.0.4.5 Law No. 5070 NES & CAdES/XAdES Module.

Defines the 3 approved provider-agnostic interfaces (ADR Section 3):
  1. EshsTrustListProvider               — BTK ESHS authorization/activity registry + separate ESHS CA chain & policies
  2. CertificateRevocationProvider       — Live & archived OCSP/CRL revocation verification (GOOD / REVOKED / UNKNOWN / UNAVAILABLE)
  3. QualifiedSignature5070VerifierProvider — CAdES (ETSI EN 319 122-1/-2) & XAdES (ETSI EN 319 132-1/-2) verification
     consuming cryptographically verified `SscdControlEvidenceVerificationResult` (NEVER plain caller dicts).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from .models import (
    BtkEshsProviderRecord,
    EshsCertificateChainBundle,
    EshsTrustEvaluationResult,
    Esign5070ProbeStatus,
    QualifiedSignature5070VerificationResult,
    RevocationEvidenceResult,
    SscdControlEvidenceVerificationResult,
)


class EshsTrustListProvider(ABC):
    """Provider-agnostic BTK ESHS authorization registry and separate ESHS CA/policy trust chain interface."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Identifier of the ESHS trust list provider."""

    @property
    @abstractmethod
    def integration_mode(self) -> str:
        """One of `LIVE_PRODUCTION`, `MOCK_SANDBOX`, or `NOT_CONFIGURED`."""

    @abstractmethod
    def probe_status(self) -> Esign5070ProbeStatus:
        """Report honest status using exact 5-state vocabulary (`NOT_CONFIGURED`, `CONFIGURED_UNVERIFIED`, `LIVE_VERIFIED`, `FAILED`, `INDETERMINATE`)."""

    @abstractmethod
    def lookup_btk_eshs_provider(self, eshs_id_or_issuer: str) -> BtkEshsProviderRecord | None:
        """Look up BTK official ESHS authorization/activity status separately from CA certificates."""

    @abstractmethod
    def get_eshs_certificate_chain_bundle(self, eshs_id: str) -> EshsCertificateChainBundle | None:
        """Return ESHS root/intermediate CA certificate bundle & certificate policy OIDs separately from BTK provider list."""

    @abstractmethod
    def evaluate_signer_trust(
        self,
        signer_cert_pem: str,
        *,
        validation_time_utc: str,
        expected_eshs_id: str | None = None,
        runtime_environment: str = "PRODUCTION",
    ) -> EshsTrustEvaluationResult:
        """Independently evaluate BTK ESHS authorization status, X.509 CA chain validity at validation_time_utc, and certificate policies."""


class CertificateRevocationProvider(ABC):
    """Provider-agnostic OCSP/CRL live and historical archive revocation verification interface."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Identifier of the revocation verification provider."""

    @property
    @abstractmethod
    def integration_mode(self) -> str:
        """One of `LIVE_PRODUCTION`, `MOCK_SANDBOX`, or `NOT_CONFIGURED`."""

    @abstractmethod
    def probe_status(self) -> Esign5070ProbeStatus:
        """Report honest status using exact 5-state vocabulary."""

    @abstractmethod
    def check_revocation(
        self,
        signer_cert_pem: str,
        issuer_cert_pem: str | None,
        *,
        validation_time_utc: str,
        archived_ocsp_response_der: bytes | None = None,
        archived_ocsp_signer_cert_pem: str | None = None,
        archived_crl_pem: str | None = None,
        runtime_environment: str = "PRODUCTION",
    ) -> RevocationEvidenceResult:
        """Evaluate certificate revocation status (`GOOD`, `REVOKED`, `UNKNOWN`, `UNAVAILABLE`); returns `INDETERMINATE` if unavailable."""


class QualifiedSignature5070VerifierProvider(ABC):
    """Provider-agnostic CAdES (ETSI EN 319 122-1/-2) & XAdES (ETSI EN 319 132-1/-2) Law No. 5070 verifier interface."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Identifier of the CAdES/XAdES verifier backend."""

    @property
    @abstractmethod
    def integration_mode(self) -> str:
        """One of `LIVE_PRODUCTION`, `MOCK_SANDBOX`, or `NOT_CONFIGURED`."""

    @abstractmethod
    def probe_status(self) -> Esign5070ProbeStatus:
        """Report honest status using exact 5-state vocabulary."""

    @abstractmethod
    def verify_cades_signature(
        self,
        cms_der_bytes: bytes,
        signed_content_bytes: bytes | None = None,
        *,
        claimed_profile: str = "B-B",
        expected_eshs_id: str | None = None,
        validation_time_utc: str | None = None,
        signature_timestamp_tsr_der: bytes | None = None,
        archive_timestamp_tsr_der: bytes | None = None,
        archived_ocsp_response_der: bytes | None = None,
        archived_ocsp_signer_cert_pem: str | None = None,
        archived_crl_pem: str | None = None,
        sscd_control_evidence_result: SscdControlEvidenceVerificationResult | None = None,
        sscd_control_evidence_envelope: dict[str, Any] | None = None,
        archived_sscd_issuer_ocsp_der: bytes | None = None,
        archived_sscd_issuer_ocsp_signer_cert_pem: str | None = None,
        archived_sscd_issuer_crl_pem: str | None = None,
        external_sscd_control_evidence: Any = None,
        runtime_environment: str = "PRODUCTION",
    ) -> QualifiedSignature5070VerificationResult:
        """Verify CAdES (ETSI EN 319 122-1/-2) signature, requiring verified SscdControlEvidenceVerificationResult (plain dicts rejected)."""

    @abstractmethod
    def verify_xades_signature(
        self,
        xades_xml_bytes: bytes,
        signed_content_bytes: bytes | None = None,
        *,
        claimed_profile: str = "B-B",
        expected_eshs_id: str | None = None,
        validation_time_utc: str | None = None,
        signature_timestamp_tsr_der: bytes | None = None,
        archive_timestamp_tsr_der: bytes | None = None,
        archived_ocsp_response_der: bytes | None = None,
        archived_ocsp_signer_cert_pem: str | None = None,
        archived_crl_pem: str | None = None,
        sscd_control_evidence_result: SscdControlEvidenceVerificationResult | None = None,
        sscd_control_evidence_envelope: dict[str, Any] | None = None,
        archived_sscd_issuer_ocsp_der: bytes | None = None,
        archived_sscd_issuer_ocsp_signer_cert_pem: str | None = None,
        archived_sscd_issuer_crl_pem: str | None = None,
        external_sscd_control_evidence: Any = None,
        runtime_environment: str = "PRODUCTION",
    ) -> QualifiedSignature5070VerificationResult:
        """Verify XAdES (ETSI EN 319 132-1/-2) signature with standards-compliant XMLDSig/C14N and verified SSCD evidence."""
