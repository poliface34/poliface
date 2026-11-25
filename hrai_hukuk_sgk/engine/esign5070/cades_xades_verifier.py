"""CAdES (ETSI EN 319 122-1/-2) & XAdES (ETSI EN 319 132-1/-2) Law No. 5070 Verifier for hrAI @HukukSGK v1.0.5.1.

Hardened across v1.0.4.1 (BLOCKER 1 & 2), v1.0.4.2 (BLOCKER 3) and v1.0.4.3 (BLOCKER 4) from independent security audits:
  - BLOCKER 1 CLOSED (v1.0.4.1): Plain caller Python dicts (`external_sscd_control_evidence={...}`) can NEVER grant
    Law No. 5070 m.4/c sole-control or m.6 SSCD/QSCD legal compliance (`CALLER_UNVERIFIED_SSCD_DICT_FORBIDDEN`).
    m.4/c & m.6 values MUST come exclusively from a cryptographically verified, service-sealed
    `SscdControlEvidenceVerificationResult` (authenticated via HMAC seal, bound to the exact signer X.509
    certificate SHA-256, checked for validity window, issuer authority, chain, revocation, and production tier).
  - BLOCKER 2, BLOCKER 3 & BLOCKER 4 CLOSED (v1.0.4.1 / v1.0.4.2 / v1.0.4.3): XAdES verification delegates to
    `xmldsig.verify_xades_xmldsig()` with spec-exact Document- and Element-level W3C Canonicalization (preserving
    top-level PIs always and top-level comments in `#WithComments`), declared `SignatureMethod` (RSA-SHA256/384/512,
    RSA-PSS, ECDSA), declared `DigestMethod`, strict sequential typed `Transforms` pipeline (`NODE_SET` vs
    `OCTET_STREAM` where Transform N output is Transform N+1 input), global duplicate-ID rejection, and full
    Anti-XML Signature Wrapping (XSW) defense.
  - Per-process HMAC service seal (`_service_seal`) is computed ONLY AFTER all technical & legal checks complete.
"""

from __future__ import annotations

import base64
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import hmac
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
from typing import Any

from ..attestation_verifier import canonical_json_bytes, parse_utc_timestamp
from ..trust_root.interfaces import TimestampAuthorityProvider
from ..trust_root.rfc3161_tsa import Rfc3161TimestampAuthorityAdapter
from .eshs_trust import DefaultEshsTrustListProvider, inspect_signer_certificate_x509
from .interfaces import (
    CertificateRevocationProvider,
    EshsTrustListProvider,
    QualifiedSignature5070VerifierProvider,
)
from .models import (
    ESIGN_5070_VERSION,
    ETSI_CADES_STANDARD,
    ETSI_XADES_STANDARD,
    LAW_5070_SEPARATION_NOTICE,
    PROFILE_RANK,
    VALID_PROBE_STATUSES,
    Esign5070ProbeStatus,
    EvidenceItem,
    Law5070ArticleAssessment,
    ProfileComplianceResult,
    QualifiedSignature5070VerificationResult,
    SignerCertificateInspection,
    SscdControlEvidenceVerificationResult,
    VerificationEvidenceBundle,
    normalize_etsi_profile,
)
from .revocation import DefaultCertificateRevocationProvider
from .sscd_evidence import (
    DefaultSscdControlEvidenceVerifier,
    verify_sscd_evidence_result_authenticity,
)
from .xmldsig import (
    C14N_INCLUSIVE_10,
    create_xades_xml_bytes_v2,
    verify_xades_xmldsig,
)

# Ephemeral per-process HMAC key sealing authentic verifier outputs against caller forgery
_ESIGN5070_RESULT_SEAL_KEY: bytes = secrets.token_bytes(32)

_KMS_HSM_ORIGIN_MARKERS: frozenset[str] = frozenset(
    {
        "KMS",
        "CLOUD_KMS",
        "GCP_CLOUD_KMS",
        "AWS_KMS",
        "AZURE_KEY_VAULT",
        "SERVER_HSM",
        "KMS_HSM",
        "PKCS11_SERVER_HSM",
        "APPLICATION_KEY",
        "SOFTWARE_KEY",
    }
)

_ELIGIBLE_SSCD_DEVICE_TYPES: frozenset[str] = frozenset(
    {
        "SMART_CARD_QSCD",
        "SMART_CARD",
        "USB_TOKEN_QSCD",
        "MOBILE_SIGNATURE_SIM_QSCD",
        "REMOTE_QSCD_SOLE_CONTROL_CERTIFIED",
    }
)

_KMS_DN_MARKERS: tuple[str, ...] = (
    "CLOUD-KMS",
    "CLOUD_KMS",
    "SERVER-HSM",
    "SERVER_HSM",
    "KMS-SIGNER",
    "KMS_SIGNER",
    "APPLICATION-SIGNER",
)


def _openssl_exe() -> str:
    exe = shutil.which("openssl")
    if not exe:
        raise RuntimeError("OpenSSL CLI bulunamadı; CAdES/XAdES doğrulaması çalıştırılamaz.")
    return exe


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _compute_esign5070_seal(result: QualifiedSignature5070VerificationResult) -> str:
    payload = {
        "result_type": type(result).__qualname__,
        "fields": result.to_dict(),
    }
    return hmac.new(_ESIGN5070_RESULT_SEAL_KEY, canonical_json_bytes(payload), hashlib.sha256).hexdigest()


def seal_esign5070_result(result: QualifiedSignature5070VerificationResult) -> QualifiedSignature5070VerificationResult:
    """Seal an authentic `QualifiedSignature5070VerificationResult` with the per-process HMAC seal."""
    return replace(result, _service_seal=_compute_esign5070_seal(result))


def verify_esign5070_result_authenticity(result: Any) -> bool:
    """Verify that `result` was genuinely emitted by the verifier service and not caller-forged."""
    if not isinstance(result, QualifiedSignature5070VerificationResult):
        return False
    seal = getattr(result, "_service_seal", "")
    if not isinstance(seal, str) or len(seal) != 64:
        return False
    expected = _compute_esign5070_seal(result)
    return hmac.compare_digest(seal, expected)


def _extract_clean_cert_pem(cert_pem: str) -> str:
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", cert_pem, flags=re.DOTALL)
    if not m:
        raise ValueError("Geçerli X.509 CERTIFICATE PEM bloğu bulunamadı.")
    return m.group(0).strip() + "\n"


def cert_pem_to_der_sha256(cert_pem: str) -> str:
    """Compute SHA-256 hex digest of an X.509 certificate's DER bytes."""
    clean_pem = _extract_clean_cert_pem(cert_pem)
    body_lines = [
        line.strip()
        for line in clean_pem.splitlines()
        if line.strip() and not line.strip().startswith("-----")
    ]
    der_bytes = base64.b64decode("".join(body_lines))
    return hashlib.sha256(der_bytes).hexdigest()


def _cert_pem_to_der_sha1(cert_pem: str) -> str:
    clean_pem = _extract_clean_cert_pem(cert_pem)
    body_lines = [
        line.strip()
        for line in clean_pem.splitlines()
        if line.strip() and not line.strip().startswith("-----")
    ]
    der_bytes = base64.b64decode("".join(body_lines))
    return hashlib.sha1(der_bytes).hexdigest()  # nosec B324 - legacy ESSCertID v1 check only


def _parse_cades_sigval_from_cms_print(txt_cms: str) -> bytes | None:
    """Parse raw `signature` octets of the first SignerInfo from `openssl cms -cmsout -print` text."""
    lines = txt_cms.splitlines()
    in_signer_infos = False
    collecting = False
    hex_chunks: list[str] = []
    for line in lines:
        if "signerInfos:" in line:
            in_signer_infos = True
            continue
        if not in_signer_infos:
            continue
        if re.match(r"^\s+signature:\s*$", line):
            collecting = True
            continue
        if collecting:
            m_hex = re.match(r"^\s+[0-9a-fA-F]{4}\s+-\s+((?:[0-9a-fA-F]{2}[ -]?)+)", line)
            if m_hex:
                hex_only = re.sub(r"[^0-9a-fA-F]", "", m_hex.group(1))
                hex_chunks.append(hex_only)
            elif hex_chunks:
                break
    if not hex_chunks:
        return None
    try:
        return bytes.fromhex("".join(hex_chunks))
    except ValueError:
        return None


def extract_cades_signature_value_bytes(cms_der_bytes: bytes) -> bytes | None:
    """Extract the raw `signature` octets of the first SignerInfo from a CMS/CAdES DER structure via OpenSSL."""
    if not cms_der_bytes:
        return None
    openssl = _openssl_exe()
    with tempfile.TemporaryDirectory(prefix="calisora_cms_sigval_") as tmp:
        cms_path = Path(tmp) / "sig.p7s"
        cms_path.write_bytes(cms_der_bytes)
        proc = subprocess.run(
            [openssl, "cms", "-cmsout", "-inform", "DER", "-in", str(cms_path), "-print"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if proc.returncode != 0:
            return None
        return _parse_cades_sigval_from_cms_print(proc.stdout)


def compute_archive_imprint_sha256(
    *,
    signature_bytes: bytes,
    signature_timestamp_tsr_der: bytes | None = None,
    archived_ocsp_response_der: bytes | None = None,
    archived_crl_pem: str | None = None,
) -> str:
    """Compute deterministic archive digest binding signature bytes, signature timestamp, and validation data."""
    payload = {
        "schema": "CALISORA_ARCHIVE_TIMESTAMP_IMPRINT_V1",
        "signature_sha256": hashlib.sha256(signature_bytes).hexdigest(),
        "signature_timestamp_sha256": (
            hashlib.sha256(signature_timestamp_tsr_der).hexdigest() if signature_timestamp_tsr_der else None
        ),
        "archived_ocsp_sha256": (
            hashlib.sha256(archived_ocsp_response_der).hexdigest() if archived_ocsp_response_der else None
        ),
        "archived_crl_sha256": (
            hashlib.sha256(archived_crl_pem.encode("utf-8")).hexdigest() if archived_crl_pem else None
        ),
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def create_cades_cms_der(
    content_bytes: bytes,
    signer_cert_pem: str,
    signer_key_pem: str,
    *,
    include_cades_attr: bool = True,
    detached: bool = True,
    extra_chain_certs_pem: str | None = None,
) -> bytes:
    """Create a real OpenSSL 3 CMS/CAdES DER signature using caller-supplied ephemeral cert & key (zero persistence)."""
    openssl = _openssl_exe()
    with tempfile.TemporaryDirectory(prefix="calisora_cades_sign_") as tmp:
        data_path = Path(tmp) / "data.bin"
        cert_path = Path(tmp) / "signer.pem"
        key_path = Path(tmp) / "signer.key"
        out_path = Path(tmp) / "sig.p7s"
        data_path.write_bytes(content_bytes)
        cert_path.write_text(_extract_clean_cert_pem(signer_cert_pem), encoding="utf-8")
        key_path.write_text(signer_key_pem.strip() + "\n", encoding="utf-8")

        cmd = [
            openssl,
            "cms",
            "-sign",
            "-binary",
            "-md",
            "sha256",
            "-in",
            str(data_path),
            "-signer",
            str(cert_path),
            "-inkey",
            str(key_path),
            "-outform",
            "DER",
            "-out",
            str(out_path),
        ]
        if include_cades_attr:
            cmd.append("-cades")
        if not detached:
            cmd.append("-nodetach")
        if extra_chain_certs_pem:
            chain_path = Path(tmp) / "chain.pem"
            chain_path.write_text(extra_chain_certs_pem.strip() + "\n", encoding="utf-8")
            cmd.extend(["-certfile", str(chain_path)])

        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"CAdES CMS imzası üretilemedi: {proc.stderr.strip()}")
        return out_path.read_bytes()


def create_xades_xml_bytes(
    content_bytes: bytes,
    signer_cert_pem: str,
    signer_key_pem: str,
    *,
    mode: str = "DETACHED",
    canonicalization_method: str = C14N_INCLUSIVE_10,
    signature_method: str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    digest_method: str = "http://www.w3.org/2001/04/xmlenc#sha256",
    data_transforms: Any = None,
    signed_props_transforms: Any = None,
    enveloping_inline_xml: bool = False,
    extra_signature_attrs: str = "",
    include_signing_cert_v2: bool = True,
    signing_time_utc: str | None = None,
    signature_timestamp_tsr_der: bytes | None = None,
    archive_timestamp_tsr_der: bytes | None = None,
    archived_ocsp_response_der: bytes | None = None,
    archived_crl_pem: str | None = None,
) -> tuple[bytes, bytes]:
    """Create a standards-compliant W3C XMLDSig + ETSI EN 319 132 XAdES XML signature."""
    return create_xades_xml_bytes_v2(
        content_bytes,
        signer_cert_pem,
        signer_key_pem,
        mode=mode,
        canonicalization_method=canonicalization_method,
        signature_method=signature_method,
        digest_method=digest_method,
        data_transforms=data_transforms,
        signed_props_transforms=signed_props_transforms,
        enveloping_inline_xml=enveloping_inline_xml,
        extra_signature_attrs=extra_signature_attrs,
        include_signing_cert_v2=include_signing_cert_v2,
        signing_time_utc=signing_time_utc,
        signature_timestamp_tsr_der=signature_timestamp_tsr_der,
        archive_timestamp_tsr_der=archive_timestamp_tsr_der,
        archived_ocsp_response_der=archived_ocsp_response_der,
        archived_crl_pem=archived_crl_pem,
    )


class DefaultQualifiedSignature5070Verifier(QualifiedSignature5070VerifierProvider):
    """Provider-agnostic CAdES (ETSI EN 319 122-1/-2) & XAdES (ETSI EN 319 132-1/-2) Law No. 5070 verifier."""

    def __init__(
        self,
        *,
        eshs_trust_provider: EshsTrustListProvider | None = None,
        revocation_provider: CertificateRevocationProvider | None = None,
        tsa_provider: TimestampAuthorityProvider | None = None,
        sscd_evidence_verifier: DefaultSscdControlEvidenceVerifier | None = None,
        integration_mode: str | None = None,
        live_verified: bool = False,
        probe_status_override: str | None = None,
        probe_error_code: str | None = None,
        probe_error_message: str | None = None,
    ) -> None:
        self.eshs_trust_provider: EshsTrustListProvider = eshs_trust_provider or DefaultEshsTrustListProvider()
        self.revocation_provider: CertificateRevocationProvider = (
            revocation_provider or DefaultCertificateRevocationProvider()
        )
        self.tsa_provider: TimestampAuthorityProvider = tsa_provider or Rfc3161TimestampAuthorityAdapter()
        self.sscd_evidence_verifier: DefaultSscdControlEvidenceVerifier | None = sscd_evidence_verifier
        self._live_verified = bool(live_verified)
        self._probe_error_code = probe_error_code
        self._probe_error_message = probe_error_message

        if probe_status_override is not None:
            norm_ov = str(probe_status_override).upper().strip()
            if norm_ov not in VALID_PROBE_STATUSES:
                raise ValueError(f"Geçersiz probe_status_override: {probe_status_override!r}")
            self._probe_status_override: str | None = norm_ov
        else:
            self._probe_status_override = None

        if integration_mode is not None:
            self._integration_mode = integration_mode.upper().strip()
        else:
            sub_modes = (
                self.eshs_trust_provider.integration_mode,
                self.revocation_provider.integration_mode,
                self.tsa_provider.integration_mode,
            )
            if "NOT_CONFIGURED" in sub_modes:
                self._integration_mode = "NOT_CONFIGURED"
            elif "MOCK_SANDBOX" in sub_modes:
                self._integration_mode = "MOCK_SANDBOX"
            else:
                self._integration_mode = "LIVE_PRODUCTION"

    @property
    def provider_name(self) -> str:
        return "HRAI_CADES_XADES_5070_VERIFIER_V1051"

    @property
    def integration_mode(self) -> str:
        return self._integration_mode

    def probe_status(self) -> Esign5070ProbeStatus:
        eshs_probe = self.eshs_trust_provider.probe_status()
        rev_probe = self.revocation_provider.probe_status()
        tsa_health = self.tsa_provider.health_check()
        tsa_live = tsa_health.integration_mode == "LIVE_PRODUCTION" and tsa_health.configured and tsa_health.reachable

        configured = bool(eshs_probe.configured and rev_probe.configured and tsa_health.configured)
        if self._probe_status_override is not None:
            st = self._probe_status_override
        elif not configured or self._integration_mode == "NOT_CONFIGURED":
            st = "NOT_CONFIGURED"
        elif (
            self._integration_mode == "LIVE_PRODUCTION"
            and self._live_verified
            and eshs_probe.probe_status == "LIVE_VERIFIED"
            and rev_probe.probe_status == "LIVE_VERIFIED"
            and tsa_live
        ):
            st = "LIVE_VERIFIED"
        elif eshs_probe.probe_status == "FAILED" or rev_probe.probe_status == "FAILED":
            st = "FAILED"
        elif eshs_probe.probe_status == "INDETERMINATE" or rev_probe.probe_status == "INDETERMINATE":
            st = "INDETERMINATE"
        else:
            st = "CONFIGURED_UNVERIFIED"

        return Esign5070ProbeStatus(
            service_name="qualified_signature_5070_verifier",
            provider_type="QualifiedSignature5070VerifierProvider",
            probe_status=st,
            integration_mode=self._integration_mode,
            configured=configured,
            reachable=st == "LIVE_VERIFIED",
            details={
                "supported_standards": [ETSI_CADES_STANDARD, ETSI_XADES_STANDARD],
                "supported_profiles": ["B-B", "B-T", "B-LT", "B-LTA"],
                "legacy_aliases_supported": ["BES", "T", "LT", "LTA"],
                "eshs_trust_probe": eshs_probe.probe_status,
                "revocation_probe": rev_probe.probe_status,
                "tsa_mode": tsa_health.integration_mode,
                "sscd_verified_evidence_required": True,
                "xmldsig_anti_xsw_enforced": True,
            },
            error_code=self._probe_error_code or (None if st == "LIVE_VERIFIED" else "VERIFIER_5070_NOT_LIVE_VERIFIED"),
            error_message=self._probe_error_message
            or (
                None
                if st == "LIVE_VERIFIED"
                else "5070 CAdES/XAdES doğrulama zinciri (BTK ESHS + OCSP/CRL + TSA) canlı üretimde doğrulanmamıştır."
            ),
        )

    def _verify_timestamp(
        self,
        *,
        tsr_der: bytes | None,
        expected_digest_sha256: str | None,
        kind: str,
    ) -> dict[str, Any] | None:
        if not tsr_der:
            return None
        if not expected_digest_sha256:
            return {
                "kind": kind,
                "valid": False,
                "status": "TSA_FAILED",
                "error_codes": ["TIMESTAMP_IMPRINT_MISSING"],
                "errors": [f"{kind} zaman damgası için beklenen SHA-256 özet değeri üretilemedi."],
                "timestamp_alone_proves_5070": False,
            }
        ts_res = self.tsa_provider.verify_timestamp_token(expected_digest_sha256, tsr_der)
        res_dict = ts_res.to_dict()
        res_dict["kind"] = kind
        res_dict["tsr_sha256"] = hashlib.sha256(tsr_der).hexdigest()
        res_dict["timestamp_alone_proves_5070"] = False
        return res_dict

    def _evaluate_profile(
        self,
        *,
        signature_format: str,
        standard: str,
        claimed_profile_raw: str,
        crypto_valid: bool,
        has_signing_cert_ref: bool,
        sig_ts_dict: dict[str, Any] | None,
        archive_ts_dict: dict[str, Any] | None,
        has_embedded_validation_data: bool,
        revocation_passed: bool,
        eshs_chain_verified: bool,
    ) -> ProfileComplianceResult:
        errors: list[str] = []
        error_codes: list[str] = []
        canonical, used_alias = normalize_etsi_profile(claimed_profile_raw)
        if canonical is None:
            canonical = "B-B"
            error_codes.append("INVALID_ETSI_PROFILE_NAME")
            errors.append(
                f"Geçersiz ETSI profil adı: '{claimed_profile_raw}'. Desteklenen profiller: B-B, B-T, B-LT, B-LTA "
                f"(eski uyumluluk adları: BES, T, LT, LTA)."
            )

        sig_ts_valid = bool(sig_ts_dict and sig_ts_dict.get("valid") is True)
        archive_ts_valid = bool(archive_ts_dict and archive_ts_dict.get("valid") is True)

        if not crypto_valid:
            achieved = "NONE"
            error_codes.append("PROFILE_FAILED_CRYPTO_INVALID")
            errors.append("Kriptografik imza doğrulaması başarısız olduğundan hiçbir ETSI profili sağlanamamıştır.")
        elif not has_signing_cert_ref:
            achieved = "NONE"
            error_codes.append("ETSI_SIGNING_CERTIFICATE_REF_MISSING")
            errors.append(
                f"{signature_format} B-B profili için zorunlu SigningCertificate/ESSCertIDv2 özniteliği eksiktir."
            )
        else:
            achieved = "B-B"
            if sig_ts_valid:
                achieved = "B-T"
                if has_embedded_validation_data and revocation_passed and eshs_chain_verified:
                    achieved = "B-LT"
                    if archive_ts_valid:
                        achieved = "B-LTA"

        compliant = (
            "INVALID_ETSI_PROFILE_NAME" not in error_codes
            and achieved != "NONE"
            and PROFILE_RANK[achieved] >= PROFILE_RANK[canonical]
        )

        if not compliant and "INVALID_ETSI_PROFILE_NAME" not in error_codes:
            if PROFILE_RANK[canonical] >= PROFILE_RANK["B-T"] and not sig_ts_valid:
                error_codes.append("ETSI_BT_SIGNATURE_TIMESTAMP_REQUIRED")
                errors.append(f"{canonical} profili için doğrulanmış RFC 3161 imza zaman damgası (B-T) zorunludur.")
            if PROFILE_RANK[canonical] >= PROFILE_RANK["B-LT"] and not (
                has_embedded_validation_data and revocation_passed and eshs_chain_verified
            ):
                error_codes.append("ETSI_BLT_VALIDATION_DATA_REQUIRED")
                errors.append(
                    f"{canonical} profili için uzun dönem doğrulama verileri (CA zinciri + arşivlenmiş/gömülü OCSP/CRL) zorunludur."
                )
            if PROFILE_RANK[canonical] >= PROFILE_RANK["B-LTA"] and not archive_ts_valid:
                error_codes.append("ETSI_BLTA_ARCHIVE_TIMESTAMP_REQUIRED")
                errors.append(f"{canonical} profili için doğrulanmış RFC 3161 arşiv zaman damgası (B-LTA) zorunludur.")

        return ProfileComplianceResult(
            signature_format=signature_format,
            standard=standard,
            claimed_profile_raw=str(claimed_profile_raw),
            canonical_claimed_profile=canonical,
            legacy_alias_used=used_alias,
            achieved_profile=achieved,
            profile_compliant=compliant,
            has_signing_certificate_ref=has_signing_cert_ref,
            has_signature_timestamp=sig_ts_valid,
            has_validation_data_embedded=has_embedded_validation_data,
            has_archive_timestamp=archive_ts_valid,
            error_codes=tuple(sorted(set(error_codes))),
            errors=tuple(errors),
        )

    def _resolve_verified_sscd_evidence(
        self,
        *,
        sscd_control_evidence_result: SscdControlEvidenceVerificationResult | None,
        sscd_control_evidence_envelope: dict[str, Any] | None,
        external_sscd_control_evidence: Any,
        cert_info: SignerCertificateInspection | None,
        effective_val_time: str,
        archived_sscd_issuer_ocsp_der: bytes | None,
        archived_sscd_issuer_ocsp_signer_cert_pem: str | None,
        archived_sscd_issuer_crl_pem: str | None,
        runtime_environment: str,
    ) -> tuple[SscdControlEvidenceVerificationResult | None, bool, bool, list[str], list[str]]:
        """Authenticate/verify SSCD/QSCD evidence; strictly REJECT plain caller dicts & forged result objects!

        Returns `(verified_sscd_result, is_kms_hsm_blocked, hard_security_reject, error_codes, errors)`.
        """
        env_norm = str(runtime_environment or "PRODUCTION").upper().strip()
        codes: list[str] = []
        errs: list[str] = []
        kms_blocked = False
        hard_reject = False

        # 0. BLOCKER 1 DEFENSE: Plain caller dicts / raw assertions are STRICTLY FORBIDDEN!
        if external_sscd_control_evidence is not None:
            if isinstance(external_sscd_control_evidence, dict):
                orig = str(
                    external_sscd_control_evidence.get("signature_origin")
                    or external_sscd_control_evidence.get("key_storage_type")
                    or ""
                ).upper().strip()
                dev = str(external_sscd_control_evidence.get("signing_device_type") or "").upper().strip()
                if (
                    orig in _KMS_HSM_ORIGIN_MARKERS
                    or dev in _KMS_HSM_ORIGIN_MARKERS
                    or external_sscd_control_evidence.get("is_kms_or_server_hsm") is True
                ):
                    kms_blocked = True
                    hard_reject = True
                    codes.append("KMS_HSM_NOT_5070_QUALIFIED_SIGNATURE")
                    errs.append(
                        "Cloud KMS / sunucu HSM / uygulama anahtarı ile üretilen teknik imzalar 5070 sayılı Kanun "
                        "kapsamında Güvenli Elektronik İmza olarak sınıflandırılamaz."
                    )
                else:
                    hard_reject = True
                    codes.append("CALLER_UNVERIFIED_SSCD_DICT_FORBIDDEN")
                    errs.append(
                        "Çağıran tarafından gönderilen doğrulanmamış ham Python sözlüğü (external_sscd_control_evidence) "
                        "5070 m.4/c veya m.6 hukuki kanıtı olarak kabul edilemez; yalnızca kriptografik olarak "
                        "doğrulanmış ve mühürlenmiş SscdControlEvidenceVerificationResult geçerlidir."
                    )
            else:
                hard_reject = True
                codes.append("CALLER_UNVERIFIED_SSCD_DICT_FORBIDDEN")
                errs.append(
                    "Doğrulanmamış çağıran SSCD/QSCD iddiası kabul edilemez; imzalı ve mühürlü "
                    "SscdControlEvidenceVerificationResult zorunludur."
                )

        # 1. Resolve from signed envelope OR service-sealed SscdControlEvidenceVerificationResult
        sscd_res: SscdControlEvidenceVerificationResult | None = None
        if sscd_control_evidence_envelope is not None:
            if self.sscd_evidence_verifier is None:
                codes.append("SSCD_EVIDENCE_VERIFIER_NOT_CONFIGURED")
                errs.append(
                    "İmzalı SSCD/QSCD kanıt zarfını doğrulayacak DefaultSscdControlEvidenceVerifier yapılandırılmamıştır."
                )
            else:
                sscd_res = self.sscd_evidence_verifier.verify_sscd_evidence_envelope(
                    sscd_control_evidence_envelope,
                    validation_time_utc=effective_val_time,
                    expected_signer_cert_sha256=cert_info.cert_sha256 if cert_info and cert_info.valid_x509 else None,
                    archived_issuer_ocsp_der=archived_sscd_issuer_ocsp_der,
                    archived_issuer_ocsp_signer_cert_pem=archived_sscd_issuer_ocsp_signer_cert_pem,
                    archived_issuer_crl_pem=archived_sscd_issuer_crl_pem,
                    runtime_environment=env_norm,
                )
        elif sscd_control_evidence_result is not None:
            if not verify_sscd_evidence_result_authenticity(sscd_control_evidence_result):
                hard_reject = True
                codes.append("FORGED_OR_UNAUTHENTICATED_SSCD_EVIDENCE_RESULT")
                errs.append(
                    "SscdControlEvidenceVerificationResult doğrulama servisi HMAC mührünü taşımıyor "
                    "(çağıran tarafından elle oluşturulmuş sahte kanıt nesnesi reddedildi)."
                )
            else:
                sscd_res = sscd_control_evidence_result
                # Independent cross-checks on pre-verified result: signer cert binding, validity window, sandbox tier!
                if (
                    cert_info is not None
                    and cert_info.valid_x509
                    and sscd_res.bound_signer_cert_sha256 != cert_info.cert_sha256.lower()
                ):
                    hard_reject = True
                    codes.append("SSCD_EVIDENCE_SIGNER_CERT_BINDING_MISMATCH")
                    errs.append(
                        "SscdControlEvidenceVerificationResult farklı bir imzacı X.509 sertifikasına bağlıdır."
                    )
                if sscd_res.valid_from_utc and sscd_res.valid_until_utc:
                    try:
                        v_dt = parse_utc_timestamp(effective_val_time)
                        ef_dt = parse_utc_timestamp(sscd_res.valid_from_utc)
                        eu_dt = parse_utc_timestamp(sscd_res.valid_until_utc)
                        if v_dt < ef_dt or v_dt > eu_dt:
                            hard_reject = True
                            codes.append("SSCD_EVIDENCE_EXPIRED_OR_NOT_YET_VALID")
                            errs.append(
                                f"SSCD kanıtı doğrulama zamanında ({effective_val_time}) geçerlilik penceresi dışındadır."
                            )
                    except Exception:
                        hard_reject = True
                        codes.append("SSCD_EVIDENCE_VALIDITY_WINDOW_INVALID")
                        errs.append("SSCD kanıt geçerlilik tarihleri geçersizdir.")
                if sscd_res.is_sandbox_issuer and env_norm == "PRODUCTION":
                    hard_reject = True
                    codes.append("SANDBOX_SSCD_ISSUER_REJECTED_IN_PRODUCTION")
                    errs.append("Sandbox/test SSCD yayımlayıcısı PRODUCTION ortamında kesinlikle reddedilir.")

        if sscd_res is not None:
            if "KMS_HSM_NOT_5070_QUALIFIED_SIGNATURE" in sscd_res.error_codes:
                kms_blocked = True
                hard_reject = True
            if not sscd_res.valid:
                codes.extend(sscd_res.error_codes)
                errs.extend(sscd_res.errors)
                if sscd_res.conclusion == "FAILED":
                    hard_reject = True

        return sscd_res, kms_blocked, hard_reject, codes, errs

    def _evaluate_law_5070(
        self,
        *,
        crypto_valid: bool,
        profile_res: ProfileComplianceResult,
        cert_info: SignerCertificateInspection | None,
        eshs_res: Any,
        rev_res: Any,
        sig_ts_dict: dict[str, Any] | None,
        archive_ts_dict: dict[str, Any] | None,
        sscd_res: SscdControlEvidenceVerificationResult | None,
        sscd_kms_blocked: bool,
        sscd_hard_reject: bool,
        sscd_codes: list[str],
        sscd_errors: list[str],
        historical_archive_mode: bool,
    ) -> Law5070ArticleAssessment:
        errors: list[str] = list(sscd_errors)
        error_codes: list[str] = list(sscd_codes)
        missing_ext: list[str] = []
        legal_notes: list[str] = [LAW_5070_SEPARATION_NOTICE]

        # 0. Strict KMS / HSM technical signature misclassification guard
        cert_dn_upper = ((cert_info.subject if cert_info else "") + " " + (cert_info.issuer if cert_info else "")).upper()
        is_kms_or_server_hsm = bool(
            sscd_kms_blocked
            or any(m in cert_dn_upper for m in _KMS_DN_MARKERS)
        )
        if is_kms_or_server_hsm and "KMS_HSM_NOT_5070_QUALIFIED_SIGNATURE" not in error_codes:
            error_codes.append("KMS_HSM_NOT_5070_QUALIFIED_SIGNATURE")
            errors.append(
                "Cloud KMS / sunucu HSM / uygulama anahtarı ile üretilen teknik imzalar 5070 sayılı Kanun m.4/m.6 "
                "kapsamında imza sahibinin münhasır kontrolündeki Güvenli Elektronik İmza olarak sınıflandırılamaz."
            )

        # Effective verified SSCD evidence (ONLY when authentic, valid, non-rejected, and signature-verified!)
        sscd_trusted = bool(
            sscd_res is not None
            and sscd_res.valid
            and sscd_res.conclusion == "VERIFIED"
            and sscd_res.signature_verified
            and sscd_res.issuer_authorized
            and sscd_res.issuer_cert_chain_verified
            and sscd_res.issuer_revocation_status == "GOOD"
            and sscd_res.scope_verified
            and sscd_res.within_validity_window
            and not sscd_hard_reject
            and not is_kms_or_server_hsm
        )

        # 1. Law No. 5070 Article 4 — Evaluate all 4 statutory sub-elements (a, b, c, d) separately!
        has_sign_ku = bool(
            cert_info
            and cert_info.valid_x509
            and not cert_info.basic_constraints_ca
            and any(
                ku.lower() in {"non repudiation", "content commitment", "digital signature"}
                for ku in cert_info.key_usage
            )
        )
        if is_kms_or_server_hsm:
            m4_a = "FAILED"
        elif crypto_valid and has_sign_ku and cert_info and cert_info.signer_common_name:
            m4_a = "PASSED"
        else:
            m4_a = "FAILED"
            error_codes.append("LAW_5070_M4A_UNIQUE_SIGNER_BINDING_FAILED")
            errors.append("5070 m.4/a: İmzanın münhasıran imza sahibine bağlılığı doğrulanamadı.")

        # (b) İmza sahibinin kimliğinin tespitini sağlama
        if cert_info is None or not cert_info.valid_x509:
            m4_b = "FAILED"
        elif not cert_info.signer_common_name or not cert_info.signer_serial_identifier:
            m4_b = "FAILED"
            error_codes.append("LAW_5070_M4B_SIGNER_IDENTITY_FIELDS_MISSING")
            errors.append("5070 m.4/b: İmzacı sertifikasında kimlik tespitini sağlayan zorunlu CN/serialNumber alanları eksiktir.")
        elif eshs_res.conclusion == "INDETERMINATE":
            m4_b = "INDETERMINATE"
            missing_ext.append("btk_eshs_trust_list_and_ca_chain")
        elif eshs_res.valid:
            m4_b = "PASSED"
        else:
            m4_b = "FAILED"
            error_codes.append("LAW_5070_M4B_UNTRUSTED_IDENTITY_ISSUER")
            errors.append("5070 m.4/b: İmza sahibinin kimliği yetkili BTK ESHS sertifika zinciri ile doğrulanamadı.")

        # (c) Sadece imza sahibinin tasarrufunda bulunan güvenli elektronik imza oluşturma aracı
        #     ONLY satisfied via cryptographically verified SscdControlEvidenceVerificationResult!
        if is_kms_or_server_hsm or sscd_hard_reject:
            m4_c = "FAILED"
        elif sscd_res is None:
            m4_c = "INDETERMINATE"
            missing_ext.append("verified_sscd_control_evidence_result")
            error_codes.append("LAW_5070_M4C_SOLE_CONTROL_EVIDENCE_MISSING")
            errors.append(
                "5070 m.4/c: İmza oluşturma aracının imza sahibinin münhasır tasarrufunda olduğuna ilişkin "
                "kriptografik olarak doğrulanmış SscdControlEvidenceVerificationResult sağlanmamıştır."
            )
        elif sscd_res.conclusion == "INDETERMINATE":
            m4_c = "INDETERMINATE"
            missing_ext.append("verified_sscd_issuer_revocation_and_authority")
        elif (
            sscd_trusted
            and sscd_res.sole_control_attested
            and sscd_res.pin_or_biometric_activation_verified
            and (sscd_res.signing_device_type or "") in _ELIGIBLE_SSCD_DEVICE_TYPES
        ):
            m4_c = "PASSED"
        else:
            m4_c = "FAILED"

        # (d) İmzalanmış elektronik veride sonradan herhangi bir değişiklik yapılıp yapılmadığının tespitini sağlama
        if crypto_valid:
            m4_d = "PASSED"
        else:
            m4_d = "FAILED"
            error_codes.append("LAW_5070_M4D_DATA_INTEGRITY_FAILED")
            errors.append("5070 m.4/d: İmzalanmış veride bütünlük/değişiklik tespiti kriptografik doğrulaması başarısızdır.")

        m4_elements = {
            "a_uniquely_linked_to_signer": m4_a,
            "b_identifies_signer": m4_b,
            "c_sole_control_of_signer": m4_c,
            "d_detects_subsequent_data_alteration": m4_d,
        }
        if "FAILED" in m4_elements.values():
            m4_conclusion = "FAILED"
        elif "INDETERMINATE" in m4_elements.values():
            m4_conclusion = "INDETERMINATE"
        else:
            m4_conclusion = "PASSED"

        # 2. Law No. 5070 Article 6 — Secure Electronic Signature Creation Device (SSCD / QSCD)
        cert_qc_sscd = bool(cert_info and cert_info.qc_sscd)
        if is_kms_or_server_hsm or sscd_hard_reject:
            m6_conclusion = "FAILED"
        elif sscd_res is None:
            m6_conclusion = "INDETERMINATE"
            missing_ext.append("verified_sscd_control_evidence_result")
            error_codes.append("LAW_5070_M6_SSCD_EVIDENCE_MISSING")
            errors.append(
                "5070 m.6: Kriptografik olarak doğrulanmış SSCD/QSCD kanıt nesnesi (SscdControlEvidenceVerificationResult) "
                "sağlanmadığından m.6 uygunluğu belirsizdir (INDETERMINATE)."
            )
        elif sscd_res.conclusion == "INDETERMINATE":
            m6_conclusion = "INDETERMINATE"
            missing_ext.append("verified_sscd_issuer_revocation_and_authority")
        elif (
            sscd_trusted
            and cert_qc_sscd
            and sscd_res.sscd_device_certified
            and bool(sscd_res.sscd_certification_ref)
            and (sscd_res.signing_device_type or "") in _ELIGIBLE_SSCD_DEVICE_TYPES
        ):
            m6_conclusion = "PASSED"
        elif sscd_trusted and not cert_qc_sscd:
            m6_conclusion = "INDETERMINATE"
            missing_ext.append("certificate_qc_sscd_oid_0_4_0_1862_1_4")
            error_codes.append("LAW_5070_M6_QC_SSCD_NOT_ASSERTED_IN_CERT")
            errors.append(
                "5070 m.6: Sertifikada QcSSCD beyanı (0.4.0.1862.1.4) doğrulanamadığından m.6 sonucu INDETERMINATE kalır."
            )
        else:
            m6_conclusion = "FAILED"

        m6_details = {
            "cert_qc_sscd_oid_present": cert_qc_sscd,
            "sscd_evidence_verified": sscd_trusted,
            "sscd_evidence_issuer_id": sscd_res.issuer_id if sscd_res else None,
            "sscd_evidence_id": sscd_res.evidence_id if sscd_res else None,
            "external_sscd_device_certified": bool(sscd_trusted and sscd_res and sscd_res.sscd_device_certified),
            "external_sscd_certification_ref": sscd_res.sscd_certification_ref if (sscd_trusted and sscd_res) else None,
            "signing_device_type": sscd_res.signing_device_type if (sscd_trusted and sscd_res) else None,
            "kms_hsm_blocked": is_kms_or_server_hsm,
        }

        # 3. Law No. 5070 Article 9 — Qualified Electronic Certificate (NES) + QCStatements/Policy context
        m9_hard_fail = False
        m9_indeterminate = False

        if cert_info is None or not cert_info.valid_x509:
            m9_hard_fail = True
        else:
            if not cert_info.valid_at_validation_time:
                m9_hard_fail = True
                error_codes.extend(cert_info.error_codes)
                errors.extend(cert_info.errors)
            if not cert_info.signer_common_name or not cert_info.signer_serial_identifier:
                m9_hard_fail = True
                error_codes.append("LAW_5070_M9_MANDATORY_SUBJECT_IDENTITY_MISSING")
                errors.append("5070 m.9: Nitelikli Elektronik Sertifika (NES) zorunlu imza sahibi kimlik bilgileri eksiktir.")
            if not cert_info.serial_number:
                m9_hard_fail = True
                error_codes.append("LAW_5070_M9_CERT_SERIAL_MISSING")

        if eshs_res.conclusion == "FAILED":
            m9_hard_fail = True
            error_codes.extend(eshs_res.error_codes)
            errors.extend(eshs_res.errors)
        elif eshs_res.conclusion == "INDETERMINATE":
            m9_indeterminate = True
            missing_ext.append("btk_eshs_live_trust_and_ca_bundle")
            error_codes.extend(eshs_res.error_codes)
            errors.extend(eshs_res.errors)

        if rev_res.status == "REVOKED" or rev_res.conclusion == "FAILED":
            m9_hard_fail = True
            error_codes.extend(rev_res.error_codes)
            errors.extend(rev_res.errors)
        elif rev_res.status in {"UNKNOWN", "UNAVAILABLE"} or rev_res.conclusion == "INDETERMINATE":
            m9_indeterminate = True
            missing_ext.append("verified_ocsp_or_crl_revocation_status")
            error_codes.extend(rev_res.error_codes)
            errors.extend(rev_res.errors)

        qc_policy_context_status = "UNVERIFIED"
        if cert_info and cert_info.valid_x509:
            if cert_info.qc_statements_present and cert_info.qc_compliance and eshs_res.policy_matched:
                qc_policy_context_status = "PASSED_QC_AND_POLICY_MATCHED"
            elif eshs_res.policy_evaluated and not eshs_res.policy_matched:
                qc_policy_context_status = "FAILED_POLICY_MISMATCH"
                m9_hard_fail = True
                if "CERTIFICATE_POLICY_OID_MISMATCH" not in error_codes:
                    error_codes.append("CERTIFICATE_POLICY_OID_MISMATCH")
                    errors.append("5070 m.9: Sertifika politika OID'leri yetkili ESHS NES profili ile uyuşmuyor.")
            elif not cert_info.qc_statements_present or not cert_info.qc_compliance:
                qc_policy_context_status = "INDETERMINATE_QC_COMPLIANCE_ABSENT_IN_POLICY_CONTEXT"
                m9_indeterminate = True
                missing_ext.append("article_9_qc_compliance_statement_0_4_0_1862_1_1")
                error_codes.append("LAW_5070_M9_QC_COMPLIANCE_MISSING_IN_POLICY_CONTEXT")
                errors.append(
                    "5070 m.9: Sertifika politika/profil bağlamında QCStatements / QcCompliance (0.4.0.1862.1.1) "
                    "beyanı doğrulanamadığından NES niteliği INDETERMINATE olarak kilitlenmiştir."
                )
            else:
                qc_policy_context_status = "INDETERMINATE_POLICY_CONTEXT_UNCONFIGURED"
                m9_indeterminate = True
                missing_ext.append("eshs_certificate_policy_oid_context")

        if m9_hard_fail:
            m9_conclusion = "FAILED"
        elif m9_indeterminate:
            m9_conclusion = "INDETERMINATE"
        else:
            m9_conclusion = "PASSED"

        m9_details = {
            "btk_provider_authorized": eshs_res.btk_provider_authorized,
            "btk_authorization_status": eshs_res.btk_authorization_status,
            "ca_chain_verified": eshs_res.ca_chain_verified,
            "revocation_status": rev_res.status,
            "cert_valid_at_validation_time": bool(cert_info and cert_info.valid_at_validation_time),
            "qc_statements_present": bool(cert_info and cert_info.qc_statements_present),
            "qc_compliance": bool(cert_info and cert_info.qc_compliance),
            "certificate_policy_oids": list(cert_info.certificate_policy_oids) if cert_info else [],
            "matched_policy_oids": list(eshs_res.matched_policy_oids),
            "qc_policy_context_status": qc_policy_context_status,
            "issuer_country": cert_info.issuer_country if cert_info else None,
        }

        ts_failed = False
        if sig_ts_dict is not None and not sig_ts_dict.get("valid"):
            ts_failed = True
            error_codes.extend(sig_ts_dict.get("error_codes") or ["SIGNATURE_TIMESTAMP_INVALID"])
            errors.extend(sig_ts_dict.get("errors") or ["İmza zaman damgası doğrulaması başarısızdır."])
        if archive_ts_dict is not None and not archive_ts_dict.get("valid"):
            ts_failed = True
            error_codes.extend(archive_ts_dict.get("error_codes") or ["ARCHIVE_TIMESTAMP_INVALID"])
            errors.extend(archive_ts_dict.get("errors") or ["Arşiv zaman damgası doğrulaması başarısızdır."])
        if historical_archive_mode and not (sig_ts_dict and sig_ts_dict.get("valid")):
            ts_failed = True
            error_codes.append("HISTORICAL_ARCHIVE_REQUIRES_VERIFIED_TIMESTAMP")
            errors.append(
                "Tarihsel arşiv doğrulamasında imza anını kanıtlayan doğrulanmış RFC 3161 zaman damgası zorunludur."
            )

        legal_notes.append(
            "RFC 3161 zaman damgası yalnızca verinin belirli bir anda var olduğunu ve B-T/B-LT/B-LTA arşiv "
            "bütünlüğünü kanıtlar; tek başına 5070 sayılı Kanun kapsamında güvenli elektronik imza ispatı sağlamaz."
        )

        if (
            not crypto_valid
            or not profile_res.profile_compliant
            or is_kms_or_server_hsm
            or sscd_hard_reject
            or ts_failed
            or "FAILED" in (m4_conclusion, m6_conclusion, m9_conclusion)
        ):
            overall = "FAILED"
        elif "INDETERMINATE" in (m4_conclusion, m6_conclusion, m9_conclusion):
            overall = "INDETERMINATE"
        else:
            overall = "VERIFIED"

        return Law5070ArticleAssessment(
            article_4_elements=m4_elements,
            article_4_conclusion=m4_conclusion,
            article_6_sscd_conclusion=m6_conclusion,
            article_6_details=m6_details,
            article_9_nes_conclusion=m9_conclusion,
            article_9_details=m9_details,
            kms_hsm_misclassification_blocked=is_kms_or_server_hsm,
            overall_5070_conclusion=overall,
            missing_external_evidences=tuple(sorted(set(missing_ext))),
            legal_notes=tuple(legal_notes),
            error_codes=tuple(sorted(set(error_codes))),
            errors=tuple(errors),
        )

    def _build_evidence_bundle(
        self,
        *,
        signature_format: str,
        raw_signature_bytes: bytes,
        profile_res: ProfileComplianceResult,
        cert_info: SignerCertificateInspection | None,
        eshs_res: Any,
        rev_res: Any,
        sscd_res: SscdControlEvidenceVerificationResult | None,
        sig_ts_dict: dict[str, Any] | None,
        archive_ts_dict: dict[str, Any] | None,
        crypto_valid: bool,
        law5070_res: Law5070ArticleAssessment,
        validation_time_utc: str,
    ) -> VerificationEvidenceBundle:
        now_utc = _now_utc_iso()
        bundle_id = f"EVB-5070-{signature_format}-{secrets.token_hex(6).upper()}"
        items: list[EvidenceItem] = []

        # 1. Signature artifact
        items.append(
            EvidenceItem(
                evidence_id=f"{bundle_id}-SIG",
                evidence_type=f"{signature_format}_SIGNATURE",
                source=f"{signature_format.lower()}_input_payload",
                provider=self.provider_name,
                acquired_at_utc=now_utc,
                valid_from_utc=cert_info.not_before_utc if cert_info and cert_info.valid_x509 else None,
                valid_until_utc=cert_info.not_after_utc if cert_info and cert_info.valid_x509 else None,
                sha256=hashlib.sha256(raw_signature_bytes).hexdigest(),
                certificate_serial_number=cert_info.serial_number if cert_info and cert_info.valid_x509 else None,
                algorithm=cert_info.signature_algorithm if cert_info and cert_info.valid_x509 else None,
                profile=profile_res.achieved_profile,
                verification_result="PASSED" if crypto_valid else "FAILED",
                trust_list_version=eshs_res.btk_list_version,
                details={
                    "standard": profile_res.standard,
                    "claimed_profile": profile_res.canonical_claimed_profile,
                    "profile_compliant": profile_res.profile_compliant,
                    "law_5070_conclusion": law5070_res.overall_5070_conclusion,
                },
            )
        )

        # 2. Signer X.509 certificate
        if cert_info and cert_info.valid_x509:
            items.append(
                EvidenceItem(
                    evidence_id=f"{bundle_id}-CERT",
                    evidence_type="SIGNER_X509_CERTIFICATE",
                    source="embedded_signature_certificate",
                    provider=self.provider_name,
                    acquired_at_utc=now_utc,
                    valid_from_utc=cert_info.not_before_utc,
                    valid_until_utc=cert_info.not_after_utc,
                    sha256=cert_info.cert_sha256,
                    certificate_serial_number=cert_info.serial_number,
                    algorithm=cert_info.signature_algorithm,
                    profile=profile_res.achieved_profile,
                    verification_result="PASSED" if cert_info.valid_at_validation_time else "FAILED",
                    trust_list_version=eshs_res.btk_list_version,
                    details={
                        "subject": cert_info.subject,
                        "issuer": cert_info.issuer,
                        "qc_statements_present": cert_info.qc_statements_present,
                        "qc_compliance": cert_info.qc_compliance,
                        "qc_sscd": cert_info.qc_sscd,
                        "certificate_policy_oids": list(cert_info.certificate_policy_oids),
                    },
                )
            )

        # 3. BTK ESHS trust list & separate CA chain
        eshs_sha = eshs_res.bundle_sha256 or hashlib.sha256(canonical_json_bytes(eshs_res.to_dict())).hexdigest()
        items.append(
            EvidenceItem(
                evidence_id=f"{bundle_id}-ESHS",
                evidence_type="BTK_ESHS_TRUST_AND_CA_CHAIN",
                source=eshs_res.eshs_id or "UNRESOLVED_ESHS",
                provider=eshs_res.provider_backend,
                acquired_at_utc=now_utc,
                valid_from_utc=validation_time_utc,
                valid_until_utc=validation_time_utc,
                sha256=eshs_sha,
                certificate_serial_number=cert_info.serial_number if cert_info and cert_info.valid_x509 else None,
                algorithm=cert_info.signature_algorithm if cert_info and cert_info.valid_x509 else None,
                profile=profile_res.achieved_profile,
                verification_result=eshs_res.conclusion,
                trust_list_version=eshs_res.btk_list_version,
                details={
                    "btk_provider_authorized": eshs_res.btk_provider_authorized,
                    "btk_authorization_status": eshs_res.btk_authorization_status,
                    "ca_chain_verified": eshs_res.ca_chain_verified,
                    "policy_matched": eshs_res.policy_matched,
                    "matched_policy_oids": list(eshs_res.matched_policy_oids),
                    "is_sandbox_ca": eshs_res.is_sandbox_ca,
                },
            )
        )

        # 4. OCSP / CRL revocation
        rev_sha = rev_res.evidence_sha256 or hashlib.sha256(canonical_json_bytes(rev_res.to_dict())).hexdigest()
        items.append(
            EvidenceItem(
                evidence_id=f"{bundle_id}-REV",
                evidence_type=f"REVOCATION_{rev_res.method}",
                source=rev_res.responder_or_issuer or rev_res.method,
                provider=rev_res.provider_backend,
                acquired_at_utc=rev_res.checked_at_utc,
                valid_from_utc=rev_res.this_update_utc,
                valid_until_utc=rev_res.next_update_utc,
                sha256=rev_sha,
                certificate_serial_number=rev_res.certificate_serial_number,
                algorithm="SHA-256",
                profile=profile_res.achieved_profile,
                verification_result=rev_res.conclusion,
                trust_list_version=eshs_res.btk_list_version,
                details={
                    "revocation_status": rev_res.status,
                    "method": rev_res.method,
                    "historical_archive_evidence": rev_res.historical_archive_evidence,
                    "revoked_at_utc": rev_res.revoked_at_utc,
                    "revocation_reason": rev_res.revocation_reason,
                },
            )
        )

        # 5. Cryptographically Verified SSCD / Sole-Control Evidence (v1.0.4.1 BLOCKER 1)
        if sscd_res is not None:
            items.append(
                EvidenceItem(
                    evidence_id=f"{bundle_id}-SSCD",
                    evidence_type="SSCD_CONTROL_EVIDENCE",
                    source=sscd_res.issuer_id or "UNRESOLVED_SSCD_ISSUER",
                    provider=sscd_res.verifier_service_id,
                    acquired_at_utc=now_utc,
                    valid_from_utc=sscd_res.valid_from_utc,
                    valid_until_utc=sscd_res.valid_until_utc,
                    sha256=sscd_res.envelope_sha256,
                    certificate_serial_number=sscd_res.issuer_cert_serial_number,
                    algorithm=sscd_res.signature_algorithm,
                    profile=profile_res.achieved_profile,
                    verification_result=sscd_res.conclusion,
                    trust_list_version=eshs_res.btk_list_version,
                    details={
                        "evidence_id": sscd_res.evidence_id,
                        "issuer_authorized": sscd_res.issuer_authorized,
                        "issuer_cert_chain_verified": sscd_res.issuer_cert_chain_verified,
                        "issuer_revocation_status": sscd_res.issuer_revocation_status,
                        "signature_verified": sscd_res.signature_verified,
                        "scope_verified": sscd_res.scope_verified,
                        "bound_signer_cert_sha256": sscd_res.bound_signer_cert_sha256,
                        "is_sandbox_issuer": sscd_res.is_sandbox_issuer,
                    },
                )
            )

        # 6. Timestamp items
        ts_evidences: list[dict[str, Any]] = []
        for idx, ts_obj in enumerate((sig_ts_dict, archive_ts_dict), start=1):
            if ts_obj is None:
                continue
            ts_sha = str(ts_obj.get("tsr_sha256") or hashlib.sha256(canonical_json_bytes(ts_obj)).hexdigest())
            ts_evidences.append(
                {
                    "kind": ts_obj.get("kind"),
                    "valid": bool(ts_obj.get("valid")),
                    "status": ts_obj.get("status"),
                    "gen_time_utc": ts_obj.get("gen_time_utc"),
                    "message_imprint_sha256": ts_obj.get("message_imprint_sha256"),
                    "policy_oid": ts_obj.get("policy_oid"),
                    "serial_number": ts_obj.get("serial_number"),
                    "tsa_cert_subject": ts_obj.get("tsa_cert_subject"),
                    "tsr_sha256": ts_sha,
                }
            )
            items.append(
                EvidenceItem(
                    evidence_id=f"{bundle_id}-TS{idx}",
                    evidence_type=f"RFC3161_{ts_obj.get('kind', 'TIMESTAMP')}",
                    source=str(ts_obj.get("tsa_url") or ts_obj.get("tsa_cert_subject") or "RFC3161_TSA"),
                    provider=str(ts_obj.get("provider_backend") or self.tsa_provider.provider_name),
                    acquired_at_utc=now_utc,
                    valid_from_utc=ts_obj.get("gen_time_utc"),
                    valid_until_utc=ts_obj.get("gen_time_utc"),
                    sha256=ts_sha,
                    certificate_serial_number=ts_obj.get("serial_number"),
                    algorithm=str(ts_obj.get("digest_algorithm") or "SHA-256"),
                    profile=profile_res.achieved_profile,
                    verification_result="PASSED" if ts_obj.get("valid") else "FAILED",
                    trust_list_version=eshs_res.btk_list_version,
                    details={"policy_oid": ts_obj.get("policy_oid"), "kind": ts_obj.get("kind")},
                )
            )

        ocsp_crl_evidences = [
            {
                "method": rev_res.method,
                "status": rev_res.status,
                "conclusion": rev_res.conclusion,
                "checked_at_utc": rev_res.checked_at_utc,
                "this_update_utc": rev_res.this_update_utc,
                "next_update_utc": rev_res.next_update_utc,
                "revoked_at_utc": rev_res.revoked_at_utc,
                "revocation_reason": rev_res.revocation_reason,
                "evidence_sha256": rev_sha,
                "historical_archive_evidence": rev_res.historical_archive_evidence,
            }
        ]

        unsigned_bundle = {
            "schema_version": ESIGN_5070_VERSION,
            "bundle_id": bundle_id,
            "created_at_utc": now_utc,
            "trust_list_version": eshs_res.btk_list_version,
            "items": [it.to_dict() for it in items],
            "ocsp_crl_evidences": ocsp_crl_evidences,
            "timestamp_evidences": ts_evidences,
        }
        bundle_sha = hashlib.sha256(canonical_json_bytes(unsigned_bundle)).hexdigest()
        return VerificationEvidenceBundle(
            schema_version=ESIGN_5070_VERSION,
            bundle_id=bundle_id,
            created_at_utc=now_utc,
            trust_list_version=eshs_res.btk_list_version,
            items=tuple(items),
            ocsp_crl_evidences=tuple(ocsp_crl_evidences),
            timestamp_evidences=tuple(ts_evidences),
            bundle_sha256=bundle_sha,
        )

    def _finalize_pipeline(
        self,
        *,
        signature_format: str,
        standard: str,
        raw_signature_bytes: bytes,
        crypto_valid: bool,
        crypto_error_codes: list[str],
        crypto_errors: list[str],
        has_signing_cert_ref: bool,
        signer_cert_pem: str | None,
        signature_value_bytes: bytes | None,
        claimed_profile: str,
        expected_eshs_id: str | None,
        validation_time_utc: str | None,
        signature_timestamp_tsr_der: bytes | None,
        archive_timestamp_tsr_der: bytes | None,
        archived_ocsp_response_der: bytes | None,
        archived_ocsp_signer_cert_pem: str | None,
        archived_crl_pem: str | None,
        sscd_control_evidence_result: SscdControlEvidenceVerificationResult | None,
        sscd_control_evidence_envelope: dict[str, Any] | None,
        archived_sscd_issuer_ocsp_der: bytes | None,
        archived_sscd_issuer_ocsp_signer_cert_pem: str | None,
        archived_sscd_issuer_crl_pem: str | None,
        external_sscd_control_evidence: Any,
        xmldsig_details: dict[str, Any] | None,
        runtime_environment: str,
    ) -> QualifiedSignature5070VerificationResult:
        # 1. Verify signature timestamp first
        sig_val_digest = (
            hashlib.sha256(signature_value_bytes).hexdigest()
            if signature_value_bytes
            else (hashlib.sha256(raw_signature_bytes).hexdigest() if raw_signature_bytes else None)
        )
        sig_ts_dict = self._verify_timestamp(
            tsr_der=signature_timestamp_tsr_der,
            expected_digest_sha256=sig_val_digest,
            kind="SIGNATURE_TIMESTAMP",
        )

        has_archived_rev = bool(archived_ocsp_response_der or archived_crl_pem)
        historical_mode = bool(has_archived_rev or archive_timestamp_tsr_der is not None)
        effective_val_time = validation_time_utc or (
            str(sig_ts_dict["gen_time_utc"])
            if (sig_ts_dict and sig_ts_dict.get("valid") and sig_ts_dict.get("gen_time_utc"))
            else _now_utc_iso()
        )

        archive_target_bytes = signature_value_bytes if signature_value_bytes else raw_signature_bytes
        archive_imprint = (
            compute_archive_imprint_sha256(
                signature_bytes=archive_target_bytes,
                signature_timestamp_tsr_der=signature_timestamp_tsr_der,
                archived_ocsp_response_der=archived_ocsp_response_der,
                archived_crl_pem=archived_crl_pem,
            )
            if archive_target_bytes
            else None
        )
        archive_ts_dict = self._verify_timestamp(
            tsr_der=archive_timestamp_tsr_der,
            expected_digest_sha256=archive_imprint,
            kind="ARCHIVE_TIMESTAMP",
        )

        # 2. Inspect signer X.509 certificate
        cert_info = (
            inspect_signer_certificate_x509(signer_cert_pem, validation_time_utc=effective_val_time)
            if signer_cert_pem
            else None
        )

        # 3. Evaluate BTK ESHS authorization + separate ESHS CA chain + certificate policy
        eshs_res = self.eshs_trust_provider.evaluate_signer_trust(
            signer_cert_pem or "",
            validation_time_utc=effective_val_time,
            expected_eshs_id=expected_eshs_id,
            runtime_environment=runtime_environment,
        )

        # 4. Evaluate OCSP/CRL revocation
        rev_res = self.revocation_provider.check_revocation(
            signer_cert_pem or "",
            eshs_res.issuer_ca_pem if signer_cert_pem else None,
            validation_time_utc=effective_val_time,
            archived_ocsp_response_der=archived_ocsp_response_der if signer_cert_pem else None,
            archived_ocsp_signer_cert_pem=archived_ocsp_signer_cert_pem if signer_cert_pem else None,
            archived_crl_pem=archived_crl_pem if signer_cert_pem else None,
            runtime_environment=runtime_environment,
        )

        # 5. Cryptographically authenticate / verify SSCD/QSCD sole-control evidence (BLOCKER 1)
        sscd_res, sscd_kms_blocked, sscd_hard_reject, sscd_codes, sscd_errors = self._resolve_verified_sscd_evidence(
            sscd_control_evidence_result=sscd_control_evidence_result,
            sscd_control_evidence_envelope=sscd_control_evidence_envelope,
            external_sscd_control_evidence=external_sscd_control_evidence,
            cert_info=cert_info,
            effective_val_time=effective_val_time,
            archived_sscd_issuer_ocsp_der=archived_sscd_issuer_ocsp_der,
            archived_sscd_issuer_ocsp_signer_cert_pem=archived_sscd_issuer_ocsp_signer_cert_pem,
            archived_sscd_issuer_crl_pem=archived_sscd_issuer_crl_pem,
            runtime_environment=runtime_environment,
        )

        # 6. Profile compliance (STRICTLY SEPARATE from cryptographic validity)
        profile_res = self._evaluate_profile(
            signature_format=signature_format,
            standard=standard,
            claimed_profile_raw=claimed_profile,
            crypto_valid=crypto_valid,
            has_signing_cert_ref=has_signing_cert_ref,
            sig_ts_dict=sig_ts_dict,
            archive_ts_dict=archive_ts_dict,
            has_embedded_validation_data=has_archived_rev and bool(eshs_res.issuer_ca_pem),
            revocation_passed=(rev_res.status == "GOOD" and rev_res.conclusion == "PASSED"),
            eshs_chain_verified=eshs_res.ca_chain_verified,
        )

        # 7. Law No. 5070 Articles 4 / 6 / 9 legal assessment
        law5070_res = self._evaluate_law_5070(
            crypto_valid=crypto_valid,
            profile_res=profile_res,
            cert_info=cert_info,
            eshs_res=eshs_res,
            rev_res=rev_res,
            sig_ts_dict=sig_ts_dict,
            archive_ts_dict=archive_ts_dict,
            sscd_res=sscd_res,
            sscd_kms_blocked=sscd_kms_blocked,
            sscd_hard_reject=sscd_hard_reject,
            sscd_codes=sscd_codes,
            sscd_errors=sscd_errors,
            historical_archive_mode=historical_mode,
        )

        # 8. Unified VerificationEvidenceBundle
        evidence_bundle = self._build_evidence_bundle(
            signature_format=signature_format,
            raw_signature_bytes=raw_signature_bytes,
            profile_res=profile_res,
            cert_info=cert_info,
            eshs_res=eshs_res,
            rev_res=rev_res,
            sscd_res=sscd_res,
            sig_ts_dict=sig_ts_dict,
            archive_ts_dict=archive_ts_dict,
            crypto_valid=crypto_valid,
            law5070_res=law5070_res,
            validation_time_utc=effective_val_time,
        )

        all_codes = sorted(
            set(crypto_error_codes)
            | set(profile_res.error_codes)
            | set(eshs_res.error_codes)
            | set(rev_res.error_codes)
            | set(law5070_res.error_codes)
        )
        dedup_errors: list[str] = []
        for e in list(crypto_errors) + list(profile_res.errors) + list(law5070_res.errors):
            if e and e not in dedup_errors:
                dedup_errors.append(e)

        env_norm = str(runtime_environment or "PRODUCTION").upper().strip()
        sandbox_blocked_in_prod = bool(
            env_norm == "PRODUCTION"
            and (
                self._integration_mode != "LIVE_PRODUCTION"
                or eshs_res.is_sandbox_ca
                or (sscd_res is not None and sscd_res.is_sandbox_issuer)
            )
        )

        qualified_verified = (
            law5070_res.overall_5070_conclusion == "VERIFIED"
            and crypto_valid
            and profile_res.profile_compliant
            and eshs_res.valid
            and rev_res.status == "GOOD"
            and rev_res.conclusion == "PASSED"
            and sscd_res is not None
            and sscd_res.valid
            and not sscd_hard_reject
            and not sandbox_blocked_in_prod
        )
        qualified_conclusion = (
            "VERIFIED"
            if qualified_verified
            else (
                "FAILED"
                if (
                    law5070_res.overall_5070_conclusion == "FAILED"
                    or (env_norm == "PRODUCTION" and (eshs_res.is_sandbox_ca or (sscd_res is not None and sscd_res.is_sandbox_issuer)))
                )
                else "INDETERMINATE"
            )
        )

        # HMAC service seal is attached ONLY AFTER full technical, cryptographic & legal verification completes!
        result = QualifiedSignature5070VerificationResult(
            schema_version=ESIGN_5070_VERSION,
            signature_format=signature_format,
            standard=standard,
            cryptographic_signature_valid=crypto_valid,
            qualified_e_signature_5070_verified=qualified_verified,
            qualified_e_signature_5070_conclusion=qualified_conclusion,
            profile_compliance=profile_res,
            signer_certificate=cert_info,
            eshs_trust=eshs_res,
            revocation=rev_res,
            signature_timestamp=sig_ts_dict,
            archive_timestamp=archive_ts_dict,
            law_5070_assessment=law5070_res,
            evidence_bundle=evidence_bundle,
            validation_time_utc=effective_val_time,
            historical_archive_mode=historical_mode,
            provider_backend=self.provider_name,
            integration_mode=self._integration_mode,
            verifier_service_id=self.provider_name,
            sscd_control_evidence=sscd_res,
            xmldsig_details=xmldsig_details,
            legal_separation_notice=LAW_5070_SEPARATION_NOTICE,
            error_codes=tuple(all_codes),
            errors=tuple(dedup_errors),
        )
        return seal_esign5070_result(result)

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
        crypto_valid = False
        has_signing_cert_ref = False
        signer_cert_pem: str | None = None
        crypto_codes: list[str] = []
        crypto_errors: list[str] = []
        sig_val_bytes: bytes | None = None

        if not cms_der_bytes:
            crypto_codes.append("CADES_PAYLOAD_EMPTY")
            crypto_errors.append("CAdES CMS DER imza verisi boştur.")
        else:
            openssl = _openssl_exe()
            with tempfile.TemporaryDirectory(prefix="calisora_cades_ver_") as tmp:
                cms_path = Path(tmp) / "sig.p7s"
                out_path = Path(tmp) / "verified.out"
                signer_out_path = Path(tmp) / "signer_out.pem"
                cms_path.write_bytes(cms_der_bytes)

                content_args: list[str] = []
                if signed_content_bytes is not None:
                    data_path = Path(tmp) / "content.bin"
                    data_path.write_bytes(signed_content_bytes)
                    content_args = ["-content", str(data_path)]

                p_math = subprocess.run(
                    [
                        openssl,
                        "cms",
                        "-verify",
                        "-inform",
                        "DER",
                        "-in",
                        str(cms_path),
                        *content_args,
                        "-binary",
                        "-noverify",
                        "-verify_retcode",
                        "-signer",
                        str(signer_out_path),
                        "-out",
                        str(out_path),
                    ],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                if p_math.returncode == 0:
                    crypto_valid = True
                    if signer_out_path.is_file():
                        s_blocks = re.findall(
                            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                            signer_out_path.read_text(encoding="utf-8", errors="ignore"),
                            flags=re.DOTALL,
                        )
                        if s_blocks:
                            signer_cert_pem = s_blocks[0]
                else:
                    crypto_codes.append("CADES_CRYPTOGRAPHIC_VERIFICATION_FAILED")
                    crypto_errors.append(
                        f"CAdES kriptografik imza doğrulaması başarısız (içerik veya imza bozulmuş olabilir): "
                        f"{(p_math.stderr or p_math.stdout).strip()}"
                    )

                if signer_cert_pem is None:
                    p_certs = subprocess.run(
                        [openssl, "pkcs7", "-inform", "DER", "-in", str(cms_path), "-print_certs"],
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                    if p_certs.returncode == 0:
                        pem_blocks = re.findall(
                            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                            p_certs.stdout,
                            flags=re.DOTALL,
                        )
                        if pem_blocks:
                            non_ca = None
                            for blk in pem_blocks:
                                insp = inspect_signer_certificate_x509(
                                    blk, validation_time_utc=validation_time_utc or _now_utc_iso()
                                )
                                if insp.valid_x509 and not insp.basic_constraints_ca:
                                    non_ca = blk
                                    break
                            signer_cert_pem = non_ca or pem_blocks[0]

                p_print = subprocess.run(
                    [openssl, "cms", "-cmsout", "-inform", "DER", "-in", str(cms_path), "-print"],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                if p_print.returncode == 0:
                    txt_cms = p_print.stdout
                    sig_val_bytes = _parse_cades_sigval_from_cms_print(txt_cms)
                    if crypto_valid and signer_cert_pem:
                        m_sa = re.search(
                            r"signedAttrs:(.*?)(?:signatureAlgorithm:|unsignedAttrs:|\Z)",
                            txt_cms,
                            flags=re.DOTALL,
                        )
                        sa_block = m_sa.group(1) if m_sa else ""
                        cert_sha256_up = cert_pem_to_der_sha256(signer_cert_pem).upper()
                        cert_sha1_up = _cert_pem_to_der_sha1(signer_cert_pem).upper()
                        has_v2 = (
                            ("1.2.840.113549.1.9.16.2.47" in sa_block or "id-smime-aa-signingCertificateV2" in sa_block)
                            and cert_sha256_up in sa_block.upper()
                        )
                        has_v1 = (
                            ("1.2.840.113549.1.9.16.2.12" in sa_block or "id-smime-aa-signingCertificate " in sa_block)
                            and cert_sha1_up in sa_block.upper()
                        )
                        has_signing_cert_ref = bool(has_v2 or has_v1)

        return self._finalize_pipeline(
            signature_format="CADES",
            standard=ETSI_CADES_STANDARD,
            raw_signature_bytes=cms_der_bytes or b"",
            crypto_valid=crypto_valid,
            crypto_error_codes=crypto_codes,
            crypto_errors=crypto_errors,
            has_signing_cert_ref=has_signing_cert_ref,
            signer_cert_pem=signer_cert_pem,
            signature_value_bytes=sig_val_bytes,
            claimed_profile=claimed_profile,
            expected_eshs_id=expected_eshs_id,
            validation_time_utc=validation_time_utc,
            signature_timestamp_tsr_der=signature_timestamp_tsr_der,
            archive_timestamp_tsr_der=archive_timestamp_tsr_der,
            archived_ocsp_response_der=archived_ocsp_response_der,
            archived_ocsp_signer_cert_pem=archived_ocsp_signer_cert_pem,
            archived_crl_pem=archived_crl_pem,
            sscd_control_evidence_result=sscd_control_evidence_result,
            sscd_control_evidence_envelope=sscd_control_evidence_envelope,
            archived_sscd_issuer_ocsp_der=archived_sscd_issuer_ocsp_der,
            archived_sscd_issuer_ocsp_signer_cert_pem=archived_sscd_issuer_ocsp_signer_cert_pem,
            archived_sscd_issuer_crl_pem=archived_sscd_issuer_crl_pem,
            external_sscd_control_evidence=external_sscd_control_evidence,
            xmldsig_details=None,
            runtime_environment=runtime_environment,
        )

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
        insp = verify_xades_xmldsig(xades_xml_bytes or b"", signed_content_bytes=signed_content_bytes)

        eff_sig_ts = signature_timestamp_tsr_der if signature_timestamp_tsr_der is not None else insp.embedded_sig_ts_der
        eff_arch_ts = archive_timestamp_tsr_der if archive_timestamp_tsr_der is not None else insp.embedded_archive_ts_der
        eff_ocsp = archived_ocsp_response_der if archived_ocsp_response_der is not None else insp.embedded_ocsp_der
        eff_crl = archived_crl_pem if archived_crl_pem is not None else insp.embedded_crl_pem

        return self._finalize_pipeline(
            signature_format="XADES",
            standard=ETSI_XADES_STANDARD,
            raw_signature_bytes=xades_xml_bytes or b"",
            crypto_valid=insp.crypto_valid,
            crypto_error_codes=list(insp.error_codes),
            crypto_errors=list(insp.errors),
            has_signing_cert_ref=insp.has_signing_cert_ref,
            signer_cert_pem=insp.signer_cert_pem,
            signature_value_bytes=insp.signature_value_bytes,
            claimed_profile=claimed_profile,
            expected_eshs_id=expected_eshs_id,
            validation_time_utc=validation_time_utc,
            signature_timestamp_tsr_der=eff_sig_ts,
            archive_timestamp_tsr_der=eff_arch_ts,
            archived_ocsp_response_der=eff_ocsp,
            archived_ocsp_signer_cert_pem=archived_ocsp_signer_cert_pem,
            archived_crl_pem=eff_crl,
            sscd_control_evidence_result=sscd_control_evidence_result,
            sscd_control_evidence_envelope=sscd_control_evidence_envelope,
            archived_sscd_issuer_ocsp_der=archived_sscd_issuer_ocsp_der,
            archived_sscd_issuer_ocsp_signer_cert_pem=archived_sscd_issuer_ocsp_signer_cert_pem,
            archived_sscd_issuer_crl_pem=archived_sscd_issuer_crl_pem,
            external_sscd_control_evidence=external_sscd_control_evidence,
            xmldsig_details=insp.xmldsig_details,
            runtime_environment=runtime_environment,
        )
