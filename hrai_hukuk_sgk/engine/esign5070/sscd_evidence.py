"""Cryptographically Verified Law No. 5070 m.4/c Sole-Control & m.6 SSCD/QSCD Evidence Verifier for hrAI @HukukSGK (v1.0.5.1).

Closes BLOCKER 1 from the v1.0.4 independent security review:
  - Plain caller Python dicts (`external_sscd_control_evidence={...}`) can NEVER grant Law No. 5070
    m.4/c sole-control or m.6 SSCD/QSCD legal compliance.
  - Law No. 5070 m.4/c (`sole_control_attested`, `pin_or_biometric_activation_verified`) and m.6
    (`sscd_device_certified`, `sscd_certification_ref`, `signing_device_type`) values MUST come
    exclusively from an authentic, service-sealed `SscdControlEvidenceVerificationResult` produced by
    `DefaultSscdControlEvidenceVerifier` AFTER cryptographically verifying:
      1. Authorized issuer identity, role, status (`ACTIVE`), and authorization time window,
      2. Issuer X.509 end-entity certificate and strict RFC 5280 (`-x509_strict -attime`) CA chain,
      3. Issuer certificate revocation status (`GOOD` via OCSP/CRL; `REVOKED` -> `FAILED`; `UNAVAILABLE` -> `INDETERMINATE`),
      4. Asymmetric cryptographic signature over RFC 8785 (JCS) canonical JSON payload,
      5. Evidence validity window (`valid_from_utc` .. `valid_until_utc`),
      6. Authorized scope coverage (`LAW_5070_M4C_SOLE_CONTROL`, `LAW_5070_M6_SSCD_CERTIFICATION`),
      7. Exact signer X.509 certificate SHA-256 binding (`bound_signer_cert_sha256`),
      8. Sandbox issuer rejection in `PRODUCTION` and KMS/HSM exclusion.
  - Per-process HMAC service seal (`_service_seal`) is attached ONLY AFTER verification completes,
    preventing caller-constructed `SscdControlEvidenceVerificationResult` forgery.
"""

from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import hmac
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
from typing import Any, Sequence

from ..attestation_verifier import canonical_json_bytes, parse_utc_timestamp
from .eshs_trust import _cert_has_sandbox_marker, inspect_signer_certificate_x509
from .interfaces import CertificateRevocationProvider
from .models import (
    AuthorizedSscdEvidenceIssuer,
    SscdControlEvidenceVerificationResult,
)
from .revocation import DefaultCertificateRevocationProvider
from .x509_metadata import parse_x509_certificate_metadata

# Dedicated per-process HMAC key sealing authentic SscdControlEvidenceVerificationResult outputs
_SSCD_EVIDENCE_SEAL_KEY: bytes = secrets.token_bytes(32)

REQUIRED_SSCD_SCOPES: frozenset[str] = frozenset(
    {
        "LAW_5070_M4C_SOLE_CONTROL",
        "LAW_5070_M6_SSCD_CERTIFICATION",
    }
)

SUPPORTED_SSCD_ENVELOPE_ALGORITHMS: frozenset[str] = frozenset(
    {
        "RSA-SHA256",
        "RSA-PSS-SHA256",
        "ECDSA-SHA256",
        "ED25519",
    }
)

_ALLOWED_ISSUER_ROLES: frozenset[str] = frozenset(
    {
        "QSCD_CONFORMITY_ASSESSMENT_BODY",
        "BTK_AUTHORIZED_ESHS_QSCD_AUTHORITY",
        "CERTIFIED_REMOTE_QSCD_AUDITOR",
    }
)

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


def _openssl_exe() -> str:
    exe = shutil.which("openssl")
    if not exe:
        raise RuntimeError("OpenSSL CLI bulunamadı; SSCD/QSCD kanıt doğrulaması çalıştırılamaz.")
    return exe


def _extract_clean_pem(pem_text: str) -> str | None:
    if not isinstance(pem_text, str):
        return None
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem_text, flags=re.DOTALL)
    return (m.group(0).strip() + "\n") if m else None


def _compute_sscd_seal(result: SscdControlEvidenceVerificationResult) -> str:
    payload = {
        "result_type": type(result).__qualname__,
        "fields": result.to_dict(),
    }
    return hmac.new(_SSCD_EVIDENCE_SEAL_KEY, canonical_json_bytes(payload), hashlib.sha256).hexdigest()


def seal_sscd_evidence_result(
    result: SscdControlEvidenceVerificationResult,
) -> SscdControlEvidenceVerificationResult:
    """Attach process-ephemeral HMAC authenticity seal AFTER verification completes."""
    return replace(result, _service_seal=_compute_sscd_seal(result))


def verify_sscd_evidence_result_authenticity(result: Any) -> bool:
    """Verify that `result` was genuinely issued by `DefaultSscdControlEvidenceVerifier` (not caller-forged)."""
    if not isinstance(result, SscdControlEvidenceVerificationResult):
        return False
    seal = getattr(result, "_service_seal", "")
    if not isinstance(seal, str) or len(seal) != 64:
        return False
    expected = _compute_sscd_seal(result)
    return hmac.compare_digest(seal, expected)


def create_signed_sscd_control_evidence_envelope(
    *,
    evidence_id: str,
    issuer_id: str,
    issuer_cert_pem: str,
    issuer_key_pem: str,
    bound_signer_cert_sha256: str,
    valid_from_utc: str,
    valid_until_utc: str,
    issued_at_utc: str,
    authorized_scopes: Sequence[str] = ("LAW_5070_M4C_SOLE_CONTROL", "LAW_5070_M6_SSCD_CERTIFICATION"),
    signature_origin: str = "QUALIFIED_SIGNER_DEVICE",
    signing_device_type: str = "SMART_CARD_QSCD",
    sole_control_attested: bool = True,
    pin_or_biometric_activation_verified: bool = True,
    sscd_device_certified: bool = True,
    sscd_certification_ref: str = "TSE-CC-EAL4PLUS-QSCD-2026-001",
    signature_algorithm: str = "RSA-SHA256",
    nonce: str | None = None,
) -> dict[str, Any]:
    """Create a real OpenSSL 3 signed SSCD/QSCD sole-control attestation envelope (RFC 8785 JCS; zero persistence)."""
    alg_norm = str(signature_algorithm or "RSA-SHA256").upper().strip()
    if alg_norm not in SUPPORTED_SSCD_ENVELOPE_ALGORITHMS:
        raise ValueError(f"Desteklenmeyen SSCD zarf imza algoritması: {signature_algorithm!r}")
    clean_cert = _extract_clean_pem(issuer_cert_pem)
    if not clean_cert:
        raise ValueError("Geçerli issuer_cert_pem PEM bloğu zorunludur.")

    payload = {
        "schema": "CALISORA_SSCD_CONTROL_EVIDENCE_V1",
        "evidence_id": str(evidence_id),
        "issuer_id": str(issuer_id),
        "issued_at_utc": str(issued_at_utc),
        "valid_from_utc": str(valid_from_utc),
        "valid_until_utc": str(valid_until_utc),
        "authorized_scopes": sorted({str(s).strip() for s in authorized_scopes if str(s).strip()}),
        "bound_signer_cert_sha256": str(bound_signer_cert_sha256).strip().lower(),
        "signature_origin": str(signature_origin).strip(),
        "signing_device_type": str(signing_device_type).strip(),
        "sole_control_attested": bool(sole_control_attested),
        "pin_or_biometric_activation_verified": bool(pin_or_biometric_activation_verified),
        "sscd_device_certified": bool(sscd_device_certified),
        "sscd_certification_ref": str(sscd_certification_ref).strip() if sscd_certification_ref else None,
        "nonce": nonce or f"SSCD-NONCE-{secrets.token_hex(8).upper()}",
    }
    msg_bytes = canonical_json_bytes(payload)
    openssl = _openssl_exe()

    with tempfile.TemporaryDirectory(prefix="calisora_sscd_sign_") as tmp:
        key_path = Path(tmp) / "issuer.key"
        msg_path = Path(tmp) / "payload.jcs"
        sig_path = Path(tmp) / "sig.bin"
        key_path.write_text(issuer_key_pem.strip() + "\n", encoding="utf-8")
        msg_path.write_bytes(msg_bytes)

        if alg_norm == "ED25519":
            cmd = [
                openssl, "pkeyutl", "-sign", "-inkey", str(key_path),
                "-rawin", "-in", str(msg_path), "-out", str(sig_path),
            ]
        elif alg_norm == "RSA-PSS-SHA256":
            cmd = [
                openssl, "dgst", "-sha256", "-sign", str(key_path),
                "-sigopt", "rsa_padding_mode:pss",
                "-sigopt", "rsa_pss_saltlen:32",
                "-sigopt", "rsa_mgf1_md:sha256",
                "-out", str(sig_path), str(msg_path),
            ]
        else:
            # RSA-SHA256 / ECDSA-SHA256
            cmd = [
                openssl, "dgst", "-sha256", "-sign", str(key_path),
                "-out", str(sig_path), str(msg_path),
            ]

        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"SSCD kanıt zarfı imzalanamadı: {proc.stderr.strip()}")
        sig_b64 = base64.b64encode(sig_path.read_bytes()).decode("ascii")

    return {
        "schema_version": "1.0.5.1",
        "payload": payload,
        "issuer_certificate_pem": clean_cert,
        "signature_algorithm": alg_norm,
        "signature_b64": sig_b64,
    }


class DefaultSscdControlEvidenceVerifier:
    """Cryptographically verifies signed Law No. 5070 m.4/c sole-control & m.6 SSCD/QSCD evidence envelopes."""

    def __init__(
        self,
        *,
        authorized_issuers: Sequence[AuthorizedSscdEvidenceIssuer] | None = None,
        revocation_provider: CertificateRevocationProvider | None = None,
        integration_mode: str | None = None,
    ) -> None:
        self._issuers: dict[str, AuthorizedSscdEvidenceIssuer] = {
            iss.issuer_id: iss for iss in (authorized_issuers or ())
        }
        self._revocation_provider: CertificateRevocationProvider = (
            revocation_provider or DefaultCertificateRevocationProvider()
        )
        if integration_mode is not None:
            self._integration_mode = integration_mode.upper().strip()
        elif not self._issuers:
            self._integration_mode = "NOT_CONFIGURED"
        elif any(i.trust_tier.upper().strip() != "LIVE_AUTHORIZED_ISSUER" for i in self._issuers.values()):
            self._integration_mode = "MOCK_SANDBOX"
        else:
            self._integration_mode = "LIVE_PRODUCTION"

    @property
    def verifier_service_id(self) -> str:
        return "HRAI_SSCD_CONTROL_EVIDENCE_VERIFIER_V1051"

    @property
    def integration_mode(self) -> str:
        return self._integration_mode

    def _verify_issuer_chain(
        self,
        issuer_cert_pem: str,
        issuer_rec: AuthorizedSscdEvidenceIssuer,
        validation_time_utc: str,
    ) -> tuple[bool, str | None, str | None]:
        openssl = _openssl_exe()
        attime_ts = str(int(parse_utc_timestamp(validation_time_utc).timestamp()))
        with tempfile.TemporaryDirectory(prefix="calisora_sscd_chain_") as tmp:
            roots_path = Path(tmp) / "roots.pem"
            leaf_path = Path(tmp) / "issuer.pem"
            roots_path.write_text("\n".join(p.strip() for p in issuer_rec.root_ca_pems) + "\n", encoding="utf-8")
            leaf_path.write_text(issuer_cert_pem.strip() + "\n", encoding="utf-8")

            cmd = [
                openssl, "verify", "-x509_strict", "-no-CApath",
                "-attime", attime_ts, "-CAfile", str(roots_path),
            ]
            if issuer_rec.intermediate_ca_pems:
                inter_path = Path(tmp) / "inters.pem"
                inter_path.write_text(
                    "\n".join(p.strip() for p in issuer_rec.intermediate_ca_pems) + "\n",
                    encoding="utf-8",
                )
                cmd.extend(["-untrusted", str(inter_path)])
            cmd.append(str(leaf_path))

            proc = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if proc.returncode == 0 and ": OK" in proc.stdout:
                issuer_ca = (
                    issuer_rec.intermediate_ca_pems[-1]
                    if issuer_rec.intermediate_ca_pems
                    else (issuer_rec.root_ca_pems[0] if issuer_rec.root_ca_pems else None)
                )
                return True, issuer_ca, None
            return False, None, (proc.stderr or proc.stdout).strip()

    def _verify_envelope_signature(
        self,
        *,
        payload: dict[str, Any],
        issuer_cert_pem: str,
        signature_algorithm: str,
        signature_b64: str,
    ) -> tuple[bool, str | None]:
        alg_norm = str(signature_algorithm or "").upper().strip()
        if alg_norm not in SUPPORTED_SSCD_ENVELOPE_ALGORITHMS:
            return False, f"Desteklenmeyen imza algoritması: {signature_algorithm!r}"
        try:
            sig_bytes = base64.b64decode(signature_b64, validate=True)
        except Exception as exc:
            return False, f"Base64 imza çözümlenemedi: {exc}"
        if not sig_bytes:
            return False, "İmza baytları boştur."

        cert_meta = parse_x509_certificate_metadata(issuer_cert_pem)
        if cert_meta is None or not cert_meta.spki_pem:
            return False, "Yayımlayıcı sertifikasından açık anahtar (SPKI) çıkarılamadı."

        msg_bytes = canonical_json_bytes(payload)
        openssl = _openssl_exe()
        with tempfile.TemporaryDirectory(prefix="calisora_sscd_sigver_") as tmp:
            pub_path = Path(tmp) / "pub.pem"
            msg_path = Path(tmp) / "payload.jcs"
            sig_path = Path(tmp) / "sig.bin"
            pub_path.write_text(cert_meta.spki_pem, encoding="utf-8")
            msg_path.write_bytes(msg_bytes)
            sig_path.write_bytes(sig_bytes)

            if alg_norm == "ED25519":
                cmd = [
                    openssl, "pkeyutl", "-verify", "-pubin", "-inkey", str(pub_path),
                    "-rawin", "-in", str(msg_path), "-sigfile", str(sig_path),
                ]
            elif alg_norm == "RSA-PSS-SHA256":
                cmd = [
                    openssl, "dgst", "-sha256", "-verify", str(pub_path),
                    "-sigopt", "rsa_padding_mode:pss",
                    "-sigopt", "rsa_pss_saltlen:32",
                    "-sigopt", "rsa_mgf1_md:sha256",
                    "-signature", str(sig_path), str(msg_path),
                ]
            else:
                cmd = [
                    openssl, "dgst", "-sha256", "-verify", str(pub_path),
                    "-signature", str(sig_path), str(msg_path),
                ]

            p_ver = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            combined = p_ver.stdout + "\n" + p_ver.stderr
            if p_ver.returncode == 0 and ("Verified OK" in combined or "Signature Verified Successfully" in combined):
                return True, None
            return False, combined.strip()

    def verify_sscd_evidence_envelope(
        self,
        envelope: dict[str, Any] | None,
        *,
        validation_time_utc: str,
        expected_signer_cert_sha256: str | None = None,
        archived_issuer_ocsp_der: bytes | None = None,
        archived_issuer_ocsp_signer_cert_pem: str | None = None,
        archived_issuer_crl_pem: str | None = None,
        runtime_environment: str = "PRODUCTION",
    ) -> SscdControlEvidenceVerificationResult:
        env_norm = str(runtime_environment or "PRODUCTION").upper().strip()
        errors: list[str] = []
        error_codes: list[str] = []

        if not isinstance(envelope, dict):
            return seal_sscd_evidence_result(
                SscdControlEvidenceVerificationResult(
                    valid=False,
                    conclusion="FAILED",
                    evidence_id="MISSING",
                    issuer_id=None,
                    issuer_name=None,
                    issuer_role=None,
                    issuer_authorized=False,
                    issuer_cert_chain_verified=False,
                    issuer_cert_serial_number=None,
                    issuer_cert_sha256=None,
                    issuer_revocation_status="UNAVAILABLE",
                    signature_verified=False,
                    signature_algorithm=None,
                    scope_verified=False,
                    authorized_scopes=(),
                    valid_from_utc=None,
                    valid_until_utc=None,
                    within_validity_window=False,
                    bound_signer_cert_sha256=None,
                    signature_origin=None,
                    signing_device_type=None,
                    sole_control_attested=False,
                    pin_or_biometric_activation_verified=False,
                    sscd_device_certified=False,
                    sscd_certification_ref=None,
                    is_sandbox_issuer=False,
                    envelope_sha256="0" * 64,
                    verifier_service_id=self.verifier_service_id,
                    integration_mode=self._integration_mode,
                    error_codes=("SSCD_EVIDENCE_ENVELOPE_MISSING",),
                    errors=("İmzalı SSCD/QSCD münhasır kontrol kanıt zarfı sağlanmamıştır.",),
                )
            )

        envelope_sha = hashlib.sha256(canonical_json_bytes(envelope)).hexdigest()
        payload = envelope.get("payload")
        raw_cert_pem = envelope.get("issuer_certificate_pem")
        sig_alg = str(envelope.get("signature_algorithm") or "").upper().strip()
        sig_b64 = envelope.get("signature_b64")

        if not isinstance(payload, dict) or not isinstance(raw_cert_pem, str) or not isinstance(sig_b64, str) or not sig_alg:
            return seal_sscd_evidence_result(
                SscdControlEvidenceVerificationResult(
                    valid=False,
                    conclusion="FAILED",
                    evidence_id=str((payload or {}).get("evidence_id") if isinstance(payload, dict) else "MALFORMED"),
                    issuer_id=None,
                    issuer_name=None,
                    issuer_role=None,
                    issuer_authorized=False,
                    issuer_cert_chain_verified=False,
                    issuer_cert_serial_number=None,
                    issuer_cert_sha256=None,
                    issuer_revocation_status="UNAVAILABLE",
                    signature_verified=False,
                    signature_algorithm=sig_alg or None,
                    scope_verified=False,
                    authorized_scopes=(),
                    valid_from_utc=None,
                    valid_until_utc=None,
                    within_validity_window=False,
                    bound_signer_cert_sha256=None,
                    signature_origin=None,
                    signing_device_type=None,
                    sole_control_attested=False,
                    pin_or_biometric_activation_verified=False,
                    sscd_device_certified=False,
                    sscd_certification_ref=None,
                    is_sandbox_issuer=False,
                    envelope_sha256=envelope_sha,
                    verifier_service_id=self.verifier_service_id,
                    integration_mode=self._integration_mode,
                    error_codes=("SSCD_EVIDENCE_ENVELOPE_MALFORMED",),
                    errors=("SSCD kanıt zarfı eksik veya geçersiz (payload, issuer_certificate_pem, signature_algorithm, signature_b64 zorunludur).",),
                )
            )

        evidence_id = str(payload.get("evidence_id") or "").strip() or "UNKNOWN"
        issuer_id = str(payload.get("issuer_id") or "").strip() or None
        valid_from_utc = str(payload.get("valid_from_utc") or "").strip() or None
        valid_until_utc = str(payload.get("valid_until_utc") or "").strip() or None
        raw_scopes = payload.get("authorized_scopes")
        payload_scopes = tuple(sorted({str(s).strip() for s in raw_scopes if str(s).strip()})) if isinstance(raw_scopes, list) else ()
        bound_cert_sha = str(payload.get("bound_signer_cert_sha256") or "").strip().lower() or None
        sig_origin = str(payload.get("signature_origin") or "").upper().strip() or None
        dev_type = str(payload.get("signing_device_type") or "").upper().strip() or None
        sscd_ref = str(payload.get("sscd_certification_ref") or "").strip() or None

        # 1. Authorized issuer lookup & status/role/window check
        issuer_rec = self._issuers.get(issuer_id) if issuer_id else None
        issuer_authorized = False
        is_sandbox = False
        if not self._issuers:
            error_codes.append("SSCD_ISSUER_REGISTRY_NOT_CONFIGURED")
            errors.append("Yetkili SSCD/QSCD kanıt yayımlayıcı kayıt defteri yapılandırılmamıştır.")
        elif issuer_rec is None:
            error_codes.append("SSCD_ISSUER_NOT_AUTHORIZED")
            errors.append(f"SSCD kanıt yayımlayıcısı ('{issuer_id}') yetkili kuruluş listesinde bulunamadı.")
        else:
            if issuer_rec.trust_tier.upper().strip() != "LIVE_AUTHORIZED_ISSUER":
                is_sandbox = True
            if issuer_rec.issuer_role not in _ALLOWED_ISSUER_ROLES:
                error_codes.append("SSCD_ISSUER_ROLE_UNAUTHORIZED")
                errors.append(f"SSCD yayımlayıcı rolü ('{issuer_rec.issuer_role}') yetkili değildir.")
            elif issuer_rec.status.upper().strip() != "ACTIVE":
                error_codes.append("SSCD_ISSUER_NOT_ACTIVE")
                errors.append(f"SSCD yayımlayıcısı '{issuer_rec.issuer_id}' aktif değildir (durum='{issuer_rec.status}').")
            else:
                try:
                    v_dt = parse_utc_timestamp(validation_time_utc)
                    af_dt = parse_utc_timestamp(issuer_rec.authorized_from_utc)
                    au_dt = parse_utc_timestamp(issuer_rec.authorized_until_utc)
                    if v_dt < af_dt or v_dt > au_dt:
                        error_codes.append("SSCD_ISSUER_AUTHORIZATION_EXPIRED")
                        errors.append(
                            f"SSCD yayımlayıcısı '{issuer_rec.issuer_id}' doğrulama zamanında ({validation_time_utc}) yetki aralığı dışındadır."
                        )
                    else:
                        issuer_authorized = True
                except Exception as exc:
                    error_codes.append("SSCD_ISSUER_WINDOW_INVALID")
                    errors.append(f"SSCD yayımlayıcı yetki zaman aralığı doğrulanamadı: {exc}")

        # 2. Issuer X.509 certificate inspection & strict CA chain verification
        clean_cert = _extract_clean_pem(raw_cert_pem)
        cert_info = (
            inspect_signer_certificate_x509(clean_cert, validation_time_utc=validation_time_utc)
            if clean_cert
            else None
        )
        chain_verified = False
        issuer_ca_pem: str | None = None

        if cert_info is None or not cert_info.valid_x509:
            error_codes.append("SSCD_ISSUER_CERTIFICATE_INVALID")
            errors.append("SSCD yayımlayıcı X.509 sertifikası geçersizdir.")
        else:
            if cert_info.basic_constraints_ca:
                error_codes.append("SSCD_ISSUER_CERT_MUST_NOT_BE_CA")
                errors.append("SSCD kanıt imzalayan sertifika CA sertifikası olamaz.")
            if not cert_info.valid_at_validation_time:
                error_codes.append("SSCD_ISSUER_CERT_EXPIRED_OR_NOT_YET_VALID")
                errors.extend(cert_info.errors)
            if clean_cert and _cert_has_sandbox_marker(clean_cert):
                is_sandbox = True
            if issuer_rec is not None and clean_cert:
                for ca_p in (*issuer_rec.root_ca_pems, *issuer_rec.intermediate_ca_pems):
                    if _cert_has_sandbox_marker(ca_p):
                        is_sandbox = True
                        break
                ok_chain, matched_ca, chain_err = self._verify_issuer_chain(clean_cert, issuer_rec, validation_time_utc)
                chain_verified = ok_chain
                issuer_ca_pem = matched_ca
                if not ok_chain:
                    error_codes.append("SSCD_ISSUER_CHAIN_VERIFICATION_FAILED")
                    errors.append(f"SSCD yayımlayıcı sertifika zinciri doğrulanamadı: {chain_err}")

        # 3. Sandbox issuer rejection in PRODUCTION
        if is_sandbox and env_norm == "PRODUCTION":
            error_codes.append("SANDBOX_SSCD_ISSUER_REJECTED_IN_PRODUCTION")
            errors.append("Test/sandbox SSCD kanıt yayımlayıcısı PRODUCTION ortamında kesinlikle reddedilir.")

        # 4. Issuer certificate revocation check via CertificateRevocationProvider
        rev_status = "UNAVAILABLE"
        rev_indeterminate = False
        if clean_cert and issuer_ca_pem:
            rev_res = self._revocation_provider.check_revocation(
                clean_cert,
                issuer_ca_pem,
                validation_time_utc=validation_time_utc,
                archived_ocsp_response_der=archived_issuer_ocsp_der,
                archived_ocsp_signer_cert_pem=archived_issuer_ocsp_signer_cert_pem,
                archived_crl_pem=archived_issuer_crl_pem,
                runtime_environment=env_norm,
            )
            rev_status = rev_res.status
            if rev_res.status == "REVOKED" or rev_res.conclusion == "FAILED":
                error_codes.append("SSCD_ISSUER_CERT_REVOKED")
                errors.extend(rev_res.errors or ("SSCD yayımlayıcı sertifikası iptal edilmiştir.",))
            elif rev_res.status != "GOOD" or rev_res.conclusion != "PASSED":
                rev_indeterminate = True
                error_codes.append("SSCD_ISSUER_REVOCATION_INDETERMINATE")
                errors.extend(rev_res.errors or ("SSCD yayımlayıcı sertifikasının iptal durumu doğrulanamadı (INDETERMINATE).",))
        elif issuer_rec is not None:
            rev_indeterminate = True
            error_codes.append("SSCD_ISSUER_REVOCATION_INDETERMINATE")
            errors.append("SSCD yayımlayıcı iptal doğrulaması için CA zinciri tamamlanamadı.")

        # 5. Asymmetric cryptographic signature verification over RFC 8785 JCS canonical payload
        sig_verified = False
        if clean_cert and cert_info and cert_info.valid_x509:
            ok_sig, sig_err = self._verify_envelope_signature(
                payload=payload,
                issuer_cert_pem=clean_cert,
                signature_algorithm=sig_alg,
                signature_b64=sig_b64,
            )
            sig_verified = ok_sig
            if not ok_sig:
                error_codes.append("SSCD_EVIDENCE_SIGNATURE_INVALID")
                errors.append(f"SSCD kanıt zarfı kriptografik imzası geçersiz: {sig_err}")

        # 6. Evidence validity window check
        within_window = False
        if not valid_from_utc or not valid_until_utc:
            error_codes.append("SSCD_EVIDENCE_VALIDITY_WINDOW_MISSING")
            errors.append("SSCD kanıt zarfında valid_from_utc / valid_until_utc geçerlilik aralığı zorunludur.")
        else:
            try:
                v_dt = parse_utc_timestamp(validation_time_utc)
                ef_dt = parse_utc_timestamp(valid_from_utc)
                eu_dt = parse_utc_timestamp(valid_until_utc)
                if v_dt < ef_dt or v_dt > eu_dt:
                    error_codes.append("SSCD_EVIDENCE_EXPIRED_OR_NOT_YET_VALID")
                    errors.append(
                        f"SSCD kanıt zarfı doğrulama zamanında ({validation_time_utc}) geçerli değildir "
                        f"({valid_from_utc}..{valid_until_utc})."
                    )
                else:
                    within_window = True
            except Exception as exc:
                error_codes.append("SSCD_EVIDENCE_VALIDITY_WINDOW_INVALID")
                errors.append(f"SSCD kanıt geçerlilik tarihleri ayrıştırılamadı: {exc}")

        # 7. Authorized scope verification
        scope_verified = False
        if issuer_rec is not None:
            issuer_scopes = set(issuer_rec.authorized_scopes)
            ev_scopes = set(payload_scopes)
            if not ev_scopes:
                error_codes.append("SSCD_EVIDENCE_SCOPE_MISSING")
                errors.append("SSCD kanıt zarfında authorized_scopes alanı boştur.")
            elif not ev_scopes.issubset(issuer_scopes):
                error_codes.append("SSCD_EVIDENCE_SCOPE_UNAUTHORIZED")
                errors.append(
                    f"SSCD kanıt kapsamı ({sorted(ev_scopes)}) yayımlayıcı yetki kapsamını ({sorted(issuer_scopes)}) aşıyor."
                )
            elif not REQUIRED_SSCD_SCOPES.issubset(ev_scopes):
                error_codes.append("SSCD_EVIDENCE_REQUIRED_5070_SCOPES_MISSING")
                errors.append(
                    f"SSCD kanıtı zorunlu 5070 kapsamlarını ({sorted(REQUIRED_SSCD_SCOPES)}) içermemektedir."
                )
            else:
                scope_verified = True

        # 8. Signer X.509 certificate SHA-256 binding check (prevents cross-signer replay!)
        cert_binding_ok = False
        if not bound_cert_sha or not re.fullmatch(r"[a-f0-9]{64}", bound_cert_sha):
            error_codes.append("SSCD_EVIDENCE_SIGNER_CERT_BINDING_MISSING")
            errors.append("SSCD kanıt zarfında imzacı sertifikası SHA-256 bağı (bound_signer_cert_sha256) zorunludur.")
        elif expected_signer_cert_sha256 and bound_cert_sha != expected_signer_cert_sha256.strip().lower():
            error_codes.append("SSCD_EVIDENCE_SIGNER_CERT_BINDING_MISMATCH")
            errors.append("SSCD kanıt zarfı farklı bir imzacı sertifikasına bağlıdır (başka imzacıya ait kanıt tekrar kullanılamaz).")
        else:
            cert_binding_ok = True

        # 9. KMS/HSM exclusion & eligible QSCD device validation
        is_kms_hsm = (sig_origin in _KMS_HSM_ORIGIN_MARKERS) or (dev_type in _KMS_HSM_ORIGIN_MARKERS)
        if is_kms_hsm:
            error_codes.append("KMS_HSM_NOT_5070_QUALIFIED_SIGNATURE")
            errors.append("KMS / Cloud KMS / sunucu HSM kaynağı SSCD/QSCD kanıtı olarak kabul edilemez.")

        device_ok = bool(dev_type in _ELIGIBLE_SSCD_DEVICE_TYPES)
        if not is_kms_hsm and not device_ok:
            error_codes.append("SSCD_EVIDENCE_INELIGIBLE_DEVICE_TYPE")
            errors.append(f"Desteklenmeyen veya niteliksiz imza oluşturma cihazı türü: '{dev_type}'.")

        raw_sole = payload.get("sole_control_attested") is True
        raw_pin = payload.get("pin_or_biometric_activation_verified") is True
        raw_sscd = payload.get("sscd_device_certified") is True

        hard_fail_codes = {
            "SSCD_ISSUER_NOT_AUTHORIZED",
            "SSCD_ISSUER_ROLE_UNAUTHORIZED",
            "SSCD_ISSUER_NOT_ACTIVE",
            "SSCD_ISSUER_AUTHORIZATION_EXPIRED",
            "SSCD_ISSUER_WINDOW_INVALID",
            "SSCD_ISSUER_CERTIFICATE_INVALID",
            "SSCD_ISSUER_CERT_MUST_NOT_BE_CA",
            "SSCD_ISSUER_CERT_EXPIRED_OR_NOT_YET_VALID",
            "SSCD_ISSUER_CHAIN_VERIFICATION_FAILED",
            "SANDBOX_SSCD_ISSUER_REJECTED_IN_PRODUCTION",
            "SSCD_ISSUER_CERT_REVOKED",
            "SSCD_EVIDENCE_SIGNATURE_INVALID",
            "SSCD_EVIDENCE_VALIDITY_WINDOW_MISSING",
            "SSCD_EVIDENCE_EXPIRED_OR_NOT_YET_VALID",
            "SSCD_EVIDENCE_VALIDITY_WINDOW_INVALID",
            "SSCD_EVIDENCE_SCOPE_MISSING",
            "SSCD_EVIDENCE_SCOPE_UNAUTHORIZED",
            "SSCD_EVIDENCE_REQUIRED_5070_SCOPES_MISSING",
            "SSCD_EVIDENCE_SIGNER_CERT_BINDING_MISSING",
            "SSCD_EVIDENCE_SIGNER_CERT_BINDING_MISMATCH",
            "KMS_HSM_NOT_5070_QUALIFIED_SIGNATURE",
            "SSCD_EVIDENCE_INELIGIBLE_DEVICE_TYPE",
        }

        crypto_and_authority_ok = bool(
            issuer_authorized
            and chain_verified
            and rev_status == "GOOD"
            and sig_verified
            and within_window
            and scope_verified
            and cert_binding_ok
            and not is_kms_hsm
            and device_ok
            and len(error_codes) == 0
        )

        # Effective attested values are ONLY propagated as True when cryptographic + authority verification succeeded!
        eff_sole = bool(crypto_and_authority_ok and raw_sole)
        eff_pin = bool(crypto_and_authority_ok and raw_pin)
        eff_sscd = bool(crypto_and_authority_ok and raw_sscd and bool(sscd_ref))

        valid = bool(crypto_and_authority_ok and eff_sole and eff_pin and eff_sscd)
        if not valid and crypto_and_authority_ok:
            if not raw_sole:
                error_codes.append("LAW_5070_M4C_SOLE_CONTROL_DENIED")
                errors.append("Doğrulanmış kanıt zarfı imza sahibinin münhasır kontrolünü onaylamamaktadır.")
            if not raw_pin:
                error_codes.append("LAW_5070_M4C_ACTIVATION_NOT_VERIFIED")
                errors.append("Doğrulanmış kanıt zarfı PIN/biyometrik aktivasyon doğrulamasını içermemektedir.")
            if not raw_sscd or not sscd_ref:
                error_codes.append("LAW_5070_M6_NON_SSCD_DEVICE")
                errors.append("Doğrulanmış kanıt zarfı sertifikalı SSCD/QSCD cihaz onayını içermemektedir.")

        if valid:
            conclusion = "VERIFIED"
        elif any(c in hard_fail_codes for c in error_codes) or any(
            c in ("LAW_5070_M4C_SOLE_CONTROL_DENIED", "LAW_5070_M4C_ACTIVATION_NOT_VERIFIED", "LAW_5070_M6_NON_SSCD_DEVICE")
            for c in error_codes
        ):
            conclusion = "FAILED"
        elif rev_indeterminate or "SSCD_ISSUER_REGISTRY_NOT_CONFIGURED" in error_codes:
            conclusion = "INDETERMINATE"
        else:
            conclusion = "FAILED"

        res = SscdControlEvidenceVerificationResult(
            valid=valid,
            conclusion=conclusion,
            evidence_id=evidence_id,
            issuer_id=issuer_id,
            issuer_name=issuer_rec.issuer_name if issuer_rec else None,
            issuer_role=issuer_rec.issuer_role if issuer_rec else None,
            issuer_authorized=issuer_authorized,
            issuer_cert_chain_verified=chain_verified,
            issuer_cert_serial_number=cert_info.serial_number if cert_info and cert_info.valid_x509 else None,
            issuer_cert_sha256=cert_info.cert_sha256 if cert_info and cert_info.valid_x509 else None,
            issuer_revocation_status=rev_status,
            signature_verified=sig_verified,
            signature_algorithm=sig_alg,
            scope_verified=scope_verified,
            authorized_scopes=payload_scopes,
            valid_from_utc=valid_from_utc,
            valid_until_utc=valid_until_utc,
            within_validity_window=within_window,
            bound_signer_cert_sha256=bound_cert_sha,
            signature_origin=sig_origin,
            signing_device_type=dev_type,
            sole_control_attested=eff_sole,
            pin_or_biometric_activation_verified=eff_pin,
            sscd_device_certified=eff_sscd,
            sscd_certification_ref=sscd_ref if eff_sscd else None,
            is_sandbox_issuer=is_sandbox,
            envelope_sha256=envelope_sha,
            verifier_service_id=self.verifier_service_id,
            integration_mode=self._integration_mode,
            error_codes=tuple(sorted(set(error_codes))),
            errors=tuple(errors),
        )
        return seal_sscd_evidence_result(res)
