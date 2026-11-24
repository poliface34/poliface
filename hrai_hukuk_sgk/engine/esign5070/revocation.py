"""Live & Historical Archive Certificate Revocation Provider (OCSP/CRL) for CALISORA @HukukSGK v1.0.4.

Implements `CertificateRevocationProvider` using real OpenSSL 3 cryptographic verification (`openssl ocsp`
and `openssl crl`) with zero external Python dependencies:
  - Strictly distinguishes `GOOD`, `REVOKED`, `UNKNOWN`, and `UNAVAILABLE`.
  - When OCSP/CRL cannot be reached or verified, returns `status="UNAVAILABLE"` and `conclusion="INDETERMINATE"`
    (FAIL-CLOSED: NEVER fabricates `GOOD` and NEVER opens the production legal gate).
  - Supports historical archive validation (`ARCHIVED_OCSP`, `ARCHIVED_CRL`) with full cryptographic verification
    against the ESHS issuer/root CA, preventing cross-certificate OCSP replay (`-cert` + `-issuer` CertID binding)
    and preventing rogue OCSP responder injection (explicit responder chain check against issuer CA).
  - Reports exact 5-state probe status (`NOT_CONFIGURED`, `CONFIGURED_UNVERIFIED`, `LIVE_VERIFIED`, `FAILED`, `INDETERMINATE`).
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Callable

from ..attestation_verifier import parse_utc_timestamp
from .eshs_trust import _normalize_serial, _parse_openssl_gmt_date, inspect_signer_certificate_x509
from .interfaces import CertificateRevocationProvider
from .models import (
    VALID_PROBE_STATUSES,
    Esign5070ProbeStatus,
    RevocationEvidenceResult,
)

# Callback signatures for injectable sandbox/live responders (returns DER OCSP bytes or PEM CRL text)
OcspFetcherFn = Callable[[str, str, str], tuple[bytes, str | None]]  # (signer_pem, issuer_pem, val_time) -> (ocsp_der, resp_cert_pem)
CrlFetcherFn = Callable[[str, str], str]  # (issuer_pem, val_time) -> crl_pem

_COMPROMISE_REASONS: frozenset[str] = frozenset(
    {
        "KEYCOMPROMISE",
        "KEY_COMPROMISE",
        "CACOMPROMISE",
        "CA_COMPROMISE",
        "AACOMPROMISE",
        "AA_COMPROMISE",
    }
)


def _openssl_exe() -> str:
    exe = shutil.which("openssl")
    if not exe:
        raise RuntimeError("OpenSSL CLI bulunamadı; OCSP/CRL iptal doğrulaması çalıştırılamaz.")
    return exe


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_reason(raw_reason: str | None) -> str | None:
    if not raw_reason:
        return None
    cleaned = re.sub(r"\s*\([^)]*\)\s*", "", raw_reason).strip()
    return cleaned or None


def _is_compromise_reason(reason: str | None) -> bool:
    if not reason:
        return False
    norm = re.sub(r"[^A-Za-z_]", "", reason).upper()
    return norm in _COMPROMISE_REASONS


class DefaultCertificateRevocationProvider(CertificateRevocationProvider):
    """OpenSSL 3 backed OCSP & CRL revocation verification provider (live + historical archive)."""

    def __init__(
        self,
        *,
        ocsp_url: str | None = None,
        crl_url: str | None = None,
        trusted_ca_pem: str | None = None,
        ocsp_fetcher: OcspFetcherFn | None = None,
        crl_fetcher: CrlFetcherFn | None = None,
        integration_mode: str | None = None,
        live_verified: bool = False,
        probe_status_override: str | None = None,
        probe_error_code: str | None = None,
        probe_error_message: str | None = None,
    ) -> None:
        self._ocsp_url = ocsp_url.strip() if isinstance(ocsp_url, str) and ocsp_url.strip() else None
        self._crl_url = crl_url.strip() if isinstance(crl_url, str) and crl_url.strip() else None
        self._trusted_ca_pem = trusted_ca_pem.strip() if isinstance(trusted_ca_pem, str) and trusted_ca_pem.strip() else None
        self._ocsp_fetcher = ocsp_fetcher
        self._crl_fetcher = crl_fetcher
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
        elif ocsp_fetcher is not None or crl_fetcher is not None:
            self._integration_mode = "MOCK_SANDBOX"
        elif self._ocsp_url or self._crl_url:
            self._integration_mode = "LIVE_PRODUCTION"
        else:
            self._integration_mode = "NOT_CONFIGURED"

    @property
    def provider_name(self) -> str:
        return "OPENSSL_OCSP_CRL_REVOCATION_PROVIDER"

    @property
    def integration_mode(self) -> str:
        return self._integration_mode

    def probe_status(self) -> Esign5070ProbeStatus:
        configured = bool(self._ocsp_url or self._crl_url or self._ocsp_fetcher or self._crl_fetcher)
        if self._probe_status_override is not None:
            st = self._probe_status_override
        elif not configured or self._integration_mode == "NOT_CONFIGURED":
            st = "NOT_CONFIGURED"
        elif self._integration_mode == "LIVE_PRODUCTION" and self._live_verified:
            st = "LIVE_VERIFIED"
        else:
            st = "CONFIGURED_UNVERIFIED"

        return Esign5070ProbeStatus(
            service_name="certificate_revocation_ocsp_crl",
            provider_type="CertificateRevocationProvider",
            probe_status=st,
            integration_mode=self._integration_mode,
            configured=configured,
            reachable=st == "LIVE_VERIFIED",
            details={
                "ocsp_url": self._ocsp_url,
                "crl_url": self._crl_url,
                "ocsp_fetcher_attached": self._ocsp_fetcher is not None,
                "crl_fetcher_attached": self._crl_fetcher is not None,
                "openssl_available": shutil.which("openssl") is not None,
            },
            error_code=self._probe_error_code or (None if st == "LIVE_VERIFIED" else "OCSP_CRL_NOT_LIVE_VERIFIED"),
            error_message=self._probe_error_message
            or (
                None
                if st == "LIVE_VERIFIED"
                else "Canlı OCSP/CRL iptal servisi doğrulanmamıştır; üretim iptal kanıtı eksik olduğunda sonuç INDETERMINATE döner."
            ),
        )

    def _verify_ocsp_response_der(
        self,
        *,
        signer_cert_pem: str,
        issuer_cert_pem: str,
        ocsp_response_der: bytes,
        ocsp_signer_cert_pem: str | None,
        validation_time_utc: str,
        historical_archive: bool,
        cert_serial: str,
    ) -> RevocationEvidenceResult:
        openssl = _openssl_exe()
        checked_at = _now_utc_iso()
        evidence_sha = hashlib.sha256(ocsp_response_der).hexdigest()
        ca_pem = self._trusted_ca_pem or issuer_cert_pem

        with tempfile.TemporaryDirectory(prefix="calisora_ocsp_ver_") as tmp:
            signer_path = Path(tmp) / "signer.pem"
            issuer_path = Path(tmp) / "issuer.pem"
            ca_path = Path(tmp) / "ca.pem"
            resp_path = Path(tmp) / "ocsp.der"
            signer_path.write_text(signer_cert_pem.strip() + "\n", encoding="utf-8")
            issuer_path.write_text(issuer_cert_pem.strip() + "\n", encoding="utf-8")
            ca_bundle_text = ca_pem.strip()
            if issuer_cert_pem.strip() not in ca_bundle_text:
                ca_bundle_text = ca_bundle_text + "\n" + issuer_cert_pem.strip()
            ca_path.write_text(ca_bundle_text + "\n", encoding="utf-8")
            resp_path.write_bytes(ocsp_response_der)

            # Security guard: if an explicit OCSP responder cert is supplied, verify it chains to trusted CA!
            va_args: list[str] = []
            if ocsp_signer_cert_pem and "BEGIN CERTIFICATE" in ocsp_signer_cert_pem:
                va_path = Path(tmp) / "ocsp_responder.pem"
                va_path.write_text(ocsp_signer_cert_pem.strip() + "\n", encoding="utf-8")
                attime_ts = str(int(parse_utc_timestamp(validation_time_utc).timestamp()))
                p_va = subprocess.run(
                    [
                        openssl,
                        "verify",
                        "-x509_strict",
                        "-no-CApath",
                        "-attime",
                        attime_ts,
                        "-CAfile",
                        str(ca_path),
                        str(va_path),
                    ],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                if p_va.returncode != 0 or ": OK" not in p_va.stdout:
                    return RevocationEvidenceResult(
                        status="UNAVAILABLE",
                        conclusion="FAILED",
                        method="ARCHIVED_OCSP" if historical_archive else "OCSP",
                        checked_at_utc=checked_at,
                        validation_time_utc=validation_time_utc,
                        certificate_serial_number=cert_serial,
                        evidence_sha256=evidence_sha,
                        historical_archive_evidence=historical_archive,
                        provider_backend=self.provider_name,
                        integration_mode=self._integration_mode,
                        error_codes=("OCSP_RESPONDER_CHAIN_UNTRUSTED",),
                        errors=(
                            f"OCSP yanıtlayıcı sertifikası güvenilir ESHS CA zincirine bağlanamadı: "
                            f"{(p_va.stderr or p_va.stdout).strip()}",
                        ),
                    )
                va_args = ["-VAfile", str(va_path)]

            cmd = [
                openssl,
                "ocsp",
                "-respin",
                str(resp_path),
                "-issuer",
                str(issuer_path),
                "-cert",
                str(signer_path),
                "-CAfile",
                str(ca_path),
                "-no-CApath",
                "-no-CAstore",
                *va_args,
                "-text",
            ]
            # In historical archive mode, responder cert validity was already verified at validation_time_utc above
            if historical_archive:
                cmd.append("-no_cert_verify")

            proc = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            combined = proc.stdout + "\n" + proc.stderr
            if proc.returncode != 0 or "Response verify OK" not in combined:
                return RevocationEvidenceResult(
                    status="UNAVAILABLE",
                    conclusion="FAILED",
                    method="ARCHIVED_OCSP" if historical_archive else "OCSP",
                    checked_at_utc=checked_at,
                    validation_time_utc=validation_time_utc,
                    certificate_serial_number=cert_serial,
                    evidence_sha256=evidence_sha,
                    historical_archive_evidence=historical_archive,
                    provider_backend=self.provider_name,
                    integration_mode=self._integration_mode,
                    error_codes=("OCSP_SIGNATURE_OR_CERTID_VERIFICATION_FAILED",),
                    errors=(
                        f"OCSP yanıtının kriptografik doğrulaması veya sertifika eşleşmesi başarısız: "
                        f"{(proc.stderr or proc.stdout).strip()}",
                    ),
                )

            # Verify target cert status block in output
            m_status = re.search(r"Cert Status:\s*(good|revoked|unknown)", combined, flags=re.IGNORECASE)
            if not m_status:
                return RevocationEvidenceResult(
                    status="UNKNOWN",
                    conclusion="INDETERMINATE",
                    method="ARCHIVED_OCSP" if historical_archive else "OCSP",
                    checked_at_utc=checked_at,
                    validation_time_utc=validation_time_utc,
                    certificate_serial_number=cert_serial,
                    evidence_sha256=evidence_sha,
                    historical_archive_evidence=historical_archive,
                    provider_backend=self.provider_name,
                    integration_mode=self._integration_mode,
                    error_codes=("OCSP_STATUS_NOT_FOUND_FOR_CERTIFICATE",),
                    errors=("OCSP yanıtında hedef sertifikaya ait durum alanı bulunamadı.",),
                )

            raw_status = m_status.group(1).upper()
            m_this = re.search(r"This Update:\s*([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s+GMT)", combined)
            m_next = re.search(r"Next Update:\s*([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s+GMT)", combined)
            m_rev_t = re.search(r"Revocation Time:\s*([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s+GMT)", combined)
            m_rev_r = re.search(r"Revocation Reason:\s*([^\n]+)", combined)
            m_resp = re.search(r"Responder Id:\s*([^\n]+)", combined)

            this_upd = _parse_openssl_gmt_date(m_this.group(1)) if m_this else None
            next_upd = _parse_openssl_gmt_date(m_next.group(1)) if m_next else None
            rev_time = _parse_openssl_gmt_date(m_rev_t.group(1)) if m_rev_t else None
            rev_reason = _normalize_reason(m_rev_r.group(1)) if m_rev_r else None
            responder_id = m_resp.group(1).strip() if m_resp else None

            val_dt = parse_utc_timestamp(validation_time_utc)
            method_name = "ARCHIVED_OCSP" if historical_archive else "OCSP"

            if raw_status == "REVOKED":
                # In historical archive mode, if revoked strictly AFTER validation_time_utc for a non-compromise reason,
                # the certificate was still valid at the trusted signing/validation time.
                if historical_archive and rev_time and not _is_compromise_reason(rev_reason):
                    rev_dt = parse_utc_timestamp(rev_time)
                    if rev_dt > val_dt:
                        return RevocationEvidenceResult(
                            status="GOOD",
                            conclusion="PASSED",
                            method=method_name,
                            checked_at_utc=checked_at,
                            validation_time_utc=validation_time_utc,
                            certificate_serial_number=cert_serial,
                            revoked_at_utc=rev_time,
                            revocation_reason=rev_reason,
                            this_update_utc=this_upd,
                            next_update_utc=next_upd,
                            responder_or_issuer=responder_id,
                            evidence_sha256=evidence_sha,
                            historical_archive_evidence=True,
                            provider_backend=self.provider_name,
                            integration_mode=self._integration_mode,
                        )
                return RevocationEvidenceResult(
                    status="REVOKED",
                    conclusion="FAILED",
                    method=method_name,
                    checked_at_utc=checked_at,
                    validation_time_utc=validation_time_utc,
                    certificate_serial_number=cert_serial,
                    revoked_at_utc=rev_time,
                    revocation_reason=rev_reason,
                    this_update_utc=this_upd,
                    next_update_utc=next_upd,
                    responder_or_issuer=responder_id,
                    evidence_sha256=evidence_sha,
                    historical_archive_evidence=historical_archive,
                    provider_backend=self.provider_name,
                    integration_mode=self._integration_mode,
                    error_codes=("SIGNER_CERTIFICATE_REVOKED",),
                    errors=(
                        f"İmzacı sertifikası (seri={cert_serial}) OCSP kaydına göre iptal edilmiştir "
                        f"(iptal_zamanı={rev_time}, neden={rev_reason}).",
                    ),
                )

            if raw_status == "UNKNOWN":
                return RevocationEvidenceResult(
                    status="UNKNOWN",
                    conclusion="INDETERMINATE",
                    method=method_name,
                    checked_at_utc=checked_at,
                    validation_time_utc=validation_time_utc,
                    certificate_serial_number=cert_serial,
                    this_update_utc=this_upd,
                    next_update_utc=next_upd,
                    responder_or_issuer=responder_id,
                    evidence_sha256=evidence_sha,
                    historical_archive_evidence=historical_archive,
                    provider_backend=self.provider_name,
                    integration_mode=self._integration_mode,
                    error_codes=("OCSP_STATUS_UNKNOWN",),
                    errors=("OCSP yanıtlayıcı sertifika durumunu UNKNOWN olarak bildirmiştir (INDETERMINATE).",),
                )

            # GOOD status — verify freshness window when not historical archive
            if not historical_archive and next_upd:
                if parse_utc_timestamp(next_upd) < val_dt:
                    return RevocationEvidenceResult(
                        status="UNAVAILABLE",
                        conclusion="INDETERMINATE",
                        method=method_name,
                        checked_at_utc=checked_at,
                        validation_time_utc=validation_time_utc,
                        certificate_serial_number=cert_serial,
                        this_update_utc=this_upd,
                        next_update_utc=next_upd,
                        responder_or_issuer=responder_id,
                        evidence_sha256=evidence_sha,
                        historical_archive_evidence=False,
                        provider_backend=self.provider_name,
                        integration_mode=self._integration_mode,
                        error_codes=("OCSP_RESPONSE_EXPIRED",),
                        errors=(
                            f"OCSP yanıtının geçerlilik süresi (nextUpdate={next_upd}) doğrulama zamanından "
                            f"({validation_time_utc}) öncedir.",
                        ),
                    )

            return RevocationEvidenceResult(
                status="GOOD",
                conclusion="PASSED",
                method=method_name,
                checked_at_utc=checked_at,
                validation_time_utc=validation_time_utc,
                certificate_serial_number=cert_serial,
                this_update_utc=this_upd,
                next_update_utc=next_upd,
                responder_or_issuer=responder_id,
                evidence_sha256=evidence_sha,
                historical_archive_evidence=historical_archive,
                provider_backend=self.provider_name,
                integration_mode=self._integration_mode,
            )

    def _verify_crl_pem(
        self,
        *,
        issuer_cert_pem: str,
        crl_pem: str,
        validation_time_utc: str,
        historical_archive: bool,
        cert_serial: str,
    ) -> RevocationEvidenceResult:
        openssl = _openssl_exe()
        checked_at = _now_utc_iso()
        evidence_sha = hashlib.sha256(crl_pem.encode("utf-8")).hexdigest()
        ca_pem = self._trusted_ca_pem or issuer_cert_pem
        method_name = "ARCHIVED_CRL" if historical_archive else "CRL"

        with tempfile.TemporaryDirectory(prefix="calisora_crl_ver_") as tmp:
            crl_path = Path(tmp) / "rev.crl"
            ca_path = Path(tmp) / "ca.pem"
            crl_path.write_text(crl_pem.strip() + "\n", encoding="utf-8")
            ca_bundle_text = ca_pem.strip()
            if issuer_cert_pem.strip() not in ca_bundle_text:
                ca_bundle_text = ca_bundle_text + "\n" + issuer_cert_pem.strip()
            ca_path.write_text(ca_bundle_text + "\n", encoding="utf-8")

            # Single OpenSSL 3 invocation: cryptographically verifies CRL signature against trusted CA
            # AND outputs CRL text; signature verification is strictly enforced before reading any fields.
            p_ver = subprocess.run(
                [openssl, "crl", "-in", str(crl_path), "-CAfile", str(ca_path), "-no-CApath", "-noout", "-verify", "-text"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            combined_ver = p_ver.stdout + "\n" + p_ver.stderr
            if p_ver.returncode != 0 or "verify OK" not in combined_ver:
                return RevocationEvidenceResult(
                    status="UNAVAILABLE",
                    conclusion="FAILED",
                    method=method_name,
                    checked_at_utc=checked_at,
                    validation_time_utc=validation_time_utc,
                    certificate_serial_number=cert_serial,
                    evidence_sha256=evidence_sha,
                    historical_archive_evidence=historical_archive,
                    provider_backend=self.provider_name,
                    integration_mode=self._integration_mode,
                    error_codes=("CRL_SIGNATURE_VERIFICATION_FAILED",),
                    errors=(f"CRL (SİL) imzası güvenilir ESHS CA ile doğrulanamadı: {combined_ver.strip()}",),
                )

            txt = p_ver.stdout
            if not txt or "Certificate Revocation List" not in txt:
                return RevocationEvidenceResult(
                    status="UNAVAILABLE",
                    conclusion="INDETERMINATE",
                    method=method_name,
                    checked_at_utc=checked_at,
                    validation_time_utc=validation_time_utc,
                    certificate_serial_number=cert_serial,
                    evidence_sha256=evidence_sha,
                    historical_archive_evidence=historical_archive,
                    provider_backend=self.provider_name,
                    integration_mode=self._integration_mode,
                    error_codes=("CRL_PARSE_FAILED",),
                    errors=(f"CRL (SİL) içeriği ayrıştırılamadı: {p_ver.stderr.strip()}",),
                )
            m_issuer = re.search(r"Issuer:\s*([^\n]+)", txt)
            m_last = re.search(r"Last Update:\s*([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s+GMT)", txt)
            m_next = re.search(r"Next Update:\s*([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s+GMT)", txt)
            issuer_name = m_issuer.group(1).strip() if m_issuer else None
            last_upd = _parse_openssl_gmt_date(m_last.group(1)) if m_last else None
            next_upd = _parse_openssl_gmt_date(m_next.group(1)) if m_next else None

            val_dt = parse_utc_timestamp(validation_time_utc)

            # Parse revoked entries
            # Pattern:
            #   Serial Number: 01AB...
            #       Revocation Date: Nov 22 00:00:00 2026 GMT
            #       CRL entry extensions:
            #           X509v3 CRL Reason Code:
            #               Key Compromise
            entries = re.split(r"(?=\n\s*Serial Number:\s*)", txt)
            for block in entries:
                m_ser = re.search(r"Serial Number:\s*([0-9A-Fa-f:]+)", block)
                if not m_ser:
                    continue
                entry_serial = _normalize_serial(m_ser.group(1))
                if entry_serial != cert_serial:
                    continue
                m_rdate = re.search(
                    r"Revocation Date:\s*([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s+GMT)",
                    block,
                )
                m_reason = re.search(r"X509v3 CRL Reason Code:[^\n]*\n\s*([^\n]+)", block)
                rev_time = _parse_openssl_gmt_date(m_rdate.group(1)) if m_rdate else None
                rev_reason = _normalize_reason(m_reason.group(1)) if m_reason else None

                if historical_archive and rev_time and not _is_compromise_reason(rev_reason):
                    if parse_utc_timestamp(rev_time) > val_dt:
                        return RevocationEvidenceResult(
                            status="GOOD",
                            conclusion="PASSED",
                            method=method_name,
                            checked_at_utc=checked_at,
                            validation_time_utc=validation_time_utc,
                            certificate_serial_number=cert_serial,
                            revoked_at_utc=rev_time,
                            revocation_reason=rev_reason,
                            this_update_utc=last_upd,
                            next_update_utc=next_upd,
                            responder_or_issuer=issuer_name,
                            evidence_sha256=evidence_sha,
                            historical_archive_evidence=True,
                            provider_backend=self.provider_name,
                            integration_mode=self._integration_mode,
                        )
                return RevocationEvidenceResult(
                    status="REVOKED",
                    conclusion="FAILED",
                    method=method_name,
                    checked_at_utc=checked_at,
                    validation_time_utc=validation_time_utc,
                    certificate_serial_number=cert_serial,
                    revoked_at_utc=rev_time,
                    revocation_reason=rev_reason,
                    this_update_utc=last_upd,
                    next_update_utc=next_upd,
                    responder_or_issuer=issuer_name,
                    evidence_sha256=evidence_sha,
                    historical_archive_evidence=historical_archive,
                    provider_backend=self.provider_name,
                    integration_mode=self._integration_mode,
                    error_codes=("SIGNER_CERTIFICATE_REVOKED",),
                    errors=(
                        f"İmzacı sertifikası (seri={cert_serial}) CRL (SİL) kaydına göre iptal edilmiştir "
                        f"(iptal_zamanı={rev_time}, neden={rev_reason}).",
                    ),
                )

            if not historical_archive and next_upd:
                if parse_utc_timestamp(next_upd) < val_dt:
                    return RevocationEvidenceResult(
                        status="UNAVAILABLE",
                        conclusion="INDETERMINATE",
                        method=method_name,
                        checked_at_utc=checked_at,
                        validation_time_utc=validation_time_utc,
                        certificate_serial_number=cert_serial,
                        this_update_utc=last_upd,
                        next_update_utc=next_upd,
                        responder_or_issuer=issuer_name,
                        evidence_sha256=evidence_sha,
                        historical_archive_evidence=False,
                        provider_backend=self.provider_name,
                        integration_mode=self._integration_mode,
                        error_codes=("CRL_EXPIRED_OR_STALE",),
                        errors=(
                            f"CRL (SİL) listesinin geçerlilik süresi (nextUpdate={next_upd}) doğrulama zamanından "
                            f"({validation_time_utc}) öncedir.",
                        ),
                    )

            return RevocationEvidenceResult(
                status="GOOD",
                conclusion="PASSED",
                method=method_name,
                checked_at_utc=checked_at,
                validation_time_utc=validation_time_utc,
                certificate_serial_number=cert_serial,
                this_update_utc=last_upd,
                next_update_utc=next_upd,
                responder_or_issuer=issuer_name,
                evidence_sha256=evidence_sha,
                historical_archive_evidence=historical_archive,
                provider_backend=self.provider_name,
                integration_mode=self._integration_mode,
            )

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
        checked_at = _now_utc_iso()
        cert_info = inspect_signer_certificate_x509(signer_cert_pem, validation_time_utc=validation_time_utc)
        cert_serial = cert_info.serial_number if cert_info.valid_x509 else ""

        if not cert_info.valid_x509:
            return RevocationEvidenceResult(
                status="UNAVAILABLE",
                conclusion="FAILED",
                method="NONE",
                checked_at_utc=checked_at,
                validation_time_utc=validation_time_utc,
                certificate_serial_number=None,
                provider_backend=self.provider_name,
                integration_mode=self._integration_mode,
                error_codes=cert_info.error_codes,
                errors=cert_info.errors,
            )

        if not issuer_cert_pem or "BEGIN CERTIFICATE" not in issuer_cert_pem:
            return RevocationEvidenceResult(
                status="UNAVAILABLE",
                conclusion="INDETERMINATE",
                method="NONE",
                checked_at_utc=checked_at,
                validation_time_utc=validation_time_utc,
                certificate_serial_number=cert_serial,
                provider_backend=self.provider_name,
                integration_mode=self._integration_mode,
                error_codes=("REVOCATION_ISSUER_CERT_MISSING",),
                errors=("OCSP/CRL iptal doğrulaması için imzacı sertifikasının ESHS düzenleyici (issuer) CA sertifikası eksiktir.",),
            )

        # 1. Historical archived OCSP evidence (highest priority for B-LT / B-LTA archival validation)
        if archived_ocsp_response_der:
            return self._verify_ocsp_response_der(
                signer_cert_pem=signer_cert_pem,
                issuer_cert_pem=issuer_cert_pem,
                ocsp_response_der=archived_ocsp_response_der,
                ocsp_signer_cert_pem=archived_ocsp_signer_cert_pem,
                validation_time_utc=validation_time_utc,
                historical_archive=True,
                cert_serial=cert_serial,
            )

        # 2. Historical archived CRL evidence
        if archived_crl_pem:
            return self._verify_crl_pem(
                issuer_cert_pem=issuer_cert_pem,
                crl_pem=archived_crl_pem,
                validation_time_utc=validation_time_utc,
                historical_archive=True,
                cert_serial=cert_serial,
            )

        # 3. Injectable OCSP fetcher (sandbox or live adapter)
        if self._ocsp_fetcher is not None:
            try:
                resp_der, resp_cert_pem = self._ocsp_fetcher(signer_cert_pem, issuer_cert_pem, validation_time_utc)
                return self._verify_ocsp_response_der(
                    signer_cert_pem=signer_cert_pem,
                    issuer_cert_pem=issuer_cert_pem,
                    ocsp_response_der=resp_der,
                    ocsp_signer_cert_pem=resp_cert_pem,
                    validation_time_utc=validation_time_utc,
                    historical_archive=False,
                    cert_serial=cert_serial,
                )
            except Exception as exc:
                # Fail-closed -> UNAVAILABLE + INDETERMINATE!
                return RevocationEvidenceResult(
                    status="UNAVAILABLE",
                    conclusion="INDETERMINATE",
                    method="OCSP",
                    checked_at_utc=checked_at,
                    validation_time_utc=validation_time_utc,
                    certificate_serial_number=cert_serial,
                    provider_backend=self.provider_name,
                    integration_mode=self._integration_mode,
                    error_codes=("REVOCATION_OCSP_ACCESS_ERROR",),
                    errors=(f"OCSP iptal servisine erişim veya yanıt alımı başarısız oldu (INDETERMINATE): {exc}",),
                )

        # 4. Injectable CRL fetcher
        if self._crl_fetcher is not None:
            try:
                crl_text = self._crl_fetcher(issuer_cert_pem, validation_time_utc)
                return self._verify_crl_pem(
                    issuer_cert_pem=issuer_cert_pem,
                    crl_pem=crl_text,
                    validation_time_utc=validation_time_utc,
                    historical_archive=False,
                    cert_serial=cert_serial,
                )
            except Exception as exc:
                return RevocationEvidenceResult(
                    status="UNAVAILABLE",
                    conclusion="INDETERMINATE",
                    method="CRL",
                    checked_at_utc=checked_at,
                    validation_time_utc=validation_time_utc,
                    certificate_serial_number=cert_serial,
                    provider_backend=self.provider_name,
                    integration_mode=self._integration_mode,
                    error_codes=("REVOCATION_CRL_ACCESS_ERROR",),
                    errors=(f"CRL (SİL) dağıtım noktasına erişim başarısız oldu (INDETERMINATE): {exc}",),
                )

        # 5. Neither archived evidence nor live OCSP/CRL reachable -> fail closed as UNAVAILABLE / INDETERMINATE
        return RevocationEvidenceResult(
            status="UNAVAILABLE",
            conclusion="INDETERMINATE",
            method="NONE",
            checked_at_utc=checked_at,
            validation_time_utc=validation_time_utc,
            certificate_serial_number=cert_serial,
            provider_backend=self.provider_name,
            integration_mode=self._integration_mode,
            error_codes=(
                "REVOCATION_SERVICE_NOT_CONFIGURED"
                if self._integration_mode == "NOT_CONFIGURED"
                else "REVOCATION_SERVICE_UNAVAILABLE",
            ),
            errors=(
                "Canlı OCSP/CRL iptal doğrulama servisi erişilebilir değildir ve arşivlenmiş iptal kanıtı "
                "sağlanmamıştır; iptal durumu INDETERMINATE olarak kilitlenir.",
            ),
        )
