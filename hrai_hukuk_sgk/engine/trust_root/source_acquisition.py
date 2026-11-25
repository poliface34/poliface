"""Official Source Acquisition Evidence Provider & Real HTTPS/TLS Verifier (Diyanet & Resmî Gazete) for CALISORA @HukukSGK v1.0.3.1.

Closes Finding 3 from the v1.0.3 independent security review:
  - Separates real `LiveHttpsSourceFetcher` (`fetcher_mode="LIVE_HTTPS"`) from injected mock callbacks
    (`fetcher_mode="MOCK_CALLBACK"`). Callback-sourced TLS metadata can NEVER yield `production_tls_verified=True`.
  - Enforces official source domain allowlist (`DEFAULT_ALLOWED_OFFICIAL_DOMAINS`) and HTTPS-only redirects
    (`HTTPS_DOWNGRADE_REDIRECT_BLOCKED`, `DISALLOWED_OFFICIAL_SOURCE_DOMAIN`).
  - Independently verifies X.509 peer certificate PEM via OpenSSL 3 (`openssl verify` + `openssl x509`):
      * Trusted CA chain verification (`TLS_UNTRUSTED_CA_OR_CHAIN_INVALID`),
      * Hostname / SAN (RFC 6125) verification (`TLS_HOSTNAME_OR_SAN_MISMATCH`),
      * Certificate validity period (`notBefore <= now <= notAfter`, `TLS_CERTIFICATE_EXPIRED_OR_NOT_YET_VALID`),
      * Consistency between actual X.509 PEM fields and declared metadata (`TLS_FAKE_OR_UNVERIFIABLE_METADATA`).
  - Produces unforgeable HMAC-sealed `SourceAcquisitionVerificationResult` objects for `ProductionAuthorizationProvider`.

CRITICAL EPISTEMIC BOUNDARY (unchanged):
  `tls_alone_proves_historical_content` is ALWAYS `False`! TLS handshake & certificate chain verification
  supports server identity at acquisition time; it NEVER proves past server content on its own.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import http.client
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import tempfile
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

from .interfaces import (
    ImmutableEvidenceStorageProvider,
    KeySignerProvider,
    SourceAcquisitionProvider,
    TimestampAuthorityProvider,
)
from .models import (
    TLS_NON_HISTORICAL_PROOF_NOTICE,
    TRUST_ROOT_VERSION,
    ProviderHealthStatus,
    SourceAcquisitionEvidenceEnvelope,
    SourceAcquisitionVerificationResult,
    TlsCertificateInfo,
    TlsVerificationResult,
)
from .verification_services import seal_service_result

AcquisitionFetcherFn = Callable[[str], dict[str, Any]]

DEFAULT_ALLOWED_OFFICIAL_DOMAINS: frozenset[str] = frozenset(
    {
        "vakithesaplama.diyanet.gov.tr",
        "diyanet.gov.tr",
        "www.resmigazete.gov.tr",
        "resmigazete.gov.tr",
        "www.mevzuat.gov.tr",
        "mevzuat.gov.tr",
        "www.gib.gov.tr",
        "gib.gov.tr",
        "www.sgk.gov.tr",
        "sgk.gov.tr",
        "karararama.yargitay.gov.tr",
        "www.yargitay.gov.tr",
    }
)

_REDIRECT_STATUSES: frozenset[int] = frozenset({301, 302, 303, 307, 308})
_SYSTEM_CA_CANDIDATES: tuple[str, ...] = (
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
)


class SourceAcquisitionSecurityError(RuntimeError):
    """Raised when live HTTPS acquisition violates HTTPS-only, domain allowlist, or TLS trust rules."""

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(f"{error_code}: {message}")
        self.error_code = error_code
        self.message = message


def _openssl_exe() -> str:
    exe = shutil.which("openssl")
    if not exe:
        raise RuntimeError("OpenSSL CLI bulunamadı; X.509/TLS sertifika zinciri doğrulanamaz.")
    return exe


def _resolve_system_ca_bundle() -> str | None:
    env_ca = os.environ.get("SSL_CERT_FILE")
    if env_ca and os.path.isfile(env_ca):
        return env_ca
    for cand in _SYSTEM_CA_CANDIDATES:
        if os.path.isfile(cand):
            return cand
    paths = ssl.get_default_verify_paths()
    if paths.cafile and os.path.isfile(paths.cafile):
        return paths.cafile
    return None


def _parse_openssl_asn1_time(raw: str) -> datetime | None:
    cleaned = re.sub(r"\s+", " ", raw.strip())
    for fmt in ("%b %d %H:%M:%S %Y GMT", "%b %d %H:%M:%S %Y UTC"):
        try:
            return datetime.strptime(cleaned, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _hostname_matches_pattern(hostname: str, pattern: str) -> bool:
    host = hostname.strip().lower().rstrip(".")
    pat = pattern.strip().lower().rstrip(".")
    if not host or not pat:
        return False
    if pat == host:
        return True
    # RFC 6125 single-label wildcard matching (*.example.gov.tr)
    if pat.startswith("*.") and pat.count("*") == 1:
        suffix = pat[2:]
        if "." not in suffix:
            return False
        if host.endswith("." + suffix):
            left = host[: -(len(suffix) + 1)]
            return bool(left) and "." not in left
    return False


def _extract_x509_fields_from_pem(cert_pem: str) -> dict[str, Any] | None:
    """Parse read-only X.509 certificate metadata directly from ASN.1 DER (no trust/chain verdict).

    CA trust chain verification remains 100% on OpenSSL 3 (`openssl verify -x509_strict -no-CApath`).
    """
    from ..esign5070.x509_metadata import parse_x509_certificate_metadata

    meta = parse_x509_certificate_metadata(cert_pem)
    if meta is None:
        return None
    try:
        not_before_dt = datetime.strptime(meta.not_before_utc, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        not_after_dt = datetime.strptime(meta.not_after_utc, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None

    return {
        "peer_subject": meta.subject,
        "peer_issuer": meta.issuer,
        "serial_number": "0x" + meta.serial_number,
        "not_before_dt": not_before_dt,
        "not_after_dt": not_after_dt,
        "not_before_utc": meta.not_before_utc,
        "not_after_utc": meta.not_after_utc,
        "leaf_cert_sha256": meta.cert_sha256,
        "san_dns_names": meta.san_dns_names,
        "common_name": meta.signer_common_name,
    }


def verify_tls_peer_certificate_chain(
    leaf_cert_pem: str | None,
    *,
    server_hostname: str,
    trusted_ca_pem: str | None = None,
    trusted_ca_pem_path: str | Path | None = None,
    chain_certs_pem: tuple[str, ...] | list[str] = (),
    declared_tls_info: dict[str, Any] | TlsCertificateInfo | None = None,
    tls_version: str = "",
    cipher_suite: str = "",
    reference_time_utc: datetime | None = None,
    fetcher_mode: str = "LIVE_HTTPS",
) -> tuple[TlsVerificationResult, TlsCertificateInfo | None]:
    """Independently verify X.509 peer cert chain against trusted CA, hostname/SAN, validity dates, and declared metadata."""
    now_dt = reference_time_utc if reference_time_utc is not None else datetime.now(timezone.utc)
    now_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    fmode = str(fetcher_mode or "UNSPECIFIED").upper().strip()
    host = str(server_hostname or "").strip().lower()

    errors: list[str] = []
    error_codes: list[str] = []

    if not leaf_cert_pem or not isinstance(leaf_cert_pem, str):
        return (
            TlsVerificationResult(
                verified=False,
                ca_chain_verified=False,
                hostname_san_verified=False,
                validity_period_verified=False,
                metadata_consistent_with_x509=False,
                trusted_ca_source="NONE",
                fetcher_mode=fmode,
                production_tls_verified=False,
                verified_at_utc=now_iso,
                server_hostname=host,
                tls_alone_proves_historical_content=False,
                error_codes=("TLS_FAKE_OR_UNVERIFIABLE_METADATA",),
                errors=(
                    "Gerçek X.509 yaprak sertifika PEM verisi (leaf_cert_pem) eksik; "
                    "yalnızca düz metin TLS metadata doğrulama olarak kabul edilemez.",
                ),
            ),
            None,
        )

    parsed = _extract_x509_fields_from_pem(leaf_cert_pem)
    if parsed is None:
        return (
            TlsVerificationResult(
                verified=False,
                ca_chain_verified=False,
                hostname_san_verified=False,
                validity_period_verified=False,
                metadata_consistent_with_x509=False,
                trusted_ca_source="NONE",
                fetcher_mode=fmode,
                production_tls_verified=False,
                verified_at_utc=now_iso,
                server_hostname=host,
                tls_alone_proves_historical_content=False,
                error_codes=("TLS_FAKE_OR_UNVERIFIABLE_METADATA",),
                errors=("leaf_cert_pem geçerli bir X.509 PEM sertifikası olarak ayrıştırılamadı.",),
            ),
            None,
        )

    # 1. Validity period check (direct from X.509 certificate!)
    validity_ok = parsed["not_before_dt"] <= now_dt <= parsed["not_after_dt"]
    if not validity_ok:
        error_codes.append("TLS_CERTIFICATE_EXPIRED_OR_NOT_YET_VALID")
        errors.append(
            f"TLS sertifikası geçerlilik süresi dışında: notBefore={parsed['not_before_utc']}, "
            f"notAfter={parsed['not_after_utc']}, kontrol={now_iso}."
        )

    # 2. Hostname & SAN (RFC 6125) check directly against X.509 SAN DNS names (fallback CN only if no SAN)
    san_names: tuple[str, ...] = parsed["san_dns_names"]
    matched_name: str | None = None
    if host:
        candidates = list(san_names) if san_names else ([parsed["common_name"]] if parsed["common_name"] else [])
        for cand in candidates:
            if _hostname_matches_pattern(host, cand):
                matched_name = cand
                break
    hostname_ok = matched_name is not None
    if not hostname_ok:
        error_codes.append("TLS_HOSTNAME_OR_SAN_MISMATCH")
        errors.append(
            f"Sunucu alan adı ('{host}') X.509 sertifika SAN/CN alanlarıyla uyuşmuyor "
            f"(SAN={list(san_names)}, CN={parsed['common_name']})."
        )

    # 3. Trusted CA certificate chain verification via OpenSSL 3 `openssl verify`
    ca_chain_ok = False
    ca_source = "NONE"
    openssl = _openssl_exe()
    with tempfile.TemporaryDirectory(prefix="calisora_tls_verify_") as tmp:
        leaf_path = Path(tmp) / "leaf.pem"
        leaf_path.write_text(leaf_cert_pem.strip() + "\n", encoding="utf-8")

        ca_file_arg: str | None = None
        if trusted_ca_pem and "-----BEGIN CERTIFICATE-----" in trusted_ca_pem:
            ca_path = Path(tmp) / "trusted_ca.pem"
            ca_path.write_text(trusted_ca_pem.strip() + "\n", encoding="utf-8")
            ca_file_arg = str(ca_path)
            ca_source = "EXPLICIT_TRUSTED_CA_PEM"
        elif trusted_ca_pem_path and Path(trusted_ca_pem_path).is_file():
            ca_file_arg = str(Path(trusted_ca_pem_path))
            ca_source = f"EXPLICIT_CA_FILE:{Path(trusted_ca_pem_path).name}"
        else:
            sys_ca = _resolve_system_ca_bundle()
            if sys_ca:
                ca_file_arg = sys_ca
                ca_source = "SYSTEM_CA_BUNDLE"

        if not ca_file_arg:
            error_codes.append("TLS_UNTRUSTED_CA_OR_CHAIN_INVALID")
            errors.append("TLS sertifika zinciri doğrulaması için güvenilir CA paketi bulunamadı.")
        else:
            cmd = [openssl, "verify", "-x509_strict", "-no-CApath", "-CAfile", ca_file_arg]
            valid_intermediates = [c.strip() for c in chain_certs_pem if isinstance(c, str) and "BEGIN CERTIFICATE" in c]
            if valid_intermediates:
                untrusted_path = Path(tmp) / "chain.pem"
                untrusted_path.write_text("\n".join(valid_intermediates) + "\n", encoding="utf-8")
                cmd.extend(["-untrusted", str(untrusted_path)])
            if reference_time_utc is not None:
                cmd.extend(["-attime", str(int(reference_time_utc.timestamp()))])
            cmd.append(str(leaf_path))

            p_ver = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if p_ver.returncode == 0 and ": OK" in p_ver.stdout:
                ca_chain_ok = True
            else:
                ver_msg = (p_ver.stderr or p_ver.stdout).strip()
                if "expired" in ver_msg.lower() or "not yet valid" in ver_msg.lower():
                    if "TLS_CERTIFICATE_EXPIRED_OR_NOT_YET_VALID" not in error_codes:
                        error_codes.append("TLS_CERTIFICATE_EXPIRED_OR_NOT_YET_VALID")
                error_codes.append("TLS_UNTRUSTED_CA_OR_CHAIN_INVALID")
                errors.append(f"TLS sertifika zinciri güvenilir CA ile doğrulanamadı: {ver_msg}")

    # 4. Cross-check declared TLS metadata (if supplied) against real parsed X.509 PEM fields
    meta_consistent = True
    decl: dict[str, Any] | None = None
    if isinstance(declared_tls_info, TlsCertificateInfo):
        decl = declared_tls_info.to_dict()
    elif isinstance(declared_tls_info, dict):
        decl = declared_tls_info

    if decl is not None:
        decl_sha = str(decl.get("leaf_cert_sha256") or "").strip().lower()
        if decl_sha and decl_sha != parsed["leaf_cert_sha256"]:
            meta_consistent = False
            error_codes.append("TLS_FAKE_OR_UNVERIFIABLE_METADATA")
            errors.append(
                f"Beyan edilen leaf_cert_sha256 ('{decl_sha}') gerçek X.509 PEM özeti ('{parsed['leaf_cert_sha256']}') ile uyuşmuyor."
            )
        decl_nb = str(decl.get("not_before_utc") or "").strip()
        decl_na = str(decl.get("not_after_utc") or "").strip()
        if (decl_nb and decl_nb != parsed["not_before_utc"]) or (decl_na and decl_na != parsed["not_after_utc"]):
            meta_consistent = False
            error_codes.append("TLS_FAKE_OR_UNVERIFIABLE_METADATA")
            errors.append("Beyan edilen sertifika geçerlilik tarihleri gerçek X.509 PEM sertifikasıyla uyuşmuyor.")
        decl_host = str(decl.get("server_hostname") or "").strip().lower()
        if decl_host and host and decl_host != host:
            meta_consistent = False
            error_codes.append("TLS_FAKE_OR_UNVERIFIABLE_METADATA")
            errors.append(f"Beyan edilen server_hostname ('{decl_host}') hedef alan adı ('{host}') ile uyuşmuyor.")

    chain_subjects = [parsed["peer_subject"]]
    for inter_pem in chain_certs_pem:
        inter_parsed = _extract_x509_fields_from_pem(inter_pem)
        if inter_parsed and inter_parsed["peer_subject"] not in chain_subjects:
            chain_subjects.append(inter_parsed["peer_subject"])

    eff_tls_ver = tls_version or (str(decl.get("tls_version") or "") if decl else "") or "TLSv1.3"
    eff_cipher = cipher_suite or (str(decl.get("cipher_suite") or "") if decl else "") or "UNKNOWN"

    cert_info = TlsCertificateInfo(
        tls_version=eff_tls_ver,
        cipher_suite=eff_cipher,
        server_hostname=host,
        peer_subject=parsed["peer_subject"],
        peer_issuer=parsed["peer_issuer"],
        san_dns_names=san_names,
        serial_number=parsed["serial_number"],
        not_before_utc=parsed["not_before_utc"],
        not_after_utc=parsed["not_after_utc"],
        leaf_cert_sha256=parsed["leaf_cert_sha256"],
        chain_subjects=tuple(chain_subjects),
        leaf_cert_pem=leaf_cert_pem.strip(),
        chain_certs_pem=tuple(c.strip() for c in chain_certs_pem if isinstance(c, str) and c.strip()),
    )

    verified = ca_chain_ok and hostname_ok and validity_ok and meta_consistent and len(errors) == 0
    # CRITICAL: Callback-sourced TLS data can NEVER count as production TLS verification!
    prod_tls_verified = bool(verified and fmode == "LIVE_HTTPS")

    return (
        TlsVerificationResult(
            verified=verified,
            ca_chain_verified=ca_chain_ok,
            hostname_san_verified=hostname_ok,
            validity_period_verified=validity_ok,
            metadata_consistent_with_x509=meta_consistent,
            trusted_ca_source=ca_source,
            fetcher_mode=fmode,
            production_tls_verified=prod_tls_verified,
            verified_at_utc=now_iso,
            server_hostname=host,
            matched_san_or_cn=matched_name,
            leaf_cert_sha256=parsed["leaf_cert_sha256"],
            tls_alone_proves_historical_content=False,
            error_codes=tuple(sorted(set(error_codes))),
            errors=tuple(errors),
        ),
        cert_info,
    )


def validate_official_https_url(
    url: str,
    *,
    allowed_domains: frozenset[str] | set[str],
    is_redirect_hop: bool = False,
) -> tuple[str | None, str | None]:
    """Validate that URL uses HTTPS strictly (no HTTP downgrade) and targets an allowlisted official domain."""
    parsed = urlparse(str(url or "").strip())
    scheme = (parsed.scheme or "").lower()
    if scheme != "https":
        if is_redirect_hop:
            return (
                "HTTPS_DOWNGRADE_REDIRECT_BLOCKED",
                f"HTTP yönlendirmesiyle HTTPS dışına çıkış engellendi: '{url}'.",
            )
        return (
            "SOURCE_ACQUISITION_HTTPS_REQUIRED",
            f"Kaynak edinimi yalnızca HTTPS protokolü üzerinden yapılabilir: '{url}'.",
        )
    if parsed.username or parsed.password:
        return "DISALLOWED_OFFICIAL_SOURCE_DOMAIN", f"URL içinde kimlik bilgisi (userinfo) yasaktır: '{url}'."
    host = (parsed.hostname or "").strip().lower()
    allowed_norm = {d.strip().lower() for d in allowed_domains if d and d.strip()}
    if not host or host not in allowed_norm:
        return (
            "DISALLOWED_OFFICIAL_SOURCE_DOMAIN",
            f"Alan adı ('{host}') izin verilen resmî kaynak alan adları listesinde değildir: {sorted(allowed_norm)}.",
        )
    return None, None


class LiveHttpsSourceFetcher:
    """Real HTTPS source acquisition client with strict TLS 1.2+, CA chain, SAN/hostname, HTTPS-only redirect & domain allowlist checks."""

    def __init__(
        self,
        *,
        allowed_domains: set[str] | frozenset[str] = DEFAULT_ALLOWED_OFFICIAL_DOMAINS,
        trusted_ca_pem_path: str | Path | None = None,
        trusted_ca_pem: str | None = None,
        timeout_seconds: float = 15.0,
        max_redirects: int = 5,
    ) -> None:
        self.allowed_domains: frozenset[str] = frozenset(d.strip().lower() for d in allowed_domains if d.strip())
        self.trusted_ca_pem_path = str(trusted_ca_pem_path) if trusted_ca_pem_path else None
        self.trusted_ca_pem = trusted_ca_pem
        self.timeout_seconds = float(timeout_seconds)
        self.max_redirects = int(max_redirects)

    def _build_ssl_context(self) -> ssl.SSLContext:
        if self.trusted_ca_pem and "-----BEGIN CERTIFICATE-----" in self.trusted_ca_pem:
            ctx = ssl.create_default_context(cadata=self.trusted_ca_pem)
        elif self.trusted_ca_pem_path:
            ctx = ssl.create_default_context(cafile=self.trusted_ca_pem_path)
        else:
            ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        ctx.verify_flags |= getattr(ssl, "VERIFY_X509_STRICT", 0)
        return ctx

    @staticmethod
    def _classify_ssl_error(exc: ssl.SSLError, hostname: str) -> SourceAcquisitionSecurityError:
        msg = str(exc)
        low = msg.lower()
        if "hostname mismatch" in low or "ip address mismatch" in low or "doesn't match" in low:
            return SourceAcquisitionSecurityError(
                "TLS_HOSTNAME_OR_SAN_MISMATCH",
                f"Canlı TLS el sıkışmasında alan adı/SAN uyuşmazlığı ('{hostname}'): {msg}",
            )
        if "certificate has expired" in low or "not yet valid" in low:
            return SourceAcquisitionSecurityError(
                "TLS_CERTIFICATE_EXPIRED_OR_NOT_YET_VALID",
                f"Canlı TLS el sıkışmasında sertifika geçerlilik süresi hatası ('{hostname}'): {msg}",
            )
        return SourceAcquisitionSecurityError(
            "TLS_UNTRUSTED_CA_OR_CHAIN_INVALID",
            f"Canlı TLS el sıkışmasında güvenilir CA / sertifika zinciri hatası ('{hostname}'): {msg}",
        )

    def fetch(self, source_url: str) -> dict[str, Any]:
        """Perform a real HTTPS fetch with hop-by-hop redirect validation and real peer X.509 certificate verification."""
        err_code, err_msg = validate_official_https_url(
            source_url,
            allowed_domains=self.allowed_domains,
            is_redirect_hop=False,
        )
        if err_code:
            raise SourceAcquisitionSecurityError(err_code, err_msg or "Geçersiz kaynak URL.")

        redirect_chain: list[str] = [source_url]
        current_url = source_url
        ssl_ctx = self._build_ssl_context()

        for _hop in range(self.max_redirects + 1):
            parsed = urlparse(current_url)
            host = parsed.hostname or ""
            port = parsed.port or 443
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"

            conn = http.client.HTTPSConnection(host, port, timeout=self.timeout_seconds, context=ssl_ctx)
            try:
                try:
                    conn.connect()
                except ssl.SSLError as ssl_exc:
                    raise self._classify_ssl_error(ssl_exc, host) from ssl_exc

                sock = conn.sock
                if sock is None or not isinstance(sock, ssl.SSLSocket):
                    raise SourceAcquisitionSecurityError(
                        "TLS_HANDSHAKE_MISSING",
                        "Canlı HTTPS bağlantısında TLS soketi doğrulanamadı.",
                    )

                der_cert = sock.getpeercert(binary_form=True)
                if not der_cert:
                    raise SourceAcquisitionSecurityError(
                        "TLS_FAKE_OR_UNVERIFIABLE_METADATA",
                        "Canlı HTTPS oturumundan X.509 eş sertifikası (DER) alınamadı.",
                    )
                leaf_pem = ssl.DER_cert_to_PEM_cert(der_cert)
                chain_pems: list[str] = []
                if hasattr(sock, "get_verified_chain"):
                    try:
                        for c_der in sock.get_verified_chain()[1:]:
                            if isinstance(c_der, (bytes, bytearray)):
                                chain_pems.append(ssl.DER_cert_to_PEM_cert(bytes(c_der)))
                    except Exception:
                        pass

                tls_ver_str = str(sock.version() or "TLSv1.3")
                cipher_tuple = sock.cipher()
                cipher_str = str(cipher_tuple[0]) if cipher_tuple else "UNKNOWN"

                # Independently verify the real X.509 PEM certificate BEFORE transmitting the HTTP request!
                tls_ver_res, cert_info = verify_tls_peer_certificate_chain(
                    leaf_pem,
                    server_hostname=host,
                    trusted_ca_pem=self.trusted_ca_pem,
                    trusted_ca_pem_path=self.trusted_ca_pem_path,
                    chain_certs_pem=tuple(chain_pems),
                    tls_version=tls_ver_str,
                    cipher_suite=cipher_str,
                    fetcher_mode="LIVE_HTTPS",
                )
                if not tls_ver_res.verified or cert_info is None:
                    first_code = tls_ver_res.error_codes[0] if tls_ver_res.error_codes else "TLS_UNTRUSTED_CA_OR_CHAIN_INVALID"
                    raise SourceAcquisitionSecurityError(first_code, "; ".join(tls_ver_res.errors))

                try:
                    conn.request(
                        "GET",
                        path,
                        headers={
                            "User-Agent": f"hrAI-HukukSGK/{TRUST_ROOT_VERSION} (SourceAcquisition)",
                            "Accept": "text/html,application/pdf,application/json,*/*;q=0.8",
                        },
                    )
                    resp = conn.getresponse()
                except ssl.SSLError as ssl_exc:
                    raise self._classify_ssl_error(ssl_exc, host) from ssl_exc

                status = int(resp.status)
                headers = {str(k): str(v) for k, v in resp.getheaders()}
                body = resp.read()

                if status in _REDIRECT_STATUSES:
                    loc = headers.get("Location") or headers.get("location")
                    if not loc:
                        raise SourceAcquisitionSecurityError(
                            "SOURCE_ACQUISITION_REDIRECT_CHAIN_INVALID",
                            f"HTTP {status} yönlendirme yanıtında Location başlığı eksiktir.",
                        )
                    next_url = urljoin(current_url, loc.strip())
                    r_code, r_msg = validate_official_https_url(
                        next_url,
                        allowed_domains=self.allowed_domains,
                        is_redirect_hop=True,
                    )
                    if r_code:
                        raise SourceAcquisitionSecurityError(r_code, r_msg or "Güvensiz yönlendirme engellendi.")
                    redirect_chain.append(next_url)
                    current_url = next_url
                    continue

                return {
                    "raw_bytes": body,
                    "final_url": current_url,
                    "redirect_chain": redirect_chain,
                    "http_status": status,
                    "http_headers": headers,
                    "tls_certificate_info": cert_info,
                    "tls_verification_result": tls_ver_res.to_dict(),
                    "fetcher_mode": "LIVE_HTTPS",
                    "acquired_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
            finally:
                conn.close()

        raise SourceAcquisitionSecurityError(
            "SOURCE_ACQUISITION_TOO_MANY_REDIRECTS",
            f"Azami yönlendirme sınırı ({self.max_redirects}) aşıldı.",
        )


def build_acquisition_signing_payload(envelope_dict: dict[str, Any]) -> dict[str, Any]:
    """Build the exact RFC 8785 (JCS) canonical signing payload binding all acquisition & TLS verification fields."""
    tsa_block = envelope_dict.get("tsa_result") or {}
    tls_block = envelope_dict.get("tls_certificate_info") or {}
    tls_ver_block = envelope_dict.get("tls_verification_result") or {}
    return {
        "schema": "CALISORA_SOURCE_ACQUISITION_EVIDENCE_V1_1",
        "schema_version": str(envelope_dict.get("schema_version") or TRUST_ROOT_VERSION),
        "acquisition_id": str(envelope_dict.get("acquisition_id") or ""),
        "source_id": str(envelope_dict.get("source_id") or ""),
        "source_url": str(envelope_dict.get("source_url") or ""),
        "final_url": str(envelope_dict.get("final_url") or ""),
        "redirect_chain": list(envelope_dict.get("redirect_chain") or []),
        "http_status": int(envelope_dict.get("http_status") or 0),
        "http_headers": dict(envelope_dict.get("http_headers") or {}),
        "fetcher_mode": str(envelope_dict.get("fetcher_mode") or "UNSPECIFIED"),
        "tls_leaf_cert_sha256": str(tls_block.get("leaf_cert_sha256") or ""),
        "tls_peer_subject": str(tls_block.get("peer_subject") or ""),
        "tls_peer_issuer": str(tls_block.get("peer_issuer") or ""),
        "tls_ca_chain_verified": bool(tls_ver_block.get("ca_chain_verified", False)),
        "tls_hostname_san_verified": bool(tls_ver_block.get("hostname_san_verified", False)),
        "tls_validity_period_verified": bool(tls_ver_block.get("validity_period_verified", False)),
        "production_tls_verified": bool(envelope_dict.get("production_tls_verified", False)),
        "acquired_at_utc": str(envelope_dict.get("acquired_at_utc") or ""),
        "raw_bytes_sha256": str(envelope_dict.get("raw_bytes_sha256") or "").lower(),
        "raw_bytes_length": int(envelope_dict.get("raw_bytes_length") or 0),
        "worm_object_uri": str(envelope_dict.get("worm_object_uri") or ""),
        "tsa_gen_time_utc": tsa_block.get("gen_time_utc"),
        "tsa_serial_number": tsa_block.get("serial_number"),
        "tls_alone_proves_historical_content": False,
    }


class DefaultSourceAcquisitionProvider(SourceAcquisitionProvider):
    """Provider-agnostic official source acquisition evidence sealer & independent TLS/WORM/TSA/KMS verifier."""

    verifier_service_id: str = "CALISORA_SOURCE_ACQUISITION_VERIFIER_V1031"

    def __init__(
        self,
        *,
        worm_storage: ImmutableEvidenceStorageProvider | None = None,
        tsa_provider: TimestampAuthorityProvider | None = None,
        kms_signer: KeySignerProvider | None = None,
        signing_key_ref: str | None = None,
        algorithm: str = "ED25519",
        live_https_fetcher: LiveHttpsSourceFetcher | None = None,
        mock_fetcher: AcquisitionFetcherFn | None = None,
        fetcher: AcquisitionFetcherFn | None = None,
        allowed_domains: set[str] | frozenset[str] = DEFAULT_ALLOWED_OFFICIAL_DOMAINS,
        trusted_ca_pem: str | None = None,
        trusted_ca_pem_path: str | Path | None = None,
    ) -> None:
        self.worm_storage = worm_storage
        self.tsa_provider = tsa_provider
        self.kms_signer = kms_signer
        self.signing_key_ref = signing_key_ref
        self.algorithm = algorithm.upper().strip()
        self.live_https_fetcher = live_https_fetcher
        self.mock_fetcher = mock_fetcher if mock_fetcher is not None else fetcher
        self.allowed_domains: frozenset[str] = (
            live_https_fetcher.allowed_domains
            if live_https_fetcher is not None
            else frozenset(d.strip().lower() for d in allowed_domains if d.strip())
        )
        self.trusted_ca_pem = (
            trusted_ca_pem
            if trusted_ca_pem is not None
            else (live_https_fetcher.trusted_ca_pem if live_https_fetcher is not None else None)
        )
        self.trusted_ca_pem_path = (
            str(trusted_ca_pem_path)
            if trusted_ca_pem_path is not None
            else (live_https_fetcher.trusted_ca_pem_path if live_https_fetcher is not None else None)
        )

        if self.live_https_fetcher is not None and self.mock_fetcher is not None:
            raise ValueError(
                "live_https_fetcher ve mock_fetcher aynı anda verilemez; canlı HTTPS istemcisi ile mock callback ayrıdır."
            )

        self._fetcher_mode = (
            "LIVE_HTTPS"
            if self.live_https_fetcher is not None
            else ("MOCK_CALLBACK" if self.mock_fetcher is not None else "UNSPECIFIED")
        )

        sub_modes = [p.integration_mode for p in (worm_storage, tsa_provider, kms_signer) if p is not None]
        if (
            worm_storage is None
            or tsa_provider is None
            or kms_signer is None
            or not signing_key_ref
            or "NOT_CONFIGURED" in sub_modes
        ):
            self._integration_mode = "NOT_CONFIGURED"
        elif "MOCK_SANDBOX" in sub_modes or self.mock_fetcher is not None:
            self._integration_mode = "MOCK_SANDBOX"
        elif self.live_https_fetcher is not None:
            self._integration_mode = "LIVE_PRODUCTION"
        else:
            self._integration_mode = "NOT_CONFIGURED"

    @property
    def provider_name(self) -> str:
        return "CALISORA_SOURCE_ACQUISITION_EVIDENCE_PROVIDER"

    @property
    def integration_mode(self) -> str:
        return self._integration_mode

    @property
    def fetcher_mode(self) -> str:
        return self._fetcher_mode

    def health_check(self) -> ProviderHealthStatus:
        if self._integration_mode == "NOT_CONFIGURED":
            return ProviderHealthStatus(
                provider_name=self.provider_name,
                provider_type="SourceAcquisitionProvider",
                backend="WORM_TSA_KMS_TLS_ACQUISITION",
                integration_mode="NOT_CONFIGURED",
                configured=False,
                reachable=False,
                details={
                    "worm_mode": self.worm_storage.integration_mode if self.worm_storage else "NOT_CONFIGURED",
                    "tsa_mode": self.tsa_provider.integration_mode if self.tsa_provider else "NOT_CONFIGURED",
                    "kms_mode": self.kms_signer.integration_mode if self.kms_signer else "NOT_CONFIGURED",
                    "fetcher_mode": self._fetcher_mode,
                    "signing_key_configured": bool(self.signing_key_ref),
                },
                error_code="SOURCE_ACQUISITION_NOT_CONFIGURED",
                error_message="Kaynak edinim kanıt zarfı için WORM, RFC 3161 TSA, KMS/HSM veya canlı HTTPS istemcisinden en az biri yapılandırılmamıştır.",
            )
        return ProviderHealthStatus(
            provider_name=self.provider_name,
            provider_type="SourceAcquisitionProvider",
            backend="WORM_TSA_KMS_TLS_ACQUISITION",
            integration_mode=self._integration_mode,
            configured=True,
            reachable=self._integration_mode == "MOCK_SANDBOX" or self.live_https_fetcher is not None,
            details={
                "algorithm": self.algorithm,
                "signing_key_ref": self.signing_key_ref,
                "fetcher_mode": self._fetcher_mode,
                "allowed_domains_count": len(self.allowed_domains),
            },
        )

    def _failed_envelope(
        self,
        *,
        acq_id: str,
        source_id: str,
        source_url: str,
        now_utc: str,
        error_codes: tuple[str, ...],
        errors: tuple[str, ...],
        fetcher_mode: str | None = None,
        integration_mode: str | None = None,
    ) -> SourceAcquisitionEvidenceEnvelope:
        return SourceAcquisitionEvidenceEnvelope(
            schema_version=TRUST_ROOT_VERSION,
            acquisition_id=acq_id,
            source_id=source_id,
            source_url=source_url,
            final_url=source_url,
            redirect_chain=(source_url,),
            http_status=0,
            http_headers={},
            tls_certificate_info=None,
            acquired_at_utc=now_utc,
            raw_bytes_sha256="",
            raw_bytes_length=0,
            worm_object_uri=None,
            worm_receipt=None,
            tsa_result=None,
            acquisition_signature=None,
            signature_verified=False,
            fetcher_mode=fetcher_mode or self._fetcher_mode,
            tls_verification_result=None,
            production_tls_verified=False,
            tls_alone_proves_historical_content=False,
            tls_non_historical_proof_notice=TLS_NON_HISTORICAL_PROOF_NOTICE,
            provider_backend=self.provider_name,
            integration_mode=integration_mode or self._integration_mode,
            valid=False,
            error_codes=error_codes,
            errors=errors,
        )

    def acquire_and_seal_source(
        self,
        source_id: str,
        source_url: str,
        *,
        runtime_environment: str = "PRODUCTION",
    ) -> SourceAcquisitionEvidenceEnvelope:
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        acq_id = f"ACQ-{source_id}-{secrets.token_hex(6).upper()}"

        if self._integration_mode == "NOT_CONFIGURED" or (
            self.live_https_fetcher is None and self.mock_fetcher is None
        ):
            return self._failed_envelope(
                acq_id=acq_id,
                source_id=source_id,
                source_url=source_url,
                now_utc=now_utc,
                error_codes=("SOURCE_ACQUISITION_NOT_CONFIGURED",),
                errors=("Kaynak edinim sağlayıcısı (WORM/TSA/KMS/HTTPS istemcisi) tam yapılandırılmamıştır.",),
                integration_mode="NOT_CONFIGURED",
            )

        # Pre-validate HTTPS scheme & official domain allowlist before any network or mock fetch
        url_err_code, url_err_msg = validate_official_https_url(
            source_url,
            allowed_domains=self.allowed_domains,
            is_redirect_hop=False,
        )
        if url_err_code:
            return self._failed_envelope(
                acq_id=acq_id,
                source_id=source_id,
                source_url=source_url,
                now_utc=now_utc,
                error_codes=(url_err_code,),
                errors=(url_err_msg or "Geçersiz kaynak URL.",),
            )

        assert self.worm_storage is not None
        assert self.tsa_provider is not None
        assert self.kms_signer is not None
        assert self.signing_key_ref is not None

        try:
            if self.live_https_fetcher is not None:
                fetched = self.live_https_fetcher.fetch(source_url)
                active_fetcher_mode = "LIVE_HTTPS"
            else:
                assert self.mock_fetcher is not None
                fetched = self.mock_fetcher(source_url)
                active_fetcher_mode = "MOCK_CALLBACK"
        except SourceAcquisitionSecurityError as sec_exc:
            return self._failed_envelope(
                acq_id=acq_id,
                source_id=source_id,
                source_url=source_url,
                now_utc=now_utc,
                error_codes=(sec_exc.error_code,),
                errors=(sec_exc.message,),
            )

        raw_bytes = bytes(fetched["raw_bytes"])
        raw_sha = hashlib.sha256(raw_bytes).hexdigest()
        final_url = str(fetched.get("final_url") or source_url)
        redirect_chain = tuple(str(u) for u in (fetched.get("redirect_chain") or [source_url]))
        http_status = int(fetched.get("http_status") or 200)
        http_headers = {str(k): str(v) for k, v in (fetched.get("http_headers") or {}).items()}
        acquired_at = str(fetched.get("acquired_at_utc") or now_utc)

        raw_tls = fetched.get("tls_certificate_info")
        tls_obj: TlsCertificateInfo | None = None
        if isinstance(raw_tls, TlsCertificateInfo):
            tls_obj = raw_tls
        elif isinstance(raw_tls, dict):
            tls_obj = TlsCertificateInfo(
                tls_version=str(raw_tls.get("tls_version") or ""),
                cipher_suite=str(raw_tls.get("cipher_suite") or ""),
                server_hostname=str(raw_tls.get("server_hostname") or ""),
                peer_subject=str(raw_tls.get("peer_subject") or ""),
                peer_issuer=str(raw_tls.get("peer_issuer") or ""),
                san_dns_names=tuple(str(x) for x in (raw_tls.get("san_dns_names") or ())),
                serial_number=str(raw_tls.get("serial_number") or ""),
                not_before_utc=str(raw_tls.get("not_before_utc") or ""),
                not_after_utc=str(raw_tls.get("not_after_utc") or ""),
                leaf_cert_sha256=str(raw_tls.get("leaf_cert_sha256") or "").lower(),
                chain_subjects=tuple(str(x) for x in (raw_tls.get("chain_subjects") or ())),
                leaf_cert_pem=raw_tls.get("leaf_cert_pem"),
                chain_certs_pem=tuple(str(x) for x in (raw_tls.get("chain_certs_pem") or ())),
            )

        # Independently verify X.509 PEM certificate chain, hostname/SAN & validity dates before sealing!
        final_host = (urlparse(final_url).hostname or "").strip().lower()
        tls_ver_res, verified_cert_info = verify_tls_peer_certificate_chain(
            tls_obj.leaf_cert_pem if tls_obj is not None else None,
            server_hostname=final_host,
            trusted_ca_pem=self.trusted_ca_pem,
            trusted_ca_pem_path=self.trusted_ca_pem_path,
            chain_certs_pem=tls_obj.chain_certs_pem if tls_obj is not None else (),
            declared_tls_info=tls_obj,
            tls_version=tls_obj.tls_version if tls_obj is not None else "",
            cipher_suite=tls_obj.cipher_suite if tls_obj is not None else "",
            fetcher_mode=active_fetcher_mode,
        )
        effective_tls_obj = verified_cert_info if verified_cert_info is not None else tls_obj

        # 1. Persist raw HTTP response bytes in WORM storage
        obj_name = f"source_acquisitions/{source_id}/{acq_id}_{raw_sha[:16]}.raw"
        worm_receipt = self.worm_storage.put_immutable_object(
            obj_name,
            raw_bytes,
            content_type=http_headers.get("Content-Type", "application/octet-stream"),
            metadata={
                "acquisition_id": acq_id,
                "source_id": source_id,
                "source_url": source_url,
                "raw_bytes_sha256": raw_sha,
                "fetcher_mode": active_fetcher_mode,
            },
        )

        # 2. Obtain independent RFC 3161 TSA timestamp over raw bytes SHA-256
        tsa_res = self.tsa_provider.request_timestamp(raw_sha)

        # 3. Sign canonical acquisition + TLS verification metadata using KMS/HSM
        draft_dict: dict[str, Any] = {
            "schema_version": TRUST_ROOT_VERSION,
            "acquisition_id": acq_id,
            "source_id": source_id,
            "source_url": source_url,
            "final_url": final_url,
            "redirect_chain": list(redirect_chain),
            "http_status": http_status,
            "http_headers": http_headers,
            "fetcher_mode": active_fetcher_mode,
            "tls_certificate_info": effective_tls_obj.to_dict() if effective_tls_obj else None,
            "tls_verification_result": tls_ver_res.to_dict(),
            "production_tls_verified": tls_ver_res.production_tls_verified,
            "acquired_at_utc": acquired_at,
            "raw_bytes_sha256": raw_sha,
            "raw_bytes_length": len(raw_bytes),
            "worm_object_uri": worm_receipt.object_uri,
            "tsa_result": tsa_res.to_dict(),
        }
        sig_env = self.kms_signer.sign_canonical_json(
            build_acquisition_signing_payload(draft_dict),
            self.signing_key_ref,
            algorithm=self.algorithm,
            runtime_environment=runtime_environment,
        )

        envelope = SourceAcquisitionEvidenceEnvelope(
            schema_version=TRUST_ROOT_VERSION,
            acquisition_id=acq_id,
            source_id=source_id,
            source_url=source_url,
            final_url=final_url,
            redirect_chain=redirect_chain,
            http_status=http_status,
            http_headers=http_headers,
            tls_certificate_info=effective_tls_obj,
            acquired_at_utc=acquired_at,
            raw_bytes_sha256=raw_sha,
            raw_bytes_length=len(raw_bytes),
            worm_object_uri=worm_receipt.object_uri,
            worm_receipt=worm_receipt.to_dict(),
            tsa_result=tsa_res.to_dict(),
            acquisition_signature=sig_env.to_dict(),
            signature_verified=False,
            fetcher_mode=active_fetcher_mode,
            tls_verification_result=tls_ver_res.to_dict(),
            production_tls_verified=tls_ver_res.production_tls_verified,
            tls_alone_proves_historical_content=False,
            tls_non_historical_proof_notice=TLS_NON_HISTORICAL_PROOF_NOTICE,
            provider_backend=self.provider_name,
            integration_mode=self._integration_mode,
            valid=False,
        )
        ver_res = self.verify_acquisition_evidence_result(
            envelope,
            expected_raw_bytes=raw_bytes,
            runtime_environment=runtime_environment,
        )
        return SourceAcquisitionEvidenceEnvelope(
            schema_version=envelope.schema_version,
            acquisition_id=envelope.acquisition_id,
            source_id=envelope.source_id,
            source_url=envelope.source_url,
            final_url=envelope.final_url,
            redirect_chain=envelope.redirect_chain,
            http_status=envelope.http_status,
            http_headers=envelope.http_headers,
            tls_certificate_info=envelope.tls_certificate_info,
            acquired_at_utc=envelope.acquired_at_utc,
            raw_bytes_sha256=envelope.raw_bytes_sha256,
            raw_bytes_length=envelope.raw_bytes_length,
            worm_object_uri=envelope.worm_object_uri,
            worm_receipt=envelope.worm_receipt,
            tsa_result=envelope.tsa_result,
            acquisition_signature=envelope.acquisition_signature,
            signature_verified=ver_res.signature_verified,
            fetcher_mode=envelope.fetcher_mode,
            tls_verification_result=envelope.tls_verification_result,
            production_tls_verified=ver_res.production_tls_verified,
            tls_alone_proves_historical_content=False,
            tls_non_historical_proof_notice=TLS_NON_HISTORICAL_PROOF_NOTICE,
            provider_backend=self.provider_name,
            integration_mode=self._integration_mode,
            valid=ver_res.valid,
            error_codes=ver_res.error_codes,
            errors=ver_res.errors,
        )

    def verify_acquisition_evidence_result(
        self,
        envelope: SourceAcquisitionEvidenceEnvelope | dict[str, Any],
        *,
        expected_raw_bytes: bytes | None = None,
        runtime_environment: str = "PRODUCTION",
        reference_time_utc: datetime | None = None,
    ) -> SourceAcquisitionVerificationResult:
        """Independently verify raw bytes SHA-256, WORM, RFC 3161 TSA, KMS signature, HTTPS/domain allowlist & X.509 TLS chain.

        Returns an HMAC-sealed `SourceAcquisitionVerificationResult` trusted by `ProductionAuthorizationProvider`.
        """
        env_d = envelope.to_dict() if isinstance(envelope, SourceAcquisitionEvidenceEnvelope) else dict(envelope)
        errors: list[str] = []
        error_codes: list[str] = []

        fmode = str(env_d.get("fetcher_mode") or "UNSPECIFIED").upper().strip()

        # 1. Enforce strict epistemic rule: TLS info NEVER proves historical content alone!
        if env_d.get("tls_alone_proves_historical_content") is not False:
            error_codes.append("INVALID_TLS_HISTORICAL_PROOF_CLAIM")
            errors.append(
                "TLS bilgisi tek başına geçmişteki sunucu içeriğinin kanıtı olarak beyan edilemez "
                "(tls_alone_proves_historical_content mutlaka false olmalıdır)."
            )

        # 2. HTTPS URL, official domain allowlist, redirect chain (blocking HTTPS->HTTP downgrades!) & HTTP headers
        src_url = str(env_d.get("source_url") or "")
        final_url = str(env_d.get("final_url") or "")
        redirects = env_d.get("redirect_chain")

        s_code, s_msg = validate_official_https_url(src_url, allowed_domains=self.allowed_domains, is_redirect_hop=False)
        if s_code:
            error_codes.append(s_code)
            errors.append(s_msg or "Geçersiz source_url.")
        f_code, f_msg = validate_official_https_url(final_url, allowed_domains=self.allowed_domains, is_redirect_hop=True)
        if f_code:
            error_codes.append(f_code)
            errors.append(f_msg or "Geçersiz final_url.")

        if not isinstance(redirects, list) or not redirects or redirects[0] != src_url or redirects[-1] != final_url:
            error_codes.append("SOURCE_ACQUISITION_REDIRECT_CHAIN_INVALID")
            errors.append("redirect_chain source_url ile başlayıp final_url ile bitmelidir.")
        else:
            for hop_idx, hop_url in enumerate(redirects):
                h_code, h_msg = validate_official_https_url(
                    str(hop_url),
                    allowed_domains=self.allowed_domains,
                    is_redirect_hop=(hop_idx > 0),
                )
                if h_code:
                    error_codes.append(h_code)
                    errors.append(h_msg or f"Güvensiz yönlendirme adımı: {hop_url}")

        if not isinstance(env_d.get("http_headers"), dict) or not env_d["http_headers"]:
            error_codes.append("SOURCE_ACQUISITION_HEADERS_MISSING")
            errors.append("HTTP üstbilgileri (http_headers) zorunludur.")

        # 3. Independent X.509 PEM TLS certificate chain, CA trust, hostname/SAN & validity verification!
        tls_verified = False
        prod_tls_verified = False
        tls_info = env_d.get("tls_certificate_info")
        final_host = (urlparse(final_url).hostname or "").strip().lower()
        if not isinstance(tls_info, dict) or not tls_info.get("leaf_cert_sha256") or not tls_info.get("peer_subject"):
            error_codes.append("SOURCE_ACQUISITION_TLS_INFO_MISSING")
            errors.append("TLS sertifika zinciri bilgileri (tls_certificate_info) zorunludur.")
        else:
            tls_chk, _ = verify_tls_peer_certificate_chain(
                tls_info.get("leaf_cert_pem"),
                server_hostname=final_host,
                trusted_ca_pem=self.trusted_ca_pem,
                trusted_ca_pem_path=self.trusted_ca_pem_path,
                chain_certs_pem=tuple(tls_info.get("chain_certs_pem") or ()),
                declared_tls_info=tls_info,
                tls_version=str(tls_info.get("tls_version") or ""),
                cipher_suite=str(tls_info.get("cipher_suite") or ""),
                reference_time_utc=reference_time_utc,
                fetcher_mode=fmode,
            )
            if tls_chk.verified:
                tls_verified = True
                prod_tls_verified = tls_chk.production_tls_verified
            else:
                error_codes.extend(tls_chk.error_codes)
                errors.extend(tls_chk.errors)

        # Reject contradictory claim of production_tls_verified=True when fetcher_mode != LIVE_HTTPS
        if env_d.get("production_tls_verified") is True and fmode != "LIVE_HTTPS":
            error_codes.append("CALLBACK_FETCHER_NOT_ALLOWED_IN_PRODUCTION")
            errors.append(
                f"Callback tabanlı edinim ('{fmode}') üretim TLS doğrulaması (production_tls_verified=True) beyan edemez."
            )

        # 4. Raw bytes SHA-256 & WORM immutability verification
        raw_sha = str(env_d.get("raw_bytes_sha256") or "").strip().lower()
        if len(raw_sha) != 64:
            error_codes.append("SOURCE_ACQUISITION_SHA256_INVALID")
            errors.append("Ham HTTP yanıt baytları için geçerli 64 haneli SHA-256 zorunludur.")
        if expected_raw_bytes is not None:
            calc_sha = hashlib.sha256(expected_raw_bytes).hexdigest()
            if calc_sha != raw_sha:
                error_codes.append("SOURCE_ACQUISITION_RAW_BYTES_MISMATCH")
                errors.append(f"Ham bayt SHA-256 uyuşmuyor: beklenen={raw_sha}, hesaplanan={calc_sha}.")

        worm_uri = env_d.get("worm_object_uri")
        worm_verified = False
        if not worm_uri or self.worm_storage is None:
            error_codes.append("SOURCE_ACQUISITION_WORM_UNVERIFIED")
            errors.append("Ham HTTP baytlarının WORM depoda saklandığı doğrulanamadı.")
        else:
            worm_chk = self.worm_storage.verify_object_immutability(str(worm_uri), expected_sha256=raw_sha)
            if not worm_chk.worm_immutable_verified:
                error_codes.append("SOURCE_ACQUISITION_WORM_UNVERIFIED")
                errors.extend(worm_chk.errors)
            else:
                worm_verified = True

        # 5. Independent RFC 3161 TSA verification over raw bytes SHA-256
        tsa_verified = False
        tsa_block = env_d.get("tsa_result")
        if not isinstance(tsa_block, dict) or not tsa_block.get("tsr_der_b64") or self.tsa_provider is None:
            error_codes.append("SOURCE_ACQUISITION_TSA_MISSING_OR_INVALID")
            errors.append("Kaynak edinimi için bağımsız RFC 3161 zaman damgası (tsr_der_b64) eksik veya doğrulanamadı.")
        else:
            try:
                tsr_bytes = base64.b64decode(str(tsa_block["tsr_der_b64"]), validate=True)
                tsa_chk = self.tsa_provider.verify_timestamp_token(raw_sha, tsr_bytes)
                if tsa_chk.valid:
                    tsa_verified = True
                else:
                    error_codes.append("SOURCE_ACQUISITION_TSA_MISSING_OR_INVALID")
                    errors.extend(tsa_chk.errors)
            except Exception as exc:
                error_codes.append("SOURCE_ACQUISITION_TSA_MISSING_OR_INVALID")
                errors.append(f"RFC 3161 zaman damgası çözümlenemedi: {exc}")

        # 6. KMS/HSM asymmetric signature verification over RFC 8785 JCS acquisition + TLS metadata
        sig_verified = False
        sig_block = env_d.get("acquisition_signature")
        if not isinstance(sig_block, dict) or not sig_block.get("signature_b64") or self.kms_signer is None:
            error_codes.append("SOURCE_ACQUISITION_SIGNATURE_INVALID")
            errors.append("Kaynak edinim zarfı için KMS/HSM imzası eksik veya doğrulanamadı.")
        else:
            if sig_block.get("qualified_e_signature_5070_equivalent") is True:
                error_codes.append("INVALID_5070_EQUIVALENCE_CLAIM")
                errors.append("Kaynak edinim imzası 5070 s. Kanun güvenli elektronik imza eşdeğeri beyan edilemez.")
            ok, msg, _ = self.kms_signer.verify_canonical_json(
                build_acquisition_signing_payload(env_d),
                str(sig_block["signature_b64"]),
                str(sig_block.get("key_resource_id") or ""),
                str(sig_block.get("algorithm") or ""),
                runtime_environment=runtime_environment,
            )
            if ok:
                sig_verified = True
            else:
                error_codes.append("SOURCE_ACQUISITION_SIGNATURE_INVALID")
                errors.append(f"Kaynak edinim zarfı KMS/HSM imzası geçersiz: {msg}")

        valid = (
            len(errors) == 0
            and len(error_codes) == 0
            and worm_verified
            and tsa_verified
            and sig_verified
            and tls_verified
        )
        return seal_service_result(
            SourceAcquisitionVerificationResult(
                valid=valid,
                status="SOURCE_ACQUISITION_VERIFIED" if valid else "SOURCE_ACQUISITION_FAILED",
                acquisition_id=env_d.get("acquisition_id"),
                source_id=env_d.get("source_id"),
                raw_bytes_sha256=raw_sha or None,
                worm_verified=worm_verified,
                tsa_verified=tsa_verified,
                signature_verified=sig_verified,
                tls_verified=tls_verified,
                production_tls_verified=prod_tls_verified,
                fetcher_mode=fmode,
                verifier_service_id=self.verifier_service_id,
                tls_alone_proves_historical_content=False,
                tls_non_historical_proof_notice=TLS_NON_HISTORICAL_PROOF_NOTICE,
                error_codes=tuple(sorted(set(error_codes))),
                errors=tuple(errors),
            )
        )

    def verify_acquisition_evidence(
        self,
        envelope: SourceAcquisitionEvidenceEnvelope | dict[str, Any],
        *,
        expected_raw_bytes: bytes | None = None,
        runtime_environment: str = "PRODUCTION",
    ) -> dict[str, Any]:
        return self.verify_acquisition_evidence_result(
            envelope,
            expected_raw_bytes=expected_raw_bytes,
            runtime_environment=runtime_environment,
        ).to_dict()
