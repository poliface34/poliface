"""Independent RFC 3161 Time-Stamp Authority (TSA) provider for CALISORA @HukukSGK v1.0.3.

Uses OpenSSL 3 (`openssl ts -query` / `openssl ts -verify` / `openssl ts -reply`) with zero external Python
dependencies to build genuine ASN.1/DER RFC 3161 TimeStampReq payloads and cryptographically verify
TimeStampResp tokens against a trusted TSA CA certificate bundle.

When no real production TSA URL / trusted CA bundle is configured, honestly reports `NOT_CONFIGURED`
and NEVER fabricates a verified timestamp.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
from typing import Any, Callable
import urllib.request

from .interfaces import TimestampAuthorityProvider
from .models import ProviderHealthStatus, TimestampTokenResult

SHA256_HEX_RE = re.compile(r"^[a-f0-9]{64}$")

TsaHttpTransportFn = Callable[[str, bytes, dict[str, str]], tuple[int, bytes]]


def _openssl_exe() -> str:
    exe = shutil.which("openssl")
    if not exe:
        raise RuntimeError("OpenSSL CLI bulunamadı; RFC 3161 zaman damgası işlemi çalıştırılamaz.")
    return exe


def _default_tsa_http_transport(tsa_url: str, tsq_der: bytes, headers: dict[str, str]) -> tuple[int, bytes]:
    req = urllib.request.Request(tsa_url, data=tsq_der, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310 - HTTPS enforced by caller
        return int(resp.status), resp.read()


def _parse_openssl_ts_reply_text(text: str) -> dict[str, str | None]:
    """Extract structured RFC 3161 TSTInfo fields from `openssl ts -reply -text` output."""
    gen_time: str | None = None
    serial_no: str | None = None
    policy_oid: str | None = None
    nonce_hex: str | None = None
    status_line: str | None = None

    m_status = re.search(r"Status:\s*(.+)", text)
    if m_status:
        status_line = m_status.group(1).strip()

    m_policy = re.search(r"Policy OID:\s*([0-9.]+)", text)
    if m_policy:
        policy_oid = m_policy.group(1).strip()

    m_serial = re.search(r"Serial number:\s*(0x[0-9A-Fa-f]+|\d+)", text)
    if m_serial:
        serial_no = m_serial.group(1).strip()

    m_nonce = re.search(r"Nonce:\s*(0x[0-9A-Fa-f]+)", text)
    if m_nonce:
        nonce_hex = m_nonce.group(1).strip().lower()

    m_time = re.search(r"Time stamp:\s*([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s+GMT)", text)
    if m_time:
        try:
            dt = datetime.strptime(m_time.group(1).strip(), "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
            gen_time = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            gen_time = m_time.group(1).strip()

    return {
        "status_line": status_line,
        "policy_oid": policy_oid,
        "serial_number": serial_no,
        "nonce_hex": nonce_hex,
        "gen_time_utc": gen_time,
    }


def _extract_tsa_signer_cert_info(tsr_der: bytes) -> tuple[str | None, str | None]:
    """Extract embedded TSA signer cert subject & SHA-256 fingerprint from TSR ASN.1 DER (metadata ONLY).

    Cryptographic timestamp verification remains 100% on OpenSSL 3 (`openssl ts -verify`).
    """
    from ..esign5070.x509_metadata import extract_leaf_cert_metadata_from_tsr_der

    return extract_leaf_cert_metadata_from_tsr_der(tsr_der)


class Rfc3161TimestampAuthorityAdapter(TimestampAuthorityProvider):
    """Independent RFC 3161 TSA client & cryptographic verifier backed by OpenSSL 3."""

    def __init__(
        self,
        *,
        tsa_url: str | None = None,
        trusted_ca_pem: str | None = None,
        policy_oid: str | None = None,
        http_transport: TsaHttpTransportFn | None = None,
        integration_mode: str | None = None,
    ) -> None:
        self._tsa_url = tsa_url.strip() if isinstance(tsa_url, str) and tsa_url.strip() else None
        self._trusted_ca_pem = trusted_ca_pem.strip() if isinstance(trusted_ca_pem, str) and trusted_ca_pem.strip() else None
        self._policy_oid = policy_oid.strip() if isinstance(policy_oid, str) and policy_oid.strip() else None
        self._http_transport = http_transport

        if integration_mode is not None:
            self._integration_mode = integration_mode.upper().strip()
        elif http_transport is not None and self._tsa_url and self._trusted_ca_pem:
            self._integration_mode = "MOCK_SANDBOX"
        elif self._tsa_url and self._trusted_ca_pem:
            self._integration_mode = "LIVE_PRODUCTION"
        else:
            self._integration_mode = "NOT_CONFIGURED"

    @property
    def provider_name(self) -> str:
        return "INDEPENDENT_RFC3161_TSA"

    @property
    def integration_mode(self) -> str:
        return self._integration_mode

    def health_check(self) -> ProviderHealthStatus:
        configured = bool(self._tsa_url and self._trusted_ca_pem)
        if not configured:
            return ProviderHealthStatus(
                provider_name=self.provider_name,
                provider_type="TimestampAuthorityProvider",
                backend="OPENSSL_RFC3161_TSA",
                integration_mode="NOT_CONFIGURED",
                configured=False,
                reachable=False,
                details={"tsa_url_configured": bool(self._tsa_url), "trusted_ca_configured": bool(self._trusted_ca_pem)},
                error_code="TSA_NOT_CONFIGURED",
                error_message="Bağımsız RFC 3161 TSA URL veya güvenilir TSA CA sertifika paketi yapılandırılmamıştır.",
            )
        return ProviderHealthStatus(
            provider_name=self.provider_name,
            provider_type="TimestampAuthorityProvider",
            backend="OPENSSL_RFC3161_TSA",
            integration_mode=self._integration_mode,
            configured=True,
            reachable=self._integration_mode == "MOCK_SANDBOX",
            details={
                "tsa_url": self._tsa_url,
                "policy_oid": self._policy_oid,
                "openssl_available": shutil.which("openssl") is not None,
            },
        )

    def build_timestamp_request(self, digest_sha256_hex: str, *, nonce_bytes: bytes | None = None) -> tuple[bytes, str]:
        digest_norm = str(digest_sha256_hex or "").strip().lower()
        if not SHA256_HEX_RE.match(digest_norm):
            raise ValueError(f"RFC 3161 TimeStampReq için geçerli 64 haneli SHA-256 hex özeti zorunludur: {digest_sha256_hex!r}")
        openssl = _openssl_exe()
        with tempfile.TemporaryDirectory(prefix="calisora_tsq_") as tmp:
            tsq_path = Path(tmp) / "req.tsq"
            cmd = [openssl, "ts", "-query", "-digest", digest_norm, "-sha256", "-cert", "-out", str(tsq_path)]
            if self._policy_oid:
                cmd.extend(["-tspolicy", self._policy_oid])
            proc = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if proc.returncode != 0:
                raise RuntimeError(f"RFC 3161 TimeStampReq üretilemedi: {proc.stderr.strip()}")
            tsq_bytes = tsq_path.read_bytes()
            p_txt = subprocess.run(
                [openssl, "ts", "-query", "-in", str(tsq_path), "-text"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            m_nonce = re.search(r"Nonce:\s*(0x[0-9A-Fa-f]+)", p_txt.stdout)
            nonce_hex = m_nonce.group(1).strip().lower() if m_nonce else (
                "0x" + (nonce_bytes.hex() if nonce_bytes else secrets.token_hex(8))
            )
            return tsq_bytes, nonce_hex

    def request_timestamp(self, digest_sha256_hex: str) -> TimestampTokenResult:
        digest_norm = str(digest_sha256_hex or "").strip().lower()
        if not SHA256_HEX_RE.match(digest_norm):
            return TimestampTokenResult(
                valid=False,
                status="TSA_FAILED",
                tsa_url=self._tsa_url,
                digest_algorithm="SHA-256",
                message_imprint_sha256=digest_norm,
                gen_time_utc=None,
                serial_number=None,
                policy_oid=self._policy_oid,
                nonce_hex=None,
                tsq_der_b64=None,
                tsr_der_b64=None,
                tsa_cert_subject=None,
                tsa_cert_fingerprint_sha256=None,
                provider_backend="OPENSSL_RFC3161_TSA",
                integration_mode=self._integration_mode,
                error_codes=("INVALID_TSA_DIGEST",),
                errors=("RFC 3161 zaman damgası için geçerli 64 haneli SHA-256 özeti gereklidir.",),
            )

        if not self._tsa_url or not self._trusted_ca_pem:
            return TimestampTokenResult(
                valid=False,
                status="NOT_CONFIGURED",
                tsa_url=self._tsa_url,
                digest_algorithm="SHA-256",
                message_imprint_sha256=digest_norm,
                gen_time_utc=None,
                serial_number=None,
                policy_oid=self._policy_oid,
                nonce_hex=None,
                tsq_der_b64=None,
                tsr_der_b64=None,
                tsa_cert_subject=None,
                tsa_cert_fingerprint_sha256=None,
                provider_backend="OPENSSL_RFC3161_TSA",
                integration_mode="NOT_CONFIGURED",
                error_codes=("TSA_NOT_CONFIGURED",),
                errors=("Bağımsız RFC 3161 TSA uç noktası veya güvenilir CA sertifika paketi yapılandırılmamıştır.",),
            )

        if self._integration_mode == "LIVE_PRODUCTION" and not self._tsa_url.lower().startswith("https://"):
            return TimestampTokenResult(
                valid=False,
                status="TSA_FAILED",
                tsa_url=self._tsa_url,
                digest_algorithm="SHA-256",
                message_imprint_sha256=digest_norm,
                gen_time_utc=None,
                serial_number=None,
                policy_oid=self._policy_oid,
                nonce_hex=None,
                tsq_der_b64=None,
                tsr_der_b64=None,
                tsa_cert_subject=None,
                tsa_cert_fingerprint_sha256=None,
                provider_backend="OPENSSL_RFC3161_TSA",
                integration_mode=self._integration_mode,
                error_codes=("TSA_HTTPS_REQUIRED",),
                errors=("Üretim RFC 3161 TSA uç noktası HTTPS olmalıdır.",),
            )

        tsq_der, nonce_hex = self.build_timestamp_request(digest_norm)
        headers = {
            "Content-Type": "application/timestamp-query",
            "Accept": "application/timestamp-reply",
        }
        transport = self._http_transport if self._http_transport is not None else _default_tsa_http_transport
        try:
            status_code, tsr_der = transport(self._tsa_url, tsq_der, headers)
        except Exception as exc:
            return TimestampTokenResult(
                valid=False,
                status="TSA_FAILED",
                tsa_url=self._tsa_url,
                digest_algorithm="SHA-256",
                message_imprint_sha256=digest_norm,
                gen_time_utc=None,
                serial_number=None,
                policy_oid=self._policy_oid,
                nonce_hex=nonce_hex,
                tsq_der_b64=base64.b64encode(tsq_der).decode("ascii"),
                tsr_der_b64=None,
                tsa_cert_subject=None,
                tsa_cert_fingerprint_sha256=None,
                provider_backend="OPENSSL_RFC3161_TSA",
                integration_mode=self._integration_mode,
                error_codes=("TSA_REQUEST_FAILED",),
                errors=(f"RFC 3161 TSA isteği başarısız oldu: {exc}",),
            )

        if status_code != 200 or not tsr_der:
            return TimestampTokenResult(
                valid=False,
                status="TSA_FAILED",
                tsa_url=self._tsa_url,
                digest_algorithm="SHA-256",
                message_imprint_sha256=digest_norm,
                gen_time_utc=None,
                serial_number=None,
                policy_oid=self._policy_oid,
                nonce_hex=nonce_hex,
                tsq_der_b64=base64.b64encode(tsq_der).decode("ascii"),
                tsr_der_b64=None,
                tsa_cert_subject=None,
                tsa_cert_fingerprint_sha256=None,
                provider_backend="OPENSSL_RFC3161_TSA",
                integration_mode=self._integration_mode,
                error_codes=("TSA_HTTP_ERROR",),
                errors=(f"RFC 3161 TSA sunucusu geçersiz HTTP yanıtı döndürdü: HTTP {status_code}.",),
            )

        verified = self.verify_timestamp_token(
            digest_norm,
            tsr_der,
            trusted_ca_pem=self._trusted_ca_pem,
            expected_nonce_hex=nonce_hex,
        )
        return TimestampTokenResult(
            valid=verified.valid,
            status=verified.status,
            tsa_url=self._tsa_url,
            digest_algorithm=verified.digest_algorithm,
            message_imprint_sha256=verified.message_imprint_sha256,
            gen_time_utc=verified.gen_time_utc,
            serial_number=verified.serial_number,
            policy_oid=verified.policy_oid,
            nonce_hex=verified.nonce_hex,
            tsq_der_b64=base64.b64encode(tsq_der).decode("ascii"),
            tsr_der_b64=verified.tsr_der_b64,
            tsa_cert_subject=verified.tsa_cert_subject,
            tsa_cert_fingerprint_sha256=verified.tsa_cert_fingerprint_sha256,
            provider_backend=verified.provider_backend,
            integration_mode=self._integration_mode,
            error_codes=verified.error_codes,
            errors=verified.errors,
        )

    def verify_timestamp_token(
        self,
        digest_sha256_hex: str,
        tsr_der_bytes: bytes,
        *,
        trusted_ca_pem: str | None = None,
        expected_nonce_hex: str | None = None,
    ) -> TimestampTokenResult:
        digest_norm = str(digest_sha256_hex or "").strip().lower()
        ca_pem = trusted_ca_pem if trusted_ca_pem is not None else self._trusted_ca_pem
        errors: list[str] = []
        error_codes: list[str] = []

        if not SHA256_HEX_RE.match(digest_norm):
            error_codes.append("INVALID_TSA_DIGEST")
            errors.append("Doğrulanacak SHA-256 özeti 64 haneli küçük harf hex olmalıdır.")
        if not tsr_der_bytes:
            error_codes.append("TSA_TOKEN_MISSING")
            errors.append("RFC 3161 TimeStampResp (DER) baytları eksiktir.")
        if not ca_pem or "BEGIN CERTIFICATE" not in ca_pem:
            error_codes.append("TSA_CA_NOT_CONFIGURED")
            errors.append("RFC 3161 TSA doğrulaması için güvenilir CA sertifika paketi (PEM) zorunludur.")

        if errors:
            return TimestampTokenResult(
                valid=False,
                status="NOT_CONFIGURED" if "TSA_CA_NOT_CONFIGURED" in error_codes else "TSA_FAILED",
                tsa_url=self._tsa_url,
                digest_algorithm="SHA-256",
                message_imprint_sha256=digest_norm,
                gen_time_utc=None,
                serial_number=None,
                policy_oid=self._policy_oid,
                nonce_hex=expected_nonce_hex,
                tsq_der_b64=None,
                tsr_der_b64=base64.b64encode(tsr_der_bytes).decode("ascii") if tsr_der_bytes else None,
                tsa_cert_subject=None,
                tsa_cert_fingerprint_sha256=None,
                provider_backend="OPENSSL_RFC3161_TSA",
                integration_mode=self._integration_mode,
                error_codes=tuple(sorted(set(error_codes))),
                errors=tuple(errors),
            )

        openssl = _openssl_exe()
        parsed_fields: dict[str, str | None] = {}
        cert_subj: str | None = None
        cert_fp: str | None = None

        with tempfile.TemporaryDirectory(prefix="calisora_ts_verify_") as tmp:
            tsr_path = Path(tmp) / "resp.tsr"
            ca_path = Path(tmp) / "ca.pem"
            tsr_path.write_bytes(tsr_der_bytes)
            ca_path.write_text(ca_pem.strip() + "\n", encoding="utf-8")

            p_ver = subprocess.run(
                [openssl, "ts", "-verify", "-digest", digest_norm, "-in", str(tsr_path), "-CAfile", str(ca_path)],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if p_ver.returncode != 0 or "Verification: OK" not in p_ver.stdout:
                error_codes.append("RFC3161_TIMESTAMP_VERIFICATION_FAILED")
                errors.append(
                    f"RFC 3161 zaman damgası kriptografik doğrulaması başarısız: "
                    f"{(p_ver.stderr or p_ver.stdout).strip()}"
                )

            p_txt = subprocess.run(
                [openssl, "ts", "-reply", "-in", str(tsr_path), "-text"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if p_txt.returncode == 0:
                parsed_fields = _parse_openssl_ts_reply_text(p_txt.stdout)
                if expected_nonce_hex and parsed_fields.get("nonce_hex"):
                    if parsed_fields["nonce_hex"].lower() != expected_nonce_hex.lower():
                        error_codes.append("RFC3161_NONCE_MISMATCH")
                        errors.append(
                            f"RFC 3161 zaman damgası nonce uyuşmazlığı: beklenen={expected_nonce_hex}, "
                            f"dönen={parsed_fields['nonce_hex']}."
                        )
            else:
                error_codes.append("RFC3161_MALFORMED_RESPONSE")
                errors.append(f"RFC 3161 yanıtı çözümlenemedi: {p_txt.stderr.strip()}")

        cert_subj, cert_fp = _extract_tsa_signer_cert_info(tsr_der_bytes)
        valid = len(errors) == 0 and len(error_codes) == 0
        return TimestampTokenResult(
            valid=valid,
            status="INDEPENDENT_TSA_VERIFIED" if valid else "TSA_FAILED",
            tsa_url=self._tsa_url,
            digest_algorithm="SHA-256",
            message_imprint_sha256=digest_norm,
            gen_time_utc=parsed_fields.get("gen_time_utc"),
            serial_number=parsed_fields.get("serial_number"),
            policy_oid=parsed_fields.get("policy_oid"),
            nonce_hex=parsed_fields.get("nonce_hex"),
            tsq_der_b64=None,
            tsr_der_b64=base64.b64encode(tsr_der_bytes).decode("ascii"),
            tsa_cert_subject=cert_subj,
            tsa_cert_fingerprint_sha256=cert_fp,
            provider_backend="OPENSSL_RFC3161_TSA",
            integration_mode=self._integration_mode,
            error_codes=tuple(sorted(set(error_codes))),
            errors=tuple(errors),
        )


class _EphemeralTsaPkiBank:
    """Thread-safe disjoint checkout pool of immutable ephemeral TSA Root CA + Signer cert/key bytes (test-only).

    Concurrently open `EphemeralSandboxTsaResponder` instances (e.g., `good_tsa` vs `rogue_tsa`) ALWAYS
    check out distinct slots with 100% cryptographically independent Root CAs and TSA signer keypairs.
    NEVER persisted to disk or used in production.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._slots: dict[int, dict[str, bytes]] = {}
        self._checked_out: set[int] = set()

    def acquire_slot(self) -> tuple[int, dict[str, bytes]]:
        with self._lock:
            slot = 0
            while slot in self._checked_out:
                slot += 1
            self._checked_out.add(slot)
            cached = self._slots.get(slot)
        if cached is not None:
            return slot, cached
        try:
            mat = self._generate_tsa_material()
        except Exception:
            self.release_slot(slot)
            raise
        with self._lock:
            self._slots[slot] = mat
        return slot, mat

    def release_slot(self, slot: int) -> None:
        with self._lock:
            self._checked_out.discard(slot)

    @staticmethod
    def _generate_tsa_material() -> dict[str, bytes]:
        openssl = _openssl_exe()
        with tempfile.TemporaryDirectory(prefix="calisora_tsa_tpl_") as tmp:
            root = Path(tmp)
            ca_key = root / "ca.key"
            ca_cert = root / "ca.pem"
            tsa_key = root / "tsa.key"
            tsa_csr = root / "tsa.csr"
            tsa_cert = root / "tsa.pem"
            tsa_ext = root / "tsa_ext.cnf"
            ca_req_cnf = root / "ca_req.cnf"
            ca_req_cnf.write_text(
                "[req]\n"
                "distinguished_name = dn\n"
                "x509_extensions = v3_ca\n"
                "prompt = no\n"
                "[dn]\n"
                "CN = CALISORA-MOCK-SANDBOX-TSA-CA\n"
                "O = CALISORA-TEST-ONLY\n"
                "[v3_ca]\n"
                "subjectKeyIdentifier = hash\n"
                "authorityKeyIdentifier = keyid:always,issuer\n"
                "basicConstraints = critical, CA:TRUE\n"
                "keyUsage = critical, keyCertSign, cRLSign\n",
                encoding="utf-8",
            )
            tsa_ext.write_text(
                "subjectKeyIdentifier = hash\n"
                "authorityKeyIdentifier = keyid,issuer\n"
                "basicConstraints = critical, CA:FALSE\n"
                "keyUsage = critical, digitalSignature\n"
                "extendedKeyUsage = critical, timeStamping\n",
                encoding="utf-8",
            )
            cmds = [
                [
                    openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-config", str(ca_req_cnf), "-extensions", "v3_ca",
                    "-keyout", str(ca_key), "-out", str(ca_cert), "-days", "30",
                ],
                [
                    openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(tsa_key), "-out", str(tsa_csr),
                    "-subj", "/CN=CALISORA-MOCK-SANDBOX-TSA-SIGNER/O=CALISORA-TEST-ONLY",
                ],
                [
                    openssl, "x509", "-req", "-in", str(tsa_csr),
                    "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
                    "-out", str(tsa_cert), "-days", "30", "-extfile", str(tsa_ext),
                ],
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
                    raise RuntimeError(f"Sandbox TSA kurulumu başarısız: {proc.stderr.strip()}")
            return {
                "ca_cert": ca_cert.read_bytes(),
                "tsa_key": tsa_key.read_bytes(),
                "tsa_cert": tsa_cert.read_bytes(),
            }


_EPHEMERAL_TSA_PKI_BANK = _EphemeralTsaPkiBank()


class EphemeralSandboxTsaResponder:
    """Ephemeral in-memory OpenSSL 3 RFC 3161 TSA responder strictly for isolated `MOCK_SANDBOX` tests.

    Checks out a cryptographically disjoint Root CA + Time-Stamping certificate
    (`extendedKeyUsage=critical,timeStamping`) inside an isolated per-instance temp directory and issues
    genuine ASN.1/DER `TimeStampResp` tokens. NEVER persisted to disk or used in production.
    """

    def __init__(self, *, policy_oid: str = "1.2.3.4.5.6.7.8.1") -> None:
        self.policy_oid = policy_oid
        self._tmpdir = tempfile.TemporaryDirectory(prefix="calisora_mock_tsa_")
        self._tsa_slot: int | None = None
        try:
            self._root = Path(self._tmpdir.name)
            self._openssl = _openssl_exe()
            self.ca_cert_pem = self._bootstrap_tsa_pki()
        except Exception:
            self.close()
            raise

    def _bootstrap_tsa_pki(self) -> str:
        ca_cert = self._root / "ca.pem"
        tsa_key = self._root / "tsa.key"
        tsa_cert = self._root / "tsa.pem"
        ts_cfg = self._root / "tsa.cnf"
        serial_file = self._root / "tsaserial"
        serial_file.write_text("01\n", encoding="utf-8")

        slot, mat = _EPHEMERAL_TSA_PKI_BANK.acquire_slot()
        self._tsa_slot = slot
        ca_cert.write_bytes(mat["ca_cert"])
        tsa_key.write_bytes(mat["tsa_key"])
        tsa_cert.write_bytes(mat["tsa_cert"])

        ts_cfg.write_text(
            "[tsa]\n"
            "default_tsa = tsa_section\n\n"
            "[tsa_section]\n"
            f"serial = {serial_file}\n"
            f"signer_cert = {tsa_cert}\n"
            f"signer_key = {tsa_key}\n"
            f"certs = {ca_cert}\n"
            "signer_digest = sha256\n"
            f"default_policy = {self.policy_oid}\n"
            "digests = sha256\n"
            "accuracy = secs:1\n"
            "ordering = no\n"
            "tsa_name = yes\n"
            "ess_cert_id_chain = no\n"
            "ess_cert_id_alg = sha256\n",
            encoding="utf-8",
        )
        return ca_cert.read_text(encoding="utf-8")

    def transport(self, _tsa_url: str, tsq_der: bytes, _headers: dict[str, str]) -> tuple[int, bytes]:
        tsq_path = self._root / f"q_{secrets.token_hex(6)}.tsq"
        tsr_path = self._root / f"r_{secrets.token_hex(6)}.tsr"
        tsq_path.write_bytes(tsq_der)
        proc = subprocess.run(
            [
                self._openssl, "ts", "-reply",
                "-config", str(self._root / "tsa.cnf"),
                "-queryfile", str(tsq_path),
                "-out", str(tsr_path),
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"Sandbox TSA yanıtı üretilemedi: {proc.stderr.strip()}")
        return 200, tsr_path.read_bytes()

    def close(self) -> None:
        if self._tsa_slot is not None:
            slot = self._tsa_slot
            self._tsa_slot = None
            _EPHEMERAL_TSA_PKI_BANK.release_slot(slot)
        self._tmpdir.cleanup()

    def __enter__(self) -> "EphemeralSandboxTsaResponder":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()
