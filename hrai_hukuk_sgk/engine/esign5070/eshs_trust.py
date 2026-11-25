"""BTK ESHS Authorization Registry & Separate ESHS X.509 CA Chain / Policy Provider for CALISORA @HukukSGK v1.0.4.5.

Strict Architectural Separation (ADR Section 3.1):
  - BTK official ESHS authorization/activity registry (`BtkEshsProviderRecord`) is stored and verified
    SEPARATELY from ESHS root/intermediate CA certificate chains and certificate policy inputs
    (`EshsCertificateChainBundle`). The BTK registry is NEVER conflated with a raw CA certificate store.
  - Read-only X.509 certificate metadata inspection (`x509_metadata.parse_x509_certificate_metadata`) parses
    genuine DER `QCStatements` (`1.3.6.1.5.5.7.1.3`), `QcCompliance` (`0.4.0.1862.1.1`), `QcSSCD`
    (`0.4.0.1862.1.4`), and `certificatePolicies` (`2.5.29.32`) OIDs with fingerprint-bound deduplication,
    NEVER making trust, chain, or signature decisions.
  - All X.509 CA chain verifications strictly execute OpenSSL 3 (`openssl verify -x509_strict -no-CApath
    -attime <validation_ts>`) so both live and historical archive validations verify exact certificate
    chain validity at the reference time.
  - Sandbox / test CAs (`trust_tier != "LIVE_BTK_ESHS"` or mock/sandbox subject markers) are explicitly
    tagged `is_sandbox_ca=True` and REJECTED in `PRODUCTION`.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any, Sequence

from ..attestation_verifier import canonical_json_bytes, parse_utc_timestamp
from .interfaces import EshsTrustListProvider
from .models import (
    OID_CERTIFICATE_POLICIES,
    OID_ETSI_QC_COMPLIANCE,
    OID_ETSI_QC_SSCD,
    OID_QC_STATEMENTS,
    VALID_PROBE_STATUSES,
    BtkEshsProviderRecord,
    EshsCertificateChainBundle,
    EshsTrustEvaluationResult,
    Esign5070ProbeStatus,
    SignerCertificateInspection,
)
from .x509_metadata import parse_x509_certificate_metadata

_SANDBOX_DN_MARKERS: tuple[str, ...] = (
    "MOCK",
    "SANDBOX",
    "TEST-ONLY",
    "TEST_ONLY",
    "DEV-ONLY",
    "LOCALHOST",
    "EPHEMERAL",
)

_OID_RE = re.compile(r"\b\d+(?:\.\d+){2,}\b")


def _openssl_exe() -> str:
    exe = shutil.which("openssl")
    if not exe:
        raise RuntimeError("OpenSSL CLI bulunamadı; 5070 X.509/ESHS doğrulaması çalıştırılamaz.")
    return exe


def compute_bundle_sha256(
    root_ca_pems: Sequence[str],
    intermediate_ca_pems: Sequence[str] = (),
    certificate_policy_oids: Sequence[str] = (),
) -> str:
    """Deterministically compute RFC 8785 (JCS) SHA-256 digest for an ESHS CA certificate chain bundle."""
    payload = {
        "root_ca_pems": [p.strip() for p in root_ca_pems if p and p.strip()],
        "intermediate_ca_pems": [p.strip() for p in intermediate_ca_pems if p and p.strip()],
        "certificate_policy_oids": sorted({str(o).strip() for o in certificate_policy_oids if str(o).strip()}),
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _parse_openssl_gmt_date(raw: str) -> str:
    cleaned = re.sub(r"\s+", " ", raw.strip())
    dt = datetime.strptime(cleaned, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _extract_dn_attr(rfc2253_dn: str, keys: tuple[str, ...]) -> str | None:
    """Extract an attribute value from an RFC 2253 DN string (e.g., `CN=...`, `serialNumber=...`, `C=...`)."""
    # Split on unescaped commas
    parts = re.split(r"(?<!\\),", rfc2253_dn)
    for part in parts:
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        if k.strip().lower() in {kk.lower() for kk in keys}:
            val = v.strip().replace(r"\,", ",")
            if val:
                return val
    return None


def _normalize_serial(raw_serial: str) -> str:
    cleaned = raw_serial.strip().replace(":", "").upper()
    if cleaned.startswith("0X"):
        cleaned = cleaned[2:]
    return cleaned.lstrip("0") or "0"


def inspect_signer_certificate_x509(
    cert_pem: str,
    *,
    validation_time_utc: str,
) -> SignerCertificateInspection:
    """Parse read-only X.509 certificate metadata directly from ASN.1 DER (no trust/signature verdict).

    All cryptographic CA chain verifications remain strictly on OpenSSL 3 (`openssl verify -x509_strict -attime`).
    """
    errors: list[str] = []
    error_codes: list[str] = []

    if not isinstance(cert_pem, str) or "-----BEGIN CERTIFICATE-----" not in cert_pem or "-----END CERTIFICATE-----" not in cert_pem:
        return SignerCertificateInspection(
            valid_x509=False,
            subject="",
            issuer="",
            serial_number="",
            not_before_utc="",
            not_after_utc="",
            cert_sha256="",
            signature_algorithm="",
            public_key_algorithm="",
            basic_constraints_ca=False,
            key_usage=(),
            qc_statements_present=False,
            qc_compliance=False,
            qc_sscd=False,
            certificate_policy_oids=(),
            signer_common_name=None,
            signer_serial_identifier=None,
            issuer_country=None,
            valid_at_validation_time=False,
            error_codes=("INVALID_SIGNER_CERTIFICATE_PEM",),
            errors=("İmzacı X.509 sertifikası geçerli PEM formatında değildir.",),
        )

    meta = parse_x509_certificate_metadata(cert_pem)
    if meta is None:
        return SignerCertificateInspection(
            valid_x509=False,
            subject="",
            issuer="",
            serial_number="",
            not_before_utc="",
            not_after_utc="",
            cert_sha256="",
            signature_algorithm="",
            public_key_algorithm="",
            basic_constraints_ca=False,
            key_usage=(),
            qc_statements_present=False,
            qc_compliance=False,
            qc_sscd=False,
            certificate_policy_oids=(),
            signer_common_name=None,
            signer_serial_identifier=None,
            issuer_country=None,
            valid_at_validation_time=False,
            error_codes=("X509_PARSE_FAILED",),
            errors=("X.509 sertifikası ASN.1 DER biçiminde ayrıştırılamadı.",),
        )

    valid_at_time = False
    try:
        val_dt = parse_utc_timestamp(validation_time_utc)
        nb_dt = parse_utc_timestamp(meta.not_before_utc)
        na_dt = parse_utc_timestamp(meta.not_after_utc)
        if val_dt < nb_dt:
            error_codes.append("SIGNER_CERTIFICATE_NOT_YET_VALID")
            errors.append(
                f"İmzacı sertifikası doğrulama zamanında ({validation_time_utc}) henüz geçerli değildir "
                f"(notBefore={meta.not_before_utc})."
            )
        elif val_dt > na_dt:
            error_codes.append("SIGNER_CERTIFICATE_EXPIRED")
            errors.append(
                f"İmzacı sertifikasının süresi doğrulama zamanı ({validation_time_utc}) itibarıyla dolmuştur "
                f"(notAfter={meta.not_after_utc})."
            )
        else:
            valid_at_time = True
    except Exception as exc:
        error_codes.append("INVALID_VALIDATION_TIMESTAMP")
        errors.append(f"Sertifika geçerlilik zamanı kontrol edilemedi: {exc}")

    if meta.basic_constraints_ca:
        error_codes.append("END_ENTITY_CERT_MUST_NOT_BE_CA")
        errors.append("İmzacı sertifikası bir CA sertifikası (CA:TRUE) olamaz.")

    return SignerCertificateInspection(
        valid_x509=True,
        subject=meta.subject,
        issuer=meta.issuer,
        serial_number=meta.serial_number,
        not_before_utc=meta.not_before_utc,
        not_after_utc=meta.not_after_utc,
        cert_sha256=meta.cert_sha256,
        signature_algorithm=meta.signature_algorithm,
        public_key_algorithm=meta.public_key_algorithm,
        basic_constraints_ca=meta.basic_constraints_ca,
        key_usage=meta.key_usage,
        qc_statements_present=meta.qc_statements_present,
        qc_compliance=meta.qc_compliance,
        qc_sscd=meta.qc_sscd,
        certificate_policy_oids=meta.certificate_policy_oids,
        signer_common_name=meta.signer_common_name,
        signer_serial_identifier=meta.signer_serial_identifier,
        issuer_country=meta.issuer_country,
        valid_at_validation_time=valid_at_time,
        error_codes=tuple(sorted(set(error_codes))),
        errors=tuple(errors),
    )


def _cert_has_sandbox_marker(cert_pem: str) -> bool:
    """Check if an X.509 certificate's subject/issuer carries sandbox/mock/test markers (read-only DER)."""
    meta = parse_x509_certificate_metadata(cert_pem)
    if meta is None:
        return False
    upper = (meta.subject + " " + meta.issuer).upper()
    return any(marker in upper for marker in _SANDBOX_DN_MARKERS)


class DefaultEshsTrustListProvider(EshsTrustListProvider):
    """Provider-agnostic ESHS trust list provider strictly separating BTK registry from ESHS CA bundles."""

    def __init__(
        self,
        *,
        btk_providers: Sequence[BtkEshsProviderRecord] | None = None,
        ca_bundles: Sequence[EshsCertificateChainBundle] | None = None,
        btk_registry_source_url: str | None = None,
        eshs_ca_bundle_source_ref: str | None = None,
        integration_mode: str | None = None,
        live_verified: bool = False,
        probe_status_override: str | None = None,
        probe_error_code: str | None = None,
        probe_error_message: str | None = None,
    ) -> None:
        self._btk_providers: dict[str, BtkEshsProviderRecord] = {
            rec.eshs_id: rec for rec in (btk_providers or ())
        }
        self._ca_bundles: dict[str, EshsCertificateChainBundle] = {
            b.eshs_id: b for b in (ca_bundles or ())
        }
        self._btk_registry_source_url = (
            btk_registry_source_url.strip()
            if isinstance(btk_registry_source_url, str) and btk_registry_source_url.strip()
            else None
        )
        self._eshs_ca_bundle_source_ref = (
            eshs_ca_bundle_source_ref.strip()
            if isinstance(eshs_ca_bundle_source_ref, str) and eshs_ca_bundle_source_ref.strip()
            else None
        )
        self._live_verified = bool(live_verified)
        self._probe_error_code = probe_error_code
        self._probe_error_message = probe_error_message

        if probe_status_override is not None:
            norm_override = str(probe_status_override).upper().strip()
            if norm_override not in VALID_PROBE_STATUSES:
                raise ValueError(f"Geçersiz probe_status_override: {probe_status_override!r}")
            self._probe_status_override: str | None = norm_override
        else:
            self._probe_status_override = None

        if integration_mode is not None:
            self._integration_mode = integration_mode.upper().strip()
        elif self._btk_providers or self._ca_bundles:
            has_sandbox = any(r.trust_source_mode != "LIVE_PRODUCTION" for r in self._btk_providers.values()) or any(
                b.trust_tier != "LIVE_BTK_ESHS" for b in self._ca_bundles.values()
            )
            self._integration_mode = "MOCK_SANDBOX" if has_sandbox else "LIVE_PRODUCTION"
        elif self._btk_registry_source_url and self._eshs_ca_bundle_source_ref:
            self._integration_mode = "LIVE_PRODUCTION"
        else:
            self._integration_mode = "NOT_CONFIGURED"

    @property
    def provider_name(self) -> str:
        return "BTK_ESHS_TRUST_LIST_AND_CA_PROVIDER"

    @property
    def integration_mode(self) -> str:
        return self._integration_mode

    def probe_status(self) -> Esign5070ProbeStatus:
        configured = bool(
            (self._btk_providers and self._ca_bundles)
            or (self._btk_registry_source_url and self._eshs_ca_bundle_source_ref)
        )
        if self._probe_status_override is not None:
            st = self._probe_status_override
        elif not configured or self._integration_mode == "NOT_CONFIGURED":
            st = "NOT_CONFIGURED"
        elif self._integration_mode == "LIVE_PRODUCTION" and self._live_verified:
            st = "LIVE_VERIFIED"
        else:
            st = "CONFIGURED_UNVERIFIED"

        return Esign5070ProbeStatus(
            service_name="btk_eshs_trust_list",
            provider_type="EshsTrustListProvider",
            probe_status=st,
            integration_mode=self._integration_mode,
            configured=configured,
            reachable=st == "LIVE_VERIFIED",
            details={
                "btk_registry_source_url": self._btk_registry_source_url,
                "eshs_ca_bundle_source_ref": self._eshs_ca_bundle_source_ref,
                "btk_provider_count": len(self._btk_providers),
                "eshs_ca_bundle_count": len(self._ca_bundles),
                "registry_and_ca_bundle_separated": True,
            },
            error_code=self._probe_error_code or (None if st == "LIVE_VERIFIED" else "BTK_ESHS_TRUST_LIST_NOT_LIVE_VERIFIED"),
            error_message=self._probe_error_message
            or (
                None
                if st == "LIVE_VERIFIED"
                else "BTK yetkili ESHS listesi ve ayrı ESHS kök/ara CA sertifika paketi canlı üretim doğrulamasına bağlı değildir."
            ),
        )

    def lookup_btk_eshs_provider(self, eshs_id_or_issuer: str) -> BtkEshsProviderRecord | None:
        key = str(eshs_id_or_issuer or "").strip()
        if not key:
            return None
        if key in self._btk_providers:
            return self._btk_providers[key]
        key_lower = key.lower()
        for rec in self._btk_providers.values():
            if rec.provider_name.lower() in key_lower or rec.eshs_id.lower() in key_lower:
                return rec
        return None

    def get_eshs_certificate_chain_bundle(self, eshs_id: str) -> EshsCertificateChainBundle | None:
        return self._ca_bundles.get(str(eshs_id or "").strip())

    def _verify_chain_with_openssl(
        self,
        signer_cert_pem: str,
        bundle: EshsCertificateChainBundle,
        validation_time_utc: str,
    ) -> tuple[bool, str | None, str | None]:
        """Verify X.509 chain strictly via `openssl verify -x509_strict -no-CApath -attime`."""
        openssl = _openssl_exe()
        val_dt = parse_utc_timestamp(validation_time_utc)
        attime_ts = str(int(val_dt.timestamp()))

        with tempfile.TemporaryDirectory(prefix="calisora_eshs_chain_") as tmp:
            roots_path = Path(tmp) / "roots.pem"
            signer_path = Path(tmp) / "signer.pem"
            roots_path.write_text("\n".join(p.strip() for p in bundle.root_ca_pems) + "\n", encoding="utf-8")
            signer_path.write_text(signer_cert_pem.strip() + "\n", encoding="utf-8")

            cmd = [
                openssl,
                "verify",
                "-x509_strict",
                "-no-CApath",
                "-attime",
                attime_ts,
                "-CAfile",
                str(roots_path),
            ]
            if bundle.intermediate_ca_pems:
                inter_path = Path(tmp) / "intermediates.pem"
                inter_path.write_text(
                    "\n".join(p.strip() for p in bundle.intermediate_ca_pems) + "\n",
                    encoding="utf-8",
                )
                cmd.extend(["-untrusted", str(inter_path)])
            cmd.append(str(signer_path))

            proc = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if proc.returncode == 0 and ": OK" in proc.stdout:
                issuer_pem = (
                    bundle.intermediate_ca_pems[-1]
                    if bundle.intermediate_ca_pems
                    else (bundle.root_ca_pems[0] if bundle.root_ca_pems else None)
                )
                return True, issuer_pem, None
            detail = (proc.stderr or proc.stdout).strip()
            return False, None, detail

    def evaluate_signer_trust(
        self,
        signer_cert_pem: str,
        *,
        validation_time_utc: str,
        expected_eshs_id: str | None = None,
        runtime_environment: str = "PRODUCTION",
    ) -> EshsTrustEvaluationResult:
        env_norm = str(runtime_environment or "PRODUCTION").upper().strip()
        errors: list[str] = []
        error_codes: list[str] = []

        if self._integration_mode == "NOT_CONFIGURED" or (not self._btk_providers and not self._ca_bundles):
            return EshsTrustEvaluationResult(
                valid=False,
                conclusion="INDETERMINATE",
                eshs_id=expected_eshs_id,
                btk_provider_authorized=False,
                btk_authorization_status=None,
                btk_list_version=None,
                ca_chain_verified=False,
                policy_evaluated=False,
                policy_matched=False,
                matched_policy_oids=(),
                is_sandbox_ca=False,
                bundle_sha256=None,
                issuer_ca_pem=None,
                provider_backend=self.provider_name,
                integration_mode="NOT_CONFIGURED",
                error_codes=("BTK_ESHS_TRUST_LIST_NOT_CONFIGURED",),
                errors=("BTK yetkili ESHS listesi ve ayrı ESHS CA sertifika zinciri yapılandırılmamıştır.",),
            )

        cert_info = inspect_signer_certificate_x509(signer_cert_pem, validation_time_utc=validation_time_utc)
        if not cert_info.valid_x509:
            return EshsTrustEvaluationResult(
                valid=False,
                conclusion="FAILED",
                eshs_id=expected_eshs_id,
                btk_provider_authorized=False,
                btk_authorization_status=None,
                btk_list_version=None,
                ca_chain_verified=False,
                policy_evaluated=False,
                policy_matched=False,
                matched_policy_oids=(),
                is_sandbox_ca=False,
                bundle_sha256=None,
                issuer_ca_pem=None,
                provider_backend=self.provider_name,
                integration_mode=self._integration_mode,
                error_codes=cert_info.error_codes,
                errors=cert_info.errors,
            )

        # Resolve target ESHS record (from expected_eshs_id or issuer DN match)
        resolved_eshs_id = expected_eshs_id.strip() if isinstance(expected_eshs_id, str) and expected_eshs_id.strip() else None
        btk_rec = self.lookup_btk_eshs_provider(resolved_eshs_id or cert_info.issuer)
        if resolved_eshs_id is None and btk_rec is not None:
            resolved_eshs_id = btk_rec.eshs_id

        # If still unresolved, attempt matching CA bundle directly to detect missing BTK authorization
        ca_bundle: EshsCertificateChainBundle | None = (
            self.get_eshs_certificate_chain_bundle(resolved_eshs_id) if resolved_eshs_id else None
        )
        if ca_bundle is None and resolved_eshs_id is None:
            for cand_id, cand_bundle in self._ca_bundles.items():
                ok_chain, _, _ = self._verify_chain_with_openssl(signer_cert_pem, cand_bundle, validation_time_utc)
                if ok_chain:
                    resolved_eshs_id = cand_id
                    ca_bundle = cand_bundle
                    btk_rec = self.lookup_btk_eshs_provider(cand_id)
                    break

        # 1. BTK ESHS authorization/activity check (SEPARATE from CA bundle!)
        btk_authorized = False
        btk_status: str | None = None
        btk_version: str | None = None
        is_sandbox = False

        if btk_rec is None:
            error_codes.append("BTK_ESHS_PROVIDER_NOT_FOUND")
            errors.append(
                f"İmzacı sertifikasının ESHS sağlayıcısı ('{resolved_eshs_id or cert_info.issuer}') "
                f"BTK yetkili ESHS listesinde bulunamadı."
            )
        else:
            btk_status = btk_rec.authorization_status.upper().strip()
            btk_version = btk_rec.btk_list_version
            if btk_rec.trust_source_mode.upper().strip() != "LIVE_PRODUCTION":
                is_sandbox = True

            if btk_status != "ACTIVE":
                error_codes.append("BTK_ESHS_PROVIDER_NOT_ACTIVE")
                errors.append(
                    f"ESHS sağlayıcısı '{btk_rec.eshs_id}' BTK listesinde aktif değildir (durum: '{btk_status}')."
                )
            else:
                try:
                    val_dt = parse_utc_timestamp(validation_time_utc)
                    af_dt = parse_utc_timestamp(btk_rec.authorized_from_utc)
                    au_dt = parse_utc_timestamp(btk_rec.authorized_until_utc)
                    if val_dt < af_dt or val_dt > au_dt:
                        error_codes.append("BTK_ESHS_AUTHORIZATION_EXPIRED_OR_NOT_ACTIVE_AT_TIME")
                        errors.append(
                            f"ESHS sağlayıcısı '{btk_rec.eshs_id}' doğrulama zamanında ({validation_time_utc}) "
                            f"BTK yetki aralığı ({btk_rec.authorized_from_utc}..{btk_rec.authorized_until_utc}) dışındadır."
                        )
                    else:
                        btk_authorized = True
                except Exception as exc:
                    error_codes.append("BTK_ESHS_AUTHORIZATION_WINDOW_INVALID")
                    errors.append(f"BTK ESHS yetki tarih aralığı doğrulanamadı: {exc}")

        # 2. Separate ESHS CA root/intermediate certificate chain verification
        ca_chain_verified = False
        issuer_ca_pem: str | None = None
        bundle_sha: str | None = None

        if ca_bundle is None:
            error_codes.append("ESHS_CA_BUNDLE_MISSING")
            errors.append(
                f"ESHS '{resolved_eshs_id or cert_info.issuer}' için ayrı kök/ara CA sertifika zinciri paketi bulunamadı."
            )
        else:
            bundle_sha = ca_bundle.bundle_sha256 or compute_bundle_sha256(
                ca_bundle.root_ca_pems,
                ca_bundle.intermediate_ca_pems,
                ca_bundle.certificate_policy_oids,
            )
            if ca_bundle.trust_tier.upper().strip() != "LIVE_BTK_ESHS":
                is_sandbox = True
            for ca_pem in (*ca_bundle.root_ca_pems, *ca_bundle.intermediate_ca_pems):
                if _cert_has_sandbox_marker(ca_pem):
                    is_sandbox = True
                    break

            if ca_bundle.valid_from_utc and ca_bundle.valid_until_utc:
                try:
                    val_dt = parse_utc_timestamp(validation_time_utc)
                    bf_dt = parse_utc_timestamp(ca_bundle.valid_from_utc)
                    bu_dt = parse_utc_timestamp(ca_bundle.valid_until_utc)
                    if val_dt < bf_dt or val_dt > bu_dt:
                        error_codes.append("ESHS_CA_BUNDLE_OUTSIDE_VALIDITY_WINDOW")
                        errors.append(
                            f"ESHS CA sertifika paketi '{ca_bundle.bundle_id}' doğrulama zamanı ({validation_time_utc}) "
                            f"için geçerli değildir."
                        )
                except Exception as exc:
                    error_codes.append("ESHS_CA_BUNDLE_WINDOW_INVALID")
                    errors.append(f"ESHS CA paketi tarih aralığı çözümlenemedi: {exc}")

            ok_chain, matched_issuer, chain_err = self._verify_chain_with_openssl(
                signer_cert_pem, ca_bundle, validation_time_utc
            )
            ca_chain_verified = ok_chain
            issuer_ca_pem = matched_issuer
            if not ok_chain:
                error_codes.append("ESHS_X509_CHAIN_VERIFICATION_FAILED")
                errors.append(f"ESHS X.509 sertifika zinciri doğrulaması başarısız: {chain_err}")

        # 3. Sandbox CA rejection in PRODUCTION
        if is_sandbox and env_norm == "PRODUCTION":
            error_codes.append("SANDBOX_ESHS_CA_REJECTED_IN_PRODUCTION")
            errors.append(
                "Test/sandbox ESHS CA veya sahte BTK güven listesi PRODUCTION ortamında kesinlikle reddedilir."
            )

        # 4. Certificate policy evaluation (evaluated in context of BTK + ESHS CA bundle + signer cert)
        permitted_oids: set[str] = set()
        if btk_rec is not None:
            permitted_oids.update(o.strip() for o in btk_rec.permitted_policy_oids if str(o).strip())
        if ca_bundle is not None:
            permitted_oids.update(o.strip() for o in ca_bundle.certificate_policy_oids if str(o).strip())

        cert_oids = set(cert_info.certificate_policy_oids)
        policy_evaluated = bool(permitted_oids or cert_oids)
        matched_oids = tuple(sorted(cert_oids & permitted_oids))

        if permitted_oids:
            policy_matched = len(matched_oids) > 0
            if not policy_matched:
                error_codes.append("CERTIFICATE_POLICY_OID_MISMATCH")
                errors.append(
                    f"İmzacı sertifikası politika OID'leri ({sorted(cert_oids)}) yetkili ESHS sertifika "
                    f"politikaları ({sorted(permitted_oids)}) ile eşleşmiyor."
                )
        else:
            policy_matched = False

        valid = bool(
            btk_authorized
            and ca_chain_verified
            and policy_matched
            and len(error_codes) == 0
        )

        if valid:
            conclusion = "PASSED"
        elif any(
            c in error_codes
            for c in (
                "BTK_ESHS_TRUST_LIST_NOT_CONFIGURED",
                "ESHS_CA_BUNDLE_MISSING",
            )
        ) and not any(
            c in error_codes
            for c in (
                "BTK_ESHS_PROVIDER_NOT_FOUND",
                "BTK_ESHS_PROVIDER_NOT_ACTIVE",
                "BTK_ESHS_AUTHORIZATION_EXPIRED_OR_NOT_ACTIVE_AT_TIME",
                "ESHS_X509_CHAIN_VERIFICATION_FAILED",
                "SANDBOX_ESHS_CA_REJECTED_IN_PRODUCTION",
                "CERTIFICATE_POLICY_OID_MISMATCH",
            )
        ):
            conclusion = "INDETERMINATE"
        else:
            conclusion = "FAILED"

        return EshsTrustEvaluationResult(
            valid=valid,
            conclusion=conclusion,
            eshs_id=resolved_eshs_id,
            btk_provider_authorized=btk_authorized,
            btk_authorization_status=btk_status,
            btk_list_version=btk_version,
            ca_chain_verified=ca_chain_verified,
            policy_evaluated=policy_evaluated,
            policy_matched=policy_matched,
            matched_policy_oids=matched_oids,
            is_sandbox_ca=is_sandbox,
            bundle_sha256=bundle_sha,
            issuer_ca_pem=issuer_ca_pem,
            provider_backend=self.provider_name,
            integration_mode=self._integration_mode,
            error_codes=tuple(sorted(set(error_codes))),
            errors=tuple(errors),
        )
