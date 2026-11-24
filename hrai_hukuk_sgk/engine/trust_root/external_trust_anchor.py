"""External Trust Anchor Provider (Separate Security Project, Read-Only, KMS-Signed, WORM-Backed, Audit-Logged) for CALISORA @HukukSGK v1.0.3.

Enforces Section 4 of the v1.0.3 Architectural Decision Record:
  - Checkpoint anchor expectations (`expected_checkpoint_head_hash`, `expected_checkpoint_entry_count`,
    `expected_chain_digest_sha256`) MUST NEVER be read from in-app mutable JSON files.
  - The external trust anchor MUST be:
      1. Read-only (`read_only == True`),
      2. Hosted in a security GCP project strictly separate from the application project
         (`security_project_id != app_project_id`),
      3. Asymmetrically signed by KMS/HSM (`kms_signed == True`, `protection_level == "HSM"` in PRODUCTION),
      4. Stored in immutable WORM storage (`worm_immutable_verified == True`),
      5. Backed by an independent audit log reference (`independent_audit_log_ref`).
  - Fail-closed: if the external trust root cannot be fetched or fails ANY verification check, production
    verification MUST fail (`EXTERNAL_TRUST_ANCHOR_UNAVAILABLE_OR_INVALID`).
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any

from ..attestation_verifier import canonical_json_bytes
from .interfaces import (
    ExternalTrustAnchorProvider,
    ImmutableEvidenceStorageProvider,
    KeySignerProvider,
    TimestampAuthorityProvider,
)
from .models import (
    DEFAULT_GCP_REGION,
    TRUST_ROOT_VERSION,
    ExternalTrustAnchorRecord,
    ProviderHealthStatus,
)

SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
REMOTE_WORM_URI_RE = re.compile(r"^(gs|s3|https)://.+$", re.IGNORECASE)


def build_trust_anchor_manifest_signing_payload(manifest: dict[str, Any]) -> dict[str, Any]:
    """Build the exact RFC 8785 (JCS) canonical signing payload for an external trust anchor manifest."""
    return {
        "schema": "CALISORA_EXTERNAL_TRUST_ANCHOR_MANIFEST_V1",
        "schema_version": str(manifest.get("schema_version") or TRUST_ROOT_VERSION),
        "manifest_id": str(manifest.get("manifest_id") or ""),
        "security_project_id": str(manifest.get("security_project_id") or ""),
        "app_project_id": str(manifest.get("app_project_id") or ""),
        "region": str(manifest.get("region") or DEFAULT_GCP_REGION),
        "ledger_id": str(manifest.get("ledger_id") or ""),
        "expected_checkpoint_head_hash": str(manifest.get("expected_checkpoint_head_hash") or "").lower(),
        "expected_checkpoint_entry_count": manifest.get("expected_checkpoint_entry_count"),
        "expected_chain_digest_sha256": str(manifest.get("expected_chain_digest_sha256") or "").lower(),
        "read_only": bool(manifest.get("read_only", False)),
        "worm_bucket_uri": str(manifest.get("worm_bucket_uri") or ""),
        "independent_audit_log_ref": str(manifest.get("independent_audit_log_ref") or ""),
        "sealed_at_utc": str(manifest.get("sealed_at_utc") or ""),
        "nonce": str(manifest.get("nonce") or ""),
    }


def build_and_seal_external_trust_anchor_manifest(
    *,
    manifest_id: str,
    security_project_id: str,
    app_project_id: str,
    ledger_id: str,
    expected_checkpoint_head_hash: str,
    expected_checkpoint_entry_count: int,
    expected_chain_digest_sha256: str,
    independent_audit_log_ref: str,
    object_name: str,
    nonce: str,
    signer: KeySignerProvider,
    signing_key_ref: str,
    worm_storage: ImmutableEvidenceStorageProvider,
    tsa_provider: TimestampAuthorityProvider | None = None,
    algorithm: str = "ED25519",
    region: str = DEFAULT_GCP_REGION,
    runtime_environment: str = "PRODUCTION",
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Construct, KMS/HSM-sign, optionally RFC 3161 timestamp, and store an external trust anchor manifest in WORM storage."""
    if security_project_id.strip() == app_project_id.strip():
        raise ValueError(
            "TRUST_ANCHOR_SAME_PROJECT_VIOLATION: Güvenlik projesi (security_project_id) uygulama projesi "
            "(app_project_id) ile aynı olamaz."
        )
    if not SHA256_RE.match(expected_checkpoint_head_hash.strip().lower()):
        raise ValueError("expected_checkpoint_head_hash geçerli 64 haneli SHA-256 özeti olmalıdır.")
    if not SHA256_RE.match(expected_chain_digest_sha256.strip().lower()):
        raise ValueError("expected_chain_digest_sha256 geçerli 64 haneli SHA-256 özeti olmalıdır.")
    if not isinstance(expected_checkpoint_entry_count, int) or isinstance(expected_checkpoint_entry_count, bool) or expected_checkpoint_entry_count < 1:
        raise ValueError("expected_checkpoint_entry_count pozitif tamsayı olmalıdır.")

    bucket_hint = getattr(worm_storage, "bucket_name", None) or "unconfigured-bucket"
    manifest: dict[str, Any] = {
        "schema_version": TRUST_ROOT_VERSION,
        "manifest_id": manifest_id,
        "security_project_id": security_project_id.strip(),
        "app_project_id": app_project_id.strip(),
        "region": region.strip(),
        "ledger_id": ledger_id.strip(),
        "expected_checkpoint_head_hash": expected_checkpoint_head_hash.strip().lower(),
        "expected_checkpoint_entry_count": expected_checkpoint_entry_count,
        "expected_chain_digest_sha256": expected_chain_digest_sha256.strip().lower(),
        "read_only": True,
        "worm_bucket_uri": f"gs://{bucket_hint}/{object_name.lstrip('/')}",
        "independent_audit_log_ref": independent_audit_log_ref.strip(),
        "sealed_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nonce": nonce.strip(),
    }

    signing_payload = build_trust_anchor_manifest_signing_payload(manifest)
    sig_env = signer.sign_canonical_json(
        signing_payload,
        signing_key_ref,
        algorithm=algorithm,
        runtime_environment=runtime_environment,
    )
    if not sig_env.valid or not sig_env.signature_b64:
        raise RuntimeError(f"Harici güven çapası manifesti KMS/HSM ile imzalanamadı: {sig_env.errors}")

    manifest["kms_signature"] = sig_env.to_dict()
    manifest_digest = hashlib.sha256(canonical_json_bytes(signing_payload)).hexdigest()

    tsa_dict: dict[str, Any] | None = None
    if tsa_provider is not None:
        tsa_res = tsa_provider.request_timestamp(manifest_digest)
        tsa_dict = tsa_res.to_dict()
    manifest["tsa_proof"] = tsa_dict

    manifest_bytes = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
    receipt = worm_storage.put_immutable_object(
        object_name,
        manifest_bytes,
        content_type="application/json",
        metadata={
            "manifest_id": manifest_id,
            "security_project_id": security_project_id.strip(),
            "ledger_id": ledger_id.strip(),
            "read_only": "true",
        },
    )
    if not receipt.stored:
        raise RuntimeError(f"Harici güven çapası manifesti WORM depoya yazılamadı: {receipt.errors}")

    return manifest, receipt.to_dict()


class GcpExternalTrustAnchorProvider(ExternalTrustAnchorProvider):
    """Out-of-band external trust anchor reader & verifier backed by separate security project WORM + KMS HSM."""

    def __init__(
        self,
        *,
        manifest_uri: str | None = None,
        security_project_id: str | None = None,
        app_project_id: str | None = None,
        worm_storage: ImmutableEvidenceStorageProvider | None = None,
        kms_signer: KeySignerProvider | None = None,
        tsa_provider: TimestampAuthorityProvider | None = None,
        require_tsa: bool = True,
    ) -> None:
        self.manifest_uri = manifest_uri.strip() if isinstance(manifest_uri, str) and manifest_uri.strip() else None
        self.security_project_id = (
            security_project_id.strip() if isinstance(security_project_id, str) and security_project_id.strip() else None
        )
        self.app_project_id = (
            app_project_id.strip() if isinstance(app_project_id, str) and app_project_id.strip() else None
        )
        self.worm_storage = worm_storage
        self.kms_signer = kms_signer
        self.tsa_provider = tsa_provider
        self.require_tsa = require_tsa

        modes = [
            p.integration_mode
            for p in (worm_storage, kms_signer)
            if p is not None
        ]
        if not self.manifest_uri or worm_storage is None or kms_signer is None or "NOT_CONFIGURED" in modes:
            self._integration_mode = "NOT_CONFIGURED"
        elif "MOCK_SANDBOX" in modes:
            self._integration_mode = "MOCK_SANDBOX"
        else:
            self._integration_mode = "LIVE_PRODUCTION"

    @property
    def provider_name(self) -> str:
        return "GCP_SEPARATE_PROJECT_WORM_KMS_TRUST_ANCHOR"

    @property
    def integration_mode(self) -> str:
        return self._integration_mode

    def health_check(self) -> ProviderHealthStatus:
        if self._integration_mode == "NOT_CONFIGURED":
            return ProviderHealthStatus(
                provider_name=self.provider_name,
                provider_type="ExternalTrustAnchorProvider",
                backend="GCP_WORM_KMS_MANIFEST",
                integration_mode="NOT_CONFIGURED",
                configured=False,
                reachable=False,
                region=DEFAULT_GCP_REGION,
                details={
                    "manifest_uri_configured": bool(self.manifest_uri),
                    "security_project_configured": bool(self.security_project_id),
                    "worm_storage_mode": self.worm_storage.integration_mode if self.worm_storage else "NOT_CONFIGURED",
                    "kms_signer_mode": self.kms_signer.integration_mode if self.kms_signer else "NOT_CONFIGURED",
                },
                error_code="EXTERNAL_TRUST_ANCHOR_UNAVAILABLE_OR_INVALID",
                error_message="Ayrı güvenlik projesindeki KMS imzalı WORM harici güven kökü yapılandırılmamıştır.",
            )
        return ProviderHealthStatus(
            provider_name=self.provider_name,
            provider_type="ExternalTrustAnchorProvider",
            backend="GCP_WORM_KMS_MANIFEST",
            integration_mode=self._integration_mode,
            configured=True,
            reachable=self._integration_mode == "MOCK_SANDBOX",
            region=DEFAULT_GCP_REGION,
            details={
                "manifest_uri": self.manifest_uri,
                "security_project_id": self.security_project_id,
                "app_project_id": self.app_project_id,
                "separate_projects": bool(
                    self.security_project_id
                    and self.app_project_id
                    and self.security_project_id != self.app_project_id
                ),
            },
        )

    def _fail(
        self,
        codes: list[str],
        errors: list[str],
        *,
        manifest_id: str | None = None,
        sec_proj: str | None = None,
        app_proj: str | None = None,
        ledger_id: str | None = None,
        read_only: bool = False,
        sep_proj: bool = False,
        kms_signed: bool = False,
        kms_prot: str | None = None,
        worm_ok: bool = False,
        audit_ok: bool = False,
        audit_ref: str | None = None,
        tsa_ok: bool = False,
    ) -> ExternalTrustAnchorRecord:
        all_codes = sorted(set([*codes, "EXTERNAL_TRUST_ANCHOR_UNAVAILABLE_OR_INVALID"]))
        return ExternalTrustAnchorRecord(
            valid=False,
            manifest_id=manifest_id,
            security_project_id=sec_proj,
            app_project_id=app_proj,
            ledger_id=ledger_id,
            expected_checkpoint_head_hash=None,
            expected_checkpoint_entry_count=None,
            expected_chain_digest_sha256=None,
            read_only=read_only,
            separate_security_project=sep_proj,
            kms_signed=kms_signed,
            kms_protection_level=kms_prot,
            worm_protected=worm_ok,
            independent_audit_logged=audit_ok,
            independent_audit_log_ref=audit_ref,
            manifest_uri=self.manifest_uri,
            tsa_verified=tsa_ok,
            trust_anchor_source="INDEPENDENT_WORM_STORE",
            provider_backend=self.provider_name,
            integration_mode=self._integration_mode,
            error_codes=tuple(all_codes),
            errors=tuple(errors),
        )

    def fetch_and_verify_trust_anchor(
        self,
        ledger_id: str,
        *,
        expected_app_project_id: str | None = None,
        runtime_environment: str = "PRODUCTION",
    ) -> ExternalTrustAnchorRecord:
        errors: list[str] = []
        error_codes: list[str] = []

        # Rule 1: Reject local/in-app JSON paths immediately!
        if not self.manifest_uri:
            return self._fail(
                ["EXTERNAL_TRUST_ANCHOR_NOT_CONFIGURED"],
                ["Harici güven kökü manifest URI'si tanımlı değildir; üretim doğrulaması başarısız (fail-closed)."],
            )
        if not REMOTE_WORM_URI_RE.match(self.manifest_uri) or self.manifest_uri.lower().startswith("file://"):
            return self._fail(
                ["TRUST_ANCHOR_IN_APP_JSON_FORBIDDEN"],
                [
                    f"Harici güven çapası uygulama içi yerel JSON/dosya yolundan okunamaz: '{self.manifest_uri}'. "
                    f"Yalnızca ayrı güvenlik projesindeki uzak WORM URI (ör. gs://...) kabul edilir."
                ],
            )

        if self.worm_storage is None or self.kms_signer is None or self._integration_mode == "NOT_CONFIGURED":
            return self._fail(
                ["EXTERNAL_TRUST_ANCHOR_NOT_CONFIGURED"],
                ["WORM saklama veya KMS/HSM sağlayıcısı yapılandırılmadığı için harici güven kökü alınamadı."],
            )

        raw_bytes, receipt, fetch_err = self.worm_storage.get_object_bytes(self.manifest_uri)
        if fetch_err or raw_bytes is None or receipt is None:
            return self._fail(
                ["TRUST_ANCHOR_FETCH_FAILED"],
                [f"Harici güven kökü manifesti WORM depodan okunamadı: {fetch_err or 'boş içerik'}."],
            )

        worm_ok = bool(receipt.worm_immutable_verified)
        if not worm_ok:
            error_codes.append("TRUST_ANCHOR_NOT_WORM_PROTECTED")
            errors.append(
                f"Harici güven kökü manifesti aktif Bucket Lock / WORM koruması altında değildir: {list(receipt.errors)}."
            )

        try:
            manifest = json.loads(raw_bytes.decode("utf-8"))
        except Exception as exc:
            return self._fail(
                ["TRUST_ANCHOR_MALFORMED_JSON"],
                [f"Harici güven kökü manifesti geçerli JSON değildir: {exc}"],
                worm_ok=worm_ok,
            )

        if not isinstance(manifest, dict):
            return self._fail(
                ["TRUST_ANCHOR_MALFORMED_JSON"],
                ["Harici güven kökü manifesti JSON nesnesi olmalıdır."],
                worm_ok=worm_ok,
            )

        manifest_id = str(manifest.get("manifest_id") or "")
        sec_proj = str(manifest.get("security_project_id") or "").strip()
        app_proj = str(manifest.get("app_project_id") or "").strip()
        man_ledger = str(manifest.get("ledger_id") or "").strip()
        eff_app_proj = (expected_app_project_id or self.app_project_id or "").strip()

        # Rule 2: Separate security project enforcement
        sep_proj = bool(sec_proj and app_proj and sec_proj != app_proj)
        if not sep_proj:
            error_codes.append("TRUST_ANCHOR_SAME_PROJECT_VIOLATION")
            errors.append(
                f"Harici güven kökü uygulama projesinden ayrı bir güvenlik projesinde tutulmalıdır "
                f"(security_project_id='{sec_proj}', app_project_id='{app_proj}')."
            )
        if self.security_project_id and sec_proj != self.security_project_id:
            error_codes.append("TRUST_ANCHOR_PROJECT_MISMATCH")
            errors.append(
                f"Manifest güvenlik projesi ('{sec_proj}') yapılandırılan güvenlik projesi ('{self.security_project_id}') ile uyuşmuyor."
            )
        if receipt.project_id and sec_proj and receipt.project_id != sec_proj:
            error_codes.append("TRUST_ANCHOR_PROJECT_MISMATCH")
            errors.append(
                f"WORM depolama projesi ('{receipt.project_id}') manifest security_project_id ('{sec_proj}') ile uyuşmuyor."
            )
        if eff_app_proj and app_proj != eff_app_proj:
            error_codes.append("TRUST_ANCHOR_APP_PROJECT_MISMATCH")
            errors.append(
                f"Manifest app_project_id ('{app_proj}') beklenen uygulama projesi ('{eff_app_proj}') ile uyuşmuyor."
            )
        if man_ledger != ledger_id:
            error_codes.append("TRUST_ANCHOR_LEDGER_ID_MISMATCH")
            errors.append(f"Manifest ledger_id ('{man_ledger}') hedeflenen defter ('{ledger_id}') ile uyuşmuyor.")

        # Rule 3: Read-only enforcement
        read_only = manifest.get("read_only") is True
        if not read_only:
            error_codes.append("TRUST_ANCHOR_NOT_READ_ONLY")
            errors.append("Harici güven kökü manifesti salt okunur (read_only=true) olarak işaretlenmemiş.")

        # Rule 4: Independent audit log reference
        audit_ref = str(manifest.get("independent_audit_log_ref") or "").strip()
        audit_ok = bool(audit_ref and len(audit_ref) >= 12 and (not sec_proj or sec_proj in audit_ref))
        if not audit_ok:
            error_codes.append("TRUST_ANCHOR_MISSING_INDEPENDENT_AUDIT_LOG")
            errors.append(
                f"Harici güven kökü güvenlik projesine ('{sec_proj}') bağlı bağımsız denetim kaydı referansı "
                f"(independent_audit_log_ref) içermemektedir."
            )

        # Validate anchor payload hashes & count
        head_hash = str(manifest.get("expected_checkpoint_head_hash") or "").strip().lower()
        chain_digest = str(manifest.get("expected_chain_digest_sha256") or "").strip().lower()
        entry_count = manifest.get("expected_checkpoint_entry_count")
        if not SHA256_RE.match(head_hash) or not SHA256_RE.match(chain_digest):
            error_codes.append("TRUST_ANCHOR_INVALID_HASHES")
            errors.append("Manifest expected_checkpoint_head_hash veya expected_chain_digest_sha256 geçersiz SHA-256.")
        if isinstance(entry_count, bool) or not isinstance(entry_count, int) or entry_count < 1:
            error_codes.append("TRUST_ANCHOR_INVALID_ENTRY_COUNT")
            errors.append("Manifest expected_checkpoint_entry_count pozitif tamsayı olmalıdır.")

        # Rule 5: KMS/HSM asymmetric signature verification over RFC 8785 canonical manifest payload
        kms_signed = False
        kms_prot: str | None = None
        sig_block = manifest.get("kms_signature")
        if not isinstance(sig_block, dict):
            error_codes.append("TRUST_ANCHOR_INVALID_KMS_SIGNATURE")
            errors.append("Harici güven kökü manifestinde kms_signature bloğu eksiktir.")
        else:
            if sig_block.get("qualified_e_signature_5070_equivalent") is True:
                error_codes.append("INVALID_5070_EQUIVALENCE_CLAIM")
                errors.append("KMS imzası 5070 sayılı Kanun kapsamında güvenli elektronik imza eşdeğeri beyan edilemez.")
            key_ref = str(sig_block.get("key_resource_id") or "")
            sig_b64 = str(sig_block.get("signature_b64") or "")
            alg = str(sig_block.get("algorithm") or "")
            signing_payload = build_trust_anchor_manifest_signing_payload(manifest)
            sig_ok, sig_msg, key_meta = self.kms_signer.verify_canonical_json(
                signing_payload,
                sig_b64,
                key_ref,
                alg,
                runtime_environment=runtime_environment,
            )
            kms_prot = key_meta.protection_level if key_meta else None
            if not sig_ok:
                error_codes.append("TRUST_ANCHOR_INVALID_KMS_SIGNATURE")
                errors.append(f"Harici güven kökü KMS/HSM imzası doğrulanamadı: {sig_msg}")
            else:
                kms_signed = True

        # Rule 6: Independent RFC 3161 TSA verification (when required or present)
        tsa_ok = False
        tsa_block = manifest.get("tsa_proof")
        if isinstance(tsa_block, dict) and tsa_block.get("tsr_der_b64") and self.tsa_provider is not None:
            try:
                tsr_bytes = base64.b64decode(str(tsa_block["tsr_der_b64"]), validate=True)
                manifest_digest = hashlib.sha256(
                    canonical_json_bytes(build_trust_anchor_manifest_signing_payload(manifest))
                ).hexdigest()
                tsa_chk = self.tsa_provider.verify_timestamp_token(manifest_digest, tsr_bytes)
                if tsa_chk.valid:
                    tsa_ok = True
                else:
                    error_codes.append("TRUST_ANCHOR_TSA_VERIFICATION_FAILED")
                    errors.extend(tsa_chk.errors)
            except Exception as exc:
                error_codes.append("TRUST_ANCHOR_TSA_VERIFICATION_FAILED")
                errors.append(f"Harici güven kökü RFC 3161 zaman damgası çözümlenemedi: {exc}")
        elif self.require_tsa:
            error_codes.append("TRUST_ANCHOR_TSA_REQUIRED")
            errors.append("Harici güven kökü manifestinde doğrulanmış RFC 3161 zaman damgası (tsa_proof) zorunludur.")

        if errors or error_codes:
            return self._fail(
                error_codes,
                errors,
                manifest_id=manifest_id or None,
                sec_proj=sec_proj or None,
                app_proj=app_proj or None,
                ledger_id=man_ledger or None,
                read_only=read_only,
                sep_proj=sep_proj,
                kms_signed=kms_signed,
                kms_prot=kms_prot,
                worm_ok=worm_ok,
                audit_ok=audit_ok,
                audit_ref=audit_ref or None,
                tsa_ok=tsa_ok,
            )

        return ExternalTrustAnchorRecord(
            valid=True,
            manifest_id=manifest_id,
            security_project_id=sec_proj,
            app_project_id=app_proj,
            ledger_id=man_ledger,
            expected_checkpoint_head_hash=head_hash,
            expected_checkpoint_entry_count=entry_count,
            expected_chain_digest_sha256=chain_digest,
            read_only=True,
            separate_security_project=True,
            kms_signed=True,
            kms_protection_level=kms_prot,
            worm_protected=True,
            independent_audit_logged=True,
            independent_audit_log_ref=audit_ref,
            manifest_uri=self.manifest_uri,
            tsa_verified=tsa_ok,
            trust_anchor_source="INDEPENDENT_WORM_STORE",
            provider_backend=self.provider_name,
            integration_mode=self._integration_mode,
        )
