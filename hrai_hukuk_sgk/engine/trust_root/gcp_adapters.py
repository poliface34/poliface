"""Primary Google Cloud Platform (GCP Frankfurt / europe-west3) Trust Root Adapters for CALISORA @HukukSGK v1.0.3.

Implements:
  - GcpCloudKmsSignerAdapter(KeySignerProvider):
      * Ed25519 (`EC_SIGN_ED25519`) and RSA-PSS-SHA256 (`RSA_SIGN_PSS_2048_SHA256` / `3072` / `4096`)
        over spec-exact RFC 8785 (JCS) canonical JSON bytes.
      * Enforces Cloud KMS `protection_level == "HSM"` in PRODUCTION.
      * Private key material NEVER leaves Cloud KMS / HSM.
      * Zero hard top-level dependency on `google-cloud-kms`; lazily loads SDK if live credentials exist,
        accepts an injectable client/backend for deterministic `MOCK_SANDBOX` testing, and honestly reports
        `NOT_CONFIGURED` when GCP credentials/project/key ring are absent.
  - GcpCloudStorageWormAdapter(ImmutableEvidenceStorageProvider):
      * Google Cloud Storage WORM evidence storage targeting Frankfurt (`europe-west3`).
      * Enforces GCS Bucket Lock irreversibility safety gate: refuses to lock retention policy unless
        `confirm_irreversible_bucket_lock=True`, `legal_retention_policy_approved=True`, and an explicit
        legal `approval_reference` are supplied.
      * Blocks overwrites and deletions on immutable objects (`WORM_IMMUTABILITY_VIOLATION`).
      * Zero hard top-level dependency on `google-cloud-storage`; honestly reports `NOT_CONFIGURED` when
        real GCS credentials/bucket are absent.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
import re
from typing import Any

from ..attestation_verifier import (
    SIGNATURE_5070_NON_EQUIVALENCE_NOTICE,
    SUPPORTED_SIGNATURE_ALGORITHMS,
    canonical_json_bytes,
    compute_public_key_fingerprint,
    generate_ephemeral_keypair,
    sign_canonical_payload,
    verify_asymmetric_signature,
)
from .interfaces import ImmutableEvidenceStorageProvider, KeySignerProvider
from .models import (
    DEFAULT_GCP_REGION,
    KeyMetadata,
    ProviderHealthStatus,
    SignatureEnvelope,
    WormObjectReceipt,
)

GCP_KMS_KEY_VERSION_RE = re.compile(
    r"^projects/(?P<project>[a-z][a-z0-9\-]{4,29})/locations/(?P<location>[a-z0-9\-]+)/"
    r"keyRings/(?P<keyring>[A-Za-z0-9_\-]+)/cryptoKeys/(?P<key>[A-Za-z0-9_\-]+)/"
    r"cryptoKeyVersions/(?P<version>[0-9]+)$"
)

GCS_URI_RE = re.compile(r"^gs://(?P<bucket>[a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])/(?P<object>.+)$")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class InMemoryMockGcpKmsBackend:
    """Ephemeral in-memory mock of GCP Cloud KMS HSM strictly for `MOCK_SANDBOX` unit/security tests.

    Private keys are generated ephemerally at runtime and NEVER written to disk or exported by the adapter.
    """

    def __init__(self, *, default_region: str = DEFAULT_GCP_REGION) -> None:
        self.default_region = default_region
        self._keys: dict[str, dict[str, Any]] = {}

    def enroll_ephemeral_key(
        self,
        key_resource_id: str,
        *,
        algorithm: str = "ED25519",
        protection_level: str = "HSM",
    ) -> KeyMetadata:
        m = GCP_KMS_KEY_VERSION_RE.match(key_resource_id)
        if not m:
            raise ValueError(f"Geçersiz GCP Cloud KMS kaynak yolu: '{key_resource_id}'.")
        alg = algorithm.upper().strip()
        if alg not in SUPPORTED_SIGNATURE_ALGORITHMS:
            raise ValueError(f"Desteklenmeyen algoritma: '{algorithm}'.")
        prot = protection_level.upper().strip()
        priv_pem, pub_pem = generate_ephemeral_keypair(alg)
        fp = compute_public_key_fingerprint(pub_pem)
        self._keys[key_resource_id] = {
            "key_resource_id": key_resource_id,
            "key_version": f"v{m.group('version')}",
            "region": m.group("location"),
            "algorithm": alg,
            "protection_level": prot,
            "public_key_pem": pub_pem,
            "public_key_fingerprint_sha256": fp,
            "_hsm_internal_priv": priv_pem,
        }
        return KeyMetadata(
            key_resource_id=key_resource_id,
            key_version=f"v{m.group('version')}",
            algorithm=alg,
            protection_level=prot,
            public_key_pem=pub_pem,
            public_key_fingerprint_sha256=fp,
            provider_backend="GCP_CLOUD_KMS_MOCK",
            integration_mode="MOCK_SANDBOX",
            region=m.group("location"),
            hsm_backed=(prot == "HSM"),
            qualified_e_signature_5070_equivalent=False,
        )

    def get_key_info(self, key_resource_id: str) -> dict[str, Any] | None:
        rec = self._keys.get(key_resource_id)
        if rec is None:
            return None
        return {k: v for k, v in rec.items() if not k.startswith("_")}

    def asymmetric_sign_canonical(self, key_resource_id: str, payload: dict[str, Any], algorithm: str) -> str:
        rec = self._keys.get(key_resource_id)
        if rec is None:
            raise KeyError(f"KMS anahtar sürümü bulunamadı: '{key_resource_id}'.")
        if rec["algorithm"] != algorithm.upper().strip():
            raise ValueError(
                f"KMS anahtar algoritması ({rec['algorithm']}) ile istenen algoritma ({algorithm}) uyuşmuyor."
            )
        return sign_canonical_payload(payload, rec["_hsm_internal_priv"], algorithm=rec["algorithm"])


class GcpCloudKmsSignerAdapter(KeySignerProvider):
    """Primary `KeySignerProvider` adapter for Google Cloud KMS (HSM protection level, Frankfurt `europe-west3`)."""

    def __init__(
        self,
        *,
        project_id: str | None = None,
        region: str = DEFAULT_GCP_REGION,
        key_ring: str | None = None,
        mock_backend: InMemoryMockGcpKmsBackend | None = None,
        kms_sdk_client: Any | None = None,
        require_hsm_in_production: bool = True,
    ) -> None:
        self.project_id = project_id.strip() if isinstance(project_id, str) and project_id.strip() else None
        self.region = region.strip() if isinstance(region, str) and region.strip() else DEFAULT_GCP_REGION
        self.key_ring = key_ring.strip() if isinstance(key_ring, str) and key_ring.strip() else None
        self._mock_backend = mock_backend
        self._kms_sdk_client = kms_sdk_client
        self.require_hsm_in_production = require_hsm_in_production

        if mock_backend is not None:
            self._integration_mode = "MOCK_SANDBOX"
        elif self.project_id and self.key_ring and (kms_sdk_client is not None or self._live_credentials_present()):
            self._integration_mode = "LIVE_PRODUCTION"
        else:
            self._integration_mode = "NOT_CONFIGURED"

    @staticmethod
    def _live_credentials_present() -> bool:
        cred_file = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        return bool(cred_file and os.path.isfile(cred_file))

    @property
    def provider_name(self) -> str:
        return "GCP_CLOUD_KMS_HSM"

    @property
    def integration_mode(self) -> str:
        return self._integration_mode

    def _get_live_client(self) -> Any:
        if self._kms_sdk_client is not None:
            return self._kms_sdk_client
        try:
            from google.cloud import kms  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError(
                "GCP Cloud KMS SDK (google-cloud-kms) yüklü değil; canlı GCP ortamında yüklenmelidir."
            ) from exc
        self._kms_sdk_client = kms.KeyManagementServiceClient()
        return self._kms_sdk_client

    def health_check(self) -> ProviderHealthStatus:
        if self._integration_mode == "NOT_CONFIGURED":
            return ProviderHealthStatus(
                provider_name=self.provider_name,
                provider_type="KeySignerProvider",
                backend="GCP_CLOUD_KMS",
                integration_mode="NOT_CONFIGURED",
                configured=False,
                reachable=False,
                region=self.region,
                details={
                    "project_id_configured": bool(self.project_id),
                    "key_ring_configured": bool(self.key_ring),
                    "live_credentials_present": self._live_credentials_present(),
                    "hsm_required_in_production": self.require_hsm_in_production,
                },
                error_code="KMS_PROVIDER_NOT_CONFIGURED",
                error_message="Gerçek GCP Cloud KMS projesi, keyRing veya kimlik bilgileri yapılandırılmamıştır.",
            )
        return ProviderHealthStatus(
            provider_name=self.provider_name,
            provider_type="KeySignerProvider",
            backend="GCP_CLOUD_KMS_MOCK" if self._integration_mode == "MOCK_SANDBOX" else "GCP_CLOUD_KMS",
            integration_mode=self._integration_mode,
            configured=True,
            reachable=self._integration_mode == "MOCK_SANDBOX" or self._kms_sdk_client is not None,
            region=self.region,
            details={
                "project_id": self.project_id,
                "key_ring": self.key_ring,
                "hsm_required_in_production": self.require_hsm_in_production,
            },
        )

    def get_key_metadata(self, key_ref: str) -> KeyMetadata | None:
        m = GCP_KMS_KEY_VERSION_RE.match(str(key_ref or "").strip())
        if not m:
            return None
        if self._mock_backend is not None:
            info = self._mock_backend.get_key_info(key_ref)
            if info is None:
                return None
            return KeyMetadata(
                key_resource_id=info["key_resource_id"],
                key_version=info["key_version"],
                algorithm=info["algorithm"],
                protection_level=info["protection_level"],
                public_key_pem=info["public_key_pem"],
                public_key_fingerprint_sha256=info["public_key_fingerprint_sha256"],
                provider_backend="GCP_CLOUD_KMS_MOCK",
                integration_mode="MOCK_SANDBOX",
                region=info["region"],
                hsm_backed=(info["protection_level"] == "HSM"),
                qualified_e_signature_5070_equivalent=False,
            )
        if self._integration_mode != "LIVE_PRODUCTION":
            return None
        client = self._get_live_client()
        ver_obj = client.get_crypto_key_version(request={"name": key_ref})
        pub_obj = client.get_public_key(request={"name": key_ref})
        pub_pem = str(pub_obj.pem)
        prot = str(getattr(ver_obj.protection_level, "name", ver_obj.protection_level)).upper()
        kms_alg = str(getattr(ver_obj.algorithm, "name", ver_obj.algorithm)).upper()
        mapped_alg = "ED25519" if "ED25519" in kms_alg else "RSA-PSS-SHA256"
        return KeyMetadata(
            key_resource_id=key_ref,
            key_version=f"v{m.group('version')}",
            algorithm=mapped_alg,
            protection_level=prot,
            public_key_pem=pub_pem,
            public_key_fingerprint_sha256=compute_public_key_fingerprint(pub_pem),
            provider_backend="GCP_CLOUD_KMS",
            integration_mode="LIVE_PRODUCTION",
            region=m.group("location"),
            hsm_backed=(prot == "HSM"),
            qualified_e_signature_5070_equivalent=False,
        )

    def sign_canonical_json(
        self,
        payload: dict[str, Any],
        key_ref: str,
        algorithm: str = "ED25519",
        *,
        runtime_environment: str = "PRODUCTION",
    ) -> SignatureEnvelope:
        alg = str(algorithm or "").upper().strip()
        env_norm = str(runtime_environment or "PRODUCTION").upper().strip()
        msg_bytes = canonical_json_bytes(payload)
        payload_sha = hashlib.sha256(msg_bytes).hexdigest()
        now_utc = _utc_now_iso()

        if alg not in SUPPORTED_SIGNATURE_ALGORITHMS:
            return SignatureEnvelope(
                valid=False,
                algorithm=alg,
                key_resource_id=key_ref,
                key_version="unknown",
                protection_level="UNKNOWN",
                public_key_fingerprint_sha256=None,
                payload_sha256=payload_sha,
                signature_b64=None,
                canonicalization_standard="RFC-8785-JCS",
                signed_at_utc=now_utc,
                provider_backend="GCP_CLOUD_KMS",
                integration_mode=self._integration_mode,
                qualified_e_signature_5070_equivalent=False,
                error_codes=("UNSUPPORTED_SIGNATURE_ALGORITHM",),
                errors=(f"Desteklenmeyen imza algoritması: '{algorithm}'.",),
            )

        if self._integration_mode == "NOT_CONFIGURED":
            return SignatureEnvelope(
                valid=False,
                algorithm=alg,
                key_resource_id=key_ref,
                key_version="unknown",
                protection_level="UNKNOWN",
                public_key_fingerprint_sha256=None,
                payload_sha256=payload_sha,
                signature_b64=None,
                canonicalization_standard="RFC-8785-JCS",
                signed_at_utc=now_utc,
                provider_backend="GCP_CLOUD_KMS",
                integration_mode="NOT_CONFIGURED",
                qualified_e_signature_5070_equivalent=False,
                error_codes=("KMS_PROVIDER_NOT_CONFIGURED",),
                errors=("GCP Cloud KMS üretim kimlik bilgileri/anahtar halkası yapılandırılmamıştır.",),
            )

        meta = self.get_key_metadata(key_ref)
        if meta is None:
            return SignatureEnvelope(
                valid=False,
                algorithm=alg,
                key_resource_id=key_ref,
                key_version="unknown",
                protection_level="UNKNOWN",
                public_key_fingerprint_sha256=None,
                payload_sha256=payload_sha,
                signature_b64=None,
                canonicalization_standard="RFC-8785-JCS",
                signed_at_utc=now_utc,
                provider_backend="GCP_CLOUD_KMS_MOCK" if self._mock_backend else "GCP_CLOUD_KMS",
                integration_mode=self._integration_mode,
                qualified_e_signature_5070_equivalent=False,
                error_codes=("KMS_KEY_NOT_FOUND_OR_INVALID_RESOURCE",),
                errors=(f"Geçersiz veya bulunamayan GCP Cloud KMS anahtar sürümü: '{key_ref}'.",),
            )

        if env_norm == "PRODUCTION" and self.require_hsm_in_production and meta.protection_level != "HSM":
            return SignatureEnvelope(
                valid=False,
                algorithm=alg,
                key_resource_id=key_ref,
                key_version=meta.key_version,
                protection_level=meta.protection_level,
                public_key_fingerprint_sha256=meta.public_key_fingerprint_sha256,
                payload_sha256=payload_sha,
                signature_b64=None,
                canonicalization_standard="RFC-8785-JCS",
                signed_at_utc=now_utc,
                provider_backend=meta.provider_backend,
                integration_mode=self._integration_mode,
                qualified_e_signature_5070_equivalent=False,
                error_codes=("KMS_HSM_PROTECTION_REQUIRED_IN_PRODUCTION",),
                errors=(
                    f"PRODUCTION ortamında Cloud KMS HSM koruma seviyesi zorunludur "
                    f"(bulunan protection_level='{meta.protection_level}').",
                ),
            )

        if self._mock_backend is not None:
            try:
                sig_b64 = self._mock_backend.asymmetric_sign_canonical(key_ref, payload, alg)
            except Exception as exc:
                return SignatureEnvelope(
                    valid=False,
                    algorithm=alg,
                    key_resource_id=key_ref,
                    key_version=meta.key_version,
                    protection_level=meta.protection_level,
                    public_key_fingerprint_sha256=meta.public_key_fingerprint_sha256,
                    payload_sha256=payload_sha,
                    signature_b64=None,
                    canonicalization_standard="RFC-8785-JCS",
                    signed_at_utc=now_utc,
                    provider_backend=meta.provider_backend,
                    integration_mode=self._integration_mode,
                    qualified_e_signature_5070_equivalent=False,
                    error_codes=("KMS_SIGNING_FAILED",),
                    errors=(str(exc),),
                )
        else:
            import base64

            client = self._get_live_client()
            if alg == "ED25519":
                resp = client.asymmetric_sign(request={"name": key_ref, "data": msg_bytes})
            else:
                resp = client.asymmetric_sign(
                    request={"name": key_ref, "digest": {"sha256": hashlib.sha256(msg_bytes).digest()}}
                )
            sig_b64 = base64.b64encode(bytes(resp.signature)).decode("ascii")

        return SignatureEnvelope(
            valid=True,
            algorithm=alg,
            key_resource_id=key_ref,
            key_version=meta.key_version,
            protection_level=meta.protection_level,
            public_key_fingerprint_sha256=meta.public_key_fingerprint_sha256,
            payload_sha256=payload_sha,
            signature_b64=sig_b64,
            canonicalization_standard="RFC-8785-JCS",
            signed_at_utc=now_utc,
            provider_backend=meta.provider_backend,
            integration_mode=self._integration_mode,
            qualified_e_signature_5070_equivalent=False,
            signature_legal_notice=SIGNATURE_5070_NON_EQUIVALENCE_NOTICE,
        )

    def verify_canonical_json(
        self,
        payload: dict[str, Any],
        signature_b64: str,
        key_ref: str,
        algorithm: str = "ED25519",
        *,
        runtime_environment: str = "PRODUCTION",
    ) -> tuple[bool, str, KeyMetadata | None]:
        env_norm = str(runtime_environment or "PRODUCTION").upper().strip()
        if self._integration_mode == "NOT_CONFIGURED":
            return False, "KMS_PROVIDER_NOT_CONFIGURED: GCP Cloud KMS yapılandırılmamıştır.", None
        meta = self.get_key_metadata(key_ref)
        if meta is None or not meta.public_key_pem:
            return False, f"KMS_KEY_NOT_FOUND_OR_INVALID_RESOURCE: '{key_ref}' açık anahtarı alınamadı.", meta
        if env_norm == "PRODUCTION" and self.require_hsm_in_production and meta.protection_level != "HSM":
            return (
                False,
                f"KMS_HSM_PROTECTION_REQUIRED_IN_PRODUCTION: protection_level='{meta.protection_level}' reddedildi.",
                meta,
            )
        ok, msg = verify_asymmetric_signature(payload, signature_b64, meta.public_key_pem, algorithm)
        return ok, msg, meta


class InMemoryMockGcpWormBackend:
    """Ephemeral in-memory mock of Google Cloud Storage Bucket Lock WORM strictly for `MOCK_SANDBOX` tests."""

    def __init__(
        self,
        *,
        project_id: str,
        bucket_name: str,
        region: str = DEFAULT_GCP_REGION,
        retention_period_seconds: int | None = None,
        retention_policy_locked: bool = False,
    ) -> None:
        self.project_id = project_id
        self.bucket_name = bucket_name
        self.region = region
        self.retention_period_seconds = retention_period_seconds
        self.retention_policy_locked = retention_policy_locked
        self.lock_approval_reference: str | None = None
        self._objects: dict[str, dict[str, Any]] = {}
        self._generation_counter = 1000

    def put_object(
        self,
        object_name: str,
        data: bytes,
        *,
        content_type: str,
        metadata: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        clean_name = object_name.lstrip("/")
        if clean_name in self._objects:
            raise PermissionError(
                f"WORM_IMMUTABILITY_VIOLATION: '{clean_name}' nesnesi zaten mevcut; değişmez WORM nesnesi üzerine yazılamaz."
            )
        self._generation_counter += 1
        sha = hashlib.sha256(data).hexdigest()
        now_utc = _utc_now_iso()
        rec = {
            "object_name": clean_name,
            "object_uri": f"gs://{self.bucket_name}/{clean_name}",
            "data": bytes(data),
            "content_type": content_type,
            "metadata": dict(metadata or {}),
            "content_sha256": sha,
            "byte_length": len(data),
            "generation": str(self._generation_counter),
            "stored_at_utc": now_utc,
            "event_based_hold": False,
            "temporary_hold": False,
        }
        self._objects[clean_name] = rec
        return rec

    def delete_object(self, object_name: str) -> None:
        clean_name = object_name.lstrip("/")
        if clean_name in self._objects and (
            self.retention_policy_locked or (self.retention_period_seconds or 0) > 0
        ):
            raise PermissionError(
                f"WORM_IMMUTABILITY_VIOLATION: '{clean_name}' saklama politikası / Bucket Lock altında silinemez."
            )
        self._objects.pop(clean_name, None)

    def get_object(self, object_name: str) -> dict[str, Any] | None:
        return self._objects.get(object_name.lstrip("/"))


class GcpCloudStorageWormAdapter(ImmutableEvidenceStorageProvider):
    """Primary `ImmutableEvidenceStorageProvider` for Google Cloud Storage + Bucket Lock (Frankfurt `europe-west3`)."""

    def __init__(
        self,
        *,
        project_id: str | None = None,
        bucket_name: str | None = None,
        region: str = DEFAULT_GCP_REGION,
        enforce_region: str | None = DEFAULT_GCP_REGION,
        mock_backend: InMemoryMockGcpWormBackend | None = None,
        gcs_sdk_client: Any | None = None,
    ) -> None:
        self.project_id = project_id.strip() if isinstance(project_id, str) and project_id.strip() else None
        self.bucket_name = bucket_name.strip() if isinstance(bucket_name, str) and bucket_name.strip() else None
        self.region = region.strip() if isinstance(region, str) and region.strip() else DEFAULT_GCP_REGION
        self.enforce_region = enforce_region
        self._mock_backend = mock_backend
        self._gcs_sdk_client = gcs_sdk_client

        if mock_backend is not None:
            self.project_id = self.project_id or mock_backend.project_id
            self.bucket_name = self.bucket_name or mock_backend.bucket_name
            self.region = mock_backend.region
            self._integration_mode = "MOCK_SANDBOX"
        elif self.project_id and self.bucket_name and (gcs_sdk_client is not None or self._live_credentials_present()):
            self._integration_mode = "LIVE_PRODUCTION"
        else:
            self._integration_mode = "NOT_CONFIGURED"

    @staticmethod
    def _live_credentials_present() -> bool:
        cred_file = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        return bool(cred_file and os.path.isfile(cred_file))

    @property
    def provider_name(self) -> str:
        return "GCP_CLOUD_STORAGE_WORM_BUCKET_LOCK"

    @property
    def integration_mode(self) -> str:
        return self._integration_mode

    def _normalize_object_name(self, object_uri_or_name: str) -> tuple[str | None, str | None]:
        raw = str(object_uri_or_name or "").strip()
        if not raw:
            return None, "Nesne yolu boş olamaz."
        if raw.startswith("gs://"):
            m = GCS_URI_RE.match(raw)
            if not m:
                return None, f"Geçersiz GCS URI: '{raw}'."
            if self.bucket_name and m.group("bucket") != self.bucket_name:
                return None, f"GCS URI bucket ('{m.group('bucket')}') bu adaptör bucket'ı ('{self.bucket_name}') ile uyuşmuyor."
            obj = m.group("object")
        else:
            obj = raw.lstrip("/")
        if ".." in obj.split("/") or obj.startswith("/"):
            return None, f"Geçersiz/traversal içeren WORM nesne yolu reddedildi: '{raw}'."
        return obj, None

    def health_check(self) -> ProviderHealthStatus:
        if self._integration_mode == "NOT_CONFIGURED":
            return ProviderHealthStatus(
                provider_name=self.provider_name,
                provider_type="ImmutableEvidenceStorageProvider",
                backend="GCP_CLOUD_STORAGE_WORM",
                integration_mode="NOT_CONFIGURED",
                configured=False,
                reachable=False,
                region=self.region,
                details={
                    "project_id_configured": bool(self.project_id),
                    "bucket_configured": bool(self.bucket_name),
                    "live_credentials_present": self._live_credentials_present(),
                    "bucket_lock_applied": False,
                },
                error_code="WORM_STORAGE_NOT_CONFIGURED",
                error_message="Gerçek GCP Cloud Storage WORM bucket veya kimlik bilgileri yapılandırılmamıştır.",
            )
        locked = bool(self._mock_backend.retention_policy_locked) if self._mock_backend else False
        ret_sec = self._mock_backend.retention_period_seconds if self._mock_backend else None
        return ProviderHealthStatus(
            provider_name=self.provider_name,
            provider_type="ImmutableEvidenceStorageProvider",
            backend="GCP_CLOUD_STORAGE_WORM_MOCK" if self._mock_backend else "GCP_CLOUD_STORAGE_WORM",
            integration_mode=self._integration_mode,
            configured=True,
            reachable=self._mock_backend is not None or self._gcs_sdk_client is not None,
            region=self.region,
            details={
                "project_id": self.project_id,
                "bucket_name": self.bucket_name,
                "retention_period_seconds": ret_sec,
                "retention_policy_locked": locked,
            },
        )

    def put_immutable_object(
        self,
        object_name: str,
        data: bytes,
        *,
        content_type: str = "application/octet-stream",
        metadata: dict[str, str] | None = None,
    ) -> WormObjectReceipt:
        clean_name, norm_err = self._normalize_object_name(object_name)
        if norm_err or not clean_name:
            return WormObjectReceipt(
                stored=False,
                object_uri=None,
                bucket_name=self.bucket_name,
                object_name=str(object_name),
                region=self.region,
                generation=None,
                content_sha256=None,
                byte_length=len(data),
                stored_at_utc=None,
                retention_policy_seconds=None,
                retention_policy_locked=False,
                event_based_hold=False,
                temporary_hold=False,
                worm_immutable_verified=False,
                project_id=self.project_id,
                provider_backend="GCP_CLOUD_STORAGE_WORM",
                integration_mode=self._integration_mode,
                error_codes=("INVALID_WORM_OBJECT_NAME",),
                errors=(norm_err or "Geçersiz WORM nesne adı.",),
            )

        if self.enforce_region and self.region != self.enforce_region:
            return WormObjectReceipt(
                stored=False,
                object_uri=None,
                bucket_name=self.bucket_name,
                object_name=clean_name,
                region=self.region,
                generation=None,
                content_sha256=None,
                byte_length=len(data),
                stored_at_utc=None,
                retention_policy_seconds=None,
                retention_policy_locked=False,
                event_based_hold=False,
                temporary_hold=False,
                worm_immutable_verified=False,
                project_id=self.project_id,
                provider_backend="GCP_CLOUD_STORAGE_WORM",
                integration_mode=self._integration_mode,
                error_codes=("GCP_REGION_POLICY_MISMATCH",),
                errors=(f"WORM bucket bölgesi '{self.region}' beklenen bölge '{self.enforce_region}' ile uyuşmuyor.",),
            )

        if self._integration_mode == "NOT_CONFIGURED":
            return WormObjectReceipt(
                stored=False,
                object_uri=None,
                bucket_name=self.bucket_name,
                object_name=clean_name,
                region=self.region,
                generation=None,
                content_sha256=None,
                byte_length=len(data),
                stored_at_utc=None,
                retention_policy_seconds=None,
                retention_policy_locked=False,
                event_based_hold=False,
                temporary_hold=False,
                worm_immutable_verified=False,
                project_id=self.project_id,
                provider_backend="GCP_CLOUD_STORAGE_WORM",
                integration_mode="NOT_CONFIGURED",
                error_codes=("WORM_STORAGE_NOT_CONFIGURED",),
                errors=("GCP Cloud Storage WORM bucket yapılandırılmamıştır.",),
            )

        if self._mock_backend is not None:
            try:
                rec = self._mock_backend.put_object(clean_name, data, content_type=content_type, metadata=metadata)
            except PermissionError as exc:
                return WormObjectReceipt(
                    stored=False,
                    object_uri=f"gs://{self.bucket_name}/{clean_name}",
                    bucket_name=self.bucket_name,
                    object_name=clean_name,
                    region=self.region,
                    generation=None,
                    content_sha256=None,
                    byte_length=len(data),
                    stored_at_utc=None,
                    retention_policy_seconds=self._mock_backend.retention_period_seconds,
                    retention_policy_locked=self._mock_backend.retention_policy_locked,
                    event_based_hold=False,
                    temporary_hold=False,
                    worm_immutable_verified=False,
                    project_id=self.project_id,
                    provider_backend="GCP_CLOUD_STORAGE_WORM_MOCK",
                    integration_mode="MOCK_SANDBOX",
                    error_codes=("WORM_IMMUTABILITY_VIOLATION",),
                    errors=(str(exc),),
                )
            worm_ok = bool(
                self._mock_backend.retention_policy_locked
                and (self._mock_backend.retention_period_seconds or 0) > 0
            )
            return WormObjectReceipt(
                stored=True,
                object_uri=rec["object_uri"],
                bucket_name=self.bucket_name,
                object_name=clean_name,
                region=self.region,
                generation=rec["generation"],
                content_sha256=rec["content_sha256"],
                byte_length=rec["byte_length"],
                stored_at_utc=rec["stored_at_utc"],
                retention_policy_seconds=self._mock_backend.retention_period_seconds,
                retention_policy_locked=self._mock_backend.retention_policy_locked,
                event_based_hold=rec["event_based_hold"],
                temporary_hold=rec["temporary_hold"],
                worm_immutable_verified=worm_ok,
                project_id=self.project_id,
                provider_backend="GCP_CLOUD_STORAGE_WORM_MOCK",
                integration_mode="MOCK_SANDBOX",
            )

        try:
            from google.cloud import storage  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("google-cloud-storage SDK yüklü değil; canlı GCP ortamında yüklenmelidir.") from exc

        client = self._gcs_sdk_client or storage.Client(project=self.project_id)
        bucket = client.get_bucket(self.bucket_name)
        blob = bucket.blob(clean_name)
        blob.metadata = dict(metadata or {})
        blob.upload_from_string(data, content_type=content_type, if_generation_match=0)
        sha = hashlib.sha256(data).hexdigest()
        locked = bool(getattr(bucket, "retention_policy_locked", False))
        ret_sec = getattr(bucket, "retention_period", None)
        return WormObjectReceipt(
            stored=True,
            object_uri=f"gs://{self.bucket_name}/{clean_name}",
            bucket_name=self.bucket_name,
            object_name=clean_name,
            region=str(getattr(bucket, "location", self.region)).lower(),
            generation=str(blob.generation),
            content_sha256=sha,
            byte_length=len(data),
            stored_at_utc=_utc_now_iso(),
            retention_policy_seconds=ret_sec,
            retention_policy_locked=locked,
            event_based_hold=bool(blob.event_based_hold),
            temporary_hold=bool(blob.temporary_hold),
            worm_immutable_verified=bool(locked and (ret_sec or 0) > 0),
            project_id=self.project_id,
            provider_backend="GCP_CLOUD_STORAGE_WORM",
            integration_mode="LIVE_PRODUCTION",
        )

    def get_object_bytes(self, object_uri_or_name: str) -> tuple[bytes | None, WormObjectReceipt | None, str | None]:
        clean_name, norm_err = self._normalize_object_name(object_uri_or_name)
        if norm_err or not clean_name:
            return None, None, norm_err
        if self._integration_mode == "NOT_CONFIGURED":
            return None, None, "WORM_STORAGE_NOT_CONFIGURED"
        if self._mock_backend is not None:
            rec = self._mock_backend.get_object(clean_name)
            if rec is None:
                return None, None, f"WORM nesnesi bulunamadı: '{clean_name}'."
            receipt = self.verify_object_immutability(clean_name)
            return rec["data"], receipt, None

        try:
            from google.cloud import storage  # type: ignore[import-not-found]
        except ImportError:
            return None, None, "google-cloud-storage SDK yüklü değil."

        client = self._gcs_sdk_client or storage.Client(project=self.project_id)
        bucket = client.get_bucket(self.bucket_name)
        blob = bucket.blob(clean_name)
        if not blob.exists():
            return None, None, f"WORM nesnesi bulunamadı: '{clean_name}'."
        data = blob.download_as_bytes()
        receipt = self.verify_object_immutability(clean_name, expected_sha256=hashlib.sha256(data).hexdigest())
        return data, receipt, None

    def verify_object_immutability(
        self,
        object_uri_or_name: str,
        *,
        expected_sha256: str | None = None,
    ) -> WormObjectReceipt:
        clean_name, norm_err = self._normalize_object_name(object_uri_or_name)
        if norm_err or not clean_name:
            return WormObjectReceipt(
                stored=False,
                object_uri=None,
                bucket_name=self.bucket_name,
                object_name=str(object_uri_or_name),
                region=self.region,
                generation=None,
                content_sha256=None,
                byte_length=0,
                stored_at_utc=None,
                retention_policy_seconds=None,
                retention_policy_locked=False,
                event_based_hold=False,
                temporary_hold=False,
                worm_immutable_verified=False,
                project_id=self.project_id,
                provider_backend="GCP_CLOUD_STORAGE_WORM",
                integration_mode=self._integration_mode,
                error_codes=("INVALID_WORM_OBJECT_NAME",),
                errors=(norm_err or "Geçersiz WORM nesne yolu.",),
            )

        if self._integration_mode == "NOT_CONFIGURED":
            return WormObjectReceipt(
                stored=False,
                object_uri=None,
                bucket_name=self.bucket_name,
                object_name=clean_name,
                region=self.region,
                generation=None,
                content_sha256=None,
                byte_length=0,
                stored_at_utc=None,
                retention_policy_seconds=None,
                retention_policy_locked=False,
                event_based_hold=False,
                temporary_hold=False,
                worm_immutable_verified=False,
                project_id=self.project_id,
                provider_backend="GCP_CLOUD_STORAGE_WORM",
                integration_mode="NOT_CONFIGURED",
                error_codes=("WORM_STORAGE_NOT_CONFIGURED",),
                errors=("GCP Cloud Storage WORM yapılandırılmamıştır.",),
            )

        errors: list[str] = []
        error_codes: list[str] = []
        if self._mock_backend is not None:
            rec = self._mock_backend.get_object(clean_name)
            if rec is None:
                return WormObjectReceipt(
                    stored=False,
                    object_uri=f"gs://{self.bucket_name}/{clean_name}",
                    bucket_name=self.bucket_name,
                    object_name=clean_name,
                    region=self.region,
                    generation=None,
                    content_sha256=None,
                    byte_length=0,
                    stored_at_utc=None,
                    retention_policy_seconds=self._mock_backend.retention_period_seconds,
                    retention_policy_locked=self._mock_backend.retention_policy_locked,
                    event_based_hold=False,
                    temporary_hold=False,
                    worm_immutable_verified=False,
                    project_id=self.project_id,
                    provider_backend="GCP_CLOUD_STORAGE_WORM_MOCK",
                    integration_mode="MOCK_SANDBOX",
                    error_codes=("WORM_OBJECT_NOT_FOUND",),
                    errors=(f"WORM nesnesi bulunamadı: '{clean_name}'.",),
                )
            actual_sha = hashlib.sha256(rec["data"]).hexdigest()
            if expected_sha256 and actual_sha != expected_sha256.strip().lower():
                error_codes.append("WORM_OBJECT_SHA256_MISMATCH")
                errors.append(
                    f"WORM nesnesi SHA-256 uyuşmazlığı: beklenen={expected_sha256}, hesaplanan={actual_sha}."
                )
            locked = bool(self._mock_backend.retention_policy_locked)
            ret_sec = self._mock_backend.retention_period_seconds
            if not locked or not (ret_sec and ret_sec > 0):
                error_codes.append("WORM_BUCKET_LOCK_NOT_ACTIVE")
                errors.append("Cloud Storage bucket üzerinde kilitli saklama politikası (Bucket Lock) aktif değildir.")
            worm_ok = len(errors) == 0 and locked and bool(ret_sec and ret_sec > 0)
            return WormObjectReceipt(
                stored=True,
                object_uri=rec["object_uri"],
                bucket_name=self.bucket_name,
                object_name=clean_name,
                region=self.region,
                generation=rec["generation"],
                content_sha256=actual_sha,
                byte_length=len(rec["data"]),
                stored_at_utc=rec["stored_at_utc"],
                retention_policy_seconds=ret_sec,
                retention_policy_locked=locked,
                event_based_hold=rec["event_based_hold"],
                temporary_hold=rec["temporary_hold"],
                worm_immutable_verified=worm_ok,
                project_id=self.project_id,
                provider_backend="GCP_CLOUD_STORAGE_WORM_MOCK",
                integration_mode="MOCK_SANDBOX",
                error_codes=tuple(sorted(set(error_codes))),
                errors=tuple(errors),
            )

        try:
            from google.cloud import storage  # type: ignore[import-not-found]
        except ImportError:
            return WormObjectReceipt(
                stored=False,
                object_uri=f"gs://{self.bucket_name}/{clean_name}",
                bucket_name=self.bucket_name,
                object_name=clean_name,
                region=self.region,
                generation=None,
                content_sha256=None,
                byte_length=0,
                stored_at_utc=None,
                retention_policy_seconds=None,
                retention_policy_locked=False,
                event_based_hold=False,
                temporary_hold=False,
                worm_immutable_verified=False,
                project_id=self.project_id,
                provider_backend="GCP_CLOUD_STORAGE_WORM",
                integration_mode="NOT_CONFIGURED",
                error_codes=("WORM_SDK_NOT_INSTALLED",),
                errors=("google-cloud-storage SDK yüklü değil.",),
            )

        client = self._gcs_sdk_client or storage.Client(project=self.project_id)
        bucket = client.get_bucket(self.bucket_name)
        blob = bucket.get_blob(clean_name)
        if blob is None:
            return WormObjectReceipt(
                stored=False,
                object_uri=f"gs://{self.bucket_name}/{clean_name}",
                bucket_name=self.bucket_name,
                object_name=clean_name,
                region=self.region,
                generation=None,
                content_sha256=None,
                byte_length=0,
                stored_at_utc=None,
                retention_policy_seconds=getattr(bucket, "retention_period", None),
                retention_policy_locked=bool(getattr(bucket, "retention_policy_locked", False)),
                event_based_hold=False,
                temporary_hold=False,
                worm_immutable_verified=False,
                project_id=self.project_id,
                provider_backend="GCP_CLOUD_STORAGE_WORM",
                integration_mode="LIVE_PRODUCTION",
                error_codes=("WORM_OBJECT_NOT_FOUND",),
                errors=(f"WORM nesnesi bulunamadı: '{clean_name}'.",),
            )
        data = blob.download_as_bytes()
        actual_sha = hashlib.sha256(data).hexdigest()
        if expected_sha256 and actual_sha != expected_sha256.strip().lower():
            error_codes.append("WORM_OBJECT_SHA256_MISMATCH")
            errors.append(f"WORM nesnesi SHA-256 uyuşmazlığı: beklenen={expected_sha256}, hesaplanan={actual_sha}.")
        locked = bool(getattr(bucket, "retention_policy_locked", False))
        ret_sec = getattr(bucket, "retention_period", None)
        if not locked or not (ret_sec and ret_sec > 0):
            error_codes.append("WORM_BUCKET_LOCK_NOT_ACTIVE")
            errors.append("Cloud Storage bucket üzerinde kalıcı Bucket Lock aktif değildir.")
        return WormObjectReceipt(
            stored=True,
            object_uri=f"gs://{self.bucket_name}/{clean_name}",
            bucket_name=self.bucket_name,
            object_name=clean_name,
            region=str(getattr(bucket, "location", self.region)).lower(),
            generation=str(blob.generation),
            content_sha256=actual_sha,
            byte_length=len(data),
            stored_at_utc=blob.time_created.isoformat() if getattr(blob, "time_created", None) else None,
            retention_policy_seconds=ret_sec,
            retention_policy_locked=locked,
            event_based_hold=bool(blob.event_based_hold),
            temporary_hold=bool(blob.temporary_hold),
            worm_immutable_verified=len(errors) == 0 and locked and bool(ret_sec and ret_sec > 0),
            project_id=self.project_id,
            provider_backend="GCP_CLOUD_STORAGE_WORM",
            integration_mode="LIVE_PRODUCTION",
            error_codes=tuple(sorted(set(error_codes))),
            errors=tuple(errors),
        )

    def lock_retention_policy(
        self,
        retention_period_seconds: int,
        *,
        confirm_irreversible_bucket_lock: bool = False,
        legal_retention_policy_approved: bool = False,
        approval_reference: str | None = None,
    ) -> dict[str, Any]:
        """GCS Bucket Lock safety guard: NEVER applies irreversible lock without explicit legal approval & confirmation."""
        if (
            isinstance(retention_period_seconds, bool)
            or not isinstance(retention_period_seconds, int)
            or retention_period_seconds < 86400
        ):
            return {
                "locked": False,
                "error_code": "INVALID_RETENTION_PERIOD",
                "message": "Saklama süresi en az 86400 saniye (1 gün) pozitif tamsayı olmalıdır.",
            }
        if not legal_retention_policy_approved or not confirm_irreversible_bucket_lock or not str(approval_reference or "").strip():
            return {
                "locked": False,
                "error_code": "BUCKET_LOCK_LEGAL_APPROVAL_REQUIRED",
                "message": (
                    "Cloud Storage Bucket Lock geri alınamaz bir işlemdir. Hukuken onaylanmış saklama süresi "
                    "(legal_retention_policy_approved=True), onay referansı (approval_reference) ve açık geri "
                    "alınamazlık teyidi (confirm_irreversible_bucket_lock=True) olmadan kilit uygulanamaz."
                ),
            }
        if self._integration_mode == "NOT_CONFIGURED":
            return {
                "locked": False,
                "error_code": "WORM_STORAGE_NOT_CONFIGURED",
                "message": "GCP Cloud Storage WORM bucket yapılandırılmamıştır.",
            }
        if self._mock_backend is not None:
            if self._mock_backend.retention_policy_locked and (
                self._mock_backend.retention_period_seconds is not None
                and retention_period_seconds < self._mock_backend.retention_period_seconds
            ):
                return {
                    "locked": False,
                    "error_code": "BUCKET_LOCK_CANNOT_SHORTEN_RETENTION",
                    "message": "Kilitli Bucket Lock saklama süresi kısaltılamaz.",
                }
            self._mock_backend.retention_period_seconds = retention_period_seconds
            self._mock_backend.retention_policy_locked = True
            self._mock_backend.lock_approval_reference = str(approval_reference).strip()
            return {
                "locked": True,
                "bucket_name": self.bucket_name,
                "region": self.region,
                "retention_period_seconds": retention_period_seconds,
                "approval_reference": self._mock_backend.lock_approval_reference,
                "integration_mode": "MOCK_SANDBOX",
                "irreversible": True,
            }

        from google.cloud import storage  # type: ignore[import-not-found]

        client = self._gcs_sdk_client or storage.Client(project=self.project_id)
        bucket = client.get_bucket(self.bucket_name)
        bucket.retention_period = retention_period_seconds
        bucket.patch()
        bucket.lock_retention_policy()
        return {
            "locked": True,
            "bucket_name": self.bucket_name,
            "region": self.region,
            "retention_period_seconds": retention_period_seconds,
            "approval_reference": str(approval_reference).strip(),
            "integration_mode": "LIVE_PRODUCTION",
            "irreversible": True,
        }
