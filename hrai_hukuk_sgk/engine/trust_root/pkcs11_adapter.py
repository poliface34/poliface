"""Alternative PKCS#11 HSM `KeySignerProvider` adapter for CALISORA @HukukSGK v1.0.3.

Ensures provider-agnostic portability (on-premises HSM, sovereign HSM, SoftHSMv2, CloudHSM via PKCS#11)
without modifying `@HukukSGK` core verification logic. Supports Ed25519 (`CKM_EDDSA`) and RSA-PSS-SHA256
(`CKM_RSA_PKCS_PSS`) over spec-exact RFC 8785 (JCS) canonical JSON.

Private keys NEVER leave the PKCS#11 token boundary. Reports `NOT_CONFIGURED` honestly when no PKCS#11
shared library / slot / HSM token is attached.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
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
from .interfaces import KeySignerProvider
from .models import KeyMetadata, ProviderHealthStatus, SignatureEnvelope

PKCS11_MECHANISM_MAP: dict[str, str] = {
    "ED25519": "CKM_EDDSA",
    "RSA-PSS-SHA256": "CKM_RSA_PKCS_PSS",
}


class InMemoryMockPkcs11Session:
    """Ephemeral in-memory PKCS#11 HSM token simulation strictly for `MOCK_SANDBOX` tests."""

    def __init__(self, *, token_label: str = "CALISORA-HSM-TOKEN-MOCK", slot_id: int = 0) -> None:
        self.token_label = token_label
        self.slot_id = slot_id
        self._objects: dict[str, dict[str, Any]] = {}

    def enroll_key_in_token(self, key_label: str, *, algorithm: str = "ED25519", key_version: str = "v1") -> KeyMetadata:
        alg = algorithm.upper().strip()
        if alg not in SUPPORTED_SIGNATURE_ALGORITHMS:
            raise ValueError(f"Desteklenmeyen PKCS#11 algoritması: '{algorithm}'.")
        priv_pem, pub_pem = generate_ephemeral_keypair(alg)
        fp = compute_public_key_fingerprint(pub_pem)
        self._objects[key_label] = {
            "key_label": key_label,
            "key_version": key_version,
            "algorithm": alg,
            "mechanism": PKCS11_MECHANISM_MAP[alg],
            "public_key_pem": pub_pem,
            "public_key_fingerprint_sha256": fp,
            "_token_non_extractable_priv": priv_pem,
        }
        return KeyMetadata(
            key_resource_id=f"pkcs11:token={self.token_label};object={key_label}",
            key_version=key_version,
            algorithm=alg,
            protection_level="HSM",
            public_key_pem=pub_pem,
            public_key_fingerprint_sha256=fp,
            provider_backend="PKCS11_HSM_MOCK",
            integration_mode="MOCK_SANDBOX",
            hsm_backed=True,
            qualified_e_signature_5070_equivalent=False,
        )

    def get_public_metadata(self, key_label: str) -> dict[str, Any] | None:
        rec = self._objects.get(key_label)
        if rec is None:
            return None
        return {k: v for k, v in rec.items() if not k.startswith("_")}

    def c_sign_canonical(self, key_label: str, payload: dict[str, Any], algorithm: str) -> str:
        rec = self._objects.get(key_label)
        if rec is None:
            raise KeyError(f"PKCS#11 HSM token içinde anahtar bulunamadı: '{key_label}'.")
        if rec["algorithm"] != algorithm.upper().strip():
            raise ValueError(
                f"PKCS#11 anahtar algoritması ({rec['algorithm']}) ile istenen algoritma ({algorithm}) uyuşmuyor."
            )
        return sign_canonical_payload(payload, rec["_token_non_extractable_priv"], algorithm=rec["algorithm"])


class Pkcs11HsmSignerAdapter(KeySignerProvider):
    """Alternative `KeySignerProvider` adapter for hardware PKCS#11 HSM devices."""

    def __init__(
        self,
        *,
        library_path: str | None = None,
        slot_id: int | None = None,
        token_label: str | None = None,
        mock_session: InMemoryMockPkcs11Session | None = None,
    ) -> None:
        self.library_path = library_path.strip() if isinstance(library_path, str) and library_path.strip() else None
        self.slot_id = slot_id
        self.token_label = token_label.strip() if isinstance(token_label, str) and token_label.strip() else None
        self._mock_session = mock_session

        if mock_session is not None:
            self.token_label = self.token_label or mock_session.token_label
            self.slot_id = self.slot_id if self.slot_id is not None else mock_session.slot_id
            self._integration_mode = "MOCK_SANDBOX"
        elif self.library_path and os.path.isfile(self.library_path) and self.token_label:
            self._integration_mode = "LIVE_PRODUCTION"
        else:
            self._integration_mode = "NOT_CONFIGURED"

    @property
    def provider_name(self) -> str:
        return "PKCS11_HSM_SIGNER"

    @property
    def integration_mode(self) -> str:
        return self._integration_mode

    @staticmethod
    def _extract_key_label(key_ref: str) -> str:
        raw = str(key_ref or "").strip()
        if raw.startswith("pkcs11:") and "object=" in raw:
            for part in raw[len("pkcs11:") :].split(";"):
                if part.startswith("object="):
                    return part.split("=", 1)[1].strip()
        return raw

    def health_check(self) -> ProviderHealthStatus:
        if self._integration_mode == "NOT_CONFIGURED":
            return ProviderHealthStatus(
                provider_name=self.provider_name,
                provider_type="KeySignerProvider",
                backend="PKCS11_HSM",
                integration_mode="NOT_CONFIGURED",
                configured=False,
                reachable=False,
                details={
                    "library_path_configured": bool(self.library_path),
                    "library_file_exists": bool(self.library_path and os.path.isfile(self.library_path)),
                    "token_label_configured": bool(self.token_label),
                },
                error_code="PKCS11_HSM_NOT_CONFIGURED",
                error_message="PKCS#11 HSM kütüphanesi (.so) veya token etiketi yapılandırılmamıştır.",
            )
        return ProviderHealthStatus(
            provider_name=self.provider_name,
            provider_type="KeySignerProvider",
            backend="PKCS11_HSM_MOCK" if self._mock_session else "PKCS11_HSM",
            integration_mode=self._integration_mode,
            configured=True,
            reachable=self._mock_session is not None,
            details={"token_label": self.token_label, "slot_id": self.slot_id},
        )

    def get_key_metadata(self, key_ref: str) -> KeyMetadata | None:
        label = self._extract_key_label(key_ref)
        if self._mock_session is not None:
            info = self._mock_session.get_public_metadata(label)
            if info is None:
                return None
            return KeyMetadata(
                key_resource_id=f"pkcs11:token={self.token_label};object={label}",
                key_version=info["key_version"],
                algorithm=info["algorithm"],
                protection_level="HSM",
                public_key_pem=info["public_key_pem"],
                public_key_fingerprint_sha256=info["public_key_fingerprint_sha256"],
                provider_backend="PKCS11_HSM_MOCK",
                integration_mode="MOCK_SANDBOX",
                hsm_backed=True,
                qualified_e_signature_5070_equivalent=False,
            )
        return None

    def sign_canonical_json(
        self,
        payload: dict[str, Any],
        key_ref: str,
        algorithm: str = "ED25519",
        *,
        runtime_environment: str = "PRODUCTION",
    ) -> SignatureEnvelope:
        _ = runtime_environment
        alg = str(algorithm or "").upper().strip()
        msg_bytes = canonical_json_bytes(payload)
        payload_sha = hashlib.sha256(msg_bytes).hexdigest()
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if alg not in SUPPORTED_SIGNATURE_ALGORITHMS:
            return SignatureEnvelope(
                valid=False,
                algorithm=alg,
                key_resource_id=key_ref,
                key_version="unknown",
                protection_level="HSM",
                public_key_fingerprint_sha256=None,
                payload_sha256=payload_sha,
                signature_b64=None,
                canonicalization_standard="RFC-8785-JCS",
                signed_at_utc=now_utc,
                provider_backend="PKCS11_HSM",
                integration_mode=self._integration_mode,
                qualified_e_signature_5070_equivalent=False,
                error_codes=("UNSUPPORTED_SIGNATURE_ALGORITHM",),
                errors=(f"Desteklenmeyen PKCS#11 algoritması: '{algorithm}'.",),
            )

        if self._integration_mode == "NOT_CONFIGURED":
            return SignatureEnvelope(
                valid=False,
                algorithm=alg,
                key_resource_id=key_ref,
                key_version="unknown",
                protection_level="HSM",
                public_key_fingerprint_sha256=None,
                payload_sha256=payload_sha,
                signature_b64=None,
                canonicalization_standard="RFC-8785-JCS",
                signed_at_utc=now_utc,
                provider_backend="PKCS11_HSM",
                integration_mode="NOT_CONFIGURED",
                qualified_e_signature_5070_equivalent=False,
                error_codes=("PKCS11_HSM_NOT_CONFIGURED",),
                errors=("PKCS#11 HSM kütüphanesi veya token yapılandırılmamıştır.",),
            )

        label = self._extract_key_label(key_ref)
        meta = self.get_key_metadata(key_ref)
        if meta is None or self._mock_session is None:
            return SignatureEnvelope(
                valid=False,
                algorithm=alg,
                key_resource_id=key_ref,
                key_version="unknown",
                protection_level="HSM",
                public_key_fingerprint_sha256=None,
                payload_sha256=payload_sha,
                signature_b64=None,
                canonicalization_standard="RFC-8785-JCS",
                signed_at_utc=now_utc,
                provider_backend="PKCS11_HSM_MOCK" if self._mock_session else "PKCS11_HSM",
                integration_mode=self._integration_mode,
                qualified_e_signature_5070_equivalent=False,
                error_codes=("PKCS11_KEY_NOT_FOUND",),
                errors=(f"PKCS#11 HSM içinde '{label}' anahtarı bulunamadı veya canlı PKCS#11 sürücüsü bağlı değil.",),
            )

        try:
            sig_b64 = self._mock_session.c_sign_canonical(label, payload, alg)
        except Exception as exc:
            return SignatureEnvelope(
                valid=False,
                algorithm=alg,
                key_resource_id=meta.key_resource_id,
                key_version=meta.key_version,
                protection_level="HSM",
                public_key_fingerprint_sha256=meta.public_key_fingerprint_sha256,
                payload_sha256=payload_sha,
                signature_b64=None,
                canonicalization_standard="RFC-8785-JCS",
                signed_at_utc=now_utc,
                provider_backend=meta.provider_backend,
                integration_mode=self._integration_mode,
                qualified_e_signature_5070_equivalent=False,
                error_codes=("PKCS11_SIGN_FAILED",),
                errors=(str(exc),),
            )

        return SignatureEnvelope(
            valid=True,
            algorithm=alg,
            key_resource_id=meta.key_resource_id,
            key_version=meta.key_version,
            protection_level="HSM",
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
        _ = runtime_environment
        if self._integration_mode == "NOT_CONFIGURED":
            return False, "PKCS11_HSM_NOT_CONFIGURED: PKCS#11 HSM yapılandırılmamıştır.", None
        meta = self.get_key_metadata(key_ref)
        if meta is None or not meta.public_key_pem:
            return False, f"PKCS11_KEY_NOT_FOUND: '{key_ref}' açık anahtarı alınamadı.", meta
        ok, msg = verify_asymmetric_signature(payload, signature_b64, meta.public_key_pem, algorithm)
        return ok, msg, meta
