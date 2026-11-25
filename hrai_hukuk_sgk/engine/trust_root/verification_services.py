"""Unforgeable Cryptographic Verification Services for CALISORA @HukukSGK v1.0.3.1.

Closes Findings 1 & 2 from the v1.0.3 independent security review:
  - No caller can self-grant authorization via plain booleans (`legal_counsel_attestation_verified=True`,
    `source_acquisition_verified=True`, `technical_verification_passed=True`, `kvkk_data_residency_approved=True`).
  - Every verification result (`LegalCounselAttestationVerificationResult`, `SourceAcquisitionVerificationResult`,
    `TechnicalVerificationResult`, `KvkkDataResidencyVerificationResult`) is sealed at creation time with a
    process-ephemeral HMAC-SHA256 service seal (`_service_seal`) over its canonical fields.
  - `LegalCounselAttestationVerifier` directly verifies signer identity, role, enrollment, key version,
    algorithm, certificate/revocation status, validity window, authorized scope, exact calendar version,
    calendar bundle SHA-256, HukukSGK release version, and asymmetric RFC 8785 (JCS) signature.
  - `TechnicalVerificationService` executes actual Diyanet HTML snapshot + central audit log verification
    and computes the canonical calendar bundle SHA-256.
  - `KvkkDataResidencyVerifier` verifies KVKK m.9 Frankfurt (`europe-west3`) residency approval only via
    signed legal assessment + matching trust root config.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
from typing import Any, TypeVar

from ..attestation_verifier import (
    SIGNATURE_5070_NON_EQUIVALENCE_NOTICE,
    SUPPORTED_SIGNATURE_ALGORITHMS,
    canonical_json_bytes,
    parse_utc_timestamp,
    sign_canonical_payload,
    validate_authorized_approver_for_attestation,
    verify_asymmetric_signature,
)
from ..document_integrity import verify_archived_holiday_snapshots
from ..knowledge_card_validator import load_knowledge_cards, validate_central_audit_log
from ..precedent_verifier import load_precedent_registry
from ..source_validator import load_source_registry
from .interfaces import KeySignerProvider
from .models import (
    DEFAULT_GCP_REGION,
    KVKK_DATA_RESIDENCY_NOTICE,
    TRUST_ROOT_VERSION,
    KvkkDataResidencyVerificationResult,
    LegalCounselAttestationVerificationResult,
    SourceAcquisitionVerificationResult,
    TechnicalVerificationResult,
)

SHA256_RE = re.compile(r"^[a-f0-9]{64}$")

# Ephemeral per-process HMAC key used solely to prevent callers from manually instantiating
# forged `*VerificationResult(valid=True, ...)` objects and passing them to the production gate.
_RUNTIME_RESULT_SEAL_KEY: bytes = secrets.token_bytes(32)

_ResultT = TypeVar(
    "_ResultT",
    LegalCounselAttestationVerificationResult,
    SourceAcquisitionVerificationResult,
    TechnicalVerificationResult,
    KvkkDataResidencyVerificationResult,
)

_ALLOWED_COUNSEL_ROLES: set[str] = {
    "EXTERNAL_LEGAL_COUNSEL",
    "SENIOR_LABOR_LAW_COUNSEL",
}


def _compute_result_seal(result: Any) -> str:
    payload = {
        "result_type": type(result).__qualname__,
        "fields": result.to_dict(),
    }
    msg = canonical_json_bytes(payload)
    return hmac.new(_RUNTIME_RESULT_SEAL_KEY, msg, hashlib.sha256).hexdigest()


def seal_service_result(result: _ResultT) -> _ResultT:
    """Attach a process-ephemeral HMAC authenticity seal to a service-produced verification result."""
    seal = _compute_result_seal(result)
    return replace(result, _service_seal=seal)


def verify_service_result_authenticity(result: Any, expected_type: type[_ResultT]) -> bool:
    """Verify that `result` was genuinely produced by an internal verification service (not caller-forged)."""
    if not isinstance(result, expected_type):
        return False
    existing_seal = getattr(result, "_service_seal", "")
    if not isinstance(existing_seal, str) or len(existing_seal) != 64:
        return False
    expected_seal = _compute_result_seal(result)
    return hmac.compare_digest(existing_seal, expected_seal)


def compute_calendar_bundle_sha256(audit_log_data: dict[str, Any]) -> str:
    """Deterministically compute RFC 8785 (JCS) SHA-256 digest of the active holiday calendar audit bundle."""
    hca = audit_log_data.get("holiday_calendar_audit") or {}
    yearly = hca.get("yearly_records") or {}
    norm_yearly: dict[str, Any] = {}
    for yr_key in sorted(yearly.keys()):
        rec = yearly[yr_key] or {}
        norm_yearly[str(yr_key)] = {
            "year": int(rec.get("year") or int(yr_key)),
            "calendar_version": str(rec.get("calendar_version") or ""),
            "official_source_url": str(rec.get("official_source_url") or ""),
            "snapshot_id": str(rec.get("snapshot_id") or ""),
            "source_document_sha256": str(rec.get("source_document_sha256") or "").lower(),
            "extracted_dates_summary": dict(rec.get("extracted_dates_summary") or {}),
        }
    canonical_bundle = {
        "schema": "CALISORA_HOLIDAY_CALENDAR_BUNDLE_V1",
        "calendar_id": str(hca.get("calendar_id") or ""),
        "calendar_version": str(hca.get("calendar_version") or ""),
        "covered_years": list(hca.get("covered_years") or []),
        "yearly_records": norm_yearly,
    }
    return hashlib.sha256(canonical_json_bytes(canonical_bundle)).hexdigest()


def build_legal_counsel_release_attestation_signing_payload(
    *,
    attestation_id: str,
    nonce: str,
    approver_id: str,
    key_id: str,
    key_version: str,
    algorithm: str,
    signed_at_utc: str,
    calendar_version: str,
    calendar_sha256: str,
    hukuk_sgk_version: str,
    authorized_scope: str,
    ledger_id: str | None = None,
    ledger_head_entry_hash: str | None = None,
) -> dict[str, Any]:
    """Build RFC 8785 (JCS) canonical signing payload for an external legal counsel release attestation envelope."""
    return {
        "schema": "CALISORA_LEGAL_COUNSEL_RELEASE_ATTESTATION_V1",
        "attestation_id": str(attestation_id).strip(),
        "nonce": str(nonce).strip(),
        "approver_id": str(approver_id).strip(),
        "key_id": str(key_id).strip(),
        "key_version": str(key_version).strip(),
        "algorithm": str(algorithm).upper().strip(),
        "signed_at_utc": str(signed_at_utc).strip(),
        "calendar_version": str(calendar_version).strip(),
        "calendar_sha256": str(calendar_sha256).strip().lower(),
        "hukuk_sgk_version": str(hukuk_sgk_version).strip(),
        "authorized_scope": str(authorized_scope).strip(),
        "ledger_id": str(ledger_id).strip() if ledger_id else None,
        "ledger_head_entry_hash": str(ledger_head_entry_hash).strip().lower() if ledger_head_entry_hash else None,
        "qualified_e_signature_5070_equivalent": False,
    }


def create_signed_legal_counsel_attestation_envelope(
    *,
    attestation_id: str,
    nonce: str,
    approver_id: str,
    key_id: str,
    key_version: str,
    algorithm: str,
    signed_at_utc: str,
    calendar_version: str,
    calendar_sha256: str,
    hukuk_sgk_version: str,
    authorized_scope: str,
    private_key_pem: str,
    public_key_fingerprint_sha256: str,
    ledger_id: str | None = None,
    ledger_head_entry_hash: str | None = None,
    timestamp_trust_level: str = "INDEPENDENT_RFC3161_TSA",
) -> dict[str, Any]:
    """Helper to construct and cryptographically sign a legal counsel attestation envelope (RFC 8785 JCS)."""
    payload = build_legal_counsel_release_attestation_signing_payload(
        attestation_id=attestation_id,
        nonce=nonce,
        approver_id=approver_id,
        key_id=key_id,
        key_version=key_version,
        algorithm=algorithm,
        signed_at_utc=signed_at_utc,
        calendar_version=calendar_version,
        calendar_sha256=calendar_sha256,
        hukuk_sgk_version=hukuk_sgk_version,
        authorized_scope=authorized_scope,
        ledger_id=ledger_id,
        ledger_head_entry_hash=ledger_head_entry_hash,
    )
    sig_b64 = sign_canonical_payload(payload, private_key_pem, algorithm=algorithm)
    return {
        "schema": "CALISORA_LEGAL_COUNSEL_RELEASE_ATTESTATION_V1",
        "attestation_id": attestation_id,
        "nonce": nonce,
        "approver_id": approver_id,
        "key_id": key_id,
        "key_version": key_version,
        "algorithm": algorithm.upper().strip(),
        "public_key_fingerprint_sha256": public_key_fingerprint_sha256.lower(),
        "signed_at_utc": signed_at_utc,
        "calendar_version": calendar_version,
        "calendar_sha256": calendar_sha256.lower(),
        "hukuk_sgk_version": hukuk_sgk_version,
        "authorized_scope": authorized_scope,
        "ledger_id": ledger_id,
        "ledger_head_entry_hash": ledger_head_entry_hash.lower() if ledger_head_entry_hash else None,
        "timestamp_trust_level": timestamp_trust_level,
        "signature_b64": sig_b64,
        "qualified_e_signature_5070_equivalent": False,
    }


def _derive_certificate_status(approver_rec: dict[str, Any] | None, signing_time_utc: str) -> str:
    if not isinstance(approver_rec, dict):
        return "UNVERIFIED"
    if str(approver_rec.get("enrollment_status") or "").upper() != "ENROLLED":
        return "NOT_ENROLLED"
    st = str(approver_rec.get("status") or "").upper()
    if st == "REVOKED" or approver_rec.get("revoked_at_utc"):
        return "REVOKED"
    if st == "SUSPENDED":
        return "SUSPENDED"
    sign_dt = parse_utc_timestamp(signing_time_utc)
    vf_dt = parse_utc_timestamp(approver_rec.get("valid_from_utc"))
    vu_dt = parse_utc_timestamp(approver_rec.get("valid_until_utc"))
    if sign_dt is None or vf_dt is None or vu_dt is None:
        return "UNVERIFIED"
    if sign_dt < vf_dt or sign_dt > vu_dt:
        return "EXPIRED"
    return "ACTIVE_VERIFIED"


class LegalCounselAttestationVerifier:
    """Direct cryptographic verifier for external legal counsel release/calendar attestations.

    `SIGNED_LEGAL_ATTESTATION_VERIFIED` can ONLY be produced by this service after verifying:
      - Signer identity, role, enrollment, key trust tier, key_id, key_version, algorithm, fingerprint
      - Validity window, revocation / certificate status, and authorized scope
      - Exact binding to `calendar_version`, `calendar_sha256`, and `hukuk_sgk_version` (and ledger head if provided)
      - Real asymmetric signature over RFC 8785 (JCS) canonical payload
    """

    verifier_service_id: str = "CALISORA_LEGAL_COUNSEL_ATTESTATION_VERIFIER_V1031"

    def verify_attestation_envelope(
        self,
        envelope: dict[str, Any] | None,
        *,
        approvers_registry: dict[str, Any] | None,
        expected_calendar_version: str,
        expected_calendar_sha256: str,
        expected_hukuk_sgk_version: str,
        expected_ledger_id: str | None = None,
        expected_ledger_head_hash: str | None = None,
        runtime_environment: str = "PRODUCTION",
        kms_signer: KeySignerProvider | None = None,
    ) -> LegalCounselAttestationVerificationResult:
        if envelope is None:
            return seal_service_result(
                LegalCounselAttestationVerificationResult(
                    valid=False,
                    status="PENDING_SIGNED_EXTERNAL_ATTESTATION",
                    approver_id=None,
                    approver_role=None,
                    key_id=None,
                    key_version=None,
                    algorithm=None,
                    signed_at_utc=None,
                    certificate_status="UNVERIFIED",
                    authorized_scope_verified=False,
                    calendar_version=None,
                    calendar_sha256=None,
                    hukuk_sgk_version=None,
                    signature_verified=False,
                    verifier_service_id=self.verifier_service_id,
                    qualified_e_signature_5070_equivalent=False,
                    signature_legal_notice=SIGNATURE_5070_NON_EQUIVALENCE_NOTICE,
                    error_codes=("EXTERNAL_LEGAL_COUNSEL_ATTESTATION_REQUIRED",),
                    errors=(
                        "İmzalı harici hukuk müşaviri onay zarfı sunulmamıştır "
                        "(PENDING_SIGNED_EXTERNAL_ATTESTATION).",
                    ),
                )
            )

        if not isinstance(envelope, dict):
            return seal_service_result(
                LegalCounselAttestationVerificationResult(
                    valid=False,
                    status="ATTESTATION_REJECTED",
                    approver_id=None,
                    approver_role=None,
                    key_id=None,
                    key_version=None,
                    algorithm=None,
                    signed_at_utc=None,
                    certificate_status="UNVERIFIED",
                    authorized_scope_verified=False,
                    calendar_version=None,
                    calendar_sha256=None,
                    hukuk_sgk_version=None,
                    signature_verified=False,
                    verifier_service_id=self.verifier_service_id,
                    qualified_e_signature_5070_equivalent=False,
                    error_codes=("MALFORMED_LEGAL_ATTESTATION_ENVELOPE",),
                    errors=("Hukuk müşaviri onay zarfı geçerli sözlük (JSON nesnesi) biçiminde değildir.",),
                )
            )

        errors: list[str] = []
        error_codes: list[str] = []

        approver_id = str(envelope.get("approver_id") or "").strip()
        attestation_id = str(envelope.get("attestation_id") or "").strip()
        nonce = str(envelope.get("nonce") or "").strip()
        key_id = str(envelope.get("key_id") or "").strip()
        key_version = str(envelope.get("key_version") or "").strip()
        algorithm = str(envelope.get("algorithm") or "").upper().strip()
        signed_at_utc = str(envelope.get("signed_at_utc") or "").strip()
        cal_ver = str(envelope.get("calendar_version") or "").strip()
        cal_sha = str(envelope.get("calendar_sha256") or "").strip().lower()
        hs_ver = str(envelope.get("hukuk_sgk_version") or "").strip()
        auth_scope = str(envelope.get("authorized_scope") or "").strip()
        sig_b64 = str(envelope.get("signature_b64") or "").strip()
        att_fp = str(envelope.get("public_key_fingerprint_sha256") or "").strip().lower() or None
        ts_trust = str(envelope.get("timestamp_trust_level") or "SELF_ASSERTED_UNTRUSTED").upper().strip()
        kms_key_ref = str(envelope.get("kms_key_resource_id") or "").strip() or None
        env_ledger_id = str(envelope.get("ledger_id") or "").strip() or None
        env_ledger_head = str(envelope.get("ledger_head_entry_hash") or "").strip().lower() or None

        if envelope.get("qualified_e_signature_5070_equivalent") is True:
            error_codes.append("INVALID_5070_EQUIVALENCE_CLAIM")
            errors.append("Hukuk müşaviri teknik imzası 5070 s. Kanun NES eşdeğeri beyan edilemez.")

        if not attestation_id or len(nonce) < 12:
            error_codes.append("MISSING_ATTESTATION_REPLAY_FIELDS")
            errors.append("Onay zarfında attestation_id ve en az 12 karakterlik tekil nonce zorunludur.")
        if not sig_b64:
            error_codes.append("MISSING_ATTESTATION_SIGNATURE")
            errors.append("Onay zarfında kriptografik imza (signature_b64) eksiktir.")
        if algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
            error_codes.append("UNSUPPORTED_SIGNATURE_ALGORITHM")
            errors.append(f"Desteklenmeyen imza algoritması: '{algorithm}'.")

        # Version & Calendar SHA-256 bindings (prevents replaying an attestation for another version!)
        if cal_ver != str(expected_calendar_version).strip():
            error_codes.append("ATTESTATION_CALENDAR_VERSION_MISMATCH")
            errors.append(
                f"Onay zarfı takvim sürümü ('{cal_ver}') beklenen takvim sürümü ('{expected_calendar_version}') ile uyuşmuyor."
            )
        if not SHA256_RE.match(cal_sha) or cal_sha != str(expected_calendar_sha256).strip().lower():
            error_codes.append("ATTESTATION_CALENDAR_SHA256_MISMATCH")
            errors.append(
                f"Onay zarfı takvim SHA-256 özeti ('{cal_sha}') beklenen özet ('{expected_calendar_sha256}') ile uyuşmuyor."
            )
        if hs_ver != str(expected_hukuk_sgk_version).strip():
            error_codes.append("ATTESTATION_HUKUK_SGK_VERSION_MISMATCH")
            errors.append(
                f"Onay zarfı HukukSGK sürümü ('{hs_ver}') aktif sürüm ('{expected_hukuk_sgk_version}') ile uyuşmuyor."
            )
        if expected_ledger_id and env_ledger_id and env_ledger_id != expected_ledger_id:
            error_codes.append("ATTESTATION_LEDGER_BINDING_MISMATCH")
            errors.append(f"Onay zarfı ledger_id ('{env_ledger_id}') beklenen defterle ('{expected_ledger_id}') uyuşmuyor.")
        if expected_ledger_head_hash and env_ledger_head and env_ledger_head != expected_ledger_head_hash.lower():
            error_codes.append("ATTESTATION_LEDGER_BINDING_MISMATCH")
            errors.append("Onay zarfı ledger_head_entry_hash değeri aktif denetim zinciri başlığıyla uyuşmuyor.")

        # Validate approver identity, role, enrollment, key_version, validity window, certificate/revocation & scope
        approver_rec: dict[str, Any] | None = None
        approver_role: str | None = None
        cert_status = "UNVERIFIED"
        scope_verified = False

        if not isinstance(approvers_registry, dict):
            error_codes.append("APPROVERS_REGISTRY_UNAVAILABLE")
            errors.append("Yetkili onaylayan kimlik defteri (authorized_approvers) erişilemediğinden doğrulama reddedildi.")
        else:
            raw_rec = (approvers_registry.get("approvers") or {}).get(approver_id)
            cert_status = _derive_certificate_status(raw_rec, signed_at_utc)
            if isinstance(raw_rec, dict):
                approver_role = str(raw_rec.get("role") or "")
                if approver_role not in _ALLOWED_COUNSEL_ROLES:
                    error_codes.append("UNAUTHORIZED_APPROVER_ROLE")
                    errors.append(
                        f"'{approver_id}' rolü ('{approver_role}') hukuk müşaviri onayı vermeye yetkili değildir."
                    )

            required_op = auth_scope.split(":", 1)[0] if auth_scope else "HOLIDAY_CALENDAR_LEGAL_APPROVAL"
            target_year: int | None = None
            if ":" in auth_scope:
                suffix = auth_scope.split(":", 1)[1].strip()
                if suffix.isdigit():
                    target_year = int(suffix)
                elif "-" in suffix and suffix.split("-", 1)[0].isdigit():
                    target_year = int(suffix.split("-", 1)[0])

            appr_chk = validate_authorized_approver_for_attestation(
                approver_id=approver_id,
                approvers_registry=approvers_registry,
                signing_time_utc=signed_at_utc,
                required_operation=required_op,
                target_year=target_year,
                runtime_environment=runtime_environment,
                expected_key_id=key_id or None,
                expected_key_version=key_version or None,
                expected_algorithm=algorithm or None,
                expected_fingerprint=att_fp,
                timestamp_trust_level=ts_trust,
            )
            approver_rec = appr_chk.get("approver_record")
            if appr_chk["valid"]:
                scope_verified = True
            else:
                error_codes.extend(appr_chk["error_codes"])
                errors.extend(appr_chk["errors"])

            # In PRODUCTION, require PRODUCTION_QUALIFIED_COUNSEL key trust tier
            if (
                str(runtime_environment or "PRODUCTION").upper().strip() == "PRODUCTION"
                and isinstance(raw_rec, dict)
                and str(raw_rec.get("key_trust_tier") or "").upper() != "PRODUCTION_QUALIFIED_COUNSEL"
            ):
                error_codes.append("PRODUCTION_SIGNING_KEY_REQUIRED")
                errors.append(
                    f"PRODUCTION ortamında hukuk müşaviri onayı için key_trust_tier='PRODUCTION_QUALIFIED_COUNSEL' zorunludur."
                )

        # Direct cryptographic verification over RFC 8785 (JCS) canonical signing payload
        sig_verified = False
        signing_payload = build_legal_counsel_release_attestation_signing_payload(
            attestation_id=attestation_id,
            nonce=nonce,
            approver_id=approver_id,
            key_id=key_id,
            key_version=key_version,
            algorithm=algorithm,
            signed_at_utc=signed_at_utc,
            calendar_version=cal_ver,
            calendar_sha256=cal_sha,
            hukuk_sgk_version=hs_ver,
            authorized_scope=auth_scope,
            ledger_id=env_ledger_id,
            ledger_head_entry_hash=env_ledger_head,
        )

        if kms_key_ref:
            if kms_signer is None or kms_signer.integration_mode == "NOT_CONFIGURED":
                error_codes.append("LEGAL_ATTESTATION_VERIFIER_UNAVAILABLE")
                errors.append("KMS tabanlı hukuk müşaviri imza doğrulama servisi erişilemez/yapılandırılmamış (fail-closed).")
            elif sig_b64 and algorithm in SUPPORTED_SIGNATURE_ALGORITHMS:
                ok, msg, _ = kms_signer.verify_canonical_json(
                    signing_payload,
                    sig_b64,
                    kms_key_ref,
                    algorithm=algorithm,
                    runtime_environment=runtime_environment,
                )
                if ok:
                    sig_verified = True
                else:
                    error_codes.append("INVALID_LEGAL_COUNSEL_SIGNATURE")
                    errors.append(f"Hukuk müşaviri KMS imzası doğrulanamadı: {msg}")
        elif isinstance(approver_rec, dict) and approver_rec.get("public_key_pem") and sig_b64:
            ok, msg = verify_asymmetric_signature(
                signing_payload,
                sig_b64,
                str(approver_rec["public_key_pem"]),
                algorithm,
            )
            if ok:
                sig_verified = True
            else:
                error_codes.append("INVALID_LEGAL_COUNSEL_SIGNATURE")
                errors.append(f"Hukuk müşaviri kriptografik imzası geçersiz: {msg}")
        else:
            if "INVALID_LEGAL_COUNSEL_SIGNATURE" not in error_codes and "MISSING_ATTESTATION_SIGNATURE" not in error_codes:
                error_codes.append("LEGAL_ATTESTATION_VERIFIER_UNAVAILABLE")
                errors.append("İmza doğrulaması için kayıtlı açık anahtar bulunamadı.")

        valid = len(errors) == 0 and len(error_codes) == 0 and sig_verified and scope_verified
        return seal_service_result(
            LegalCounselAttestationVerificationResult(
                valid=valid,
                status="SIGNED_LEGAL_ATTESTATION_VERIFIED" if valid else "ATTESTATION_REJECTED",
                approver_id=approver_id or None,
                approver_role=approver_role,
                key_id=key_id or None,
                key_version=key_version or None,
                algorithm=algorithm or None,
                signed_at_utc=signed_at_utc or None,
                certificate_status=cert_status if not valid else "ACTIVE_VERIFIED",
                authorized_scope_verified=scope_verified,
                calendar_version=cal_ver or None,
                calendar_sha256=cal_sha or None,
                hukuk_sgk_version=hs_ver or None,
                signature_verified=sig_verified,
                verifier_service_id=self.verifier_service_id,
                qualified_e_signature_5070_equivalent=False,
                signature_legal_notice=SIGNATURE_5070_NON_EQUIVALENCE_NOTICE,
                error_codes=tuple(sorted(set(error_codes))),
                errors=tuple(errors),
            )
        )


class TechnicalVerificationService:
    """Executes real Stage-1 technical integrity checks (archived Diyanet HTML snapshots + central audit log)."""

    verifier_service_id: str = "CALISORA_TECHNICAL_VERIFICATION_SERVICE_V1031"

    def verify_repository_technical_integrity(
        self,
        *,
        project_root: str | Path | None = None,
    ) -> TechnicalVerificationResult:
        root = Path(project_root) if project_root is not None else Path(__file__).resolve().parent.parent.parent
        errors: list[str] = []
        error_codes: list[str] = []

        audit_path = root / "config" / "verification_audit_log.json"
        if not audit_path.is_file():
            return seal_service_result(
                TechnicalVerificationResult(
                    valid=False,
                    status="TECHNICAL_FAILED",
                    calendar_version="",
                    calendar_sha256="",
                    hukuk_sgk_version=TRUST_ROOT_VERSION,
                    verified_years=(),
                    audit_log_valid=False,
                    snapshots_verified=False,
                    verifier_service_id=self.verifier_service_id,
                    error_codes=("TECHNICAL_AUDIT_LOG_MISSING",),
                    errors=("Merkezi denetim defteri (verification_audit_log.json) bulunamadı.",),
                )
            )

        audit_data = json.loads(audit_path.read_text(encoding="utf-8"))
        hca = audit_data.get("holiday_calendar_audit") or {}
        cal_ver = str(hca.get("calendar_version") or "")
        hs_ver = str(audit_data.get("schema_version") or TRUST_ROOT_VERSION)
        cal_sha = compute_calendar_bundle_sha256(audit_data)

        snap_res = verify_archived_holiday_snapshots(project_root=root)
        snapshots_ok = bool(snap_res.get("ok"))
        verified_years = tuple(int(y) for y in (snap_res.get("verified_years") or ()))
        if not snapshots_ok:
            error_codes.append("ARCHIVED_HOLIDAY_SNAPSHOTS_FAILED")
            errors.append("Arşivlenmiş 2024–2027 Diyanet HTML kopyaları teknik doğrulamadan geçemedi.")

        sources = load_source_registry(root / "config" / "legal_sources_registry.json")
        precedents = load_precedent_registry(root / "config" / "yargitay_precedents.json")
        cards = load_knowledge_cards(root / "rag_kb", sources, precedents)
        audit_rep = validate_central_audit_log(audit_data, sources, precedents, cards, project_root=root)
        audit_ok = bool(audit_rep.valid)
        if not audit_ok:
            error_codes.append("CENTRAL_AUDIT_LOG_VALIDATION_FAILED")
            errors.extend(f.message for f in audit_rep.flags)

        valid = snapshots_ok and audit_ok and len(errors) == 0
        return seal_service_result(
            TechnicalVerificationResult(
                valid=valid,
                status="TECHNICAL_VERIFIED" if valid else "TECHNICAL_FAILED",
                calendar_version=cal_ver,
                calendar_sha256=cal_sha,
                hukuk_sgk_version=hs_ver,
                verified_years=verified_years,
                audit_log_valid=audit_ok,
                snapshots_verified=snapshots_ok,
                verifier_service_id=self.verifier_service_id,
                error_codes=tuple(sorted(set(error_codes))),
                errors=tuple(errors),
            )
        )


def build_kvkk_m9_assessment_signing_payload(
    *,
    assessment_reference: str,
    nonce: str,
    primary_region: str,
    kvkk_m9_decision: str,
    approver_id: str,
    key_id: str,
    key_version: str,
    algorithm: str,
    approved_at_utc: str,
) -> dict[str, Any]:
    """Build RFC 8785 (JCS) canonical signing payload for a KVKK m.9 data residency legal assessment."""
    return {
        "schema": "CALISORA_KVKK_M9_DATA_RESIDENCY_ASSESSMENT_V1",
        "assessment_reference": str(assessment_reference).strip(),
        "nonce": str(nonce).strip(),
        "primary_region": str(primary_region).strip(),
        "kvkk_m9_decision": str(kvkk_m9_decision).upper().strip(),
        "approver_id": str(approver_id).strip(),
        "key_id": str(key_id).strip(),
        "key_version": str(key_version).strip(),
        "algorithm": str(algorithm).upper().strip(),
        "approved_at_utc": str(approved_at_utc).strip(),
        "qualified_e_signature_5070_equivalent": False,
    }


class KvkkDataResidencyVerifier:
    """Verifies KVKK m.9 (GCP Frankfurt europe-west3) data residency approval from signed legal assessment + config."""

    verifier_service_id: str = "CALISORA_KVKK_M9_RESIDENCY_VERIFIER_V1031"

    def verify_kvkk_m9_assessment(
        self,
        assessment_envelope: dict[str, Any] | None,
        *,
        trust_root_config: dict[str, Any] | None = None,
        approvers_registry: dict[str, Any] | None = None,
        runtime_environment: str = "PRODUCTION",
    ) -> KvkkDataResidencyVerificationResult:
        kvkk_cfg = (trust_root_config or {}).get("kvkk_and_data_residency") or {}
        region = str(kvkk_cfg.get("primary_region") or DEFAULT_GCP_REGION)

        if assessment_envelope is None:
            return seal_service_result(
                KvkkDataResidencyVerificationResult(
                    valid=False,
                    status="PENDING_KVKK_M9_DATA_RESIDENCY_ASSESSMENT",
                    primary_region=region,
                    assessment_reference=None,
                    approved_by_approver_id=None,
                    approved_at_utc=None,
                    signature_verified=False,
                    verifier_service_id=self.verifier_service_id,
                    notice=KVKK_DATA_RESIDENCY_NOTICE,
                    error_codes=("KVKK_DATA_RESIDENCY_ASSESSMENT_PENDING",),
                    errors=(KVKK_DATA_RESIDENCY_NOTICE,),
                )
            )

        errors: list[str] = []
        error_codes: list[str] = []
        if not isinstance(assessment_envelope, dict):
            return seal_service_result(
                KvkkDataResidencyVerificationResult(
                    valid=False,
                    status="REJECTED",
                    primary_region=region,
                    assessment_reference=None,
                    approved_by_approver_id=None,
                    approved_at_utc=None,
                    signature_verified=False,
                    verifier_service_id=self.verifier_service_id,
                    notice=KVKK_DATA_RESIDENCY_NOTICE,
                    error_codes=("KVKK_ASSESSMENT_MALFORMED",),
                    errors=("KVKK m.9 değerlendirme zarfı geçerli sözlük biçiminde olmalıdır.",),
                )
            )

        # If trust_root_config explicitly marks kvkk_m9_assessment_approved=False, do not silently override
        if trust_root_config is not None and kvkk_cfg.get("kvkk_m9_assessment_approved") is not True:
            error_codes.append("KVKK_CONFIG_APPROVAL_NOT_ENABLED")
            errors.append("production_trust_root_config.json içinde kvkk_m9_assessment_approved=true değildir.")

        ref = str(assessment_envelope.get("assessment_reference") or "").strip()
        nonce = str(assessment_envelope.get("nonce") or "").strip()
        env_region = str(assessment_envelope.get("primary_region") or "").strip()
        decision = str(assessment_envelope.get("kvkk_m9_decision") or "").upper().strip()
        approver_id = str(assessment_envelope.get("approver_id") or "").strip()
        key_id = str(assessment_envelope.get("key_id") or "").strip()
        key_version = str(assessment_envelope.get("key_version") or "").strip()
        algorithm = str(assessment_envelope.get("algorithm") or "").upper().strip()
        approved_at = str(assessment_envelope.get("approved_at_utc") or "").strip()
        sig_b64 = str(assessment_envelope.get("signature_b64") or "").strip()

        if not ref or len(nonce) < 12:
            error_codes.append("KVKK_ASSESSMENT_INCOMPLETE")
            errors.append("KVKK m.9 değerlendirmesinde assessment_reference ve en az 12 karakterlik nonce zorunludur.")
        if env_region != region:
            error_codes.append("KVKK_REGION_MISMATCH")
            errors.append(f"KVKK m.9 değerlendirme bölgesi ('{env_region}') hedef bölge ('{region}') ile uyuşmuyor.")
        if decision != "APPROVED":
            error_codes.append("KVKK_DATA_RESIDENCY_ASSESSMENT_PENDING")
            errors.append(f"KVKK m.9 kararı onaylı değildir (mevcut: '{decision}').")

        sig_verified = False
        if not isinstance(approvers_registry, dict):
            error_codes.append("APPROVERS_REGISTRY_UNAVAILABLE")
            errors.append("KVKK m.9 onaylayan kimlik doğrulaması için authorized_approvers gereklidir.")
        else:
            raw_rec = (approvers_registry.get("approvers") or {}).get(approver_id)
            if isinstance(raw_rec, dict) and str(raw_rec.get("role") or "") not in _ALLOWED_COUNSEL_ROLES:
                error_codes.append("UNAUTHORIZED_APPROVER_ROLE")
                errors.append(f"'{approver_id}' KVKK m.9 hukuki onayı vermeye yetkili rolde değildir.")
            appr_chk = validate_authorized_approver_for_attestation(
                approver_id=approver_id,
                approvers_registry=approvers_registry,
                signing_time_utc=approved_at,
                required_operation="KVKK_M9_DATA_RESIDENCY_APPROVAL",
                target_year=None,
                runtime_environment=runtime_environment,
                expected_key_id=key_id or None,
                expected_key_version=key_version or None,
                expected_algorithm=algorithm or None,
                timestamp_trust_level=str(assessment_envelope.get("timestamp_trust_level") or "SELF_ASSERTED_UNTRUSTED"),
            )
            if not appr_chk["valid"]:
                error_codes.extend(appr_chk["error_codes"])
                errors.extend(appr_chk["errors"])
            elif appr_chk.get("approver_record") and appr_chk["approver_record"].get("public_key_pem") and sig_b64:
                payload = build_kvkk_m9_assessment_signing_payload(
                    assessment_reference=ref,
                    nonce=nonce,
                    primary_region=env_region,
                    kvkk_m9_decision=decision,
                    approver_id=approver_id,
                    key_id=key_id,
                    key_version=key_version,
                    algorithm=algorithm,
                    approved_at_utc=approved_at,
                )
                ok, msg = verify_asymmetric_signature(
                    payload,
                    sig_b64,
                    str(appr_chk["approver_record"]["public_key_pem"]),
                    algorithm,
                )
                if ok:
                    sig_verified = True
                else:
                    error_codes.append("KVKK_ASSESSMENT_INVALID_SIGNATURE")
                    errors.append(f"KVKK m.9 değerlendirme imzası doğrulanamadı: {msg}")
            else:
                error_codes.append("KVKK_ASSESSMENT_INVALID_SIGNATURE")
                errors.append("KVKK m.9 değerlendirmesi imzasız veya açık anahtarsızdır.")

        valid = len(errors) == 0 and len(error_codes) == 0 and sig_verified
        return seal_service_result(
            KvkkDataResidencyVerificationResult(
                valid=valid,
                status="APPROVED" if valid else "PENDING_KVKK_M9_DATA_RESIDENCY_ASSESSMENT",
                primary_region=region,
                assessment_reference=ref or None,
                approved_by_approver_id=approver_id or None,
                approved_at_utc=approved_at or None,
                signature_verified=sig_verified,
                verifier_service_id=self.verifier_service_id,
                notice=KVKK_DATA_RESIDENCY_NOTICE,
                error_codes=tuple(sorted(set(error_codes))),
                errors=tuple(errors),
            )
        )
