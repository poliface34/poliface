"""Independent Security & Legal Acceptance Gate for Law No. 5070 Qualified Electronic Signatures (v1.0.4.5).

Strict Architectural Separation (ADR Sections 3, 4, 6, 8 & v1.0.4.1–v1.0.4.5 Security Hardening):
  - Technical cryptographic verification (`cryptographic_signature_valid`), ETSI profile compliance
    (`profile_compliant`), verified SSCD/sole-control evidence (`sscd_control_evidence`), Law No. 5070
    legal qualification (`legal_5070_qualification_status`), and production acceptance
    (`qualified_e_signature_5070_production_accepted`) are reported and enforced separately.
  - Rejects caller booleans (`CALLER_SELF_ASSERTED_BOOLEAN_FORBIDDEN`), plain caller SSCD dicts
    (`CALLER_UNVERIFIED_SSCD_DICT_FORBIDDEN`), forged/unsealed verification results
    (`FORGED_OR_UNAUTHENTICATED_VERIFICATION_RESULT`, `FORGED_OR_UNAUTHENTICATED_SSCD_EVIDENCE_RESULT`),
    KMS/HSM signatures (`NON_5070_TECHNICAL_SIGNATURE`), XSW / duplicate XML ID / invalid transform
    pipeline attacks, `INDETERMINATE` evidences (`DENIED_INDETERMINATE_EVIDENCE`), and sandbox/mock CAs
    or SSCD issuers in `PRODUCTION`.
"""

from __future__ import annotations

import hashlib
from typing import Any

from ..attestation_verifier import canonical_json_bytes
from .cades_xades_verifier import verify_esign5070_result_authenticity
from .models import (
    PROFILE_RANK,
    AcceptanceGate5070Decision,
    QualifiedSignature5070VerificationResult,
    normalize_etsi_profile,
)
from .sscd_evidence import verify_sscd_evidence_result_authenticity

_SECURITY_VIOLATION_CODES: frozenset[str] = frozenset(
    {
        "CALLER_SELF_ASSERTED_BOOLEAN_FORBIDDEN",
        "CALLER_UNVERIFIED_SSCD_DICT_FORBIDDEN",
        "FORGED_OR_UNAUTHENTICATED_VERIFICATION_RESULT",
        "FORGED_OR_UNAUTHENTICATED_SSCD_EVIDENCE_RESULT",
        "SANDBOX_ESHS_CA_REJECTED_IN_PRODUCTION",
        "SANDBOX_SSCD_ISSUER_REJECTED_IN_PRODUCTION",
        "SSCD_EVIDENCE_SIGNER_CERT_BINDING_MISMATCH",
        "SSCD_EVIDENCE_SIGNATURE_INVALID",
        "EVIDENCE_BUNDLE_SHA256_MISMATCH",
        "KMS_HSM_NOT_5070_QUALIFIED_SIGNATURE",
        "XML_XXE_OR_DOCTYPE_FORBIDDEN",
        "XADES_DUPLICATE_XML_ID_DETECTED",
        "XADES_XSW_MULTIPLE_OR_NESTED_SIGNATURES",
        "XADES_XSW_DATA_REF_HIDDEN_INSIDE_SIGNATURE",
        "XADES_XSW_UNSIGNED_CONTENT_OUTSIDE_SIGNED_SCOPE",
        "XADES_XSW_SIGNED_PROPERTIES_OUTSIDE_SIGNATURE",
        "XADES_XSW_QUALIFYING_PROPERTIES_TARGET_MISMATCH",
        "XADES_UNSUPPORTED_OR_FORBIDDEN_TRANSFORM",
        "XADES_TRANSFORM_INVALID_INPUT_TYPE",
        "XADES_BASE64_TRANSFORM_DECODE_FAILED",
        "XADES_TRANSFORM_XML_REPARSE_FAILED",
        "XADES_EXCESSIVE_TRANSFORMS_COUNT",
    }
)


def verify_evidence_bundle_integrity(result: QualifiedSignature5070VerificationResult) -> bool:
    """Recompute RFC 8785 (JCS) SHA-256 of the VerificationEvidenceBundle and verify exact match."""
    eb = result.evidence_bundle
    unsigned_bundle = {
        "schema_version": eb.schema_version,
        "bundle_id": eb.bundle_id,
        "created_at_utc": eb.created_at_utc,
        "trust_list_version": eb.trust_list_version,
        "items": [it.to_dict() for it in eb.items],
        "ocsp_crl_evidences": list(eb.ocsp_crl_evidences),
        "timestamp_evidences": list(eb.timestamp_evidences),
    }
    expected_sha = hashlib.sha256(canonical_json_bytes(unsigned_bundle)).hexdigest()
    return expected_sha == eb.bundle_sha256


class Default5070AcceptanceGate:
    """Fail-closed independent Security & Legal Acceptance Gate for Law No. 5070 NES CAdES/XAdES signatures."""

    def evaluate_5070_acceptance(
        self,
        verification_result: QualifiedSignature5070VerificationResult | None,
        *,
        required_min_profile: str = "B-B",
        runtime_environment: str = "PRODUCTION",
        **forbidden_caller_claims: Any,
    ) -> AcceptanceGate5070Decision:
        env_norm = str(runtime_environment or "PRODUCTION").upper().strip()
        blocking_codes: list[str] = []
        blocking_reasons: list[str] = []

        # 0. Anti-self-grant guard: reject ANY caller-supplied boolean/status claim!
        if forbidden_caller_claims:
            names = sorted(forbidden_caller_claims.keys())
            blocking_codes.append("CALLER_SELF_ASSERTED_BOOLEAN_FORBIDDEN")
            blocking_reasons.append(
                f"Çağıran tarafından gönderilen ham 5070 doğrulama bayrakları ({names}) kabul edilemez; "
                f"yalnızca mühürlü doğrulama servisi çıktısı değerlendirilir."
            )

        min_prof, _ = normalize_etsi_profile(required_min_profile)
        if min_prof is None:
            blocking_codes.append("INVALID_REQUIRED_MIN_PROFILE")
            blocking_reasons.append(f"Geçersiz minimum ETSI profil politikası: '{required_min_profile}'.")
            min_prof = "B-B"

        # 1. Require genuine service-sealed QualifiedSignature5070VerificationResult
        if verification_result is None:
            blocking_codes.append("VERIFICATION_RESULT_MISSING")
            blocking_reasons.append("QualifiedSignature5070VerificationResult sağlanmamıştır.")
            return AcceptanceGate5070Decision(
                cryptographic_signature_valid=False,
                profile_compliant=False,
                technical_5070_security_status="SECURITY_FAILED",
                legal_5070_qualification_status="REJECTED",
                production_5070_acceptance_status=(
                    "DENIED_SECURITY_VIOLATION"
                    if "CALLER_SELF_ASSERTED_BOOLEAN_FORBIDDEN" in blocking_codes
                    else "DENIED_VERIFICATION_MISSING"
                ),
                qualified_e_signature_5070_verified=False,
                qualified_e_signature_5070_production_accepted=False,
                runtime_environment=env_norm,
                integration_mode="NOT_CONFIGURED",
                checks={
                    "no_caller_self_asserted_booleans": len(forbidden_caller_claims) == 0,
                    "service_result_authentic": False,
                },
                blocking_codes=tuple(sorted(set(blocking_codes))),
                blocking_reasons=tuple(blocking_reasons),
                verification_result=None,
            )

        authentic = verify_esign5070_result_authenticity(verification_result)
        if not authentic:
            blocking_codes.append("FORGED_OR_UNAUTHENTICATED_VERIFICATION_RESULT")
            blocking_reasons.append(
                "QualifiedSignature5070VerificationResult doğrulama servisi mührünü taşımıyor (sahte/elle üretilmiş nesne reddedildi)."
            )
            return AcceptanceGate5070Decision(
                cryptographic_signature_valid=False,
                profile_compliant=False,
                technical_5070_security_status="SECURITY_FAILED",
                legal_5070_qualification_status="REJECTED",
                production_5070_acceptance_status="DENIED_SECURITY_VIOLATION",
                qualified_e_signature_5070_verified=False,
                qualified_e_signature_5070_production_accepted=False,
                runtime_environment=env_norm,
                integration_mode=str(getattr(verification_result, "integration_mode", "UNKNOWN")),
                checks={
                    "no_caller_self_asserted_booleans": len(forbidden_caller_claims) == 0,
                    "service_result_authentic": False,
                },
                blocking_codes=tuple(sorted(set(blocking_codes))),
                blocking_reasons=tuple(blocking_reasons),
                verification_result=None,
            )

        res = verification_result
        # Surface any security-violation error codes emitted by verifier (e.g. XSW, duplicate ID, plain dict SSCD)
        for code in res.error_codes:
            if code in _SECURITY_VIOLATION_CODES:
                blocking_codes.append(code)

        bundle_ok = verify_evidence_bundle_integrity(res)
        if not bundle_ok:
            blocking_codes.append("EVIDENCE_BUNDLE_SHA256_MISMATCH")
            blocking_reasons.append("VerificationEvidenceBundle SHA-256 bütünlük doğrulaması başarısızdır.")

        # 2. Check KMS / HSM misclassification block
        kms_blocked = bool(res.law_5070_assessment.kms_hsm_misclassification_blocked)
        if kms_blocked:
            blocking_codes.append("KMS_HSM_NOT_5070_QUALIFIED_SIGNATURE")
            blocking_reasons.append(
                "KMS/Cloud KMS/sunucu HSM teknik imzası 5070 sayılı Kanun kapsamında güvenli elektronik imza olarak kabul edilemez."
            )

        # 3. Cryptographic & ETSI profile checks
        crypto_ok = bool(res.cryptographic_signature_valid)
        if not crypto_ok:
            blocking_codes.append("CRYPTOGRAPHIC_SIGNATURE_INVALID")
            blocking_reasons.append("Kriptografik imza doğrulaması başarısızdır.")

        achieved = res.profile_compliance.achieved_profile
        min_profile_ok = bool(
            res.profile_compliance.profile_compliant
            and achieved in PROFILE_RANK
            and PROFILE_RANK[achieved] >= PROFILE_RANK[min_prof]
            and achieved != "NONE"
        )
        if not min_profile_ok:
            blocking_codes.append("ETSI_PROFILE_BELOW_REQUIRED_MINIMUM")
            blocking_reasons.append(
                f"İmza profili ('{achieved}') zorunlu asgari profili ('{min_prof}') veya talep edilen profili karşılamıyor."
            )

        # 4. BTK ESHS Trust & Sandbox CA isolation
        eshs_ok = bool(res.eshs_trust.valid and res.eshs_trust.btk_provider_authorized and res.eshs_trust.ca_chain_verified)
        if res.eshs_trust.is_sandbox_ca and env_norm == "PRODUCTION":
            blocking_codes.append("SANDBOX_ESHS_CA_REJECTED_IN_PRODUCTION")
            blocking_reasons.append("Sandbox/test ESHS CA sertifikası PRODUCTION ortamında kesinlikle reddedilir.")
        if not eshs_ok:
            blocking_codes.extend(res.eshs_trust.error_codes or ("BTK_ESHS_TRUST_FAILED",))
            blocking_reasons.extend(res.eshs_trust.errors or ("BTK ESHS yetki veya CA zinciri doğrulaması başarısızdır.",))

        # 5. Revocation check (INDETERMINATE MUST NOT open the legal acceptance gate!)
        rev_ok = bool(res.revocation.status == "GOOD" and res.revocation.conclusion == "PASSED")
        if not rev_ok:
            blocking_codes.extend(res.revocation.error_codes or ("REVOCATION_NOT_GOOD",))
            blocking_reasons.extend(res.revocation.errors or (f"İptal durumu GOOD değildir (durum='{res.revocation.status}').",))

        # 6. Independent verification of SscdControlEvidenceVerificationResult (BLOCKER 1 defense-in-depth!)
        sscd = res.sscd_control_evidence
        sscd_authentic = bool(sscd is not None and verify_sscd_evidence_result_authenticity(sscd))
        if sscd is not None and not sscd_authentic:
            blocking_codes.append("FORGED_OR_UNAUTHENTICATED_SSCD_EVIDENCE_RESULT")
            blocking_reasons.append("SSCD kanıt nesnesi doğrulama servisi HMAC mührünü taşımıyor.")
        if sscd is not None and sscd.is_sandbox_issuer and env_norm == "PRODUCTION":
            blocking_codes.append("SANDBOX_SSCD_ISSUER_REJECTED_IN_PRODUCTION")
            blocking_reasons.append("Sandbox/test SSCD yayımlayıcısı PRODUCTION ortamında kesinlikle reddedilir.")

        sscd_ok = bool(
            sscd is not None
            and sscd_authentic
            and sscd.valid
            and sscd.conclusion == "VERIFIED"
            and sscd.signature_verified
            and sscd.issuer_authorized
            and sscd.issuer_cert_chain_verified
            and sscd.issuer_revocation_status == "GOOD"
            and sscd.sole_control_attested
            and sscd.pin_or_biometric_activation_verified
            and sscd.sscd_device_certified
            and not (sscd.is_sandbox_issuer and env_norm == "PRODUCTION")
        )
        if not sscd_ok:
            if sscd is None:
                blocking_codes.append("VERIFIED_SSCD_CONTROL_EVIDENCE_REQUIRED")
                blocking_reasons.append("5070 m.4/c ve m.6 için kriptografik olarak doğrulanmış SscdControlEvidenceVerificationResult zorunludur.")
            else:
                blocking_codes.extend(sscd.error_codes)
                blocking_reasons.extend(sscd.errors)

        # 7. Law No. 5070 Articles 4 / 6 / 9 legal assessment
        law_ok = bool(
            res.law_5070_assessment.overall_5070_conclusion == "VERIFIED"
            and res.law_5070_assessment.article_4_conclusion == "PASSED"
            and res.law_5070_assessment.article_6_sscd_conclusion == "PASSED"
            and res.law_5070_assessment.article_9_nes_conclusion == "PASSED"
            and res.qualified_e_signature_5070_verified is True
            and sscd_ok
        )
        if not law_ok:
            blocking_codes.extend(res.law_5070_assessment.error_codes)
            blocking_reasons.extend(res.law_5070_assessment.errors)

        # 8. Live Production Infrastructure Guard (NEVER open production gate on MOCK_SANDBOX / NOT_CONFIGURED!)
        live_prod_modes_ok = (
            res.integration_mode == "LIVE_PRODUCTION"
            and res.eshs_trust.integration_mode == "LIVE_PRODUCTION"
            and res.revocation.integration_mode == "LIVE_PRODUCTION"
            and (sscd is not None and sscd.integration_mode == "LIVE_PRODUCTION")
        )
        if not live_prod_modes_ok:
            blocking_codes.append("LIVE_5070_PROVIDERS_REQUIRED_FOR_PRODUCTION")
            blocking_reasons.append(
                f"5070 üretim kabul kapısı yalnızca canlı üretim servisleriyle (LIVE_PRODUCTION) açılabilir "
                f"(mevcut: verifier='{res.integration_mode}', eshs='{res.eshs_trust.integration_mode}', "
                f"revocation='{res.revocation.integration_mode}', sscd='{sscd.integration_mode if sscd else 'NONE'}')."
            )

        if env_norm != "PRODUCTION":
            blocking_codes.append("NON_PRODUCTION_RUNTIME_ENVIRONMENT")
            blocking_reasons.append(
                f"Üretim kabul yetkisi yalnızca PRODUCTION ortamında verilebilir (mevcut: '{env_norm}')."
            )

        checks = {
            "no_caller_self_asserted_booleans": len(forbidden_caller_claims) == 0,
            "service_result_authentic": True,
            "evidence_bundle_integrity_verified": bundle_ok,
            "cryptographic_signature_valid": crypto_ok,
            "profile_meets_minimum": min_profile_ok,
            "not_kms_or_server_hsm_signature": not kms_blocked,
            "btk_eshs_trust_verified": eshs_ok,
            "not_sandbox_ca_in_production": not (res.eshs_trust.is_sandbox_ca and env_norm == "PRODUCTION"),
            "revocation_status_good": rev_ok,
            "sscd_control_evidence_verified": sscd_ok,
            "law_5070_m4_m6_m9_verified": law_ok,
            "live_production_providers_active": live_prod_modes_ok,
            "runtime_environment_is_production": env_norm == "PRODUCTION",
        }

        prod_accepted = all(checks.values()) and len(blocking_codes) == 0

        if (
            crypto_ok
            and min_profile_ok
            and bundle_ok
            and eshs_ok
            and rev_ok
            and not (res.eshs_trust.is_sandbox_ca and env_norm == "PRODUCTION")
        ):
            tech_status = "SECURITY_VERIFIED"
        elif (
            crypto_ok
            and (res.revocation.conclusion == "INDETERMINATE" or res.eshs_trust.conclusion == "INDETERMINATE")
            and not any(c in _SECURITY_VIOLATION_CODES for c in blocking_codes)
        ):
            tech_status = "SECURITY_INDETERMINATE"
        else:
            tech_status = "SECURITY_FAILED"

        if kms_blocked:
            legal_status = "NON_5070_TECHNICAL_SIGNATURE"
        elif law_ok and not (res.eshs_trust.is_sandbox_ca and env_norm == "PRODUCTION"):
            legal_status = "QUALIFIED_5070_VERIFIED"
        elif (
            res.law_5070_assessment.overall_5070_conclusion == "INDETERMINATE"
            or res.revocation.conclusion == "INDETERMINATE"
            or res.eshs_trust.conclusion == "INDETERMINATE"
            or (sscd is not None and sscd.conclusion == "INDETERMINATE")
        ) and not any(c in _SECURITY_VIOLATION_CODES for c in blocking_codes):
            legal_status = "INDETERMINATE"
        else:
            legal_status = "REJECTED"

        if prod_accepted:
            prod_status = "ACCEPTED_5070_PRODUCTION"
        elif any(c in _SECURITY_VIOLATION_CODES for c in blocking_codes):
            prod_status = "DENIED_SECURITY_VIOLATION"
        elif legal_status == "INDETERMINATE" or tech_status == "SECURITY_INDETERMINATE":
            prod_status = "DENIED_INDETERMINATE_EVIDENCE"
        elif not live_prod_modes_ok:
            prod_status = "DENIED_MOCK_OR_UNCONFIGURED_PROVIDER"
        else:
            prod_status = "DENIED_5070_REQUIREMENTS_NOT_MET"

        dedup_reasons: list[str] = []
        for r in blocking_reasons:
            if r and r not in dedup_reasons:
                dedup_reasons.append(r)

        return AcceptanceGate5070Decision(
            cryptographic_signature_valid=crypto_ok,
            profile_compliant=min_profile_ok,
            technical_5070_security_status=tech_status,
            legal_5070_qualification_status=legal_status,
            production_5070_acceptance_status=prod_status,
            qualified_e_signature_5070_verified=bool(
                law_ok and not (res.eshs_trust.is_sandbox_ca and env_norm == "PRODUCTION")
            ),
            qualified_e_signature_5070_production_accepted=prod_accepted,
            runtime_environment=env_norm,
            integration_mode=res.integration_mode,
            checks=checks,
            blocking_codes=tuple(sorted(set(blocking_codes))),
            blocking_reasons=tuple(dedup_reasons),
            verification_result=res.to_dict(),
        )
