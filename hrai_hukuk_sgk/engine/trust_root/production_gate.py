"""Hardened Production Authorization Gate (`ProductionAuthorizationProvider`) for CALISORA @HukukSGK v1.0.3.1.

Core Security Principle (v1.0.3.1 Acceptance Criterion):
  NO APPLICATION CALLER CAN SELF-GRANT VERIFICATION AUTHORITY!

Closes Findings 1 & 2 from the v1.0.3 independent security review:
  1. Caller-supplied booleans (`legal_counsel_attestation_verified`, `source_acquisition_verified`,
     `technical_verification_passed`, `kvkk_data_residency_approved`) and caller-supplied plain status
     strings (`external_legal_counsel_signoff_status`) are STRICTLY FORBIDDEN and actively rejected
     with `CALLER_SELF_ASSERTED_BOOLEAN_FORBIDDEN` (`DENIED_SECURITY_VIOLATION`).
  2. External legal counsel signoff (`SIGNED_LEGAL_ATTESTATION_VERIFIED`) is accepted ONLY when directly
     verified by `LegalCounselAttestationVerifier` (checking signer identity, role, enrollment, key version,
     algorithm, certificate/revocation status, validity window, scope, calendar version, calendar SHA-256,
     HukukSGK version, and RFC 8785 asymmetric signature) and authenticated via runtime service seal.
  3. Source acquisition verification has NO unsafe default `True`: missing evidence fails closed
     (`SOURCE_ACQUISITION_EVIDENCE_MISSING`), and callback-sourced evidence (`MOCK_CALLBACK`) is rejected
     in `PRODUCTION` (`CALLBACK_FETCHER_NOT_ALLOWED_IN_PRODUCTION`).
  4. Technical verification and KVKK m.9 data residency must come from authenticated service verification
     results (`TechnicalVerificationService`, `KvkkDataResidencyVerifier`), NEVER plain booleans.
  5. Mock/sandbox or unconfigured providers (`MOCK_SANDBOX`, `NOT_CONFIGURED`) can NEVER authorize production use,
     and `qualified_e_signature_5070_equivalent` is ALWAYS `False` in v1.0.3.x.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..attestation_verifier import verify_attestation_ledger
from .interfaces import (
    ExternalTrustAnchorProvider,
    ImmutableEvidenceStorageProvider,
    KeySignerProvider,
    ProductionAuthorizationProvider,
    SourceAcquisitionProvider,
    TimestampAuthorityProvider,
)
from .models import (
    KVKK_DATA_RESIDENCY_NOTICE,
    LAW_5070_V103_BOUNDARY_NOTICE,
    TRUST_ROOT_VERSION,
    KvkkDataResidencyVerificationResult,
    LegalCounselAttestationVerificationResult,
    ProductionAuthorizationDecision,
    SourceAcquisitionEvidenceEnvelope,
    SourceAcquisitionVerificationResult,
    TechnicalVerificationResult,
)
from .verification_services import (
    KvkkDataResidencyVerifier,
    LegalCounselAttestationVerifier,
    TechnicalVerificationService,
    verify_service_result_authenticity,
)

_SECURITY_VIOLATION_CODES: frozenset[str] = frozenset(
    {
        "AUDIT_CHAIN_TAMPERING_DETECTED",
        "TRUST_ANCHOR_SAME_PROJECT_VIOLATION",
        "TRUST_ANCHOR_IN_APP_JSON_FORBIDDEN",
        "TRUST_ANCHOR_INVALID_KMS_SIGNATURE",
        "UNTRUSTED_SELF_DECLARED_ANCHOR_IN_LEDGER",
        "CALLER_SELF_ASSERTED_BOOLEAN_FORBIDDEN",
        "FORGED_OR_UNAUTHENTICATED_VERIFICATION_RESULT",
        "INVALID_5070_EQUIVALENCE_CLAIM",
        "INVALID_TLS_HISTORICAL_PROOF_CLAIM",
    }
)


class DefaultProductionAuthorizationProvider(ProductionAuthorizationProvider):
    """Fail-closed 3-way production authorization gate uniting KMS/HSM, TSA, WORM, External Anchor, Legal Attestation, Source Acquisition, Technical Integrity & KVKK m.9."""

    def __init__(
        self,
        *,
        kms_signer: KeySignerProvider | None = None,
        tsa_provider: TimestampAuthorityProvider | None = None,
        worm_storage: ImmutableEvidenceStorageProvider | None = None,
        trust_anchor_provider: ExternalTrustAnchorProvider | None = None,
        source_acquisition_provider: SourceAcquisitionProvider | None = None,
        legal_attestation_verifier: LegalCounselAttestationVerifier | None = None,
        technical_verification_service: TechnicalVerificationService | None = None,
        kvkk_residency_verifier: KvkkDataResidencyVerifier | None = None,
        trust_root_config: dict[str, Any] | None = None,
        project_root: str | Path | None = None,
    ) -> None:
        self.kms_signer = kms_signer
        self.tsa_provider = tsa_provider
        self.worm_storage = worm_storage
        self.trust_anchor_provider = trust_anchor_provider
        self.source_acquisition_provider = source_acquisition_provider
        self.legal_attestation_verifier = legal_attestation_verifier or LegalCounselAttestationVerifier()
        self.technical_verification_service = technical_verification_service or TechnicalVerificationService()
        self.kvkk_residency_verifier = kvkk_residency_verifier or KvkkDataResidencyVerifier()
        self.trust_root_config = trust_root_config
        self.project_root = Path(project_root) if project_root is not None else None

    @property
    def provider_name(self) -> str:
        return "CALISORA_PRODUCTION_AUTHORIZATION_GATE_V1031"

    @property
    def integration_mode(self) -> str:
        modes = self._collect_integration_modes().values()
        if "NOT_CONFIGURED" in modes:
            return "NOT_CONFIGURED"
        if "MOCK_SANDBOX" in modes:
            return "MOCK_SANDBOX"
        return "LIVE_PRODUCTION"

    def _collect_integration_modes(self) -> dict[str, str]:
        return {
            "kms_signer": self.kms_signer.integration_mode if self.kms_signer else "NOT_CONFIGURED",
            "tsa_provider": self.tsa_provider.integration_mode if self.tsa_provider else "NOT_CONFIGURED",
            "worm_storage": self.worm_storage.integration_mode if self.worm_storage else "NOT_CONFIGURED",
            "trust_anchor_provider": (
                self.trust_anchor_provider.integration_mode if self.trust_anchor_provider else "NOT_CONFIGURED"
            ),
            "source_acquisition_provider": (
                self.source_acquisition_provider.integration_mode if self.source_acquisition_provider else "NOT_CONFIGURED"
            ),
        }

    def evaluate_production_authorization(
        self,
        *,
        ledger: dict[str, Any],
        approvers_registry: dict[str, Any] | None,
        technical_verification_result: TechnicalVerificationResult | None = None,
        legal_counsel_attestation_envelope: dict[str, Any] | None = None,
        legal_counsel_attestation_result: LegalCounselAttestationVerificationResult | None = None,
        source_acquisition_envelope: SourceAcquisitionEvidenceEnvelope | dict[str, Any] | None = None,
        source_acquisition_expected_raw_bytes: bytes | None = None,
        source_acquisition_result: SourceAcquisitionVerificationResult | None = None,
        kvkk_assessment_envelope: dict[str, Any] | None = None,
        kvkk_residency_result: KvkkDataResidencyVerificationResult | None = None,
        runtime_environment: str = "PRODUCTION",
        expected_app_project_id: str | None = None,
        **forbidden_caller_claims: Any,
    ) -> ProductionAuthorizationDecision:
        env_norm = str(runtime_environment or "PRODUCTION").upper().strip()
        modes = self._collect_integration_modes()

        blocking_codes: list[str] = []
        blocking_reasons: list[str] = []

        # 0. STRICT ANTI-SELF-GRANT GUARD: Reject ANY caller-supplied boolean or plain signoff claim!
        if forbidden_caller_claims:
            claim_names = sorted(forbidden_caller_claims.keys())
            blocking_codes.append("CALLER_SELF_ASSERTED_BOOLEAN_FORBIDDEN")
            blocking_reasons.append(
                f"Çağıran tarafından gönderilen ham doğrulama bayrakları/statüleri ({claim_names}) "
                f"güven kaynağı olarak kabul edilemez; yalnızca kriptografik doğrulama servisi çıktıları geçerlidir."
            )

        # 1. Stage 1 — Technical Verification (must be an authentic TechnicalVerificationResult)
        tech_res: TechnicalVerificationResult | None = None
        if technical_verification_result is not None:
            if not verify_service_result_authenticity(technical_verification_result, TechnicalVerificationResult):
                blocking_codes.append("FORGED_OR_UNAUTHENTICATED_VERIFICATION_RESULT")
                blocking_reasons.append(
                    "technical_verification_result doğrulama servisi mührünü taşımıyor (sahte/elle üretilmiş nesne reddedildi)."
                )
            else:
                tech_res = technical_verification_result
        elif self.project_root is not None:
            tech_res = self.technical_verification_service.verify_repository_technical_integrity(
                project_root=self.project_root
            )
        else:
            blocking_codes.append("TECHNICAL_VERIFICATION_RESULT_MISSING")
            blocking_reasons.append(
                "Aşama 1 teknik doğrulama servisi çıktısı (TechnicalVerificationResult) sağlanmamıştır."
            )

        tech_passed = bool(tech_res is not None and tech_res.valid and tech_res.status == "TECHNICAL_VERIFIED")
        tech_status = "TECHNICAL_VERIFIED" if tech_passed else "TECHNICAL_FAILED"
        if tech_res is not None and not tech_passed:
            blocking_codes.append("TECHNICAL_VERIFICATION_FAILED")
            blocking_codes.extend(tech_res.error_codes)
            blocking_reasons.extend(tech_res.errors or ("Aşama 1 teknik kaynak/içerik doğrulaması başarısızdır.",))

        expected_cal_ver = tech_res.calendar_version if tech_res is not None else TRUST_ROOT_VERSION
        expected_cal_sha = tech_res.calendar_sha256 if tech_res is not None else ""
        expected_hs_ver = tech_res.hukuk_sgk_version if tech_res is not None else TRUST_ROOT_VERSION
        ledger_entries = ledger.get("entries") if isinstance(ledger, dict) else None
        ledger_head_hash = (
            str(ledger_entries[-1].get("entry_hash") or "")
            if isinstance(ledger_entries, list) and ledger_entries and isinstance(ledger_entries[-1], dict)
            else None
        )

        # 2. Stage 2 — External Legal Counsel Cryptographic Attestation (DIRECT verification, NEVER caller boolean!)
        legal_res: LegalCounselAttestationVerificationResult | None = None
        if legal_counsel_attestation_envelope is not None:
            legal_res = self.legal_attestation_verifier.verify_attestation_envelope(
                legal_counsel_attestation_envelope,
                approvers_registry=approvers_registry,
                expected_calendar_version=expected_cal_ver,
                expected_calendar_sha256=expected_cal_sha,
                expected_hukuk_sgk_version=expected_hs_ver,
                expected_ledger_id=str(ledger.get("ledger_id") or "") or None,
                expected_ledger_head_hash=ledger_head_hash,
                runtime_environment=env_norm,
                kms_signer=self.kms_signer,
            )
        elif legal_counsel_attestation_result is not None:
            if not verify_service_result_authenticity(
                legal_counsel_attestation_result, LegalCounselAttestationVerificationResult
            ):
                blocking_codes.append("FORGED_OR_UNAUTHENTICATED_VERIFICATION_RESULT")
                blocking_reasons.append(
                    "legal_counsel_attestation_result doğrulama servisi mührünü taşımıyor (elle üretilmiş sonuç reddedildi)."
                )
            else:
                legal_res = legal_counsel_attestation_result
                # Cross-check exact calendar version, calendar SHA-256 & HukukSGK version binding!
                if tech_res is not None:
                    if legal_res.calendar_version != tech_res.calendar_version:
                        blocking_codes.append("ATTESTATION_CALENDAR_VERSION_MISMATCH")
                        blocking_reasons.append(
                            f"Hukuk müşaviri onayındaki takvim sürümü ('{legal_res.calendar_version}') aktif takvim sürümü "
                            f"('{tech_res.calendar_version}') ile uyuşmuyor."
                        )
                    if legal_res.calendar_sha256 != tech_res.calendar_sha256:
                        blocking_codes.append("ATTESTATION_CALENDAR_SHA256_MISMATCH")
                        blocking_reasons.append(
                            "Hukuk müşaviri onayındaki takvim SHA-256 özeti aktif takvim özetiyle uyuşmuyor."
                        )
                    if legal_res.hukuk_sgk_version != tech_res.hukuk_sgk_version:
                        blocking_codes.append("ATTESTATION_HUKUK_SGK_VERSION_MISMATCH")
                        blocking_reasons.append(
                            f"Hukuk müşaviri onayındaki HukukSGK sürümü ('{legal_res.hukuk_sgk_version}') "
                            f"aktif sürüm ('{tech_res.hukuk_sgk_version}') ile uyuşmuyor."
                        )
        else:
            legal_res = self.legal_attestation_verifier.verify_attestation_envelope(
                None,
                approvers_registry=approvers_registry,
                expected_calendar_version=expected_cal_ver,
                expected_calendar_sha256=expected_cal_sha,
                expected_hukuk_sgk_version=expected_hs_ver,
                runtime_environment=env_norm,
                kms_signer=self.kms_signer,
            )

        version_binding_ok = not any(
            c in blocking_codes
            for c in (
                "ATTESTATION_CALENDAR_VERSION_MISMATCH",
                "ATTESTATION_CALENDAR_SHA256_MISMATCH",
                "ATTESTATION_HUKUK_SGK_VERSION_MISMATCH",
            )
        )
        legal_ok = bool(
            legal_res is not None
            and legal_res.valid
            and legal_res.signature_verified
            and legal_res.authorized_scope_verified
            and legal_res.certificate_status == "ACTIVE_VERIFIED"
            and legal_res.status == "SIGNED_LEGAL_ATTESTATION_VERIFIED"
            and legal_res.qualified_e_signature_5070_equivalent is False
            and version_binding_ok
        )
        if legal_ok:
            legal_status = "SIGNED_LEGAL_ATTESTATION_VERIFIED"
            effective_signoff = "SIGNED_LEGAL_ATTESTATION_VERIFIED"
        else:
            if legal_res is not None and legal_res.status == "PENDING_SIGNED_EXTERNAL_ATTESTATION":
                legal_status = "PENDING_SIGNED_EXTERNAL_ATTESTATION"
                effective_signoff = "PENDING_SIGNED_EXTERNAL_ATTESTATION"
            else:
                legal_status = "ATTESTATION_REJECTED"
                effective_signoff = "PENDING_SIGNED_EXTERNAL_ATTESTATION"
            if legal_res is not None:
                blocking_codes.extend(legal_res.error_codes)
                blocking_reasons.extend(legal_res.errors)
            if "EXTERNAL_LEGAL_COUNSEL_ATTESTATION_REQUIRED" not in blocking_codes and not legal_ok:
                blocking_codes.append("EXTERNAL_LEGAL_COUNSEL_ATTESTATION_REQUIRED")
                blocking_reasons.append(
                    "Kriptografik olarak doğrulanmış harici yetkili hukuk müşaviri onayı olmadan üretim yetkisi verilemez."
                )

        # 3. Stage 3 — Source Acquisition & TLS Verification (NO default True; fails closed when missing!)
        acq_res: SourceAcquisitionVerificationResult | None = None
        if source_acquisition_envelope is not None:
            if self.source_acquisition_provider is None:
                blocking_codes.append("SOURCE_ACQUISITION_VERIFIER_UNAVAILABLE")
                blocking_reasons.append(
                    "Kaynak edinim doğrulama servisi (SourceAcquisitionProvider) tanımlı değildir."
                )
            else:
                acq_res = self.source_acquisition_provider.verify_acquisition_evidence_result(
                    source_acquisition_envelope,
                    expected_raw_bytes=source_acquisition_expected_raw_bytes,
                    runtime_environment=env_norm,
                )
        elif source_acquisition_result is not None:
            if not verify_service_result_authenticity(source_acquisition_result, SourceAcquisitionVerificationResult):
                blocking_codes.append("FORGED_OR_UNAUTHENTICATED_VERIFICATION_RESULT")
                blocking_reasons.append(
                    "source_acquisition_result doğrulama servisi mührünü taşımıyor (elle üretilmiş sonuç reddedildi)."
                )
            else:
                acq_res = source_acquisition_result
        else:
            blocking_codes.append("SOURCE_ACQUISITION_EVIDENCE_MISSING")
            blocking_reasons.append(
                "Kaynak edinim kanıt zarfı veya doğrulanmış SourceAcquisitionVerificationResult sağlanmamıştır (varsayılan reddedilir)."
            )

        acq_ok = False
        if acq_res is not None:
            if not acq_res.valid:
                blocking_codes.extend(acq_res.error_codes)
                blocking_reasons.extend(acq_res.errors)
            if env_norm == "PRODUCTION" and (acq_res.fetcher_mode != "LIVE_HTTPS" or not acq_res.production_tls_verified):
                blocking_codes.append("CALLBACK_FETCHER_NOT_ALLOWED_IN_PRODUCTION")
                blocking_reasons.append(
                    f"PRODUCTION ortamında yalnızca gerçek canlı HTTPS/TLS doğrulamalı kaynak edinimi "
                    f"(fetcher_mode='LIVE_HTTPS', production_tls_verified=True) kabul edilir "
                    f"(bulunan: fetcher_mode='{acq_res.fetcher_mode}', production_tls_verified={acq_res.production_tls_verified})."
                )
            if acq_res.tls_alone_proves_historical_content is not False:
                blocking_codes.append("INVALID_TLS_HISTORICAL_PROOF_CLAIM")
                blocking_reasons.append("tls_alone_proves_historical_content mutlaka false olmalıdır.")
            acq_ok = bool(
                acq_res.valid
                and acq_res.worm_verified
                and acq_res.tsa_verified
                and acq_res.signature_verified
                and acq_res.tls_verified
                and acq_res.tls_alone_proves_historical_content is False
                and (env_norm != "PRODUCTION" or (acq_res.fetcher_mode == "LIVE_HTTPS" and acq_res.production_tls_verified))
            )

        # 4. Stage 4 — KVKK m.9 Data Residency Verification (NEVER plain caller boolean!)
        kvkk_res: KvkkDataResidencyVerificationResult | None = None
        if kvkk_assessment_envelope is not None:
            kvkk_res = self.kvkk_residency_verifier.verify_kvkk_m9_assessment(
                kvkk_assessment_envelope,
                trust_root_config=self.trust_root_config,
                approvers_registry=approvers_registry,
                runtime_environment=env_norm,
            )
        elif kvkk_residency_result is not None:
            if not verify_service_result_authenticity(kvkk_residency_result, KvkkDataResidencyVerificationResult):
                blocking_codes.append("FORGED_OR_UNAUTHENTICATED_VERIFICATION_RESULT")
                blocking_reasons.append(
                    "kvkk_residency_result doğrulama servisi mührünü taşımıyor (elle üretilmiş sonuç reddedildi)."
                )
            else:
                kvkk_res = kvkk_residency_result
        else:
            kvkk_res = self.kvkk_residency_verifier.verify_kvkk_m9_assessment(
                None,
                trust_root_config=self.trust_root_config,
                approvers_registry=approvers_registry,
                runtime_environment=env_norm,
            )

        kvkk_ok = bool(kvkk_res is not None and kvkk_res.valid and kvkk_res.signature_verified and kvkk_res.status == "APPROVED")
        if not kvkk_ok:
            if kvkk_res is not None:
                blocking_codes.extend(kvkk_res.error_codes)
                blocking_reasons.extend(kvkk_res.errors)
            else:
                blocking_codes.append("KVKK_DATA_RESIDENCY_ASSESSMENT_PENDING")
                blocking_reasons.append(KVKK_DATA_RESIDENCY_NOTICE)

        # 5. Live Production Infrastructure Checks (NEVER satisfied by MOCK_SANDBOX or NOT_CONFIGURED!)
        all_live_prod = all(m == "LIVE_PRODUCTION" for m in modes.values())
        if not all_live_prod:
            blocking_codes.append("LIVE_PRODUCTION_PROVIDERS_REQUIRED")
            blocking_reasons.append(
                f"Gerçek üretim servisleri (GCP Cloud KMS HSM, RFC 3161 TSA, GCS WORM, harici güven çapası, "
                f"canlı HTTPS kaynak edinimi) tamamlanmadan üretim yetkisi verilemez (mevcut modlar: {modes})."
            )

        if env_norm != "PRODUCTION":
            blocking_codes.append("NON_PRODUCTION_RUNTIME_ENVIRONMENT")
            blocking_reasons.append(f"Üretim yetkisi yalnızca PRODUCTION ortamında verilebilir (mevcut: '{env_norm}').")

        # 6. External Trust Anchor Fetch & Ledger Verification (fail-closed!)
        anchor_valid = False
        anchor_hsm_backed = False
        ledger_externally_immutable = False
        if self.trust_anchor_provider is None:
            blocking_codes.append("EXTERNAL_TRUST_ANCHOR_UNAVAILABLE_OR_INVALID")
            blocking_reasons.append("Harici güven kökü sağlayıcısı (ExternalTrustAnchorProvider) tanımlı değildir.")
        else:
            ledger_id = str(ledger.get("ledger_id") or "")
            anchor_rec = self.trust_anchor_provider.fetch_and_verify_trust_anchor(
                ledger_id,
                expected_app_project_id=expected_app_project_id,
                runtime_environment=env_norm,
            )
            if not anchor_rec.valid:
                blocking_codes.extend(anchor_rec.error_codes)
                blocking_reasons.extend(anchor_rec.errors)
            else:
                anchor_valid = True
                anchor_hsm_backed = anchor_rec.kms_protection_level == "HSM"
                if not anchor_hsm_backed:
                    blocking_codes.append("KMS_HSM_PROTECTION_REQUIRED_IN_PRODUCTION")
                    blocking_reasons.append(
                        f"Harici güven kökü imzası HSM koruma seviyesinde olmalıdır (bulunan: '{anchor_rec.kms_protection_level}')."
                    )
                led_chk = verify_attestation_ledger(
                    ledger,
                    approvers_registry=approvers_registry,
                    runtime_environment=env_norm,
                    expected_checkpoint_head_hash=anchor_rec.expected_checkpoint_head_hash,
                    expected_checkpoint_entry_count=anchor_rec.expected_checkpoint_entry_count,
                    expected_chain_digest_sha256=anchor_rec.expected_chain_digest_sha256,
                    require_signed_checkpoints=True,
                    trust_anchor_source="INDEPENDENT_WORM_STORE",
                )
                ledger_externally_immutable = bool(led_chk["valid"] and led_chk["externally_verified_immutable"])
                if not ledger_externally_immutable:
                    blocking_codes.extend(led_chk["error_codes"])
                    blocking_reasons.extend(led_chk["errors"])

        checks = {
            "no_caller_self_asserted_booleans": len(forbidden_caller_claims) == 0,
            "runtime_environment_is_production": env_norm == "PRODUCTION",
            "all_providers_live_production": all_live_prod,
            "technical_verification_passed": tech_passed,
            "external_trust_anchor_valid": anchor_valid,
            "kms_hsm_protection_verified": anchor_hsm_backed,
            "ledger_externally_verified_immutable": ledger_externally_immutable,
            "source_acquisition_verified": acq_ok,
            "legal_counsel_attestation_verified": legal_ok,
            "kvkk_data_residency_approved": kvkk_ok,
        }

        authorized = all(checks.values()) and len(blocking_codes) == 0

        if authorized:
            prod_status = "AUTHORIZED"
        elif any(c in _SECURITY_VIOLATION_CODES for c in blocking_codes):
            prod_status = "DENIED_SECURITY_VIOLATION"
        elif not all_live_prod:
            prod_status = "DENIED_MOCK_OR_UNCONFIGURED_PROVIDER"
        elif not legal_ok:
            prod_status = "DENIED_PENDING_LEGAL_ATTESTATION"
        else:
            prod_status = "DENIED_PENDING_PRODUCTION_TRUST_ROOT"

        return ProductionAuthorizationDecision(
            technical_verification_status=tech_status,
            legal_counsel_attestation_status=legal_status,
            production_authorization_status=prod_status,
            production_use_authorized=authorized,
            external_legal_counsel_signoff_status=effective_signoff,
            qualified_e_signature_5070_equivalent=False,
            signature_legal_notice=LAW_5070_V103_BOUNDARY_NOTICE,
            kvkk_data_residency_status=(
                "APPROVED" if kvkk_ok else "PENDING_KVKK_M9_DATA_RESIDENCY_ASSESSMENT"
            ),
            kvkk_data_residency_notice=KVKK_DATA_RESIDENCY_NOTICE,
            runtime_environment=env_norm,
            integration_modes=modes,
            checks=checks,
            blocking_codes=tuple(sorted(set(blocking_codes))),
            blocking_reasons=tuple(blocking_reasons),
            legal_attestation_verification=legal_res.to_dict() if legal_res is not None else None,
            source_acquisition_verification=acq_res.to_dict() if acq_res is not None else None,
            technical_verification=tech_res.to_dict() if tech_res is not None else None,
            kvkk_residency_verification=kvkk_res.to_dict() if kvkk_res is not None else None,
        )
