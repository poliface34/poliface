"""Honest Live Production Integration Probe for CALISORA @HukukSGK v1.0.4.

Inspects `config/production_trust_root_config.json`, `config/esign_5070_config.json`, and runtime
environment variables to report the EXACT status of:
  1. Core Production Trust Root services (GCP Cloud KMS HSM, GCS WORM Bucket Lock, Cloud SQL PostgreSQL,
     Independent RFC 3161 TSA, PKCS#11 HSM, External Security Project Trust Anchor, Live HTTPS Source Acquisition).
  2. Law No. 5070 NES & CAdES/XAdES services (ADR Section 7):
     - `btk_eshs_trust_list` (`EshsTrustListProvider`)
     - `certificate_revocation_ocsp_crl` (`CertificateRevocationProvider`)
     - `qualified_signature_5070_verifier` (`QualifiedSignature5070VerifierProvider`)

Reports exact 5-state probe statuses (`NOT_CONFIGURED`, `CONFIGURED_UNVERIFIED`, `LIVE_VERIFIED`,
`FAILED`, `INDETERMINATE`) and NEVER claims live integration or Law No. 5070 production readiness
when real BTK/ESHS inputs, OCSP/CRL responders, TSA endpoints, or GCP/HSM services are absent.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from ..esign5070.cades_xades_verifier import DefaultQualifiedSignature5070Verifier
from ..esign5070.eshs_trust import DefaultEshsTrustListProvider
from ..esign5070.models import LAW_5070_SEPARATION_NOTICE, VALID_PROBE_STATUSES
from ..esign5070.revocation import DefaultCertificateRevocationProvider
from .external_trust_anchor import GcpExternalTrustAnchorProvider
from .gcp_adapters import GcpCloudKmsSignerAdapter, GcpCloudStorageWormAdapter
from .models import (
    DEFAULT_GCP_REGION,
    KVKK_DATA_RESIDENCY_NOTICE,
    LAW_5070_V103_BOUNDARY_NOTICE,
    TRUST_ROOT_VERSION,
)
from .pkcs11_adapter import Pkcs11HsmSignerAdapter
from .production_gate import DefaultProductionAuthorizationProvider
from .rfc3161_tsa import Rfc3161TimestampAuthorityAdapter
from .source_acquisition import DefaultSourceAcquisitionProvider
from .verification_services import (
    KvkkDataResidencyVerifier,
    LegalCounselAttestationVerifier,
    TechnicalVerificationService,
)


def _derive_legacy_service_probe_status(health_dict: dict[str, Any]) -> str:
    mode = str(health_dict.get("integration_mode") or "NOT_CONFIGURED").upper()
    configured = bool(health_dict.get("configured"))
    reachable = bool(health_dict.get("reachable"))
    if not configured or mode == "NOT_CONFIGURED":
        return "NOT_CONFIGURED"
    if mode == "LIVE_PRODUCTION" and reachable:
        return "LIVE_VERIFIED"
    return "CONFIGURED_UNVERIFIED"


def run_live_integration_probe(
    *,
    config_path: str | Path | None = None,
    esign_5070_config_path: str | Path | None = None,
    project_root: str | Path | None = None,
) -> dict[str, Any]:
    """Probe live production trust root and Law No. 5070 configurations without making false claims."""
    root = Path(project_root) if project_root is not None else Path(__file__).resolve().parent.parent.parent
    cfg_file = Path(config_path) if config_path is not None else root / "config" / "production_trust_root_config.json"
    cfg = json.loads(cfg_file.read_text(encoding="utf-8")) if cfg_file.is_file() else {}

    esign_cfg_file = (
        Path(esign_5070_config_path) if esign_5070_config_path is not None else root / "config" / "esign_5070_config.json"
    )
    esign_cfg = json.loads(esign_cfg_file.read_text(encoding="utf-8")) if esign_cfg_file.is_file() else {}

    gcp_cfg = cfg.get("gcp_primary", {})
    tsa_cfg = cfg.get("rfc3161_tsa", {})
    pkcs_cfg = cfg.get("pkcs11_alternative", {})
    anchor_cfg = cfg.get("external_trust_anchor", {})

    region = str(os.environ.get("CALISORA_GCP_REGION") or gcp_cfg.get("region") or DEFAULT_GCP_REGION)
    sec_project = os.environ.get("CALISORA_GCP_SECURITY_PROJECT") or gcp_cfg.get("security_project_id")
    app_project = os.environ.get("CALISORA_GCP_APP_PROJECT") or gcp_cfg.get("app_project_id")
    kms_ring = os.environ.get("CALISORA_GCP_KMS_KEY_RING") or (gcp_cfg.get("cloud_kms") or {}).get("key_ring")
    worm_bucket = os.environ.get("CALISORA_GCS_WORM_BUCKET") or (gcp_cfg.get("cloud_storage_worm") or {}).get("bucket_name")
    cloud_sql_conn = os.environ.get("CALISORA_CLOUD_SQL_INSTANCE") or (gcp_cfg.get("cloud_sql_postgresql") or {}).get(
        "instance_connection_name"
    )
    tsa_url = os.environ.get("CALISORA_RFC3161_TSA_URL") or tsa_cfg.get("tsa_url")
    tsa_ca_path = os.environ.get("CALISORA_RFC3161_TSA_CA_PATH") or tsa_cfg.get("trusted_ca_pem_path")
    tsa_ca_pem = Path(tsa_ca_path).read_text(encoding="utf-8") if (tsa_ca_path and Path(tsa_ca_path).is_file()) else None
    manifest_uri = os.environ.get("CALISORA_TRUST_ANCHOR_MANIFEST_URI") or anchor_cfg.get("manifest_uri")
    pkcs_lib = os.environ.get("CALISORA_PKCS11_LIBRARY_PATH") or pkcs_cfg.get("library_path")
    pkcs_token = os.environ.get("CALISORA_PKCS11_TOKEN_LABEL") or pkcs_cfg.get("token_label")

    # Law No. 5070 external service settings (separate BTK registry vs ESHS CA bundle + OCSP/CRL)
    btk_cfg = esign_cfg.get("btk_eshs_registry", {})
    ca_cfg = esign_cfg.get("eshs_ca_certificate_bundles", {})
    rev_cfg = esign_cfg.get("revocation_services", {})
    btk_url = os.environ.get("CALISORA_BTK_ESHS_REGISTRY_URL") or btk_cfg.get("registry_source_url")
    eshs_ca_ref = os.environ.get("CALISORA_ESHS_CA_BUNDLE_PATH") or ca_cfg.get("bundle_source_ref")
    ocsp_url = os.environ.get("CALISORA_OCSP_URL") or rev_cfg.get("ocsp_responder_url")
    crl_url = os.environ.get("CALISORA_CRL_URL") or rev_cfg.get("crl_distribution_url")

    kms_adapter = GcpCloudKmsSignerAdapter(project_id=sec_project, region=region, key_ring=kms_ring)
    worm_adapter = GcpCloudStorageWormAdapter(project_id=sec_project, bucket_name=worm_bucket, region=region)
    tsa_adapter = Rfc3161TimestampAuthorityAdapter(tsa_url=tsa_url, trusted_ca_pem=tsa_ca_pem)
    pkcs_adapter = Pkcs11HsmSignerAdapter(library_path=pkcs_lib, token_label=pkcs_token)
    anchor_provider = GcpExternalTrustAnchorProvider(
        manifest_uri=manifest_uri,
        security_project_id=sec_project,
        app_project_id=app_project,
        worm_storage=worm_adapter,
        kms_signer=kms_adapter,
        tsa_provider=tsa_adapter,
    )
    acq_provider = DefaultSourceAcquisitionProvider(
        worm_storage=worm_adapter,
        tsa_provider=tsa_adapter,
        kms_signer=kms_adapter,
        signing_key_ref=None,
    )
    tech_service = TechnicalVerificationService()
    legal_verifier = LegalCounselAttestationVerifier()
    kvkk_verifier = KvkkDataResidencyVerifier()

    # Law No. 5070 v1.0.4 providers (honestly NOT_CONFIGURED / CONFIGURED_UNVERIFIED without live verified inputs)
    eshs_provider = DefaultEshsTrustListProvider(
        btk_registry_source_url=btk_url,
        eshs_ca_bundle_source_ref=eshs_ca_ref,
        live_verified=False,
    )
    revocation_provider = DefaultCertificateRevocationProvider(
        ocsp_url=ocsp_url,
        crl_url=crl_url,
        live_verified=False,
    )
    verifier_5070 = DefaultQualifiedSignature5070Verifier(
        eshs_trust_provider=eshs_provider,
        revocation_provider=revocation_provider,
        tsa_provider=tsa_adapter,
        live_verified=False,
    )

    auth_gate = DefaultProductionAuthorizationProvider(
        kms_signer=kms_adapter,
        tsa_provider=tsa_adapter,
        worm_storage=worm_adapter,
        trust_anchor_provider=anchor_provider,
        source_acquisition_provider=acq_provider,
        legal_attestation_verifier=legal_verifier,
        technical_verification_service=tech_service,
        kvkk_residency_verifier=kvkk_verifier,
        trust_root_config=cfg,
        project_root=root,
    )

    ledger_path = root / "config" / "calendar_attestation_ledger.json"
    approvers_path = root / "config" / "authorized_approvers.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8")) if ledger_path.is_file() else {"entries": []}
    approvers = json.loads(approvers_path.read_text(encoding="utf-8")) if approvers_path.is_file() else None

    tech_result = tech_service.verify_repository_technical_integrity(project_root=root)

    decision = auth_gate.evaluate_production_authorization(
        ledger=ledger,
        approvers_registry=approvers,
        technical_verification_result=tech_result,
        legal_counsel_attestation_envelope=None,
        source_acquisition_envelope=None,
        kvkk_assessment_envelope=None,
        runtime_environment="PRODUCTION",
        expected_app_project_id=app_project,
    )

    services: dict[str, dict[str, Any]] = {
        "gcp_cloud_kms_hsm": kms_adapter.health_check().to_dict(),
        "gcp_cloud_storage_worm": worm_adapter.health_check().to_dict(),
        "independent_rfc3161_tsa": tsa_adapter.health_check().to_dict(),
        "pkcs11_hsm_alternative": pkcs_adapter.health_check().to_dict(),
        "external_trust_anchor": anchor_provider.health_check().to_dict(),
        "source_acquisition_provider": acq_provider.health_check().to_dict(),
        "gcp_cloud_sql_postgresql": {
            "provider_name": "GCP_CLOUD_SQL_POSTGRESQL",
            "provider_type": "OperationalDatabase",
            "backend": "CLOUD_SQL_POSTGRESQL",
            "integration_mode": "LIVE_PRODUCTION" if cloud_sql_conn else "NOT_CONFIGURED",
            "configured": bool(cloud_sql_conn),
            "reachable": False,
            "region": region,
            "error_code": None if cloud_sql_conn else "CLOUD_SQL_NOT_CONFIGURED",
        },
    }
    for svc in services.values():
        svc["probe_status"] = _derive_legacy_service_probe_status(svc)

    esign_5070_services = {
        "btk_eshs_trust_list": eshs_provider.probe_status().to_dict(),
        "certificate_revocation_ocsp_crl": revocation_provider.probe_status().to_dict(),
        "qualified_signature_5070_verifier": verifier_5070.probe_status().to_dict(),
    }

    primary_modes = [
        services["gcp_cloud_kms_hsm"]["integration_mode"],
        services["gcp_cloud_storage_worm"]["integration_mode"],
        services["independent_rfc3161_tsa"]["integration_mode"],
        services["external_trust_anchor"]["integration_mode"],
        services["source_acquisition_provider"]["integration_mode"],
    ]
    overall_live = "LIVE_PRODUCTION" if all(m == "LIVE_PRODUCTION" for m in primary_modes) else "NOT_CONFIGURED"

    esign_5070_statuses = [svc["probe_status"] for svc in esign_5070_services.values()]
    tsa_probe = services["independent_rfc3161_tsa"]["probe_status"]
    if all(s == "LIVE_VERIFIED" for s in (*esign_5070_statuses, tsa_probe)):
        esign_5070_overall = "LIVE_VERIFIED"
        esign_5070_prod_ready = True
    elif any(s == "FAILED" for s in (*esign_5070_statuses, tsa_probe)):
        esign_5070_overall = "FAILED"
        esign_5070_prod_ready = False
    elif any(s == "INDETERMINATE" for s in (*esign_5070_statuses, tsa_probe)):
        esign_5070_overall = "INDETERMINATE"
        esign_5070_prod_ready = False
    elif all(s == "NOT_CONFIGURED" for s in esign_5070_statuses):
        esign_5070_overall = "NOT_CONFIGURED"
        esign_5070_prod_ready = False
    else:
        esign_5070_overall = "CONFIGURED_UNVERIFIED"
        esign_5070_prod_ready = False

    return {
        "product_brand": "hrAI",
        "coordinator_agent": "@hrAI",
        "specialist_agent": "@HukukSGK",
        "product_website": "https://www.insenai.com.tr",
        "schema_version": TRUST_ROOT_VERSION,
        "region": region,
        "overall_live_integration_status": overall_live,
        "live_services": services,
        "esign_5070_probe_statuses_supported": sorted(VALID_PROBE_STATUSES),
        "esign_5070_overall_status": esign_5070_overall,
        "esign_5070_services": esign_5070_services,
        "qualified_e_signature_5070_production_ready": esign_5070_prod_ready,
        "production_authorization_decision": decision.to_dict(),
        "production_use_authorized": decision.production_use_authorized,
        "external_legal_counsel_signoff_status": decision.external_legal_counsel_signoff_status,
        "qualified_e_signature_5070_equivalent": False,
        "law_5070_boundary_notice": LAW_5070_V103_BOUNDARY_NOTICE,
        "law_5070_separation_notice": LAW_5070_SEPARATION_NOTICE,
        "kvkk_data_residency_notice": KVKK_DATA_RESIDENCY_NOTICE,
    }


def _cli() -> int:
    report = run_live_integration_probe()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
