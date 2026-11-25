"""Deterministic validator for official Turkish legal source registries (v1.0.1)."""

from __future__ import annotations

from datetime import date
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from .models import (
    NORM_LAYER_PRIORITY,
    VALID_DOCUMENT_FETCH_STATUSES,
    VALID_SOURCE_STATUSES,
    VALID_SOURCE_TYPES,
    VALID_VERIFICATION_METHODS,
    VALID_VERIFIER_ROLES,
    AmendmentRecord,
    ArticleEffectiveRule,
    LegalSourceRecord,
    RegistryValidationReport,
    VerificationAudit,
    VerificationFlag,
)

OFFICIAL_LEGAL_DOMAINS: set[str] = {
    "mevzuat.gov.tr",
    "mevzuat.adalet.gov.tr",
    "resmigazete.gov.tr",
    "gib.gov.tr",
    "cdn.gib.gov.tr",
    "sgk.gov.tr",
    "karararama.yargitay.gov.tr",
    "yargitay.gov.tr",
    "anayasa.gov.tr",
    "kvkk.gov.tr",
    "csgb.gov.tr",
}

BARE_PATH_BLOCKLIST: set[str] = {
    "",
    "/",
    "/anasayfa",
    "/index",
    "/index.html",
    "/index.htm",
    "/default.aspx",
    "/mevzuat",
    "/mevzuat/",
    "/kanunlar",
    "/kanunlar/",
    "/tebligler",
    "/tebligler/",
    "/genelgeler",
    "/genelgeler/",
    "/kararlar",
    "/kararlar/",
    "/eskiler",
    "/eskiler/",
    "/tr",
    "/tr/",
    "/tr/anasayfa",
}

DISALLOWED_VERIFIERS: set[str] = {
    "",
    "NONE",
    "UNKNOWN",
    "NULL",
    "LLM",
    "AI",
    "AUTO",
    "SELF",
    "BOT",
}

SOURCE_TYPE_TO_EXPECTED_NORM_LAYER: dict[str, str] = {
    "CONSTITUTION": "CONSTITUTION",
    "INTERNATIONAL_TREATY_FUNDAMENTAL_RIGHTS": "INTERNATIONAL_TREATY_FUNDAMENTAL_RIGHTS",
    "INTERNATIONAL_TREATY_GENERAL": "INTERNATIONAL_TREATY_GENERAL",
    "OFFICIAL_GAZETTE_LAW": "STATUTORY_LAW",
    "PRESIDENTIAL_DECREE": "PRESIDENTIAL_DECREE",
    "PRESIDENTIAL_DECISION": "PRESIDENTIAL_DECISION",
    "REGULATION": "REGULATION",
    "GIB_COMMUNIQUE": "COMMUNIQUE_AND_SGK_CIRCULAR",
    "SGK_CIRCULAR": "COMMUNIQUE_AND_SGK_CIRCULAR",
    "HR_PROCEDURE": "CBA_CONTRACT_AND_HR_PROCEDURE",
}

ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SOURCE_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9\-_]{2,63}$")
VERIFIER_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9\-_]{2,40}$")
AUDIT_LOG_ID_RE = re.compile(r"^AUD-\d{8}-[A-Z0-9\-_]{2,32}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
RESMIGAZETE_YEAR_MONTH_DIR_RE = re.compile(r"^/eskiler/\d{4}(?:/\d{2})?/?$")


def parse_iso_date(value: str | None) -> date | None:
    if not isinstance(value, str) or not ISO_DATE_RE.match(value):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def is_specific_official_url(
    url: str,
    allowed_domains: set[str] | None = None,
) -> tuple[bool, str]:
    """Validate that a URL is HTTPS, on an official TR legal domain, and points to a specific document/issue."""
    if not isinstance(url, str) or not url.strip():
        return False, "URL boş olamaz."

    parsed = urlparse(url.strip())
    if parsed.scheme.lower() != "https":
        return False, f"Yalnızca HTTPS resmî bağlantılar kabul edilir (bulunan: '{parsed.scheme or 'none'}')."

    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]

    whitelist = allowed_domains if allowed_domains is not None else OFFICIAL_LEGAL_DOMAINS
    if host not in whitelist:
        return False, f"Resmî mevzuat alan adı beyaz listesinde değil: '{host}'."

    path = (parsed.path or "").strip()
    lower_path = path.lower()
    query = parsed.query or ""

    if lower_path in BARE_PATH_BLOCKLIST and not query:
        return False, f"Çıplak ana sayfa veya dizin URL'si yasaktır: '{url}'."

    if host == "mevzuat.gov.tr" and lower_path in {"/mevzuat", "/mevzuat/"}:
        qs = parse_qs(query)
        if not qs.get("MevzuatNo"):
            return False, f"mevzuat.gov.tr bağlantısı özgül 'MevzuatNo' parametresi içermelidir: '{url}'."

    if host == "resmigazete.gov.tr":
        if RESMIGAZETE_YEAR_MONTH_DIR_RE.match(lower_path):
            return False, f"Resmî Gazete yıl/ay dizini geçerli bir belge bağlantısı değildir: '{url}'."
        if lower_path in {"/arsiv", "/arsiv/"} and not query:
            return False, f"Resmî Gazete arşiv dizini özgül belge bağlantısı değildir: '{url}'."

    if host == "cdn.gib.gov.tr":
        qs = parse_qs(query)
        if not qs.get("objectKey") and not re.search(r"\.[a-z0-9]{2,5}$", lower_path):
            return False, f"GİB CDN bağlantısı özgül dosya referansı (objectKey veya dosya adı) içermelidir: '{url}'."

    if len(path.strip("/")) < 2 and not query:
        return False, f"URL yolu özgül bir belgeyi işaret etmiyor: '{url}'."

    return True, "OK"


def validate_verification_audit_block(
    record_key: str,
    audit: Any,
    flags: list[VerificationFlag],
) -> None:
    """Validate structured verification_audit metadata, verifier identity, audit log ID, and fetch integrity."""
    if not isinstance(audit, dict):
        flags.append(
            VerificationFlag(
                code="MISSING_VERIFICATION_AUDIT",
                severity="BLOCKER",
                message=f"'{record_key}' kaydında yapılandırılmış verification_audit denetim kaydı eksik.",
                evidence=record_key,
                remediation="verifier_id, verifier_role, verification_method, audit_log_id ve belge bütünlük alanlarını ekleyin.",
            )
        )
        return

    verifier_id = str(audit.get("verifier_id", "")).strip()
    if verifier_id.upper() in DISALLOWED_VERIFIERS or not VERIFIER_ID_RE.match(verifier_id):
        flags.append(
            VerificationFlag(
                code="MISSING_OR_INVALID_VERIFIER",
                severity="BLOCKER",
                message=f"'{record_key}' denetim kaydında geçersiz verifier_id: '{verifier_id}'.",
                evidence=f"{record_key}.verification_audit.verifier_id",
            )
        )

    if audit.get("verifier_role") not in VALID_VERIFIER_ROLES:
        flags.append(
            VerificationFlag(
                code="INVALID_VERIFIER_ROLE",
                severity="BLOCKER",
                message=f"'{record_key}' için geçersiz verifier_role: '{audit.get('verifier_role')}'.",
                evidence=record_key,
            )
        )

    if audit.get("verification_method") not in VALID_VERIFICATION_METHODS:
        flags.append(
            VerificationFlag(
                code="INVALID_VERIFICATION_METHOD",
                severity="BLOCKER",
                message=f"'{record_key}' için geçersiz verification_method: '{audit.get('verification_method')}'.",
                evidence=record_key,
            )
        )

    audit_log_id = str(audit.get("audit_log_id", ""))
    if not AUDIT_LOG_ID_RE.match(audit_log_id):
        flags.append(
            VerificationFlag(
                code="INVALID_AUDIT_LOG_ID",
                severity="BLOCKER",
                message=f"'{record_key}' için geçersiz audit_log_id (AUD-YYYYMMDD-ID beklenir): '{audit_log_id}'.",
                evidence=record_key,
            )
        )

    fetch_status = audit.get("document_fetch_status")
    if fetch_status not in VALID_DOCUMENT_FETCH_STATUSES:
        flags.append(
            VerificationFlag(
                code="INVALID_DOCUMENT_FETCH_STATUS",
                severity="BLOCKER",
                message=f"'{record_key}' için geçersiz document_fetch_status: '{fetch_status}'.",
                evidence=record_key,
            )
        )

    expected_markers = audit.get("expected_text_markers")
    matched_markers = audit.get("matched_text_markers")
    if not isinstance(expected_markers, list) or not expected_markers:
        flags.append(
            VerificationFlag(
                code="MISSING_EXPECTED_TEXT_MARKERS",
                severity="BLOCKER",
                message=f"'{record_key}' kaydında belge içerik doğrulaması için expected_text_markers zorunludur.",
                evidence=record_key,
            )
        )

    if fetch_status == "FETCHED_AND_MATCHED":
        http_status = audit.get("retrieved_http_status")
        sha256 = audit.get("retrieved_content_sha256")
        if http_status != 200:
            flags.append(
                VerificationFlag(
                    code="INCONSISTENT_FETCH_HTTP_STATUS",
                    severity="BLOCKER",
                    message=f"'{record_key}' FETCHED_AND_MATCHED işaretli ancak retrieved_http_status={http_status} (200 olmalı).",
                    evidence=record_key,
                )
            )
        if not isinstance(sha256, str) or not SHA256_RE.match(sha256):
            flags.append(
                VerificationFlag(
                    code="MISSING_DOCUMENT_SHA256",
                    severity="BLOCKER",
                    message=f"'{record_key}' FETCHED_AND_MATCHED işaretli ancak geçerli SHA-256 özeti yok.",
                    evidence=record_key,
                )
            )
        if not isinstance(matched_markers, list) or not matched_markers:
            flags.append(
                VerificationFlag(
                    code="MISSING_MATCHED_TEXT_MARKERS",
                    severity="BLOCKER",
                    message=f"'{record_key}' FETCHED_AND_MATCHED işaretli ancak matched_text_markers boş.",
                    evidence=record_key,
                )
            )
        elif isinstance(expected_markers, list) and set(expected_markers) - set(matched_markers):
            flags.append(
                VerificationFlag(
                    code="INCOMPLETE_MARKER_MATCH",
                    severity="BLOCKER",
                    message=f"'{record_key}' için beklenen metin işaretçilerinin tümü eşleşmemiş.",
                    evidence=record_key,
                )
            )


def validate_source_registry(raw_data: dict[str, Any]) -> RegistryValidationReport:
    """Validate structure, official URLs, audit trail, original/consolidated separation, and article effective rules."""
    flags: list[VerificationFlag] = []

    if not isinstance(raw_data, dict):
        flags.append(
            VerificationFlag(
                code="INVALID_REGISTRY_ROOT",
                severity="BLOCKER",
                message="Kayıt defteri kökü JSON nesnesi olmalıdır.",
            )
        )
        return RegistryValidationReport("legal_sources_registry", False, 0, 0, flags)

    sources = raw_data.get("sources")
    if not isinstance(sources, dict) or not sources:
        flags.append(
            VerificationFlag(
                code="EMPTY_OR_INVALID_SOURCES",
                severity="BLOCKER",
                message="'sources' alanı boş olmayan bir sözlük olmalıdır.",
            )
        )
        return RegistryValidationReport("legal_sources_registry", False, 0, 0, flags)

    required_fields = (
        "source_id",
        "source_title",
        "source_url",
        "source_type",
        "norm_layer",
        "norm_priority",
        "legal_reference",
        "statute_number",
        "official_gazette_no",
        "publication_date",
        "effective_from",
        "effective_to",
        "last_verified_at",
        "verified_by",
        "verification_status",
        "supersedes",
    )

    verified_count = 0
    all_ids = set(sources.keys())

    for key, rec in sources.items():
        if not isinstance(rec, dict):
            flags.append(
                VerificationFlag(
                    code="INVALID_SOURCE_RECORD",
                    severity="BLOCKER",
                    message=f"'{key}' kaydı geçerli bir nesne değil.",
                    evidence=key,
                )
            )
            continue

        for req in required_fields:
            if req not in rec or rec[req] is None or (isinstance(rec[req], str) and not rec[req].strip()):
                flags.append(
                    VerificationFlag(
                        code="MISSING_REQUIRED_FIELD",
                        severity="BLOCKER",
                        message=f"'{key}' kaydında zorunlu alan eksik veya boş: '{req}'.",
                        evidence=f"{key}.{req}",
                    )
                )

        source_id = str(rec.get("source_id", ""))
        if source_id != key or not SOURCE_ID_RE.match(source_id):
            flags.append(
                VerificationFlag(
                    code="INVALID_SOURCE_ID",
                    severity="BLOCKER",
                    message=f"Anahtar '{key}' ile source_id '{source_id}' eşleşmiyor veya geçersiz biçimde.",
                    evidence=key,
                )
            )

        url = rec.get("source_url", "")
        url_ok, url_reason = is_specific_official_url(url)
        if not url_ok:
            flags.append(
                VerificationFlag(
                    code="INVALID_SOURCE_URL",
                    severity="BLOCKER",
                    message=f"'{key}' için source_url geçersiz: {url_reason}",
                    evidence=str(url),
                    remediation="Çıplak ana sayfa yerine özgül HTTPS resmî belge URL'si girin.",
                )
            )

        sec_url = rec.get("secondary_official_url")
        if sec_url:
            sec_ok, sec_reason = is_specific_official_url(sec_url)
            if not sec_ok:
                flags.append(
                    VerificationFlag(
                        code="INVALID_SECONDARY_SOURCE_URL",
                        severity="BLOCKER",
                        message=f"'{key}' için secondary_official_url geçersiz: {sec_reason}",
                        evidence=str(sec_url),
                    )
                )

        source_type = rec.get("source_type")
        if source_type not in VALID_SOURCE_TYPES:
            flags.append(
                VerificationFlag(
                    code="INVALID_SOURCE_TYPE",
                    severity="BLOCKER",
                    message=f"'{key}' için geçersiz source_type: '{source_type}'.",
                    evidence=key,
                )
            )

        norm_layer = rec.get("norm_layer")
        norm_priority = rec.get("norm_priority")
        if norm_layer == "YARGITAY_PRECEDENT":
            flags.append(
                VerificationFlag(
                    code="PRECEDENT_CLASSIFIED_AS_LEGISLATIVE_SOURCE",
                    severity="BLOCKER",
                    message=(
                        f"'{key}' kaydında norm_layer='YARGITAY_PRECEDENT' kullanılamaz; Yargıtay içtihatları "
                        f"mevzuat katmanı değildir ve yargitay_precedents.json defterinde ayrı izlenir."
                    ),
                    evidence=key,
                )
            )
        else:
            expected_priority = NORM_LAYER_PRIORITY.get(str(norm_layer))
            if expected_priority is None or norm_priority != expected_priority:
                flags.append(
                    VerificationFlag(
                        code="NORM_LAYER_PRIORITY_MISMATCH",
                        severity="BLOCKER",
                        message=(
                            f"'{key}' kaydında norm_layer='{norm_layer}' ile norm_priority={norm_priority} "
                            f"uyumsuz (beklenen: {expected_priority})."
                        ),
                        evidence=key,
                    )
                )

        expected_layer = SOURCE_TYPE_TO_EXPECTED_NORM_LAYER.get(str(source_type))
        if expected_layer is not None and norm_layer != expected_layer:
            flags.append(
                VerificationFlag(
                    code="SOURCE_TYPE_NORM_LAYER_MISMATCH",
                    severity="BLOCKER",
                    message=(
                        f"'{key}' kaydında source_type='{source_type}' ile norm_layer='{norm_layer}' "
                        f"uyumsuz (beklenen: '{expected_layer}')."
                    ),
                    evidence=key,
                )
            )

        title_and_ref = f"{rec.get('legal_reference', '')} {rec.get('source_title', '')}".replace("İ", "i").replace("I", "ı").lower()
        if (source_type == "CONSTITUTION" or norm_layer == "CONSTITUTION") and any(
            tok in title_and_ref for tok in ("ilo", "uluslararası", "milletlerarası", "sözleşme", "andlaşma", "antlaşma")
        ):
            flags.append(
                VerificationFlag(
                    code="TREATY_CLASSIFIED_AS_CONSTITUTION",
                    severity="BLOCKER",
                    message=(
                        f"'{key}' kaydı uluslararası sözleşme/ILO niteliğinde olup Anayasa (CONSTITUTION) "
                        f"katmanına konulamaz; Anayasa m.90/5 uyarınca INTERNATIONAL_TREATY_FUNDAMENTAL_RIGHTS "
                        f"veya INTERNATIONAL_TREATY_GENERAL olarak sınıflandırılmalıdır."
                    ),
                    evidence=key,
                    remediation="Temel hak/özgürlük antlaşması için INTERNATIONAL_TREATY_FUNDAMENTAL_RIGHTS (2), diğer uluslararası antlaşmalar için INTERNATIONAL_TREATY_GENERAL (3) kullanın.",
                )
            )

        if "cumhurbaşkanı kararı" in title_and_ref and (
            source_type == "PRESIDENTIAL_DECREE" or norm_layer == "PRESIDENTIAL_DECREE"
        ):
            flags.append(
                VerificationFlag(
                    code="PRESIDENTIAL_NORM_TYPE_MISCLASSIFICATION",
                    severity="BLOCKER",
                    message=(
                        f"'{key}' kaydı bir Cumhurbaşkanı Kararıdır; PRESIDENTIAL_DECREE "
                        f"(Cumhurbaşkanlığı Kararnamesi) değil PRESIDENTIAL_DECISION olarak sınıflandırılmalıdır."
                    ),
                    evidence=key,
                    remediation="source_type ve norm_layer alanlarını 'PRESIDENTIAL_DECISION', norm_priority alanını 5 yapın.",
                )
            )
        elif "cumhurbaşkanlığı kararnamesi" in title_and_ref and (
            source_type == "PRESIDENTIAL_DECISION" or norm_layer == "PRESIDENTIAL_DECISION"
        ):
            flags.append(
                VerificationFlag(
                    code="PRESIDENTIAL_NORM_TYPE_MISCLASSIFICATION",
                    severity="BLOCKER",
                    message=(
                        f"'{key}' kaydı bir Cumhurbaşkanlığı Kararnamesidir; PRESIDENTIAL_DECISION "
                        f"değil PRESIDENTIAL_DECREE olarak sınıflandırılmalıdır."
                    ),
                    evidence=key,
                    remediation="source_type ve norm_layer alanlarını 'PRESIDENTIAL_DECREE', norm_priority alanını 4 yapın.",
                )
            )

        pub_dt = parse_iso_date(rec.get("publication_date"))
        eff_from = parse_iso_date(rec.get("effective_from"))
        eff_to = parse_iso_date(rec.get("effective_to"))
        ver_dt = parse_iso_date(rec.get("last_verified_at"))

        for field_name, dt_val in (
            ("publication_date", pub_dt),
            ("effective_from", eff_from),
            ("effective_to", eff_to),
            ("last_verified_at", ver_dt),
        ):
            if dt_val is None:
                flags.append(
                    VerificationFlag(
                        code="INVALID_ISO_DATE",
                        severity="BLOCKER",
                        message=f"'{key}.{field_name}' geçerli YYYY-MM-DD tarihi değil: '{rec.get(field_name)}'.",
                        evidence=f"{key}.{field_name}",
                    )
                )

        if eff_from and eff_to and eff_from > eff_to:
            flags.append(
                VerificationFlag(
                    code="INVALID_EFFECTIVE_DATE_RANGE",
                    severity="BLOCKER",
                    message=f"'{key}' kaydında effective_from ({eff_from}) > effective_to ({eff_to}).",
                    evidence=key,
                )
            )

        verifier = str(rec.get("verified_by", "")).strip().upper()
        if verifier in DISALLOWED_VERIFIERS or len(verifier) < 3:
            flags.append(
                VerificationFlag(
                    code="MISSING_OR_INVALID_VERIFIER",
                    severity="BLOCKER",
                    message=f"'{key}' kaydında geçerli doğrulayan (verified_by) eksik veya otomatik/LLM değeri içeriyor.",
                    evidence=f"{key}.verified_by={rec.get('verified_by')}",
                )
            )

        # v1.0.1: Structured audit trail & content integrity enforcement
        validate_verification_audit_block(key, rec.get("verification_audit"), flags)

        # v1.0.1: Separation of original text vs consolidated text vs amendment history
        orig_pub = rec.get("original_publication")
        if not isinstance(orig_pub, dict) or orig_pub.get("text_type") != "ORIGINAL_PUBLISHED_TEXT":
            flags.append(
                VerificationFlag(
                    code="MISSING_ORIGINAL_PUBLICATION_SEPARATION",
                    severity="BLOCKER",
                    message=f"'{key}' kaydında ilk yayımlanan metin (original_publication) ayrımı eksik.",
                    evidence=key,
                )
            )

        cons_txt = rec.get("consolidated_text")
        if not isinstance(cons_txt, dict) or not cons_txt.get("consolidated_url"):
            flags.append(
                VerificationFlag(
                    code="MISSING_CONSOLIDATED_TEXT_SEPARATION",
                    severity="BLOCKER",
                    message=f"'{key}' kaydında güncel konsolide metin (consolidated_text) ayrımı eksik.",
                    evidence=key,
                )
            )
        else:
            c_ok, c_reason = is_specific_official_url(cons_txt["consolidated_url"])
            if not c_ok:
                flags.append(
                    VerificationFlag(
                        code="INVALID_CONSOLIDATED_URL",
                        severity="BLOCKER",
                        message=f"'{key}' consolidated_url geçersiz: {c_reason}",
                        evidence=str(cons_txt["consolidated_url"]),
                    )
                )

        if not isinstance(rec.get("amendment_history"), list):
            flags.append(
                VerificationFlag(
                    code="MISSING_AMENDMENT_HISTORY",
                    severity="BLOCKER",
                    message=f"'{key}' kaydında değişiklik geçmişi (amendment_history) listesi zorunludur.",
                    evidence=key,
                )
            )
        else:
            for a_idx, amend in enumerate(rec["amendment_history"]):
                if not isinstance(amend, dict) or parse_iso_date(amend.get("effective_from")) is None:
                    flags.append(
                        VerificationFlag(
                            code="INVALID_AMENDMENT_RECORD",
                            severity="BLOCKER",
                            message=f"'{key}.amendment_history[{a_idx}]' geçersiz değişiklik kaydı veya yürürlük tarihi.",
                            evidence=f"{key}.amendment_history[{a_idx}]",
                        )
                    )

        # v1.0.1: Validate article-level effective rules when present
        for r_idx, rule in enumerate(rec.get("article_effective_rules", []) or []):
            r_from = parse_iso_date(rule.get("effective_from"))
            r_to = parse_iso_date(rule.get("effective_to"))
            if r_from is None or r_to is None or r_from > r_to:
                flags.append(
                    VerificationFlag(
                        code="INVALID_ARTICLE_EFFECTIVE_RULE",
                        severity="BLOCKER",
                        message=f"'{key}.article_effective_rules[{r_idx}]' geçersiz madde yürürlük aralığı.",
                        evidence=f"{key}.article_effective_rules[{r_idx}]",
                    )
                )

        status = rec.get("verification_status")
        if status not in VALID_SOURCE_STATUSES:
            flags.append(
                VerificationFlag(
                    code="INVALID_VERIFICATION_STATUS",
                    severity="BLOCKER",
                    message=f"'{key}' için geçersiz verification_status: '{status}'.",
                    evidence=key,
                )
            )
        elif status == "VERIFIED":
            audit_block = rec.get("verification_audit")
            fetch_st = audit_block.get("document_fetch_status") if isinstance(audit_block, dict) else None
            if fetch_st != "FETCHED_AND_MATCHED":
                flags.append(
                    VerificationFlag(
                        code="UNVERIFIED_DOCUMENT_ON_VERIFIED_SOURCE",
                        severity="BLOCKER",
                        message=(
                            f"'{key}' mevzuat kaynağı document_fetch_status='{fetch_st}' iken "
                            f"verification_status='VERIFIED' olamaz; tam metin eşleşmesi (FETCHED_AND_MATCHED) zorunludur."
                        ),
                        evidence=key,
                        remediation="Tam metin/OCR doğrulaması tamamlanana kadar verification_status='PENDING_REVIEW' yapın.",
                    )
                )
            verified_count += 1

        superseded_by = rec.get("superseded_by")
        if status == "SUPERSEDED":
            if not superseded_by or superseded_by not in all_ids:
                flags.append(
                    VerificationFlag(
                        code="BROKEN_SUPERSEDED_BY_REFERENCE",
                        severity="BLOCKER",
                        message=(
                            f"'{key}' kaydı SUPERSEDED işaretli ancak superseded_by='{superseded_by}' "
                            f"kayıt defterinde bulunamadı."
                        ),
                        evidence=key,
                    )
                )
        elif superseded_by and superseded_by not in all_ids:
            flags.append(
                VerificationFlag(
                    code="BROKEN_SUPERSEDED_BY_REFERENCE",
                    severity="BLOCKER",
                    message=f"'{key}' için superseded_by='{superseded_by}' kayıt defterinde yok.",
                    evidence=key,
                )
            )

        content_sha = rec.get("content_sha256")
        if content_sha is not None and not SHA256_RE.match(str(content_sha)):
            flags.append(
                VerificationFlag(
                    code="INVALID_CONTENT_SHA256",
                    severity="BLOCKER",
                    message=f"'{key}' için content_sha256 geçerli 64 karakterlik hex özeti değil.",
                    evidence=key,
                )
            )

    has_blocker = any(f.severity == "BLOCKER" for f in flags)
    return RegistryValidationReport(
        registry_name="legal_sources_registry",
        valid=not has_blocker,
        total_records=len(sources),
        verified_count=verified_count,
        flags=flags,
    )


def _parse_audit(raw_audit: dict[str, Any] | None) -> VerificationAudit | None:
    if not isinstance(raw_audit, dict):
        return None
    return VerificationAudit(
        verifier_id=raw_audit["verifier_id"],
        verifier_role=raw_audit["verifier_role"],
        verification_method=raw_audit["verification_method"],
        audit_log_id=raw_audit["audit_log_id"],
        verified_at=raw_audit["verified_at"],
        document_fetch_status=raw_audit.get("document_fetch_status", "NOT_CHECKED"),
        retrieved_http_status=raw_audit.get("retrieved_http_status"),
        retrieved_content_sha256=raw_audit.get("retrieved_content_sha256"),
        expected_text_markers=tuple(raw_audit.get("expected_text_markers", [])),
        matched_text_markers=tuple(raw_audit.get("matched_text_markers", [])),
    )


def load_source_registry(path: str | Path, strict: bool = True) -> dict[str, LegalSourceRecord]:
    """Load and optionally strictly validate a legal_sources_registry.json file."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    report = validate_source_registry(raw)
    if strict and not report.valid:
        msgs = "; ".join(f"{f.code}: {f.message}" for f in report.flags if f.severity == "BLOCKER")
        raise ValueError(f"Mevzuat kayıt defteri doğrulaması başarısız: {msgs}")

    records: dict[str, LegalSourceRecord] = {}
    for key, rec in raw.get("sources", {}).items():
        amendments = tuple(
            AmendmentRecord(
                amending_law_no=a["amending_law_no"],
                official_gazette_no=a["official_gazette_no"],
                publication_date=a["publication_date"],
                affected_articles=tuple(a["affected_articles"]),
                effective_from=a["effective_from"],
                summary=a["summary"],
            )
            for a in rec.get("amendment_history", [])
        )
        article_rules = tuple(
            ArticleEffectiveRule(
                article_ref=r["article_ref"],
                effective_from=r["effective_from"],
                effective_to=r["effective_to"],
                basis=r["basis"],
                amended_by=r.get("amended_by"),
            )
            for r in rec.get("article_effective_rules", [])
        )
        records[key] = LegalSourceRecord(
            source_id=rec["source_id"],
            source_title=rec["source_title"],
            source_url=rec["source_url"],
            source_type=rec["source_type"],
            norm_layer=rec["norm_layer"],
            norm_priority=int(rec["norm_priority"]),
            legal_reference=rec["legal_reference"],
            statute_number=str(rec["statute_number"]),
            official_gazette_no=str(rec["official_gazette_no"]),
            publication_date=rec["publication_date"],
            effective_from=rec["effective_from"],
            effective_to=rec["effective_to"],
            last_verified_at=rec["last_verified_at"],
            verified_by=rec["verified_by"],
            verification_status=rec["verification_status"],
            supersedes=rec["supersedes"],
            superseded_by=rec.get("superseded_by"),
            secondary_official_url=rec.get("secondary_official_url"),
            url_granularity=rec.get("url_granularity", "DIRECT_DOCUMENT"),
            keywords=tuple(rec.get("keywords", [])),
            content_sha256=rec.get("content_sha256"),
            verification_audit=_parse_audit(rec.get("verification_audit")),
            original_publication=rec.get("original_publication"),
            consolidated_text=rec.get("consolidated_text"),
            amendment_history=amendments,
            article_effective_rules=article_rules,
        )
    return records


def resolve_effective_sources(
    sources: dict[str, LegalSourceRecord],
    as_of_date: str,
    layers: list[str] | None = None,
    include_superseded: bool = False,
) -> dict[str, list[LegalSourceRecord]]:
    """Filter legal sources by as_of_date, verification_status, and optional norm layers."""
    target_dt = parse_iso_date(as_of_date)
    if target_dt is None:
        raise ValueError(f"Geçersiz as_of_date (YYYY-MM-DD beklenir): '{as_of_date}'")

    layer_filter = set(layers) if layers else None
    effective: list[LegalSourceRecord] = []
    inactive: list[LegalSourceRecord] = []

    for rec in sources.values():
        if layer_filter and rec.norm_layer not in layer_filter:
            continue

        eff_from = parse_iso_date(rec.effective_from)
        eff_to = parse_iso_date(rec.effective_to)
        in_window = eff_from is not None and eff_to is not None and eff_from <= target_dt <= eff_to

        if rec.verification_status == "VERIFIED" and in_window:
            effective.append(rec)
        elif include_superseded:
            inactive.append(rec)

    effective.sort(key=lambda r: (r.norm_priority, r.source_id))
    inactive.sort(key=lambda r: (r.norm_priority, r.source_id))
    return {
        "effective_sources": effective,
        "inactive_or_superseded_sources": inactive,
    }


def _normalize_article_ref(article_ref: str) -> str:
    s = article_ref.replace("İ", "i").replace("I", "ı").lower().strip()
    s = re.sub(r"^(?:madde|md\.?|m\.?)\s*", "", s)
    s = re.sub(r"\s+", " ", s)
    return s


def resolve_effective_article(
    source: LegalSourceRecord,
    article_ref: str,
    as_of_date: str,
) -> dict[str, Any]:
    """Check whether a specific article of a statute is effective on as_of_date (article-level tracking)."""
    target_dt = parse_iso_date(as_of_date)
    if target_dt is None:
        raise ValueError(f"Geçersiz as_of_date: '{as_of_date}'")

    norm_art = _normalize_article_ref(article_ref)
    for rule in source.article_effective_rules:
        if _normalize_article_ref(rule.article_ref) == norm_art:
            r_from = parse_iso_date(rule.effective_from)
            r_to = parse_iso_date(rule.effective_to)
            is_eff = (
                source.verification_status == "VERIFIED"
                and r_from is not None
                and r_to is not None
                and r_from <= target_dt <= r_to
            )
            return {
                "source_id": source.source_id,
                "article_ref": rule.article_ref,
                "as_of_date": as_of_date,
                "is_effective": is_eff,
                "effective_from": rule.effective_from,
                "effective_to": rule.effective_to,
                "basis": rule.basis,
                "amended_by": rule.amended_by,
                "granularity": "ARTICLE_LEVEL_RULE",
            }

    # Fall back to statute-level effective window when no article override exists
    s_from = parse_iso_date(source.effective_from)
    s_to = parse_iso_date(source.effective_to)
    is_eff = (
        source.verification_status == "VERIFIED"
        and s_from is not None
        and s_to is not None
        and s_from <= target_dt <= s_to
    )
    return {
        "source_id": source.source_id,
        "article_ref": article_ref,
        "as_of_date": as_of_date,
        "is_effective": is_eff,
        "effective_from": source.effective_from,
        "effective_to": source.effective_to,
        "basis": f"{source.legal_reference} genel yürürlük tarihi",
        "amended_by": None,
        "granularity": "STATUTE_LEVEL_DEFAULT",
    }
