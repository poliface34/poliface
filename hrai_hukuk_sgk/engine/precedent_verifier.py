"""Deterministic Yargıtay precedent validator and LLM draft citation auditor (v1.0.1)."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from .models import (
    PRECEDENT_BINDING_RANK,
    VALID_PRECEDENT_CHAMBERS,
    VALID_PRECEDENT_STATUSES,
    CitationAuditResult,
    LegalSourceRecord,
    PrecedentRecord,
    RegistryValidationReport,
    VerificationAudit,
    VerificationFlag,
)
from .source_validator import (
    DISALLOWED_VERIFIERS,
    SHA256_RE,
    is_specific_official_url,
    parse_iso_date,
    resolve_effective_article,
    validate_verification_audit_block,
)

OFFICIAL_PRECEDENT_DOMAINS: set[str] = {
    "resmigazete.gov.tr",
    "karararama.yargitay.gov.tr",
    "yargitay.gov.tr",
    "anayasa.gov.tr",
    "mevzuat.adalet.gov.tr",
}

PRECEDENT_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9\-_]{3,63}$")
ESAS_KARAR_NO_RE = re.compile(r"^\d{4}/\d+$")

PRECEDENT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\bE(?:sas)?\.?\s*[:.]?\s*(?P<esas>\d{4}/\d+)\s*[,;\-–/\s]+(?:ve\s+)?K(?:arar)?\.?\s*[:.]?\s*(?P<karar>\d{4}/\d+)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?P<esas>\d{4}/\d+)\s*E(?:sas)?\.?\s*[,;\-–/\s]+(?:ve\s+)?(?P<karar>\d{4}/\d+)\s*K(?:arar)?\.?\b",
        re.IGNORECASE,
    ),
)

PRESIDENTIAL_DECISION_CITATION_RE = re.compile(
    r"(?<!\d)(?P<num>\d{3,5})\s+[Ss]ayılı\s+(?:Cumhurbaşkanı\s+Karar[ıi]|CK)\b"
)
PRESIDENTIAL_DECREE_CITATION_RE = re.compile(
    r"(?<!\d)(?P<num>\d{3,5})\s+[Ss]ayılı\s+(?:Cumhurbaşkanlığı\s+Kararname\w*|CBK)\b"
)
TEBLIG_CITATION_RE = re.compile(
    r"(?<!\d)(?P<num>\d{2,4})\s+Seri\s+No\.?lu\s+(?:Gelir\s+Vergisi\s+)?(?:Genel\s+)?Tebliğ\w*"
)
LAW_CITATION_RE = re.compile(
    r"(?<!\d)(?P<num>\d{3,5})\s+[Ss]ayılı\s+"
    r"(?!Resm[îi]\s+Gazete|Cumhurbaşkan[ıi]|Cumhurbaşkanlığı|CBK\b|CK\b)"
    r"(?:(?:[A-ZÇĞİÖŞÜa-zçğıöşü0-9\-']+\s+){0,8}Kanun\w*|"
    r"(?:TBK|İİK|GVK|DVK|İSGK|STİSK|KVKK))\b"
)
SHORT_ARTICLE_STATUTE_RE = re.compile(
    r"(?<!\d)(?P<num>\d{3,5})\s+(?:[Ss]ayılı\s+(?:[A-ZÇĞİÖŞÜa-zçğıöşü\s]{0,55}?Kanun\w*\s+)?)?"
    r"(?:(?:Ek\s+Madde|Ek\s+m\.|Geçici\s+Madde|Geçici\s+m\.|Madde|m\.)\s*(?P<art>\d+))",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s\)\]>\"']+")

HISTORICAL_DISCLOSURE_MARKERS: tuple[str, ...] = (
    "mülga",
    "yürürlükten kaldır",
    "yürürlükten kalk",
    "yerine",
    "süresi dol",
    "sona ermiş",
    "eski düzenleme",
)


def validate_precedent_registry(
    raw_data: dict[str, Any],
    source_registry: dict[str, LegalSourceRecord] | None = None,
) -> RegistryValidationReport:
    """Validate precedent structure, separate full-text/holding/scope verification, audit trail, and cross-refs."""
    flags: list[VerificationFlag] = []

    if not isinstance(raw_data, dict):
        flags.append(
            VerificationFlag(
                code="INVALID_REGISTRY_ROOT",
                severity="BLOCKER",
                message="İçtihat kayıt defteri kökü JSON nesnesi olmalıdır.",
            )
        )
        return RegistryValidationReport("yargitay_precedents", False, 0, 0, flags)

    precedents = raw_data.get("precedents")
    if not isinstance(precedents, dict):
        flags.append(
            VerificationFlag(
                code="INVALID_PRECEDENTS_CONTAINER",
                severity="BLOCKER",
                message="'precedents' alanı bir sözlük olmalıdır.",
            )
        )
        return RegistryValidationReport("yargitay_precedents", False, 0, 0, flags)

    required_fields = (
        "precedent_id",
        "chamber",
        "binding_level",
        "esas_no",
        "karar_no",
        "decision_date",
        "official_source_url",
        "related_source_ids",
        "legal_principle",
        "scope_limitations",
        "verification_status",
        "verified_by",
        "last_verified_at",
    )

    verified_count = 0
    all_ids = set(precedents.keys())

    for key, rec in precedents.items():
        if not isinstance(rec, dict):
            flags.append(
                VerificationFlag(
                    code="INVALID_PRECEDENT_RECORD",
                    severity="BLOCKER",
                    message=f"'{key}' içtihat kaydı geçerli bir nesne değil.",
                    evidence=key,
                )
            )
            continue

        for req in required_fields:
            val = rec.get(req)
            if val is None or (isinstance(val, str) and not val.strip()) or (isinstance(val, list) and not val):
                flags.append(
                    VerificationFlag(
                        code="MISSING_REQUIRED_FIELD",
                        severity="BLOCKER",
                        message=f"'{key}' içtihat kaydında zorunlu alan eksik veya boş: '{req}'.",
                        evidence=f"{key}.{req}",
                    )
                )

        prec_id = str(rec.get("precedent_id", ""))
        if prec_id != key or not PRECEDENT_ID_RE.match(prec_id):
            flags.append(
                VerificationFlag(
                    code="INVALID_PRECEDENT_ID",
                    severity="BLOCKER",
                    message=f"Anahtar '{key}' ile precedent_id '{prec_id}' eşleşmiyor veya geçersiz.",
                    evidence=key,
                )
            )

        chamber = rec.get("chamber")
        if chamber not in VALID_PRECEDENT_CHAMBERS:
            flags.append(
                VerificationFlag(
                    code="INVALID_CHAMBER",
                    severity="BLOCKER",
                    message=f"'{key}' için geçersiz Yargıtay dairesi/kurulu: '{chamber}'.",
                    evidence=key,
                )
            )

        binding = rec.get("binding_level")
        if binding not in PRECEDENT_BINDING_RANK or binding == "NONE":
            flags.append(
                VerificationFlag(
                    code="INVALID_BINDING_LEVEL",
                    severity="BLOCKER",
                    message=f"'{key}' için geçersiz binding_level: '{binding}'.",
                    evidence=key,
                )
            )

        esas_no = str(rec.get("esas_no", ""))
        karar_no = str(rec.get("karar_no", ""))
        if not ESAS_KARAR_NO_RE.match(esas_no):
            flags.append(
                VerificationFlag(
                    code="INVALID_ESAS_FORMAT",
                    severity="BLOCKER",
                    message=f"'{key}' için esas_no '{esas_no}' YYYY/N biçiminde değil.",
                    evidence=esas_no,
                )
            )
        if not ESAS_KARAR_NO_RE.match(karar_no):
            flags.append(
                VerificationFlag(
                    code="INVALID_KARAR_FORMAT",
                    severity="BLOCKER",
                    message=f"'{key}' için karar_no '{karar_no}' YYYY/N biçiminde değil.",
                    evidence=karar_no,
                )
            )

        decision_dt = parse_iso_date(rec.get("decision_date"))
        last_ver_dt = parse_iso_date(rec.get("last_verified_at"))
        if decision_dt is None:
            flags.append(
                VerificationFlag(
                    code="INVALID_DECISION_DATE",
                    severity="BLOCKER",
                    message=f"'{key}' için decision_date geçersiz: '{rec.get('decision_date')}'.",
                    evidence=key,
                )
            )
        if last_ver_dt is None:
            flags.append(
                VerificationFlag(
                    code="INVALID_LAST_VERIFIED_DATE",
                    severity="BLOCKER",
                    message=f"'{key}' için last_verified_at geçersiz: '{rec.get('last_verified_at')}'.",
                    evidence=key,
                )
            )

        if chamber == "YIBBGK":
            if binding != "STATUTORY_BINDING_YIBBGK":
                flags.append(
                    VerificationFlag(
                        code="YIBBGK_BINDING_MISMATCH",
                        severity="BLOCKER",
                        message=f"YİBBGK kararı '{key}' için binding_level='STATUTORY_BINDING_YIBBGK' olmalıdır.",
                        evidence=key,
                    )
                )
            rg_no = rec.get("official_gazette_no")
            rg_dt = parse_iso_date(rec.get("official_gazette_date"))
            if not rg_no or not str(rg_no).strip() or rg_dt is None:
                flags.append(
                    VerificationFlag(
                        code="YIBBGK_MISSING_OFFICIAL_GAZETTE",
                        severity="BLOCKER",
                        message=(
                            f"YİBBGK kararı '{key}' Resmî Gazete sayı ve tarihi (official_gazette_no, "
                            f"official_gazette_date) olmadan kaydedilemez."
                        ),
                        evidence=key,
                    )
                )
            elif decision_dt and rg_dt < decision_dt:
                flags.append(
                    VerificationFlag(
                        code="YIBBGK_GAZETTE_BEFORE_DECISION",
                        severity="BLOCKER",
                        message=f"'{key}' için Resmî Gazete tarihi ({rg_dt}) karar tarihinden ({decision_dt}) önce olamaz.",
                        evidence=key,
                    )
                )

        url = rec.get("official_source_url", "")
        url_ok, url_reason = is_specific_official_url(url, allowed_domains=OFFICIAL_PRECEDENT_DOMAINS)
        if not url_ok:
            flags.append(
                VerificationFlag(
                    code="INVALID_PRECEDENT_URL",
                    severity="BLOCKER",
                    message=f"'{key}' için official_source_url geçersiz: {url_reason}",
                    evidence=str(url),
                )
            )

        verifier = str(rec.get("verified_by", "")).strip().upper()
        if verifier in DISALLOWED_VERIFIERS or len(verifier) < 3:
            flags.append(
                VerificationFlag(
                    code="MISSING_OR_INVALID_VERIFIER",
                    severity="BLOCKER",
                    message=f"'{key}' için verified_by alanı eksik veya geçersiz: '{rec.get('verified_by')}'.",
                    evidence=key,
                )
            )

        # v1.0.1: Structured audit trail
        validate_verification_audit_block(key, rec.get("verification_audit"), flags)

        # v1.0.1: Separate verification of full text, operative holding, and scope limitations
        ft = rec.get("full_text_verification")
        if not isinstance(ft, dict) or not ft.get("official_source_url"):
            flags.append(
                VerificationFlag(
                    code="MISSING_FULL_TEXT_VERIFICATION",
                    severity="BLOCKER",
                    message=f"'{key}' için tam metin doğrulama kaydı (full_text_verification) eksik.",
                    evidence=key,
                )
            )
        else:
            ft_ok, ft_reason = is_specific_official_url(
                str(ft.get("official_source_url", "")), allowed_domains=OFFICIAL_PRECEDENT_DOMAINS
            )
            if not ft_ok:
                flags.append(
                    VerificationFlag(
                        code="INVALID_FULL_TEXT_URL",
                        severity="BLOCKER",
                        message=f"'{key}' tam metin URL'si geçersiz: {ft_reason}",
                        evidence=key,
                    )
                )
            if ft.get("status") == "FETCHED_AND_MATCHED":
                ft_sha = ft.get("retrieved_content_sha256")
                if ft.get("retrieved_http_status") != 200 or not isinstance(ft_sha, str) or not SHA256_RE.match(ft_sha):
                    flags.append(
                        VerificationFlag(
                            code="INCOMPLETE_FULL_TEXT_INTEGRITY",
                            severity="BLOCKER",
                            message=f"'{key}' tam metin FETCHED_AND_MATCHED işaretli ancak HTTP 200 veya SHA-256 eksik.",
                            evidence=key,
                        )
                    )

        audit = rec.get("verification_audit")
        ft_is_matched = (
            isinstance(ft, dict)
            and ft.get("status") == "FETCHED_AND_MATCHED"
            and isinstance(audit, dict)
            and audit.get("document_fetch_status") == "FETCHED_AND_MATCHED"
        )

        holding = rec.get("operative_holding")
        if not isinstance(holding, dict) or len(str(holding.get("text", "")).strip()) < 20:
            flags.append(
                VerificationFlag(
                    code="MISSING_OPERATIVE_HOLDING_VERIFICATION",
                    severity="BLOCKER",
                    message=f"'{key}' için sonuç/hüküm bölümü (operative_holding) ayrı doğrulanmamış.",
                    evidence=key,
                )
            )
        else:
            if rec.get("verification_status") == "VERIFIED" and holding.get("verified_against_gazette") is not True:
                flags.append(
                    VerificationFlag(
                        code="UNVERIFIED_OPERATIVE_HOLDING",
                        severity="BLOCKER",
                        message=f"'{key}' VERIFIED işaretli ancak operative_holding.verified_against_gazette != true.",
                        evidence=key,
                    )
                )
            if not ft_is_matched and holding.get("verified_against_gazette") is True:
                flags.append(
                    VerificationFlag(
                        code="FALSE_GAZETTE_VERIFICATION_CLAIM",
                        severity="BLOCKER",
                        message=(
                            f"'{key}' kaydında tam metin doğrulaması (FETCHED_AND_MATCHED) tamamlanmamışken "
                            f"operative_holding.verified_against_gazette=true beyan edilemez."
                        ),
                        evidence=key,
                        remediation="Tam metin/OCR doğrulaması tamamlanana kadar verified_against_gazette=false yapın.",
                    )
                )

        scope_det = rec.get("scope_limitations_detail")
        if (
            not isinstance(scope_det, dict)
            or not scope_det.get("applies_to")
            or not scope_det.get("does_not_apply_to")
            or not scope_det.get("statutory_anchors")
        ):
            flags.append(
                VerificationFlag(
                    code="MISSING_SCOPE_LIMITATIONS_DETAIL",
                    severity="BLOCKER",
                    message=f"'{key}' için kapsam sınırlamaları (applies_to / does_not_apply_to / statutory_anchors) eksik.",
                    evidence=key,
                )
            )
        else:
            if rec.get("verification_status") == "VERIFIED" and scope_det.get("verified_by_legal_review") is not True:
                flags.append(
                    VerificationFlag(
                        code="UNVERIFIED_SCOPE_LIMITATIONS",
                        severity="BLOCKER",
                        message=f"'{key}' VERIFIED işaretli ancak scope_limitations_detail.verified_by_legal_review != true.",
                        evidence=key,
                    )
                )
            if not ft_is_matched and scope_det.get("verified_by_legal_review") is True:
                flags.append(
                    VerificationFlag(
                        code="FALSE_FULL_VERIFICATION_CLAIM_WITHOUT_FULL_TEXT",
                        severity="BLOCKER",
                        message=(
                            f"'{key}' kaydında tam metin doğrulaması (FETCHED_AND_MATCHED) tamamlanmamışken "
                            f"scope_limitations_detail.verified_by_legal_review=true tam doğrulama iddiası konulamaz."
                        ),
                        evidence=key,
                        remediation="Tam metin/OCR doğrulaması tamamlanana kadar verified_by_legal_review=false yapın.",
                    )
                )

        status = rec.get("verification_status")
        if status not in VALID_PRECEDENT_STATUSES:
            flags.append(
                VerificationFlag(
                    code="INVALID_VERIFICATION_STATUS",
                    severity="BLOCKER",
                    message=f"'{key}' için geçersiz verification_status: '{status}'.",
                    evidence=key,
                )
            )
        elif status == "VERIFIED":
            if not ft_is_matched:
                flags.append(
                    VerificationFlag(
                        code="UNVERIFIED_FULL_TEXT_ON_VERIFIED_PRECEDENT",
                        severity="BLOCKER",
                        message=(
                            f"'{key}' içtihadı tam metin eşleşmesi (full_text_verification.status='FETCHED_AND_MATCHED' "
                            f"ve document_fetch_status='FETCHED_AND_MATCHED') tamamlanmadan VERIFIED olamaz."
                        ),
                        evidence=key,
                        remediation="Tam metin doğrulaması tamamlanana kadar verification_status='PENDING_REVIEW' yapın.",
                    )
                )
            verified_count += 1

        if source_registry is not None:
            for src_id in rec.get("related_source_ids", []):
                if src_id not in source_registry:
                    flags.append(
                        VerificationFlag(
                            code="BROKEN_RELATED_SOURCE_ID",
                            severity="BLOCKER",
                            message=f"'{key}' içtihadının bağlı olduğu '{src_id}' mevzuat kayıt defterinde yok.",
                            evidence=f"{key}->{src_id}",
                        )
                    )

        superseded_by = rec.get("superseded_by")
        if status == "SUPERSEDED" and (not superseded_by or superseded_by not in all_ids):
            flags.append(
                VerificationFlag(
                    code="BROKEN_SUPERSEDED_BY_PRECEDENT",
                    severity="BLOCKER",
                    message=f"'{key}' SUPERSEDED işaretli ancak superseded_by='{superseded_by}' kayıt defterinde yok.",
                    evidence=key,
                )
            )

        for conflict_id in rec.get("conflicting_precedent_ids", []) or []:
            if conflict_id not in all_ids:
                flags.append(
                    VerificationFlag(
                        code="BROKEN_CONFLICTING_PRECEDENT_ID",
                        severity="BLOCKER",
                        message=f"'{key}' için conflicting_precedent_ids içindeki '{conflict_id}' bulunamadı.",
                        evidence=f"{key}<->{conflict_id}",
                    )
                )

    has_blocker = any(f.severity == "BLOCKER" for f in flags)
    return RegistryValidationReport(
        registry_name="yargitay_precedents",
        valid=not has_blocker,
        total_records=len(precedents),
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


def load_precedent_registry(
    path: str | Path,
    source_registry: dict[str, LegalSourceRecord] | None = None,
    strict: bool = True,
) -> dict[str, PrecedentRecord]:
    """Load and optionally strictly validate yargitay_precedents.json."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    report = validate_precedent_registry(raw, source_registry=source_registry)
    if strict and not report.valid:
        msgs = "; ".join(f"{f.code}: {f.message}" for f in report.flags if f.severity == "BLOCKER")
        raise ValueError(f"Yargıtay içtihat kayıt defteri doğrulaması başarısız: {msgs}")

    records: dict[str, PrecedentRecord] = {}
    for key, rec in raw.get("precedents", {}).items():
        records[key] = PrecedentRecord(
            precedent_id=rec["precedent_id"],
            chamber=rec["chamber"],
            binding_level=rec["binding_level"],
            esas_no=rec["esas_no"],
            karar_no=rec["karar_no"],
            decision_date=rec["decision_date"],
            official_source_url=rec["official_source_url"],
            related_source_ids=tuple(rec["related_source_ids"]),
            legal_principle=rec["legal_principle"],
            scope_limitations=rec["scope_limitations"],
            verification_status=rec["verification_status"],
            verified_by=rec["verified_by"],
            last_verified_at=rec["last_verified_at"],
            official_gazette_no=rec.get("official_gazette_no"),
            official_gazette_date=rec.get("official_gazette_date"),
            url_granularity=rec.get("url_granularity", "DIRECT_DOCUMENT"),
            superseded_by=rec.get("superseded_by"),
            conflicting_precedent_ids=tuple(rec.get("conflicting_precedent_ids", [])),
            keywords=tuple(rec.get("keywords", [])),
            full_text_verification=rec.get("full_text_verification"),
            operative_holding=rec.get("operative_holding"),
            scope_limitations_detail=rec.get("scope_limitations_detail"),
            verification_audit=_parse_audit(rec.get("verification_audit")),
        )
    return records


def _extract_precedent_pairs(text: str) -> list[tuple[str, str]]:
    seen: list[tuple[str, str]] = []
    for pat in PRECEDENT_PATTERNS:
        for match in pat.finditer(text):
            pair = (match.group("esas"), match.group("karar"))
            if pair not in seen:
                seen.append(pair)
    return seen


def _has_historical_disclosure(text: str, start: int, end: int) -> bool:
    window = text[max(0, start - 60) : min(len(text), end + 80)].lower()
    return any(marker in window for marker in HISTORICAL_DISCLOSURE_MARKERS)


def _audit_single_precedent(
    rec: PrecedentRecord,
    matched_precedent_ids: list[str],
    flags: list[VerificationFlag],
) -> bool:
    requires_escalation = False
    if rec.precedent_id not in matched_precedent_ids:
        matched_precedent_ids.append(rec.precedent_id)

    if rec.verification_status == "SUPERSEDED":
        flags.append(
            VerificationFlag(
                code="SUPERSEDED_PRECEDENT_CITED",
                severity="BLOCKER",
                message=(
                    f"Yürürlükten kalkmış/aşılmış içtihat atfı: {rec.precedent_id} "
                    f"(E. {rec.esas_no}, K. {rec.karar_no}). Yerine geçen: {rec.superseded_by}."
                ),
                evidence=rec.precedent_id,
                remediation=f"Güncel içtihat olan '{rec.superseded_by}' kararını esas alın.",
            )
        )
    elif rec.verification_status == "CONFLICTING" or rec.conflicting_precedent_ids:
        requires_escalation = True
        flags.append(
            VerificationFlag(
                code="CONFLICTING_PRECEDENT_ESCALATE",
                severity="BLOCKER",
                message=(
                    f"Çelişkili içtihat tespit edildi: {rec.precedent_id} "
                    f"(çelişen kayıtlar: {', '.join(rec.conflicting_precedent_ids) or 'işaretli'}). "
                    f"Şirket avukatına zorunlu eskalasyon gerekir."
                ),
                evidence=rec.precedent_id,
                remediation="escalate_to_legal_counsel aracını çağırın ve otomatik onay vermeyin.",
            )
        )
    elif rec.verification_status != "VERIFIED":
        flags.append(
            VerificationFlag(
                code="UNVERIFIED_PRECEDENT_CITED",
                severity="BLOCKER",
                message=f"Doğrulanmamış içtihat atfı: {rec.precedent_id} (durum: {rec.verification_status}).",
                evidence=rec.precedent_id,
                remediation="Yalnızca VERIFIED içtihatları zikredin.",
            )
        )
    return requires_escalation


def verify_response_citations(
    draft_text: str,
    as_of_date: str,
    source_registry: dict[str, LegalSourceRecord],
    precedent_registry: dict[str, PrecedentRecord],
    cited_source_ids: list[str] | None = None,
    cited_precedent_ids: list[str] | None = None,
) -> CitationAuditResult:
    """Audit LLM draft citations for fabricated precedents/statutes, article-level effective dates, and bad URLs."""
    target_dt = parse_iso_date(as_of_date)
    if target_dt is None:
        raise ValueError(f"Geçersiz as_of_date (YYYY-MM-DD beklenir): '{as_of_date}'")

    flags: list[VerificationFlag] = []
    matched_source_ids: list[str] = []
    matched_precedent_ids: list[str] = []
    requires_escalation = False

    by_esas_karar: dict[tuple[str, str], PrecedentRecord] = {
        (p.esas_no, p.karar_no): p for p in precedent_registry.values()
    }
    by_statute_no: dict[str, list[LegalSourceRecord]] = {}
    for src in source_registry.values():
        by_statute_no.setdefault(src.statute_number, []).append(src)

    # 1. Audit Yargıtay Esas/Karar citations
    for esas_no, karar_no in _extract_precedent_pairs(draft_text):
        rec = by_esas_karar.get((esas_no, karar_no))
        if rec is None:
            flags.append(
                VerificationFlag(
                    code="FABRICATED_PRECEDENT",
                    severity="BLOCKER",
                    message=(
                        f"Kayıt defterinde bulunmayan Yargıtay karar numarası tespit edildi: "
                        f"E. {esas_no}, K. {karar_no}. Numara uydurulamaz."
                    ),
                    evidence=f"E. {esas_no}, K. {karar_no}",
                    remediation="Doğrulanmamış karar numarasını metinden çıkarın ve ilke şerhi düşerek yanıtlayın.",
                )
            )
        else:
            if _audit_single_precedent(rec, matched_precedent_ids, flags):
                requires_escalation = True

    for pid in cited_precedent_ids or []:
        rec = precedent_registry.get(pid)
        if rec is None:
            flags.append(
                VerificationFlag(
                    code="FABRICATED_PRECEDENT",
                    severity="BLOCKER",
                    message=f"Beyan edilen precedent_id '{pid}' doğrulanmış içtihat defterinde yok.",
                    evidence=pid,
                )
            )
        else:
            if _audit_single_precedent(rec, matched_precedent_ids, flags):
                requires_escalation = True

    # 2. Extract statutes, Presidential Decisions/Decrees, communiques, and article-specific citations
    extracted_statutes: list[tuple[str, str, int, int]] = []
    for category, pattern in (
        ("PRESIDENTIAL_DECISION", PRESIDENTIAL_DECISION_CITATION_RE),
        ("PRESIDENTIAL_DECREE", PRESIDENTIAL_DECREE_CITATION_RE),
        ("GIB_COMMUNIQUE", TEBLIG_CITATION_RE),
        ("STATUTORY_LAW", LAW_CITATION_RE),
    ):
        for match in pattern.finditer(draft_text):
            extracted_statutes.append((match.group("num"), category, match.start(), match.end()))

    article_mentions: list[tuple[str, str, int, int]] = []
    for match in SHORT_ARTICLE_STATUTE_RE.finditer(draft_text):
        num = match.group("num")
        raw_span = match.group(0)
        art_num = match.group("art")
        if re.search(r"ek\s+(?:madde|m\.)", raw_span, re.IGNORECASE):
            art_label = f"Ek Madde {art_num}"
        elif re.search(r"geçici\s+(?:madde|m\.)", raw_span, re.IGNORECASE):
            art_label = f"Geçici Madde {art_num}"
        else:
            art_label = f"Madde {art_num}"
        if num in by_statute_no:
            extracted_statutes.append((num, "SHORT_REF", match.start(), match.end()))
            article_mentions.append((num, art_label, match.start(), match.end()))

    actively_mentioned_ids: set[str] = set()
    for num, category, _, _ in extracted_statutes:
        for src in by_statute_no.get(num, []):
            if category in {"PRESIDENTIAL_DECISION", "PRESIDENTIAL_DECREE"} and src.norm_layer != category:
                continue
            eff_from = parse_iso_date(src.effective_from)
            eff_to = parse_iso_date(src.effective_to)
            if (
                src.verification_status == "VERIFIED"
                and eff_from is not None
                and eff_to is not None
                and eff_from <= target_dt <= eff_to
            ):
                actively_mentioned_ids.add(src.source_id)

    seen_statute_checks: set[tuple[str, str]] = set()
    for num, category, start, end in extracted_statutes:
        key = (num, category)
        if key in seen_statute_checks:
            continue
        seen_statute_checks.add(key)

        candidates = by_statute_no.get(num, [])
        if not candidates:
            flags.append(
                VerificationFlag(
                    code="FABRICATED_STATUTE",
                    severity="BLOCKER",
                    message=f"Doğrulanmış mevzuat kayıt defterinde bulunmayan mevzuat sayısı atfı: '{num}' ({category}).",
                    evidence=draft_text[start:end],
                    remediation="Yalnızca doğrulanmış kayıt defterindeki resmî mevzuat numaralarına atıf yapın.",
                )
            )
            continue

        if category in {"PRESIDENTIAL_DECISION", "PRESIDENTIAL_DECREE"}:
            norm_matched = [src for src in candidates if src.norm_layer == category]
            if not norm_matched:
                actual_layers = sorted({src.norm_layer for src in candidates})
                flags.append(
                    VerificationFlag(
                        code="NORM_TYPE_MISMATCH_DECREE_VS_DECISION",
                        severity="BLOCKER",
                        message=(
                            f"Norm türü hatası: '{draft_text[start:end]}' metinde {category} olarak anılmış; "
                            f"ancak kayıt defterindeki '{candidates[0].source_id}' kaydının norm türü "
                            f"{actual_layers} (Cumhurbaşkanı Kararı ile Cumhurbaşkanlığı Kararnamesi karıştırılamaz)."
                        ),
                        evidence=draft_text[start:end],
                        remediation="Cumhurbaşkanı Kararlarını 'Cumhurbaşkanı Kararı', Cumhurbaşkanlığı Kararnamelerini 'Cumhurbaşkanlığı Kararnamesi' olarak doğru norm türüyle anın.",
                    )
                )
                continue
            candidates = norm_matched

        active_match: LegalSourceRecord | None = None
        inactive_match: LegalSourceRecord | None = None
        for src in candidates:
            eff_from = parse_iso_date(src.effective_from)
            eff_to = parse_iso_date(src.effective_to)
            in_window = eff_from is not None and eff_to is not None and eff_from <= target_dt <= eff_to
            if src.verification_status == "VERIFIED" and in_window:
                active_match = src
                break
            inactive_match = src

        if active_match is not None:
            if active_match.source_id not in matched_source_ids:
                matched_source_ids.append(active_match.source_id)
        elif inactive_match is not None:
            if inactive_match.verification_status in {"PENDING_REVIEW", "UNVERIFIED"}:
                flags.append(
                    VerificationFlag(
                        code="UNVERIFIED_SOURCE_CITED",
                        severity="BLOCKER",
                        message=(
                            f"Tam metin doğrulaması tamamlanmamış mevzuat kaynağı kesin dayanak olarak zikredilemez: "
                            f"{inactive_match.source_id} ({inactive_match.legal_reference}, "
                            f"durum={inactive_match.verification_status})."
                        ),
                        evidence=inactive_match.source_id,
                        remediation="Yalnızca tam metni doğrulanmış (VERIFIED) mevzuat kaynaklarını kesin dayanak olarak kullanın.",
                    )
                )
                continue
            is_historical_ctx = (
                _has_historical_disclosure(draft_text, start, end)
                and inactive_match.superseded_by is not None
                and inactive_match.superseded_by in actively_mentioned_ids
            )
            if is_historical_ctx:
                flags.append(
                    VerificationFlag(
                        code="HISTORICAL_STATUTE_REFERENCE",
                        severity="WARNING",
                        message=(
                            f"Tarihsel/mülga kaynak '{inactive_match.source_id}' yerine geçen "
                            f"'{inactive_match.superseded_by}' ile birlikte anıldı."
                        ),
                        evidence=inactive_match.source_id,
                    )
                )
            else:
                flags.append(
                    VerificationFlag(
                        code="EXPIRED_OR_REPEALED_STATUTE",
                        severity="BLOCKER",
                        message=(
                            f"{as_of_date} tarihinde yürürlükte olmayan veya mülga mevzuat atfı: "
                            f"{inactive_match.source_id} ({inactive_match.legal_reference}, "
                            f"durum={inactive_match.verification_status}, yürürlük={inactive_match.effective_from}..{inactive_match.effective_to})."
                        ),
                        evidence=inactive_match.source_id,
                        remediation=(
                            f"Yerine yürürlüğe giren '{inactive_match.superseded_by}' kaynağını esas alın."
                            if inactive_match.superseded_by
                            else "Yürürlükte olan güncel mevzuat kaynağını doğrulayın."
                        ),
                    )
                )

    # 3. v1.0.1: Article-level effective date verification (e.g., 7036 m.3 effective 2018-01-01)
    seen_article_checks: set[tuple[str, str]] = set()
    for num, art_label, _, _ in article_mentions:
        if (num, art_label) in seen_article_checks:
            continue
        seen_article_checks.add((num, art_label))
        for src in by_statute_no.get(num, []):
            art_res = resolve_effective_article(src, art_label, as_of_date)
            if art_res["granularity"] == "ARTICLE_LEVEL_RULE" and not art_res["is_effective"]:
                flags.append(
                    VerificationFlag(
                        code="ARTICLE_NOT_EFFECTIVE_ON_DATE",
                        severity="BLOCKER",
                        message=(
                            f"{src.source_id} {art_res['article_ref']} hükmü {as_of_date} tarihinde "
                            f"yürürlükte değildir (madde yürürlüğü: {art_res['effective_from']}..{art_res['effective_to']}, "
                            f"dayanak: {art_res['basis']})."
                        ),
                        evidence=f"{src.source_id}:{art_res['article_ref']}",
                        remediation="Olay tarihinde yürürlükte olan önceki veya güncel madde metnini esas alın.",
                    )
                )

    # 4. Audit explicitly declared cited_source_ids
    for sid in cited_source_ids or []:
        src = source_registry.get(sid)
        if src is None:
            flags.append(
                VerificationFlag(
                    code="FABRICATED_STATUTE",
                    severity="BLOCKER",
                    message=f"Beyan edilen source_id '{sid}' mevzuat kayıt defterinde yok.",
                    evidence=sid,
                )
            )
            continue

        eff_from = parse_iso_date(src.effective_from)
        eff_to = parse_iso_date(src.effective_to)
        in_window = eff_from is not None and eff_to is not None and eff_from <= target_dt <= eff_to
        if src.verification_status in {"PENDING_REVIEW", "UNVERIFIED"}:
            flags.append(
                VerificationFlag(
                    code="UNVERIFIED_SOURCE_CITED",
                    severity="BLOCKER",
                    message=(
                        f"Dayanak olarak beyan edilen '{sid}' kaynağının tam metin doğrulaması tamamlanmamış "
                        f"(durum={src.verification_status})."
                    ),
                    evidence=sid,
                    remediation="Yalnızca tam metni doğrulanmış (VERIFIED) mevzuat kaynaklarını zikredin.",
                )
            )
        elif src.verification_status != "VERIFIED" or not in_window:
            flags.append(
                VerificationFlag(
                    code="EXPIRED_OR_REPEALED_STATUTE",
                    severity="BLOCKER",
                    message=(
                        f"Dayanak olarak beyan edilen '{sid}' kaynağı {as_of_date} tarihinde yürürlükte değil "
                        f"(durum={src.verification_status}, yürürlük={src.effective_from}..{src.effective_to})."
                    ),
                    evidence=sid,
                )
            )
        elif sid not in matched_source_ids:
            matched_source_ids.append(sid)

    # 5. Audit URLs in draft_text
    for match in URL_RE.finditer(draft_text):
        url = match.group(0).rstrip(".,;:")
        url_ok, url_reason = is_specific_official_url(url)
        if not url_ok:
            flags.append(
                VerificationFlag(
                    code="INVALID_SOURCE_URL",
                    severity="BLOCKER",
                    message=f"Yanıt metninde geçersiz/ana sayfa veya resmî olmayan URL bulundu: {url_reason}",
                    evidence=url,
                    remediation="Çıplak ana sayfa veya resmî olmayan bağlantıyı kaldırın; kayıt defterindeki özgül resmî URL'yi kullanın.",
                )
            )

    # 6. v1.0.2a.2: Deterministic pattern guardrails (safety layer; supplements semantic legal eval)
    norm_draft = draft_text.replace("İ", "i").replace("I", "ı").lower()
    overbroad_rules: tuple[tuple[str, re.Pattern[str], str, str], ...] = (
        (
            "OVERBROAD_LEGAL_CLAIM_KVKK_CRIMINAL_RECORD",
            re.compile(
                r"(?:adli\s+sicil(?:\s+belgesi|\s+kaydı)?\s+(?:her|tüm|bütün)\s+(?:pozisyonda|çalışandan|işe\s+alımda)\s+(?:istenebilir|toplanabilir|alınabilir|talep\s+edilebilir)(?!\s*(?:mi|değil|denilemez|diyemeyiz|şeklinde)))"
                r"|(?:(?:her|tüm|bütün)\s+(?:pozisyonlarda|çalışanlardan|işe\s+alımlarda|işe\s+alımda)\s+adli\s+sicil(?:\s+belgesi|\s+kaydı)?\s+(?:istenebilir|toplanabilir|alınabilir|talep\s+edilebilir|zorunludur)(?!\s*(?:mi|değil|denilemez|diyemeyiz|şeklinde)))"
                r"|(?:işin\s+niteliği\s+tek\s+başına\s+adli\s+sicil(?:\s+belgesi)?\s+için\s+yeterli(?!\s*(?:değil|olmaz|sayılmaz|denilemez)))",
                re.IGNORECASE,
            ),
            "Eksik bağlamlı/hatalı KVKK çıkarımı: Adli sicil belgesi her pozisyonda istenemez ve işin niteliği tek başına m.6/3-f hukuki sebebi oluşturmaz.",
            "6698 m.6/3 kapsamında açık kanuni yükümlülük, somut zorunluluk ve geçerli açık rıza yollarını birbirinden ayırarak belirtin.",
        ),
        (
            "OVERBROAD_LEGAL_CLAIM_OVERTIME_CONSENT",
            re.compile(
                r"(?:fazla\s+çalışma\s+onayı\s+(?:yoksa|olmadan|alınmadıkça)\s+(?:hiçbir\s+durumda\s+)?(?:çalışma\s+yapılamaz|işçi\s+çalıştırılamaz)(?!\s*(?:denilemez|diyemeyiz|şeklinde)))"
                r"|(?:yazılı\s+onay\s+(?:yoksa|olmadan|alınmadıkça)\s+hiçbir\s+(?:koşulda|halde|durumda)\s+fazla\s+çalışma\s+(?:yapılamaz|yaptırılamaz)(?!\s*(?:denilemez|diyemeyiz|şeklinde)))",
                re.IGNORECASE,
            ),
            "Eksik bağlamlı 4857 m.41 çıkarımı: Fazla çalışma onayı olmaması normal çalışmayı (45 saat) engellemez ve 4857 m.42 (zorunlu nedenler) ile m.43 (olağanüstü haller) istisnaları saklıdır.",
            "Yalnızca 4857 m.41 kapsamındaki olağan fazla çalışmanın yazılı onaya tabi olduğunu, 30 gün önceden geri alma hakkını ve m.42-43 istisnalarını açıkça belirtin.",
        ),
        (
            "OVERBROAD_LEGAL_CLAIM_NIGHT_WORK_M69_VS_M7",
            re.compile(
                r"(?:(?:turizm|özel\s+güvenlik|sağlık\s+hizmet\w*)[\w\s,ve]+(?:sektör\w*|işler\w*)\s+fazla\s+çalışma\s+yasağı\s+(?:otomatik\s+olarak\s+|tamamen\s+)?(?:kalkmıştır|kalkar|ortadan\s+kalkar|uygulanmaz)(?!\s*(?:denilemez|diyemeyiz|şeklinde)))"
                r"|(?:(?:4857\s+)?m\.?\s*69(?:/3)?\s+(?:yazılı\s+onay[ıi]?\s+)?(?:istisnası\s+ile|kapsamında|nedeniyle)\s+(?:yönetmelik\s+m\.?\s*7\s+)?fazla\s+çalışma\s+yasağı\s+(?:otomatik\s+olarak\s+|tamamen\s+)?(?:kalkar|kalkmıştır|ortadan\s+kalkar)(?!\s*(?:denilemez|diyemeyiz|şeklinde)))"
                r"|(?:sağlık\s+kuralları\s+bakımından\s+(?:günde\s+)?(?:en\s+çok\s+)?7[,.]5\s+saat[\w\s]+işlerde\s+yazılı\s+onay(?:la|\s+ile)\s+fazla\s+çalışma\s+(?:yapılabilir|yaptırılabilir)(?!\s*(?:mi|değil|denilemez|diyemeyiz|şeklinde)))",
                re.IGNORECASE,
            ),
            "Hatalı 4857 m.69 / Yönetmelik m.7 birleştirmesi: 4857 m.69/3 yazılı onay istisnası yalnızca gece çalışmasının 7,5 saatlik sınırına ilişkindir; Fazla Çalışma Yönetmeliği m.7'deki fazla çalışma yasaklarını otomatik olarak kaldırmaz.",
            "Fazla Çalışma Yönetmeliği m.7 kapsamındaki fazla çalışma yasaklarını, m.9 yazılı onay kuralını ve 4857 m.69/3 gece çalışması 7,5 saat sınır istisnasını ayrı ayrı belirtin.",
        ),
        (
            "OVERBROAD_LEGAL_CLAIM_REG_M7_AUTO_M42_M43_EXCEPTION",
            re.compile(
                r"(?:(?:fazla\s+çalışma\s+)?yönetmeli[ğg]i\s+m\.?\s*7(?:'de|\s+metninde|\s+kapsamındaki\s+(?:tüm|bütün)\s+işlerde)[\w\s,/\-]*?(?:m\.?\s*42\s*[-–/]\s*43|m\.?\s*42\s+ve\s+m\.?\s*43)[\w\s,]*?(?:otomatik\s+(?:olarak\s+)?(?:fazla\s+çalışma\s+)?(?:yaptırılabilir|yapılabilir|istisnadır|istisna\s+oluşturur)|açık\s+istisna\s+(?:yazılıdır|bulunur|yer\s+alır))(?!\s*(?:mi|değil|denilemez|diyemeyiz|şeklinde)))"
                r"|(?:(?:sağlık\s+kuralları\s+(?:gereği|bakımından)\s+(?:günde\s+)?(?:en\s+çok\s+)?7[,.]5\s+saat[\w\s]+işlerde|su\s+altı[\w\s,]+işlerinde)\s+(?:4857\s+)?m\.?\s*42\s*[-–/]\s*43(?:\s+kapsamında|\s+ile)\s+otomatik(?:\s+olarak)?\s+fazla\s+çalışma\s+(?:yapılabilir|yaptırılabilir)(?!\s*(?:mi|değil|denilemez|diyemeyiz|şeklinde)))",
                re.IGNORECASE,
            ),
            "Hatalı Yönetmelik m.7 / 4857 m.42-43 genellemesi: Fazla Çalışma Yönetmeliği m.7 metninde genel bir m.42-43 istisna cümlesi bulunmaz; açık kanuni istisna 4857 m.41/9-10 ile yalnızca yer altında maden işleri için öngörülmüştür.",
            "Yönetmelik m.7 yasaklarını metnine sadık aktarın; 4857 m.41/9-10 yer altı maden özel hükmünü diğer m.7 işlerinden ayırın ve maden dışı yasaklı işlerde hukuk müşaviri incelemesine yönlendirin.",
        ),
        (
            "OVERBROAD_LEGAL_CLAIM_SGK_CODE_22",
            re.compile(
                r"(?:(?:kod\s*22|çıkış\s+kodu\s*22)\s+(?:tek\s+başına|kesin\s+olarak|mutlaka)\s+işsizlik\s+ödeneğine\s+(?:engeldir|hak\s+kazandırmaz)(?!\s*(?:denilemez|diyemeyiz|şeklinde)))"
                r"|(?:kod\s*22\s+ile\s+çıkanlar\s+(?:kesinlikle|otomatik\s+olarak)\s+işsizlik\s+ödeneği\s+alamaz(?!\s*(?:denilemez|diyemeyiz|şeklinde)))",
                re.IGNORECASE,
            ),
            "Eksik bağlamlı 4447 m.51 çıkarımı: SGK çıkış kodu 22 tek başına kesin işsizlik ödeneği ret kararı üretmez.",
            "Çıkış kodunun yanında gerçek sona erme sebebinin, destekleyici belgelerin ve 4447 m.51 şartlarının birlikte değerlendirilmesi gerektiğini belirtin.",
        ),
        (
            "OVERBROAD_LEGAL_CLAIM_PRE_18_INSURANCE",
            re.compile(
                r"18\s+yaş(?:ından)?\s+önce(?:ki)?\s+(?:ödenen\s+)?(?:uzun\s+vadeli\s+)?prim\s+günleri\s+(?:sayılmaz|hesaba\s+katılmaz|geçersizdir)(?!\s*(?:denilemez|diyemeyiz|şeklinde))",
                re.IGNORECASE,
            ),
            "Hatalı 5510 m.38/2 & 1475 m.14 çıkarımı: 18 yaş öncesi sigortalılık süresinin başlangıcı 18 yaş ikmalinde başlasa da 18 yaş öncesi ödenen uzun vadeli (MYÖ) prim günleri prim ödeme gün sayısına dahil edilir.",
            "Sigortalılık süresi başlangıcı (18 yaş ikmali) ile MYÖ prim günlerinin sayılması kurallarını 5510 m.38/2 uyarınca ayrı belirtin.",
        ),
        (
            "OVERBROAD_LEGAL_CLAIM_SECONDARY_OVERRIDES_STATUTE",
            re.compile(
                r"(?:(?:cumhurbaşkanı\s+kararı|yönetmelik|genelge|tebliğ)(?:\s+hükmü|\s+kuralı|\s+ile)?[\w\s,]{0,55}?(?:üst\s+)?kanun(?:u(?:\s+hükmünü|\s+maddesini|\s+sınırını)?|un\s+hükmünü|daki\s+sınırı|daki\s+hakkı|\s+hükmünü)?\s+(?:ortadan\s+kaldırır|bertaraf\s+eder|aşabilir|değiştirebilir|geçersiz\s+kılar|önüne\s+geçer)(?!\s*(?:mi|değil|denilemez|diyemeyiz|olamaz|şeklinde)))"
                r"|(?:(?:cumhurbaşkanı\s+kararı|sgk\s+genelgesi|gib\s+tebliği|yönetmelik)\s+kanundan\s+(?:üstündür|önceliklidir|önce\s+uygulanır)(?!\s*(?:mi|değil|denilemez|diyemeyiz|şeklinde)))",
                re.IGNORECASE,
            ),
            "Normlar hiyerarşisi ihlali (statutory_subordination): Cumhurbaşkanı Kararı, yönetmelik, GİB tebliği veya SGK genelgesi üst norm olan kanunu bertaraf edemez, değiştiremez veya kanuni hak/sınırları işçi/mükellef aleyhine genişletemez.",
            "İkincil mevzuatın yalnızca üst kanun hükmünü somutlaştırdığını ve çatışma halinde üst norm olan kanunun uygulanacağını belirtin (resolve_norm_conflict).",
        ),
        (
            "OVERBROAD_LEGAL_CLAIM_ILO_EQUALS_CONSTITUTION",
            re.compile(
                r"(?:(?:tüm|bütün)\s+ilo\s+sözleşmeleri[\w\s,]{0,35}?(?:anayasa\s+ile\s+(?:aynı\s+(?:seviyededir|basamaktadır|düzeydedir)|eşittir)|anayasa\s+(?:düzeyindedir|seviyesindedir|hükmündedir)|kanunlardan\s+otomatik\s+(?:olarak\s+)?üstündür)(?!\s*(?:mi|değil|denilemez|diyemeyiz|olamaz|şeklinde)))"
                r"|(?:(?:uluslararası|milletlerarası)\s+(?:sözleşmeler|andlaşmalar|antlaşmalar)\s+(?:anayasa\s+ile\s+(?:aynı\s+(?:seviyededir|basamaktadır|düzeydedir)|eşittir)|anayasadan\s+üstündür)(?!\s*(?:mi|değil|denilemez|diyemeyiz|olamaz|şeklinde)))",
                re.IGNORECASE,
            ),
            "Hatalı Anayasa m.90/5 çıkarımı: Uluslararası sözleşmeler ve ILO sözleşmeleri Anayasa ile aynı seviyede değildir; kural olarak kanun hükmündedir ve kanunlarla çatışmada özel öncelik yalnızca Anayasa m.90/5 son cümle kapsamındaki temel hak ve özgürlüklere ilişkin antlaşmalar için geçerlidir.",
            "Anayasa (m.11), temel haklara ilişkin uluslararası antlaşmalar (Anayasa m.90/5 son cümle) ve genel uluslararası/ILO antlaşmalarını (Anayasa m.90/5 cümle 1 — kanun hükmünde) ayrı belirtin.",
        ),
        (
            "OVERBROAD_LEGAL_CLAIM_PRECEDENT_AS_LEGISLATIVE_NORM",
            re.compile(
                r"(?:(?:yargıtay\s+içtihadı|yibbgk\s+kararı)[\w\s,]{0,30}?(?:kanun\s+veya\s+yönetmelik\s+gibi\s+bir\s+mevzuat\s+katmanıdır|bağımsız\s+bir\s+mevzuat\s+katmanıdır)(?!\s*(?:mi|değil|denilemez|diyemeyiz|olamaz|şeklinde)))"
                r"|(?:(?:yargıtay\s+içtihadı|yibbgk\s+kararı)\s+işçi\s+lehine\s+(?:tis|toplu\s+iş\s+sözleşmesi|iş\s+sözleşmesi)[\w\s,]{0,30}?(?:otomatik\s+olarak|her\s+koşulda)\s+(?:geçersiz\s+kılar|bertaraf\s+eder|ortadan\s+kaldırır)(?!\s*(?:mi|değil|denilemez|diyemeyiz|olamaz|şeklinde)))",
                re.IGNORECASE,
            ),
            "Hatalı içtihat modellemesi: Yargıtay içtihadı (2797 s. Kanun m.45 kapsamında bağlayıcı olan YİBBGK dahil) genel bir mevzuat katmanı değildir; işçi lehine TİS/sözleşme hükümlerini katman sırasıyla otomatik geçersiz kılmaz.",
            "İçtihadın yorumladığı dayanak kanun hükmünü, 2797 s. Kanun m.45 kapsamındaki bağlayıcılık sınırını ve somut TİS/sözleşmenin nispi emredicilik ilişkisini evaluate_precedent_application ile birlikte değerlendirin.",
        ),
    )
    for code, pat, msg, rem in overbroad_rules:
        m = pat.search(norm_draft)
        if m:
            flags.append(
                VerificationFlag(
                    code=code,
                    severity="BLOCKER",
                    message=msg,
                    evidence=draft_text[m.start() : m.end()],
                    remediation=rem,
                )
            )

    has_blocker = any(f.severity == "BLOCKER" for f in flags)
    return CitationAuditResult(
        passed=not has_blocker,
        as_of_date=as_of_date,
        requires_counsel_escalation=requires_escalation,
        matched_source_ids=matched_source_ids,
        matched_precedent_ids=matched_precedent_ids,
        flags=flags,
    )
