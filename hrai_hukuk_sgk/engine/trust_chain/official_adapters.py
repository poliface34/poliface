"""Official Legislation Source Adapters: Resmî Gazete & Mevzuat Bilgi Sistemi (hrAI @HukukSGK v1.0.6 WP2.2)."""

from __future__ import annotations

import re
from typing import Any

from .adapter import (
    SourceAdapter,
    extract_title_keywords,
    format_turkish_date_variants,
    has_exact_identifier,
    normalize_turkish_text,
)
from .models import (
    ADAPTER_MEVZUAT,
    ADAPTER_RESMI_GAZETE,
    CONTENT_MATCH_MATCHED,
    CONTENT_MATCH_MISMATCH,
    SourceDocumentRequest,
)

_GAZETTE_NO_RE = re.compile(r"^[1-9][0-9]{3,6}$")
_MEVZUAT_NO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,63}$")
_VALID_MEVZUAT_TYPES: frozenset[str] = frozenset(
    {"KANUN", "CBK", "YONETMELIK", "TEBLIG", "TUZUK", "KARAR", "GENELGE"}
)
_MEVZUAT_TYPE_TEXT_MARKERS: dict[str, tuple[str, ...]] = {
    "KANUN": ("kanun", "kanunu", "kanunun"),
    "CBK": ("cumhurbaskanligi kararnamesi", "kararname"),
    "YONETMELIK": ("yonetmelik", "yonetmeligi"),
    "TEBLIG": ("teblig", "tebligi"),
    "TUZUK": ("tuzuk", "tuzugu"),
    "KARAR": ("karar", "karari"),
    "GENELGE": ("genelge", "genelgesi"),
}


class ResmiGazeteAdapter(SourceAdapter):
    """Fail-closed adapter for T.C. Resmî Gazete (`resmigazete.gov.tr`) with content-vs-metadata matching."""

    @property
    def adapter_type(self) -> str:
        return ADAPTER_RESMI_GAZETE

    @property
    def allowed_domains(self) -> frozenset[str]:
        return frozenset({"www.resmigazete.gov.tr", "resmigazete.gov.tr"})

    def _validate_adapter_specific_metadata(
        self,
        request: SourceDocumentRequest,
        raw_bytes: bytes,
        headers: dict[str, str],
    ) -> list[tuple[str, str]]:
        errors: list[tuple[str, str]] = []
        gazette_no = str(request.adapter_metadata.get("gazette_number", "")).strip()
        if not _GAZETTE_NO_RE.fullmatch(gazette_no):
            errors.append(
                (
                    "RESMI_GAZETE_INVALID_ISSUE_NUMBER",
                    f"Resmî Gazete 'gazette_number' alanı geçerli sayı numarası olmalıdır: {gazette_no!r}",
                )
            )
        if b"\x00" in raw_bytes and not raw_bytes.startswith(b"%PDF-"):
            errors.append(
                (
                    "RESMI_GAZETE_CORRUPT_PAYLOAD",
                    "PDF olmayan Resmî Gazete belgesinde beklenmeyen NUL baytı tespit edildi.",
                )
            )
        return errors

    def _verify_document_content(
        self,
        request: SourceDocumentRequest,
        extracted_text: str,
        text_format: str,
    ) -> dict[str, Any]:
        norm = normalize_turkish_text(extracted_text)
        gazette_no = str(request.adapter_metadata.get("gazette_number", "")).strip()
        title_kws = extract_title_keywords(request.title)
        date_variants = format_turkish_date_variants(request.publication_date)

        matched: list[str] = []
        missing: list[str] = []
        extracted: dict[str, Any] = {}

        if has_exact_identifier(norm, gazette_no):
            matched.append("gazette_number")
            extracted["gazette_number"] = gazette_no
        else:
            missing.append("gazette_number")

        non_num_kws = [kw for kw in title_kws if kw != normalize_turkish_text(gazette_no)]
        matched_kws = [kw for kw in non_num_kws if has_exact_identifier(norm, kw)]
        has_rg_marker = "resmi gazete" in norm
        matched_dates = [dv for dv in date_variants if dv in norm]

        if matched_kws:
            matched.append("title_keywords")
            extracted["matched_title_keywords"] = matched_kws
        elif non_num_kws:
            missing.append("title_keywords")

        if has_rg_marker:
            matched.append("institution_marker")
            extracted["institution_marker"] = "resmi gazete"
        if matched_dates:
            matched.append("publication_date")
            extracted["publication_date"] = matched_dates[0]

        if not has_rg_marker and not matched_dates and len(matched_kws) < 2:
            missing.append("resmi_gazete_or_date_context")

        if missing:
            return {
                "content_match_status": CONTENT_MATCH_MISMATCH,
                "extracted_text_format": text_format,
                "matched_fields": matched,
                "mismatched_or_missing_fields": missing,
                "extracted_evidence": extracted,
                "error_code": "RESMI_GAZETE_CONTENT_MISMATCH",
                "error_message": (
                    f"İndirilen Resmî Gazete belgesi beyan edilen sayı ({gazette_no}) veya başlık/kurum "
                    f"bilgileriyle uyuşmuyor (eksik: {missing})."
                ),
            }
        return {
            "content_match_status": CONTENT_MATCH_MATCHED,
            "extracted_text_format": text_format,
            "matched_fields": matched,
            "mismatched_or_missing_fields": [],
            "extracted_evidence": extracted,
        }


class MevzuatAdapter(SourceAdapter):
    """Fail-closed adapter for T.C. Mevzuat Bilgi Sistemi (`mevzuat.gov.tr`) with content-vs-metadata matching."""

    @property
    def adapter_type(self) -> str:
        return ADAPTER_MEVZUAT

    @property
    def allowed_domains(self) -> frozenset[str]:
        return frozenset({"www.mevzuat.gov.tr", "mevzuat.gov.tr"})

    def _validate_adapter_specific_metadata(
        self,
        request: SourceDocumentRequest,
        raw_bytes: bytes,
        headers: dict[str, str],
    ) -> list[tuple[str, str]]:
        errors: list[tuple[str, str]] = []
        mevzuat_no = str(request.adapter_metadata.get("mevzuat_no", "")).strip()
        mevzuat_turu = str(request.adapter_metadata.get("mevzuat_turu", "")).strip().upper()
        if not _MEVZUAT_NO_RE.fullmatch(mevzuat_no):
            errors.append(
                (
                    "MEVZUAT_INVALID_NUMBER",
                    f"Mevzuat 'mevzuat_no' alanı zorunlu ve geçerli biçimde olmalıdır: {mevzuat_no!r}",
                )
            )
        if mevzuat_turu not in _VALID_MEVZUAT_TYPES:
            errors.append(
                (
                    "MEVZUAT_INVALID_TYPE",
                    f"Mevzuat 'mevzuat_turu' desteklenen türlerden biri olmalıdır {sorted(_VALID_MEVZUAT_TYPES)}: {mevzuat_turu!r}",
                )
            )
        if b"\x00" in raw_bytes and not raw_bytes.startswith(b"%PDF-"):
            errors.append(
                (
                    "MEVZUAT_CORRUPT_PAYLOAD",
                    "PDF olmayan Mevzuat belgesinde beklenmeyen NUL baytı tespit edildi.",
                )
            )
        return errors

    def _verify_document_content(
        self,
        request: SourceDocumentRequest,
        extracted_text: str,
        text_format: str,
    ) -> dict[str, Any]:
        norm = normalize_turkish_text(extracted_text)
        mevzuat_no = str(request.adapter_metadata.get("mevzuat_no", "")).strip()
        mevzuat_turu = str(request.adapter_metadata.get("mevzuat_turu", "")).strip().upper()
        title_kws = extract_title_keywords(request.title)

        matched: list[str] = []
        missing: list[str] = []
        extracted: dict[str, Any] = {}

        if has_exact_identifier(norm, mevzuat_no):
            matched.append("mevzuat_no")
            extracted["mevzuat_no"] = mevzuat_no
        else:
            missing.append("mevzuat_no")

        type_markers = _MEVZUAT_TYPE_TEXT_MARKERS.get(mevzuat_turu, ())
        matched_type = next((tm for tm in type_markers if tm in norm), None)
        if matched_type:
            matched.append("mevzuat_turu")
            extracted["mevzuat_turu"] = matched_type
        else:
            missing.append("mevzuat_turu")

        matched_kws = [kw for kw in title_kws if kw != normalize_turkish_text(mevzuat_no) and has_exact_identifier(norm, kw)]
        if matched_kws:
            matched.append("title_keywords")
            extracted["matched_title_keywords"] = matched_kws
        else:
            missing.append("title_keywords")

        if missing:
            return {
                "content_match_status": CONTENT_MATCH_MISMATCH,
                "extracted_text_format": text_format,
                "matched_fields": matched,
                "mismatched_or_missing_fields": missing,
                "extracted_evidence": extracted,
                "error_code": "MEVZUAT_CONTENT_MISMATCH",
                "error_message": (
                    f"İndirilen mevzuat belgesi beyan edilen mevzuat_no ({mevzuat_no}), tür ({mevzuat_turu}) "
                    f"veya başlık anahtar sözcükleriyle uyuşmuyor (eksik: {missing})."
                ),
            }
        return {
            "content_match_status": CONTENT_MATCH_MATCHED,
            "extracted_text_format": text_format,
            "matched_fields": matched,
            "mismatched_or_missing_fields": [],
            "extracted_evidence": extracted,
        }
