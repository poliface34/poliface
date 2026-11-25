"""Institutional Source Adapters: SGK & İŞKUR (hrAI @HukukSGK v1.0.6 WP2.4)."""

from __future__ import annotations

import re
from typing import Any

from .adapter import (
    SourceAdapter,
    extract_title_keywords,
    has_exact_identifier,
    normalize_turkish_text,
)
from .models import (
    ADAPTER_ISKUR,
    ADAPTER_SGK,
    CONTENT_MATCH_MATCHED,
    CONTENT_MATCH_MISMATCH,
    SourceDocumentRequest,
)

_REF_NO_RE = re.compile(r"^[A-Za-z0-9ÇĞİÖŞÜçğıöşü][A-Za-z0-9ÇĞİÖŞÜçğıöşü._/ -]{1,63}$")
_SGK_DOC_TYPES: frozenset[str] = frozenset({"GENELGE", "GENEL_YAZI", "DUYURU", "TEBLIG", "YONETMELIK"})
_ISKUR_DOC_TYPES: frozenset[str] = frozenset(
    {"GENELGE", "YONETMELIK", "DUYURU", "USUL_VE_ESASLAR", "PROGRAM_REHBERI"}
)


def _match_institutional_content(
    *,
    prefix: str,
    institution_markers: tuple[str, ...],
    request: SourceDocumentRequest,
    extracted_text: str,
    text_format: str,
) -> dict[str, Any]:
    norm = normalize_turkish_text(extracted_text)
    ref_no = str(request.adapter_metadata.get("reference_no", "")).strip()
    title_kws = extract_title_keywords(request.title)

    matched: list[str] = []
    missing: list[str] = []
    extracted: dict[str, Any] = {}

    if has_exact_identifier(norm, ref_no):
        matched.append("reference_no")
        extracted["reference_no"] = ref_no
    else:
        # Also allow compact reference token match when prefix like "ISKUR-2026/01" is rendered as "2026/01"
        sub_match = re.search(r"(?:19|20)\d{2}/\d+", ref_no)
        if sub_match and has_exact_identifier(norm, sub_match.group(0)):
            matched.append("reference_no")
            extracted["reference_no"] = sub_match.group(0)
        else:
            missing.append("reference_no")

    inst_hit = next((m for m in institution_markers if m in norm), None)
    if inst_hit:
        matched.append("institution_marker")
        extracted["institution_marker"] = inst_hit
    else:
        missing.append("institution_marker")

    matched_kws = [kw for kw in title_kws if has_exact_identifier(norm, kw)]
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
            "error_code": f"{prefix}_CONTENT_MISMATCH",
            "error_message": (
                f"İndirilen {prefix} belgesi beyan edilen referans numarası ({ref_no}), kurum veya "
                f"başlık bilgileriyle uyuşmuyor (eksik: {missing})."
            ),
        }
    return {
        "content_match_status": CONTENT_MATCH_MATCHED,
        "extracted_text_format": text_format,
        "matched_fields": matched,
        "mismatched_or_missing_fields": [],
        "extracted_evidence": extracted,
    }


class SgkAdapter(SourceAdapter):
    """Fail-closed adapter for Sosyal Güvenlik Kurumu (`sgk.gov.tr`) with content-vs-metadata matching."""

    @property
    def adapter_type(self) -> str:
        return ADAPTER_SGK

    @property
    def allowed_domains(self) -> frozenset[str]:
        return frozenset({"www.sgk.gov.tr", "sgk.gov.tr"})

    def _validate_adapter_specific_metadata(
        self,
        request: SourceDocumentRequest,
        raw_bytes: bytes,
        headers: dict[str, str],
    ) -> list[tuple[str, str]]:
        errors: list[tuple[str, str]] = []
        doc_type = str(request.adapter_metadata.get("document_type", "")).strip().upper()
        ref_no = str(request.adapter_metadata.get("reference_no", "")).strip()
        if doc_type not in _SGK_DOC_TYPES:
            errors.append(
                (
                    "SGK_INVALID_DOCUMENT_TYPE",
                    f"SGK 'document_type' desteklenen türlerden biri olmalıdır {sorted(_SGK_DOC_TYPES)}: {doc_type!r}",
                )
            )
        if not _REF_NO_RE.fullmatch(ref_no):
            errors.append(
                (
                    "SGK_INVALID_REFERENCE_NO",
                    f"SGK 'reference_no' alanı zorunlu ve geçerli biçimde olmalıdır: {ref_no!r}",
                )
            )
        if b"\x00" in raw_bytes and not raw_bytes.startswith(b"%PDF-"):
            errors.append(("SGK_CORRUPT_PAYLOAD", "PDF olmayan SGK belgesinde beklenmeyen NUL baytı tespit edildi."))
        return errors

    def _verify_document_content(
        self,
        request: SourceDocumentRequest,
        extracted_text: str,
        text_format: str,
    ) -> dict[str, Any]:
        return _match_institutional_content(
            prefix="SGK",
            institution_markers=("sgk", "sosyal guvenlik kurumu"),
            request=request,
            extracted_text=extracted_text,
            text_format=text_format,
        )


class IskurAdapter(SourceAdapter):
    """Fail-closed adapter for Türkiye İş Kurumu (`iskur.gov.tr`) with content-vs-metadata matching."""

    @property
    def adapter_type(self) -> str:
        return ADAPTER_ISKUR

    @property
    def allowed_domains(self) -> frozenset[str]:
        return frozenset({"www.iskur.gov.tr", "iskur.gov.tr"})

    def _validate_adapter_specific_metadata(
        self,
        request: SourceDocumentRequest,
        raw_bytes: bytes,
        headers: dict[str, str],
    ) -> list[tuple[str, str]]:
        errors: list[tuple[str, str]] = []
        doc_type = str(request.adapter_metadata.get("document_type", "")).strip().upper()
        ref_no = str(request.adapter_metadata.get("reference_no", "")).strip()
        if doc_type not in _ISKUR_DOC_TYPES:
            errors.append(
                (
                    "ISKUR_INVALID_DOCUMENT_TYPE",
                    f"İŞKUR 'document_type' desteklenen türlerden biri olmalıdır {sorted(_ISKUR_DOC_TYPES)}: {doc_type!r}",
                )
            )
        if not _REF_NO_RE.fullmatch(ref_no):
            errors.append(
                (
                    "ISKUR_INVALID_REFERENCE_NO",
                    f"İŞKUR 'reference_no' alanı zorunlu ve geçerli biçimde olmalıdır: {ref_no!r}",
                )
            )
        if b"\x00" in raw_bytes and not raw_bytes.startswith(b"%PDF-"):
            errors.append(
                ("ISKUR_CORRUPT_PAYLOAD", "PDF olmayan İŞKUR belgesinde beklenmeyen NUL baytı tespit edildi.")
            )
        return errors

    def _verify_document_content(
        self,
        request: SourceDocumentRequest,
        extracted_text: str,
        text_format: str,
    ) -> dict[str, Any]:
        return _match_institutional_content(
            prefix="ISKUR",
            institution_markers=("iskur", "turkiye is kurumu"),
            request=request,
            extracted_text=extracted_text,
            text_format=text_format,
        )
