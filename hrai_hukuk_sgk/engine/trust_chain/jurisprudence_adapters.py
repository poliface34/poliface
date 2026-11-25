"""Jurisprudence Source Adapters: Yargıtay & Danıştay (hrAI @HukukSGK v1.0.6 WP2.5)."""

from __future__ import annotations

import re
from typing import Any

from .adapter import SourceAdapter, has_exact_identifier, normalize_turkish_text
from .models import (
    ADAPTER_DANISTAY,
    ADAPTER_YARGITAY,
    CONTENT_MATCH_MATCHED,
    CONTENT_MATCH_MISMATCH,
    SourceDocumentRequest,
    TrustChainError,
    parse_strict_iso_date,
)

_DOCKET_NO_RE = re.compile(r"^(?:19|20)\d{2}/[1-9]\d{0,7}$")


def _validate_court_decision_metadata(
    prefix: str,
    request: SourceDocumentRequest,
    raw_bytes: bytes,
) -> list[tuple[str, str]]:
    errors: list[tuple[str, str]] = []
    chamber = str(request.adapter_metadata.get("chamber", "")).strip()
    esas_no = str(request.adapter_metadata.get("esas_no", "")).strip()
    karar_no = str(request.adapter_metadata.get("karar_no", "")).strip()
    decision_date_raw = request.adapter_metadata.get("decision_date")

    if len(chamber) < 3:
        errors.append((f"{prefix}_MISSING_CHAMBER", f"{prefix} 'chamber' (daire/kurul) alanı zorunludur."))
    if not _DOCKET_NO_RE.fullmatch(esas_no):
        errors.append(
            (f"{prefix}_INVALID_ESAS_NO", f"{prefix} 'esas_no' YYYY/NNNN biçiminde olmalıdır: {esas_no!r}")
        )
    if not _DOCKET_NO_RE.fullmatch(karar_no):
        errors.append(
            (f"{prefix}_INVALID_KARAR_NO", f"{prefix} 'karar_no' YYYY/NNNN biçiminde olmalıdır: {karar_no!r}")
        )
    try:
        dec_dt = parse_strict_iso_date(decision_date_raw, "decision_date")
        pub_dt = parse_strict_iso_date(request.publication_date, "publication_date")
        if dec_dt > pub_dt:
            errors.append(
                (
                    f"{prefix}_DECISION_DATE_AFTER_PUBLICATION",
                    f"Karar tarihi ({decision_date_raw}) yayım tarihinden ({request.publication_date}) sonra olamaz.",
                )
            )
    except TrustChainError as exc:
        errors.append((f"{prefix}_{exc.error_code}", exc.message))

    if b"\x00" in raw_bytes and not raw_bytes.startswith(b"%PDF-"):
        errors.append((f"{prefix}_CORRUPT_PAYLOAD", f"PDF olmayan {prefix} karar metninde NUL baytı tespit edildi."))
    return errors


def _match_court_decision_content(
    *,
    prefix: str,
    court_marker: str,
    request: SourceDocumentRequest,
    extracted_text: str,
    text_format: str,
) -> dict[str, Any]:
    norm = normalize_turkish_text(extracted_text)
    chamber = str(request.adapter_metadata.get("chamber", "")).strip()
    esas_no = str(request.adapter_metadata.get("esas_no", "")).strip()
    karar_no = str(request.adapter_metadata.get("karar_no", "")).strip()

    matched: list[str] = []
    missing: list[str] = []
    extracted: dict[str, Any] = {}

    if court_marker in norm:
        matched.append("court_marker")
        extracted["court_marker"] = court_marker
    else:
        missing.append("court_marker")

    if has_exact_identifier(norm, esas_no):
        matched.append("esas_no")
        extracted["esas_no"] = esas_no
    else:
        missing.append("esas_no")

    if has_exact_identifier(norm, karar_no):
        matched.append("karar_no")
        extracted["karar_no"] = karar_no
    else:
        missing.append("karar_no")

    # Match chamber number (e.g. "9" from "9. Hukuk Dairesi") or chamber phrase ("hukuk genel kurulu" / "10. daire")
    chamber_norm = normalize_turkish_text(chamber)
    num_match = re.match(r"^(\d+)\.", chamber_norm)
    chamber_ok = False
    if num_match:
        ch_num = num_match.group(1)
        chamber_ok = bool(re.search(rf"(?<![0-9]){re.escape(ch_num)}\s*\.\s*(?:hukuk|ceza|hd|cd|daire)", norm))
    if not chamber_ok:
        chamber_tokens = [t for t in re.findall(r"[a-z0-9]+", chamber_norm) if len(t) >= 3]
        chamber_ok = bool(chamber_tokens) and all(has_exact_identifier(norm, t) for t in chamber_tokens[:2])

    if chamber_ok:
        matched.append("chamber")
        extracted["chamber"] = chamber
    else:
        missing.append("chamber")

    if missing:
        return {
            "content_match_status": CONTENT_MATCH_MISMATCH,
            "extracted_text_format": text_format,
            "matched_fields": matched,
            "mismatched_or_missing_fields": missing,
            "extracted_evidence": extracted,
            "error_code": f"{prefix}_CONTENT_MISMATCH",
            "error_message": (
                f"İndirilen {prefix} kararı beyan edilen daire ({chamber}), Esas ({esas_no}) veya "
                f"Karar ({karar_no}) bilgileriyle uyuşmuyor (eksik: {missing})."
            ),
        }
    return {
        "content_match_status": CONTENT_MATCH_MATCHED,
        "extracted_text_format": text_format,
        "matched_fields": matched,
        "mismatched_or_missing_fields": [],
        "extracted_evidence": extracted,
    }


class YargitayAdapter(SourceAdapter):
    """Fail-closed adapter for Yargıtay karar arama portalı (`karararama.yargitay.gov.tr`, `www.yargitay.gov.tr`)."""

    @property
    def adapter_type(self) -> str:
        return ADAPTER_YARGITAY

    @property
    def allowed_domains(self) -> frozenset[str]:
        return frozenset({"karararama.yargitay.gov.tr", "www.yargitay.gov.tr"})

    def _validate_adapter_specific_metadata(
        self,
        request: SourceDocumentRequest,
        raw_bytes: bytes,
        headers: dict[str, str],
    ) -> list[tuple[str, str]]:
        return _validate_court_decision_metadata("YARGITAY", request, raw_bytes)

    def _verify_document_content(
        self,
        request: SourceDocumentRequest,
        extracted_text: str,
        text_format: str,
    ) -> dict[str, Any]:
        return _match_court_decision_content(
            prefix="YARGITAY",
            court_marker="yargitay",
            request=request,
            extracted_text=extracted_text,
            text_format=text_format,
        )


class DanistayAdapter(SourceAdapter):
    """Fail-closed adapter for Danıştay karar arama portalı (`karararama.danistay.gov.tr`, `www.danistay.gov.tr`)."""

    @property
    def adapter_type(self) -> str:
        return ADAPTER_DANISTAY

    @property
    def allowed_domains(self) -> frozenset[str]:
        return frozenset({"karararama.danistay.gov.tr", "www.danistay.gov.tr"})

    def _validate_adapter_specific_metadata(
        self,
        request: SourceDocumentRequest,
        raw_bytes: bytes,
        headers: dict[str, str],
    ) -> list[tuple[str, str]]:
        return _validate_court_decision_metadata("DANISTAY", request, raw_bytes)

    def _verify_document_content(
        self,
        request: SourceDocumentRequest,
        extracted_text: str,
        text_format: str,
    ) -> dict[str, Any]:
        return _match_court_decision_content(
            prefix="DANISTAY",
            court_marker="danistay",
            request=request,
            extracted_text=extracted_text,
            text_format=text_format,
        )
