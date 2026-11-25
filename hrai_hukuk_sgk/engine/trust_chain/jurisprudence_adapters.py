"""Jurisprudence Source Adapters: Yargıtay & Danıştay (hrAI @HukukSGK v1.0.6 WP2.5)."""

from __future__ import annotations

import re

from .adapter import SourceAdapter
from .models import (
    ADAPTER_DANISTAY,
    ADAPTER_YARGITAY,
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
