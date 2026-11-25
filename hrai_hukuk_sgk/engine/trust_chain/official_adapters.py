"""Official Legislation Source Adapters: Resmî Gazete & Mevzuat Bilgi Sistemi (hrAI @HukukSGK v1.0.6 WP2.2)."""

from __future__ import annotations

import re

from .adapter import SourceAdapter
from .models import ADAPTER_MEVZUAT, ADAPTER_RESMI_GAZETE, SourceDocumentRequest

_GAZETTE_NO_RE = re.compile(r"^[1-9][0-9]{3,6}$")
_MEVZUAT_NO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,63}$")
_VALID_MEVZUAT_TYPES: frozenset[str] = frozenset(
    {"KANUN", "CBK", "YONETMELIK", "TEBLIG", "TUZUK", "KARAR", "GENELGE"}
)


class ResmiGazeteAdapter(SourceAdapter):
    """Fail-closed adapter for T.C. Resmî Gazete (`resmigazete.gov.tr`)."""

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


class MevzuatAdapter(SourceAdapter):
    """Fail-closed adapter for T.C. Mevzuat Bilgi Sistemi (`mevzuat.gov.tr`)."""

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
