"""Institutional Source Adapters: SGK & İŞKUR (hrAI @HukukSGK v1.0.6 WP2.4)."""

from __future__ import annotations

import re

from .adapter import SourceAdapter
from .models import ADAPTER_ISKUR, ADAPTER_SGK, SourceDocumentRequest

_REF_NO_RE = re.compile(r"^[A-Za-z0-9ÇĞİÖŞÜçğıöşü][A-Za-z0-9ÇĞİÖŞÜçğıöşü._/ -]{1,63}$")
_SGK_DOC_TYPES: frozenset[str] = frozenset({"GENELGE", "GENEL_YAZI", "DUYURU", "TEBLIG", "YONETMELIK"})
_ISKUR_DOC_TYPES: frozenset[str] = frozenset(
    {"GENELGE", "YONETMELIK", "DUYURU", "USUL_VE_ESASLAR", "PROGRAM_REHBERI"}
)


class SgkAdapter(SourceAdapter):
    """Fail-closed adapter for Sosyal Güvenlik Kurumu (`sgk.gov.tr`)."""

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


class IskurAdapter(SourceAdapter):
    """Fail-closed adapter for Türkiye İş Kurumu (`iskur.gov.tr`)."""

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
