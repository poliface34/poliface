"""Data contracts, strict validators, and canonical SHA-256 helpers for hrAI @HukukSGK v1.0.6 WP-2 Trust Chain."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timezone
import hashlib
import json
import re
from typing import Any

TRUST_CHAIN_VERSION = "1.0.6-wp2"

TRUST_CHAIN_LEGAL_BOUNDARY_NOTICE = (
    "hrAI @HukukSGK v1.0.6 WP-2 güven zinciri kaynak edinimi ve kanıt bağlama katmanı teknik izlenebilirlik "
    "ve bütünlük doğrulaması sağlar; tek başına üretim kullanım yetkisi, 5070 sayılı Kanun kapsamında "
    "Güvenli Elektronik İmza eşdeğerliği veya 6698 sayılı KVKK m.9 yurt dışına veri aktarımı onayı vermez. "
    "TLS el sıkışması tek başına geçmiş içerik kanıtı değildir."
)

# Canonical adapter types
ADAPTER_RESMI_GAZETE = "RESMI_GAZETE"
ADAPTER_MEVZUAT = "MEVZUAT"
ADAPTER_SGK = "SGK"
ADAPTER_ISKUR = "ISKUR"
ADAPTER_YARGITAY = "YARGITAY"
ADAPTER_DANISTAY = "DANISTAY"

VALID_ADAPTER_TYPES: frozenset[str] = frozenset(
    {
        ADAPTER_RESMI_GAZETE,
        ADAPTER_MEVZUAT,
        ADAPTER_SGK,
        ADAPTER_ISKUR,
        ADAPTER_YARGITAY,
        ADAPTER_DANISTAY,
    }
)

# Transport & verification statuses
TRANSPORT_LIVE_HTTPS = "LIVE_HTTPS"
TRANSPORT_INJECTED_TEST = "INJECTED_TEST_TRANSPORT"
TRANSPORT_UNREACHABLE = "UNREACHABLE"

STATUS_VERIFIED_LIVE = "VERIFIED_LIVE"
STATUS_VERIFIED_TEST_TRANSPORT = "VERIFIED_TEST_TRANSPORT"
STATUS_UNREACHABLE_NOT_VERIFIED = "UNREACHABLE_NOT_VERIFIED"
STATUS_REJECTED_INVALID_SOURCE = "REJECTED_INVALID_SOURCE"
STATUS_SUPERSEDED = "SUPERSEDED"

GENESIS_CHAIN_HASH = "GENESIS"

_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_UTC_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_KEY_RE = re.compile(r"^[A-Z0-9][A-Z0-9._:/-]{1,127}$")


class TrustChainError(RuntimeError):
    """Base fail-closed exception for WP-2 trust chain adapters, registry, and answer linkage."""

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(f"[{error_code}] {message}")
        self.error_code = error_code
        self.message = message


class EvidenceRegistryError(TrustChainError):
    """Raised when EvidenceRegistry invariants or fail-closed checks are violated."""


class AnswerLinkageError(TrustChainError):
    """Raised when a legal answer cannot be safely bound to verified evidence."""


def canonical_json_bytes(obj: Any) -> bytes:
    """Serialize `obj` deterministically as compact UTF-8 JSON for SHA-256 hashing."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def canonical_sha256(obj: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()


def parse_strict_iso_date(value: Any, field_name: str) -> date:
    """Strictly parse `YYYY-MM-DD` date string; fail closed on malformed or missing dates."""
    if not isinstance(value, str) or not _ISO_DATE_RE.fullmatch(value.strip()):
        raise TrustChainError("INVALID_ISO_DATE", f"'{field_name}' alanı geçerli YYYY-MM-DD biçiminde olmalıdır: {value!r}")
    try:
        return date.fromisoformat(value.strip())
    except ValueError as exc:
        raise TrustChainError("INVALID_ISO_DATE", f"'{field_name}' geçersiz takvim tarihidir: {value!r}") from exc


def normalize_utc_timestamp(value: Any, field_name: str = "acquired_at_utc") -> str:
    """Parse timezone-aware ISO-8601 timestamp and normalize strictly to `YYYY-MM-DDTHH:MM:SSZ`."""
    if not isinstance(value, str) or not _UTC_TS_RE.fullmatch(value.strip()):
        raise TrustChainError(
            "INVALID_UTC_TIMESTAMP",
            f"'{field_name}' alanı saat dilimli ISO-8601 (YYYY-MM-DDTHH:MM:SSZ veya ±HH:MM) olmalıdır: {value!r}",
        )
    raw = value.strip()
    iso_str = f"{raw[:-1]}+00:00" if raw.endswith("Z") else raw
    try:
        dt = datetime.fromisoformat(iso_str).astimezone(timezone.utc)
    except ValueError as exc:
        raise TrustChainError("INVALID_UTC_TIMESTAMP", f"'{field_name}' geçersiz zaman damgasıdır: {value!r}") from exc
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def is_valid_sha256_hex(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256_RE.fullmatch(value))


def is_valid_source_key(value: Any) -> bool:
    return isinstance(value, str) and bool(_SOURCE_KEY_RE.fullmatch(value.strip()))


@dataclass(frozen=True)
class SourceDocumentRequest:
    """Input descriptor for acquiring and validating a single official legal source document."""

    source_key: str
    source_url: str
    title: str
    publication_date: str
    effective_date: str
    expiry_or_repeal_date: str | None = None
    adapter_metadata: dict[str, Any] = field(default_factory=dict)
    expected_content_sha256: str | None = None
    supersedes_evidence_id: str | None = None
    retroactive_effective_allowed: bool = False


@dataclass(frozen=True)
class EvidenceRecord:
    """Immutable, SHA-256-sealed evidence record for an acquired legal source."""

    evidence_id: str
    source_key: str
    adapter_type: str
    title: str
    source_url: str
    final_url: str
    redirect_chain: tuple[str, ...]
    acquired_at_utc: str
    publication_date: str
    effective_date: str
    expiry_or_repeal_date: str | None
    version_number: int
    supersedes_evidence_id: str | None
    content_sha256: str
    content_bytes_length: int
    content_type: str
    http_status: int | None
    transport_mode: str
    live_verified: bool
    status: str
    adapter_metadata: dict[str, Any]
    metadata_sha256: str
    record_sha256: str
    previous_record_sha256: str = GENESIS_CHAIN_HASH
    error_codes: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    legal_boundary_notice: str = TRUST_CHAIN_LEGAL_BOUNDARY_NOTICE

    @property
    def is_verified_authority(self) -> bool:
        return (
            self.status in (STATUS_VERIFIED_LIVE, STATUS_VERIFIED_TEST_TRANSPORT)
            and is_valid_sha256_hex(self.content_sha256)
            and self.content_bytes_length > 0
            and len(self.error_codes) == 0
        )

    def metadata_payload(self) -> dict[str, Any]:
        return {
            "source_key": self.source_key,
            "adapter_type": self.adapter_type,
            "title": self.title,
            "source_url": self.source_url,
            "final_url": self.final_url,
            "redirect_chain": list(self.redirect_chain),
            "acquired_at_utc": self.acquired_at_utc,
            "publication_date": self.publication_date,
            "effective_date": self.effective_date,
            "expiry_or_repeal_date": self.expiry_or_repeal_date,
            "content_type": self.content_type,
            "http_status": self.http_status,
            "transport_mode": self.transport_mode,
            "live_verified": self.live_verified,
            "adapter_metadata": self.adapter_metadata,
        }

    def chain_payload(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source_key": self.source_key,
            "adapter_type": self.adapter_type,
            "version_number": self.version_number,
            "supersedes_evidence_id": self.supersedes_evidence_id,
            "content_sha256": self.content_sha256,
            "content_bytes_length": self.content_bytes_length,
            "metadata_sha256": self.metadata_sha256,
            "status": self.status,
            "previous_record_sha256": self.previous_record_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source_key": self.source_key,
            "adapter_type": self.adapter_type,
            "title": self.title,
            "source_url": self.source_url,
            "final_url": self.final_url,
            "redirect_chain": list(self.redirect_chain),
            "acquired_at_utc": self.acquired_at_utc,
            "publication_date": self.publication_date,
            "effective_date": self.effective_date,
            "expiry_or_repeal_date": self.expiry_or_repeal_date,
            "version_number": self.version_number,
            "supersedes_evidence_id": self.supersedes_evidence_id,
            "content_sha256": self.content_sha256,
            "content_bytes_length": self.content_bytes_length,
            "content_type": self.content_type,
            "http_status": self.http_status,
            "transport_mode": self.transport_mode,
            "live_verified": self.live_verified,
            "status": self.status,
            "adapter_metadata": dict(self.adapter_metadata),
            "metadata_sha256": self.metadata_sha256,
            "record_sha256": self.record_sha256,
            "previous_record_sha256": self.previous_record_sha256,
            "error_codes": list(self.error_codes),
            "errors": list(self.errors),
            "legal_boundary_notice": self.legal_boundary_notice,
        }


@dataclass(frozen=True)
class AcquisitionResult:
    """Outcome of a single `SourceAdapter.acquire_and_validate()` invocation."""

    ok: bool
    status: str
    record: EvidenceRecord
    raw_bytes: bytes = b""
    error_codes: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status": self.status,
            "record": self.record.to_dict(),
            "raw_bytes_length": len(self.raw_bytes),
            "error_codes": list(self.error_codes),
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class AnswerEvidenceLink:
    """Explicit traceable binding between a legal answer and one registered EvidenceRecord."""

    evidence_id: str
    source_key: str
    adapter_type: str
    title: str
    source_url: str
    final_url: str
    acquired_at_utc: str
    publication_date: str
    effective_date: str
    expiry_or_repeal_date: str | None
    version_number: int
    supersedes_evidence_id: str | None
    is_current_version: bool
    is_superseded: bool
    content_sha256: str
    record_sha256: str
    transport_mode: str
    live_verified: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source_key": self.source_key,
            "adapter_type": self.adapter_type,
            "title": self.title,
            "source_url": self.source_url,
            "final_url": self.final_url,
            "acquired_at_utc": self.acquired_at_utc,
            "publication_date": self.publication_date,
            "effective_date": self.effective_date,
            "expiry_or_repeal_date": self.expiry_or_repeal_date,
            "version_number": self.version_number,
            "supersedes_evidence_id": self.supersedes_evidence_id,
            "is_current_version": self.is_current_version,
            "is_superseded": self.is_superseded,
            "content_sha256": self.content_sha256,
            "record_sha256": self.record_sha256,
            "transport_mode": self.transport_mode,
            "live_verified": self.live_verified,
        }


@dataclass(frozen=True)
class EvidenceLinkedAnswer:
    """End-to-end traceable legal answer bound to verified EvidenceRegistry records."""

    answer_id: str
    trust_chain_version: str
    query: str
    as_of_date: str
    generated_at_utc: str
    answer_text: str
    evidence_ids: tuple[str, ...]
    evidence_links: tuple[AnswerEvidenceLink, ...]
    all_evidence_verified: bool
    all_evidence_live_verified: bool
    historical_disclosure_included: bool
    historical_disclosure_text: str | None
    registry_head_sha256: str
    answer_sha256: str
    router_payload: dict[str, Any] | None = None
    production_use_authorized: bool = False
    qualified_e_signature_5070_equivalent: bool = False
    kvkk_data_residency_approved: bool = False
    legal_boundary_notice: str = TRUST_CHAIN_LEGAL_BOUNDARY_NOTICE

    def to_dict(self) -> dict[str, Any]:
        return {
            "answer_id": self.answer_id,
            "trust_chain_version": self.trust_chain_version,
            "query": self.query,
            "as_of_date": self.as_of_date,
            "generated_at_utc": self.generated_at_utc,
            "answer_text": self.answer_text,
            "evidence_ids": list(self.evidence_ids),
            "evidence_links": [lnk.to_dict() for lnk in self.evidence_links],
            "all_evidence_verified": self.all_evidence_verified,
            "all_evidence_live_verified": self.all_evidence_live_verified,
            "historical_disclosure_included": self.historical_disclosure_included,
            "historical_disclosure_text": self.historical_disclosure_text,
            "registry_head_sha256": self.registry_head_sha256,
            "answer_sha256": self.answer_sha256,
            "router_payload": self.router_payload,
            "production_use_authorized": self.production_use_authorized,
            "qualified_e_signature_5070_equivalent": self.qualified_e_signature_5070_equivalent,
            "kvkk_data_residency_approved": self.kvkk_data_residency_approved,
            "legal_boundary_notice": self.legal_boundary_notice,
        }
