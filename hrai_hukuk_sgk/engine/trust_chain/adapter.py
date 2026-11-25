"""Common fail-closed SourceAdapter contract with Document Content-vs-Metadata Verification (hrAI @HukukSGK v1.0.6 WP2.1).

Reuses `engine/trust_root/source_acquisition.py` HTTPS/domain/TLS verification primitives and enforces:
  - HTTPS-only allowlisted official domain URLs (rejects generic root homepages `/` and userinfo).
  - Strict separation of `publication_date` vs `effective_date` (and optional `expiry_or_repeal_date`).
  - Strict separation of `LIVE_HTTPS` (only via real `LiveHttpsSourceFetcher` with subset domain scope)
    vs `INJECTED_TEST_TRANSPORT` (callback spoofing of `LIVE_HTTPS` is unconditionally blocked).
  - Fail-closed handling of unreachable sources (timeout, network error, HTTP != 200 -> `UNREACHABLE_NOT_VERIFIED`).
  - PR #3 Finding 2 remediation: parses downloaded document content (HTML/text/PDF text streams) and
    matches declared document identifiers (gazette/mevzuat/reference/Esas-Karar numbers, title/date
    markers) against actual downloaded bytes. Transport/TLS alone NEVER yields `VERIFIED_LIVE`:
      * Extractable text mismatch -> `REJECTED_CONTENT_MISMATCH` (`ok=False`, fail-closed).
      * Unparseable opaque binary (e.g. image-only PDF) -> `TRANSPORT_ONLY_UNVERIFIED_CONTENT`
        (`ok=False`, `content_verified=False`, `live_verified=False`, NEVER `VERIFIED_LIVE`).
      * Full content + metadata match -> `VERIFIED_LIVE` (real HTTPS) or `VERIFIED_TEST_TRANSPORT`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import copy
from datetime import datetime, timezone
import hashlib
import html
import re
from typing import Any, Callable
from urllib.parse import urlparse
import zlib

from ..trust_root.source_acquisition import (
    LiveHttpsSourceFetcher,
    SourceAcquisitionSecurityError,
    validate_official_https_url,
)
from .models import (
    CONTENT_MATCH_MATCHED,
    CONTENT_MATCH_MISMATCH,
    CONTENT_MATCH_NOT_EVALUATED,
    CONTENT_MATCH_UNPARSEABLE_BINARY,
    GENESIS_CHAIN_HASH,
    STATUS_REJECTED_CONTENT_MISMATCH,
    STATUS_REJECTED_INVALID_SOURCE,
    STATUS_TRANSPORT_ONLY_UNVERIFIED_CONTENT,
    STATUS_UNREACHABLE_NOT_VERIFIED,
    STATUS_VERIFIED_LIVE,
    STATUS_VERIFIED_TEST_TRANSPORT,
    TRANSPORT_INJECTED_TEST,
    TRANSPORT_LIVE_HTTPS,
    TRANSPORT_UNREACHABLE,
    TRUST_CHAIN_LEGAL_BOUNDARY_NOTICE,
    AcquisitionResult,
    EvidenceRecord,
    SourceDocumentRequest,
    TrustChainError,
    canonical_sha256,
    is_valid_sha256_hex,
    is_valid_source_key,
    normalize_utc_timestamp,
    parse_strict_iso_date,
)

TransportCallable = Callable[[str], dict[str, Any]]
MIN_DOCUMENT_BYTES = 20
_MAX_PDF_INFLATE_BYTES = 2 * 1024 * 1024

_TR_FOLD_TABLE = str.maketrans(
    {
        "İ": "i",
        "I": "i",
        "ı": "i",
        "Ş": "s",
        "ş": "s",
        "Ğ": "g",
        "ğ": "g",
        "Ü": "u",
        "ü": "u",
        "Ö": "o",
        "ö": "o",
        "Ç": "c",
        "ç": "c",
    }
)
_SCRIPT_STYLE_RE = re.compile(r"<(?:script|style)\b[^>]*>.*?</(?:script|style)>", re.IGNORECASE | re.DOTALL)
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_PDF_STREAM_RE = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.DOTALL)
_PDF_STRUCTURAL_TOKENS: frozenset[str] = frozenset(
    {
        "pdf",
        "obj",
        "endobj",
        "xref",
        "trailer",
        "startxref",
        "eof",
        "stream",
        "endstream",
        "type",
        "catalog",
        "pages",
        "page",
        "length",
        "filter",
        "flatedecode",
        "image",
        "xobject",
        "subtype",
        "width",
        "height",
        "bitspercomponent",
        "colorspace",
        "devicergb",
        "devicegray",
    }
)
_STOPWORDS: frozenset[str] = frozenset(
    {
        "ve",
        "veya",
        "ile",
        "bir",
        "bu",
        "da",
        "de",
        "icin",
        "gore",
        "hakkinda",
        "iliskin",
        "sayili",
        "yili",
        "karari",
        "metni",
        "eski",
        "guncel",
        "surumu",
    }
)


def normalize_turkish_text(text: str) -> str:
    """Fold Turkish characters and case to normalized ASCII-friendly lowercase with collapsed whitespace."""
    folded = text.translate(_TR_FOLD_TABLE).lower()
    return re.sub(r"\s+", " ", folded).strip()


def has_exact_identifier(normalized_text: str, identifier: str) -> bool:
    """Return True iff `identifier` appears in `normalized_text` with non-alphanumeric boundaries."""
    needle = normalize_turkish_text(identifier)
    if not needle:
        return False
    pattern = r"(?<![a-z0-9])" + re.escape(needle) + r"(?![a-z0-9])"
    return bool(re.search(pattern, normalized_text))


def extract_title_keywords(title: str) -> list[str]:
    """Extract normalized significant keywords (`len >= 3`) from a declared document title."""
    norm = normalize_turkish_text(title)
    tokens = re.findall(r"[a-z0-9]+", norm)
    out: list[str] = []
    seen: set[str] = set()
    for tok in tokens:
        if len(tok) >= 3 and tok not in _STOPWORDS and tok not in seen:
            seen.add(tok)
            out.append(tok)
    return out


def format_turkish_date_variants(iso_date: str) -> tuple[str, ...]:
    """Return normalized textual representations of an ISO date (`YYYY-MM-DD`, `DD.MM.YYYY`, `DD/MM/YYYY`)."""
    parts = iso_date.strip().split("-")
    if len(parts) != 3:
        return (iso_date.strip(),)
    yyyy, mm, dd = parts
    return (
        f"{yyyy}-{mm}-{dd}",
        f"{dd}.{mm}.{yyyy}",
        f"{int(dd)}.{int(mm)}.{yyyy}",
        f"{dd}/{mm}/{yyyy}",
    )


_PDF_DICT_RE = re.compile(rb"<<.*?>>", re.DOTALL)
_PDF_OBJ_HDR_RE = re.compile(rb"\b\d+\s+\d+\s+(?:obj|R)\b|\b(?:endobj|xref|trailer|startxref)\b|%PDF-\d+\.\d+|%%EOF")


def _is_mostly_printable_text(data: bytes) -> bool:
    if not data or b"\x00" in data:
        return False
    printable = sum(1 for b in data if b in (9, 10, 13) or 32 <= b <= 126 or b >= 128)
    return (printable / len(data)) >= 0.85


def extract_document_text(raw_bytes: bytes, content_type: str = "") -> tuple[str, str]:
    """Extract human-readable text from downloaded HTML/text/PDF bytes using stdlib only.

    Returns `(extracted_text, format_label)` where `format_label` is one of:
      - `"TEXT_HTML"`
      - `"PDF_TEXT_STREAM"`
      - `"UNPARSEABLE_BINARY"`
    """
    is_pdf = raw_bytes.startswith(b"%PDF-") or "application/pdf" in content_type.lower()
    if is_pdf:
        chunks: list[str] = []
        # 1. Decompress bounded FlateDecode streams (bomb-safe) or accept printable text streams; skip binary/image streams
        total_inflated = 0
        for m in _PDF_STREAM_RE.finditer(raw_bytes):
            remaining = _MAX_PDF_INFLATE_BYTES - total_inflated
            if remaining <= 0:
                break
            preceding_hdr = raw_bytes[max(0, m.start() - 256) : m.start()]
            if re.search(rb"/Subtype\s*/Image|/DCTDecode|/JPXDecode|/CCITTFaxDecode|/JBIG2Decode", preceding_hdr):
                continue
            stream_data = m.group(1)
            decompressed: bytes | None = None
            try:
                decompressor = zlib.decompressobj()
                cand = decompressor.decompress(stream_data, remaining)
                if cand and _is_mostly_printable_text(cand):
                    decompressed = cand
            except zlib.error:
                if _is_mostly_printable_text(stream_data[:remaining]):
                    decompressed = stream_data[:remaining]
            if decompressed:
                total_inflated += len(decompressed)
                chunks.append(decompressed.decode("utf-8", errors="ignore"))

        # 2. Extract readable printable text runs outside binary streams and PDF dictionaries/object headers
        outside_streams = _PDF_STREAM_RE.sub(b" ", raw_bytes)
        outside_dicts = _PDF_DICT_RE.sub(b" ", outside_streams)
        outside_struct = _PDF_OBJ_HDR_RE.sub(b" ", outside_dicts)
        printable_runs = re.findall(rb"[A-Za-z0-9\xC0-\xFF\s./,:;()_\-]{6,}", outside_struct)
        for run in printable_runs:
            chunks.append(run.decode("utf-8", errors="ignore"))

        combined = " ".join(chunks)
        norm = normalize_turkish_text(combined)
        meaningful_words = [
            tok for tok in re.findall(r"[a-z]{3,}", norm) if tok not in _PDF_STRUCTURAL_TOKENS
        ]
        if len(meaningful_words) < 3:
            return "", "UNPARSEABLE_BINARY"
        return combined, "PDF_TEXT_STREAM"

    # Non-PDF payload: reject pure binary containing NUL bytes
    if b"\x00" in raw_bytes:
        return "", "UNPARSEABLE_BINARY"

    try:
        decoded = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            decoded = raw_bytes.decode("cp1254")
        except UnicodeDecodeError:
            return "", "UNPARSEABLE_BINARY"

    stripped = _SCRIPT_STYLE_RE.sub(" ", decoded)
    stripped = _HTML_TAG_RE.sub(" ", stripped)
    stripped = html.unescape(stripped)
    stripped = re.sub(r"\s+", " ", stripped).strip()
    if len(stripped) < 10:
        return "", "UNPARSEABLE_BINARY"
    return stripped, "TEXT_HTML"


def _validate_specific_official_url(url: str, allowed_domains: frozenset[str]) -> tuple[str | None, str | None]:
    """Validate HTTPS + official domain allowlist + non-generic document path/query."""
    err_code, err_msg = validate_official_https_url(url, allowed_domains=allowed_domains)
    if err_code:
        return err_code, err_msg
    parsed = urlparse(url.strip())
    path = (parsed.path or "").strip()
    query = (parsed.query or "").strip()
    if (not path or path == "/") and not query:
        return (
            "GENERIC_ROOT_URL_REJECTED",
            f"Genel ana sayfa URL'si kaynak kanıtı olarak kabul edilmez; belgeye özgü yol/sorgu zorunludur: '{url}'.",
        )
    return None, None


class SourceAdapter(ABC):
    """Abstract base contract implemented by all official, institutional, and jurisprudence source adapters."""

    def __init__(
        self,
        *,
        live_fetcher: LiveHttpsSourceFetcher | None = None,
        transport: TransportCallable | None = None,
        timeout_seconds: float = 15.0,
    ) -> None:
        if live_fetcher is not None and transport is not None:
            raise ValueError("Specify at most one of `live_fetcher` or `transport`.")
        self._live_fetcher = live_fetcher
        self._transport = transport
        self._timeout_seconds = float(timeout_seconds)

    @property
    @abstractmethod
    def adapter_type(self) -> str:
        """Canonical adapter identifier (e.g. RESMI_GAZETE, MEVZUAT, SGK, ISKUR, YARGITAY, DANISTAY)."""

    @property
    @abstractmethod
    def allowed_domains(self) -> frozenset[str]:
        """Strict allowlist of official hostnames permitted for this adapter."""

    @abstractmethod
    def _validate_adapter_specific_metadata(
        self,
        request: SourceDocumentRequest,
        raw_bytes: bytes,
        headers: dict[str, str],
    ) -> list[tuple[str, str]]:
        """Validate source-specific metadata fields and payload sanity; return list of `(error_code, message)`."""

    @abstractmethod
    def _verify_document_content(
        self,
        request: SourceDocumentRequest,
        extracted_text: str,
        text_format: str,
    ) -> dict[str, Any]:
        """Match declared request identifiers/metadata against extracted document text."""

    def _build_failure_result(
        self,
        *,
        request: SourceDocumentRequest,
        status: str,
        transport_mode: str,
        error_codes: list[str],
        errors: list[str],
        acquired_at_utc: str,
        final_url: str = "",
        redirect_chain: tuple[str, ...] = (),
        http_status: int | None = None,
        content_type: str = "",
        raw_bytes: bytes = b"",
        content_sha256: str = "",
        content_verification: dict[str, Any] | None = None,
    ) -> AcquisitionResult:
        cv_block = copy.deepcopy(
            content_verification
            if content_verification is not None
            else {
                "content_match_status": CONTENT_MATCH_NOT_EVALUATED,
                "extracted_text_format": "NONE",
                "matched_fields": [],
                "mismatched_or_missing_fields": [],
                "extracted_evidence": {},
            }
        )
        fail_seed = {
            "source_key": request.source_key,
            "adapter_type": self.adapter_type,
            "source_url": request.source_url,
            "acquired_at_utc": acquired_at_utc,
            "status": status,
            "content_sha256": content_sha256,
            "error_codes": error_codes,
        }
        ev_id = f"EVD-FAIL-{self.adapter_type}-{canonical_sha256(fail_seed)[:12].upper()}"
        meta_payload = {
            "source_key": request.source_key,
            "adapter_type": self.adapter_type,
            "title": request.title,
            "source_url": request.source_url,
            "final_url": final_url or request.source_url,
            "redirect_chain": list(redirect_chain),
            "acquired_at_utc": acquired_at_utc,
            "publication_date": request.publication_date,
            "effective_date": request.effective_date,
            "expiry_or_repeal_date": request.expiry_or_repeal_date,
            "content_type": content_type,
            "http_status": http_status,
            "transport_mode": transport_mode,
            "live_verified": False,
            "content_verified": False,
            "content_verification": cv_block,
            "adapter_metadata": copy.deepcopy(request.adapter_metadata),
        }
        meta_sha = canonical_sha256(meta_payload)
        rec_sha = canonical_sha256(
            {
                "evidence_id": ev_id,
                "source_key": request.source_key,
                "adapter_type": self.adapter_type,
                "version_number": 0,
                "supersedes_evidence_id": request.supersedes_evidence_id,
                "content_sha256": content_sha256,
                "content_bytes_length": len(raw_bytes),
                "metadata_sha256": meta_sha,
                "status": status,
                "previous_record_sha256": GENESIS_CHAIN_HASH,
            }
        )
        rec = EvidenceRecord(
            evidence_id=ev_id,
            source_key=str(request.source_key or ""),
            adapter_type=self.adapter_type,
            title=str(request.title or ""),
            source_url=str(request.source_url or ""),
            final_url=final_url or str(request.source_url or ""),
            redirect_chain=redirect_chain,
            acquired_at_utc=acquired_at_utc,
            publication_date=str(request.publication_date or ""),
            effective_date=str(request.effective_date or ""),
            expiry_or_repeal_date=request.expiry_or_repeal_date,
            version_number=0,
            supersedes_evidence_id=request.supersedes_evidence_id,
            content_sha256=content_sha256,
            content_bytes_length=len(raw_bytes),
            content_type=content_type,
            http_status=http_status,
            transport_mode=transport_mode,
            live_verified=False,
            content_verified=False,
            content_verification=cv_block,
            status=status,
            adapter_metadata=copy.deepcopy(request.adapter_metadata),
            metadata_sha256=meta_sha,
            record_sha256=rec_sha,
            previous_record_sha256=GENESIS_CHAIN_HASH,
            error_codes=tuple(error_codes),
            errors=tuple(errors),
            legal_boundary_notice=TRUST_CHAIN_LEGAL_BOUNDARY_NOTICE,
        )
        return AcquisitionResult(
            ok=False,
            status=status,
            record=rec,
            raw_bytes=raw_bytes,
            error_codes=tuple(error_codes),
            errors=tuple(errors),
        )

    def acquire_and_validate(self, request: SourceDocumentRequest) -> AcquisitionResult:
        """Acquire document from official source, validate URL/dates/metadata/SHA-256 AND match downloaded content."""
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        req_errors: list[tuple[str, str]] = []

        # 1. Core request field validation
        if not is_valid_source_key(request.source_key):
            req_errors.append(("INVALID_SOURCE_KEY", f"Geçersiz source_key biçimi: {request.source_key!r}"))
        if not isinstance(request.title, str) or len(request.title.strip()) < 3:
            req_errors.append(("MISSING_OR_SHORT_TITLE", "Kaynak başlığı ('title') en az 3 karakter olmalıdır."))

        url_code, url_msg = _validate_specific_official_url(request.source_url, self.allowed_domains)
        if url_code:
            req_errors.append((url_code, url_msg or "Geçersiz resmî kaynak URL'si."))

        pub_date = None
        eff_date = None
        try:
            pub_date = parse_strict_iso_date(request.publication_date, "publication_date")
        except TrustChainError as exc:
            req_errors.append((exc.error_code, exc.message))
        try:
            eff_date = parse_strict_iso_date(request.effective_date, "effective_date")
        except TrustChainError as exc:
            req_errors.append((exc.error_code, exc.message))

        if pub_date is not None and eff_date is not None and eff_date < pub_date:
            rationale = str(request.adapter_metadata.get("retroactive_rationale", "")).strip()
            if not request.retroactive_effective_allowed or not rationale:
                req_errors.append(
                    (
                        "RETROACTIVE_EFFECTIVE_DATE_UNDECLARED",
                        f"Yürürlük tarihi ({request.effective_date}) yayım tarihinden ({request.publication_date}) "
                        "önce olamaz (geriye yürürlük açıkça ve gerekçesiyle beyan edilmedikçe).",
                    )
                )

        if request.expiry_or_repeal_date is not None:
            try:
                exp_date = parse_strict_iso_date(request.expiry_or_repeal_date, "expiry_or_repeal_date")
                if eff_date is not None and exp_date < eff_date:
                    req_errors.append(
                        (
                            "INVALID_EXPIRY_BEFORE_EFFECTIVE",
                            f"Mülga/sona erme tarihi ({request.expiry_or_repeal_date}) yürürlük tarihinden "
                            f"({request.effective_date}) önce olamaz.",
                        )
                    )
            except TrustChainError as exc:
                req_errors.append((exc.error_code, exc.message))

        if request.expected_content_sha256 is not None and not is_valid_sha256_hex(request.expected_content_sha256):
            req_errors.append(
                (
                    "INVALID_EXPECTED_SHA256",
                    f"expected_content_sha256 64 karakterlik küçük harf SHA-256 olmalıdır: {request.expected_content_sha256!r}",
                )
            )

        if req_errors:
            return self._build_failure_result(
                request=request,
                status=STATUS_REJECTED_INVALID_SOURCE,
                transport_mode=TRANSPORT_UNREACHABLE,
                error_codes=[c for c, _ in req_errors],
                errors=[m for _, m in req_errors],
                acquired_at_utc=now_utc,
            )

        # 2. Execute acquisition transport (strictly separating real LiveHttpsSourceFetcher vs injected transport)
        is_real_live = self._transport is None
        try:
            if is_real_live:
                fetcher = self._live_fetcher or LiveHttpsSourceFetcher(
                    allowed_domains=self.allowed_domains,
                    timeout_seconds=self._timeout_seconds,
                )
                if not isinstance(fetcher, LiveHttpsSourceFetcher):
                    return self._build_failure_result(
                        request=request,
                        status=STATUS_REJECTED_INVALID_SOURCE,
                        transport_mode=TRANSPORT_UNREACHABLE,
                        error_codes=["INVALID_LIVE_FETCHER_INSTANCE"],
                        errors=["live_fetcher gerçek bir LiveHttpsSourceFetcher örneği olmalıdır."],
                        acquired_at_utc=now_utc,
                    )
                if not fetcher.allowed_domains.issubset(self.allowed_domains):
                    return self._build_failure_result(
                        request=request,
                        status=STATUS_REJECTED_INVALID_SOURCE,
                        transport_mode=TRANSPORT_UNREACHABLE,
                        error_codes=["LIVE_FETCHER_DOMAIN_SCOPE_EXCEEDED"],
                        errors=[
                            f"live_fetcher izinli alan adları ({sorted(fetcher.allowed_domains)}) "
                            f"adaptör beyaz listesini ({sorted(self.allowed_domains)}) aşamaz."
                        ],
                        acquired_at_utc=now_utc,
                    )
                resp = fetcher.fetch(request.source_url.strip())
            else:
                assert self._transport is not None
                resp = self._transport(request.source_url.strip())
        except SourceAcquisitionSecurityError as sec_exc:
            return self._build_failure_result(
                request=request,
                status=STATUS_UNREACHABLE_NOT_VERIFIED,
                transport_mode=TRANSPORT_UNREACHABLE,
                error_codes=[sec_exc.error_code],
                errors=[sec_exc.message],
                acquired_at_utc=now_utc,
            )
        except (TimeoutError, ConnectionError, OSError) as net_exc:
            return self._build_failure_result(
                request=request,
                status=STATUS_UNREACHABLE_NOT_VERIFIED,
                transport_mode=TRANSPORT_UNREACHABLE,
                error_codes=["SOURCE_UNREACHABLE"],
                errors=[f"Resmî kaynağa erişilemedi ('{request.source_url}'): {net_exc}"],
                acquired_at_utc=now_utc,
            )
        except Exception as exc:
            return self._build_failure_result(
                request=request,
                status=STATUS_UNREACHABLE_NOT_VERIFIED,
                transport_mode=TRANSPORT_UNREACHABLE,
                error_codes=["SOURCE_ACQUISITION_EXCEPTION"],
                errors=[f"Kaynak edinimi sırasında beklenmeyen hata: {exc}"],
                acquired_at_utc=now_utc,
            )

        if not isinstance(resp, dict) or resp.get("unreachable") is True:
            return self._build_failure_result(
                request=request,
                status=STATUS_UNREACHABLE_NOT_VERIFIED,
                transport_mode=TRANSPORT_UNREACHABLE,
                error_codes=["SOURCE_UNREACHABLE"],
                errors=[f"Kaynak erişilemez olarak bildirildi: '{request.source_url}'."],
                acquired_at_utc=now_utc,
            )

        # 3. Validate HTTP status, final URL, redirect chain, acquired_at_utc, and payload bytes
        http_status_raw = resp.get("http_status")
        http_status = (
            int(http_status_raw) if isinstance(http_status_raw, int) and not isinstance(http_status_raw, bool) else None
        )
        final_url = str(resp.get("final_url") or request.source_url).strip()
        redirect_chain = tuple(str(u).strip() for u in (resp.get("redirect_chain") or [request.source_url]))
        raw_headers = resp.get("http_headers") or {}
        headers = {str(k).lower(): str(v) for k, v in raw_headers.items()} if isinstance(raw_headers, dict) else {}
        content_type = headers.get("content-type", str(resp.get("content_type") or "")).strip()

        raw_acq_ts = resp.get("acquired_at_utc") or now_utc
        try:
            acquired_at_utc = normalize_utc_timestamp(raw_acq_ts, "acquired_at_utc")
        except TrustChainError as exc:
            return self._build_failure_result(
                request=request,
                status=STATUS_REJECTED_INVALID_SOURCE,
                transport_mode=TRANSPORT_UNREACHABLE,
                error_codes=[exc.error_code],
                errors=[exc.message],
                acquired_at_utc=now_utc,
                final_url=final_url,
                redirect_chain=redirect_chain,
                http_status=http_status,
                content_type=content_type,
            )

        if http_status != 200:
            return self._build_failure_result(
                request=request,
                status=STATUS_UNREACHABLE_NOT_VERIFIED,
                transport_mode=TRANSPORT_UNREACHABLE,
                error_codes=["SOURCE_HTTP_STATUS_NOT_OK"],
                errors=[f"Kaynak HTTP 200 döndürmedi (alınan: {http_status}): '{final_url}'."],
                acquired_at_utc=acquired_at_utc,
                final_url=final_url,
                redirect_chain=redirect_chain,
                http_status=http_status,
                content_type=content_type,
            )

        hop_errors: list[tuple[str, str]] = []
        if not redirect_chain or redirect_chain[0] != request.source_url.strip() or redirect_chain[-1] != final_url:
            hop_errors.append(
                (
                    "REDIRECT_CHAIN_INCONSISTENT",
                    f"Yönlendirme zinciri başlangıç URL'si ({request.source_url.strip()!r}) veya "
                    f"son URL ({final_url!r}) ile tutarsızdır.",
                )
            )
        f_code, f_msg = _validate_specific_official_url(final_url, self.allowed_domains)
        if f_code:
            hop_errors.append((f_code, f_msg or f"Geçersiz son URL: '{final_url}'."))
        for idx, hop in enumerate(redirect_chain):
            h_code, h_msg = validate_official_https_url(
                hop,
                allowed_domains=self.allowed_domains,
                is_redirect_hop=(idx > 0),
            )
            if h_code:
                hop_errors.append((h_code, h_msg or f"Geçersiz yönlendirme adımı: '{hop}'."))

        raw_bytes_obj = resp.get("raw_bytes")
        if not isinstance(raw_bytes_obj, (bytes, bytearray)) or len(raw_bytes_obj) < MIN_DOCUMENT_BYTES:
            hop_errors.append(
                (
                    "EMPTY_OR_TRUNCATED_DOCUMENT_BODY",
                    f"Alınan belge gövdesi boş veya çok kısa (< {MIN_DOCUMENT_BYTES} bayt).",
                )
            )
            raw_bytes = b""
        else:
            raw_bytes = bytes(raw_bytes_obj)

        if is_real_live:
            tls_res = resp.get("tls_verification_result")
            if not isinstance(tls_res, dict) or tls_res.get("verified") is not True or resp.get("fetcher_mode") != "LIVE_HTTPS":
                hop_errors.append(
                    (
                        "LIVE_TLS_VERIFICATION_MISSING",
                        "Canlı HTTPS ediniminde doğrulanmış TLS sertifika zinciri sonucu bulunamadı.",
                    )
                )

        if raw_bytes:
            hop_errors.extend(self._validate_adapter_specific_metadata(request, raw_bytes, headers))

        content_sha256 = hashlib.sha256(raw_bytes).hexdigest() if raw_bytes else ""
        if request.expected_content_sha256 is not None and content_sha256 != request.expected_content_sha256:
            hop_errors.append(
                (
                    "CONTENT_SHA256_MISMATCH",
                    f"Belge SHA-256 özeti beklenen değerle uyuşmuyor ({content_sha256} != {request.expected_content_sha256}).",
                )
            )

        transport_mode = TRANSPORT_LIVE_HTTPS if is_real_live else TRANSPORT_INJECTED_TEST

        if hop_errors:
            return self._build_failure_result(
                request=request,
                status=STATUS_REJECTED_INVALID_SOURCE,
                transport_mode=transport_mode,
                error_codes=[c for c, _ in hop_errors],
                errors=[m for _, m in hop_errors],
                acquired_at_utc=acquired_at_utc,
                final_url=final_url,
                redirect_chain=redirect_chain,
                http_status=http_status,
                content_type=content_type,
            )

        # 4. PR #3 Finding 2: Parse downloaded document bytes and match against declared metadata!
        extracted_text, text_format = extract_document_text(raw_bytes, content_type=content_type)
        if text_format == "UNPARSEABLE_BINARY":
            cv_unparseable = {
                "content_match_status": CONTENT_MATCH_UNPARSEABLE_BINARY,
                "extracted_text_format": "UNPARSEABLE_BINARY",
                "matched_fields": [],
                "mismatched_or_missing_fields": ["extractable_document_text"],
                "extracted_evidence": {},
            }
            return self._build_failure_result(
                request=request,
                status=STATUS_TRANSPORT_ONLY_UNVERIFIED_CONTENT,
                transport_mode=transport_mode,
                error_codes=["DOCUMENT_CONTENT_UNPARSEABLE_BINARY"],
                errors=[
                    "Taşıma/HTTPS/SHA-256 tamamlandı ancak indirilen ikili belgeden (örn. taranmış PDF) "
                    "metin ayrıştırılamadığı için içerik-metadata eşleştirmesi doğrulanamadı; "
                    "VERIFIED_LIVE / aktif kanıt statüsü verilmedi."
                ],
                acquired_at_utc=acquired_at_utc,
                final_url=final_url,
                redirect_chain=redirect_chain,
                http_status=http_status,
                content_type=content_type,
                raw_bytes=raw_bytes,
                content_sha256=content_sha256,
                content_verification=cv_unparseable,
            )

        content_ver = self._verify_document_content(request, extracted_text, text_format)
        match_status = content_ver.get("content_match_status")
        clean_cv = {
            "content_match_status": match_status,
            "extracted_text_format": content_ver.get("extracted_text_format", text_format),
            "matched_fields": list(content_ver.get("matched_fields", [])),
            "mismatched_or_missing_fields": list(content_ver.get("mismatched_or_missing_fields", [])),
            "extracted_evidence": copy.deepcopy(dict(content_ver.get("extracted_evidence", {}))),
        }

        if match_status != CONTENT_MATCH_MATCHED:
            err_code = str(content_ver.get("error_code") or f"{self.adapter_type}_CONTENT_MISMATCH")
            err_msg = str(
                content_ver.get("error_message")
                or f"İndirilen belge içeriği beyan edilen {self.adapter_type} metadatasıyla uyuşmuyor."
            )
            return self._build_failure_result(
                request=request,
                status=STATUS_REJECTED_CONTENT_MISMATCH,
                transport_mode=transport_mode,
                error_codes=[err_code],
                errors=[err_msg],
                acquired_at_utc=acquired_at_utc,
                final_url=final_url,
                redirect_chain=redirect_chain,
                http_status=http_status,
                content_type=content_type,
                raw_bytes=raw_bytes,
                content_sha256=content_sha256,
                content_verification=clean_cv,
            )

        # 5. Build content-verified EvidenceRecord (callback transport NEVER produces live_verified=True!)
        live_verified = bool(is_real_live)
        status = STATUS_VERIFIED_LIVE if live_verified else STATUS_VERIFIED_TEST_TRANSPORT

        meta_payload = {
            "source_key": request.source_key.strip(),
            "adapter_type": self.adapter_type,
            "title": request.title.strip(),
            "source_url": request.source_url.strip(),
            "final_url": final_url,
            "redirect_chain": list(redirect_chain),
            "acquired_at_utc": acquired_at_utc,
            "publication_date": request.publication_date.strip(),
            "effective_date": request.effective_date.strip(),
            "expiry_or_repeal_date": request.expiry_or_repeal_date.strip() if request.expiry_or_repeal_date else None,
            "content_type": content_type or "application/octet-stream",
            "http_status": http_status,
            "transport_mode": transport_mode,
            "live_verified": live_verified,
            "content_verified": True,
            "content_verification": clean_cv,
            "adapter_metadata": copy.deepcopy(request.adapter_metadata),
        }
        meta_sha = canonical_sha256(meta_payload)
        ev_seed = {
            "adapter_type": self.adapter_type,
            "source_key": request.source_key.strip(),
            "content_sha256": content_sha256,
            "metadata_sha256": meta_sha,
            "supersedes_evidence_id": request.supersedes_evidence_id,
        }
        evidence_id = f"EVD-{self.adapter_type}-{canonical_sha256(ev_seed)[:16].upper()}"
        record_sha = canonical_sha256(
            {
                "evidence_id": evidence_id,
                "source_key": request.source_key.strip(),
                "adapter_type": self.adapter_type,
                "version_number": 1,
                "supersedes_evidence_id": request.supersedes_evidence_id,
                "content_sha256": content_sha256,
                "content_bytes_length": len(raw_bytes),
                "metadata_sha256": meta_sha,
                "status": status,
                "previous_record_sha256": GENESIS_CHAIN_HASH,
            }
        )

        record = EvidenceRecord(
            evidence_id=evidence_id,
            source_key=request.source_key.strip(),
            adapter_type=self.adapter_type,
            title=request.title.strip(),
            source_url=request.source_url.strip(),
            final_url=final_url,
            redirect_chain=redirect_chain,
            acquired_at_utc=acquired_at_utc,
            publication_date=request.publication_date.strip(),
            effective_date=request.effective_date.strip(),
            expiry_or_repeal_date=request.expiry_or_repeal_date.strip() if request.expiry_or_repeal_date else None,
            version_number=1,
            supersedes_evidence_id=request.supersedes_evidence_id,
            content_sha256=content_sha256,
            content_bytes_length=len(raw_bytes),
            content_type=content_type or "application/octet-stream",
            http_status=http_status,
            transport_mode=transport_mode,
            live_verified=live_verified,
            content_verified=True,
            content_verification=clean_cv,
            status=status,
            adapter_metadata=copy.deepcopy(request.adapter_metadata),
            metadata_sha256=meta_sha,
            record_sha256=record_sha,
            previous_record_sha256=GENESIS_CHAIN_HASH,
            error_codes=(),
            errors=(),
            legal_boundary_notice=TRUST_CHAIN_LEGAL_BOUNDARY_NOTICE,
        )
        return AcquisitionResult(
            ok=True,
            status=status,
            record=record,
            raw_bytes=raw_bytes,
            error_codes=(),
            errors=(),
        )
