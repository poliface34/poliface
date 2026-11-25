"""Common fail-closed SourceAdapter contract (hrAI @HukukSGK v1.0.6 WP2.1).

Reuses `engine/trust_root/source_acquisition.py` HTTPS/domain/TLS verification primitives and enforces:
  - HTTPS-only allowlisted official domain URLs (rejects generic root homepages `/` and userinfo).
  - Strict separation of `publication_date` vs `effective_date` (and optional `expiry_or_repeal_date`).
  - Strict separation of `LIVE_HTTPS` (only via real `LiveHttpsSourceFetcher`) vs `INJECTED_TEST_TRANSPORT`
    (callback spoofing of `LIVE_HTTPS` is unconditionally blocked).
  - Fail-closed handling of unreachable sources (timeout, network error, HTTP != 200 -> `UNREACHABLE_NOT_VERIFIED`,
    NEVER marked verified).
  - Real SHA-256 content digest computation + optional expected digest verification.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import copy
from datetime import datetime, timezone
import hashlib
from typing import Any, Callable
from urllib.parse import urlparse

from ..trust_root.source_acquisition import (
    LiveHttpsSourceFetcher,
    SourceAcquisitionSecurityError,
    validate_official_https_url,
)
from .models import (
    GENESIS_CHAIN_HASH,
    STATUS_REJECTED_INVALID_SOURCE,
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
        """Validate source-specific metadata fields and document sanity; return list of `(error_code, message)`."""

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
    ) -> AcquisitionResult:
        fail_seed = {
            "source_key": request.source_key,
            "adapter_type": self.adapter_type,
            "source_url": request.source_url,
            "acquired_at_utc": acquired_at_utc,
            "status": status,
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
                "content_sha256": "",
                "content_bytes_length": 0,
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
            content_sha256="",
            content_bytes_length=0,
            content_type=content_type,
            http_status=http_status,
            transport_mode=transport_mode,
            live_verified=False,
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
            raw_bytes=b"",
            error_codes=tuple(error_codes),
            errors=tuple(errors),
        )

    def acquire_and_validate(self, request: SourceDocumentRequest) -> AcquisitionResult:
        """Acquire document from official source, validate URL/dates/metadata/SHA-256, and return AcquisitionResult."""
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        req_errors: list[tuple[str, str]] = []

        # 1. Core request field validation
        if not is_valid_source_key(request.source_key):
            req_errors.append(
                ("INVALID_SOURCE_KEY", f"Geçersiz source_key biçimi: {request.source_key!r}")
            )
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
        http_status = int(http_status_raw) if isinstance(http_status_raw, int) and not isinstance(http_status_raw, bool) else None
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

        # Validate final_url and every redirect hop against HTTPS + official domain allowlist
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

        # Validate real live TLS result when running in LIVE_HTTPS mode
        if is_real_live:
            tls_res = resp.get("tls_verification_result")
            if not isinstance(tls_res, dict) or tls_res.get("verified") is not True or resp.get("fetcher_mode") != "LIVE_HTTPS":
                hop_errors.append(
                    (
                        "LIVE_TLS_VERIFICATION_MISSING",
                        "Canlı HTTPS ediniminde doğrulanmış TLS sertifika zinciri sonucu bulunamadı.",
                    )
                )

        # Adapter-specific metadata & document validation
        if raw_bytes:
            hop_errors.extend(self._validate_adapter_specific_metadata(request, raw_bytes, headers))

        # SHA-256 computation & optional expected digest check
        content_sha256 = hashlib.sha256(raw_bytes).hexdigest() if raw_bytes else ""
        if request.expected_content_sha256 is not None and content_sha256 != request.expected_content_sha256:
            hop_errors.append(
                (
                    "CONTENT_SHA256_MISMATCH",
                    f"Belge SHA-256 özeti beklenen değerle uyuşmuyor ({content_sha256} != {request.expected_content_sha256}).",
                )
            )

        if hop_errors:
            return self._build_failure_result(
                request=request,
                status=STATUS_REJECTED_INVALID_SOURCE,
                transport_mode=TRANSPORT_LIVE_HTTPS if is_real_live else TRANSPORT_INJECTED_TEST,
                error_codes=[c for c, _ in hop_errors],
                errors=[m for _, m in hop_errors],
                acquired_at_utc=acquired_at_utc,
                final_url=final_url,
                redirect_chain=redirect_chain,
                http_status=http_status,
                content_type=content_type,
            )

        # 4. Build verified EvidenceRecord (callback transport NEVER produces live_verified=True!)
        transport_mode = TRANSPORT_LIVE_HTTPS if is_real_live else TRANSPORT_INJECTED_TEST
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
