"""Live & offline official document content integrity verifier (v1.0.1).

Verifies not only URL syntax/domain, but also that:
1. The official HTTPS URL actually returns HTTP 200,
2. The fetched official document (HTML or PDF, including mevzuat.gov.tr embedded PDFs)
   yields readable legal text,
3. Every declared expected_text_marker appears in the normalized legal text,
4. The SHA-256 hash of the fetched document is computed and auditable.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import html
import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Callable
import urllib.error
import urllib.request
from urllib.parse import urljoin

from .models import DocumentFetchResult
from .source_validator import OFFICIAL_LEGAL_DOMAINS, is_specific_official_url

FetcherFn = Callable[[str, int], tuple[int, str, bytes]]

HTML_TAG_RE = re.compile(r"<[^>]+>")
WHITESPACE_RE = re.compile(r"\s+")
MEVZUAT_PDF_REF_RE = re.compile(r"MevzuatMetin/[0-9]+\.[0-9]+\.[0-9]+\.pdf", re.IGNORECASE)


def _tr_normalize(text: str) -> str:
    text = text.replace("İ", "i").replace("I", "ı").lower()
    text = WHITESPACE_RE.sub(" ", text).strip()
    return text


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_text_from_payload(data: bytes, content_type: str) -> str:
    """Extract normalized readable text from PDF or HTML/plain bytes using stdlib + optional pdftotext."""
    is_pdf = "pdf" in content_type.lower() or data[:5] == b"%PDF-"
    if is_pdf:
        if shutil.which("pdftotext"):
            proc = subprocess.run(
                ["pdftotext", "-", "-"],
                input=data,
                capture_output=True,
                timeout=30,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout:
                return proc.stdout.decode("utf-8", errors="ignore")
        # Fallback if pdftotext unavailable
        return data.decode("latin-1", errors="ignore")

    decoded = ""
    for encoding in ("utf-8", "windows-1254", "iso-8859-9", "latin-1"):
        try:
            decoded = data.decode(encoding)
            if encoding == "utf-8" or any(ch in decoded for ch in ("ş", "ğ", "ı", "ü", "ö", "ç", "Madde", "KANUN")):
                break
        except UnicodeDecodeError:
            continue

    cleaned = html.unescape(HTML_TAG_RE.sub(" ", decoded))
    return WHITESPACE_RE.sub(" ", cleaned).strip()


def default_http_fetcher(url: str, timeout: int = 15) -> tuple[int, str, bytes]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (CALISORA-LegalIntegrityVerifier/1.0.1)",
            "Accept": "text/html,application/pdf,*/*;q=0.8",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        status = getattr(resp, "status", 200)
        content_type = resp.headers.get("Content-Type", "")
        payload = resp.read()
        return int(status), content_type, payload


def verify_official_document(
    url: str,
    expected_markers: list[str] | tuple[str, ...],
    allowed_domains: set[str] | None = None,
    fetcher: FetcherFn | None = None,
    timeout: int = 15,
    expected_sha256: str | None = None,
) -> DocumentFetchResult:
    """Fetch an official URL, resolve mevzuat.gov.tr wrapper PDF if present, and verify text markers + SHA-256."""
    checked_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    markers = tuple(m for m in expected_markers if m and m.strip())

    url_ok, url_reason = is_specific_official_url(
        url, allowed_domains=allowed_domains if allowed_domains is not None else OFFICIAL_LEGAL_DOMAINS
    )
    if not url_ok:
        return DocumentFetchResult(
            url=url,
            resolved_document_url=url,
            ok=False,
            http_status=None,
            content_type="",
            content_length=0,
            content_sha256=None,
            expected_markers=markers,
            matched_markers=(),
            missing_markers=markers,
            checked_at_utc=checked_at,
            error=f"URL doğrulama reddi: {url_reason}",
        )

    if not markers:
        return DocumentFetchResult(
            url=url,
            resolved_document_url=url,
            ok=False,
            http_status=None,
            content_type="",
            content_length=0,
            content_sha256=None,
            expected_markers=(),
            matched_markers=(),
            missing_markers=(),
            checked_at_utc=checked_at,
            error="En az bir expected_text_marker zorunludur.",
        )

    fetch_fn = fetcher or default_http_fetcher
    resolved_url = url
    try:
        http_status, content_type, payload = fetch_fn(url, timeout)
    except Exception as exc:
        return DocumentFetchResult(
            url=url,
            resolved_document_url=resolved_url,
            ok=False,
            http_status=None,
            content_type="",
            content_length=0,
            content_sha256=None,
            expected_markers=markers,
            matched_markers=(),
            missing_markers=markers,
            checked_at_utc=checked_at,
            error=f"Belge indirilemedi ({type(exc).__name__}): {exc}",
        )

    if http_status != 200 or not payload:
        return DocumentFetchResult(
            url=url,
            resolved_document_url=resolved_url,
            ok=False,
            http_status=http_status,
            content_type=content_type,
            content_length=len(payload),
            content_sha256=None,
            expected_markers=markers,
            matched_markers=(),
            missing_markers=markers,
            checked_at_utc=checked_at,
            error=f"HTTP {http_status} veya boş yanıt döndü.",
        )

    # mevzuat.gov.tr HTML shell embeds consolidated text in MevzuatMetin/<tur>.<tertip>.<no>.pdf
    if "mevzuat.gov.tr/mevzuat?" in url.lower() and "html" in content_type.lower():
        raw_html = payload.decode("utf-8", errors="ignore")
        pdf_match = MEVZUAT_PDF_REF_RE.search(raw_html)
        if pdf_match:
            resolved_url = urljoin("https://www.mevzuat.gov.tr/", pdf_match.group(0))
            try:
                pdf_status, pdf_ct, pdf_payload = fetch_fn(resolved_url, timeout)
                if pdf_status == 200 and pdf_payload:
                    http_status, content_type, payload = pdf_status, pdf_ct, pdf_payload
            except Exception:
                # Fall back to checking HTML shell if embedded PDF fetch fails
                resolved_url = url

    sha256 = compute_sha256(payload)
    extracted_text = extract_text_from_payload(payload, content_type)
    normalized_text = _tr_normalize(extracted_text)

    matched: list[str] = []
    missing: list[str] = []
    for marker in markers:
        if _tr_normalize(marker) in normalized_text:
            matched.append(marker)
        else:
            missing.append(marker)

    sha_mismatch_err = None
    if expected_sha256 and sha256 != expected_sha256:
        sha_mismatch_err = f"SHA-256 bütünlük uyuşmazlığı: beklenen={expected_sha256}, hesaplanan={sha256}"

    ok = (not missing) and (sha_mismatch_err is None)
    error_msg = sha_mismatch_err
    if missing:
        miss_str = f"Beklenen metin işaretçileri belgede bulunamadı: {missing}"
        error_msg = f"{error_msg}; {miss_str}" if error_msg else miss_str

    return DocumentFetchResult(
        url=url,
        resolved_document_url=resolved_url,
        ok=ok,
        http_status=http_status,
        content_type=content_type,
        content_length=len(payload),
        content_sha256=sha256,
        expected_markers=markers,
        matched_markers=tuple(matched),
        missing_markers=tuple(missing),
        checked_at_utc=checked_at,
        error=error_msg,
    )


def verify_archived_holiday_snapshots(
    audit_log_path: str | Path | None = None,
    project_root: str | Path | None = None,
) -> dict[str, object]:
    """Verify archived 2024–2027 official Diyanet holiday HTML snapshots locally without requiring live origin access.

    Offline/unreachable origin URLs today do NOT invalidate a previously archived snapshot whose local bytes
    match its stored SHA-256 and parse strictly to all 9 exact bayram/arife slots.
    """
    from .attestation_verifier import verify_holiday_source_snapshot

    root = Path(project_root) if project_root is not None else Path(__file__).resolve().parent.parent
    aud_path = Path(audit_log_path) if audit_log_path is not None else root / "config" / "verification_audit_log.json"
    raw = json.loads(aud_path.read_text(encoding="utf-8"))
    cal = raw.get("holiday_calendar_audit") or {}
    yearly = cal.get("yearly_records") or {}

    results: dict[str, object] = {}
    verified_years: list[int] = []
    all_ok = bool(yearly)
    for yr_key, yr_rec in sorted(yearly.items()):
        yr = int(yr_key)
        res = verify_holiday_source_snapshot(yr, yr_rec, project_root=root)
        results[yr_key] = res
        if res["valid"]:
            verified_years.append(yr)
        else:
            all_ok = False

    return {
        "ok": all_ok,
        "origin_offline_resilient": True,
        "verified_years": verified_years,
        "results": results,
    }


def _cli() -> int:
    root = Path(__file__).resolve().parent.parent
    src_data = json.loads((root / "config" / "legal_sources_registry.json").read_text(encoding="utf-8"))
    prec_data = json.loads((root / "config" / "yargitay_precedents.json").read_text(encoding="utf-8"))

    summary = {"sources": {}, "precedents": {}, "archived_holiday_snapshots": {}}
    failures = 0

    for sid, rec in src_data["sources"].items():
        audit = rec.get("verification_audit", {})
        markers = audit.get("expected_text_markers", [rec.get("statute_number", "")])
        res = verify_official_document(rec["source_url"], markers)
        summary["sources"][sid] = res.to_dict()
        if not res.ok:
            failures += 1

    for pid, rec in prec_data["precedents"].items():
        audit = rec.get("verification_audit", {})
        markers = audit.get("expected_text_markers", [rec.get("esas_no", ""), rec.get("karar_no", "")])
        res = verify_official_document(rec["official_source_url"], markers)
        summary["precedents"][pid] = res.to_dict()
        if not res.ok:
            failures += 1

    snap_summary = verify_archived_holiday_snapshots(project_root=root)
    summary["archived_holiday_snapshots"] = snap_summary
    if not snap_summary["ok"]:
        failures += 1

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(_cli())
