"""Cryptographic attestation, approver identity governance, official source content parsing, and tamper-evident audit chain verifier for CALISORA @HukukSGK (v1.0.3).

Implements the hardened security and legal-evidence guarantees (preserving v1.0.2c.6 frozen baseline):
  1. Externally verifiable tamper-evident SHA-256 hash chain + mandatory external trust anchor
     (signed checkpoints covering chain head OR independently verified out-of-band WORM/TSA anchor
     via provider-agnostic `ExternalTrustAnchorProvider`; unsigned checkpoints rejected in PRODUCTION;
     mathematical chain without external anchor reports `CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR`
     and NEVER authorizes production use; self-declared anchor fields inside untrusted ledger content
     rejected with `UNTRUSTED_SELF_DECLARED_ANCHOR_IN_LEDGER`).
  2. Time-bounded & scope-bounded authorized approver identity governance (`valid_from_utc`,
     `valid_until_utc`, `revoked_at_utc`, `revocation_reason`, `authorized_scopes`,
     `environment_restrictions`) with nuanced compromise vs. non-compromise revocation handling.
  3. Immutable versioned official source snapshots with strict `project_root` path-traversal & symlink
     containment (`SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT` across Linux & Windows path formats),
     SHA-256 verification, and offline-origin resilience.
  4. Strict Turkish religious holiday source parser enforcing exact bayram, arife, and day-order binding
     (9 distinct slots: Ramazan arife + 1..3, Kurban arife + 1..4) and OCR confidence gating.
  5. Asymmetric signatures (Ed25519 & RSA-PSS-SHA256 via OpenSSL 3 / KMS / PKCS#11 HSM) over spec-exact
     RFC 8785 (JCS / ECMAScript ES2015 §7.1.12.1) canonical JSON with algorithm, key_version, record_id,
     and nonce replay prevention; strict PRODUCTION vs TEST_SANDBOX_ONLY isolation; explicit Law No. 5070
     non-equivalence (NES/CAdES/XAdES deferred to v1.0.4).
  6. Three-way status separation: Stage 1 (system technical source verification), Stage 2 (authorized legal
     counsel cryptographic attestation), and Stage 3 (live production authorization gate).
"""

from __future__ import annotations

import base64
from datetime import date, datetime, timezone
import hashlib
import html as html_lib
from html.parser import HTMLParser
import json
import math
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import subprocess
import tempfile
from typing import Any

from .document_integrity import compute_sha256, extract_text_from_payload

PARSER_VERSION = "tr_diyanet_holiday_parser_v1.0.5.1"
GENESIS_PREV_HASH = "0" * 64
MIN_OCR_CONFIDENCE = 0.95

JCS_SAFE_INT_MAX = (2**53) - 1
JCS_SAFE_INT_MIN = -((2**53) - 1)

FORBIDDEN_LEDGER_SELF_ANCHOR_FIELDS: set[str] = {
    "expected_checkpoint_head_hash",
    "expected_checkpoint_entry_count",
    "expected_chain_digest_sha256",
    "worm_anchor",
    "trusted_anchor",
}

VALID_TRUST_ANCHOR_SOURCES: set[str] = {
    "OUT_OF_BAND_TRUSTED_CONFIG",
    "INDEPENDENT_WORM_STORE",
    "INDEPENDENT_TSA_ANCHOR",
}

SUPPORTED_SIGNATURE_ALGORITHMS: set[str] = {
    "ED25519",
    "RSA-PSS-SHA256",
}

COMPROMISE_REVOCATION_REASONS: set[str] = {
    "KEY_COMPROMISE",
    "CA_COMPROMISE",
}

NON_COMPROMISE_REVOCATION_REASONS: set[str] = {
    "SUPERSEDED_ROTATION",
    "ROLE_CHANGE",
    "ADMINISTRATIVE_SUSPENSION",
}

TRUSTED_TIMESTAMP_LEVELS: set[str] = {
    "INDEPENDENT_TSA_VERIFIED",
    "SIGNED_EXTERNAL_CHECKPOINT_ANCHORED",
}

SIGNATURE_5070_NON_EQUIVALENCE_NOTICE = (
    "Ed25519 / RSA-PSS-SHA256 kriptografik doğrulama, dahili bütünlük ve kimlik doğrulama "
    "mekanizmasıdır; 5070 sayılı Elektronik İmza Kanunu kapsamındaki Güvenli Elektronik İmza "
    "veya Nitelikli Elektronik Sertifika (NES) ile eşdeğer değildir."
)

TR_MONTH_MAP: dict[str, int] = {
    "ocak": 1,
    "şubat": 2,
    "subat": 2,
    "mart": 3,
    "nisan": 4,
    "mayıs": 5,
    "mayis": 5,
    "haziran": 6,
    "temmuz": 7,
    "ağustos": 8,
    "agustos": 8,
    "eylül": 9,
    "eylul": 9,
    "ekim": 10,
    "kasım": 11,
    "kasim": 11,
    "aralık": 12,
    "aralik": 12,
}

REQUIRED_HOLIDAY_SLOTS: tuple[str, ...] = (
    "ramazan_arife",
    "ramazan_day_1",
    "ramazan_day_2",
    "ramazan_day_3",
    "kurban_arife",
    "kurban_day_1",
    "kurban_day_2",
    "kurban_day_3",
    "kurban_day_4",
)

ISO_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
NONCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-_]{11,127}$")
RECORD_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9\-_.:]{5,127}$")

_DAY_MONTH_YEAR_RE = re.compile(
    r"\b(0?[1-9]|[12]\d|3[01])\s*[.\-/ ]+\s*"
    r"(ocak|şubat|subat|mart|nisan|mayıs|mayis|haziran|temmuz|ağustos|agustos|eylül|eylul|ekim|kasım|kasim|aralık|aralik)"
    r"\s*[-/ ]*\s*(20\d{2})\b",
    re.IGNORECASE,
)
_MONTH_YEAR_RE = re.compile(
    r"^(ocak|şubat|subat|mart|nisan|mayıs|mayis|haziran|temmuz|ağustos|agustos|eylül|eylul|ekim|kasım|kasim|aralık|aralik)"
    r"\s*[-/ ]+\s*(20\d{2})$",
    re.IGNORECASE,
)
_DMY_DOT_RE = re.compile(r"\b(0?[1-9]|[12]\d|3[01])[./-](0?[1-9]|1[0-2])[./-](20\d{2})\b")
_ISO_YMD_RE = re.compile(r"\b(20\d{2})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])\b")
_WHITESPACE_RE = re.compile(r"\s+")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")


def _tr_lower(text: str) -> str:
    return _WHITESPACE_RE.sub(" ", text.replace("İ", "i").replace("I", "ı").lower()).strip()


def parse_utc_timestamp(value: Any) -> datetime | None:
    """Strictly parse an ISO-8601 UTC/timezone-aware timestamp string into UTC datetime."""
    if not isinstance(value, str) or not ISO_UTC_RE.match(value.strip()):
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            return None
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# 1. RFC 8785 (JCS) Spec-Exact Deterministic Canonical JSON (ES2015 §7.1.12.1)
# ---------------------------------------------------------------------------


def _serialize_jcs_number(val: int | float) -> str:
    """Serialize an integer or IEEE-754 double strictly per RFC 8785 §3.2.2.3 (ECMAScript ES2015 §7.1.12.1).

    - Rejects NaN, +Inf, -Inf, and Python integers outside IEEE-754 safe integer range [-(2^53-1), 2^53-1].
    - Normalizes -0.0 and +0.0 to "0".
    - Produces byte-exact ECMAScript Number::toString(10) formatting (no zero-padded exponents, fixed-point
      for 1e-6 .. 1e20, scientific notation with unpadded signed exponent for < 1e-6 or >= 1e21).
    """
    if isinstance(val, bool):
        raise TypeError("bool değeri sayı olarak serileştirilemez.")
    if isinstance(val, int):
        if val < JCS_SAFE_INT_MIN or val > JCS_SAFE_INT_MAX:
            raise ValueError(
                f"RFC 8785 (I-JSON / IEEE-754) güvenli tamsayı aralığı dışında değer: {val} "
                f"(izin verilen: [{JCS_SAFE_INT_MIN}, {JCS_SAFE_INT_MAX}])."
            )
        return str(val)

    fval = float(val)
    if math.isnan(fval) or math.isinf(fval):
        raise ValueError("Canonical JSON (RFC 8785) NaN veya Infinity değerlerini desteklemez.")
    if fval == 0.0:
        return "0"

    sign = "-" if math.copysign(1.0, fval) < 0.0 else ""
    mag = abs(fval)
    raw = repr(mag)

    if "e" in raw or "E" in raw:
        mant, exp_str = raw.lower().split("e", 1)
        exp_val = int(exp_str)
    else:
        mant = raw
        exp_val = 0

    if "." in mant:
        int_part, frac_part = mant.split(".", 1)
        digits = int_part + frac_part
        exp_val -= len(frac_part)
    else:
        digits = mant

    digits = digits.lstrip("0")
    stripped = digits.rstrip("0")
    trailing_zeros = len(digits) - len(stripped)
    exp_val += trailing_zeros
    s = stripped
    k = len(s)
    n = exp_val + k

    if k <= n <= 21:
        return sign + s + ("0" * (n - k))
    if 0 < n <= 21:
        return sign + s[:n] + "." + s[n:]
    if -6 < n <= 0:
        return sign + "0." + ("0" * (-n)) + s
    exp_sign = "+" if (n - 1) >= 0 else "-"
    exp_abs = abs(n - 1)
    if k == 1:
        return f"{sign}{s}e{exp_sign}{exp_abs}"
    return f"{sign}{s[0]}.{s[1:]}e{exp_sign}{exp_abs}"


def _serialize_jcs_string(val: str) -> str:
    """Serialize a Unicode string strictly per RFC 8785 §3.2.2.2 (lowercase \\u00xx, unescaped '/', no lone surrogates)."""
    out: list[str] = ['"']
    for ch in val:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF:
            raise ValueError(f"Canonical JSON (RFC 8785) tekil UTF-16 vekil kod noktasını desteklemez: U+{cp:04X}")
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif cp == 0x08:
            out.append("\\b")
        elif cp == 0x09:
            out.append("\\t")
        elif cp == 0x0A:
            out.append("\\n")
        elif cp == 0x0C:
            out.append("\\f")
        elif cp == 0x0D:
            out.append("\\r")
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _canonicalize_value(val: Any) -> str:
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return _serialize_jcs_number(val)
    if isinstance(val, str):
        return _serialize_jcs_string(val)
    if isinstance(val, (list, tuple)):
        return "[" + ",".join(_canonicalize_value(item) for item in val) + "]"
    if isinstance(val, dict):
        for k in val:
            if not isinstance(k, str):
                raise TypeError(f"Canonical JSON anahtarları str olmalıdır (bulunan: {type(k).__name__}).")
            for ch in k:
                if 0xD800 <= ord(ch) <= 0xDFFF:
                    raise ValueError(
                        f"Canonical JSON (RFC 8785) anahtarında tekil UTF-16 vekil kod noktası yasaktır: U+{ord(ch):04X}"
                    )
        # RFC 8785 §3.2.3: sort object properties by UTF-16 code units
        sorted_keys = sorted(val.keys(), key=lambda s: s.encode("utf-16-be"))
        pairs = [f"{_serialize_jcs_string(k)}:{_canonicalize_value(val[k])}" for k in sorted_keys]
        return "{" + ",".join(pairs) + "}"
    raise TypeError(f"Canonical JSON serileştirilemeyen tür: {type(val).__name__}")


def canonical_json_bytes(obj: Any) -> bytes:
    """Return spec-exact RFC 8785 (JCS) deterministic canonical UTF-8 JSON bytes for cryptographic signing/hashing."""
    return _canonicalize_value(obj).encode("utf-8")


def compute_canonical_sha256(obj: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()


def compute_public_key_fingerprint(public_key_pem: str) -> str:
    normalized = "\n".join(line.strip() for line in public_key_pem.strip().splitlines() if line.strip())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# 2. Asymmetric Digital Signatures (Ed25519 & RSA-PSS-SHA256 via OpenSSL 3)
# ---------------------------------------------------------------------------


def _openssl_bin() -> str:
    exe = shutil.which("openssl")
    if not exe:
        raise RuntimeError("OpenSSL CLI bulunamadı; Ed25519/RSA-PSS-SHA256 imza doğrulaması çalıştırılamaz.")
    return exe


def generate_ephemeral_keypair(algorithm: str = "ED25519") -> tuple[str, str]:
    """Generate an ephemeral asymmetric keypair in memory (for isolated sandbox/tests only; NEVER commit private keys)."""
    alg = algorithm.upper().strip()
    if alg not in SUPPORTED_SIGNATURE_ALGORITHMS:
        raise ValueError(f"Desteklenmeyen imza algoritması: {algorithm}")
    openssl = _openssl_bin()
    with tempfile.TemporaryDirectory(prefix="calisora_keygen_") as tmp:
        priv_path = Path(tmp) / "priv.pem"
        pub_path = Path(tmp) / "pub.pem"
        if alg == "ED25519":
            cmd_gen = [openssl, "genpkey", "-algorithm", "ED25519", "-out", str(priv_path)]
        else:
            cmd_gen = [
                openssl,
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(priv_path),
            ]
        p1 = subprocess.run(
            cmd_gen,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if p1.returncode != 0:
            raise RuntimeError(f"Anahtar üretimi başarısız ({alg}): {p1.stderr.strip()}")
        p2 = subprocess.run(
            [openssl, "pkey", "-in", str(priv_path), "-pubout", "-out", str(pub_path)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if p2.returncode != 0:
            raise RuntimeError(f"Açık anahtar çıkarımı başarısız ({alg}): {p2.stderr.strip()}")
        return priv_path.read_text(encoding="utf-8"), pub_path.read_text(encoding="utf-8")


def sign_canonical_payload(payload: dict[str, Any], private_key_pem: str, algorithm: str = "ED25519") -> str:
    """Sign RFC 8785 canonical JSON bytes of `payload` with Ed25519 or RSA-PSS-SHA256 and return base64 signature."""
    alg = algorithm.upper().strip()
    if alg not in SUPPORTED_SIGNATURE_ALGORITHMS:
        raise ValueError(f"Desteklenmeyen imza algoritması: {algorithm}")
    msg_bytes = canonical_json_bytes(payload)
    openssl = _openssl_bin()
    with tempfile.TemporaryDirectory(prefix="calisora_sign_") as tmp:
        priv_path = Path(tmp) / "priv.pem"
        msg_path = Path(tmp) / "msg.bin"
        sig_path = Path(tmp) / "sig.bin"
        priv_path.write_text(private_key_pem, encoding="utf-8")
        msg_path.write_bytes(msg_bytes)
        if alg == "ED25519":
            cmd = [
                openssl,
                "pkeyutl",
                "-sign",
                "-inkey",
                str(priv_path),
                "-rawin",
                "-in",
                str(msg_path),
                "-out",
                str(sig_path),
            ]
        else:
            cmd = [
                openssl,
                "dgst",
                "-sha256",
                "-sigopt",
                "rsa_padding_mode:pss",
                "-sigopt",
                "rsa_pss_saltlen:32",
                "-sign",
                str(priv_path),
                "-out",
                str(sig_path),
                str(msg_path),
            ]
        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"İmzalama başarısız ({alg}): {proc.stderr.strip()}")
        return base64.b64encode(sig_path.read_bytes()).decode("ascii")


def verify_asymmetric_signature(
    payload: dict[str, Any],
    signature_b64: str,
    public_key_pem: str,
    algorithm: str,
) -> tuple[bool, str]:
    """Verify an Ed25519 or RSA-PSS-SHA256 signature over RFC 8785 canonical JSON bytes."""
    alg = str(algorithm or "").upper().strip()
    if alg not in SUPPORTED_SIGNATURE_ALGORITHMS:
        return False, f"Desteklenmeyen imza algoritması: '{algorithm}'."
    if not isinstance(signature_b64, str) or not signature_b64.strip():
        return False, "İmza (signature_b64) boş olamaz."
    if not isinstance(public_key_pem, str) or "BEGIN PUBLIC KEY" not in public_key_pem:
        return False, "Geçerli PEM açık anahtarı (BEGIN PUBLIC KEY) bulunamadı."
    try:
        sig_bytes = base64.b64decode(signature_b64.strip(), validate=True)
    except Exception:
        return False, "signature_b64 geçerli Base64 biçiminde değil."
    if not sig_bytes:
        return False, "Çözümlenen imza baytları boş."

    msg_bytes = canonical_json_bytes(payload)
    openssl = _openssl_bin()
    with tempfile.TemporaryDirectory(prefix="calisora_verify_") as tmp:
        pub_path = Path(tmp) / "pub.pem"
        msg_path = Path(tmp) / "msg.bin"
        sig_path = Path(tmp) / "sig.bin"
        pub_path.write_text(public_key_pem, encoding="utf-8")
        msg_path.write_bytes(msg_bytes)
        sig_path.write_bytes(sig_bytes)
        if alg == "ED25519":
            cmd = [
                openssl,
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(pub_path),
                "-rawin",
                "-in",
                str(msg_path),
                "-sigfile",
                str(sig_path),
            ]
        else:
            cmd = [
                openssl,
                "dgst",
                "-sha256",
                "-sigopt",
                "rsa_padding_mode:pss",
                "-sigopt",
                "rsa_pss_saltlen:32",
                "-verify",
                str(pub_path),
                "-signature",
                str(sig_path),
                str(msg_path),
            ]
        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if proc.returncode == 0:
            return True, f"{alg} kriptografik imza doğrulaması başarılı."
        err_msg = (proc.stderr or proc.stdout or "Doğrulama başarısız").strip()
        return False, f"{alg} kriptografik imza doğrulaması reddedildi: {err_msg}"


# ---------------------------------------------------------------------------
# 3. Strict Turkish Religious Holiday Source Parser & Snapshot Verification
# ---------------------------------------------------------------------------


class _HTMLTableExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._in_tr = False
        self._in_cell = False
        self._cur_row: list[str] = []
        self._cur_cell: list[str] = []
        self.rows: list[list[str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        if t == "tr":
            self._in_tr = True
            self._cur_row = []
        elif t in ("td", "th") and self._in_tr:
            self._in_cell = True
            self._cur_cell = []

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t in ("td", "th") and self._in_cell:
            self._in_cell = False
            cell_text = _WHITESPACE_RE.sub(" ", html_lib.unescape("".join(self._cur_cell))).strip()
            self._cur_row.append(cell_text)
        elif t == "tr" and self._in_tr:
            self._in_tr = False
            if self._cur_row:
                self.rows.append(self._cur_row)

    def handle_data(self, data: str) -> None:
        if self._in_cell:
            self._cur_cell.append(data)


def _extract_date_from_text(text: str) -> date | None:
    norm = _tr_lower(text)
    m_iso = _ISO_YMD_RE.search(norm)
    if m_iso:
        try:
            return date(int(m_iso.group(1)), int(m_iso.group(2)), int(m_iso.group(3)))
        except ValueError:
            pass
    m_dot = _DMY_DOT_RE.search(norm)
    if m_dot:
        try:
            return date(int(m_dot.group(3)), int(m_dot.group(2)), int(m_dot.group(1)))
        except ValueError:
            pass
    m_tr = _DAY_MONTH_YEAR_RE.search(norm)
    if m_tr:
        month_num = TR_MONTH_MAP.get(m_tr.group(2))
        if month_num:
            try:
                return date(int(m_tr.group(3)), month_num, int(m_tr.group(1)))
            except ValueError:
                pass
    return None


def _extract_date_from_table_row(row: list[str]) -> date | None:
    # Check Diyanet split-cell format: [..., '09', 'NİSAN-2024', ...] or [..., '10', 'NİSAN -2024', ...]
    for i in range(len(row) - 1):
        c_day = row[i].strip()
        c_my = _tr_lower(row[i + 1])
        if c_day.isdigit() and 1 <= int(c_day) <= 31:
            m_my = _MONTH_YEAR_RE.match(c_my)
            if m_my:
                month_num = TR_MONTH_MAP.get(m_my.group(1))
                if month_num:
                    try:
                        return date(int(m_my.group(2)), month_num, int(c_day))
                    except ValueError:
                        pass
    # Fallback: single cell or joined row containing DD Ay YYYY / DD.MM.YYYY / YYYY-MM-DD
    for cell in row:
        dt = _extract_date_from_text(cell)
        if dt is not None:
            return dt
    return _extract_date_from_text(" ".join(row))


def _classify_holiday_slot(label_text: str, hijri_context: str = "") -> str | None:
    """Strictly bind an event label + optional Hicrî month context to one of the 9 exact holiday slots."""
    lbl = _tr_lower(label_text)
    hctx = _tr_lower(hijri_context)

    # Explicitly exclude non-holiday religious observances even if they mention "ramazan"
    if any(
        non_hol in lbl
        for non_hol in (
            "başlangıc",
            "baslangic",
            "kadir gecesi",
            "mevlid",
            "regaib",
            "miraç",
            "mirac",
            "berat",
            "aşure",
            "asure",
            "hicri yılbaşı",
            "hicri yilbasi",
            "üç aylar",
            "uc aylar",
        )
    ):
        return None

    has_ramazan = "ramazan" in lbl
    has_kurban = "kurban" in lbl
    has_bayram = "bayram" in lbl
    has_arife = ("arefe" in lbl) or ("arife" in lbl)

    if has_arife:
        if has_ramazan and not has_kurban:
            return "ramazan_arife"
        if has_kurban and not has_ramazan:
            return "kurban_arife"
        # Diyanet table lists generic "AREFE" with Hicrî month cell ("RAMAZAN" vs "ZİLHİCCE")
        if "ramazan" in hctx and "zilhicce" not in hctx:
            return "ramazan_arife"
        if "zilhicce" in hctx and "ramazan" not in hctx:
            return "kurban_arife"
        return "AMBIGUOUS_ARIFE"

    if has_ramazan and has_bayram and not has_kurban:
        m_day = re.search(r"\b([1-3])\s*\.\s*g[üu]n", lbl)
        if m_day:
            return f"ramazan_day_{m_day.group(1)}"
        return None

    if has_kurban and has_bayram and not has_ramazan:
        m_day = re.search(r"\b([1-4])\s*\.\s*g[üu]n", lbl)
        if m_day:
            return f"kurban_day_{m_day.group(1)}"
        return None

    return None


def parse_turkish_religious_holidays_from_source(
    source_bytes: bytes,
    year: int,
    *,
    content_type: str = "text/html",
    extraction_method: str = "NATIVE_HTML_TABLE",
    ocr_confidence: float | None = None,
    manual_ocr_review_confirmed: bool = False,
) -> dict[str, Any]:
    """Deterministically parse Ramazan & Kurban Bayramı + arife dates with exact bayram & day-order binding.

    Enforces:
      - Exact 9-slot extraction (`ramazan_arife`, `ramazan_day_1..3`, `kurban_arife`, `kurban_day_1..4`).
      - Wrong-bayram or ambiguous arife entries are NEVER guessed.
      - OCR extraction with missing/low confidence (< 0.95) or without manual confirmation is rejected
        with `OCR_LOW_CONFIDENCE_MANUAL_REVIEW_REQUIRED`.
    """
    errors: list[str] = []
    error_codes: list[str] = []
    method_norm = str(extraction_method or "NATIVE_HTML_TABLE").upper().strip()

    if method_norm == "OCR":
        if ocr_confidence is None or isinstance(ocr_confidence, bool) or not isinstance(ocr_confidence, (int, float)):
            error_codes.append("OCR_LOW_CONFIDENCE_MANUAL_REVIEW_REQUIRED")
            errors.append("OCR metin çıkarımı için ocr_confidence (0.0–1.0) değeri zorunludur; otomatik VERIFIED üretilemez.")
        elif float(ocr_confidence) < MIN_OCR_CONFIDENCE or not manual_ocr_review_confirmed:
            error_codes.append("OCR_LOW_CONFIDENCE_MANUAL_REVIEW_REQUIRED")
            errors.append(
                f"OCR metin çıkarımı güven düzeyi ({ocr_confidence}) düşük (< {MIN_OCR_CONFIDENCE}) veya "
                f"manuel doğrulama onayı (manual_ocr_review_confirmed=True) eksik; otomatik VERIFIED yasaktır."
            )

    if not isinstance(source_bytes, (bytes, bytearray)) or len(source_bytes) == 0:
        error_codes.append("SOURCE_SNAPSHOT_MISSING_OR_MISMATCH")
        errors.append("Kaynak belge içeriği boş.")
        return {
            "valid": False,
            "parser_version": PARSER_VERSION,
            "extraction_method": method_norm,
            "ocr_confidence": ocr_confidence,
            "source_document_sha256": None,
            "extracted_slots": {},
            "slot_evidence": {},
            "ambiguous_rows": [],
            "error_codes": sorted(set(error_codes)),
            "errors": errors,
        }

    doc_sha256 = compute_sha256(bytes(source_bytes))
    extracted_slots: dict[str, str] = {}
    slot_evidence: dict[str, str] = {}
    ambiguous_rows: list[str] = []

    def _record_slot(slot: str, dt: date, raw_evidence: str) -> None:
        # Allow Dec 31 of year-1 for arife or Jan 1-3 of year+1 for bayram tail if start is in year
        if dt.year not in {year - 1, year, year + 1}:
            return
        iso = dt.isoformat()
        if slot == "AMBIGUOUS_ARIFE":
            ambiguous_rows.append(f"{iso}: {raw_evidence}")
            return
        if slot in extracted_slots and extracted_slots[slot] != iso:
            if "SOURCE_CONTENT_BAYRAM_OR_ORDER_MISMATCH" not in error_codes:
                error_codes.append("SOURCE_CONTENT_BAYRAM_OR_ORDER_MISMATCH")
            errors.append(
                f"Kaynak belgede '{slot}' için çelişkili tarihler bulundu: {extracted_slots[slot]} vs {iso}."
            )
            return
        extracted_slots[slot] = iso
        slot_evidence[slot] = raw_evidence

    # Decode text for HTML table parsing first
    decoded_html = ""
    for enc in ("utf-8", "windows-1254", "iso-8859-9", "latin-1"):
        try:
            decoded_html = bytes(source_bytes).decode(enc)
            break
        except UnicodeDecodeError:
            continue

    is_html = ("html" in content_type.lower()) or ("<tr" in decoded_html.lower() and "<td" in decoded_html.lower())
    if is_html:
        parser = _HTMLTableExtractor()
        parser.feed(decoded_html)
        for row in parser.rows:
            if len(row) < 2:
                continue
            dt = _extract_date_from_table_row(row)
            if dt is None:
                continue
            event_cell = row[-1]
            # First 3 columns in Diyanet table carry Hicrî day, month, year
            hijri_ctx = " ".join(row[:3]) if len(row) >= 5 else " ".join(row[:-1])
            slot = _classify_holiday_slot(event_cell, hijri_ctx)
            if slot is None:
                # Fallback if event label is in another column
                for cell in row:
                    cand = _classify_holiday_slot(cell, hijri_ctx)
                    if cand is not None:
                        slot = cand
                        break
            if slot is not None:
                _record_slot(slot, dt, " | ".join(row))

    # Also parse line-oriented plain text if table extraction didn't populate all 9 slots (e.g., plain text / PDF text)
    if len(extracted_slots) < len(REQUIRED_HOLIDAY_SLOTS):
        plain_text = extract_text_from_payload(bytes(source_bytes), content_type)
        # Re-split raw text preserving newlines for strict line-level bayram-to-date association
        raw_lines = decoded_html.splitlines() if not is_html else []
        if not raw_lines and plain_text:
            raw_lines = [plain_text]
        for line in raw_lines:
            clean_line = _WHITESPACE_RE.sub(" ", line).strip()
            if not clean_line:
                continue
            dt = _extract_date_from_text(clean_line)
            if dt is None:
                continue
            slot = _classify_holiday_slot(clean_line, "")
            if slot is not None:
                _record_slot(slot, dt, clean_line)

    missing_slots = [s for s in REQUIRED_HOLIDAY_SLOTS if s not in extracted_slots]
    if missing_slots:
        if "SOURCE_CONTENT_BAYRAM_OR_ORDER_MISMATCH" not in error_codes:
            error_codes.append("SOURCE_CONTENT_BAYRAM_OR_ORDER_MISMATCH")
        errors.append(
            f"{year} yılı kaynak belgesinden tüm zorunlu bayram/arife günleri kesin eşleşmeyle çıkarılamadı; "
            f"eksik alanlar: {missing_slots}."
        )

    if ambiguous_rows:
        if "SOURCE_CONTENT_BAYRAM_OR_ORDER_MISMATCH" not in error_codes:
            error_codes.append("SOURCE_CONTENT_BAYRAM_OR_ORDER_MISMATCH")
        errors.append(
            f"Kaynak belgede hangi bayrama ait olduğu belirsiz arife satırı bulundu: {ambiguous_rows}."
        )

    valid = len(errors) == 0 and len(error_codes) == 0
    return {
        "valid": valid,
        "parser_version": PARSER_VERSION,
        "extraction_method": method_norm,
        "ocr_confidence": ocr_confidence,
        "source_document_sha256": doc_sha256,
        "extracted_slots": extracted_slots,
        "slot_evidence": slot_evidence,
        "ambiguous_rows": ambiguous_rows,
        "error_codes": sorted(set(error_codes)),
        "errors": errors,
    }


def resolve_safe_project_path(
    rel_path_str: Any,
    project_root: Path | None = None,
) -> tuple[Path | None, str | None, str | None]:
    """Resolve a relative project path strictly inside `project_root` across POSIX and Windows path syntaxes.

    Blocks:
      - Empty / non-string paths, NUL bytes, ASCII control characters, NTFS colon streams
      - Absolute POSIX paths (`/etc/passwd`, `//server/share`)
      - Absolute Windows paths (`C:\\...`, `C:/...`, `\\Windows\\...`, UNC `\\\\server\\share`)
      - Directory traversal segments (`..`) across BOTH `/` and `\\` separators
      - Any symlink (direct file symlink OR intermediate directory symlink) resolving outside `project_root`

    Returns `(resolved_path, error_code, error_message)` where `error_code` is
    `"SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT"` on any containment/traversal violation.
    """
    base = project_root if project_root is not None else Path(__file__).resolve().parent.parent
    base_real_str = os.path.realpath(str(base))
    base_real = Path(base_real_str)

    if not isinstance(rel_path_str, str) or not rel_path_str.strip():
        return (
            None,
            "SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT",
            "Dosya yolu boş veya geçersiz metin biçimindedir.",
        )

    raw = rel_path_str.strip()
    if "\x00" in raw or any(ord(ch) < 0x20 for ch in raw):
        return (
            None,
            "SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT",
            f"Dosya yolu yasaklı kontrol karakteri veya NUL baytı içeriyor: {raw!r}.",
        )

    if (
        raw.startswith("/")
        or raw.startswith("\\")
        or _WINDOWS_DRIVE_RE.match(raw) is not None
        or PurePosixPath(raw).is_absolute()
        or PureWindowsPath(raw).is_absolute()
    ):
        return (
            None,
            "SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT",
            f"Mutlak dosya yolu, sürücü harfi veya UNC yolu yasaktır (yalnızca proje kökü içi göreli yol kabul edilir): '{raw}'.",
        )

    raw_segments = re.split(r"[\\/]+", raw)
    if ".." in raw_segments:
        return (
            None,
            "SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT",
            f"Dizin dışına çıkış ('..') içeren dosya yolu engellendi: '{raw}'.",
        )

    clean_segments = [seg for seg in raw_segments if seg not in ("", ".")]
    if not clean_segments:
        return (
            None,
            "SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT",
            f"Proje kökü içinde geçerli bir hedef dosya belirtilmedi: '{raw}'.",
        )

    for seg in clean_segments:
        if ":" in seg:
            return (
                None,
                "SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT",
                f"Dosya yolu segmenti yasaklı ':' karakteri içeriyor: '{raw}'.",
            )

    # Check every intermediate prefix for symlink escapes outside project_root
    cur_path = base_real
    for seg in clean_segments:
        cur_path = cur_path / seg
        if os.path.islink(str(cur_path)):
            link_real_str = os.path.realpath(str(cur_path))
            try:
                common = os.path.commonpath([base_real_str, link_real_str])
                Path(link_real_str).relative_to(base_real)
            except ValueError:
                return (
                    None,
                    "SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT",
                    f"Sembolik bağlantı (symlink) proje kökü dışına çıkıyor ve engellendi: '{raw}'.",
                )
            if common != base_real_str:
                return (
                    None,
                    "SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT",
                    f"Sembolik bağlantı (symlink) proje kökü dışına çıkıyor ve engellendi: '{raw}'.",
                )

    candidate_real_str = os.path.realpath(str(cur_path))
    candidate_real = Path(candidate_real_str)
    try:
        common_final = os.path.commonpath([base_real_str, candidate_real_str])
        candidate_real.relative_to(base_real)
    except ValueError:
        return (
            None,
            "SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT",
            f"Çözümlenen dosya yolu proje kökü dışına çıkıyor ve engellendi: '{raw}'.",
        )

    if common_final != base_real_str or candidate_real == base_real:
        return (
            None,
            "SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT",
            f"Çözümlenen dosya yolu proje kökü sınırları içinde değildir: '{raw}'.",
        )

    return candidate_real, None, None


def verify_holiday_source_snapshot(
    year: int,
    claimed_record: dict[str, Any],
    *,
    project_root: Path | None = None,
    source_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Verify Stage 1 (Technical Source Verification): safe project_root containment, archived document existence, SHA-256 hash, and 9-slot date/bayram match.

    NOTE: Offline/unreachable remote origin URLs today do NOT invalidate a previously archived snapshot
    whose local bytes (strictly confined inside `project_root`) match `source_document_sha256` and parse
    to all 9 exact bayram/arife slots.
    """
    errors: list[str] = []
    error_codes: list[str] = []

    expected_sha = str(claimed_record.get("source_document_sha256") or "").strip().lower()
    if not re.match(r"^[a-f0-9]{64}$", expected_sha):
        error_codes.append("SOURCE_SNAPSHOT_MISSING_OR_MISMATCH")
        errors.append(f"{year} yılı kaydı için geçerli 64 haneli SHA-256 (source_document_sha256) zorunludur.")

    resolved_bytes: bytes | None = None
    safe_snapshot_path: Path | None = None
    path_containment_failed = False
    snapshot_path_str = claimed_record.get("snapshot_path")

    # Always validate snapshot_path containment if present, even when inline bytes/content are also provided!
    if isinstance(snapshot_path_str, str) and snapshot_path_str.strip():
        safe_snapshot_path, path_err_code, path_err_msg = resolve_safe_project_path(
            snapshot_path_str,
            project_root=project_root,
        )
        if path_err_code is not None:
            path_containment_failed = True
            error_codes.append(path_err_code)
            errors.append(f"{year} yılı snapshot_path güvenlik ihlali: {path_err_msg}")
    elif snapshot_path_str is not None and not isinstance(snapshot_path_str, str):
        path_containment_failed = True
        error_codes.append("SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT")
        errors.append(f"{year} yılı snapshot_path geçerli bir metin dosya yolu olmalıdır.")

    if not path_containment_failed:
        if source_bytes is not None:
            resolved_bytes = bytes(source_bytes)
        elif isinstance(claimed_record.get("source_document_content"), str) and claimed_record["source_document_content"]:
            resolved_bytes = claimed_record["source_document_content"].encode("utf-8")
        elif isinstance(claimed_record.get("source_document_bytes_b64"), str) and claimed_record["source_document_bytes_b64"]:
            try:
                resolved_bytes = base64.b64decode(claimed_record["source_document_bytes_b64"], validate=True)
            except Exception:
                error_codes.append("SOURCE_SNAPSHOT_MISSING_OR_MISMATCH")
                errors.append(f"{year} yılı source_document_bytes_b64 geçerli Base64 değildir.")
        elif safe_snapshot_path is not None:
            if not safe_snapshot_path.is_file():
                error_codes.append("SOURCE_SNAPSHOT_MISSING_OR_MISMATCH")
                errors.append(f"{year} yılı arşivlenen kaynak belgesi bulunamadı: '{snapshot_path_str}'.")
            else:
                resolved_bytes = safe_snapshot_path.read_bytes()
        else:
            error_codes.append("SOURCE_SNAPSHOT_MISSING_OR_MISMATCH")
            errors.append(
                f"{year} yılı için arşivlenen kaynak belgesi (snapshot_path / source_document_content / source_document_bytes_b64) sunulmamıştır."
            )

    actual_sha: str | None = None
    parsed_result: dict[str, Any] = {}
    if resolved_bytes is not None and not path_containment_failed:
        actual_sha = compute_sha256(resolved_bytes)
        if expected_sha and actual_sha != expected_sha:
            error_codes.append("SOURCE_SNAPSHOT_MISSING_OR_MISMATCH")
            errors.append(
                f"{year} yılı kaynak belgesi SHA-256 uyuşmazlığı: beklenen={expected_sha}, hesaplanan={actual_sha}."
            )

        content_type = str(claimed_record.get("source_content_type") or "text/html")
        extraction_method = str(claimed_record.get("extraction_method") or "NATIVE_HTML_TABLE")
        ocr_conf = claimed_record.get("ocr_confidence")
        manual_ocr_ok = bool(claimed_record.get("manual_ocr_review_confirmed", False))

        parsed_result = parse_turkish_religious_holidays_from_source(
            resolved_bytes,
            year,
            content_type=content_type,
            extraction_method=extraction_method,
            ocr_confidence=ocr_conf,
            manual_ocr_review_confirmed=manual_ocr_ok,
        )
        error_codes.extend(parsed_result["error_codes"])
        errors.extend(parsed_result["errors"])

        # Compare every one of the 9 exact slots against the claimed record dates
        if parsed_result["extracted_slots"]:
            ram_s = claimed_record.get("ramazan_start_date")
            kurb_s = claimed_record.get("kurban_start_date")
            expected_slots: dict[str, str | None] = {
                "ramazan_arife": claimed_record.get("ramazan_arife_date"),
                "kurban_arife": claimed_record.get("kurban_arife_date"),
            }
            if isinstance(ram_s, str):
                try:
                    rs_dt = date.fromisoformat(ram_s)
                    expected_slots["ramazan_day_1"] = rs_dt.isoformat()
                    expected_slots["ramazan_day_2"] = date.fromordinal(rs_dt.toordinal() + 1).isoformat()
                    expected_slots["ramazan_day_3"] = date.fromordinal(rs_dt.toordinal() + 2).isoformat()
                except ValueError:
                    pass
            if isinstance(kurb_s, str):
                try:
                    ks_dt = date.fromisoformat(kurb_s)
                    expected_slots["kurban_day_1"] = ks_dt.isoformat()
                    expected_slots["kurban_day_2"] = date.fromordinal(ks_dt.toordinal() + 1).isoformat()
                    expected_slots["kurban_day_3"] = date.fromordinal(ks_dt.toordinal() + 2).isoformat()
                    expected_slots["kurban_day_4"] = date.fromordinal(ks_dt.toordinal() + 3).isoformat()
                except ValueError:
                    pass

            for slot_name in REQUIRED_HOLIDAY_SLOTS:
                claimed_dt = expected_slots.get(slot_name)
                parsed_dt = parsed_result["extracted_slots"].get(slot_name)
                if claimed_dt and parsed_dt and claimed_dt != parsed_dt:
                    error_codes.append("SOURCE_CONTENT_BAYRAM_OR_ORDER_MISMATCH")
                    errors.append(
                        f"{year} yılı '{slot_name}' tarihi kaynak metinle uyuşmuyor: "
                        f"beyan={claimed_dt}, kaynak={parsed_dt}."
                    )

            # Also check extracted_dates_summary consistency if present on the record
            declared_summary = claimed_record.get("extracted_dates_summary")
            if isinstance(declared_summary, dict):
                for slot_name in REQUIRED_HOLIDAY_SLOTS:
                    if declared_summary.get(slot_name) != parsed_result["extracted_slots"].get(slot_name):
                        error_codes.append("SOURCE_CONTENT_BAYRAM_OR_ORDER_MISMATCH")
                        errors.append(
                            f"{year} yılı extracted_dates_summary.{slot_name} "
                            f"({declared_summary.get(slot_name)}) ayrıştırılan kaynakla "
                            f"({parsed_result['extracted_slots'].get(slot_name)}) uyuşmuyor."
                        )

    valid = len(errors) == 0 and len(error_codes) == 0
    return {
        "valid": valid,
        "status": "TECHNICAL_VERIFIED" if valid else "TECHNICAL_FAILED",
        "year": year,
        "parser_version": PARSER_VERSION,
        "source_document_sha256": actual_sha,
        "expected_sha256": expected_sha or None,
        "extracted_dates_summary": parsed_result.get("extracted_slots", {}),
        "slot_evidence": parsed_result.get("slot_evidence", {}),
        "extraction_method": parsed_result.get("extraction_method"),
        "origin_offline_resilient": True,
        "error_codes": sorted(set(error_codes)),
        "errors": errors,
    }


def create_revised_snapshot_entry(
    existing_history: list[dict[str, Any]],
    *,
    new_snapshot_id: str,
    new_snapshot_version: str,
    new_snapshot_path: str,
    new_sha256: str,
    captured_at_utc: str,
    reason: str,
    project_root: Path | None = None,
) -> list[dict[str, Any]]:
    """Append an immutable new snapshot revision without overwriting prior versions."""
    if not existing_history:
        raise ValueError("SNAPSHOT_IMMUTABILITY_VIOLATION: Revizyon eklemek için en az bir ilk sürüm kaydı gereklidir.")
    if parse_utc_timestamp(captured_at_utc) is None:
        raise ValueError("captured_at_utc geçerli ISO-8601 UTC zaman damgası olmalıdır.")
    if not re.match(r"^[a-f0-9]{64}$", new_sha256.lower()):
        raise ValueError("new_sha256 geçerli 64 haneli SHA-256 özeti olmalıdır.")

    _, path_err_code, path_err_msg = resolve_safe_project_path(new_snapshot_path, project_root=project_root)
    if path_err_code is not None:
        raise ValueError(f"{path_err_code}: {path_err_msg}")

    for old in existing_history:
        if old.get("snapshot_id") == new_snapshot_id:
            raise ValueError(
                f"SNAPSHOT_IMMUTABILITY_VIOLATION: '{new_snapshot_id}' kimliği zaten mevcut; eski sürüm üzerine yazılamaz."
            )
        if old.get("snapshot_version") == new_snapshot_version:
            raise ValueError(
                f"SNAPSHOT_IMMUTABILITY_VIOLATION: '{new_snapshot_version}' sürümü zaten mevcut; yeni sürüm numarası verilmelidir."
            )
        if old.get("snapshot_path") == new_snapshot_path:
            raise ValueError(
                f"SNAPSHOT_IMMUTABILITY_VIOLATION: '{new_snapshot_path}' dosya yolu eski sürümle aynı olamaz; eski belge korunmalıdır."
            )

    prev_id = existing_history[-1]["snapshot_id"]
    new_entry = {
        "snapshot_id": new_snapshot_id,
        "snapshot_version": new_snapshot_version,
        "snapshot_path": new_snapshot_path,
        "captured_at_utc": captured_at_utc,
        "source_document_sha256": new_sha256.lower(),
        "parser_version": PARSER_VERSION,
        "supersedes_snapshot_id": prev_id,
        "revision_reason": reason,
    }
    return [*existing_history, new_entry]


# ---------------------------------------------------------------------------
# 4. Authorized Approver Identity, Temporal, Scope & Revocation Governance
# ---------------------------------------------------------------------------


def _scope_matches(authorized_scopes: list[str], required_operation: str, target_year: int | None) -> bool:
    for raw_scope in authorized_scopes:
        scope = str(raw_scope or "").strip()
        if scope == "*" or scope == required_operation or scope == f"{required_operation}:*":
            return True
        if target_year is not None and scope.startswith(f"{required_operation}:"):
            suffix = scope.split(":", 1)[1].strip()
            if suffix.isdigit() and int(suffix) == target_year:
                return True
            m_range = re.match(r"^(\d{4})-(\d{4})$", suffix)
            if m_range:
                lo, hi = int(m_range.group(1)), int(m_range.group(2))
                if lo <= target_year <= hi:
                    return True
    return False


def validate_authorized_approver_for_attestation(
    approver_id: str,
    approvers_registry: dict[str, Any],
    *,
    signing_time_utc: str,
    required_operation: str,
    target_year: int | None = None,
    runtime_environment: str = "PRODUCTION",
    expected_key_id: str | None = None,
    expected_key_version: str | None = None,
    expected_algorithm: str | None = None,
    expected_fingerprint: str | None = None,
    timestamp_trust_level: str = "SELF_ASSERTED_UNTRUSTED",
) -> dict[str, Any]:
    """Validate approver identity, environment trust tier, scope, key version/fingerprint, temporal window, and revocation semantics."""
    errors: list[str] = []
    error_codes: list[str] = []
    warnings: list[str] = []

    approvers_map = approvers_registry.get("approvers") if isinstance(approvers_registry, dict) else None
    if not isinstance(approvers_map, dict) or approver_id not in approvers_map:
        return {
            "valid": False,
            "approver_id": approver_id,
            "approver_record": None,
            "error_codes": ["UNAUTHORIZED_APPROVER"],
            "errors": [f"'{approver_id}' yetkili onaylayan kimlik defterinde (authorized_approvers) kayıtlı değildir."],
            "warnings": [],
        }

    rec = approvers_map[approver_id]
    if not isinstance(rec, dict):
        return {
            "valid": False,
            "approver_id": approver_id,
            "approver_record": None,
            "error_codes": ["UNAUTHORIZED_APPROVER"],
            "errors": [f"'{approver_id}' onaylayan kaydı geçersiz biçimdedir."],
            "warnings": [],
        }

    env_norm = str(runtime_environment or "PRODUCTION").upper().strip()
    trust_tier = str(rec.get("key_trust_tier") or "").upper().strip()
    env_restrictions = [str(e).upper().strip() for e in (rec.get("environment_restrictions") or [])]

    # 1. Production vs TEST_SANDBOX_ONLY strict separation
    if env_norm == "PRODUCTION":
        if trust_tier == "TEST_SANDBOX_ONLY" or "PRODUCTION" not in env_restrictions:
            error_codes.append("PRODUCTION_SIGNING_KEY_REQUIRED")
            errors.append(
                f"'{approver_id}' anahtarı (trust_tier='{trust_tier}', environments={env_restrictions}) "
                f"TEST_SANDBOX_ONLY / üretim dışı sınıftadır; PRODUCTION ortamında kabul edilemez."
            )
    elif env_norm not in env_restrictions:
        error_codes.append("PRODUCTION_SIGNING_KEY_REQUIRED")
        errors.append(
            f"'{approver_id}' anahtarı '{env_norm}' ortamı için yetkilendirilmemiştir (izinli: {env_restrictions})."
        )

    # 2. Public key enrollment & algorithm/version/fingerprint binding
    pub_pem = rec.get("public_key_pem")
    reg_alg = str(rec.get("key_algorithm") or "").upper().strip()
    reg_key_id = str(rec.get("key_id") or "").strip()
    reg_key_ver = str(rec.get("key_version") or "").strip()
    reg_fp = str(rec.get("public_key_fingerprint_sha256") or "").strip().lower()

    if not isinstance(pub_pem, str) or "BEGIN PUBLIC KEY" not in pub_pem:
        error_codes.append("UNAUTHORIZED_APPROVER")
        errors.append(
            f"'{approver_id}' için kayıtlı asimetrik açık anahtar (public_key_pem) bulunmamaktadır "
            f"(durum: {rec.get('enrollment_status', 'UNENROLLED')})."
        )
    else:
        computed_fp = compute_public_key_fingerprint(pub_pem)
        if reg_fp and computed_fp != reg_fp:
            error_codes.append("SIGNING_KEY_VERSION_OR_FINGERPRINT_MISMATCH")
            errors.append(f"'{approver_id}' kayıtlı açık anahtar parmak izi uyuşmuyor.")
        if expected_fingerprint and expected_fingerprint.lower() != computed_fp:
            error_codes.append("SIGNING_KEY_VERSION_OR_FINGERPRINT_MISMATCH")
            errors.append(
                f"İmza zarfındaki public_key_fingerprint_sha256 '{approver_id}' açık anahtarıyla uyuşmuyor."
            )

    if reg_alg not in SUPPORTED_SIGNATURE_ALGORITHMS:
        error_codes.append("UNSUPPORTED_SIGNATURE_ALGORITHM")
        errors.append(f"'{approver_id}' için desteklenmeyen anahtar algoritması: '{reg_alg}'.")
    if expected_algorithm and str(expected_algorithm).upper().strip() != reg_alg:
        error_codes.append("SIGNING_KEY_VERSION_OR_FINGERPRINT_MISMATCH")
        errors.append(
            f"İmza algoritması ('{expected_algorithm}') onaylayan anahtar algoritmasıyla ('{reg_alg}') uyuşmuyor."
        )
    if expected_key_id and expected_key_id != reg_key_id:
        error_codes.append("SIGNING_KEY_VERSION_OR_FINGERPRINT_MISMATCH")
        errors.append(f"İmza key_id ('{expected_key_id}') kayıtlı key_id ('{reg_key_id}') ile uyuşmuyor.")
    if expected_key_version and expected_key_version != reg_key_ver:
        error_codes.append("SIGNING_KEY_VERSION_OR_FINGERPRINT_MISMATCH")
        errors.append(f"İmza key_version ('{expected_key_version}') kayıtlı key_version ('{reg_key_ver}') ile uyuşmuyor.")

    # 3. Scope check (operation + calendar year)
    auth_scopes = rec.get("authorized_scopes")
    if not isinstance(auth_scopes, list) or not _scope_matches(auth_scopes, required_operation, target_year):
        error_codes.append("APPROVER_OUT_OF_SCOPE")
        errors.append(
            f"'{approver_id}' kimliği '{required_operation}' (yıl={target_year}) işlemi için yetkili kapsamda değildir "
            f"(authorized_scopes={auth_scopes})."
        )

    # 4. Temporal validity window: valid_from_utc <= signing_time_utc <= valid_until_utc
    sign_dt = parse_utc_timestamp(signing_time_utc)
    valid_from = parse_utc_timestamp(rec.get("valid_from_utc"))
    valid_until = parse_utc_timestamp(rec.get("valid_until_utc"))
    if sign_dt is None:
        error_codes.append("APPROVER_NOT_VALID_AT_SIGNING_TIME")
        errors.append(f"İmza zamanı geçerli ISO-8601 UTC zaman damgası değildir: '{signing_time_utc}'.")
    if valid_from is None or valid_until is None or valid_until < valid_from:
        error_codes.append("APPROVER_NOT_VALID_AT_SIGNING_TIME")
        errors.append(
            f"'{approver_id}' için valid_from_utc / valid_until_utc geçerlilik aralığı eksik veya geçersiz."
        )
    elif sign_dt is not None:
        if sign_dt < valid_from or sign_dt > valid_until:
            error_codes.append("APPROVER_NOT_VALID_AT_SIGNING_TIME")
            errors.append(
                f"'{approver_id}' imza tarihinde ({signing_time_utc}) yetkili değildi "
                f"(geçerlilik: {rec.get('valid_from_utc')}..{rec.get('valid_until_utc')})."
            )

    # 5. Nuanced revocation evaluation (revoked_at_utc, revocation_reason, timestamp trustworthiness)
    status = str(rec.get("status") or "").upper().strip()
    revoked_at_raw = rec.get("revoked_at_utc")
    revocation_reason = str(rec.get("revocation_reason") or "NONE").upper().strip()
    ts_trust = str(timestamp_trust_level or "SELF_ASSERTED_UNTRUSTED").upper().strip()

    if status == "SUSPENDED":
        error_codes.append("APPROVER_REVOKED_BEFORE_SIGNATURE")
        errors.append(f"'{approver_id}' kimliği askıya alınmıştır (status=SUSPENDED).")
    elif status == "REVOKED" or revoked_at_raw is not None:
        rev_dt = parse_utc_timestamp(revoked_at_raw)
        if rev_dt is None:
            error_codes.append("APPROVER_REVOKED_BEFORE_SIGNATURE")
            errors.append(
                f"'{approver_id}' iptal edilmiş ancak geçerli revoked_at_utc zaman damgası kaydedilmemiştir."
            )
        elif sign_dt is not None:
            if sign_dt >= rev_dt:
                error_codes.append("APPROVER_REVOKED_BEFORE_SIGNATURE")
                errors.append(
                    f"İmza ({signing_time_utc}), '{approver_id}' anahtarının iptal zamanı ({revoked_at_raw}) "
                    f"sonrasında atılmıştır (neden={revocation_reason})."
                )
            else:
                # Signature claims to pre-date revocation: evaluate compromise vs non-compromise + timestamp trust!
                if revocation_reason in COMPROMISE_REVOCATION_REASONS:
                    error_codes.append("APPROVER_KEY_COMPROMISED_RETROACTIVE_INVALIDATION")
                    errors.append(
                        f"'{approver_id}' anahtarı '{revocation_reason}' nedeniyle iptal edildiğinden iptal öncesi "
                        f"imza ({signing_time_utc}) geriye dönük olarak geçersiz sayılmıştır."
                    )
                elif revocation_reason in NON_COMPROMISE_REVOCATION_REASONS:
                    if ts_trust in TRUSTED_TIMESTAMP_LEVELS:
                        warnings.append(
                            f"REVOCATION_PRE_DATE_TRUSTED_TIMESTAMP_VALID: '{approver_id}' anahtarı imza sonrası "
                            f"({revoked_at_raw}) '{revocation_reason}' nedeniyle iptal edilmiştir; imza zamanı "
                            f"('{ts_trust}') güvenilir olduğundan tarihsel geçerliliği korunmuştur."
                        )
                    else:
                        error_codes.append("REVOKED_KEY_UNTRUSTED_SIGNING_TIMESTAMP")
                        errors.append(
                            f"'{approver_id}' anahtarı '{revocation_reason}' nedeniyle {revoked_at_raw} tarihinde iptal "
                            f"edilmiş olup imza zamanı yalnızca kendi beyanına ('{ts_trust}') dayandığından iptal "
                            f"öncesi atıldığı kanıtlanamamaktadır; bağımsız TSA veya imzalı checkpoint çapa gerekir."
                        )
                else:
                    error_codes.append("APPROVER_REVOKED_BEFORE_SIGNATURE")
                    errors.append(
                        f"'{approver_id}' bilinmeyen/belirsiz iptal nedeni ('{revocation_reason}') ile iptal edilmiştir."
                    )

    return {
        "valid": len(errors) == 0 and len(error_codes) == 0,
        "approver_id": approver_id,
        "approver_record": rec,
        "error_codes": sorted(set(error_codes)),
        "errors": errors,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# 5. Externally Verifiable Hash-Chained Audit Ledger & Signed Checkpoints
# ---------------------------------------------------------------------------


def compute_ledger_entry_hash(entry: dict[str, Any]) -> str:
    """Compute canonical SHA-256 hash of a ledger entry binding sequence, id, type, timestamp, payload, and prev_entry_hash."""
    body = {
        "sequence_no": entry.get("sequence_no"),
        "entry_id": entry.get("entry_id"),
        "entry_type": entry.get("entry_type"),
        "recorded_at_utc": entry.get("recorded_at_utc"),
        "payload": entry.get("payload"),
        "prev_entry_hash": entry.get("prev_entry_hash"),
    }
    return compute_canonical_sha256(body)


def compute_chain_digest(entry_hashes: list[str]) -> str:
    """Compute deterministic chain digest over an ordered sequence of entry hashes."""
    return hashlib.sha256(":".join(entry_hashes).encode("utf-8")).hexdigest()


def append_ledger_entry(
    ledger: dict[str, Any],
    *,
    entry_id: str,
    entry_type: str,
    recorded_at_utc: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Append a new hash-chained entry to an attestation ledger (returns newly appended entry)."""
    entries = ledger.setdefault("entries", [])
    seq = len(entries) + 1
    prev_hash = GENESIS_PREV_HASH if seq == 1 else str(entries[-1]["entry_hash"])
    entry: dict[str, Any] = {
        "sequence_no": seq,
        "entry_id": entry_id,
        "entry_type": entry_type,
        "recorded_at_utc": recorded_at_utc,
        "payload": payload,
        "prev_entry_hash": prev_hash,
    }
    entry["entry_hash"] = compute_ledger_entry_hash(entry)
    entries.append(entry)
    return entry


def build_checkpoint_signing_payload(checkpoint: dict[str, Any]) -> dict[str, Any]:
    return {
        "checkpoint_id": checkpoint.get("checkpoint_id"),
        "checkpoint_scope": checkpoint.get("checkpoint_scope"),
        "created_at_utc": checkpoint.get("created_at_utc"),
        "from_sequence_no": checkpoint.get("from_sequence_no"),
        "to_sequence_no": checkpoint.get("to_sequence_no"),
        "entry_count": checkpoint.get("entry_count"),
        "head_entry_hash": checkpoint.get("head_entry_hash"),
        "chain_digest_sha256": checkpoint.get("chain_digest_sha256"),
        "nonce": checkpoint.get("nonce"),
        "signer_approver_id": checkpoint.get("signer_approver_id"),
        "key_id": checkpoint.get("key_id"),
        "key_version": checkpoint.get("key_version"),
        "algorithm": checkpoint.get("algorithm"),
    }


def create_ledger_checkpoint(
    ledger: dict[str, Any],
    *,
    checkpoint_id: str,
    checkpoint_scope: str,
    created_at_utc: str,
    nonce: str,
    signer_approver_id: str | None = None,
    private_key_pem: str | None = None,
    key_id: str | None = None,
    key_version: str | None = None,
    algorithm: str = "ED25519",
    public_key_pem: str | None = None,
    external_tsa_token_status: str = "PENDING_EXTERNAL_TSA_INTEGRATION",
) -> dict[str, Any]:
    """Create a daily or release chain digest checkpoint (optionally signed with separate sealer key)."""
    entries = ledger.get("entries") or []
    if not entries:
        raise ValueError("Boş denetim zinciri için checkpoint oluşturulamaz.")
    hashes = [str(e["entry_hash"]) for e in entries]
    cp: dict[str, Any] = {
        "checkpoint_id": checkpoint_id,
        "checkpoint_scope": checkpoint_scope,
        "created_at_utc": created_at_utc,
        "from_sequence_no": 1,
        "to_sequence_no": len(entries),
        "entry_count": len(entries),
        "head_entry_hash": hashes[-1],
        "chain_digest_sha256": compute_chain_digest(hashes),
        "nonce": nonce,
        "worm_storage_policy": "WORM_AND_INDEPENDENT_TSA_REQUIRED_FOR_PRODUCTION",
        "external_tsa_token_status": external_tsa_token_status,
        "signer_approver_id": signer_approver_id,
        "key_id": key_id,
        "key_version": key_version,
        "algorithm": algorithm.upper() if private_key_pem else None,
        "public_key_fingerprint_sha256": compute_public_key_fingerprint(public_key_pem) if public_key_pem else None,
        "checkpoint_signature_b64": None,
        "checkpoint_signature_status": "PENDING_PRODUCTION_SEALER_KEY_ENROLLMENT",
    }
    if private_key_pem and signer_approver_id:
        signing_payload = build_checkpoint_signing_payload(cp)
        cp["checkpoint_signature_b64"] = sign_canonical_payload(signing_payload, private_key_pem, algorithm=algorithm)
        cp["checkpoint_signature_status"] = "SIGNED_CHECKPOINT"
    ledger.setdefault("checkpoints", []).append(cp)
    return cp


def verify_attestation_ledger(
    ledger: dict[str, Any],
    *,
    approvers_registry: dict[str, Any] | None = None,
    runtime_environment: str = "PRODUCTION",
    expected_checkpoint_head_hash: str | None = None,
    expected_checkpoint_entry_count: int | None = None,
    expected_chain_digest_sha256: str | None = None,
    require_signed_checkpoints: bool | None = None,
    trust_anchor_source: str = "OUT_OF_BAND_TRUSTED_CONFIG",
) -> dict[str, Any]:
    """Verify hash-chain continuity, entry integrity, replay/nonce uniqueness, signed checkpoints, and out-of-band WORM/TSA trust anchors.

    v1.0.2c.6 Mandatory External Trust Root Guarantees:
      - Default `require_signed_checkpoints=True`: an unsigned or unanchored chain is NEVER reported as `valid=True`.
      - In `PRODUCTION`, unsigned checkpoints are ALWAYS rejected (`UNSIGNED_CHECKPOINT_REJECTED_IN_PRODUCTION`),
        even if a caller attempts to pass `require_signed_checkpoints=False`.
      - Without an independently verified signed checkpoint covering the chain head OR an out-of-band verified
        WORM/TSA anchor covering the chain head, a mathematically self-consistent chain is reported as
        `trust_anchor_status="CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR"` (`valid=False`,
        `mathematical_chain_intact=True`, `externally_verified_immutable=False`, `production_use_authorized=False`).
      - Anchor expectations (`expected_checkpoint_head_hash`, `expected_checkpoint_entry_count`,
        `expected_chain_digest_sha256`) are NEVER read from untrusted ledger content; self-declared anchor fields
        injected inside the ledger or untrusted `trust_anchor_source` values are rejected with
        `UNTRUSTED_SELF_DECLARED_ANCHOR_IN_LEDGER` + `AUDIT_CHAIN_TAMPERING_DETECTED`.
    """
    errors: list[str] = []
    error_codes: list[str] = []
    warnings: list[str] = []

    env_norm = str(runtime_environment or "PRODUCTION").upper().strip()
    eff_require_signed = True if require_signed_checkpoints is None else bool(require_signed_checkpoints)
    anchor_src_norm = str(trust_anchor_source or "").upper().strip()

    if not isinstance(ledger, dict) or not isinstance(ledger.get("entries"), list):
        return {
            "valid": False,
            "trust_anchor_status": "TAMPERED",
            "mathematical_chain_intact": False,
            "externally_verified_immutable": False,
            "production_use_authorized": False,
            "runtime_environment": env_norm,
            "trust_anchor_source": anchor_src_norm or "UNSPECIFIED",
            "entry_count": 0,
            "head_entry_hash": None,
            "chain_digest_sha256": None,
            "verified_checkpoints_count": 0,
            "unsigned_checkpoints_count": 0,
            "max_signed_checkpoint_sequence_no": 0,
            "signed_checkpoint_covers_head": False,
            "external_worm_anchor_provided": False,
            "external_worm_anchor_verified": False,
            "error_codes": ["AUDIT_CHAIN_TAMPERING_DETECTED"],
            "errors": ["Denetim zinciri (calendar_attestation_ledger) geçersiz veya entries listesi eksik."],
            "warnings": [],
        }

    # Anti-self-anchoring defense: reject any forbidden self-declared anchor fields embedded in untrusted ledger JSON!
    self_anchor_violation = False
    top_forbidden = sorted(FORBIDDEN_LEDGER_SELF_ANCHOR_FIELDS & set(ledger.keys()))
    if top_forbidden:
        self_anchor_violation = True
        error_codes.append("UNTRUSTED_SELF_DECLARED_ANCHOR_IN_LEDGER")
        error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
        errors.append(
            f"Denetim defteri içinde doğrulanmamış öz-çapa (self-declared anchor) alanları tespit edildi ve reddedildi: {top_forbidden}. "
            f"Güven çapa değerleri yalnızca harici/bant-dışı (out-of-band) güvenilir kaynaktan sağlanmalıdır."
        )

    raw_cps_prescan = ledger.get("checkpoints")
    if isinstance(raw_cps_prescan, list):
        for cp_idx, cp_item in enumerate(raw_cps_prescan):
            if isinstance(cp_item, dict):
                cp_forbidden = sorted(FORBIDDEN_LEDGER_SELF_ANCHOR_FIELDS & set(cp_item.keys()))
                if cp_forbidden:
                    self_anchor_violation = True
                    error_codes.append("UNTRUSTED_SELF_DECLARED_ANCHOR_IN_LEDGER")
                    error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
                    errors.append(
                        f"Checkpoint #{cp_idx + 1} içinde doğrulanmamış öz-çapa alanları tespit edildi ve reddedildi: {cp_forbidden}."
                    )

    any_anchor_arg = (
        expected_checkpoint_head_hash is not None
        or expected_checkpoint_entry_count is not None
        or expected_chain_digest_sha256 is not None
    )
    anchor_source_invalid = False
    if any_anchor_arg and anchor_src_norm not in VALID_TRUST_ANCHOR_SOURCES:
        anchor_source_invalid = True
        error_codes.append("UNTRUSTED_SELF_DECLARED_ANCHOR_IN_LEDGER")
        error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
        errors.append(
            f"Harici çapa kaynağı (trust_anchor_source='{trust_anchor_source}') güvenilir bant-dışı kaynaklardan "
            f"({sorted(VALID_TRUST_ANCHOR_SOURCES)}) biri değildir; doğrulanmamış/ledger-içi çapa kabul edilemez."
        )

    entries = ledger["entries"]
    seen_entry_ids: set[str] = set()
    seen_nonces: set[str] = set()
    entry_hashes: list[str] = []
    chain_math_broken = False

    if len(entries) == 0:
        chain_math_broken = True
        error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
        errors.append("Denetim zinciri boş (entries=[]) olamaz.")

    prev_hash = GENESIS_PREV_HASH
    for idx, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            chain_math_broken = True
            error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
            errors.append(f"Denetim zinciri #{idx} kaydı geçersiz nesne biçimindedir.")
            continue

        seq = entry.get("sequence_no")
        if seq != idx:
            chain_math_broken = True
            error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
            errors.append(
                f"Denetim zincirinde kayıt silinmesi/sıra bozulması tespit edildi: beklenen sequence_no={idx}, bulunan={seq}."
            )

        eid = str(entry.get("entry_id") or "")
        if not eid or eid in seen_entry_ids:
            chain_math_broken = True
            error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
            errors.append(f"Denetim zincirinde eksik veya mükerrer entry_id: '{eid}'.")
        else:
            seen_entry_ids.add(eid)

        if entry.get("prev_entry_hash") != prev_hash:
            chain_math_broken = True
            error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
            errors.append(
                f"Denetim zinciri #{idx} ({eid}) prev_entry_hash kopması: beklenen={prev_hash}, bulunan={entry.get('prev_entry_hash')}."
            )

        recomputed_hash = compute_ledger_entry_hash(entry)
        stored_hash = str(entry.get("entry_hash") or "")
        if recomputed_hash != stored_hash:
            chain_math_broken = True
            error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
            errors.append(
                f"Denetim zinciri #{idx} ({eid}) geriye dönük değiştirilmiş: hesaplanan={recomputed_hash}, kayıtlı={stored_hash}."
            )

        # Replay prevention: nonces in legal attestation payloads must never repeat
        payload = entry.get("payload")
        if isinstance(payload, dict) and payload.get("nonce"):
            nc = str(payload["nonce"])
            if nc in seen_nonces:
                chain_math_broken = True
                error_codes.append("DUPLICATE_ATTESTATION_NONCE")
                error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
                errors.append(f"Denetim zincirinde mükerrer/tekrar kullanılan nonce tespit edildi: '{nc}'.")
            else:
                seen_nonces.add(nc)

        entry_hashes.append(stored_hash)
        prev_hash = stored_hash

    # Verify checkpoints (signed checkpoints + tail-append protection + unsigned checkpoint rejection in PRODUCTION)
    checkpoints = ledger.get("checkpoints")
    verified_cp_count = 0
    unsigned_cp_count = 0
    max_signed_checkpoint_seq = 0
    all_signed_cps_production_tier = True

    if not isinstance(checkpoints, list) or len(checkpoints) == 0:
        if eff_require_signed:
            error_codes.append("SIGNED_CHECKPOINT_REQUIRED")
            errors.append("Denetim zinciri için imzalı checkpoint özeti bulunamadı.")
    else:
        seen_cp_nonces: set[str] = set()
        for cp in checkpoints:
            if not isinstance(cp, dict):
                chain_math_broken = True
                error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
                errors.append("Checkpoint kaydı JSON nesnesi olmalıdır.")
                continue
            cp_id = str(cp.get("checkpoint_id") or "UNKNOWN")
            cp_from = cp.get("from_sequence_no")
            cp_to = cp.get("to_sequence_no")
            cp_cnt = cp.get("entry_count")
            cp_nonce = str(cp.get("nonce") or "")
            if cp_nonce:
                if cp_nonce in seen_cp_nonces:
                    chain_math_broken = True
                    error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
                    errors.append(f"Checkpoint '{cp_id}' içinde mükerrer nonce: '{cp_nonce}'.")
                seen_cp_nonces.add(cp_nonce)

            if (
                isinstance(cp_from, bool)
                or isinstance(cp_to, bool)
                or isinstance(cp_cnt, bool)
                or not isinstance(cp_from, int)
                or not isinstance(cp_to, int)
                or not isinstance(cp_cnt, int)
                or cp_from != 1
                or cp_to != cp_cnt
                or cp_to < 1
            ):
                chain_math_broken = True
                error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
                errors.append(f"Checkpoint '{cp_id}' sıra aralığı/sayısı geçersiz ({cp_from}..{cp_to}, count={cp_cnt}).")
                continue

            if len(entries) < cp_to:
                chain_math_broken = True
                error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
                errors.append(
                    f"Denetim zincirinden kayıt silinmiş/kırpılmış: checkpoint '{cp_id}' en az {cp_to} kayıt beklerken "
                    f"zincirde yalnızca {len(entries)} kayıt var."
                )
                continue

            slice_hashes = entry_hashes[:cp_to]
            expected_head = slice_hashes[-1]
            expected_digest = compute_chain_digest(slice_hashes)
            if cp.get("head_entry_hash") != expected_head or cp.get("chain_digest_sha256") != expected_digest:
                chain_math_broken = True
                error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
                errors.append(
                    f"Checkpoint '{cp_id}' zincir özeti uyuşmuyor (zincir yeniden oluşturulmuş veya kayıt değiştirilmiş olabilir): "
                    f"head beklenen={cp.get('head_entry_hash')} / gerçek={expected_head}."
                )
                continue

            sig_b64 = cp.get("checkpoint_signature_b64")
            if sig_b64:
                if approvers_registry is None:
                    error_codes.append("UNAUTHORIZED_APPROVER")
                    errors.append(f"Checkpoint '{cp_id}' imzasını doğrulamak için authorized_approvers defteri gereklidir.")
                    continue
                signer_id = str(cp.get("signer_approver_id") or "")
                approver_chk = validate_authorized_approver_for_attestation(
                    signer_id,
                    approvers_registry,
                    signing_time_utc=str(cp.get("created_at_utc") or ""),
                    required_operation="AUDIT_CHECKPOINT_SEAL",
                    target_year=None,
                    runtime_environment=env_norm,
                    expected_key_id=cp.get("key_id"),
                    expected_key_version=cp.get("key_version"),
                    expected_algorithm=cp.get("algorithm"),
                    expected_fingerprint=cp.get("public_key_fingerprint_sha256"),
                    timestamp_trust_level=(
                        "INDEPENDENT_TSA_VERIFIED"
                        if cp.get("external_tsa_token_status") == "VERIFIED_EXTERNAL_TSA"
                        else "SELF_ASSERTED_UNTRUSTED"
                    ),
                )
                if not approver_chk["valid"]:
                    error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
                    error_codes.extend(approver_chk["error_codes"])
                    errors.extend(approver_chk["errors"])
                    continue
                pub_pem = approver_chk["approver_record"]["public_key_pem"]
                sig_ok, sig_msg = verify_asymmetric_signature(
                    build_checkpoint_signing_payload(cp),
                    sig_b64,
                    pub_pem,
                    str(cp.get("algorithm") or ""),
                )
                if not sig_ok:
                    error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
                    error_codes.append("INVALID_ATTESTATION_SIGNATURE")
                    errors.append(f"Checkpoint '{cp_id}' imzası geçersiz: {sig_msg}")
                    continue
                verified_cp_count += 1
                if cp_to > max_signed_checkpoint_seq:
                    max_signed_checkpoint_seq = cp_to
                if approver_chk["approver_record"].get("key_trust_tier") == "TEST_SANDBOX_ONLY":
                    all_signed_cps_production_tier = False
            else:
                unsigned_cp_count += 1
                warnings.append(
                    f"Checkpoint '{cp_id}' henüz imzasızdır ({cp.get('checkpoint_signature_status')}); "
                    f"harici imzalı mühür ve WORM/TSA çapa olmadan zincir değişmezliği kanıtlanamaz."
                )
                if env_norm == "PRODUCTION":
                    error_codes.append("UNSIGNED_CHECKPOINT_REJECTED_IN_PRODUCTION")
                    errors.append(
                        f"PRODUCTION ortamında imzasız checkpoint ('{cp_id}') reddedildi; "
                        f"yetkili mühürleyici imzası veya bağımsız WORM/TSA güven kökü zorunludur."
                    )
                elif eff_require_signed:
                    error_codes.append("SIGNED_CHECKPOINT_REQUIRED")
                    errors.append(f"Checkpoint '{cp_id}' için zorunlu kriptografik imza eksik.")

    # Out-of-band external WORM / TSA anchor verification (NEVER read from untrusted ledger content!)
    external_worm_anchor_provided = (
        expected_checkpoint_head_hash is not None or expected_chain_digest_sha256 is not None
    )
    worm_anchor_mismatch = False
    anchor_covers_head = False

    if expected_checkpoint_head_hash is not None:
        if not isinstance(expected_checkpoint_head_hash, str) or not re.match(
            r"^[a-f0-9]{64}$", expected_checkpoint_head_hash.strip().lower()
        ):
            worm_anchor_mismatch = True
            error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
            errors.append("Harici WORM expected_checkpoint_head_hash geçerli 64 haneli SHA-256 özeti değildir.")

    if expected_chain_digest_sha256 is not None:
        if not isinstance(expected_chain_digest_sha256, str) or not re.match(
            r"^[a-f0-9]{64}$", expected_chain_digest_sha256.strip().lower()
        ):
            worm_anchor_mismatch = True
            error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
            errors.append("Harici WORM expected_chain_digest_sha256 geçerli 64 haneli SHA-256 özeti değildir.")

    if expected_checkpoint_entry_count is not None:
        if (
            isinstance(expected_checkpoint_entry_count, bool)
            or not isinstance(expected_checkpoint_entry_count, int)
            or expected_checkpoint_entry_count < 1
        ):
            worm_anchor_mismatch = True
            error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
            errors.append("Harici WORM expected_checkpoint_entry_count pozitif tamsayı olmalıdır.")
        elif len(entries) < expected_checkpoint_entry_count:
            worm_anchor_mismatch = True
            error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
            errors.append(
                f"Harici WORM çapa kayıt sayısı ({expected_checkpoint_entry_count}) denetim zincirinden ({len(entries)}) büyük; kayıt silinmiş."
            )
        else:
            if expected_checkpoint_head_hash is not None and not worm_anchor_mismatch:
                actual_at_anchor = entry_hashes[expected_checkpoint_entry_count - 1]
                if actual_at_anchor != expected_checkpoint_head_hash.strip().lower():
                    worm_anchor_mismatch = True
                    error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
                    errors.append(
                        f"Harici WORM çapa özeti uyuşmuyor (tüm zincir baştan yazılmış olabilir): "
                        f"çapa={expected_checkpoint_head_hash}, zincir={actual_at_anchor}."
                    )
            if expected_chain_digest_sha256 is not None and not worm_anchor_mismatch:
                actual_digest = compute_chain_digest(entry_hashes[:expected_checkpoint_entry_count])
                if actual_digest != expected_chain_digest_sha256.strip().lower():
                    worm_anchor_mismatch = True
                    error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
                    errors.append(
                        f"Harici WORM zincir özeti uyuşmuyor: çapa={expected_chain_digest_sha256}, zincir={actual_digest}."
                    )
            if external_worm_anchor_provided and not worm_anchor_mismatch and not anchor_source_invalid:
                anchor_covers_head = (expected_checkpoint_entry_count == len(entries) and len(entries) > 0)
    else:
        if expected_checkpoint_head_hash is not None and not worm_anchor_mismatch:
            head_now = entry_hashes[-1] if entry_hashes else None
            if head_now != expected_checkpoint_head_hash.strip().lower():
                worm_anchor_mismatch = True
                error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
                errors.append(
                    f"Harici başlık özeti uyuşmuyor (tüm zincir baştan yazılmış olabilir): "
                    f"çapa={expected_checkpoint_head_hash}, zincir={head_now}."
                )
        if expected_chain_digest_sha256 is not None and not worm_anchor_mismatch:
            full_digest_now = compute_chain_digest(entry_hashes) if entry_hashes else None
            if full_digest_now != expected_chain_digest_sha256.strip().lower():
                worm_anchor_mismatch = True
                error_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
                errors.append(
                    f"Harici WORM zincir özeti uyuşmuyor: çapa={expected_chain_digest_sha256}, zincir={full_digest_now}."
                )
        if external_worm_anchor_provided and not worm_anchor_mismatch and not anchor_source_invalid:
            anchor_covers_head = len(entries) > 0

    external_worm_anchor_verified = bool(
        external_worm_anchor_provided and not worm_anchor_mismatch and not anchor_source_invalid
    )
    mathematical_chain_intact = bool(len(entries) > 0 and not chain_math_broken)
    signed_checkpoint_covers_head = bool(
        len(entries) > 0 and verified_cp_count > 0 and max_signed_checkpoint_seq == len(entries)
    )

    # Tail-append detection: signed checkpoint verified for earlier entries, but new unanchored tail entries exist!
    if verified_cp_count > 0 and max_signed_checkpoint_seq < len(entries) and not anchor_covers_head:
        error_codes.append("CHAIN_HEAD_NOT_COVERED_BY_TRUST_ANCHOR")
        errors.append(
            f"Denetim zincirinin son kaydı (#{len(entries)}) imzalı checkpoint kapsamı "
            f"(en son mühürlenen #{max_signed_checkpoint_seq}) veya harici WORM çapası dışında kalmıştır."
        )

    # Mandatory External Trust Anchor Gate: mathematical chain consistency ALONE is NEVER trusted as immutable!
    has_external_trust_anchor_covering_head = bool(
        signed_checkpoint_covers_head or (external_worm_anchor_verified and anchor_covers_head)
    )
    if eff_require_signed and not signed_checkpoint_covers_head:
        if "CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR" not in error_codes:
            error_codes.append("CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR")
        errors.append(
            "Zincir başlığını kapsayan doğrulanmış imzalı checkpoint bulunmadığından harici güven kökü doğrulanamadı "
            "(yalnızca dahili matematiksel zincir bütünlüğü değişmezlik kanıtı değildir)."
        )
    elif not has_external_trust_anchor_covering_head:
        if "CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR" not in error_codes:
            error_codes.append("CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR")
        errors.append(
            "Doğrulanmış imzalı checkpoint veya harici WORM/TSA güven çapası sunulmadığından zincirin "
            "değiştirilemezliği dışarıdan doğrulanamadı (CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR)."
        )

    tampering_detected = bool(
        chain_math_broken
        or self_anchor_violation
        or anchor_source_invalid
        or worm_anchor_mismatch
        or "AUDIT_CHAIN_TAMPERING_DETECTED" in error_codes
    )

    externally_verified_immutable = bool(
        mathematical_chain_intact
        and not tampering_detected
        and len(errors) == 0
        and len(error_codes) == 0
        and has_external_trust_anchor_covering_head
        and (unsigned_cp_count == 0 if env_norm == "PRODUCTION" else True)
    )

    valid = externally_verified_immutable

    production_use_authorized = bool(
        externally_verified_immutable
        and env_norm == "PRODUCTION"
        and unsigned_cp_count == 0
        and (all_signed_cps_production_tier if verified_cp_count > 0 else external_worm_anchor_verified)
    )

    if tampering_detected:
        trust_anchor_status = "TAMPERED"
    elif externally_verified_immutable:
        trust_anchor_status = "EXTERNALLY_VERIFIED_IMMUTABLE"
    elif mathematical_chain_intact:
        trust_anchor_status = "CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR"
    else:
        trust_anchor_status = "TAMPERED"

    head_hash = entry_hashes[-1] if entry_hashes else None
    chain_digest = compute_chain_digest(entry_hashes) if entry_hashes else None
    return {
        "valid": valid,
        "trust_anchor_status": trust_anchor_status,
        "mathematical_chain_intact": mathematical_chain_intact,
        "externally_verified_immutable": externally_verified_immutable,
        "production_use_authorized": production_use_authorized,
        "runtime_environment": env_norm,
        "trust_anchor_source": anchor_src_norm or "UNSPECIFIED",
        "entry_count": len(entries),
        "head_entry_hash": head_hash,
        "chain_digest_sha256": chain_digest,
        "verified_checkpoints_count": verified_cp_count,
        "unsigned_checkpoints_count": unsigned_cp_count,
        "max_signed_checkpoint_sequence_no": max_signed_checkpoint_seq,
        "signed_checkpoint_covers_head": signed_checkpoint_covers_head,
        "external_worm_anchor_provided": external_worm_anchor_provided,
        "external_worm_anchor_verified": external_worm_anchor_verified,
        "error_codes": sorted(set(error_codes)),
        "errors": errors,
        "warnings": warnings,
    }


def verify_attestation_ledger_with_provider(
    ledger: dict[str, Any],
    *,
    external_trust_anchor_provider: Any,
    approvers_registry: dict[str, Any] | None = None,
    runtime_environment: str = "PRODUCTION",
    expected_app_project_id: str | None = None,
    require_signed_checkpoints: bool | None = None,
) -> dict[str, Any]:
    """Verify an attestation ledger against a provider-agnostic out-of-band `ExternalTrustAnchorProvider`.

    Fail-closed:
      - If the external trust anchor cannot be fetched or fails verification, verification FAILS immediately
        with `EXTERNAL_TRUST_ANCHOR_UNAVAILABLE_OR_INVALID` (NEVER falls back to in-app JSON files).
      - If the external provider is in `MOCK_SANDBOX` or `NOT_CONFIGURED` mode, `production_use_authorized`
        is strictly forced to `False`.
    """
    env_norm = str(runtime_environment or "PRODUCTION").upper().strip()
    ledger_id = str(ledger.get("ledger_id") or "") if isinstance(ledger, dict) else ""
    anchor = external_trust_anchor_provider.fetch_and_verify_trust_anchor(
        ledger_id,
        expected_app_project_id=expected_app_project_id,
        runtime_environment=env_norm,
    )
    if not anchor.valid:
        return {
            "valid": False,
            "trust_anchor_status": "EXTERNAL_TRUST_ANCHOR_UNAVAILABLE_OR_INVALID",
            "mathematical_chain_intact": False,
            "externally_verified_immutable": False,
            "production_use_authorized": False,
            "runtime_environment": env_norm,
            "trust_anchor_source": anchor.trust_anchor_source,
            "provider_integration_mode": anchor.integration_mode,
            "external_trust_anchor": anchor.to_dict(),
            "entry_count": len(ledger.get("entries", [])) if isinstance(ledger, dict) and isinstance(ledger.get("entries"), list) else 0,
            "head_entry_hash": None,
            "chain_digest_sha256": None,
            "verified_checkpoints_count": 0,
            "unsigned_checkpoints_count": 0,
            "max_signed_checkpoint_sequence_no": 0,
            "signed_checkpoint_covers_head": False,
            "external_worm_anchor_provided": False,
            "external_worm_anchor_verified": False,
            "error_codes": list(anchor.error_codes),
            "errors": list(anchor.errors),
            "warnings": [],
        }

    led_chk = verify_attestation_ledger(
        ledger,
        approvers_registry=approvers_registry,
        runtime_environment=env_norm,
        expected_checkpoint_head_hash=anchor.expected_checkpoint_head_hash,
        expected_checkpoint_entry_count=anchor.expected_checkpoint_entry_count,
        expected_chain_digest_sha256=anchor.expected_chain_digest_sha256,
        require_signed_checkpoints=require_signed_checkpoints,
        trust_anchor_source=anchor.trust_anchor_source,
    )
    led_chk["provider_integration_mode"] = anchor.integration_mode
    led_chk["external_trust_anchor"] = anchor.to_dict()
    if anchor.integration_mode != "LIVE_PRODUCTION":
        led_chk["production_use_authorized"] = False
    return led_chk


# ---------------------------------------------------------------------------
# 6. Two-Stage Signed Holiday Calendar Attestation Verification
# ---------------------------------------------------------------------------


def build_calendar_attestation_signing_payload(
    *,
    record_id: str,
    nonce: str,
    year: int,
    calendar_record: dict[str, Any],
    source_document_sha256: str,
    approver_id: str,
    approved_at_utc: str,
    key_id: str,
    key_version: str,
    algorithm: str,
) -> dict[str, Any]:
    """Build the exact canonical signing payload binding record_id, nonce, dates, source hash, and approver metadata."""
    return {
        "schema": "CALISORA_HOLIDAY_CALENDAR_ATTESTATION_V1",
        "record_id": record_id,
        "nonce": nonce,
        "year": year,
        "calendar_version": str(calendar_record.get("calendar_version") or "").strip(),
        "official_source_url": str(calendar_record.get("official_source_url") or "").strip(),
        "source_document_sha256": source_document_sha256.lower().strip(),
        "ramazan_arife_date": calendar_record.get("ramazan_arife_date"),
        "ramazan_start_date": calendar_record.get("ramazan_start_date"),
        "ramazan_end_date": calendar_record.get("ramazan_end_date"),
        "kurban_arife_date": calendar_record.get("kurban_arife_date"),
        "kurban_start_date": calendar_record.get("kurban_start_date"),
        "kurban_end_date": calendar_record.get("kurban_end_date"),
        "approver_id": approver_id,
        "approved_at_utc": approved_at_utc,
        "key_id": key_id,
        "key_version": key_version,
        "algorithm": algorithm.upper().strip(),
    }


def verify_signed_calendar_attestation(
    year: int,
    calendar_record: dict[str, Any],
    *,
    approvers_registry: dict[str, Any] | None,
    attestation_ledger: dict[str, Any] | None = None,
    project_root: Path | None = None,
    runtime_environment: str = "PRODUCTION",
    used_nonces: set[str] | None = None,
    expected_checkpoint_head_hash: str | None = None,
    expected_checkpoint_entry_count: int | None = None,
    expected_chain_digest_sha256: str | None = None,
    require_signed_ledger_checkpoint: bool = True,
    external_trust_anchor_provider: Any | None = None,
    expected_app_project_id: str | None = None,
) -> dict[str, Any]:
    """Execute full Two-Stage Verification for an external holiday calendar record.

    Stage 1 (Technical Source Verification — by System):
      - Archived/supplied official document stays strictly inside `project_root`, exists, SHA-256 matches
        `source_document_sha256`,
      - Strict Turkish parser matches ALL 9 exact bayram/arife/day-order slots, OCR confidence check passes.

    Stage 2 (Legal Counsel Cryptographic Attestation — by Authorized Legal Counsel):
      - `legal_attestation` envelope present with valid `record_id`, `nonce` (non-replayed), `algorithm`
        (Ed25519 or RSA-PSS-SHA256), `key_id`, `key_version`, `approver_id`, `approved_at_utc`, `signature_b64`,
      - Approver is registered in `approvers_registry`, authorized for `HOLIDAY_CALENDAR_LEGAL_APPROVAL:{year}`,
        valid at `approved_at_utc`, passes revocation & environment (`PRODUCTION` blocks `TEST_SANDBOX_ONLY`) checks,
      - Asymmetric signature verifies over spec-exact RFC 8785 (JCS) canonical JSON payload,
      - Linked to an externally anchored untampered entry in `attestation_ledger` (signed checkpoint covering head
        or verified out-of-band WORM/TSA anchor; NEVER authorizes production use without an external trust root).
    """
    errors: list[str] = []
    error_codes: list[str] = []
    warnings: list[str] = []

    # ---- Stage 1: Technical Source Snapshot & 9-Slot Content Match ----
    tech = verify_holiday_source_snapshot(year, calendar_record, project_root=project_root)
    if not tech["valid"]:
        error_codes.extend(tech["error_codes"])
        errors.extend(tech["errors"])

    # ---- Stage 2: Authorized Legal Counsel Cryptographic Attestation ----
    att = calendar_record.get("legal_attestation")
    legal_errors: list[str] = []
    legal_codes: list[str] = []
    legal_warnings: list[str] = []
    ledger_externally_verified_immutable = False
    ledger_trust_anchor_status = "UNVERIFIED"
    ledger_provider_live_prod = True

    if not isinstance(att, dict):
        legal_codes.append("TWO_STAGE_VERIFICATION_INCOMPLETE")
        legal_errors.append(
            f"{year} yılı takvim kaydı için yetkili hukuk müşavirinin kriptografik onay zarfı (legal_attestation) eksiktir."
        )
        claimed_verifier = str(calendar_record.get("verified_by") or "").strip()
        approvers_map = approvers_registry.get("approvers") if isinstance(approvers_registry, dict) else None
        if not isinstance(approvers_map, dict) or not claimed_verifier or claimed_verifier not in approvers_map:
            legal_codes.append("UNAUTHORIZED_APPROVER")
            legal_errors.append(
                f"'{claimed_verifier}' yetkili onaylayan kimlik defterinde (authorized_approvers) kayıtlı değildir."
            )
    else:
        record_id = str(att.get("record_id") or "").strip()
        nonce = str(att.get("nonce") or "").strip()
        approver_id = str(att.get("approver_id") or "").strip()
        approved_at_utc = str(att.get("approved_at_utc") or "").strip()
        algorithm = str(att.get("algorithm") or "").upper().strip()
        key_id = str(att.get("key_id") or "").strip()
        key_version = str(att.get("key_version") or "").strip()
        sig_b64 = str(att.get("signature_b64") or "").strip()
        att_fp = str(att.get("public_key_fingerprint_sha256") or "").strip().lower() or None
        ts_trust = str(att.get("timestamp_trust_level") or "SELF_ASSERTED_UNTRUSTED").upper().strip()

        # Verify record_id & nonce format and binding to calendar_record
        if not RECORD_ID_RE.match(record_id):
            legal_codes.append("SIGNATURE_REPLAY_OR_RECORD_MISMATCH")
            legal_errors.append(f"{year} yılı legal_attestation.record_id eksik veya geçersiz: '{record_id}'.")
        elif calendar_record.get("record_id") and str(calendar_record["record_id"]).strip() != record_id:
            legal_codes.append("SIGNATURE_REPLAY_OR_RECORD_MISMATCH")
            legal_errors.append(
                f"İmza record_id ('{record_id}') ile takvim kaydı record_id ('{calendar_record.get('record_id')}') uyuşmuyor (tekrar kullanım şüphesi)."
            )

        if att.get("year") is not None and att.get("year") != year:
            legal_codes.append("SIGNATURE_REPLAY_OR_RECORD_MISMATCH")
            legal_errors.append(
                f"İmza yılı ({att.get('year')}) hedeflenen takvim yılı ({year}) ile uyuşmuyor (tekrar kullanım engellendi)."
            )

        if not NONCE_RE.match(nonce):
            legal_codes.append("SIGNATURE_REPLAY_OR_RECORD_MISMATCH")
            legal_errors.append(f"{year} yılı legal_attestation.nonce eksik veya zayıf (>= 12 karakter alfanümerik gereklidir).")
        elif used_nonces is not None and nonce in used_nonces:
            legal_codes.append("DUPLICATE_ATTESTATION_NONCE")
            legal_errors.append(f"İmza nonce değeri ('{nonce}') daha önce başka bir kayıtta kullanılmış (replay engellendi).")

        if calendar_record.get("verified_by") and str(calendar_record["verified_by"]).strip() != approver_id:
            legal_codes.append("UNAUTHORIZED_APPROVER")
            legal_errors.append(
                f"Takvim kaydındaki verified_by ('{calendar_record.get('verified_by')}') ile imza approver_id ('{approver_id}') uyuşmuyor."
            )

        # Approver identity, temporal, scope, revocation & environment checks
        if approvers_registry is None:
            legal_codes.append("UNAUTHORIZED_APPROVER")
            legal_errors.append("Yetkili onaylayan kimlik defteri (authorized_approvers) sunulmadığından kimlik doğrulanamadı.")
            approver_chk: dict[str, Any] = {"valid": False, "approver_record": None}
        else:
            approver_chk = validate_authorized_approver_for_attestation(
                approver_id,
                approvers_registry,
                signing_time_utc=approved_at_utc,
                required_operation="HOLIDAY_CALENDAR_LEGAL_APPROVAL",
                target_year=year,
                runtime_environment=runtime_environment,
                expected_key_id=key_id or None,
                expected_key_version=key_version or None,
                expected_algorithm=algorithm or None,
                expected_fingerprint=att_fp,
                timestamp_trust_level=ts_trust,
            )
            legal_codes.extend(approver_chk["error_codes"])
            legal_errors.extend(approver_chk["errors"])
            legal_warnings.extend(approver_chk["warnings"])

        # Asymmetric cryptographic verification over spec-exact RFC 8785 (JCS) canonical JSON
        expected_doc_sha = str(calendar_record.get("source_document_sha256") or "").strip().lower()
        if approver_chk.get("valid") and approver_chk.get("approver_record"):
            pub_pem = approver_chk["approver_record"]["public_key_pem"]
            signing_payload = build_calendar_attestation_signing_payload(
                record_id=record_id,
                nonce=nonce,
                year=year,
                calendar_record=calendar_record,
                source_document_sha256=expected_doc_sha,
                approver_id=approver_id,
                approved_at_utc=approved_at_utc,
                key_id=key_id,
                key_version=key_version,
                algorithm=algorithm,
            )
            sig_ok, sig_msg = verify_asymmetric_signature(signing_payload, sig_b64, pub_pem, algorithm)
            if not sig_ok:
                legal_codes.append("INVALID_ATTESTATION_SIGNATURE")
                legal_errors.append(f"{year} yılı dijital imzası geçersiz: {sig_msg}")
            elif used_nonces is not None and nonce:
                used_nonces.add(nonce)

        # Immutable hash-chained audit ledger linkage check with mandatory external trust anchor
        ledger_entry_id = str(att.get("ledger_entry_id") or "").strip()
        if attestation_ledger is None:
            legal_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
            legal_errors.append(
                f"{year} yılı onay kaydı değiştirilemez hash zincirli denetim defterine (calendar_attestation_ledger) bağlı değildir."
            )
        else:
            if external_trust_anchor_provider is not None:
                ledger_chk = verify_attestation_ledger_with_provider(
                    attestation_ledger,
                    external_trust_anchor_provider=external_trust_anchor_provider,
                    approvers_registry=approvers_registry,
                    runtime_environment=runtime_environment,
                    expected_app_project_id=expected_app_project_id,
                    require_signed_checkpoints=require_signed_ledger_checkpoint,
                )
                ledger_provider_live_prod = ledger_chk.get("provider_integration_mode") == "LIVE_PRODUCTION"
            else:
                ledger_chk = verify_attestation_ledger(
                    attestation_ledger,
                    approvers_registry=approvers_registry,
                    runtime_environment=runtime_environment,
                    expected_checkpoint_head_hash=expected_checkpoint_head_hash,
                    expected_checkpoint_entry_count=expected_checkpoint_entry_count,
                    expected_chain_digest_sha256=expected_chain_digest_sha256,
                    require_signed_checkpoints=require_signed_ledger_checkpoint,
                )
            ledger_externally_verified_immutable = bool(ledger_chk["externally_verified_immutable"])
            ledger_trust_anchor_status = str(ledger_chk["trust_anchor_status"])
            if not ledger_chk["valid"]:
                legal_codes.extend(ledger_chk["error_codes"])
                legal_errors.extend(ledger_chk["errors"])
            else:
                # Confirm the exact signed attestation record exists in the untampered externally anchored ledger!
                matched_entry = None
                for entry in attestation_ledger.get("entries", []):
                    if entry.get("entry_id") == ledger_entry_id and entry.get("entry_type") == "LEGAL_COUNSEL_ATTESTATION":
                        p = entry.get("payload") or {}
                        if (
                            p.get("record_id") == record_id
                            and p.get("nonce") == nonce
                            and p.get("year") == year
                            and p.get("approver_id") == approver_id
                            and p.get("approved_at_utc") == approved_at_utc
                            and p.get("source_document_sha256") == expected_doc_sha
                            and p.get("signature_b64") == sig_b64
                        ):
                            matched_entry = entry
                            break
                if matched_entry is None:
                    legal_codes.append("AUDIT_CHAIN_TAMPERING_DETECTED")
                    legal_errors.append(
                        f"{year} yılı imzalı onayı (ledger_entry_id='{ledger_entry_id}', record_id='{record_id}') "
                        f"denetim zincirinde birebir eşleşen kayıtla doğrulanamadı."
                    )
                elif ts_trust == "SIGNED_EXTERNAL_CHECKPOINT_ANCHORED" and approver_chk.get("approver_record"):
                    rev_raw = approver_chk["approver_record"].get("revoked_at_utc")
                    rev_dt = parse_utc_timestamp(rev_raw) if rev_raw else None
                    if rev_dt is not None:
                        entry_seq = int(matched_entry.get("sequence_no") or 0)
                        anchored_before_rev = False
                        for cp in attestation_ledger.get("checkpoints", []):
                            cp_dt = parse_utc_timestamp(cp.get("created_at_utc"))
                            if (
                                cp.get("checkpoint_signature_b64")
                                and isinstance(cp.get("to_sequence_no"), int)
                                and cp["to_sequence_no"] >= entry_seq
                                and cp_dt is not None
                                and cp_dt < rev_dt
                            ):
                                anchored_before_rev = True
                                break
                        if not anchored_before_rev:
                            legal_codes.append("REVOKED_KEY_UNTRUSTED_SIGNING_TIMESTAMP")
                            legal_errors.append(
                                f"'{approver_id}' iptal öncesi imza için SIGNED_EXTERNAL_CHECKPOINT_ANCHORED beyan edilmiş "
                                f"ancak iptal zamanı ({rev_raw}) öncesinde bu kaydı kapsayan imzalı checkpoint bulunamamıştır."
                            )

    trust_tier_used = None
    if isinstance(att, dict) and isinstance(approvers_registry, dict):
        appr_obj = (approvers_registry.get("approvers") or {}).get(str(att.get("approver_id") or ""))
        if isinstance(appr_obj, dict):
            trust_tier_used = appr_obj.get("key_trust_tier")

    if (
        str(runtime_environment or "PRODUCTION").upper().strip() == "PRODUCTION"
        and isinstance(att, dict)
        and trust_tier_used is not None
        and trust_tier_used != "PRODUCTION_QUALIFIED_COUNSEL"
        and "PRODUCTION_SIGNING_KEY_REQUIRED" not in legal_codes
    ):
        legal_codes.append("PRODUCTION_SIGNING_KEY_REQUIRED")
        legal_errors.append(
            f"PRODUCTION ortamında hukuki takvim onayı için key_trust_tier='PRODUCTION_QUALIFIED_COUNSEL' zorunludur "
            f"(bulunan: '{trust_tier_used}')."
        )

    error_codes.extend(legal_codes)
    errors.extend(legal_errors)
    warnings.extend(legal_warnings)

    legal_valid = len(legal_errors) == 0 and len(legal_codes) == 0
    both_valid = tech["valid"] and legal_valid

    production_use_authorized = bool(
        both_valid
        and ledger_externally_verified_immutable
        and ledger_provider_live_prod
        and str(runtime_environment or "PRODUCTION").upper().strip() == "PRODUCTION"
        and trust_tier_used == "PRODUCTION_QUALIFIED_COUNSEL"
    )

    return {
        "valid": both_valid,
        "year": year,
        "technical_source_verification": tech,
        "legal_counsel_attestation": {
            "valid": legal_valid,
            "status": (
                "SIGNED_LEGAL_ATTESTATION_VERIFIED"
                if legal_valid
                else ("PENDING_SIGNED_EXTERNAL_ATTESTATION" if att is None else "ATTESTATION_REJECTED")
            ),
            "approver_id": att.get("approver_id") if isinstance(att, dict) else None,
            "approved_at_utc": att.get("approved_at_utc") if isinstance(att, dict) else None,
            "algorithm": att.get("algorithm") if isinstance(att, dict) else None,
            "key_id": att.get("key_id") if isinstance(att, dict) else None,
            "key_version": att.get("key_version") if isinstance(att, dict) else None,
            "key_trust_tier": trust_tier_used,
            "record_id": att.get("record_id") if isinstance(att, dict) else None,
            "nonce": att.get("nonce") if isinstance(att, dict) else None,
            "ledger_entry_id": att.get("ledger_entry_id") if isinstance(att, dict) else None,
            "error_codes": sorted(set(legal_codes)),
            "errors": legal_errors,
            "warnings": legal_warnings,
        },
        "ledger_trust_anchor_status": ledger_trust_anchor_status,
        "externally_verified_immutable": ledger_externally_verified_immutable,
        "production_use_authorized": production_use_authorized,
        "qualified_e_signature_5070_equivalent": False,
        "signature_legal_notice": SIGNATURE_5070_NON_EQUIVALENCE_NOTICE,
        "error_codes": sorted(set(error_codes)),
        "errors": errors,
        "warnings": warnings,
    }
