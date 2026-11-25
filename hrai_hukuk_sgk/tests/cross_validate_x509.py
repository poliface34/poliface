"""Single-Command Independent X.509 / ASN.1 DER Cross-Validation Tool (hrAI @HukukSGK v1.0.5.1).

Usage (from project root `hrai_hukuk_sgk/`):
    python3 -m tests.cross_validate_x509 --mode strict
    python3 -m tests.cross_validate_x509 --mode offline
    python3 -m tests.cross_validate_x509 --mode strict --output /tmp/x509_crossval_report.json
    python3 -m tests.cross_validate_x509 --mode strict --summary-only

Execution Modes:
  - `strict` (default): Requires OpenSSL, `pyasn1`/`pyasn1_modules`, `cryptography`, and `hrAI`.
    Evaluates all 4 parsers independently. Unsupported types remain `UNSUPPORTED_BY_PARSER` and
    are never counted as PASS. BER-permissive acceptances remain `BER_PERMISSIVE_ACCEPT`
    (`ber_permissive_not_der_proof: true`) and are never DER validity proof. Exits non-zero if
    any required parser is missing (`exit_code = 2`) or if configured positive/negative
    verification thresholds or authoritative `hrAI` checks fail (`exit_code = 1`).
  - `offline`: Runs ONLY `hrAI` strict DER validation. External parsers are marked
    `NOT_PERFORMED_OFFLINE_MODE` and the report explicitly carries
    `INDEPENDENT_CROSS_VALIDATION=NOT_PERFORMED`. Exits `0` iff fixture integrity and 100% of
    authoritative `hrAI` strict DER checks pass (`1` otherwise).

OpenSSL Classification Rules:
  - `openssl x509 -noout -text`, `openssl asn1parse -inform PEM -i`, and
    `openssl asn1parse -inform DER -i` are evaluated independently, each recording `exit_code`,
    `stdout_summary`, `stderr_summary`, `status`, and `parser_version`.
  - A positive vector is classified `ACCEPTED` ONLY when `x509 -text` decodes the SAN AND both
    PEM and DER `asn1parse` succeed (`rc == 0`) AND `pem_der_asn1_match` is `True`.
  - If `x509 -text` succeeds but ASN.1 parse fails -> `ASN1_PARSE_FAILED` (NEVER `ACCEPTED`).
  - If `x509 -text` and both ASN.1 parses succeed but PEM/DER trees diverge -> `PEM_DER_ASN1_MISMATCH`.
  - BER-permissive acceptance on a negative vector -> `BER_PERMISSIVE_ACCEPT` (NEVER DER proof).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
from pathlib import Path
import shutil
import subprocess
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from engine.esign5070 import (
    ESIGN_5070_VERSION,
    DerParseError,
    inspect_signer_certificate_x509,
    parse_x509_certificate_metadata,
    parse_x509_certificate_metadata_der,
)
from engine.esign5070 import x509_metadata as x509_mod
from tests.x509_crossval_vectors import FIXTURES_DIR, CrossValVectorSpec, load_and_verify_fixtures

VALIDATION_TIME_UTC = "2026-11-24T00:00:00Z"
REQUIRED_STRICT_PARSERS: tuple[str, ...] = ("openssl", "pyasn1_rfc5280", "cryptography", "hrai")
DEFAULT_MIN_EXTERNAL_POSITIVE_RATIO: float = 1.0
DEFAULT_MIN_EXTERNAL_NEGATIVE_RATIO: float = 0.90
_OPENSSL_KNOWN_SAN_PREFIXES: tuple[str, ...] = (
    "othername:",
    "DNS:",
    "email:",
    "URI:",
    "IP Address:",
    "DirName:",
    "Registered ID:",
)


def _summarize_text(text: str, *, max_len: int = 200) -> str:
    cleaned = " ".join(ln.strip() for ln in text.strip().splitlines() if ln.strip())
    if len(cleaned) <= max_len:
        return cleaned
    return cleaned[: max_len - 3] + "..."


def _summarize_asn1parse_stdout(stdout: str, *, max_len: int = 200) -> str:
    lines = [ln.rstrip() for ln in stdout.splitlines() if ln.strip()]
    if not lines:
        return ""
    head = lines[0].strip()
    summary = f"{len(lines)} lines; first={head}"
    if len(summary) <= max_len:
        return summary
    return summary[: max_len - 3] + "..."


def _extract_san_line(x509_text_stdout: str) -> str:
    lines = x509_text_stdout.splitlines()
    for i, ln in enumerate(lines):
        if "X509v3 Subject Alternative Name:" in ln and i + 1 < len(lines):
            return lines[i + 1].strip()
    return ""


def _detect_openssl() -> tuple[str | None, str]:
    exe = shutil.which("openssl")
    if not exe:
        return None, "NOT_INSTALLED"
    proc = subprocess.run(
        [exe, "version"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
    )
    ver = proc.stdout.strip() if proc.returncode == 0 else "UNKNOWN"
    return exe, ver


def _find_python_with_module(module_name: str) -> tuple[str | None, str]:
    """Return `(python_executable, version_string)` for a Python interpreter that can import `module_name`."""
    candidates: list[str] = [sys.executable]
    sys_py = "/usr/bin/python3"
    if Path(sys_py).exists() and sys_py not in candidates:
        candidates.append(sys_py)
    probe = f"import {module_name}; print(getattr({module_name}, '__version__', 'installed'))"
    if module_name == "pyasn1_modules":
        probe = (
            "import pyasn1, pyasn1_modules; "
            "print(f'pyasn1={pyasn1.__version__}, pyasn1_modules={pyasn1_modules.__version__}')"
        )
    for py_bin in candidates:
        proc = subprocess.run(
            [py_bin, "-c", probe],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return py_bin, proc.stdout.strip()
    return None, "NOT_INSTALLED"


def _classify_openssl_result(
    *,
    openssl_ver: str,
    expected_der_verdict: str,
    x509_rc: int,
    x509_stdout: str,
    x509_stderr: str,
    pem_asn1_rc: int,
    pem_asn1_stdout: str,
    pem_asn1_stderr: str,
    der_asn1_rc: int,
    der_asn1_stdout: str,
    der_asn1_stderr: str,
) -> dict[str, object]:
    """Independently classify OpenSSL `x509 -text`, `asn1parse -inform PEM`, and `asn1parse -inform DER` results.

    Strict classification contract:
      - `x509_text`, `asn1parse_pem`, and `asn1parse_der` each carry independent status, exit_code,
        stdout_summary, stderr_summary, and parser_version fields.
      - Positive vectors are NEVER unconditionally `ACCEPTED` if `asn1parse` fails (`ASN1_PARSE_FAILED`)
        or if PEM and DER ASN.1 parse trees diverge (`PEM_DER_ASN1_MISMATCH`).
      - Negative vectors accepted by OpenSSL due to BER leniency are explicitly labeled
        `BER_PERMISSIVE_ACCEPT` (`ber_permissive_not_der_proof: True`) and never DER validity proof.
      - Unsupported GeneralName markers (`<unsupported>`) remain `UNSUPPORTED_BY_PARSER` (or
        `ASN1_PARSE_FAILED` / `PEM_DER_ASN1_MISMATCH` if ASN.1 parse fails/diverges on a positive vector).
    """
    san_line = _extract_san_line(x509_stdout) if x509_rc == 0 else ""

    pem_asn1_ok = pem_asn1_rc == 0 and bool(pem_asn1_stdout.strip())
    der_asn1_ok = der_asn1_rc == 0 and bool(der_asn1_stdout.strip())
    pem_der_match = pem_asn1_ok and der_asn1_ok and (pem_asn1_stdout == der_asn1_stdout)

    if not pem_asn1_ok or not der_asn1_ok:
        asn1_status = "ASN1_PARSE_FAILED"
    elif not pem_der_match:
        asn1_status = "PEM_DER_ASN1_MISMATCH"
    else:
        asn1_status = "VERIFIED"

    # 1. Independent `x509 -noout -text` classification
    if x509_rc != 0:
        x509_status = "REJECTED"
    elif "<unsupported>" in san_line:
        x509_status = "UNSUPPORTED_BY_PARSER"
    elif not san_line or not any(san_line.startswith(pfx) for pfx in _OPENSSL_KNOWN_SAN_PREFIXES):
        x509_status = "REJECTED"
    elif expected_der_verdict == "REJECT":
        x509_status = "BER_PERMISSIVE_ACCEPT"
    else:
        x509_status = "OK"

    # 2. Combined OpenSSL verdict incorporating ASN.1 parse & PEM/DER parity
    ber_permissive = False
    error_detail: str | None = None

    if x509_status == "REJECTED":
        overall_status = "REJECTED"
        if x509_rc != 0:
            error_detail = f"openssl x509 -text failed (rc={x509_rc}): {_summarize_text(x509_stderr or x509_stdout)}"
        else:
            error_detail = f"OpenSSL failed GeneralNames decode (raw fallback output: {san_line!r})"
    elif x509_status == "UNSUPPORTED_BY_PARSER":
        if expected_der_verdict == "ACCEPT" and asn1_status != "VERIFIED":
            overall_status = asn1_status
            error_detail = (
                f"OpenSSL printed unsupported marker ({san_line!r}) AND ASN.1 verification failed "
                f"(status={asn1_status}, pem_rc={pem_asn1_rc}, der_rc={der_asn1_rc}, match={pem_der_match})."
            )
        else:
            overall_status = "UNSUPPORTED_BY_PARSER"
            error_detail = f"OpenSSL printed unsupported marker: {san_line}"
    elif x509_status == "BER_PERMISSIVE_ACCEPT":
        if asn1_status == "ASN1_PARSE_FAILED":
            overall_status = "REJECTED"
            error_detail = (
                f"OpenSSL x509 -text parsed SAN leniently ({san_line!r}) but asn1parse failed "
                f"(pem_rc={pem_asn1_rc}, der_rc={der_asn1_rc})."
            )
        else:
            overall_status = "BER_PERMISSIVE_ACCEPT"
            ber_permissive = True
            extra = "" if pem_der_match else " (PEM/DER asn1parse mismatch observed)"
            error_detail = (
                f"OpenSSL leniently accepted non-DER/BER encoding ({san_line!r}){extra}; "
                "NOT treated as DER canonicality proof."
            )
    else:
        # Positive vector where `x509 -text` parsed SAN: MUST ALSO pass PEM/DER asn1parse + match!
        if asn1_status == "VERIFIED":
            overall_status = "ACCEPTED"
        elif asn1_status == "ASN1_PARSE_FAILED":
            overall_status = "ASN1_PARSE_FAILED"
            error_detail = (
                f"OpenSSL x509 -text succeeded ({san_line!r}) but asn1parse failed "
                f"(pem_rc={pem_asn1_rc}, der_rc={der_asn1_rc}); NOT classified as ACCEPTED."
            )
        else:
            overall_status = "PEM_DER_ASN1_MISMATCH"
            error_detail = (
                f"OpenSSL x509 -text succeeded ({san_line!r}) but PEM and DER asn1parse outputs "
                "diverged (pem_der_asn1_match=False); NOT classified as ACCEPTED."
            )

    return {
        "parser_name": "openssl",
        "parser_version": openssl_ver,
        "status": overall_status,
        "san_text": san_line,
        "x509_text_rc": x509_rc,
        "pem_asn1_rc": pem_asn1_rc,
        "der_asn1_rc": der_asn1_rc,
        "pem_der_asn1_match": pem_der_match,
        "ber_permissive_not_der_proof": ber_permissive,
        "error_detail": error_detail,
        "asn1_verification": {
            "status": asn1_status,
            "pem_asn1_ok": pem_asn1_ok,
            "der_asn1_ok": der_asn1_ok,
            "pem_der_asn1_match": pem_der_match,
            "required_for_positive_accepted": True,
        },
        "commands": {
            "x509_text": {
                "command": "openssl x509 -noout -text",
                "parser_version": openssl_ver,
                "exit_code": x509_rc,
                "status": x509_status,
                "san_text": san_line,
                "stdout_summary": san_line if san_line else _summarize_text(x509_stdout),
                "stderr_summary": _summarize_text(x509_stderr),
            },
            "asn1parse_pem": {
                "command": "openssl asn1parse -inform PEM -i",
                "parser_version": openssl_ver,
                "exit_code": pem_asn1_rc,
                "status": "OK" if pem_asn1_ok else "FAILED",
                "stdout_summary": _summarize_asn1parse_stdout(pem_asn1_stdout),
                "stderr_summary": _summarize_text(pem_asn1_stderr),
            },
            "asn1parse_der": {
                "command": "openssl asn1parse -inform DER -i",
                "parser_version": openssl_ver,
                "exit_code": der_asn1_rc,
                "status": "OK" if der_asn1_ok else "FAILED",
                "stdout_summary": _summarize_asn1parse_stdout(der_asn1_stdout),
                "stderr_summary": _summarize_text(der_asn1_stderr),
            },
        },
    }


def _eval_openssl(
    openssl_bin: str | None,
    openssl_ver: str,
    spec: CrossValVectorSpec,
    pem_p: Path,
    der_p: Path,
) -> dict[str, object]:
    if not openssl_bin:
        return {
            "parser_name": "openssl",
            "parser_version": "NOT_INSTALLED",
            "status": "NOT_INSTALLED",
            "san_text": "",
            "x509_text_rc": None,
            "pem_asn1_rc": None,
            "der_asn1_rc": None,
            "pem_der_asn1_match": False,
            "ber_permissive_not_der_proof": False,
            "error_detail": "openssl binary not found",
            "asn1_verification": {
                "status": "NOT_INSTALLED",
                "pem_asn1_ok": False,
                "der_asn1_ok": False,
                "pem_der_asn1_match": False,
                "required_for_positive_accepted": True,
            },
            "commands": {},
        }
    res_text = subprocess.run(
        [openssl_bin, "x509", "-in", str(pem_p), "-noout", "-text"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
    )
    res_pem_asn1 = subprocess.run(
        [openssl_bin, "asn1parse", "-in", str(pem_p), "-inform", "PEM", "-i"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
    )
    res_der_asn1 = subprocess.run(
        [openssl_bin, "asn1parse", "-in", str(der_p), "-inform", "DER", "-i"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return _classify_openssl_result(
        openssl_ver=openssl_ver,
        expected_der_verdict=spec.expected_der_verdict,
        x509_rc=res_text.returncode,
        x509_stdout=res_text.stdout,
        x509_stderr=res_text.stderr,
        pem_asn1_rc=res_pem_asn1.returncode,
        pem_asn1_stdout=res_pem_asn1.stdout,
        pem_asn1_stderr=res_pem_asn1.stderr,
        der_asn1_rc=res_der_asn1.returncode,
        der_asn1_stdout=res_der_asn1.stdout,
        der_asn1_stderr=res_der_asn1.stderr,
    )


def _eval_pyasn1_batch(
    py_bin: str | None,
    pyasn1_ver: str,
    vectors: list[tuple[CrossValVectorSpec, Path, Path, bytes]],
) -> dict[str, dict[str, object]]:
    if not py_bin:
        return {
            spec.vector_id: {
                "parser_name": "pyasn1_rfc5280",
                "parser_version": "NOT_INSTALLED",
                "status": "NOT_INSTALLED",
                "san_types": [],
                "der_roundtrip": None,
                "ber_permissive_not_der_proof": False,
                "error_detail": "pyasn1 / pyasn1_modules not installed",
            }
            for spec, _dp, _pp, _db in vectors
        }

    worker = """
import base64, json, sys
from pyasn1.codec.der import decoder as der_decoder, encoder as der_encoder
from pyasn1_modules import rfc5280

payload = json.loads(sys.stdin.read())
out = {}
for item in payload:
    vid = item["vector_id"]
    raw = base64.b64decode(item["der_b64"])
    try:
        cert, rest = der_decoder.decode(raw, asn1Spec=rfc5280.Certificate())
        if rest:
            out[vid] = {"raw_status": "REJECTED", "der_roundtrip": False, "error_detail": f"trailing bytes: {len(rest)}"}
            continue
        san_types = []
        roundtrip = None
        for ext in cert["tbsCertificate"]["extensions"]:
            if str(ext["extnID"]) == "2.5.29.17":
                raw_san = bytes(ext["extnValue"])
                gns, grest = der_decoder.decode(raw_san, asn1Spec=rfc5280.GeneralNames())
                if grest:
                    raise ValueError(f"SAN trailing bytes: {len(grest)}")
                san_types = [gn.getName() for gn in gns]
                roundtrip = (der_encoder.encode(gns) == raw_san)
        out[vid] = {"raw_status": "ACCEPTED", "san_types": san_types, "der_roundtrip": roundtrip, "error_detail": None}
    except Exception as exc:
        out[vid] = {"raw_status": "REJECTED", "der_roundtrip": False, "error_detail": f"{type(exc).__name__}: {str(exc)[:180]}"}
print(json.dumps(out))
"""
    req_data = [
        {
            "vector_id": spec.vector_id,
            "der_b64": base64.b64encode(der_bytes).decode("ascii"),
        }
        for spec, _dp, _pp, der_bytes in vectors
    ]
    proc = subprocess.run(
        [py_bin, "-c", worker],
        input=json.dumps(req_data),
        capture_output=True,
        text=True,
        timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"pyasn1 worker failed: {proc.stderr}")
    raw_map = json.loads(proc.stdout)

    results: dict[str, dict[str, object]] = {}
    for spec, _dp, _pp, _db in vectors:
        rec = raw_map[spec.vector_id]
        raw_status = rec["raw_status"]
        roundtrip = rec.get("der_roundtrip")
        ber_permissive = False
        err = rec.get("error_detail")
        if raw_status == "REJECTED":
            status = "REJECTED"
        elif spec.expected_der_verdict == "REJECT":
            status = "BER_PERMISSIVE_ACCEPT"
            ber_permissive = True
            err = (
                f"pyasn1 accepted non-DER/BER/opaque-Any vector (der_roundtrip={roundtrip}); "
                "NOT treated as DER canonicality proof."
            )
        else:
            status = "ACCEPTED" if roundtrip else "NON_CANONICAL_ROUNDTRIP"
        results[spec.vector_id] = {
            "parser_name": "pyasn1_rfc5280",
            "parser_version": pyasn1_ver,
            "status": status,
            "san_types": rec.get("san_types", []),
            "der_roundtrip": roundtrip,
            "ber_permissive_not_der_proof": ber_permissive,
            "error_detail": err,
        }
    return results


def _eval_cryptography_batch(
    py_bin: str | None,
    crypto_ver: str,
    vectors: list[tuple[CrossValVectorSpec, Path, Path, bytes]],
) -> dict[str, dict[str, object]]:
    if not py_bin:
        return {
            spec.vector_id: {
                "parser_name": "cryptography_rust_asn1",
                "parser_version": "NOT_INSTALLED",
                "status": "NOT_INSTALLED",
                "san_types": [],
                "ber_permissive_not_der_proof": False,
                "error_detail": "cryptography not installed",
            }
            for spec, _dp, _pp, _db in vectors
        }

    worker = """
import base64, json, sys
import cryptography
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

payload = json.loads(sys.stdin.read())
out = {}
for item in payload:
    vid = item["vector_id"]
    raw = base64.b64decode(item["der_b64"])
    try:
        cert = x509.load_der_x509_certificate(raw)
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            vals = [type(v).__name__ for v in ext.value]
            out[vid] = {"raw_status": "ACCEPTED", "san_types": vals, "error_detail": None}
        except x509.UnsupportedGeneralNameType as exc:
            out[vid] = {"raw_status": "UNSUPPORTED_BY_PARSER", "san_types": [], "error_detail": str(exc)}
        except Exception as exc:
            out[vid] = {"raw_status": "REJECTED", "san_types": [], "error_detail": f"{type(exc).__name__}: {str(exc)[:180]}"}
    except Exception as exc:
        out[vid] = {"raw_status": "REJECTED", "san_types": [], "error_detail": f"{type(exc).__name__}: {str(exc)[:180]}"}
print(json.dumps(out))
"""
    req_data = [
        {
            "vector_id": spec.vector_id,
            "der_b64": base64.b64encode(der_bytes).decode("ascii"),
        }
        for spec, _dp, _pp, der_bytes in vectors
    ]
    proc = subprocess.run(
        [py_bin, "-c", worker],
        input=json.dumps(req_data),
        capture_output=True,
        text=True,
        timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"cryptography worker failed: {proc.stderr}")
    raw_map = json.loads(proc.stdout)

    results: dict[str, dict[str, object]] = {}
    for spec, _dp, _pp, _db in vectors:
        rec = raw_map[spec.vector_id]
        raw_status = rec["raw_status"]
        ber_permissive = False
        err = rec.get("error_detail")
        if raw_status == "ACCEPTED" and spec.expected_der_verdict == "REJECT":
            status = "BER_PERMISSIVE_ACCEPT"
            ber_permissive = True
            err = "cryptography accepted negative vector; NOT treated as DER canonicality proof."
        else:
            status = raw_status
        results[spec.vector_id] = {
            "parser_name": "cryptography_rust_asn1",
            "parser_version": crypto_ver,
            "status": status,
            "san_types": rec.get("san_types", []),
            "ber_permissive_not_der_proof": ber_permissive,
            "error_detail": err,
        }
    return results


def _offline_placeholder(parser_name: str) -> dict[str, object]:
    return {
        "parser_name": parser_name,
        "parser_version": "NOT_PERFORMED_OFFLINE_MODE",
        "status": "NOT_PERFORMED_OFFLINE_MODE",
        "ber_permissive_not_der_proof": False,
        "error_detail": "Skipped in offline mode (INDEPENDENT_CROSS_VALIDATION=NOT_PERFORMED).",
    }


def _eval_hrai(spec: CrossValVectorSpec, pem_p: Path, der_bytes: bytes) -> dict[str, object]:
    """Authoritative strict ITU-T X.690 / RFC 5280 DER parser evaluation (fail-closed, zero partial metadata)."""
    cache_key = (hashlib.sha256(der_bytes).hexdigest(), len(der_bytes))
    pem_text = pem_p.read_text(encoding="utf-8")
    try:
        meta = parse_x509_certificate_metadata_der(der_bytes)
        pem_meta = parse_x509_certificate_metadata(pem_text)
        matched_expected = spec.expected_der_verdict == "ACCEPT" and pem_meta is not None
        return {
            "parser_name": "hrAI_x509_metadata",
            "parser_version": ESIGN_5070_VERSION,
            "status": "ACCEPTED",
            "matches_expected_der": matched_expected,
            "signer_common_name": meta.signer_common_name,
            "san_dns_names": list(meta.san_dns_names),
            "zero_partial_metadata": None,
            "cache_unpolluted": None,
            "error_detail": None,
        }
    except DerParseError as exc:
        cache_unpolluted = cache_key not in x509_mod._METADATA_CACHE
        pem_meta = parse_x509_certificate_metadata(pem_text)
        insp = inspect_signer_certificate_x509(pem_text, validation_time_utc=VALIDATION_TIME_UTC)
        zero_partial = (
            pem_meta is None
            and not insp.valid_x509
            and insp.subject == ""
            and insp.issuer == ""
            and insp.serial_number == ""
            and insp.not_before_utc == ""
            and insp.not_after_utc == ""
            and insp.cert_sha256 == ""
            and insp.signature_algorithm == ""
            and insp.public_key_algorithm == ""
            and not insp.qc_compliance
            and not insp.qc_sscd
            and insp.signer_common_name is None
        )
        cache_unpolluted = cache_unpolluted and (cache_key not in x509_mod._METADATA_CACHE)
        matched_expected = spec.expected_der_verdict == "REJECT" and zero_partial and cache_unpolluted
        return {
            "parser_name": "hrAI_x509_metadata",
            "parser_version": ESIGN_5070_VERSION,
            "status": "REJECTED",
            "matches_expected_der": matched_expected,
            "zero_partial_metadata": zero_partial,
            "cache_unpolluted": cache_unpolluted,
            "error_detail": str(exc),
        }


def _summarize_parser(rows: list[dict[str, object]], key: str) -> dict[str, int]:
    """Summarize per-parser outcomes with zero conflation across distinct statuses."""
    counts = {
        "positive_accepted": 0,
        "positive_rejected": 0,
        "positive_asn1_failed": 0,
        "positive_pem_der_mismatch": 0,
        "positive_non_canonical_roundtrip": 0,
        "positive_unsupported": 0,
        "negative_rejected": 0,
        "negative_ber_permissive_accepted": 0,
        "negative_unsupported": 0,
        "not_installed": 0,
        "not_performed_offline": 0,
    }
    for row in rows:
        exp = row["expected_der_verdict"]
        st = row["parsers"][key]["status"]
        if st == "NOT_INSTALLED":
            counts["not_installed"] += 1
        elif st == "NOT_PERFORMED_OFFLINE_MODE":
            counts["not_performed_offline"] += 1
        elif exp == "ACCEPT":
            if st == "ACCEPTED":
                counts["positive_accepted"] += 1
            elif st == "UNSUPPORTED_BY_PARSER":
                counts["positive_unsupported"] += 1
            elif st == "ASN1_PARSE_FAILED":
                counts["positive_asn1_failed"] += 1
            elif st == "PEM_DER_ASN1_MISMATCH":
                counts["positive_pem_der_mismatch"] += 1
            elif st == "NON_CANONICAL_ROUNDTRIP":
                counts["positive_non_canonical_roundtrip"] += 1
            else:
                counts["positive_rejected"] += 1
        else:
            if st == "REJECTED":
                counts["negative_rejected"] += 1
            elif st == "BER_PERMISSIVE_ACCEPT":
                counts["negative_ber_permissive_accepted"] += 1
            elif st == "UNSUPPORTED_BY_PARSER":
                counts["negative_unsupported"] += 1
            else:
                counts["negative_ber_permissive_accepted"] += 1
    return counts


def _evaluate_run_policy(
    *,
    mode: str,
    rows: list[dict[str, object]],
    parser_versions: dict[str, str],
    per_parser_counts: dict[str, dict[str, int]],
    min_external_positive_confirmed: int | None = None,
    min_external_negative_confirmed: int | None = None,
) -> dict[str, object]:
    """Evaluate `strict` or `offline` mode gates and compute explicit CI/audit verdict + exit code."""
    positive_count = sum(1 for r in rows if r["expected_der_verdict"] == "ACCEPT")
    negative_count = sum(1 for r in rows if r["expected_der_verdict"] == "REJECT")
    hrai_counts = per_parser_counts["hrai"]
    hrai_all_matched = all(r["parsers"]["hrai"]["matches_expected_der"] for r in rows)

    ext_pos_confirmed = sum(
        1
        for r in rows
        if r["expected_der_verdict"] == "ACCEPT"
        and len(r["authoritative_der_canonicality_decision"]["strict_external_confirmations"]) >= 1
    )
    ext_neg_confirmed = sum(
        1
        for r in rows
        if r["expected_der_verdict"] == "REJECT"
        and len(r["authoritative_der_canonicality_decision"]["strict_external_confirmations"]) >= 1
    )

    if mode == "offline":
        failure_reasons: list[str] = []
        if not hrai_all_matched:
            failure_reasons.append(
                f"Authoritative hrAI strict DER check failed "
                f"(pos={hrai_counts['positive_accepted']}/{positive_count}, "
                f"neg={hrai_counts['negative_rejected']}/{negative_count})."
            )
        exit_code = 0 if not failure_reasons else 1
        return {
            "mode": "offline",
            "independent_cross_validation": "NOT_PERFORMED",
            "independent_cross_validation_tag": "INDEPENDENT_CROSS_VALIDATION=NOT_PERFORMED",
            "parser_versions": parser_versions,
            "missing_parsers": [],
            "verification_thresholds": {
                "hrai_positive_accepted": {
                    "required": positive_count,
                    "observed": hrai_counts["positive_accepted"],
                    "passed": hrai_counts["positive_accepted"] == positive_count,
                },
                "hrai_negative_rejected_zero_partial_meta": {
                    "required": negative_count,
                    "observed": hrai_counts["negative_rejected"],
                    "passed": hrai_all_matched and hrai_counts["negative_rejected"] == negative_count,
                },
                "external_independent_cross_validation": {
                    "required": "NOT_PERFORMED_IN_OFFLINE_MODE",
                    "observed": "NOT_PERFORMED",
                    "passed": None,
                },
            },
            "exit_code": exit_code,
            "failure_reasons": failure_reasons,
        }

    # --- `strict` mode ---
    missing_parsers = [
        pname for pname in REQUIRED_STRICT_PARSERS if parser_versions.get(pname) == "NOT_INSTALLED"
    ]
    req_ext_pos = (
        min_external_positive_confirmed
        if min_external_positive_confirmed is not None
        else math.ceil(DEFAULT_MIN_EXTERNAL_POSITIVE_RATIO * positive_count)
    )
    req_ext_neg = (
        min_external_negative_confirmed
        if min_external_negative_confirmed is not None
        else math.ceil(DEFAULT_MIN_EXTERNAL_NEGATIVE_RATIO * negative_count)
    )

    ext_positive_errors = 0
    for ext_key in ("openssl", "pyasn1_rfc5280", "cryptography"):
        pc = per_parser_counts[ext_key]
        ext_positive_errors += (
            pc["positive_rejected"]
            + pc["positive_asn1_failed"]
            + pc["positive_pem_der_mismatch"]
            + pc["positive_non_canonical_roundtrip"]
        )

    thresholds = {
        "all_required_parsers_available": {
            "required": list(REQUIRED_STRICT_PARSERS),
            "missing": missing_parsers,
            "passed": len(missing_parsers) == 0,
        },
        "hrai_positive_accepted": {
            "required": positive_count,
            "observed": hrai_counts["positive_accepted"],
            "passed": hrai_counts["positive_accepted"] == positive_count,
        },
        "hrai_negative_rejected_zero_partial_meta": {
            "required": negative_count,
            "observed": hrai_counts["negative_rejected"],
            "passed": hrai_all_matched and hrai_counts["negative_rejected"] == negative_count,
        },
        "external_zero_positive_parse_errors": {
            "required": 0,
            "observed": ext_positive_errors,
            "passed": ext_positive_errors == 0,
        },
        "external_positive_strict_confirmed": {
            "required": req_ext_pos,
            "observed": ext_pos_confirmed,
            "passed": ext_pos_confirmed >= req_ext_pos,
        },
        "external_negative_strict_confirmed": {
            "required": req_ext_neg,
            "observed": ext_neg_confirmed,
            "passed": ext_neg_confirmed >= req_ext_neg,
        },
    }

    failure_reasons = []
    if missing_parsers:
        failure_reasons.append(f"Strict mode requires all parsers installed; missing: {missing_parsers}")
    if not hrai_all_matched:
        failure_reasons.append(
            f"Authoritative hrAI strict DER check failed "
            f"(pos={hrai_counts['positive_accepted']}/{positive_count}, "
            f"neg={hrai_counts['negative_rejected']}/{negative_count})."
        )
    if ext_positive_errors > 0:
        failure_reasons.append(
            f"External parser reported {ext_positive_errors} positive vector parse/ASN.1/roundtrip error(s)."
        )
    if ext_pos_confirmed < req_ext_pos:
        failure_reasons.append(
            f"External positive strict confirmation below threshold ({ext_pos_confirmed} < {req_ext_pos})."
        )
    if ext_neg_confirmed < req_ext_neg:
        failure_reasons.append(
            f"External negative strict confirmation below threshold ({ext_neg_confirmed} < {req_ext_neg})."
        )

    if missing_parsers:
        icv_status = "FAILED_MISSING_PARSERS"
        exit_code = 2
    elif failure_reasons:
        icv_status = "FAILED_THRESHOLD"
        exit_code = 1
    else:
        icv_status = "PASSED"
        exit_code = 0

    return {
        "mode": "strict",
        "independent_cross_validation": icv_status,
        "independent_cross_validation_tag": f"INDEPENDENT_CROSS_VALIDATION={icv_status}",
        "parser_versions": parser_versions,
        "missing_parsers": missing_parsers,
        "verification_thresholds": thresholds,
        "exit_code": exit_code,
        "failure_reasons": failure_reasons,
    }


def run_cross_validation(
    fixtures_dir: Path = FIXTURES_DIR,
    *,
    mode: str = "strict",
    min_external_positive_confirmed: int | None = None,
    min_external_negative_confirmed: int | None = None,
) -> dict[str, object]:
    if mode not in ("strict", "offline"):
        raise ValueError(f"Unsupported cross-validation mode: {mode!r} (expected 'strict' or 'offline').")

    manifest, vectors = load_and_verify_fixtures(fixtures_dir)

    if mode == "offline":
        openssl_bin, openssl_ver = None, "NOT_PERFORMED_OFFLINE_MODE"
        pyasn1_ver = "NOT_PERFORMED_OFFLINE_MODE"
        crypto_ver = "NOT_PERFORMED_OFFLINE_MODE"
        pyasn1_results = {spec.vector_id: _offline_placeholder("pyasn1_rfc5280") for spec, *_ in vectors}
        crypto_results = {spec.vector_id: _offline_placeholder("cryptography_rust_asn1") for spec, *_ in vectors}
    else:
        openssl_bin, openssl_ver = _detect_openssl()
        pyasn1_py, pyasn1_ver = _find_python_with_module("pyasn1_modules")
        crypto_py, crypto_ver = _find_python_with_module("cryptography")
        pyasn1_results = _eval_pyasn1_batch(pyasn1_py, pyasn1_ver, vectors)
        crypto_results = _eval_cryptography_batch(crypto_py, crypto_ver, vectors)

    rows: list[dict[str, object]] = []
    for spec, der_p, pem_p, der_bytes in vectors:
        if mode == "offline":
            ossl_res = _offline_placeholder("openssl")
        else:
            ossl_res = _eval_openssl(openssl_bin, openssl_ver, spec, pem_p, der_p)
        pya_res = pyasn1_results[spec.vector_id]
        cry_res = crypto_results[spec.vector_id]
        hrai_res = _eval_hrai(spec, pem_p, der_bytes)

        # Independent strict agreement (excludes BER_PERMISSIVE_ACCEPT, UNSUPPORTED_BY_PARSER, NOT_INSTALLED, NOT_PERFORMED_OFFLINE_MODE)
        strict_external_confirmations: list[str] = []
        if mode == "strict":
            for pname, pres in (("openssl", ossl_res), ("pyasn1_rfc5280", pya_res), ("cryptography", cry_res)):
                if spec.expected_der_verdict == "ACCEPT" and pres["status"] == "ACCEPTED":
                    strict_external_confirmations.append(pname)
                elif spec.expected_der_verdict == "REJECT" and pres["status"] == "REJECTED":
                    strict_external_confirmations.append(pname)

        rows.append(
            {
                "vector_id": spec.vector_id,
                "category": spec.category,
                "general_name_type": spec.general_name_type,
                "description": spec.description,
                "expected_der_verdict": spec.expected_der_verdict,
                "der_file": der_p.name,
                "pem_file": pem_p.name,
                "der_sha256": hashlib.sha256(der_bytes).hexdigest(),
                "parsers": {
                    "openssl": ossl_res,
                    "pyasn1_rfc5280": pya_res,
                    "cryptography": cry_res,
                    "hrai": hrai_res,
                },
                "authoritative_der_canonicality_decision": {
                    "authority": "hrAI_x509_metadata",
                    "verdict": hrai_res["status"],
                    "matches_expected_der": hrai_res["matches_expected_der"],
                    "strict_external_confirmations": strict_external_confirmations,
                },
            }
        )

    positive_count = sum(1 for r in rows if r["expected_der_verdict"] == "ACCEPT")
    negative_count = sum(1 for r in rows if r["expected_der_verdict"] == "REJECT")
    hrai_all_matched = all(r["parsers"]["hrai"]["matches_expected_der"] for r in rows)
    external_confirmed_count = sum(
        1 for r in rows if len(r["authoritative_der_canonicality_decision"]["strict_external_confirmations"]) >= 1
    )

    parser_versions = {
        "openssl": openssl_ver,
        "pyasn1_rfc5280": pyasn1_ver,
        "cryptography": crypto_ver,
        "hrai": ESIGN_5070_VERSION,
    }
    per_parser_counts = {
        "openssl": _summarize_parser(rows, "openssl"),
        "pyasn1_rfc5280": _summarize_parser(rows, "pyasn1_rfc5280"),
        "cryptography": _summarize_parser(rows, "cryptography"),
        "hrai": _summarize_parser(rows, "hrai"),
    }
    ci_audit = _evaluate_run_policy(
        mode=mode,
        rows=rows,
        parser_versions=parser_versions,
        per_parser_counts=per_parser_counts,
        min_external_positive_confirmed=min_external_positive_confirmed,
        min_external_negative_confirmed=min_external_negative_confirmed,
    )

    return {
        "tool": "hrAI @HukukSGK Independent X.509 / ASN.1 DER Cross-Validator",
        "schema_version": ESIGN_5070_VERSION,
        "product_brand": "hrAI",
        "specialist_agent": "@HukukSGK",
        "mode": mode,
        "independent_cross_validation": ci_audit["independent_cross_validation"],
        "independent_cross_validation_tag": ci_audit["independent_cross_validation_tag"],
        "policy": {
            "independent_parser_evaluation": True,
            "ber_permissive_accept_never_der_proof": True,
            "unsupported_never_pass": True,
            "openssl_positive_requires_pem_and_der_asn1_match": True,
            "authoritative_der_canonicality_parser": "hrAI_x509_metadata",
            "read_only_metadata_not_5070_or_signature_proof": True,
        },
        "ci_audit": ci_audit,
        "parser_versions": parser_versions,
        "fixture_integrity": {
            "fixtures_dir": str(fixtures_dir.relative_to(PROJECT_ROOT)),
            "manifest_verified": True,
            "private_keys_stored": manifest["private_keys_stored"],
            "base_public_cert_sha256": manifest["base_public_cert_sha256"],
        },
        "summary": {
            "total_vectors": len(rows),
            "positive_vectors": positive_count,
            "negative_vectors": negative_count,
            "authoritative_hrai_strict_der_all_matched": hrai_all_matched,
            "vectors_confirmed_by_at_least_one_strict_external_parser": external_confirmed_count,
            "per_parser_counts": per_parser_counts,
        },
        "vectors": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run single-command independent X.509 / ASN.1 DER cross-validation (strict or offline mode)."
    )
    parser.add_argument(
        "--mode",
        choices=("strict", "offline"),
        default="strict",
        help="Execution mode: 'strict' (all 4 parsers required + thresholds) or 'offline' (hrAI-only, INDEPENDENT_CROSS_VALIDATION=NOT_PERFORMED).",
    )
    parser.add_argument("--output", "-o", type=Path, default=None, help="Optional path to write full JSON report.")
    parser.add_argument("--summary-only", action="store_true", help="Print only summary & CI audit metadata JSON.")
    parser.add_argument("--min-ext-pos", type=int, default=None, help="Optional strict-mode positive external confirmation threshold override.")
    parser.add_argument("--min-ext-neg", type=int, default=None, help="Optional strict-mode negative external confirmation threshold override.")
    args = parser.parse_args(argv)

    report = run_cross_validation(
        mode=args.mode,
        min_external_positive_confirmed=args.min_ext_pos,
        min_external_negative_confirmed=args.min_ext_neg,
    )
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    out_obj = {k: v for k, v in report.items() if k != "vectors"} if args.summary_only else report
    print(json.dumps(out_obj, indent=2, ensure_ascii=False))
    return int(report["ci_audit"]["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
