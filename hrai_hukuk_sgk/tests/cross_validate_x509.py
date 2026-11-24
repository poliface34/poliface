"""Single-Command Independent X.509 / ASN.1 DER Cross-Validation Tool (hrAI @HukukSGK v1.0.5.1).

Usage (from project root `hrai_hukuk_sgk/`):
    python3 -m tests.cross_validate_x509
    python3 -m tests.cross_validate_x509 --output /tmp/x509_crossval_report.json
    python3 -m tests.cross_validate_x509 --summary-only

Evaluates fixed deterministic public X.509 DER/PEM vectors independently across:
  1. OpenSSL CLI (`openssl x509 -noout -text`, `openssl asn1parse -inform PEM/DER -i`)
  2. `pyasn1` + `pyasn1_modules` (`rfc5280.Certificate` + `rfc5280.GeneralNames` + DER round-trip)
  3. `cryptography` (Rust `rust-asn1` / `cryptography.x509`)
  4. `hrAI` (`engine.esign5070.x509_metadata` — AUTHORITATIVE strict DER canonicality verdict)

Audit rules enforced:
  - Every parser's output is evaluated and reported independently with exact version & error detail.
  - BER-permissive acceptances by OpenSSL or `pyasn1` on negative DER/P-C-bit vectors are explicitly
    labeled `BER_PERMISSIVE_ACCEPT` (`ber_permissive_not_der_proof: true`) and are NEVER counted as
    DER validity proof.
  - Unsupported GeneralName types (e.g., OpenSSL `<unsupported>` or Rust `UnsupportedGeneralNameType`)
    are explicitly labeled `UNSUPPORTED_BY_PARSER` and NEVER counted as PASS.
  - Authoritative strict DER canonicality verdict relies strictly on `hrAI`'s fail-closed DER parser
    with verified zero partial metadata and zero `_METADATA_CACHE` pollution on rejected vectors.
  - Vector counts (total, positive, negative, and per-parser accepted/rejected/unsupported/BER-permissive)
    are computed automatically from the verified vector corpus.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
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
    probe = (
        f"import {module_name}; "
        f"print(getattr({module_name}, '__version__', 'installed'))"
    )
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
            "ber_permissive_not_der_proof": False,
            "error_detail": "openssl binary not found",
        }
    res_text = subprocess.run(
        [openssl_bin, "x509", "-in", str(pem_p), "-noout", "-text"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
    )
    san_line = ""
    if res_text.returncode == 0:
        lines = res_text.stdout.splitlines()
        for i, ln in enumerate(lines):
            if "X509v3 Subject Alternative Name:" in ln and i + 1 < len(lines):
                san_line = lines[i + 1].strip()
                break
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
    pem_der_match = res_pem_asn1.returncode == 0 and res_der_asn1.returncode == 0 and (
        res_pem_asn1.stdout == res_der_asn1.stdout
    )

    known_prefixes = ("othername:", "DNS:", "email:", "URI:", "IP Address:", "DirName:", "Registered ID:")
    ber_permissive = False
    error_detail: str | None = None
    if res_text.returncode != 0:
        status = "REJECTED"
        error_detail = (res_text.stderr or res_text.stdout).strip()[:200]
    elif "<unsupported>" in san_line:
        status = "UNSUPPORTED_BY_PARSER"
        error_detail = f"OpenSSL printed unsupported marker: {san_line}"
    elif not san_line or not any(san_line.startswith(pfx) for pfx in known_prefixes):
        # OpenSSL d2i_GENERAL_NAMES failed and fell back to raw ASCII/hex dump (e.g., "0...raw", "0....")
        status = "REJECTED"
        error_detail = f"OpenSSL failed GeneralNames decode (raw fallback output: {san_line!r})"
    else:
        if spec.expected_der_verdict == "REJECT":
            status = "BER_PERMISSIVE_ACCEPT"
            ber_permissive = True
            error_detail = (
                f"OpenSSL leniently accepted non-DER/BER encoding ({san_line!r}); "
                "NOT treated as DER canonicality proof."
            )
        else:
            status = "ACCEPTED"

    return {
        "parser_name": "openssl",
        "parser_version": openssl_ver,
        "status": status,
        "san_text": san_line,
        "x509_text_rc": res_text.returncode,
        "pem_asn1_rc": res_pem_asn1.returncode,
        "der_asn1_rc": res_der_asn1.returncode,
        "pem_der_asn1_match": pem_der_match,
        "ber_permissive_not_der_proof": ber_permissive,
        "error_detail": error_detail,
    }


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
    exp = item["expected_der_verdict"]
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
            "expected_der_verdict": spec.expected_der_verdict,
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
    counts = {
        "positive_accepted": 0,
        "positive_rejected": 0,
        "positive_unsupported": 0,
        "negative_rejected": 0,
        "negative_ber_permissive_accepted": 0,
        "negative_unsupported": 0,
        "not_installed": 0,
    }
    for row in rows:
        exp = row["expected_der_verdict"]
        st = row["parsers"][key]["status"]
        if st == "NOT_INSTALLED":
            counts["not_installed"] += 1
        elif exp == "ACCEPT":
            if st == "ACCEPTED":
                counts["positive_accepted"] += 1
            elif st == "UNSUPPORTED_BY_PARSER":
                counts["positive_unsupported"] += 1
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


def run_cross_validation(fixtures_dir: Path = FIXTURES_DIR) -> dict[str, object]:
    manifest, vectors = load_and_verify_fixtures(fixtures_dir)
    openssl_bin, openssl_ver = _detect_openssl()
    pyasn1_py, pyasn1_ver = _find_python_with_module("pyasn1_modules")
    crypto_py, crypto_ver = _find_python_with_module("cryptography")

    pyasn1_results = _eval_pyasn1_batch(pyasn1_py, pyasn1_ver, vectors)
    crypto_results = _eval_cryptography_batch(crypto_py, crypto_ver, vectors)

    rows: list[dict[str, object]] = []
    for spec, der_p, pem_p, der_bytes in vectors:
        ossl_res = _eval_openssl(openssl_bin, openssl_ver, spec, pem_p, der_p)
        pya_res = pyasn1_results[spec.vector_id]
        cry_res = crypto_results[spec.vector_id]
        hrai_res = _eval_hrai(spec, pem_p, der_bytes)

        # Independent strict agreement (excludes BER_PERMISSIVE_ACCEPT & UNSUPPORTED_BY_PARSER!)
        strict_external_confirmations: list[str] = []
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

    return {
        "tool": "hrAI @HukukSGK Independent X.509 / ASN.1 DER Cross-Validator",
        "schema_version": ESIGN_5070_VERSION,
        "product_brand": "hrAI",
        "specialist_agent": "@HukukSGK",
        "policy": {
            "independent_parser_evaluation": True,
            "ber_permissive_accept_never_der_proof": True,
            "unsupported_never_pass": True,
            "authoritative_der_canonicality_parser": "hrAI_x509_metadata",
            "read_only_metadata_not_5070_or_signature_proof": True,
        },
        "parser_versions": {
            "openssl": openssl_ver,
            "pyasn1_rfc5280": pyasn1_ver,
            "cryptography": crypto_ver,
            "hrai": ESIGN_5070_VERSION,
        },
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
            "per_parser_counts": {
                "openssl": _summarize_parser(rows, "openssl"),
                "pyasn1_rfc5280": _summarize_parser(rows, "pyasn1_rfc5280"),
                "cryptography": _summarize_parser(rows, "cryptography"),
                "hrai": _summarize_parser(rows, "hrai"),
            },
        },
        "vectors": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run single-command independent X.509 / ASN.1 DER cross-validation (OpenSSL, pyasn1, cryptography, hrAI)."
    )
    parser.add_argument("--output", "-o", type=Path, default=None, help="Optional path to write full JSON report.")
    parser.add_argument("--summary-only", action="store_true", help="Print only summary & parser versions JSON.")
    args = parser.parse_args(argv)

    report = run_cross_validation()
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    out_obj = {k: v for k, v in report.items() if k != "vectors"} if args.summary_only else report
    print(json.dumps(out_obj, indent=2, ensure_ascii=False))
    return 0 if report["summary"]["authoritative_hrai_strict_der_all_matched"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
