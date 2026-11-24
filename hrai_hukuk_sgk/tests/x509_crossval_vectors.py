"""Deterministic X.509 DER/PEM Cross-Validation Vector Corpus for hrAI @HukukSGK v1.0.5.1.

Stores and verifies fixed PUBLIC-ONLY X.509 v3 certificate vectors under
`tests/fixtures/x509_crossval/` (zero private keys anywhere in repository) alongside the
deterministic ASN.1 DER payload builders for all 9 RFC 5280 GeneralName alternatives and
negative P/C-bit, ASN.1 inner-schema, legacy string, and DER canonicality vectors.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from engine.esign5070 import x509_metadata as x509_mod

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "x509_crossval"
MANIFEST_PATH = FIXTURES_DIR / "manifest.json"
OID_SAN_BYTES = bytes([0x55, 0x1D, 0x11])  # 2.5.29.17 SubjectAltName
UPN_OID_BYTES = bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03])  # 1.3.6.1.4.1.311.20.2.3


@dataclass(frozen=True)
class CrossValVectorSpec:
    vector_id: str
    category: str
    general_name_type: str
    expected_der_verdict: str  # "ACCEPT" or "REJECT"
    description: str
    san_der: bytes
    signed_by_openssl: bool


def encode_der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: bytes, val: bytes) -> bytes:
    return tag + encode_der_len(len(val)) + val


def der_to_pem(der_bytes: bytes) -> str:
    b64 = base64.b64encode(der_bytes).decode("ascii")
    body = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"


def pem_to_der(pem_text: str) -> bytes:
    lines = [ln.strip() for ln in pem_text.strip().splitlines() if not ln.startswith("-----")]
    return base64.b64decode("".join(lines).encode("ascii"))


def rebuild_cert_with_san(base_cert_der: bytes, san_val_der: bytes) -> bytes:
    """Deterministically append a SubjectAltName (2.5.29.17) extension to a base X.509 DER certificate."""
    _, c_vs, c_ve, _ = x509_mod._read_tlv(base_cert_der, 0, len(base_cert_der))
    cert_spans = x509_mod._iter_children_with_spans(base_cert_der, c_vs, c_ve)
    _, _, tbs_vs, tbs_ve, _ = cert_spans[0]
    sigalg_s, _, _, _, sigalg_nxt = cert_spans[1]
    sigval_s, _, _, _, sigval_nxt = cert_spans[2]
    tbs_spans = x509_mod._iter_children_with_spans(base_cert_der, tbs_vs, tbs_ve)
    new_ext = tlv(b"\x30", tlv(b"\x06", OID_SAN_BYTES) + tlv(b"\x04", san_val_der))
    parts: list[bytes] = []
    added = False
    for fs, ft, fvs, fve, fnxt in tbs_spans:
        if ft == 0xA3:
            _, es_vs, es_ve, _ = x509_mod._read_tlv(base_cert_der, fvs, fve)
            parts.append(tlv(b"\xa3", tlv(b"\x30", base_cert_der[es_vs:es_ve] + new_ext)))
            added = True
        else:
            parts.append(base_cert_der[fs:fnxt])
    if not added:
        parts.append(tlv(b"\xa3", tlv(b"\x30", new_ext)))
    new_tbs = tlv(b"\x30", b"".join(parts))
    return tlv(b"\x30", new_tbs + base_cert_der[sigalg_s:sigalg_nxt] + base_cert_der[sigval_s:sigval_nxt])


def build_deterministic_vector_specs() -> tuple[CrossValVectorSpec, ...]:
    """Return the complete deterministic corpus of positive and negative RFC 5280 GeneralName vectors."""
    cn_oid = bytes([0x55, 0x04, 0x03])
    c_oid = bytes([0x55, 0x04, 0x06])

    valid_other = tlv(b"\xa0", tlv(b"\x06", UPN_OID_BYTES) + tlv(b"\xa0", tlv(b"\x0c", b"uzman@insenai.com.tr")))
    valid_bsa = tlv(
        b"\x30",
        tlv(b"\x61", tlv(b"\x13", b"TR"))
        + tlv(b"\x62", tlv(b"\x13", b"hrAI"))
        + tlv(b"\x83", b"hrAI Insenai")
        + tlv(b"\xa5", tlv(b"\x80", b"Yilmaz") + tlv(b"\x81", b"Ali"))
        + tlv(b"\xa6", tlv(b"\x13", b"HukukSGK")),
    )
    valid_bdda = tlv(b"\x30", tlv(b"\x30", tlv(b"\x13", b"DEPT") + tlv(b"\x13", b"HR")))
    ea1 = tlv(b"\x30", tlv(b"\x80", b"\x01") + tlv(b"\xa1", tlv(b"\x13", b"Alpha")))
    ea2 = tlv(b"\x30", tlv(b"\x80", b"\x02") + tlv(b"\xa1", tlv(b"\x13", b"Bravo")))
    assert ea1 < ea2
    valid_x400 = tlv(b"\xa3", valid_bsa + valid_bdda + tlv(b"\x31", ea1 + ea2))
    valid_edi = tlv(
        b"\xa5",
        tlv(b"\xa0", tlv(b"\x0c", "hrAI İnsenai".encode("utf-8"))) + tlv(b"\xa1", tlv(b"\x13", b"HukukSGK-EDI")),
    )
    valid_dir = tlv(
        b"\xa4",
        tlv(
            b"\x30",
            tlv(b"\x31", tlv(b"\x30", tlv(b"\x06", c_oid) + tlv(b"\x13", b"TR")))
            + tlv(b"\x31", tlv(b"\x30", tlv(b"\x06", cn_oid) + tlv(b"\x0c", b"hrAI DirName"))),
        ),
    )
    valid_dns = tlv(b"\x82", b"www.insenai.com.tr")
    valid_email = tlv(b"\x81", b"hukuk@insenai.com.tr")
    valid_uri = tlv(b"\x86", b"https://www.insenai.com.tr")
    valid_ips = tlv(b"\x87", bytes([192, 0, 2, 10])) + tlv(
        b"\x87", bytes([0x20, 0x01, 0x0D, 0xB8] + [0] * 11 + [1])
    )
    valid_rid = tlv(b"\x88", bytes([0x2A, 0x03, 0x04, 0x05]))

    return (
        # --- 9 Positive RFC 5280 GeneralName vectors (OpenSSL 3 signed public certs) ---
        CrossValVectorSpec(
            vector_id="01_valid_otherName",
            category="positive_general_name",
            general_name_type="otherName [0] (0xA0)",
            expected_der_verdict="ACCEPT",
            description="Valid RFC 5280 OtherName (UPN OID + [0] EXPLICIT UTF8String)",
            san_der=tlv(b"\x30", valid_other),
            signed_by_openssl=True,
        ),
        CrossValVectorSpec(
            vector_id="02_valid_x400Address",
            category="positive_general_name",
            general_name_type="x400Address [3] (0xA3)",
            expected_der_verdict="ACCEPT",
            description="Valid RFC 5280 ORAddress (BSA + PersonalName SET + BDDA + sorted ExtensionAttributes SET OF)",
            san_der=tlv(b"\x30", valid_x400),
            signed_by_openssl=True,
        ),
        CrossValVectorSpec(
            vector_id="03_valid_ediPartyName",
            category="positive_general_name",
            general_name_type="ediPartyName [5] (0xA5)",
            expected_der_verdict="ACCEPT",
            description="Valid RFC 5280 EDIPartyName (nameAssigner [0] EXPLICIT UTF8String + partyName [1] EXPLICIT PrintableString)",
            san_der=tlv(b"\x30", valid_edi),
            signed_by_openssl=True,
        ),
        CrossValVectorSpec(
            vector_id="04_valid_directoryName",
            category="positive_general_name",
            general_name_type="directoryName [4] (0xA4)",
            expected_der_verdict="ACCEPT",
            description="Valid RFC 5280 directoryName ([4] EXPLICIT Name with canonical RDNs)",
            san_der=tlv(b"\x30", valid_dir),
            signed_by_openssl=True,
        ),
        CrossValVectorSpec(
            vector_id="05_valid_dNSName",
            category="positive_general_name",
            general_name_type="dNSName [2] (0x82)",
            expected_der_verdict="ACCEPT",
            description="Valid RFC 5280 dNSName (www.insenai.com.tr)",
            san_der=tlv(b"\x30", valid_dns),
            signed_by_openssl=True,
        ),
        CrossValVectorSpec(
            vector_id="06_valid_rfc822Name",
            category="positive_general_name",
            general_name_type="rfc822Name [1] (0x81)",
            expected_der_verdict="ACCEPT",
            description="Valid unquoted dot-atom rfc822Name (hukuk@insenai.com.tr)",
            san_der=tlv(b"\x30", valid_email),
            signed_by_openssl=True,
        ),
        CrossValVectorSpec(
            vector_id="07_valid_URI",
            category="positive_general_name",
            general_name_type="uniformResourceIdentifier [6] (0x86)",
            expected_der_verdict="ACCEPT",
            description="Valid absolute IA5String URI (https://www.insenai.com.tr)",
            san_der=tlv(b"\x30", valid_uri),
            signed_by_openssl=True,
        ),
        CrossValVectorSpec(
            vector_id="08_valid_IPv4_IPv6",
            category="positive_general_name",
            general_name_type="iPAddress [7] (0x87)",
            expected_der_verdict="ACCEPT",
            description="Valid 4-octet IPv4 (192.0.2.10) + 16-octet IPv6 (2001:db8::1) iPAddress entries",
            san_der=tlv(b"\x30", valid_ips),
            signed_by_openssl=True,
        ),
        CrossValVectorSpec(
            vector_id="09_valid_registeredID",
            category="positive_general_name",
            general_name_type="registeredID [8] (0x88)",
            expected_der_verdict="ACCEPT",
            description="Valid DER OID registeredID (1.2.3.4.5)",
            san_der=tlv(b"\x30", valid_rid),
            signed_by_openssl=True,
        ),
        # --- 13 Negative DER / P-C-bit / ASN.1 inner-schema / legacy-string vectors ---
        CrossValVectorSpec(
            vector_id="10_bad_pc_prim_otherName_0x80",
            category="negative_pc_bit",
            general_name_type="otherName [0] primitive 0x80",
            expected_der_verdict="REJECT",
            description="Primitive 0x80 encoding of constructed-only otherName [0]",
            san_der=tlv(b"\x30", tlv(b"\x80", b"raw")),
            signed_by_openssl=False,
        ),
        CrossValVectorSpec(
            vector_id="11_bad_pc_prim_x400_0x83",
            category="negative_pc_bit",
            general_name_type="x400Address [3] primitive 0x83",
            expected_der_verdict="REJECT",
            description="Primitive 0x83 encoding of constructed-only x400Address [3]",
            san_der=tlv(b"\x30", tlv(b"\x83", b"raw")),
            signed_by_openssl=False,
        ),
        CrossValVectorSpec(
            vector_id="12_bad_pc_prim_dirName_0x84",
            category="negative_pc_bit",
            general_name_type="directoryName [4] primitive 0x84",
            expected_der_verdict="REJECT",
            description="Primitive 0x84 encoding of EXPLICIT constructed directoryName [4]",
            san_der=tlv(b"\x30", tlv(b"\x84", b"raw")),
            signed_by_openssl=False,
        ),
        CrossValVectorSpec(
            vector_id="13_bad_pc_prim_edi_0x85",
            category="negative_pc_bit",
            general_name_type="ediPartyName [5] primitive 0x85",
            expected_der_verdict="REJECT",
            description="Primitive 0x85 encoding of constructed-only ediPartyName [5]",
            san_der=tlv(b"\x30", tlv(b"\x85", b"raw")),
            signed_by_openssl=False,
        ),
        CrossValVectorSpec(
            vector_id="14_bad_pc_constr_dns_0xA2",
            category="negative_pc_bit",
            general_name_type="dNSName [2] constructed 0xA2",
            expected_der_verdict="REJECT",
            description="Constructed 0xA2 encoding of primitive-only IMPLICIT IA5String dNSName [2]",
            san_der=tlv(b"\x30", tlv(b"\xa2", tlv(b"\x16", b"www.insenai.com.tr"))),
            signed_by_openssl=False,
        ),
        CrossValVectorSpec(
            vector_id="15_bad_asn1_otherName_prim_val",
            category="negative_asn1_schema",
            general_name_type="otherName [0] (0xA0)",
            expected_der_verdict="REJECT",
            description="OtherName value encoded as primitive 0x80 instead of [0] EXPLICIT 0xA0",
            san_der=tlv(b"\x30", tlv(b"\xa0", tlv(b"\x06", UPN_OID_BYTES) + tlv(b"\x80", b"v"))),
            signed_by_openssl=False,
        ),
        CrossValVectorSpec(
            vector_id="16_bad_asn1_x400_missing_surname",
            category="negative_asn1_schema",
            general_name_type="x400Address [3] (0xA3)",
            expected_der_verdict="REJECT",
            description="ORAddress PersonalName SET missing mandatory surname [0] (0x80)",
            san_der=tlv(b"\x30", tlv(b"\xa3", tlv(b"\x30", tlv(b"\xa5", tlv(b"\x81", b"Ali"))))),
            signed_by_openssl=False,
        ),
        CrossValVectorSpec(
            vector_id="17_bad_asn1_x400_unsorted_ext_attrs",
            category="negative_der_canonicality",
            general_name_type="x400Address [3] (0xA3)",
            expected_der_verdict="REJECT",
            description="ORAddress ExtensionAttributes SET OF out of X.690 §11.6 ascending octet order",
            san_der=tlv(b"\x30", tlv(b"\xa3", tlv(b"\x30", tlv(b"\x83", b"hrAI")) + tlv(b"\x31", ea2 + ea1))),
            signed_by_openssl=False,
        ),
        CrossValVectorSpec(
            vector_id="18_bad_asn1_edi_missing_party",
            category="negative_asn1_schema",
            general_name_type="ediPartyName [5] (0xA5)",
            expected_der_verdict="REJECT",
            description="EDIPartyName missing mandatory partyName [1] (only nameAssigner [0] present)",
            san_der=tlv(b"\x30", tlv(b"\xa5", tlv(b"\xa0", tlv(b"\x13", b"Assigner")))),
            signed_by_openssl=False,
        ),
        CrossValVectorSpec(
            vector_id="19_bad_string_legacy_teletex_otherName",
            category="negative_legacy_string",
            general_name_type="otherName [0] (0xA0)",
            expected_der_verdict="REJECT",
            description="Unsupported legacy TeletexString (0x14) with T.61 accents inside OtherName value",
            san_der=tlv(b"\x30", tlv(b"\xa0", tlv(b"\x06", UPN_OID_BYTES) + tlv(b"\xa0", tlv(b"\x14", b"\xcbcagri")))),
            signed_by_openssl=False,
        ),
        CrossValVectorSpec(
            vector_id="20_bad_der_non_minimal_len",
            category="negative_der_canonicality",
            general_name_type="otherName [0] (0xA0)",
            expected_der_verdict="REJECT",
            description="Non-minimal DER long-form length (0x81 0x03 for length 3) inside OtherName value",
            san_der=tlv(b"\x30", tlv(b"\xa0", tlv(b"\x06", UPN_OID_BYTES) + tlv(b"\xa0", b"\x0c\x81\x03abc"))),
            signed_by_openssl=False,
        ),
        CrossValVectorSpec(
            vector_id="21_bad_der_indefinite_ber",
            category="negative_der_canonicality",
            general_name_type="otherName [0] (0xA0)",
            expected_der_verdict="REJECT",
            description="Indefinite BER length (0x80) inside OtherName value",
            san_der=tlv(b"\x30", tlv(b"\xa0", tlv(b"\x06", UPN_OID_BYTES) + tlv(b"\xa0", b"\x30\x80\x00\x00"))),
            signed_by_openssl=False,
        ),
        CrossValVectorSpec(
            vector_id="22_bad_der_non_minimal_high_tag",
            category="negative_der_canonicality",
            general_name_type="otherName [0] (0xA0)",
            expected_der_verdict="REJECT",
            description="Non-minimal high-tag-number encoding (0x1F 0x05 for tag 5 < 31) inside OtherName value",
            san_der=tlv(b"\x30", tlv(b"\xa0", tlv(b"\x06", UPN_OID_BYTES) + tlv(b"\xa0", b"\x1f\x05\x00"))),
            signed_by_openssl=False,
        ),
    )


def generate_public_fixtures(out_dir: Path = FIXTURES_DIR) -> dict[str, object]:
    """Generate fixed PUBLIC-ONLY DER/PEM certificate fixtures and manifest.json (ephemeral key destroyed immediately)."""
    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError("openssl binary is required to generate fixed public X.509 certificate fixtures.")
    out_dir.mkdir(parents=True, exist_ok=True)
    specs = build_deterministic_vector_specs()

    def _issue_public_cert(tdp: Path, key_p: Path, label: str, san_der: bytes | None) -> bytes:
        cnf = tdp / f"{label}.cnf"
        pem_p = tdp / f"{label}.pem"
        der_p = tdp / f"{label}.der"
        ext_lines = ["basicConstraints = critical,CA:FALSE", "keyUsage = critical,digitalSignature"]
        if san_der is not None:
            ext_lines.append(f"subjectAltName = DER:{san_der.hex()}")
        cnf.write_text(
            "\n".join(
                [
                    "[req]",
                    "distinguished_name = dn",
                    "x509_extensions = v3_ext",
                    "prompt = no",
                    "[dn]",
                    "C = TR",
                    "O = hrAI",
                    f"CN = CrossVal {label}",
                    "[v3_ext]",
                    *ext_lines,
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        subprocess.run(
            [openssl, "req", "-x509", "-new", "-key", str(key_p), "-config", str(cnf), "-days", "365", "-out", str(pem_p)],
            stdin=subprocess.DEVNULL,
            check=True,
            capture_output=True,
            timeout=30,
        )
        subprocess.run(
            [openssl, "x509", "-in", str(pem_p), "-outform", "DER", "-out", str(der_p)],
            stdin=subprocess.DEVNULL,
            check=True,
            capture_output=True,
            timeout=30,
        )
        return der_p.read_bytes()

    manifest_entries: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="hrai_gen_crossval_ephemeral_") as td:
        tdp = Path(td)
        ephemeral_key = tdp / "ephemeral_discarded.key"
        subprocess.run(
            [openssl, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ephemeral_key)],
            stdin=subprocess.DEVNULL,
            check=True,
            capture_output=True,
            timeout=30,
        )
        base_der = _issue_public_cert(tdp, ephemeral_key, "00_base", None)
        base_der_file = "00_base_public_cert.der"
        base_pem_file = "00_base_public_cert.pem"
        (out_dir / base_der_file).write_bytes(base_der)
        (out_dir / base_pem_file).write_text(der_to_pem(base_der), encoding="utf-8")

        for spec in specs:
            if spec.signed_by_openssl:
                cert_der = _issue_public_cert(tdp, ephemeral_key, spec.vector_id, spec.san_der)
            else:
                cert_der = rebuild_cert_with_san(base_der, spec.san_der)
            der_name = f"{spec.vector_id}.der"
            pem_name = f"{spec.vector_id}.pem"
            (out_dir / der_name).write_bytes(cert_der)
            (out_dir / pem_name).write_text(der_to_pem(cert_der), encoding="utf-8")
            manifest_entries.append(
                {
                    "vector_id": spec.vector_id,
                    "category": spec.category,
                    "general_name_type": spec.general_name_type,
                    "expected_der_verdict": spec.expected_der_verdict,
                    "description": spec.description,
                    "signed_by_openssl": spec.signed_by_openssl,
                    "der_file": der_name,
                    "pem_file": pem_name,
                    "der_sha256": hashlib.sha256(cert_der).hexdigest(),
                    "san_der_hex": spec.san_der.hex(),
                }
            )

    manifest = {
        "schema_version": "1.0.5.1",
        "product_brand": "hrAI",
        "specialist_agent": "@HukukSGK",
        "private_keys_stored": False,
        "base_public_cert_der_file": base_der_file,
        "base_public_cert_pem_file": base_pem_file,
        "base_public_cert_sha256": hashlib.sha256(base_der).hexdigest(),
        "vector_count": len(manifest_entries),
        "vectors": manifest_entries,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return manifest


def load_and_verify_fixtures(fixtures_dir: Path = FIXTURES_DIR) -> tuple[dict[str, object], list[tuple[CrossValVectorSpec, Path, Path, bytes]]]:
    """Load fixed DER/PEM certificate vectors and verify SHA-256, PEM/DER parity, and deterministic SAN payloads."""
    manifest_path = fixtures_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    specs_by_id = {s.vector_id: s for s in build_deterministic_vector_specs()}
    entries = manifest.get("vectors", [])
    if len(entries) != len(specs_by_id):
        raise AssertionError(f"Fixture manifest count ({len(entries)}) != deterministic spec count ({len(specs_by_id)})")

    base_der = (fixtures_dir / manifest["base_public_cert_der_file"]).read_bytes()
    if hashlib.sha256(base_der).hexdigest() != manifest["base_public_cert_sha256"]:
        raise AssertionError("Base public cert SHA-256 mismatch.")
    base_pem = (fixtures_dir / manifest["base_public_cert_pem_file"]).read_text(encoding="utf-8")
    if pem_to_der(base_pem) != base_der:
        raise AssertionError("Base public cert PEM/DER byte mismatch.")

    loaded: list[tuple[CrossValVectorSpec, Path, Path, bytes]] = []
    for entry in entries:
        vid = entry["vector_id"]
        spec = specs_by_id[vid]
        if entry["san_der_hex"] != spec.san_der.hex():
            raise AssertionError(f"Vector {vid} SAN DER hex diverges from deterministic spec.")
        der_p = fixtures_dir / entry["der_file"]
        pem_p = fixtures_dir / entry["pem_file"]
        der_bytes = der_p.read_bytes()
        if hashlib.sha256(der_bytes).hexdigest() != entry["der_sha256"]:
            raise AssertionError(f"Vector {vid} DER SHA-256 mismatch.")
        if pem_to_der(pem_p.read_text(encoding="utf-8")) != der_bytes:
            raise AssertionError(f"Vector {vid} PEM/DER byte mismatch.")
        if not spec.signed_by_openssl:
            expected_mut = rebuild_cert_with_san(base_der, spec.san_der)
            if der_bytes != expected_mut:
                raise AssertionError(f"Negative vector {vid} DER does not match deterministic mutation of base cert.")
        loaded.append((spec, der_p, pem_p, der_bytes))
    return manifest, loaded


if __name__ == "__main__":
    m = generate_public_fixtures()
    print(f"Generated {m['vector_count']} fixed public X.509 cross-validation vectors in {FIXTURES_DIR}")
