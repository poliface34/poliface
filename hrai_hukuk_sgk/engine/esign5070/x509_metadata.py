"""Pure-Python Strict ITU-T X.690 / RFC 5280 ASN.1 DER X.509 Certificate Metadata Reader (hrAI @HukukSGK v1.0.5.1).

STRICT ARCHITECTURAL BOUNDARY:
  - This module performs READ-ONLY strict ASN.1 DER metadata parsing ONLY (subject, issuer, serial
    number, validity window, SHA-256 DER fingerprint, keyUsage, basicConstraints, QCStatements,
    certificatePolicies, subjectAltName, and SPKI public key PEM extraction).
  - It NEVER verifies cryptographic signatures, NEVER evaluates X.509 CA trust chains, NEVER
    checks revocation (OCSP/CRL), and NEVER makes trust or Law No. 5070 legal decisions.
  - All cryptographic signature, CA chain (`openssl verify -x509_strict -attime`), CMS/CAdES,
    XMLDSig/XAdES, OCSP, CRL, and RFC 3161 TSA verifications remain 100% on OpenSSL 3.
  - Strict ITU-T X.690 DER canonicality is enforced (v1.0.5 + v1.0.5.1 audit closure):
      * MAX_ASN1_DEPTH = 32 nesting guard,
      * Rejection of indefinite (BER) lengths, reserved 0xFF lengths, non-minimal long-form lengths
        (< 128 encoded in long form), and leading 0x00 octets in multi-byte lengths,
      * Rejection of non-minimal high-tag-number encodings (tag < 31 or leading 0x80),
      * Rejection of constructed encodings of DER primitive-only types (X.690 §10.2),
      * Strict DER BOOLEAN (1 octet, strictly 0x00 or 0xFF),
      * Strict DER INTEGER (minimal two's-complement encoding; no redundant 0x00/0xFF prefixes),
      * Strict DER NULL (0 octets),
      * Strict DER OID (minimal base-128 subidentifiers; no leading 0x80 octets),
      * Strict DER BIT STRING (unused bits 0..7, empty requires unused=0, trailing unused bits MUST be 0),
      * Strict DER SET (X.690 §11.5 / X.680 §8.6 canonical tag order, no duplicate tags) and
        DER SET OF (X.690 §11.6 ascending octet order with trailing 0x00 padding comparison),
      * Strict per-type ASN.1 character string decoding with zero lossy replacement fallback
        (UTF8String, PrintableString, NumericString, IA5String, VisibleString, GraphicString,
        GeneralString, TeletexString/T61String, VideotexString, BMPString UCS-2 without surrogates,
        UniversalString UTF-32-BE),
      * Strict RFC 5280 UTCTime / GeneralizedTime calendar validation & zero trailing garbage,
      * Strict single-block RFC 7468 PEM / Base64 decoding (rejects multiple blocks & extra data),
      * Fail-closed: malformed DER NEVER returns partially parsed metadata.
  - Immutable parsed metadata entries are deduplicated strictly by exact `(cert_sha256, der_len)`
    WITH raw DER byte-equality verification (`hit[0] == raw`) so metadata can NEVER be mismatched
    across distinct certificates.
"""

from __future__ import annotations

import base64
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re
import threading

from .models import (
    OID_CERTIFICATE_POLICIES,
    OID_ETSI_QC_COMPLIANCE,
    OID_ETSI_QC_SSCD,
    OID_QC_STATEMENTS,
)

MAX_ASN1_DEPTH: int = 32

OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_KEY_USAGE = "2.5.29.15"
OID_SUBJECT_ALT_NAME = "2.5.29.17"

# Universal primitive ASN.1 character string tags (X.680 / X.690 §10.2: MUST be primitive in DER)
_ASN1_UNIVERSAL_STRING_TAGS: frozenset[int] = frozenset(
    {
        0x0C,  # UTF8String
        0x12,  # NumericString
        0x13,  # PrintableString
        0x14,  # TeletexString / T61String
        0x15,  # VideotexString
        0x16,  # IA5String
        0x19,  # GraphicString
        0x1A,  # VisibleString / ISO646String
        0x1B,  # GeneralString
        0x1C,  # UniversalString
        0x1E,  # BMPString
    }
)

# Universal tag numbers whose constructed encoding (P/C bit = 1) is forbidden in DER (X.690 §10.2)
_DER_PRIMITIVE_ONLY_UNIVERSAL_TAGS: frozenset[int] = frozenset(
    {
        0x01,  # BOOLEAN
        0x02,  # INTEGER
        0x03,  # BIT STRING
        0x04,  # OCTET STRING
        0x05,  # NULL
        0x06,  # OBJECT IDENTIFIER
        0x0C,  # UTF8String
        0x12,  # NumericString
        0x13,  # PrintableString
        0x14,  # TeletexString / T61String
        0x15,  # VideotexString
        0x16,  # IA5String
        0x17,  # UTCTime
        0x18,  # GeneralizedTime
        0x19,  # GraphicString
        0x1A,  # VisibleString / ISO646String
        0x1B,  # GeneralString
        0x1C,  # UniversalString
        0x1E,  # BMPString
    }
)

# ITU-T X.680 Table 10 — PrintableString allowed 74-character set
_PRINTABLE_STRING_ALLOWED_BYTES: frozenset[int] = frozenset(
    list(range(ord("A"), ord("Z") + 1))
    + list(range(ord("a"), ord("z") + 1))
    + list(range(ord("0"), ord("9") + 1))
    + [ord(ch) for ch in " '()+,-./:=?"]
)

# ITU-T X.680 Table 9 — NumericString allowed characters ('0'..'9' and space)
_NUMERIC_STRING_ALLOWED_BYTES: frozenset[int] = frozenset(
    list(range(ord("0"), ord("9") + 1)) + [ord(" ")]
)

_SIG_ALG_OIDS: dict[str, str] = {
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassaPss",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "ED25519",
    "1.3.101.113": "ED448",
}

_PK_ALG_OIDS: dict[str, str] = {
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.10": "rsassaPss",
    "1.2.840.10045.2.1": "id-ecPublicKey",
    "1.3.101.112": "ED25519",
    "1.3.101.113": "ED448",
}

_DN_ATTR_OIDS: dict[str, str] = {
    "2.5.4.3": "CN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "0.9.2342.19200300.100.1.1": "UID",
    "1.2.840.113549.1.9.1": "emailAddress",
}

_KEY_USAGE_BIT_NAMES: tuple[str, ...] = (
    "Digital Signature",
    "Non Repudiation",
    "Key Encipherment",
    "Data Encipherment",
    "Key Agreement",
    "Certificate Sign",
    "CRL Sign",
    "Encipher Only",
    "Decipher Only",
)

# Strict single-certificate PEM block regex (MUST match entire stripped input — no extra text or multiple certs)
_STRICT_SINGLE_PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+?)\r?\n-----END CERTIFICATE-----",
)

_MAX_CACHE_ENTRIES = 1024
_CACHE_LOCK = threading.Lock()
_METADATA_CACHE: OrderedDict[tuple[str, int], tuple[bytes, "ParsedX509Metadata"]] = OrderedDict()


class DerParseError(ValueError):
    """Raised on invalid, malformed, or non-canonical ASN.1 DER certificate encodings."""


@dataclass(frozen=True)
class ParsedX509Metadata:
    """Immutable X.509 certificate metadata extracted strictly from ASN.1 DER (no trust/signature verdict)."""

    cert_sha256: str
    subject: str
    issuer: str
    serial_number: str
    not_before_utc: str
    not_after_utc: str
    signature_algorithm: str
    public_key_algorithm: str
    basic_constraints_ca: bool
    key_usage: tuple[str, ...]
    qc_statements_present: bool
    qc_compliance: bool
    qc_sscd: bool
    certificate_policy_oids: tuple[str, ...]
    san_dns_names: tuple[str, ...]
    signer_common_name: str | None
    signer_serial_identifier: str | None
    issuer_country: str | None
    spki_pem: str


def _read_tlv(
    data: bytes,
    offset: int,
    end: int | None = None,
    *,
    depth: int = 0,
) -> tuple[int, int, int, int]:
    """Read one strict ITU-T X.690 DER TLV at `offset`.

    Returns `(tag, value_start, value_end, next_offset)`.
    Enforces MAX_ASN1_DEPTH, canonical tag encoding, and canonical definite length encoding.
    """
    if depth > MAX_ASN1_DEPTH:
        raise DerParseError(f"ASN.1 DER iç içe geçme derinliği sınırını ({MAX_ASN1_DEPTH}) aştı.")
    limit = len(data) if end is None else end
    if offset >= limit:
        raise DerParseError("Beklenmeyen ASN.1 DER sonu.")
    tag = data[offset]
    pos = offset + 1

    # High-tag-number form (X.690 §8.1.2.4): low 5 bits all 1
    if (tag & 0x1F) == 0x1F:
        tag_val = tag
        tag_num = 0
        sub_octets = 0
        while True:
            if pos >= limit:
                raise DerParseError("Kesik yüksek etiketli ASN.1 DER başlığı.")
            b = data[pos]
            pos += 1
            if sub_octets == 0 and b == 0x80:
                raise DerParseError("Yüksek etiket numarasında baştaki 0x80 (kanonik olmayan DER) yasaktır.")
            sub_octets += 1
            if sub_octets > 4:
                raise DerParseError("Yüksek etiket numarası izin verilen 4 bayt sınırını aşıyor.")
            tag_val = (tag_val << 8) | b
            tag_num = (tag_num << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
        if tag_num < 31:
            raise DerParseError("31'den küçük etiket numaraları yüksek etiket biçiminde kodlanamaz (DER ihlali).")
        tag = tag_val

    if pos >= limit:
        raise DerParseError("Eksik ASN.1 DER uzunluk baytı.")
    first_len = data[pos]
    pos += 1
    if first_len == 0x80:
        raise DerParseError("Belirsiz (BER) uzunluk X.509 DER içinde yasaktır.")
    if first_len == 0xFF:
        raise DerParseError("Ayrılmış 0xFF ASN.1 uzunluk baytı geçersizdir.")
    if first_len < 0x80:
        length = first_len
    else:
        num_octets = first_len & 0x7F
        if num_octets == 0 or num_octets > 4 or pos + num_octets > limit:
            raise DerParseError("Geçersiz veya kesik ASN.1 DER uzunluk alanı.")
        if data[pos] == 0x00:
            raise DerParseError("DER uzun-form uzunluk alanında baştaki sıfır baytı (0x00) yasaktır.")
        length = int.from_bytes(data[pos : pos + num_octets], "big")
        if length < 0x80:
            raise DerParseError("128 bayttan küçük uzunluklar uzun-formda kodlanamaz (DER kanoniklik ihlali).")
        pos += num_octets

    val_start = pos
    val_end = pos + length
    if val_end > limit:
        raise DerParseError("ASN.1 DER uzunluğu tampon sınırını aşıyor.")
    return tag, val_start, val_end, val_end


def _extract_tag_info(data: bytes, offset: int, limit: int) -> tuple[int, bool, int]:
    """Extract `(tag_class, is_constructed, tag_number)` from a validated DER TLV header at `offset`."""
    if offset >= limit:
        raise DerParseError("Beklenmeyen ASN.1 DER etiket sonu.")
    first = data[offset]
    tag_class = (first >> 6) & 0x03
    is_constructed = bool(first & 0x20)
    low5 = first & 0x1F
    if low5 < 0x1F:
        return tag_class, is_constructed, low5
    pos = offset + 1
    tag_num = 0
    while pos < limit:
        b = data[pos]
        pos += 1
        tag_num = (tag_num << 7) | (b & 0x7F)
        if not (b & 0x80):
            return tag_class, is_constructed, tag_num
    raise DerParseError("Kesik yüksek etiketli ASN.1 DER başlığı.")


def _compare_der_set_of_octets(a: bytes, b: bytes) -> int:
    """Compare two DER-encoded SET OF component octets per ITU-T X.690 §11.6.

    Shorter component encodings are conceptually padded at their trailing end with 0x00 octets
    for comparison purposes only. Returns -1 if a < b, 0 if a == b, +1 if a > b.
    """
    max_len = max(len(a), len(b))
    for i in range(max_len):
        ba = a[i] if i < len(a) else 0
        bb = b[i] if i < len(b) else 0
        if ba < bb:
            return -1
        if ba > bb:
            return 1
    return 0


def _iter_children_with_spans(
    data: bytes,
    start: int,
    end: int,
    *,
    depth: int = 0,
) -> list[tuple[int, int, int, int, int]]:
    """Return `[(tlv_start, tag, val_start, val_end, next_offset), ...]` with strict DER checks."""
    if depth > MAX_ASN1_DEPTH:
        raise DerParseError(f"ASN.1 DER iç içe geçme derinliği sınırını ({MAX_ASN1_DEPTH}) aştı.")
    items: list[tuple[int, int, int, int, int]] = []
    pos = start
    while pos < end:
        t, vs, ve, nxt = _read_tlv(data, pos, end, depth=depth)
        items.append((pos, t, vs, ve, nxt))
        pos = nxt
    if pos != end:
        raise DerParseError("ASN.1 DER bileşik yapı sınırıyla eşleşmeyen artık bayt tespit edildi.")
    return items


def _iter_children(
    data: bytes,
    start: int,
    end: int,
    *,
    depth: int = 0,
) -> list[tuple[int, int, int, int]]:
    return [
        (t, vs, ve, nxt)
        for _tlv_start, t, vs, ve, nxt in _iter_children_with_spans(data, start, end, depth=depth)
    ]


def _validate_der_set_order(
    data: bytes,
    start: int,
    end: int,
    *,
    depth: int = 0,
) -> list[tuple[int, int, int, int, int]]:
    """Validate ITU-T X.690 §11.5 / X.680 §8.6 canonical tag order for ASN.1 DER `SET`.

    Components MUST appear in strictly ascending `(tag_class, tag_number)` order with no duplicate tags:
    UNIVERSAL (0) < APPLICATION (1) < CONTEXT-SPECIFIC (2) < PRIVATE (3), then ascending tag number.
    """
    children = _iter_children_with_spans(data, start, end, depth=depth)
    prev_key: tuple[int, int] | None = None
    for tlv_start, _t, _vs, _ve, nxt in children:
        tag_class, _is_constructed, tag_number = _extract_tag_info(data, tlv_start, nxt)
        key = (tag_class, tag_number)
        if prev_key is not None:
            if key == prev_key:
                raise DerParseError(
                    f"DER SET içinde yinelenen etiket (sınıf={tag_class}, numara={tag_number}) X.690 §11.5 ihlalidir."
                )
            if key < prev_key:
                raise DerParseError(
                    f"DER SET elemanları X.690 §11.5 kanonik etiket sırasına uymuyor "
                    f"({prev_key} sonrası {key})."
                )
        prev_key = key
    return children


def _validate_der_set_of_order(
    data: bytes,
    start: int,
    end: int,
    *,
    depth: int = 0,
) -> list[tuple[int, int, int, int, int]]:
    """Validate ITU-T X.690 §11.6 canonical ascending octet order for ASN.1 DER `SET OF`.

    Complete DER TLV encodings of elements MUST appear in ascending octet order (with shorter
    components conceptually padded with trailing 0x00 octets for comparison).
    """
    children = _iter_children_with_spans(data, start, end, depth=depth)
    prev_raw: bytes | None = None
    for tlv_start, _t, _vs, _ve, nxt in children:
        curr_raw = data[tlv_start:nxt]
        if prev_raw is not None and _compare_der_set_of_octets(prev_raw, curr_raw) > 0:
            raise DerParseError("DER SET OF elemanları X.690 §11.6 kanonik artan oktet sırasına uymuyor.")
        prev_raw = curr_raw
    return children


def _validate_der_set_container(
    data: bytes,
    start: int,
    end: int,
    *,
    depth: int = 0,
) -> list[tuple[int, int, int, int, int]]:
    """Validate X.690 canonical ordering for a universal `SET` / `SET OF` (tag 0x31) container.

    - If any `(tag_class, tag_number)` repeats across elements, the container MUST be a `SET OF`
      (since ASN.1 `SET` forbids duplicate tags per X.680 §27.3), so X.690 §11.6 octet order is enforced.
    - If all `(tag_class, tag_number)` keys are distinct, X.690 §11.5 / X.680 §8.6 canonical tag order
      is enforced.
    """
    children = _iter_children_with_spans(data, start, end, depth=depth)
    if len(children) <= 1:
        return children
    tag_keys = [
        (_extract_tag_info(data, tlv_start, nxt)[0], _extract_tag_info(data, tlv_start, nxt)[2])
        for tlv_start, _t, _vs, _ve, nxt in children
    ]
    if len(set(tag_keys)) < len(tag_keys):
        prev_raw: bytes | None = None
        for tlv_start, _t, _vs, _ve, nxt in children:
            curr_raw = data[tlv_start:nxt]
            if prev_raw is not None and _compare_der_set_of_octets(prev_raw, curr_raw) > 0:
                raise DerParseError("DER SET OF elemanları X.690 §11.6 kanonik artan oktet sırasına uymuyor.")
            prev_raw = curr_raw
    else:
        for i in range(1, len(tag_keys)):
            if tag_keys[i] <= tag_keys[i - 1]:
                raise DerParseError(
                    f"DER SET elemanları X.690 §11.5 kanonik etiket sırasına uymuyor "
                    f"({tag_keys[i - 1]} sonrası {tag_keys[i]})."
                )
    return children


def _decode_der_boolean(raw: bytes) -> bool:
    """Decode strict DER BOOLEAN (X.690 §11.1: exactly 1 octet, strictly 0x00 or 0xFF)."""
    if len(raw) != 1 or raw[0] not in (0x00, 0xFF):
        raise DerParseError(f"Kanonik olmayan DER BOOLEAN değeri: {raw.hex()!r}")
    return raw[0] == 0xFF


def _validate_der_integer(raw: bytes) -> bytes:
    """Validate strict minimal two's-complement DER INTEGER encoding (X.690 §8.3.2)."""
    if not raw:
        raise DerParseError("Boş ASN.1 DER INTEGER.")
    if len(raw) >= 2:
        if raw[0] == 0x00 and (raw[1] & 0x80) == 0:
            raise DerParseError("DER INTEGER gereksiz baştaki 0x00 baytı içeriyor (kanonik olmayan kodlama).")
        if raw[0] == 0xFF and (raw[1] & 0x80) != 0:
            raise DerParseError("DER INTEGER gereksiz baştaki 0xFF baytı içeriyor (kanonik olmayan kodlama).")
    return raw


def _validate_der_bit_string(raw: bytes) -> tuple[int, bytes]:
    """Validate strict DER BIT STRING encoding (X.690 §8.6 & §11.2.1)."""
    if not raw:
        raise DerParseError("Boş ASN.1 DER BIT STRING.")
    unused = raw[0]
    bit_bytes = raw[1:]
    if unused > 7:
        raise DerParseError(f"Geçersiz BIT STRING kullanılmayan bit sayısı: {unused}")
    if not bit_bytes:
        if unused != 0:
            raise DerParseError("Boş BIT STRING için kullanılmayan bit sayısı 0 olmalıdır.")
        return 0, b""
    if unused > 0:
        mask = (1 << unused) - 1
        if (bit_bytes[-1] & mask) != 0:
            raise DerParseError("DER BIT STRING kullanılmayan son bitler sıfır (0) olmalıdır.")
    return unused, bit_bytes


def _decode_oid(raw: bytes) -> str:
    """Decode strict ITU-T X.690 §8.19 DER OBJECT IDENTIFIER (forbids leading 0x80 subidentifiers)."""
    if not raw:
        raise DerParseError("Boş ASN.1 OID.")
    subids: list[int] = []
    val = 0
    in_arc = False
    for b in raw:
        if not in_arc and b == 0x80:
            raise DerParseError("DER OID alt tanımlayıcısı baştaki 0x80 (minimal olmayan kodlama) içeremez.")
        val = (val << 7) | (b & 0x7F)
        in_arc = True
        if not (b & 0x80):
            subids.append(val)
            val = 0
            in_arc = False
    if in_arc or not subids:
        raise DerParseError("Kesik ASN.1 OID kodlaması.")
    first = subids[0]
    if first < 40:
        arcs = [0, first]
    elif first < 80:
        arcs = [1, first - 40]
    else:
        arcs = [2, first - 80]
    arcs.extend(subids[1:])
    return ".".join(str(a) for a in arcs)


def _validate_and_collect_oids(
    data: bytes,
    start: int,
    end: int,
    out: set[str],
    *,
    depth: int = 0,
) -> None:
    """Recursively validate strict DER structure (including SET/SET OF order and strings) and collect OIDs."""
    if depth > MAX_ASN1_DEPTH:
        raise DerParseError(f"ASN.1 DER uzantı derinliği sınırını ({MAX_ASN1_DEPTH}) aştı.")
    pos = start
    while pos < end:
        tag, vs, ve, nxt = _read_tlv(data, pos, end, depth=depth)
        tag_class, is_constructed, tag_number = _extract_tag_info(data, pos, nxt)
        if tag_class == 0 and is_constructed and tag_number in _DER_PRIMITIVE_ONLY_UNIVERSAL_TAGS:
            raise DerParseError(
                f"ASN.1 DER içinde yapısal (constructed) ilkel tür yasaktır (X.690 §10.2): 0x{tag:02x}"
            )
        if tag == 0x06:
            out.add(_decode_oid(data[vs:ve]))
        elif tag == 0x01:
            _decode_der_boolean(data[vs:ve])
        elif tag == 0x02:
            _validate_der_integer(data[vs:ve])
        elif tag == 0x03:
            _validate_der_bit_string(data[vs:ve])
        elif tag == 0x05:
            if vs != ve:
                raise DerParseError("ASN.1 DER NULL değeri 0 bayt uzunluğunda olmalıdır (X.690 §8.8.2).")
        elif tag in (0x17, 0x18):
            _decode_x509_time(tag, data[vs:ve])
        elif tag in _ASN1_UNIVERSAL_STRING_TAGS:
            _decode_asn1_string(tag, data[vs:ve])
        elif tag == 0x31:
            _validate_der_set_container(data, vs, ve, depth=depth + 1)
            _validate_and_collect_oids(data, vs, ve, out, depth=depth + 1)
        elif is_constructed:  # Constructed SEQUENCE / explicit context / application / private
            _validate_and_collect_oids(data, vs, ve, out, depth=depth + 1)
        pos = nxt
    if pos != end:
        raise DerParseError("Uzantı ASN.1 DER yapısında artık bayt tespit edildi.")


def _decode_asn1_string(tag: int, raw: bytes) -> str:
    """Strictly decode an ASN.1 DER character string according to its exact Universal tag.

    Fail-closed: never uses lossy replacement or ignore decoding modes. Rejects invalid encodings,
    disallowed characters, odd-length BMPString, UTF-16 surrogates in BMPString/UniversalString,
    out-of-range code points, constructed string tags, and unsupported ASN.1 tags.
    """
    if tag == 0x0C:  # UTF8String (RFC 3629 strict UTF-8)
        try:
            return raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise DerParseError("Geçersiz ASN.1 DER UTF8String bayt dizisi.") from exc

    if tag == 0x13:  # PrintableString (ITU-T X.680 Table 10)
        for b in raw:
            if b not in _PRINTABLE_STRING_ALLOWED_BYTES:
                raise DerParseError(f"ASN.1 DER PrintableString izin verilmeyen bayt içeriyor: 0x{b:02x}")
        return raw.decode("ascii", errors="strict")

    if tag == 0x12:  # NumericString (ITU-T X.680 Table 9: '0'..'9' and space)
        for b in raw:
            if b not in _NUMERIC_STRING_ALLOWED_BYTES:
                raise DerParseError(f"ASN.1 DER NumericString izin verilmeyen bayt içeriyor: 0x{b:02x}")
        return raw.decode("ascii", errors="strict")

    if tag == 0x16:  # IA5String (ITU-T T.50: strict 7-bit ASCII 0x00..0x7F)
        try:
            return raw.decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise DerParseError("ASN.1 DER IA5String 7-bit ASCII (0x00..0x7F) dışı bayt içeriyor.") from exc

    if tag == 0x1A:  # VisibleString / ISO646String (0x20..0x7E)
        for b in raw:
            if b < 0x20 or b > 0x7E:
                raise DerParseError(f"ASN.1 DER VisibleString izin verilmeyen bayt içeriyor: 0x{b:02x}")
        return raw.decode("ascii", errors="strict")

    if tag == 0x19:  # GraphicString (0x20..0x7E printable graphic characters)
        for b in raw:
            if b < 0x20 or b > 0x7E:
                raise DerParseError(f"ASN.1 DER GraphicString izin verilmeyen bayt içeriyor: 0x{b:02x}")
        return raw.decode("ascii", errors="strict")

    if tag == 0x1B:  # GeneralString (strict 7-bit ASCII, no NUL)
        for b in raw:
            if b == 0x00 or b > 0x7F:
                raise DerParseError(f"ASN.1 DER GeneralString geçersiz bayt içeriyor: 0x{b:02x}")
        return raw.decode("ascii", errors="strict")

    if tag == 0x14:  # TeletexString / T61String (forbid NUL, illegal C0/C1 controls, DEL, 0xA0, 0xFF)
        for b in raw:
            if (b < 0x20 and b not in (0x0A, 0x0D)) or (0x7F <= b <= 0xA0) or b == 0xFF:
                raise DerParseError(f"ASN.1 DER TeletexString (T61String) geçersiz bayt içeriyor: 0x{b:02x}")
        return raw.decode("latin-1", errors="strict")

    if tag == 0x15:  # VideotexString (forbid NUL, illegal C0/C1 controls, DEL, 0xFF)
        for b in raw:
            if (b < 0x20 and b not in (0x0A, 0x0D)) or (0x7F <= b <= 0x9F) or b == 0xFF:
                raise DerParseError(f"ASN.1 DER VideotexString geçersiz bayt içeriyor: 0x{b:02x}")
        return raw.decode("latin-1", errors="strict")

    if tag == 0x1E:  # BMPString (ITU-T X.680 §41.15: 2-byte big-endian UCS-2 BMP ONLY — no surrogates)
        if (len(raw) % 2) != 0:
            raise DerParseError(f"ASN.1 DER BMPString bayt uzunluğu 2'nin katı olmalıdır (bulunan: {len(raw)}).")
        for i in range(0, len(raw), 2):
            code_unit = (raw[i] << 8) | raw[i + 1]
            if 0xD800 <= code_unit <= 0xDFFF:
                raise DerParseError(
                    f"ASN.1 DER BMPString (UCS-2) içinde UTF-16 surrogate kod noktası (U+{code_unit:04X}) yasaktır."
                )
        try:
            return raw.decode("utf-16-be", errors="strict")
        except UnicodeDecodeError as exc:
            raise DerParseError("Geçersiz ASN.1 DER BMPString bayt dizisi.") from exc

    if tag == 0x1C:  # UniversalString (ITU-T X.680 §41.15: 4-byte big-endian UCS-4 / UTF-32-BE)
        if (len(raw) % 4) != 0:
            raise DerParseError(
                f"ASN.1 DER UniversalString bayt uzunluğu 4'ün katı olmalıdır (bulunan: {len(raw)})."
            )
        for i in range(0, len(raw), 4):
            cp = int.from_bytes(raw[i : i + 4], "big")
            if cp > 0x10FFFF or (0xD800 <= cp <= 0xDFFF):
                raise DerParseError(
                    f"ASN.1 DER UniversalString geçersiz Unicode kod noktası içeriyor: U+{cp:08X}"
                )
        try:
            return raw.decode("utf-32-be", errors="strict")
        except UnicodeDecodeError as exc:
            raise DerParseError("Geçersiz ASN.1 DER UniversalString bayt dizisi.") from exc

    raise DerParseError(f"Desteklenmeyen veya kanonik olmayan ASN.1 karakter dizisi etiketi: 0x{tag:02x}")


def _escape_rfc2253_val(val: str) -> str:
    out: list[str] = []
    for ch in val:
        if ch in (",", "+", '"', "\\", "<", ">", ";"):
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def _parse_name(data: bytes, start: int, end: int, *, depth: int = 0) -> tuple[str, dict[str, str]]:
    """Parse X.509 Name -> `(rfc2253_dn, attrs_by_lower_key)` with strict DER SET OF & string checks."""
    rdns = _iter_children(data, start, end, depth=depth)
    rdn_strings: list[str] = []
    attrs: dict[str, str] = {}
    for rdn_tag, rdn_s, rdn_e, _ in rdns:
        if rdn_tag != 0x31:  # SET OF AttributeTypeAndValue
            raise DerParseError(f"X.509 Name RDN SET (0x31) beklenirken 0x{rdn_tag:02x} bulundu.")
        # Enforce ITU-T X.690 §11.6 canonical ascending octet order for RDN SET OF elements
        avas = _validate_der_set_of_order(data, rdn_s, rdn_e, depth=depth + 1)
        if not avas:
            raise DerParseError("Boş X.509 RDN SET.")
        ava_parts: list[str] = []
        for _ava_start, ava_tag, ava_s, ava_e, _ in avas:
            if ava_tag != 0x30:  # SEQUENCE
                raise DerParseError(f"X.509 AVA SEQUENCE (0x30) beklenirken 0x{ava_tag:02x} bulundu.")
            pair = _iter_children(data, ava_s, ava_e, depth=depth + 2)
            if len(pair) != 2 or pair[0][0] != 0x06:
                raise DerParseError("X.509 AttributeTypeAndValue yapısı geçersiz.")
            oid = _decode_oid(data[pair[0][1] : pair[0][2]])
            val_decoded = _decode_asn1_string(pair[1][0], data[pair[1][1] : pair[1][2]])
            if "\x00" in val_decoded:
                raise DerParseError("X.509 Name öznitelik değerinde NUL (0x00) karakteri yasaktır.")
            val_str = val_decoded.strip()
            key_name = _DN_ATTR_OIDS.get(oid, oid)
            ava_parts.append(f"{key_name}={_escape_rfc2253_val(val_str)}")
            attrs[key_name.lower()] = val_str
            attrs[oid.lower()] = val_str
        if ava_parts:
            rdn_strings.append("+".join(ava_parts))
    # RFC 2253 outputs RDNs in reverse order (matching `openssl x509 -nameopt RFC2253`)
    rdn_strings.reverse()
    return ",".join(rdn_strings), attrs


def _decode_x509_time(tag: int, raw: bytes) -> str:
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise DerParseError("X.509 geçerlilik zamanı geçerli ASCII değil.") from exc

    if tag == 0x17:  # UTCTime: strict YYMMDDHHMMSSZ (13 chars, RFC 5280 §4.1.2.5.1)
        m = re.fullmatch(r"(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z", text)
        if not m:
            raise DerParseError(f"Geçersiz UTCTime biçimi: {text!r}")
        yy, mo, dd, hh, mi, ss = (int(g) for g in m.groups())
        yyyy = (1900 + yy) if yy >= 50 else (2000 + yy)
        try:
            dt = datetime(yyyy, mo, dd, hh, mi, ss, tzinfo=timezone.utc)
        except ValueError as exc:
            raise DerParseError(f"Geçersiz UTCTime takvim değeri: {text!r}") from exc
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    if tag == 0x18:  # GeneralizedTime: strict YYYYMMDDHHMMSSZ (15 chars, RFC 5280 §4.1.2.5.2 — no fractional secs)
        m = re.fullmatch(r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z", text)
        if not m:
            raise DerParseError(f"Geçersiz veya kesirli GeneralizedTime biçimi: {text!r}")
        yyyy, mo, dd, hh, mi, ss = (int(g) for g in m.groups())
        try:
            dt = datetime(yyyy, mo, dd, hh, mi, ss, tzinfo=timezone.utc)
        except ValueError as exc:
            raise DerParseError(f"Geçersiz GeneralizedTime takvim değeri: {text!r}") from exc
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    raise DerParseError(f"Beklenmeyen geçerlilik zaman etiketi: 0x{tag:02x}")


def _decode_algorithm_oid(
    data: bytes,
    start: int,
    end: int,
    table: dict[str, str],
    *,
    depth: int = 0,
) -> str:
    children = _iter_children(data, start, end, depth=depth)
    if not children or children[0][0] != 0x06:
        raise DerParseError("AlgorithmIdentifier geçerli bir OID (0x06) ile başlamalıdır.")
    oid = _decode_oid(data[children[0][1] : children[0][2]])
    if len(children) > 1:
        _validate_and_collect_oids(data, children[0][3], end, set(), depth=depth)
    return table.get(oid, oid)


def _parse_key_usage(ext_bytes: bytes, *, depth: int = 0) -> tuple[str, ...]:
    tag, vs, ve, nxt = _read_tlv(ext_bytes, 0, len(ext_bytes), depth=depth)
    if tag != 0x03 or nxt != len(ext_bytes):
        raise DerParseError("KeyUsage uzantısı tekil ve tam DER BIT STRING olmalıdır.")
    unused, bit_bytes = _validate_der_bit_string(ext_bytes[vs:ve])
    if not bit_bytes:
        return ()
    total_bits = len(bit_bytes) * 8 - unused
    usages: list[str] = []
    for bit_idx in range(min(total_bits, len(_KEY_USAGE_BIT_NAMES))):
        byte_val = bit_bytes[bit_idx // 8]
        mask = 0x80 >> (bit_idx % 8)
        if byte_val & mask:
            usages.append(_KEY_USAGE_BIT_NAMES[bit_idx])
    return tuple(usages)


def _parse_basic_constraints_ca(ext_bytes: bytes, *, depth: int = 0) -> bool:
    tag, vs, ve, nxt = _read_tlv(ext_bytes, 0, len(ext_bytes), depth=depth)
    if tag != 0x30 or nxt != len(ext_bytes):
        raise DerParseError("BasicConstraints uzantısı tekil DER SEQUENCE olmalıdır.")
    children = _iter_children(ext_bytes, vs, ve, depth=depth + 1)
    if len(children) > 2:
        raise DerParseError("BasicConstraints en fazla 2 alan (cA, pathLenConstraint) içerebilir.")
    idx = 0
    is_ca = False
    if idx < len(children) and children[idx][0] == 0x01:  # BOOLEAN cA
        is_ca = _decode_der_boolean(ext_bytes[children[idx][1] : children[idx][2]])
        idx += 1
    if idx < len(children):
        if children[idx][0] != 0x02:
            raise DerParseError("BasicConstraints pathLenConstraint INTEGER (0x02) olmalıdır.")
        pl_raw = _validate_der_integer(ext_bytes[children[idx][1] : children[idx][2]])
        if pl_raw[0] & 0x80:
            raise DerParseError("BasicConstraints pathLenConstraint negatif olamaz.")
        idx += 1
    if idx != len(children):
        raise DerParseError("BasicConstraints bilinmeyen alan içeriyor.")
    return is_ca


def _parse_san_dns_names(ext_bytes: bytes, *, depth: int = 0) -> tuple[str, ...]:
    tag, vs, ve, nxt = _read_tlv(ext_bytes, 0, len(ext_bytes), depth=depth)
    if tag != 0x30 or nxt != len(ext_bytes):
        raise DerParseError("SubjectAltName uzantısı tekil DER SEQUENCE olmalıdır.")
    names: list[str] = []
    for c_start, ctag, cvs, cve, cnxt in _iter_children_with_spans(ext_bytes, vs, ve, depth=depth + 1):
        _c_class, c_constructed, _c_num = _extract_tag_info(ext_bytes, c_start, cnxt)
        if ctag == 0x82:  # [2] IMPLICIT dNSName (IA5String)
            dns_decoded = _decode_asn1_string(0x16, ext_bytes[cvs:cve])
            if "\x00" in dns_decoded:
                raise DerParseError("SAN dNSName içinde NUL (0x00) karakteri yasaktır.")
            dns = dns_decoded.strip()
            if dns and dns not in names:
                names.append(dns)
        elif ctag in (0x81, 0x86):  # [1] rfc822Name, [6] uniformResourceIdentifier (IMPLICIT IA5String)
            ia5_decoded = _decode_asn1_string(0x16, ext_bytes[cvs:cve])
            if "\x00" in ia5_decoded:
                raise DerParseError("SAN IA5String alanında NUL (0x00) karakteri yasaktır.")
        elif ctag == 0xA4:  # [4] EXPLICIT directoryName (Name)
            dn_tag, dn_vs, dn_ve, dn_nxt = _read_tlv(ext_bytes, cvs, cve, depth=depth + 2)
            if dn_tag != 0x30 or dn_nxt != cve:
                raise DerParseError("SAN directoryName tekil DER Name SEQUENCE olmalıdır.")
            _parse_name(ext_bytes, dn_vs, dn_ve, depth=depth + 3)
        elif c_constructed:
            _validate_and_collect_oids(ext_bytes, cvs, cve, set(), depth=depth + 2)
    return tuple(names)


def _format_spki_pem(spki_der: bytes) -> str:
    b64 = base64.b64encode(spki_der).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"


def _parse_certificate_der_uncached(der_bytes: bytes) -> ParsedX509Metadata:
    cert_sha256 = hashlib.sha256(der_bytes).hexdigest()

    # Outer Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    c_tag, c_vs, c_ve, c_nxt = _read_tlv(der_bytes, 0, len(der_bytes), depth=0)
    if c_tag != 0x30 or c_nxt != len(der_bytes):
        raise DerParseError("Sertifika dış ASN.1 SEQUENCE yapısı geçersiz veya artık bayt içeriyor.")
    cert_fields = _iter_children(der_bytes, c_vs, c_ve, depth=1)
    if len(cert_fields) != 3:
        raise DerParseError("X.509 Certificate 3 zorunlu bileşen (tbs, sigAlg, sigVal) içermelidir.")

    tbs_tag, tbs_vs, tbs_ve, _ = cert_fields[0]
    sigalg_tag, sigalg_vs, sigalg_ve, _ = cert_fields[1]
    sigval_tag, sigval_vs, sigval_ve, _ = cert_fields[2]
    if tbs_tag != 0x30 or sigalg_tag != 0x30 or sigval_tag != 0x03:
        raise DerParseError("X.509 Certificate iç alan türleri geçersiz.")
    _validate_der_bit_string(der_bytes[sigval_vs:sigval_ve])

    tbs_fields = _iter_children(der_bytes, tbs_vs, tbs_ve, depth=2)
    idx = 0
    # Optional [0] EXPLICIT version (defaults to v1)
    if idx < len(tbs_fields) and tbs_fields[idx][0] == 0xA0:
        v_tag, v_vs, v_ve, v_nxt = _read_tlv(der_bytes, tbs_fields[idx][1], tbs_fields[idx][2], depth=3)
        if v_tag != 0x02 or v_nxt != tbs_fields[idx][2]:
            raise DerParseError("TBSCertificate version alanı tekil DER INTEGER olmalıdır.")
        v_raw = _validate_der_integer(der_bytes[v_vs:v_ve])
        v_int = int.from_bytes(v_raw, "big", signed=True)
        if v_int not in (0, 1, 2):
            raise DerParseError(f"Desteklenmeyen X.509 sürüm değeri: {v_int}")
        idx += 1

    if len(tbs_fields) - idx < 6:
        raise DerParseError("TBSCertificate zorunlu alanları eksik.")

    # 1. serialNumber (strict DER positive INTEGER)
    ser_tag, ser_vs, ser_ve, _ = tbs_fields[idx]
    if ser_tag != 0x02:
        raise DerParseError("X.509 serialNumber INTEGER geçersiz.")
    ser_raw = _validate_der_integer(der_bytes[ser_vs:ser_ve])
    if ser_raw[0] & 0x80:
        raise DerParseError("X.509 serialNumber negatif olamaz.")
    serial_hex = ser_raw.hex().upper().lstrip("0") or "0"
    idx += 1

    # 2. signature (AlgorithmIdentifier inside TBSCertificate)
    tbs_sigalg_tag, tbs_sigalg_vs, tbs_sigalg_ve, _ = tbs_fields[idx]
    if tbs_sigalg_tag != 0x30:
        raise DerParseError("TBSCertificate signature AlgorithmIdentifier geçersiz.")
    _decode_algorithm_oid(der_bytes, tbs_sigalg_vs, tbs_sigalg_ve, _SIG_ALG_OIDS, depth=3)
    idx += 1

    # 3. issuer (Name)
    iss_tag, iss_vs, iss_ve, _ = tbs_fields[idx]
    if iss_tag != 0x30:
        raise DerParseError("X.509 issuer Name geçersiz.")
    issuer_dn, issuer_attrs = _parse_name(der_bytes, iss_vs, iss_ve, depth=3)
    idx += 1

    # 4. validity (SEQUENCE { notBefore, notAfter })
    val_tag, val_vs, val_ve, _ = tbs_fields[idx]
    if val_tag != 0x30:
        raise DerParseError("X.509 validity SEQUENCE geçersiz.")
    val_pair = _iter_children(der_bytes, val_vs, val_ve, depth=3)
    if len(val_pair) != 2:
        raise DerParseError("X.509 validity iki tarih (notBefore, notAfter) içermelidir.")
    not_before_utc = _decode_x509_time(val_pair[0][0], der_bytes[val_pair[0][1] : val_pair[0][2]])
    not_after_utc = _decode_x509_time(val_pair[1][0], der_bytes[val_pair[1][1] : val_pair[1][2]])
    idx += 1

    # 5. subject (Name)
    sub_tag, sub_vs, sub_ve, _ = tbs_fields[idx]
    if sub_tag != 0x30:
        raise DerParseError("X.509 subject Name geçersiz.")
    subject_dn, subject_attrs = _parse_name(der_bytes, sub_vs, sub_ve, depth=3)
    idx += 1

    # 6. subjectPublicKeyInfo (SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING })
    spki_tag, spki_vs, spki_ve, _ = tbs_fields[idx]
    if spki_tag != 0x30:
        raise DerParseError("X.509 subjectPublicKeyInfo geçersiz.")
    spki_tlv_start = tbs_fields[idx - 1][3]
    spki_der = der_bytes[spki_tlv_start:spki_ve]
    spki_children = _iter_children(der_bytes, spki_vs, spki_ve, depth=3)
    if len(spki_children) != 2 or spki_children[0][0] != 0x30 or spki_children[1][0] != 0x03:
        raise DerParseError("X.509 subjectPublicKeyInfo (AlgorithmIdentifier + BIT STRING) yapısı geçersiz.")
    _validate_der_bit_string(der_bytes[spki_children[1][1] : spki_children[1][2]])
    pk_alg = _decode_algorithm_oid(der_bytes, spki_children[0][1], spki_children[0][2], _PK_ALG_OIDS, depth=4)
    spki_pem = _format_spki_pem(spki_der)
    idx += 1

    sig_alg = _decode_algorithm_oid(der_bytes, sigalg_vs, sigalg_ve, _SIG_ALG_OIDS, depth=2)

    # 7. Optional issuerUniqueID [1], subjectUniqueID [2], extensions [3]
    basic_constraints_ca = False
    key_usage: tuple[str, ...] = ()
    qc_present = False
    qc_oids: set[str] = set()
    policy_oids: set[str] = set()
    san_dns: tuple[str, ...] = ()

    while idx < len(tbs_fields):
        ftag, fvs, fve, _ = tbs_fields[idx]
        idx += 1
        if ftag == 0xA3:  # [3] EXPLICIT extensions
            ext_seq_tag, es_vs, es_ve, es_nxt = _read_tlv(der_bytes, fvs, fve, depth=3)
            if ext_seq_tag != 0x30 or es_nxt != fve:
                raise DerParseError("X.509 Extensions alanı tekil DER SEQUENCE olmalıdır.")
            for ext_tag, ext_vs, ext_ve, _ in _iter_children(der_bytes, es_vs, es_ve, depth=4):
                if ext_tag != 0x30:
                    raise DerParseError("X.509 Extension öğesi SEQUENCE (0x30) olmalıdır.")
                ext_parts = _iter_children(der_bytes, ext_vs, ext_ve, depth=5)
                if len(ext_parts) not in (2, 3) or ext_parts[0][0] != 0x06 or ext_parts[-1][0] != 0x04:
                    raise DerParseError("X.509 Extension (OID, [critical BOOLEAN], OCTET STRING) yapısı geçersiz.")
                if len(ext_parts) == 3:
                    if ext_parts[1][0] != 0x01:
                        raise DerParseError("X.509 Extension critical alanı BOOLEAN (0x01) olmalıdır.")
                    _decode_der_boolean(der_bytes[ext_parts[1][1] : ext_parts[1][2]])
                ext_oid = _decode_oid(der_bytes[ext_parts[0][1] : ext_parts[0][2]])
                ext_val_bytes = der_bytes[ext_parts[-1][1] : ext_parts[-1][2]]
                if ext_oid == OID_BASIC_CONSTRAINTS:
                    basic_constraints_ca = _parse_basic_constraints_ca(ext_val_bytes, depth=6)
                elif ext_oid == OID_KEY_USAGE:
                    key_usage = _parse_key_usage(ext_val_bytes, depth=6)
                elif ext_oid == OID_QC_STATEMENTS:
                    qc_present = True
                    q_tag, q_vs, q_ve, q_nxt = _read_tlv(ext_val_bytes, 0, len(ext_val_bytes), depth=6)
                    if q_tag != 0x30 or q_nxt != len(ext_val_bytes):
                        raise DerParseError("QCStatements uzantısı tekil DER SEQUENCE olmalıdır.")
                    _validate_and_collect_oids(ext_val_bytes, q_vs, q_ve, qc_oids, depth=7)
                elif ext_oid == OID_CERTIFICATE_POLICIES:
                    p_tag, p_vs, p_ve, p_nxt = _read_tlv(ext_val_bytes, 0, len(ext_val_bytes), depth=6)
                    if p_tag != 0x30 or p_nxt != len(ext_val_bytes):
                        raise DerParseError("CertificatePolicies uzantısı tekil DER SEQUENCE olmalıdır.")
                    _validate_and_collect_oids(ext_val_bytes, p_vs, p_ve, policy_oids, depth=7)
                elif ext_oid == OID_SUBJECT_ALT_NAME:
                    san_dns = _parse_san_dns_names(ext_val_bytes, depth=6)
                else:
                    _, _, _, u_nxt = _read_tlv(ext_val_bytes, 0, len(ext_val_bytes), depth=6)
                    if u_nxt != len(ext_val_bytes):
                        raise DerParseError(
                            f"X.509 uzantısı ({ext_oid}) tekil ve artık baytsız DER değeri olmalıdır."
                        )
                    _validate_and_collect_oids(ext_val_bytes, 0, len(ext_val_bytes), set(), depth=6)
        elif ftag in (0x81, 0x82):  # IMPLICIT BIT STRING uniqueIDs
            _validate_der_bit_string(der_bytes[fvs:fve])
        else:
            raise DerParseError(f"TBSCertificate içinde beklenmeyen etiket: 0x{ftag:02x}")

    signer_cn = subject_attrs.get("cn") or subject_attrs.get("2.5.4.3")
    signer_serial_id = (
        subject_attrs.get("serialnumber")
        or subject_attrs.get("2.5.4.5")
        or subject_attrs.get("uid")
        or subject_attrs.get("0.9.2342.19200300.100.1.1")
    )
    issuer_country = issuer_attrs.get("c") or issuer_attrs.get("2.5.4.6")

    return ParsedX509Metadata(
        cert_sha256=cert_sha256,
        subject=subject_dn,
        issuer=issuer_dn,
        serial_number=serial_hex,
        not_before_utc=not_before_utc,
        not_after_utc=not_after_utc,
        signature_algorithm=sig_alg,
        public_key_algorithm=pk_alg,
        basic_constraints_ca=basic_constraints_ca,
        key_usage=key_usage,
        qc_statements_present=qc_present,
        qc_compliance=OID_ETSI_QC_COMPLIANCE in qc_oids,
        qc_sscd=OID_ETSI_QC_SSCD in qc_oids,
        certificate_policy_oids=tuple(sorted(policy_oids)),
        san_dns_names=san_dns,
        signer_common_name=signer_cn,
        signer_serial_identifier=signer_serial_id,
        issuer_country=issuer_country,
        spki_pem=spki_pem,
    )


def parse_x509_certificate_metadata_der(der_bytes: bytes) -> ParsedX509Metadata:
    """Parse X.509 DER bytes into immutable metadata, deduplicated strictly by `(sha256, len)` + raw byte equality."""
    if not isinstance(der_bytes, (bytes, bytearray)) or len(der_bytes) < 32:
        raise DerParseError("Geçersiz veya çok kısa X.509 DER verisi.")
    raw = bytes(der_bytes)
    key = (hashlib.sha256(raw).hexdigest(), len(raw))
    with _CACHE_LOCK:
        hit = _METADATA_CACHE.get(key)
        if hit is not None and hit[0] == raw:
            _METADATA_CACHE.move_to_end(key)
            return hit[1]

    parsed = _parse_certificate_der_uncached(raw)
    with _CACHE_LOCK:
        _METADATA_CACHE[key] = (raw, parsed)
        _METADATA_CACHE.move_to_end(key)
        while len(_METADATA_CACHE) > _MAX_CACHE_ENTRIES:
            _METADATA_CACHE.popitem(last=False)
    return parsed


def parse_x509_certificate_metadata(cert_pem: str) -> ParsedX509Metadata | None:
    """Strictly parse a SINGLE X.509 PEM certificate block and return read-only ASN.1 DER metadata (or None).

    Rejects:
      - Non-string inputs, empty strings, missing PEM boundaries,
      - Multiple PEM blocks concatenated together,
      - Unexpected leading or trailing non-whitespace text outside the single PEM block,
      - Corrupt / non-canonical Base64,
      - Malformed or non-canonical ASN.1 DER (NEVER returns partial metadata!).
    """
    if not isinstance(cert_pem, str):
        return None
    stripped = cert_pem.strip()
    if not stripped:
        return None
    m = _STRICT_SINGLE_PEM_RE.fullmatch(stripped)
    if m is None:
        return None
    raw_body = m.group(1)
    # Reject spaces/tabs inside Base64 lines; allow only strict Base64 alphabet and line endings
    b64_body = raw_body.replace("\r", "").replace("\n", "")
    if not b64_body or (len(b64_body) % 4) != 0:
        return None
    try:
        der_bytes = base64.b64decode(b64_body, validate=True)
        return parse_x509_certificate_metadata_der(der_bytes)
    except Exception:
        return None


def extract_leaf_cert_metadata_from_tsr_der(tsr_der: bytes) -> tuple[str | None, str | None]:
    """Read embedded TSA signer certificate subject & SHA-256 fingerprint from RFC 3161 TSR DER (metadata ONLY).

    Does NOT validate the timestamp token signature or CA chain — callers MUST run `openssl ts -verify`!
    """
    if not isinstance(tsr_der, (bytes, bytearray)) or len(tsr_der) < 32:
        return None, None
    data = bytes(tsr_der)
    try:
        # TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo OPTIONAL }
        tag, vs, ve, nxt = _read_tlv(data, 0, len(data), depth=0)
        if tag != 0x30 or nxt != len(data):
            return None, None
        resp_fields = _iter_children(data, vs, ve, depth=1)
        if len(resp_fields) < 2 or resp_fields[1][0] != 0x30:
            return None, None
        # ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT SignedData }
        ci_fields = _iter_children(data, resp_fields[1][1], resp_fields[1][2], depth=2)
        if len(ci_fields) < 2 or ci_fields[1][0] != 0xA0:
            return None, None
        sd_tag, sd_vs, sd_ve, sd_nxt = _read_tlv(data, ci_fields[1][1], ci_fields[1][2], depth=3)
        if sd_tag != 0x30 or sd_nxt != ci_fields[1][2]:
            return None, None
        # SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo, certificates [0] IMPLICIT OPTIONAL, ... }
        for ftag, fvs, fve, _ in _iter_children(data, sd_vs, sd_ve, depth=4):
            if ftag == 0xA0:  # [0] IMPLICIT CertificateSet
                cert_items = _iter_children(data, fvs, fve, depth=5)
                first_meta: ParsedX509Metadata | None = None
                prev_end = fvs
                for ctag, _cvs, cve, cnxt in cert_items:
                    if ctag == 0x30:
                        cert_der = data[prev_end:cve]
                        meta = parse_x509_certificate_metadata_der(cert_der)
                        if first_meta is None:
                            first_meta = meta
                        if not meta.basic_constraints_ca:
                            return meta.subject, meta.cert_sha256
                    prev_end = cnxt
                if first_meta is not None:
                    return first_meta.subject, first_meta.cert_sha256
    except DerParseError:
        return None, None
    return None, None
