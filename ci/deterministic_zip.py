"""Deterministic ZIP Builder & Bit-for-Bit Reproducibility Verifier (hrAI @HukukSGK v1.0.6 WP-1).

Stdlib-only canonical packaging specification:
  - Single top-level root directory (`<root_name>/`), POSIX `/` paths.
  - Deterministic UTF-8 lexicographical sorting (root dir, then subdirs, then regular files).
  - Explicit exclusion of build/cache artifacts (`__pycache__`, `*.pyc`, `*.pyo`, `.DS_Store`,
    `.pytest_cache`, `.git`).
  - Unconditional fail-closed rejection of symbolic links: both the raw `source_dir` itself
    (checked BEFORE `resolve()`) and every entry anywhere beneath it — regardless of exclusion
    patterns (even `.pyc`, `.pyo`, `.DS_Store`, or `__pycache__` symlinks are rejected).
  - Strict ISO-8601 DOS timestamp normalization: accepts naive UTC-neutral `YYYY-MM-DDTHH:MM:SS`
    or explicit UTC / offset (`Z`, `+HH:MM`, `-HH:MM`), normalizing all timezone-aware inputs
    strictly to UTC (`timezone.utc`) before DOS range & 2-second granularity checks.
  - Normalized UNIX modes (`0o40755` for dirs, `0o100644` for regular files), `create_system = 3`
    (UNIX), `extra = b""`, `comment = b""`, `ZIP_STORED` for directory entries and `ZIP_DEFLATED`
    (`compresslevel = 9`) for files.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import stat
import sys
import tempfile
import zipfile

CANONICAL_V1051_TIMESTAMP = "2026-11-24T12:00:00"
EXCLUDED_DIR_NAMES: frozenset[str] = frozenset({"__pycache__", ".pytest_cache", ".git"})
EXCLUDED_FILE_NAMES: frozenset[str] = frozenset({".DS_Store"})
EXCLUDED_FILE_SUFFIXES: frozenset[str] = frozenset({".pyc", ".pyo"})
_STRICT_ISO_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})?$")


class DeterministicZipError(RuntimeError):
    """Raised when deterministic archive creation or verification fails closed."""


def parse_dos_timestamp(ts_iso: str) -> tuple[int, int, int, int, int, int]:
    """Parse a strict ISO-8601 timestamp into a UTC-normalized ZIP DOS tuple.

    Accepted formats:
      - Naive UTC-neutral: `YYYY-MM-DDTHH:MM:SS`
      - Explicit UTC:      `YYYY-MM-DDTHH:MM:SSZ`
      - Explicit offset:   `YYYY-MM-DDTHH:MM:SS±HH:MM` (converted strictly to UTC)

    Rejected fail-closed: date-only strings, fractional seconds, malformed offsets,
    out-of-range DOS years (outside `[1980, 2107]`), and odd seconds.
    """
    if not isinstance(ts_iso, str):
        raise DeterministicZipError(f"ZIP timestamp must be a string, got {type(ts_iso).__name__}.")
    cleaned = ts_iso.strip()
    if not _STRICT_ISO_TS_RE.fullmatch(cleaned):
        raise DeterministicZipError(
            f"Timestamp must match YYYY-MM-DDTHH:MM:SS[Z|±HH:MM] without fractional seconds: {ts_iso!r}"
        )
    iso_for_parse = f"{cleaned[:-1]}+00:00" if cleaned.endswith("Z") else cleaned
    try:
        dt = datetime.fromisoformat(iso_for_parse)
    except ValueError as exc:
        raise DeterministicZipError(f"Invalid ISO timestamp for ZIP metadata: {ts_iso!r}") from exc
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    if dt.year < 1980 or dt.year > 2107:
        raise DeterministicZipError(f"ZIP DOS timestamp year must be in [1980, 2107], got {dt.year}.")
    if dt.second % 2 != 0:
        raise DeterministicZipError(
            f"ZIP DOS timestamps have 2-second granularity; seconds must be even, got {dt.second}."
        )
    return (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _validate_source_dir_no_symlink(source_dir: Path) -> Path:
    """Validate `source_dir` BEFORE calling `resolve()`, rejecting symlinked source dirs fail-closed."""
    try:
        st = source_dir.lstat()
    except OSError as exc:
        raise DeterministicZipError(f"Source directory does not exist or cannot be stat'd: {source_dir}") from exc
    if stat.S_ISLNK(st.st_mode) or source_dir.is_symlink():
        raise DeterministicZipError(f"Source directory must not be a symlink: {source_dir}")
    if not stat.S_ISDIR(st.st_mode):
        raise DeterministicZipError(f"Source path is not a regular directory: {source_dir}")
    return source_dir.resolve()


def _is_excluded(rel_parts: tuple[str, ...], is_dir: bool) -> bool:
    for part in rel_parts:
        if part in EXCLUDED_DIR_NAMES:
            return True
    if not is_dir and rel_parts:
        leaf = rel_parts[-1]
        if leaf in EXCLUDED_FILE_NAMES:
            return True
        if any(leaf.endswith(suf) for suf in EXCLUDED_FILE_SUFFIXES):
            return True
    return False


def _collect_canonical_entries(
    source_dir: Path,
    root_name: str,
) -> tuple[list[str], list[tuple[str, Path]]]:
    """Collect sorted `(dirs, files)` relative to `root_name`, rejecting ALL symlinks unconditionally."""
    resolved_src = _validate_source_dir_no_symlink(source_dir)
    if not root_name or "/" in root_name or "\\" in root_name or root_name in (".", ".."):
        raise DeterministicZipError(f"Invalid archive root directory name: {root_name!r}")

    dirs: list[str] = []
    files: list[tuple[str, Path]] = []

    def _walk(cur: Path) -> None:
        for entry in sorted(cur.iterdir(), key=lambda p: p.name.encode("utf-8")):
            # Unconditional symlink rejection BEFORE any exclusion rule
            if entry.is_symlink():
                raise DeterministicZipError(f"Symlink forbidden in deterministic archive: {entry}")
            rel_parts = entry.relative_to(resolved_src).parts
            if entry.is_dir():
                if _is_excluded(rel_parts, is_dir=True):
                    continue
                rel_posix = "/".join((root_name, *rel_parts)) + "/"
                dirs.append(rel_posix)
                _walk(entry)
            elif entry.is_file():
                if _is_excluded(rel_parts, is_dir=False):
                    continue
                rel_posix = "/".join((root_name, *rel_parts))
                files.append((rel_posix, entry))
            else:
                raise DeterministicZipError(f"Unsupported non-regular filesystem entry: {entry}")

    _walk(resolved_src)
    dirs.sort(key=lambda s: s.encode("utf-8"))
    files.sort(key=lambda item: item[0].encode("utf-8"))
    return dirs, files


def _make_dir_zipinfo(arcname: str, date_time: tuple[int, int, int, int, int, int]) -> zipfile.ZipInfo:
    zi = zipfile.ZipInfo(arcname, date_time=date_time)
    zi.compress_type = zipfile.ZIP_STORED
    zi.create_system = 3  # UNIX
    zi.create_version = 20
    zi.extract_version = 20
    zi.flag_bits = 0
    zi.external_attr = (0o40755 << 16) | 0x10
    zi.extra = b""
    zi.comment = b""
    return zi


def _make_file_zipinfo(arcname: str, date_time: tuple[int, int, int, int, int, int]) -> zipfile.ZipInfo:
    zi = zipfile.ZipInfo(arcname, date_time=date_time)
    zi.compress_type = zipfile.ZIP_DEFLATED
    zi.create_system = 3  # UNIX
    zi.create_version = 20
    zi.extract_version = 20
    zi.flag_bits = 0
    zi.external_attr = 0o100644 << 16
    zi.extra = b""
    zi.comment = b""
    return zi


def build_deterministic_zip(
    source_dir: Path,
    output_zip: Path,
    *,
    root_name: str | None = None,
    timestamp: str = CANONICAL_V1051_TIMESTAMP,
) -> dict[str, object]:
    """Build a canonical bit-for-bit reproducible ZIP archive from `source_dir`."""
    resolved_src = _validate_source_dir_no_symlink(source_dir)
    arc_root = root_name if root_name is not None else resolved_src.name
    dos_dt = parse_dos_timestamp(timestamp)
    dirs, files = _collect_canonical_entries(source_dir, arc_root)

    output_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr(_make_dir_zipinfo(f"{arc_root}/", dos_dt), b"")
        for d in dirs:
            zf.writestr(_make_dir_zipinfo(d, dos_dt), b"")
        for rel_posix, fpath in files:
            zf.writestr(_make_file_zipinfo(rel_posix, dos_dt), fpath.read_bytes())

    # Integrity verification immediately after creation
    with zipfile.ZipFile(output_zip, "r") as zf:
        bad = zf.testzip()
        if bad is not None:
            raise DeterministicZipError(f"Generated ZIP failed CRC integrity test at entry: {bad}")

    return {
        "output_zip": str(output_zip),
        "root_name": arc_root,
        "timestamp": timestamp,
        "normalized_utc_dos_tuple": list(dos_dt),
        "size_bytes": output_zip.stat().st_size,
        "sha256": sha256_file(output_zip),
        "file_count": len(files),
        "dir_count": len(dirs) + 1,
        "total_entries": len(files) + len(dirs) + 1,
    }


def verify_extract_parity(source_dir: Path, zip_path: Path, *, root_name: str | None = None) -> dict[str, object]:
    """Extract `zip_path` cleanly and verify 100% file-list and byte-for-byte parity with `source_dir`."""
    resolved_src = _validate_source_dir_no_symlink(source_dir)
    arc_root = root_name if root_name is not None else resolved_src.name
    _dirs, expected_files = _collect_canonical_entries(source_dir, arc_root)
    expected_map = {rel: path.read_bytes() for rel, path in expected_files}

    with tempfile.TemporaryDirectory(prefix="hrai_detzip_parity_") as td:
        td_path = Path(td)
        with zipfile.ZipFile(zip_path, "r") as zf:
            bad = zf.testzip()
            if bad is not None:
                raise DeterministicZipError(f"ZIP CRC verification failed at entry: {bad}")
            roots = sorted({i.filename.split("/", 1)[0] for i in zf.infolist()})
            if roots != [arc_root]:
                raise DeterministicZipError(f"Expected single root [{arc_root!r}], found {roots}")
            zf.extractall(td_path)

        ext_root = td_path / arc_root
        actual_files = sorted(
            f"{arc_root}/{p.relative_to(ext_root).as_posix()}"
            for p in ext_root.rglob("*")
            if p.is_file()
        )
        expected_keys = sorted(expected_map.keys())
        if actual_files != expected_keys:
            missing = sorted(set(expected_keys) - set(actual_files))
            extra = sorted(set(actual_files) - set(expected_keys))
            raise DeterministicZipError(f"Extracted file list mismatch: missing={missing}, extra={extra}")

        mismatches = [
            rel
            for rel in expected_keys
            if (td_path / rel).read_bytes() != expected_map[rel]
        ]
        if mismatches:
            raise DeterministicZipError(f"Extracted byte mismatch on files: {mismatches}")

    return {
        "parity_verified": True,
        "matched_files": len(expected_keys),
        "root_name": arc_root,
    }


def verify_reproducible_build(
    source_dir: Path,
    *,
    root_name: str | None = None,
    timestamp: str = CANONICAL_V1051_TIMESTAMP,
    extract_to: Path | None = None,
) -> dict[str, object]:
    """Build two independent deterministic ZIPs from `source_dir`, verify bit-for-bit equality & extract parity."""
    _validate_source_dir_no_symlink(source_dir)
    with tempfile.TemporaryDirectory(prefix="hrai_detzip_repro_") as td:
        td_path = Path(td)
        zip1 = td_path / "build_1.zip"
        zip2 = td_path / "build_2.zip"
        meta1 = build_deterministic_zip(source_dir, zip1, root_name=root_name, timestamp=timestamp)
        meta2 = build_deterministic_zip(source_dir, zip2, root_name=root_name, timestamp=timestamp)
        if meta1["sha256"] != meta2["sha256"] or meta1["size_bytes"] != meta2["size_bytes"]:
            raise DeterministicZipError(
                f"Non-deterministic ZIP build detected: build_1={meta1['sha256']} ({meta1['size_bytes']}B) "
                f"!= build_2={meta2['sha256']} ({meta2['size_bytes']}B)"
            )
        parity = verify_extract_parity(source_dir, zip1, root_name=root_name)

        extracted_path: str | None = None
        if extract_to is not None:
            if extract_to.exists():
                raise DeterministicZipError(f"Refusing to overwrite existing extract_to directory: {extract_to}")
            extract_to.mkdir(parents=True, exist_ok=False)
            with zipfile.ZipFile(zip1, "r") as zf:
                zf.extractall(extract_to)
            extracted_path = str(extract_to / meta1["root_name"])

    return {
        "reproducible": True,
        "build_1_sha256": meta1["sha256"],
        "build_2_sha256": meta2["sha256"],
        "size_bytes": meta1["size_bytes"],
        "file_count": meta1["file_count"],
        "dir_count": meta1["dir_count"],
        "root_name": meta1["root_name"],
        "timestamp": timestamp,
        "normalized_utc_dos_tuple": meta1["normalized_utc_dos_tuple"],
        "parity": parity,
        "extracted_root": extracted_path,
    }


def verify_frozen_archive_reproducibility(
    frozen_zip: Path,
    *,
    expected_sha256: str,
    expected_bytes: int,
    expected_root_dir: str,
    timestamp: str,
) -> dict[str, object]:
    """Verify frozen archive matches expected hash/size AND bit-for-bit reproduces when cleanly rebuilt."""
    actual_bytes = frozen_zip.stat().st_size
    actual_sha = sha256_file(frozen_zip)
    if actual_bytes != expected_bytes or actual_sha != expected_sha256:
        raise DeterministicZipError(
            f"Frozen archive mismatch for {frozen_zip}: got sha256={actual_sha} ({actual_bytes}B), "
            f"expected sha256={expected_sha256} ({expected_bytes}B)"
        )

    with tempfile.TemporaryDirectory(prefix="hrai_frozen_repro_") as td:
        td_path = Path(td)
        extract_dir = td_path / "extracted"
        extract_dir.mkdir()
        with zipfile.ZipFile(frozen_zip, "r") as zf:
            bad = zf.testzip()
            if bad is not None:
                raise DeterministicZipError(f"Frozen ZIP CRC failure at {bad}")
            zf.extractall(extract_dir)

        rebuilt_zip = td_path / "rebuilt.zip"
        rebuilt_meta = build_deterministic_zip(
            extract_dir / expected_root_dir,
            rebuilt_zip,
            root_name=expected_root_dir,
            timestamp=timestamp,
        )
        if rebuilt_meta["sha256"] != expected_sha256 or rebuilt_meta["size_bytes"] != expected_bytes:
            raise DeterministicZipError(
                f"Frozen archive {frozen_zip.name} failed bit-for-bit deterministic rebuild: "
                f"rebuilt={rebuilt_meta['sha256']} ({rebuilt_meta['size_bytes']}B) != "
                f"expected={expected_sha256} ({expected_bytes}B)"
            )

    return {
        "frozen_archive": str(frozen_zip),
        "expected_sha256": expected_sha256,
        "rebuilt_sha256": rebuilt_meta["sha256"],
        "size_bytes": rebuilt_meta["size_bytes"],
        "bit_for_bit_reproducible": True,
        "timestamp": timestamp,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="hrAI Deterministic ZIP Builder & Reproducibility Verifier")
    parser.add_argument("--source", type=Path, required=True, help="Source directory to package")
    parser.add_argument("--output", type=Path, default=None, help="Output ZIP path (build mode)")
    parser.add_argument("--root-name", type=str, default=None, help="Archive top-level directory name")
    parser.add_argument(
        "--timestamp",
        type=str,
        default=CANONICAL_V1051_TIMESTAMP,
        help="Strict UTC/offset ISO-8601 timestamp with even seconds (default: 2026-11-24T12:00:00)",
    )
    parser.add_argument(
        "--verify-reproducible",
        action="store_true",
        help="Build twice in isolated temp files, assert identical SHA-256 and 100% clean-extract parity",
    )
    parser.add_argument(
        "--extract-to",
        type=Path,
        default=None,
        help="When used with --verify-reproducible, extract verified build_1 archive into this clean directory",
    )
    args = parser.parse_args(argv)

    try:
        if args.verify_reproducible:
            report = verify_reproducible_build(
                args.source,
                root_name=args.root_name,
                timestamp=args.timestamp,
                extract_to=args.extract_to,
            )
        else:
            if args.output is None:
                raise DeterministicZipError("Either --output or --verify-reproducible must be provided.")
            report = build_deterministic_zip(
                args.source,
                args.output,
                root_name=args.root_name,
                timestamp=args.timestamp,
            )
    except DeterministicZipError as exc:
        print(json.dumps({"status": "FAILED", "error": str(exc)}, indent=2), file=sys.stderr)
        return 1

    print(json.dumps({"status": "PASS", **report}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
