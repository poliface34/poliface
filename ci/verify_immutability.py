"""Release Immutability Guard (hrAI @HukukSGK v1.0.6 WP-1).

Fail-closed verifier for `ci/release_immutability_manifest.json` with independent integrity anchoring:
  1. Verifies the manifest file's own SHA-256 against an independently pinned digest
     (`DEFAULT_EXPECTED_MANIFEST_SHA256` and/or CLI `--expected-manifest-sha256` passed by CI)
     so tampering with the manifest in-place fails closed immediately.
  2. Strictly validates the manifest schema:
     - Top-level JSON object with exact `schema_version == "1.0.6-wp1"`
     - Non-empty `frozen_archives` list (no duplicate releases) containing ALL required baseline
       releases (`v1.0.5`, `v1.0.5.1`) with required typed fields and exact baseline anchor digests
     - Non-empty `immutable_files` list (no duplicate names) containing ALL required protected core
       files (`xmldsig_core_invariant`) with required typed fields and exact baseline anchor digests
     - Empty lists, missing baseline entries, malformed JSON, or invalid field types ALWAYS fail.
  3. Verifies every declared frozen historical archive (`kadroai_hukuk_sgk.zip`,
     `hrai_hukuk_sgk_v1.0.5.1.zip`): byte size, SHA-256, ZIP CRC integrity, single root dir,
     exact file/dir counts, internal `xmldsig.py` SHA-256, and bit-for-bit deterministic rebuild
     reproducibility for `v1.0.5.1`.
  4. Verifies every declared active-branch immutable file (`hrai_hukuk_sgk/engine/esign5070/xmldsig.py`).
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile

from ci.deterministic_zip import (
    DeterministicZipError,
    parse_dos_timestamp,
    sha256_file,
    verify_frozen_archive_reproducibility,
)

DEFAULT_MANIFEST_PATH = Path(__file__).resolve().parent / "release_immutability_manifest.json"
DEFAULT_REPO_ROOT = Path(__file__).resolve().parent.parent

# Independent integrity anchors (fail-closed even if the manifest file itself is altered)
REQUIRED_MANIFEST_SCHEMA_VERSION = "1.0.6-wp1"
DEFAULT_EXPECTED_MANIFEST_SHA256 = "818089a7d066c44a1f26527b878fa5134ff4d9734640d0a2b73c0d5c0044fdf8"
REQUIRED_FROZEN_ARCHIVE_ANCHORS: dict[str, tuple[str, int]] = {
    "v1.0.5": ("97a555dcc20ef28adbeb8ff33f31ebe8a5cad2548a3ceeded099a2761039ea5e", 697340),
    "v1.0.5.1": ("69b67a5f9aee3377f6bc50c0ae1463cb8d205b550a9a2a9b1cfe0b5af67369bc", 782246),
}
REQUIRED_IMMUTABLE_FILE_ANCHORS: dict[str, tuple[str, int]] = {
    "xmldsig_core_invariant": ("b16207b5fb71d7c0d0372838411c7795459ac460c2ff232766ae230b9cbacf85", 82205),
}
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def _is_nonempty_str(val: object) -> bool:
    return isinstance(val, str) and bool(val.strip())


def _is_pos_int(val: object) -> bool:
    return isinstance(val, int) and not isinstance(val, bool) and val > 0


def _is_sha256_hex(val: object) -> bool:
    return isinstance(val, str) and bool(_SHA256_HEX_RE.fullmatch(val))


def _validate_manifest_schema(manifest: object) -> list[str]:
    """Strictly validate manifest structure, non-empty lists, required fields, and baseline anchors."""
    errors: list[str] = []
    if not isinstance(manifest, dict):
        return ["Manifest root must be a JSON object."]

    if manifest.get("schema_version") != REQUIRED_MANIFEST_SCHEMA_VERSION:
        errors.append(
            f"Manifest schema_version must be {REQUIRED_MANIFEST_SCHEMA_VERSION!r}, "
            f"got {manifest.get('schema_version')!r}"
        )

    archives = manifest.get("frozen_archives")
    if not isinstance(archives, list) or len(archives) == 0:
        errors.append("Manifest 'frozen_archives' must be a non-empty list.")
    else:
        seen_releases: set[str] = set()
        for idx, entry in enumerate(archives):
            if not isinstance(entry, dict):
                errors.append(f"frozen_archives[{idx}] must be a JSON object.")
                continue
            rel = entry.get("release")
            if not _is_nonempty_str(rel):
                errors.append(f"frozen_archives[{idx}].release must be a non-empty string.")
            elif rel in seen_releases:
                errors.append(f"Duplicate frozen_archives release entry: {rel!r}")
            else:
                seen_releases.add(rel)

            if not _is_nonempty_str(entry.get("path")):
                errors.append(f"frozen_archives[{idx}].path must be a non-empty string.")
            if not _is_sha256_hex(entry.get("expected_sha256")):
                errors.append(f"frozen_archives[{idx}].expected_sha256 must be a 64-char lowercase hex SHA-256.")
            if not _is_pos_int(entry.get("expected_bytes")):
                errors.append(f"frozen_archives[{idx}].expected_bytes must be a positive integer.")
            if not _is_nonempty_str(entry.get("expected_root_dir")):
                errors.append(f"frozen_archives[{idx}].expected_root_dir must be a non-empty string.")
            if not _is_pos_int(entry.get("expected_file_count")):
                errors.append(f"frozen_archives[{idx}].expected_file_count must be a positive integer.")
            if not _is_pos_int(entry.get("expected_dir_count")):
                errors.append(f"frozen_archives[{idx}].expected_dir_count must be a positive integer.")

            inner_map = entry.get("expected_internal_files_sha256")
            if not isinstance(inner_map, dict) or len(inner_map) == 0:
                errors.append(f"frozen_archives[{idx}].expected_internal_files_sha256 must be a non-empty object.")
            else:
                for k, v in inner_map.items():
                    if not _is_nonempty_str(k) or not _is_sha256_hex(v):
                        errors.append(
                            f"frozen_archives[{idx}].expected_internal_files_sha256 contains invalid pair: {k!r}: {v!r}"
                        )

            ts = entry.get("deterministic_rebuild_timestamp")
            if ts is not None:
                try:
                    parse_dos_timestamp(ts)
                except DeterministicZipError as exc:
                    errors.append(f"frozen_archives[{idx}].deterministic_rebuild_timestamp invalid: {exc}")
            elif rel == "v1.0.5.1":
                errors.append("frozen_archives entry 'v1.0.5.1' must define deterministic_rebuild_timestamp.")

            if isinstance(rel, str) and rel in REQUIRED_FROZEN_ARCHIVE_ANCHORS:
                anc_sha, anc_bytes = REQUIRED_FROZEN_ARCHIVE_ANCHORS[rel]
                if entry.get("expected_sha256") != anc_sha or entry.get("expected_bytes") != anc_bytes:
                    errors.append(
                        f"frozen_archives[{rel!r}] diverges from protected baseline anchor "
                        f"(manifest={entry.get('expected_sha256')}/{entry.get('expected_bytes')}B != "
                        f"anchor={anc_sha}/{anc_bytes}B)."
                    )

        missing_releases = sorted(set(REQUIRED_FROZEN_ARCHIVE_ANCHORS.keys()) - seen_releases)
        if missing_releases:
            errors.append(f"Manifest missing required frozen_archives releases: {missing_releases}")

    imm_files = manifest.get("immutable_files")
    if not isinstance(imm_files, list) or len(imm_files) == 0:
        errors.append("Manifest 'immutable_files' must be a non-empty list.")
    else:
        seen_names: set[str] = set()
        for idx, fentry in enumerate(imm_files):
            if not isinstance(fentry, dict):
                errors.append(f"immutable_files[{idx}] must be a JSON object.")
                continue
            fname = fentry.get("name")
            if not _is_nonempty_str(fname):
                errors.append(f"immutable_files[{idx}].name must be a non-empty string.")
            elif fname in seen_names:
                errors.append(f"Duplicate immutable_files name entry: {fname!r}")
            else:
                seen_names.add(fname)

            if not _is_nonempty_str(fentry.get("path")):
                errors.append(f"immutable_files[{idx}].path must be a non-empty string.")
            if not _is_sha256_hex(fentry.get("expected_sha256")):
                errors.append(f"immutable_files[{idx}].expected_sha256 must be a 64-char lowercase hex SHA-256.")
            if not _is_pos_int(fentry.get("expected_bytes")):
                errors.append(f"immutable_files[{idx}].expected_bytes must be a positive integer.")

            if isinstance(fname, str) and fname in REQUIRED_IMMUTABLE_FILE_ANCHORS:
                anc_sha, anc_bytes = REQUIRED_IMMUTABLE_FILE_ANCHORS[fname]
                if fentry.get("expected_sha256") != anc_sha or fentry.get("expected_bytes") != anc_bytes:
                    errors.append(
                        f"immutable_files[{fname!r}] diverges from protected baseline anchor "
                        f"(manifest={fentry.get('expected_sha256')}/{fentry.get('expected_bytes')}B != "
                        f"anchor={anc_sha}/{anc_bytes}B)."
                    )

        missing_names = sorted(set(REQUIRED_IMMUTABLE_FILE_ANCHORS.keys()) - seen_names)
        if missing_names:
            errors.append(f"Manifest missing required immutable_files records: {missing_names}")

    return errors


def verify_immutability(
    repo_root: Path = DEFAULT_REPO_ROOT,
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
    *,
    expected_manifest_sha256: str | None = DEFAULT_EXPECTED_MANIFEST_SHA256,
) -> tuple[bool, dict[str, object]]:
    """Verify manifest integrity, strict schema, frozen archives, deterministic rebuilds, and immutable files."""
    failures: list[str] = []
    archive_results: list[dict[str, object]] = []
    file_results: list[dict[str, object]] = []

    if not manifest_path.is_file():
        msg = f"Immutability manifest missing: {manifest_path}"
        return False, {
            "schema_version": None,
            "status": "FAILED",
            "manifest_integrity": {"passed": False, "error": msg},
            "frozen_archives": [],
            "immutable_files": [],
            "failures": [msg],
        }

    actual_manifest_sha = sha256_file(manifest_path)
    manifest_integrity: dict[str, object] = {
        "manifest_path": str(manifest_path),
        "actual_sha256": actual_manifest_sha,
        "expected_sha256": expected_manifest_sha256,
        "passed": True,
    }
    if expected_manifest_sha256 is not None:
        if not _is_sha256_hex(expected_manifest_sha256):
            msg = f"Invalid expected_manifest_sha256 argument: {expected_manifest_sha256!r}"
            manifest_integrity["passed"] = False
            failures.append(msg)
        elif actual_manifest_sha != expected_manifest_sha256:
            msg = (
                f"Manifest SHA-256 mismatch ({actual_manifest_sha} != {expected_manifest_sha256}); "
                "unauthorized or unpinned manifest modification rejected fail-closed."
            )
            manifest_integrity["passed"] = False
            failures.append(msg)

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        msg = f"Manifest JSON parse failed: {exc}"
        failures.append(msg)
        return False, {
            "schema_version": None,
            "status": "FAILED",
            "manifest_integrity": manifest_integrity,
            "frozen_archives": [],
            "immutable_files": [],
            "failures": failures,
        }

    schema_errors = _validate_manifest_schema(manifest)
    if schema_errors:
        failures.extend(schema_errors)
        return False, {
            "schema_version": manifest.get("schema_version") if isinstance(manifest, dict) else None,
            "status": "FAILED",
            "manifest_integrity": manifest_integrity,
            "frozen_archives": [],
            "immutable_files": [],
            "failures": failures,
        }

    for entry in manifest["frozen_archives"]:
        rel_path = entry["path"]
        zp = repo_root / rel_path
        row: dict[str, object] = {
            "release": entry["release"],
            "path": rel_path,
            "passed": False,
        }
        if not zp.is_file():
            msg = f"Frozen archive missing: {rel_path}"
            failures.append(msg)
            row["error"] = msg
            archive_results.append(row)
            continue

        actual_bytes = zp.stat().st_size
        actual_sha = sha256_file(zp)
        row["actual_bytes"] = actual_bytes
        row["actual_sha256"] = actual_sha
        row["expected_bytes"] = entry["expected_bytes"]
        row["expected_sha256"] = entry["expected_sha256"]

        entry_errors: list[str] = []
        if actual_bytes != entry["expected_bytes"]:
            entry_errors.append(
                f"{rel_path}: byte size mismatch ({actual_bytes} != {entry['expected_bytes']})"
            )
        if actual_sha != entry["expected_sha256"]:
            entry_errors.append(
                f"{rel_path}: SHA-256 mismatch ({actual_sha} != {entry['expected_sha256']})"
            )

        try:
            with zipfile.ZipFile(zp, "r") as zf:
                bad = zf.testzip()
                if bad is not None:
                    entry_errors.append(f"{rel_path}: ZIP CRC failure at entry {bad}")
                infos = zf.infolist()
                roots = sorted({i.filename.split("/", 1)[0] for i in infos})
                f_count = sum(1 for i in infos if not i.is_dir())
                d_count = sum(1 for i in infos if i.is_dir())
                row["roots"] = roots
                row["file_count"] = f_count
                row["dir_count"] = d_count
                if roots != [entry["expected_root_dir"]]:
                    entry_errors.append(
                        f"{rel_path}: expected root [{entry['expected_root_dir']!r}], got {roots}"
                    )
                if f_count != entry["expected_file_count"]:
                    entry_errors.append(
                        f"{rel_path}: file count mismatch ({f_count} != {entry['expected_file_count']})"
                    )
                if d_count != entry["expected_dir_count"]:
                    entry_errors.append(
                        f"{rel_path}: dir count mismatch ({d_count} != {entry['expected_dir_count']})"
                    )
                for inner_path, exp_inner_sha in entry["expected_internal_files_sha256"].items():
                    if inner_path not in zf.namelist():
                        entry_errors.append(f"{rel_path}: missing internal file {inner_path}")
                    else:
                        inner_sha = hashlib.sha256(zf.read(inner_path)).hexdigest()
                        if inner_sha != exp_inner_sha:
                            entry_errors.append(
                                f"{rel_path}:{inner_path}: SHA-256 mismatch ({inner_sha} != {exp_inner_sha})"
                            )
        except zipfile.BadZipFile as exc:
            entry_errors.append(f"{rel_path}: corrupt ZIP ({exc})")

        rebuild_ts = entry.get("deterministic_rebuild_timestamp")
        if rebuild_ts and not entry_errors:
            try:
                repro = verify_frozen_archive_reproducibility(
                    zp,
                    expected_sha256=entry["expected_sha256"],
                    expected_bytes=entry["expected_bytes"],
                    expected_root_dir=entry["expected_root_dir"],
                    timestamp=rebuild_ts,
                )
                row["deterministic_rebuild"] = repro
            except DeterministicZipError as exc:
                entry_errors.append(str(exc))

        if entry_errors:
            failures.extend(entry_errors)
            row["errors"] = entry_errors
        else:
            row["passed"] = True
        archive_results.append(row)

    for fentry in manifest["immutable_files"]:
        rel_path = fentry["path"]
        fp = repo_root / rel_path
        row = {
            "name": fentry["name"],
            "path": rel_path,
            "passed": False,
        }
        if not fp.is_file():
            msg = f"Immutable file missing: {rel_path}"
            failures.append(msg)
            row["error"] = msg
            file_results.append(row)
            continue

        actual_bytes = fp.stat().st_size
        actual_sha = sha256_file(fp)
        row["actual_bytes"] = actual_bytes
        row["actual_sha256"] = actual_sha
        row["expected_bytes"] = fentry["expected_bytes"]
        row["expected_sha256"] = fentry["expected_sha256"]

        f_errors: list[str] = []
        if actual_bytes != fentry["expected_bytes"]:
            f_errors.append(f"{rel_path}: byte size mismatch ({actual_bytes} != {fentry['expected_bytes']})")
        if actual_sha != fentry["expected_sha256"]:
            f_errors.append(f"{rel_path}: SHA-256 mismatch ({actual_sha} != {fentry['expected_sha256']})")
        if f_errors:
            failures.extend(f_errors)
            row["errors"] = f_errors
        else:
            row["passed"] = True
        file_results.append(row)

    # Extra safety guard: never allow zero verified items to pass
    if len(archive_results) < len(REQUIRED_FROZEN_ARCHIVE_ANCHORS) or len(file_results) < len(
        REQUIRED_IMMUTABLE_FILE_ANCHORS
    ):
        failures.append("Verified archive/file count below required baseline minimum.")

    passed = len(failures) == 0
    return passed, {
        "schema_version": manifest.get("schema_version"),
        "status": "PASS" if passed else "FAILED",
        "manifest_integrity": manifest_integrity,
        "frozen_archives": archive_results,
        "immutable_files": file_results,
        "failures": failures,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify frozen release archives and immutable core files.")
    parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument(
        "--expected-manifest-sha256",
        type=str,
        default=DEFAULT_EXPECTED_MANIFEST_SHA256,
        help="Independent SHA-256 digest pin for the immutability manifest file itself",
    )
    args = parser.parse_args(argv)

    ok, report = verify_immutability(
        repo_root=args.repo_root,
        manifest_path=args.manifest,
        expected_manifest_sha256=args.expected_manifest_sha256,
    )
    print(json.dumps(report, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
