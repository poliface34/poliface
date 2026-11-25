"""Release Immutability Guard (hrAI @HukukSGK v1.0.6 WP-1).

Verifies all entries declared in `ci/release_immutability_manifest.json`:
  1. Frozen historical release archives (`kadroai_hukuk_sgk.zip`, `hrai_hukuk_sgk_v1.0.5.1.zip`):
     - File existence, exact byte size, exact SHA-256 digest
     - ZIP CRC integrity (`testzip() is None`), single top-level root dir, exact file/dir counts
     - Internal protected file SHA-256 digests (`xmldsig.py`)
     - When `deterministic_rebuild_timestamp` is set (`v1.0.5.1`), extracts cleanly and rebuilds via
       `ci.deterministic_zip` asserting bit-for-bit SHA-256 & byte-size identity.
  2. Active-branch immutable core files (`hrai_hukuk_sgk/engine/esign5070/xmldsig.py`):
     - File existence, exact byte size, exact SHA-256 digest.

Fail-closed: returns non-zero exit code (1) on any mismatch, missing entry, or corruption.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import zipfile

from ci.deterministic_zip import (
    DeterministicZipError,
    sha256_file,
    verify_frozen_archive_reproducibility,
)

DEFAULT_MANIFEST_PATH = Path(__file__).resolve().parent / "release_immutability_manifest.json"
DEFAULT_REPO_ROOT = Path(__file__).resolve().parent.parent


def verify_immutability(
    repo_root: Path = DEFAULT_REPO_ROOT,
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
) -> tuple[bool, dict[str, object]]:
    """Verify every frozen archive and immutable file declared in `manifest_path`."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    failures: list[str] = []
    archive_results: list[dict[str, object]] = []
    file_results: list[dict[str, object]] = []

    for entry in manifest.get("frozen_archives", []):
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
                for inner_path, exp_inner_sha in entry.get("expected_internal_files_sha256", {}).items():
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

    for fentry in manifest.get("immutable_files", []):
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

    passed = len(failures) == 0
    return passed, {
        "schema_version": manifest.get("schema_version"),
        "status": "PASS" if passed else "FAILED",
        "frozen_archives": archive_results,
        "immutable_files": file_results,
        "failures": failures,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify frozen release archives and immutable core files.")
    parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST_PATH)
    args = parser.parse_args(argv)

    ok, report = verify_immutability(repo_root=args.repo_root, manifest_path=args.manifest)
    print(json.dumps(report, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
