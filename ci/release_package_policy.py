"""Release package & CI artifact exclusion policy for registered sealed evaluation vault files (WP-4.6).

Stdlib-only wrapper around the WP-1 deterministic ZIP builder (`ci.deterministic_zip`, unchanged):

  1. Reads ONLY the vault registry metadata (`vaults[].file_relpath`, `vaults[].file_sha256`).
  2. Stages a copy of the source tree that omits every registered vault file. Excluded files are
     identified by path alone and are never opened, read, hashed or parsed.
  3. Writes a deterministic `PACKAGE_EXCLUSION_MANIFEST.json` into the staged tree that records the
     exclusion (path + already-registered SHA-256) and states `migration_state = NOT_VERIFIED`:
     absence from a package is NOT evidence that the file was moved to an external vault.
  4. Builds twice with `ci.deterministic_zip.verify_reproducible_build` (bit-for-bit equality and
     clean-extract parity) and then checks the extracted tree / ZIP name list for the excluded paths
     and for any file whose SHA-256 equals a registered vault hash (copy under another name).

`verify-artifacts` applies the same name / registered-hash / ZIP-member checks to CI artifact
candidates (summary JSON files, step summary, ZIPs).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import zipfile

from ci.deterministic_zip import (
    CANONICAL_V1051_TIMESTAMP,
    DeterministicZipError,
    build_deterministic_zip,
    verify_reproducible_build,
)

DEFAULT_REGISTRY_RELPATH = "engine/evaluation/governance/holdout_vault_registry.json"
REGISTRY_SCHEMA = "hrai.holdout_vault_registry.v1"
EXCLUSION_MANIFEST_NAME = "PACKAGE_EXCLUSION_MANIFEST.json"
EXCLUSION_MANIFEST_SCHEMA = "hrai.release_package_exclusion_manifest.v1"
_SKIP_DIRS = frozenset({"__pycache__", ".pytest_cache", ".git"})
_SKIP_NAMES = frozenset({".DS_Store"})
_SKIP_SUFFIXES = (".pyc", ".pyo")


class PackagePolicyError(RuntimeError):
    """Raised when the exclusion policy cannot be applied or verified (fail-closed)."""


GUARD_RELPATH = "engine/holdout_access_guard.py"
_GUARD_MODULES: dict[str, object] = {}


def install_source_access_guard(source_dir: Path) -> tuple[str, ...]:
    """WP-4.7: install the project's process-wide HOLDOUT access guard (audit hook) for `source_dir`.

    Loaded by file path (stdlib only, no `engine` package import). After this, any attempt in this
    process to open/copy/rename a registered vault file, including from the unchanged WP-1 builder, is
    refused before the OS opens it. Fails closed when the guard module or registry is missing.
    """
    guard_path = (source_dir / GUARD_RELPATH).resolve()
    if not guard_path.is_file():
        raise PackagePolicyError(f"HOLDOUT access guard missing: {GUARD_RELPATH}")
    mod = _GUARD_MODULES.get("guard")
    if mod is None:
        spec = importlib.util.spec_from_file_location("hrai_holdout_access_guard_ci", guard_path)
        if spec is None or spec.loader is None:
            raise PackagePolicyError("Cannot load HOLDOUT access guard.")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        _GUARD_MODULES["guard"] = mod
    try:
        paths = mod.install_holdout_access_guard(source_dir)  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001 - any guard failure must stop packaging
        raise PackagePolicyError(f"HOLDOUT access guard could not be installed: {exc}") from exc
    return tuple(str(p) for p in paths)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_exclusions(source_dir: Path, registry_relpath: str = DEFAULT_REGISTRY_RELPATH) -> list[dict[str, str]]:
    """Return `[{relpath, file_name, registered_sha256, vault_id}]` from registry metadata (fail-closed)."""
    reg_path = source_dir / registry_relpath
    try:
        raw = json.loads(reg_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PackagePolicyError(f"Vault registry unreadable ({registry_relpath}): {exc}") from exc
    if not isinstance(raw, dict) or raw.get("schema") != REGISTRY_SCHEMA or not isinstance(raw.get("vaults"), list):
        raise PackagePolicyError(f"Vault registry schema must be {REGISTRY_SCHEMA} with a 'vaults' list.")
    out: list[dict[str, str]] = []
    for i, v in enumerate(raw["vaults"]):
        rel = v.get("file_relpath") if isinstance(v, dict) else None
        sha = v.get("file_sha256") if isinstance(v, dict) else None
        vid = v.get("vault_id") if isinstance(v, dict) else None
        if not isinstance(rel, str) or not rel or not isinstance(vid, str) or not vid:
            raise PackagePolicyError(f"vaults[{i}] needs file_relpath and vault_id.")
        p = Path(rel)
        if p.is_absolute() or ".." in p.parts or "\\" in rel:
            raise PackagePolicyError(f"vaults[{i}].file_relpath must be a relative POSIX path: {rel!r}")
        if not isinstance(sha, str) or len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise PackagePolicyError(f"vaults[{i}].file_sha256 must be lowercase hex SHA-256.")
        out.append({"relpath": p.as_posix(), "file_name": p.name, "registered_sha256": sha, "vault_id": vid})
    if not out:
        raise PackagePolicyError("Vault registry lists no vault files; refusing to build without an exclusion policy.")
    return sorted(out, key=lambda e: e["relpath"])


def exclusion_manifest_bytes(exclusions: list[dict[str, str]]) -> bytes:
    body = {
        "schema": EXCLUSION_MANIFEST_SCHEMA,
        "description": (
            "Registered sealed evaluation vault files are excluded from this package by path. "
            "Exclusion is NOT a migration: the files remain in the Git working tree and history, "
            "and the external vault is not verified."
        ),
        "excluded": [
            {
                "relpath": e["relpath"],
                "vault_id": e["vault_id"],
                "registered_sha256": e["registered_sha256"],
                "reason": "REGISTERED_VAULT_FILE_EXCLUDED_FROM_RELEASE_PACKAGES_AND_CI_ARTIFACTS",
            }
            for e in exclusions
        ],
        "migration_state": "NOT_VERIFIED",
        "absence_means_migrated": False,
        "working_tree_copy_retained": True,
        "registry_source": DEFAULT_REGISTRY_RELPATH,
    }
    return (json.dumps(body, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def stage_source(source_dir: Path, staging_dir: Path, exclusions: list[dict[str, str]]) -> dict[str, object]:
    """Copy `source_dir` into `staging_dir` minus excluded vault files; never touch excluded bytes."""
    if source_dir.is_symlink() or not source_dir.is_dir():
        raise PackagePolicyError(f"Source must be a real directory: {source_dir}")
    excluded = {e["relpath"] for e in exclusions}
    found_excluded: list[str] = []
    copied = 0
    for dirpath, dirnames, filenames in os.walk(source_dir):
        cur = Path(dirpath)
        rel_dir = cur.relative_to(source_dir)
        for d in list(dirnames):
            if (cur / d).is_symlink():
                raise PackagePolicyError(f"Symlink forbidden in package source: {cur / d}")
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        (staging_dir / rel_dir).mkdir(parents=True, exist_ok=True)
        for name in sorted(filenames):
            src = cur / name
            rel = (rel_dir / name).as_posix()
            if src.is_symlink():
                raise PackagePolicyError(f"Symlink forbidden in package source: {src}")
            if rel in excluded:
                found_excluded.append(rel)
                continue  # path-only decision: the excluded file is never opened
            if name in _SKIP_NAMES or name.endswith(_SKIP_SUFFIXES):
                continue
            if rel == EXCLUSION_MANIFEST_NAME:
                raise PackagePolicyError(f"Source already contains reserved file {EXCLUSION_MANIFEST_NAME}.")
            shutil.copyfile(src, staging_dir / rel)
            copied += 1
    (staging_dir / EXCLUSION_MANIFEST_NAME).write_bytes(exclusion_manifest_bytes(exclusions))
    return {"copied_files": copied, "excluded_present_in_source": sorted(found_excluded)}


def check_tree_excludes(tree_root: Path, exclusions: list[dict[str, str]]) -> dict[str, object]:
    """Fail if any excluded path exists or any file's SHA-256 equals a registered vault hash."""
    registered = {e["registered_sha256"]: e["relpath"] for e in exclusions}
    names = {e["file_name"] for e in exclusions}
    present = [e["relpath"] for e in exclusions if os.path.lexists(tree_root / e["relpath"])]
    if present:
        raise PackagePolicyError(f"Excluded vault paths present in package tree: {present}")
    files = sorted(p for p in tree_root.rglob("*") if p.is_file())
    name_hits = [p.relative_to(tree_root).as_posix() for p in files if p.name in names]
    hash_hits = [p.relative_to(tree_root).as_posix() for p in files if _sha256_file(p) in registered]
    if name_hits or hash_hits:
        raise PackagePolicyError(f"Vault file copies found in package tree: names={name_hits} hashes={hash_hits}")
    rels = [p.relative_to(tree_root).as_posix() for p in files]
    if EXCLUSION_MANIFEST_NAME not in rels:
        raise PackagePolicyError(f"{EXCLUSION_MANIFEST_NAME} missing from package tree.")
    listing = "\n".join(rels).encode("utf-8")
    return {"files_checked": len(files), "file_list_sha256": hashlib.sha256(listing).hexdigest()}


def check_zip_excludes(zip_path: Path, root_name: str, exclusions: list[dict[str, str]]) -> dict[str, object]:
    registered = {e["registered_sha256"] for e in exclusions}
    names = {e["file_name"] for e in exclusions}
    forbidden = {f"{root_name}/{e['relpath']}" for e in exclusions}
    with zipfile.ZipFile(zip_path, "r") as zf:
        members = zf.namelist()
        bad = sorted(m for m in members if m in forbidden or m.rsplit("/", 1)[-1] in names)
        if bad:
            raise PackagePolicyError(f"Vault files present in ZIP {zip_path.name}: {bad}")
        hash_hits = [i.filename for i in zf.infolist() if not i.is_dir() and hashlib.sha256(zf.read(i)).hexdigest() in registered]
        if hash_hits:
            raise PackagePolicyError(f"Vault file copies (by registered hash) in ZIP {zip_path.name}: {hash_hits}")
        if f"{root_name}/{EXCLUSION_MANIFEST_NAME}" not in members:
            raise PackagePolicyError(f"{EXCLUSION_MANIFEST_NAME} missing from ZIP {zip_path.name}.")
    return {"zip_members": len(members), "zip_excludes_vault_files": True}


def build_package(
    source_dir: Path,
    *,
    root_name: str,
    timestamp: str = CANONICAL_V1051_TIMESTAMP,
    output: Path | None = None,
    verify_reproducible: bool = False,
    extract_to: Path | None = None,
    registry_relpath: str = DEFAULT_REGISTRY_RELPATH,
) -> dict[str, object]:
    exclusions = load_exclusions(source_dir, registry_relpath)
    if (source_dir / GUARD_RELPATH).exists():
        install_source_access_guard(source_dir)
    with tempfile.TemporaryDirectory(prefix="hrai_pkgpolicy_") as td:
        staging = Path(td) / root_name
        staging.mkdir()
        stage_info = stage_source(source_dir, staging, exclusions)
        report: dict[str, object] = {}
        if verify_reproducible:
            report.update(verify_reproducible_build(staging, root_name=root_name, timestamp=timestamp, extract_to=extract_to))
            if extract_to is not None:
                report["extract_check"] = check_tree_excludes(extract_to / root_name, exclusions)
            # Re-check the archive bytes themselves (name list + registered hashes).
            check_zip = Path(td) / "policy_check.zip"
            meta = build_deterministic_zip(staging, check_zip, root_name=root_name, timestamp=timestamp)
            if meta["sha256"] != report["build_1_sha256"]:
                raise PackagePolicyError("Policy check build differs from reproducible build.")
            report["zip_check"] = check_zip_excludes(check_zip, root_name, exclusions)
        if output is not None:
            meta = build_deterministic_zip(staging, output, root_name=root_name, timestamp=timestamp)
            report.update({"output_zip": str(output), "sha256": meta["sha256"], "size_bytes": meta["size_bytes"],
                           "file_count": meta["file_count"]})
            report["zip_check"] = check_zip_excludes(output, root_name, exclusions)
        if not verify_reproducible and output is None:
            raise PackagePolicyError("Either --output or --verify-reproducible must be provided.")
    report["excluded_relpaths"] = [e["relpath"] for e in exclusions]
    report["excluded_present_in_source"] = stage_info["excluded_present_in_source"]
    report["exclusion_manifest_sha256"] = hashlib.sha256(exclusion_manifest_bytes(exclusions)).hexdigest()
    report["migration_state"] = "NOT_VERIFIED"
    return report


def verify_artifacts(paths: list[Path], exclusions: list[dict[str, str]], *, root_name: str | None = None) -> dict[str, object]:
    """Check CI artifact candidates by name, registered hash and (for ZIPs) member names."""
    registered = {e["registered_sha256"] for e in exclusions}
    names = {e["file_name"] for e in exclusions}
    checked: list[str] = []
    problems: list[str] = []
    for base in paths:
        if not os.path.lexists(base):
            problems.append(f"missing:{base}")
            continue
        candidates = sorted(p for p in base.rglob("*") if p.is_file()) if base.is_dir() else [base]
        for f in candidates:
            if f.is_symlink():
                problems.append(f"symlink:{f}")
                continue
            checked.append(str(f))
            if f.name in names:
                problems.append(f"name:{f}")
            if _sha256_file(f) in registered:
                problems.append(f"registered_hash:{f}")
            if zipfile.is_zipfile(f):
                with zipfile.ZipFile(f) as zf:
                    for m in zf.namelist():
                        if m.rsplit("/", 1)[-1] in names:
                            problems.append(f"zip_member:{f}!{m}")
    if problems:
        raise PackagePolicyError(f"CI artifact candidates contain vault material: {problems}")
    return {"artifact_candidates_checked": len(checked), "artifacts_exclude_vault_files": True}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Registered vault file exclusion for release packages and CI artifacts")
    sub = parser.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="Stage without vault files and build/verify the deterministic ZIP")
    b.add_argument("--source", type=Path, required=True)
    b.add_argument("--root-name", type=str, required=True)
    b.add_argument("--timestamp", type=str, default=CANONICAL_V1051_TIMESTAMP)
    b.add_argument("--output", type=Path, default=None)
    b.add_argument("--verify-reproducible", action="store_true")
    b.add_argument("--extract-to", type=Path, default=None)
    b.add_argument("--registry-relpath", type=str, default=DEFAULT_REGISTRY_RELPATH)
    a = sub.add_parser("verify-artifacts", help="Check CI artifact candidates for vault files")
    a.add_argument("--source", type=Path, required=True)
    a.add_argument("--registry-relpath", type=str, default=DEFAULT_REGISTRY_RELPATH)
    a.add_argument("paths", type=Path, nargs="+")
    args = parser.parse_args(argv)
    try:
        if args.cmd == "build":
            report = build_package(
                args.source, root_name=args.root_name, timestamp=args.timestamp, output=args.output,
                verify_reproducible=args.verify_reproducible, extract_to=args.extract_to,
                registry_relpath=args.registry_relpath,
            )
        else:
            install_source_access_guard(args.source)
            report = verify_artifacts(args.paths, load_exclusions(args.source, args.registry_relpath))
    except (PackagePolicyError, DeterministicZipError) as exc:
        print(json.dumps({"status": "FAILED", "error": str(exc)}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps({"status": "PASS", **report}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
