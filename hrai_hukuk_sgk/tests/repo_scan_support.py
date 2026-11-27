"""WP-4.7 support for repository-wide private-key scans that must never open the HOLDOUT vault file.

The three historical "zero private keys anywhere in the repository" tests walk the whole project tree.
Before WP-4.7 that walk opened the registered HOLDOUT vault file as text. These helpers keep the scans'
purpose and file coverage while:

  * skipping registered vault paths by path (from registry metadata) BEFORE any open,
  * proving the skipped file is still the historically pinned object via metadata only
    (Git index blob id + on-disk size, or the package exclusion manifest in a clean extract): the
    pinned object already passed these scans in earlier CI runs, so an unchanged object needs no re-read,
  * exercising the very same scan routine on a controlled synthetic fixture (planted marker detected,
    synthetic "vault" never opened).

No file content and no HOLDOUT data is ever logged.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
import json
import os
from pathlib import Path
import tempfile
import unittest

from engine.holdout_access_guard import protected_holdout_paths


def registered_vault_paths(project_root: Path) -> frozenset[str]:
    return frozenset(str(p) for p in protected_holdout_paths(project_root))


def repository_scan_files(project_root: Path, include: Callable[[Path], bool]) -> list[Path]:
    """Sorted files under `project_root` accepted by `include`, minus registered vault paths (not opened)."""
    vaults = registered_vault_paths(project_root)
    out: list[Path] = []
    for p in sorted(project_root.rglob("*")):
        if os.path.realpath(p) in vaults:
            continue  # decided by path only; the vault file is never opened
        if p.is_file() and include(p):
            out.append(p)
    return out


def scan_files_for_markers(files: Iterable[Path], markers: Iterable[str]) -> list[str]:
    """The scan routine itself: returns `["<file>:<marker index>"]` hits (no content is returned)."""
    marks = list(markers)
    hits: list[str] = []
    for p in files:
        text = p.read_text(encoding="utf-8", errors="ignore")
        for i, mk in enumerate(marks):
            if mk in text:
                hits.append(f"{p}:{i}")
    return hits


def assert_vaults_pinned_by_metadata(tc: unittest.TestCase, project_root: Path) -> int:
    """Skipped vault files must still be the historically pinned objects (metadata only, no read)."""
    from engine.evaluation.holdout_vault import (
        load_historical_holdout_reference,
        load_package_exclusion_manifest,
        verify_holdout_git_metadata,
    )

    ref = load_historical_holdout_reference()
    meta = verify_holdout_git_metadata(project_root, ref.file_relpath, ref.git_blob_sha1, ref.size_bytes)
    if meta["mode"] == "GIT":
        tc.assertEqual(meta["git_blob_sha1"], ref.git_blob_sha1)
    else:
        pkg = load_package_exclusion_manifest(project_root)
        tc.assertIsNotNone(pkg, "Clean extract without PACKAGE_EXCLUSION_MANIFEST.json")
        tc.assertFalse(os.path.lexists(project_root / ref.file_relpath))
    return len(registered_vault_paths(project_root))


def assert_scan_routine_on_synthetic_fixture(
    tc: unittest.TestCase, markers: list[str], include: Callable[[Path], bool]
) -> None:
    """Run the real scan routine on a synthetic tree: planted marker found, synthetic vault never opened."""
    with tempfile.TemporaryDirectory(prefix="hrai_wp47_scan_") as td:
        root = Path(td) / "pkg"
        reg = root / "engine" / "evaluation" / "governance" / "holdout_vault_registry.json"
        reg.parent.mkdir(parents=True)
        (root / "engine" / "evaluation" / "datasets").mkdir(parents=True)
        vault = root / "engine" / "evaluation" / "datasets" / "synthetic_sealed_vault.json"
        vault.write_text(json.dumps({"synthetic": True}), encoding="utf-8")
        reg.write_text(json.dumps({
            "schema": "hrai.holdout_vault_registry.v1",
            "vaults": [{"file_relpath": "engine/evaluation/datasets/synthetic_sealed_vault.json"}],
        }), encoding="utf-8")
        clean = root / "engine" / "clean.json"
        clean.write_text('{"ok": true}\n', encoding="utf-8")
        planted = root / "engine" / "planted.json"
        planted.write_text("x\n" + markers[0] + "\nsynthetic\n", encoding="utf-8")
        files = repository_scan_files(root, include)
        tc.assertNotIn(vault, files)
        tc.assertIn(clean, files)
        hits = scan_files_for_markers(files, markers)
        tc.assertEqual(hits, [f"{planted}:0"])
        planted.unlink()
        tc.assertEqual(scan_files_for_markers(repository_scan_files(root, include), markers), [])
