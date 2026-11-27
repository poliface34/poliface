"""WP-4.7 tests: `ci.release_package_policy` installs the project's HOLDOUT access guard (audit hook).

Synthetic trees only: a copy of `engine/holdout_access_guard.py` and a synthetic registry/vault are
placed in a temporary source tree. After `build_package`, the synthetic vault is refused before the OS
opens it. The real HOLDOUT vault file is never touched by these tests.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from ci import release_package_policy as rpp

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
GUARD_SRC = REPO_ROOT / "hrai_hukuk_sgk" / rpp.GUARD_RELPATH
CI_MARKERS = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "JENKINS_URL", "TF_BUILD", "CIRCLECI")


def _custodian_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in CI_MARKERS}
    env["HOLDOUT_ACCESS_ALLOWED"] = "true"
    return env


def _tree(root: Path, with_guard: bool) -> tuple[Path, Path]:
    src = root / "pkg"
    vault = src / "engine" / "evaluation" / "datasets" / "wp47_policy_synthetic_vault.json"
    vault.parent.mkdir(parents=True)
    (src / "engine" / "evaluation" / "governance").mkdir(parents=True)
    (src / "engine" / "code.py").write_text("x = 1\n", encoding="utf-8")
    vault.write_bytes(b'{"synthetic": true}\n')
    (src / rpp.DEFAULT_REGISTRY_RELPATH).write_text(json.dumps({
        "schema": rpp.REGISTRY_SCHEMA,
        "vaults": [{"vault_id": "SYNTH", "file_relpath": vault.relative_to(src).as_posix(),
                    "file_sha256": "0" * 64}],
    }), encoding="utf-8")
    if with_guard:
        shutil.copyfile(GUARD_SRC, src / rpp.GUARD_RELPATH)
    return src, vault


class TestPackagePolicyAccessGuardWp47(unittest.TestCase):
    def test_01_build_installs_guard_and_blocks_vault_open(self) -> None:
        """build_package korumayı kurar; ardından sentetik kasa açılmadan engellenir, paket kasasızdır."""
        td = Path(tempfile.mkdtemp(prefix="hrai_wp47_pol_"))
        try:
            src, vault = _tree(td, with_guard=True)
            rep = rpp.build_package(src, root_name="pkg", output=td / "p.zip")
            self.assertEqual(rep["excluded_relpaths"], [vault.relative_to(src).as_posix()])
            with self.assertRaises(PermissionError) as cm:
                open(vault, "rb")
            self.assertEqual(type(cm.exception).__name__, "HoldoutFileAccessBlocked")
            with self.assertRaises(PermissionError):
                shutil.copyfile(vault, td / "leak.json")
            self.assertFalse((td / "leak.json").exists())
        finally:
            with mock.patch.dict(os.environ, _custodian_env(), clear=True):
                shutil.rmtree(td)

    def test_02_missing_or_broken_guard_fails_closed(self) -> None:
        """Koruma modülü yoksa veya kurulamazsa install_source_access_guard paketlemeyi durdurur."""
        with tempfile.TemporaryDirectory(prefix="hrai_wp47_pol_") as td:
            src, _ = _tree(Path(td), with_guard=False)
            with self.assertRaises(rpp.PackagePolicyError):
                rpp.install_source_access_guard(src)
            (src / rpp.DEFAULT_REGISTRY_RELPATH).write_text("not json", encoding="utf-8")
            shutil.copyfile(GUARD_SRC, src / rpp.GUARD_RELPATH)
            with self.assertRaises(rpp.PackagePolicyError):
                rpp.install_source_access_guard(src)

    def test_03_verify_artifacts_cli_installs_guard(self) -> None:
        """verify-artifacts CLI korumayı kaynak ağaç için kurar ve PASS verir."""
        td = Path(tempfile.mkdtemp(prefix="hrai_wp47_pol_"))
        try:
            src, vault = _tree(td, with_guard=True)
            art = td / "art"
            art.mkdir()
            (art / "summary.json").write_text("{}", encoding="utf-8")
            with mock.patch("sys.stdout"):
                rc = rpp.main(["verify-artifacts", "--source", str(src), str(art)])
            self.assertEqual(rc, 0)
            with self.assertRaises(PermissionError):
                vault.read_bytes()
        finally:
            with mock.patch.dict(os.environ, _custodian_env(), clear=True):
                shutil.rmtree(td)


if __name__ == "__main__":
    unittest.main()
