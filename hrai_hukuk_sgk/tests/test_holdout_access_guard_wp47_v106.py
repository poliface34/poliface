"""WP-4.7 tests for the process-wide HOLDOUT access guard (HOLDOUT_ACCESS_ALLOWED=false by default).

Every attempt against the REAL registered vault path is made only while two independent layers are
armed: the engine guard (installed when `engine` is imported) and a test-local sentinel audit hook
added after it. If the engine guard ever failed to raise, the sentinel would still stop the call before
the operating system opens the file and the test would fail on the exception type. The real vault
file is therefore never opened, read, hashed, parsed, copied, renamed or deleted here; only read-only
APIs are attempted against it. Destructive APIs (remove/rename/truncate/link) are exercised against a
synthetic protected file registered from a synthetic registry. The protected path is taken from the
registry metadata only. No file content is logged.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import engine  # noqa: F401  (importing the package installs the guard)
from engine import holdout_access_guard as hag
from engine.evaluation import holdout_vault as hv
from engine.evaluation import load_evaluation_dataset

PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SCAN_TESTS = (
    "tests/test_esign_5070_v104.py",
    "tests/test_trust_root_v103.py",
    "tests/test_verification_engine.py",
)

_SENTINEL = {"armed": False, "paths": frozenset(), "hits": []}


class _SentinelStop(AssertionError):
    """Raised only if the engine guard let a protected-path event through (second layer)."""


def _sentinel_hook(event: str, args: tuple) -> None:
    if not _SENTINEL["armed"] or event not in hag._PATH_EVENTS:
        return
    for i in hag._PATH_EVENTS[event]:
        if i < len(args) and not isinstance(args[i], int) and args[i] is not None:
            try:
                p = os.fsdecode(os.fspath(args[i]))
            except TypeError:
                continue
            if os.path.realpath(p) in _SENTINEL["paths"]:
                _SENTINEL["hits"].append(event)
                raise _SentinelStop(f"engine guard did not stop '{event}'")


sys.addaudithook(_sentinel_hook)


def _stat_tuple(p: Path) -> tuple | None:
    if not os.path.lexists(p):
        return None
    st = os.stat(p)  # metadata only
    return (st.st_ino, st.st_size, st.st_mtime_ns, st.st_mode)


def _no_ci_allowed_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in hag.CI_MARKERS}
    env[hag.HOLDOUT_ACCESS_ENV] = "true"
    return env


class TestHoldoutAccessGuardWp47(unittest.TestCase):
    def setUp(self) -> None:
        self.real = [Path(p) for p in hag.protected_holdout_paths(PROJECT_ROOT)]
        self.assertGreaterEqual(len(self.real), 1)
        self.before = {p: _stat_tuple(p) for p in self.real}
        _SENTINEL["paths"] = frozenset(str(p) for p in self.real)
        _SENTINEL["hits"] = []
        _SENTINEL["armed"] = True

    def tearDown(self) -> None:
        _SENTINEL["armed"] = False
        self.assertEqual(_SENTINEL["hits"], [], "second layer had to stop an access")
        for p in self.real:
            self.assertEqual(_stat_tuple(p), self.before[p], "protected file metadata changed")

    def _assert_blocked(self, fn, label: str) -> None:
        n0 = len(hag.blocked_attempts())
        with self.assertRaises(hag.HoldoutFileAccessBlocked, msg=label):
            fn()
        after = hag.blocked_attempts()
        self.assertEqual(len(after), n0 + 1, label)
        event, detail = after[-1]
        names = {p.name for p in self.real}
        self.assertTrue(detail in names or detail == "argv mentions a protected HOLDOUT file", label)

    def test_01_guard_installed_default_denied_paths_from_registry(self) -> None:
        """Koruma motor import'unda kurulu; varsayılan HOLDOUT_ACCESS_ALLOWED=false; yollar yalnız registry'den."""
        self.assertTrue(hag.guard_installed())
        self.assertFalse(hag.holdout_access_allowed())
        self.assertNotEqual(os.environ.get(hag.HOLDOUT_ACCESS_ENV, ""), "true")
        expected = {os.path.realpath(PROJECT_ROOT / rel) for rel in hv.package_exclusion_relpaths()}
        self.assertEqual({str(p) for p in self.real}, expected)
        self.assertTrue(expected.issubset(set(hag.guarded_paths())))
        self.assertIn(str(PROJECT_ROOT.resolve()), hag._state["roots"])

    def test_02_allowed_only_for_exact_true_outside_ci(self) -> None:
        """İzin yalnız tam 'true' ve CI işareti yokken; CI'da koşulsuz ret."""
        f = hag.holdout_access_allowed
        self.assertFalse(f({}))
        for v in ("", "false", "TRUE", "True", "1", "yes", " tru"):
            self.assertFalse(f({hag.HOLDOUT_ACCESS_ENV: v}), v)
        self.assertTrue(f({hag.HOLDOUT_ACCESS_ENV: "true"}))
        self.assertTrue(f({hag.HOLDOUT_ACCESS_ENV: " true "}))
        for marker in hag.CI_MARKERS:
            self.assertFalse(f({hag.HOLDOUT_ACCESS_ENV: "true", marker: "true"}), marker)
            self.assertFalse(f({hag.HOLDOUT_ACCESS_ENV: "true", marker: "1"}), marker)
            self.assertTrue(f({hag.HOLDOUT_ACCESS_ENV: "true", marker: "false"}), marker)

    def test_03_read_apis_on_real_path_blocked_before_open(self) -> None:
        """Gerçek kasa yolu: builtins/io/os.open, pathlib, shutil, zip kaynaklı tüm okumalar açılmadan engellenir."""
        p = self.real[0]
        with tempfile.TemporaryDirectory(prefix="hrai_wp47_guard_") as td:
            dst = Path(td) / "copy.bin"
            attempts = [
                ("builtins.open r", lambda: open(p, "r", encoding="utf-8")),
                ("builtins.open rb", lambda: open(p, "rb")),
                ("builtins.open str", lambda: open(str(p), "rb")),
                ("builtins.open bytes", lambda: open(os.fsencode(str(p)), "rb")),
                ("io.open", lambda: io.open(p, "rb")),
                ("os.open", lambda: os.open(p, os.O_RDONLY)),
                ("Path.read_bytes", lambda: p.read_bytes()),
                ("Path.read_text", lambda: p.read_text(encoding="utf-8")),
                ("Path.open", lambda: p.open("rb")),
                ("shutil.copyfile", lambda: shutil.copyfile(p, dst)),
                ("shutil.copy", lambda: shutil.copy(p, dst)),
                ("relative path", lambda: open(os.path.relpath(p), "rb")),
            ]
            for label, fn in attempts:
                with self.subTest(api=label):
                    self._assert_blocked(fn, label)
            self.assertFalse(dst.exists())

    def test_04_subprocess_naming_protected_file_refused(self) -> None:
        """Korunan dosyayı argv'de anan alt süreç başlatılmadan reddedilir."""
        p = self.real[0]
        self._assert_blocked(lambda: subprocess.run([sys.executable, "-c", "pass", str(p)], check=False, timeout=30, stdin=subprocess.DEVNULL), "argv")
        self._assert_blocked(lambda: subprocess.run(["cat", p.name], check=False, timeout=30, stdin=subprocess.DEVNULL), "argv name")
        r = subprocess.run([sys.executable, "-c", "pass"], check=False, timeout=30, stdin=subprocess.DEVNULL)  # unrelated launches unaffected
        self.assertEqual(r.returncode, 0)

    def test_05_engine_loader_explicit_path_blocked(self) -> None:
        """Motor yükleyicisine kasa yolu açıkça verilse bile dosya açılmadan engellenir (grant yok)."""
        p = self.real[0]
        self._assert_blocked(lambda: load_evaluation_dataset(dataset_path=p), "loader")

    def test_06_allowed_env_with_ci_marker_still_blocked(self) -> None:
        """HOLDOUT_ACCESS_ALLOWED=true olsa da CI işareti varken erişim engellenir."""
        p = self.real[0]
        env = _no_ci_allowed_env()
        env["CI"] = "true"
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertFalse(hag.holdout_access_allowed())
            self._assert_blocked(lambda: open(p, "rb"), "ci+allowed")

    def test_07_destructive_apis_blocked_on_synthetic_protected_file(self) -> None:
        """Sentetik korunan dosya: silme/yeniden adlandırma/kısaltma/link/taşıma engellenir; içerik değişmez."""
        td = Path(tempfile.mkdtemp(prefix="hrai_wp47_guard_"))
        root = td / "pkg"
        vault = root / "engine" / "evaluation" / "datasets" / "wp47_synthetic_protected.json"
        vault.parent.mkdir(parents=True)
        reg = root / hag.REGISTRY_RELPATH
        reg.parent.mkdir(parents=True)
        payload = b'{"synthetic": true}\n'
        vault.write_bytes(payload)
        reg.write_text(json.dumps({
            "schema": hag.REGISTRY_SCHEMA,
            "vaults": [{"file_relpath": vault.relative_to(root).as_posix()}],
        }), encoding="utf-8")
        try:
            hag.install_holdout_access_guard(root)
            self.assertIn(os.path.realpath(vault), hag.guarded_paths())
            st0 = _stat_tuple(vault)
            other = td / "other.json"
            attempts = [
                ("open", lambda: open(vault, "rb")),
                ("open w", lambda: open(vault, "wb")),
                ("os.remove", lambda: os.remove(vault)),
                ("Path.unlink", lambda: vault.unlink()),
                ("os.rename", lambda: os.rename(vault, other)),
                ("os.replace", lambda: os.replace(vault, other)),
                ("os.truncate", lambda: os.truncate(vault, 0)),
                ("os.link", lambda: os.link(vault, other)),
                ("os.symlink", lambda: os.symlink(vault, other)),
                ("shutil.move", lambda: shutil.move(str(vault), str(other))),
            ]
            for label, fn in attempts:
                with self.subTest(api=label):
                    n0 = len(hag.blocked_attempts())
                    with self.assertRaises(hag.HoldoutFileAccessBlocked):
                        fn()
                    self.assertEqual(len(hag.blocked_attempts()), n0 + 1)
                    self.assertEqual(hag.blocked_attempts()[-1][1], vault.name)
            self.assertFalse(os.path.lexists(other))
            self.assertEqual(_stat_tuple(vault), st0)
            # custodian environment (exactly true, no CI marker): the synthetic file is readable
            with mock.patch.dict(os.environ, _no_ci_allowed_env(), clear=True):
                self.assertEqual(vault.read_bytes(), payload)
        finally:
            with mock.patch.dict(os.environ, _no_ci_allowed_env(), clear=True):
                shutil.rmtree(td)

    def test_08_registry_problems_fail_closed(self) -> None:
        """Registry yok/bozuk/boş veya yol dışarı taşıyorsa koruma kurulmaz, hata verilir."""
        with tempfile.TemporaryDirectory(prefix="hrai_wp47_guard_") as td:
            root = Path(td)
            with self.assertRaises(FileNotFoundError):
                hag.protected_holdout_paths(root)
            reg = root / hag.REGISTRY_RELPATH
            reg.parent.mkdir(parents=True)
            for bad in (
                {"schema": "other", "vaults": [{"file_relpath": "a.json"}]},
                {"schema": hag.REGISTRY_SCHEMA, "vaults": []},
                {"schema": hag.REGISTRY_SCHEMA, "vaults": [{"file_relpath": "/abs.json"}]},
                {"schema": hag.REGISTRY_SCHEMA, "vaults": [{"file_relpath": "../x.json"}]},
                {"schema": hag.REGISTRY_SCHEMA, "vaults": [{}]},
            ):
                with self.subTest(bad=str(bad)[:50]):
                    reg.write_text(json.dumps(bad), encoding="utf-8")
                    with self.assertRaises(RuntimeError):
                        hag.protected_holdout_paths(root)

    def test_09_metadata_allowed_and_blocked_log_has_no_content(self) -> None:
        """stat/exists serbest (okuma değil); engelleme kaydı yalnız olay adı ve dosya adı içerir."""
        p = self.real[0]
        os.path.exists(p)
        os.path.lexists(p)
        if os.path.lexists(p):
            os.stat(p)
        self._assert_blocked(lambda: open(p, "rb"), "log")
        for event, detail in hag.blocked_attempts():
            self.assertIsInstance(event, str)
            self.assertLessEqual(len(detail), 80)
            self.assertNotIn("{", detail)
            self.assertNotIn("\n", detail)

    def test_10_static_review_scan_tests_use_safe_walker(self) -> None:
        """Statik inceleme: 3 depo tarama testi kasa yolunu açmayan ortak yürüyücüyü kullanır."""
        for rel in _SCAN_TESTS:
            text = (PROJECT_ROOT / rel).read_text(encoding="utf-8")
            with self.subTest(file=rel):
                self.assertIn("repository_scan_files(PROJECT_ROOT", text)
                self.assertIn("assert_vaults_pinned_by_metadata(self, PROJECT_ROOT)", text)
                self.assertIn("assert_scan_routine_on_synthetic_fixture(self", text)
        init = (PROJECT_ROOT / "engine" / "__init__.py").read_text(encoding="utf-8")
        first_import = next(line for line in init.splitlines() if line.startswith(("from ", "import ")))
        self.assertIn("holdout_access_guard", first_import)


if __name__ == "__main__":
    unittest.main()
