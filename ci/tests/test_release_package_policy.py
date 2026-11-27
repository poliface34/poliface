"""WP-4.6 tests for `ci.release_package_policy` (registered vault file exclusion from packages & artifacts).

Synthetic source trees are used for negative cases. The live-repository test builds the real
`hrai_hukuk_sgk` package through the policy under an open/read guard proving that the registered
vault file (path taken from the registry) is never opened, and that it is absent from the ZIP, the
clean extract and the CI artifact candidates. The WP-1 builder `ci.deterministic_zip` is unchanged.
"""

from __future__ import annotations

import builtins
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

from ci import release_package_policy as rpp

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SOURCE = REPO_ROOT / "hrai_hukuk_sgk"


class _OpenGuard:
    def __init__(self, target: Path) -> None:
        self.target = target.resolve()
        self.hits: list[str] = []
        self._patches: list[mock._patch] = []

    def _check(self, p: object, api: str) -> None:
        try:
            if Path(os.fspath(p)).resolve() == self.target:  # type: ignore[arg-type]
                self.hits.append(api)
        except TypeError:
            pass

    def __enter__(self) -> "_OpenGuard":
        real_open, real_io_open, real_os_open = builtins.open, io.open, os.open
        g = self

        def t_open(f, *a, **k):
            g._check(f, "open")
            return real_open(f, *a, **k)

        def t_io_open(f, *a, **k):
            g._check(f, "io.open")
            return real_io_open(f, *a, **k)

        def t_os_open(f, *a, **k):
            g._check(f, "os.open")
            return real_os_open(f, *a, **k)

        self._patches = [mock.patch("builtins.open", t_open), mock.patch("io.open", t_io_open), mock.patch("os.open", t_os_open)]
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc: object) -> None:
        for p in reversed(self._patches):
            p.stop()


def _synthetic_tree(root: Path, sealed_bytes: bytes = b'{"sealed": true}\n') -> tuple[Path, str]:
    src = root / "pkg"
    (src / "engine" / "evaluation" / "governance").mkdir(parents=True)
    (src / "engine" / "evaluation" / "datasets").mkdir(parents=True)
    (src / "engine" / "code.py").write_text("x = 1\n", encoding="utf-8")
    (src / "engine" / "evaluation" / "datasets" / "dev.json").write_text("{}\n", encoding="utf-8")
    sealed = src / "engine" / "evaluation" / "datasets" / "sealed_vault.json"
    sealed.write_bytes(sealed_bytes)
    sha = hashlib.sha256(sealed_bytes).hexdigest()
    (src / rpp.DEFAULT_REGISTRY_RELPATH).write_text(
        json.dumps({
            "schema": rpp.REGISTRY_SCHEMA,
            "vaults": [{"vault_id": "SYNTH", "file_relpath": "engine/evaluation/datasets/sealed_vault.json", "file_sha256": sha}],
        }),
        encoding="utf-8",
    )
    return src, sha


class TestReleasePackagePolicyWp46(unittest.TestCase):
    def test_01_live_package_excludes_registered_vault_without_opening_it(self) -> None:
        """Gerçek paket: kasa dosyası açılmadan hariç tutulur; ZIP deterministik; extract ve artifact'lerde yok."""
        exclusions = rpp.load_exclusions(SOURCE)
        self.assertGreaterEqual(len(exclusions), 1)
        target = SOURCE / exclusions[0]["relpath"]
        with tempfile.TemporaryDirectory(prefix="hrai_wp46_pkg_") as td:
            td_p = Path(td)
            with _OpenGuard(target) as guard:
                rep = rpp.build_package(SOURCE, root_name="hrai_hukuk_sgk", verify_reproducible=True,
                                        extract_to=td_p / "extract")
                out = rpp.build_package(SOURCE, root_name="hrai_hukuk_sgk", output=td_p / "pkg.zip")
                art = rpp.verify_artifacts([td_p / "extract", td_p / "pkg.zip"], exclusions)
            self.assertEqual(guard.hits, [])
            self.assertTrue(rep["reproducible"])
            self.assertEqual(rep["build_1_sha256"], rep["build_2_sha256"])
            self.assertEqual(out["sha256"], rep["build_1_sha256"])  # --output and verify builds identical
            self.assertTrue(rep["parity"]["parity_verified"])
            self.assertEqual(rep["parity"]["matched_files"], rep["file_count"])
            self.assertGreaterEqual(rep["file_count"], 159)
            self.assertEqual(rep["excluded_relpaths"], [e["relpath"] for e in exclusions])
            self.assertEqual(rep["migration_state"], "NOT_VERIFIED")
            self.assertTrue(art["artifacts_exclude_vault_files"])
            ext_root = td_p / "extract" / "hrai_hukuk_sgk"
            self.assertFalse(os.path.lexists(ext_root / exclusions[0]["relpath"]))
            manifest = json.loads((ext_root / rpp.EXCLUSION_MANIFEST_NAME).read_text(encoding="utf-8"))
            self.assertIs(manifest["absence_means_migrated"], False)
            self.assertEqual(manifest["migration_state"], "NOT_VERIFIED")
            with zipfile.ZipFile(td_p / "pkg.zip") as zf:
                self.assertNotIn(f"hrai_hukuk_sgk/{exclusions[0]['relpath']}", zf.namelist())
        self.assertTrue(target.is_file())  # working-tree copy retained (not deleted, not renamed)

    def test_02_synthetic_build_is_deterministic_and_lists_files(self) -> None:
        """Sentetik ağaç: iki ayrı build aynı SHA-256; dosya listesi beklenen; kasa yok, manifest var."""
        with tempfile.TemporaryDirectory(prefix="hrai_wp46_pkg_") as td:
            src, _sha = _synthetic_tree(Path(td))
            a = rpp.build_package(src, root_name="pkg", output=Path(td) / "a.zip")
            b = rpp.build_package(src, root_name="pkg", output=Path(td) / "b.zip")
            self.assertEqual(a["sha256"], b["sha256"])
            with zipfile.ZipFile(Path(td) / "a.zip") as zf:
                files = sorted(n for n in zf.namelist() if not n.endswith("/"))
            self.assertEqual(files, sorted([
                "pkg/PACKAGE_EXCLUSION_MANIFEST.json",
                "pkg/engine/code.py",
                "pkg/engine/evaluation/datasets/dev.json",
                f"pkg/{rpp.DEFAULT_REGISTRY_RELPATH}",
            ]))

    def test_03_copies_by_other_name_and_artifacts_detected_by_registered_hash(self) -> None:
        """Kasa baytlarının başka adla kopyası paket ve artifact kontrolünde kayıtlı SHA-256 ile yakalanır."""
        with tempfile.TemporaryDirectory(prefix="hrai_wp46_pkg_") as td:
            src, _sha = _synthetic_tree(Path(td))
            (src / "engine" / "renamed_copy.json").write_bytes(b'{"sealed": true}\n')
            with self.assertRaises(rpp.PackagePolicyError):
                rpp.build_package(src, root_name="pkg", verify_reproducible=True, extract_to=Path(td) / "x")
            with self.assertRaises(rpp.PackagePolicyError):
                rpp.build_package(src, root_name="pkg", output=Path(td) / "c.zip")
            art_dir = Path(td) / "artifacts"
            art_dir.mkdir()
            (art_dir / "summary.json").write_text("{}", encoding="utf-8")
            excl = rpp.load_exclusions(src)
            self.assertTrue(rpp.verify_artifacts([art_dir], excl)["artifacts_exclude_vault_files"])
            (art_dir / "leak.bin").write_bytes(b'{"sealed": true}\n')
            with self.assertRaises(rpp.PackagePolicyError):
                rpp.verify_artifacts([art_dir], excl)
            (art_dir / "leak.bin").unlink()
            with zipfile.ZipFile(art_dir / "bundle.zip", "w") as zf:
                zf.writestr("x/sealed_vault.json", b"different bytes")
            with self.assertRaises(rpp.PackagePolicyError):
                rpp.verify_artifacts([art_dir], excl)
            with self.assertRaises(rpp.PackagePolicyError):
                rpp.verify_artifacts([art_dir / "missing.json"], excl)

    def test_04_registry_problems_fail_closed(self) -> None:
        """Kayıt defteri yok/bozuk/boş veya yol geçersizse paket üretilmez."""
        with tempfile.TemporaryDirectory(prefix="hrai_wp46_pkg_") as td:
            src, sha = _synthetic_tree(Path(td))
            reg = src / rpp.DEFAULT_REGISTRY_RELPATH
            bad_payloads = [
                "not json",
                json.dumps({"schema": "other", "vaults": []}),
                json.dumps({"schema": rpp.REGISTRY_SCHEMA, "vaults": []}),
                json.dumps({"schema": rpp.REGISTRY_SCHEMA, "vaults": [{"vault_id": "V", "file_relpath": "/abs.json", "file_sha256": sha}]}),
                json.dumps({"schema": rpp.REGISTRY_SCHEMA, "vaults": [{"vault_id": "V", "file_relpath": "../x.json", "file_sha256": sha}]}),
                json.dumps({"schema": rpp.REGISTRY_SCHEMA, "vaults": [{"vault_id": "V", "file_relpath": "a.json", "file_sha256": "XYZ"}]}),
            ]
            for payload in bad_payloads:
                with self.subTest(payload=payload[:40]):
                    reg.write_text(payload, encoding="utf-8")
                    with self.assertRaises(rpp.PackagePolicyError):
                        rpp.build_package(src, root_name="pkg", output=Path(td) / "z.zip")
            reg.unlink()
            with self.assertRaises(rpp.PackagePolicyError):
                rpp.load_exclusions(src)

    def test_05_symlinks_and_reserved_names_rejected(self) -> None:
        """Kaynakta symlink veya ayrılmış manifest adı varsa fail-closed."""
        with tempfile.TemporaryDirectory(prefix="hrai_wp46_pkg_") as td:
            src, _ = _synthetic_tree(Path(td))
            (src / "link.json").symlink_to(src / "engine" / "code.py")
            with self.assertRaises(rpp.PackagePolicyError):
                rpp.build_package(src, root_name="pkg", output=Path(td) / "s.zip")
            (src / "link.json").unlink()
            (src / rpp.EXCLUSION_MANIFEST_NAME).write_text("{}", encoding="utf-8")
            with self.assertRaises(rpp.PackagePolicyError):
                rpp.build_package(src, root_name="pkg", output=Path(td) / "r.zip")

    def test_06_cli_reports_pass_and_failed(self) -> None:
        """CLI: başarıda PASS JSON ve 0; hatada FAILED ve 1."""
        with tempfile.TemporaryDirectory(prefix="hrai_wp46_pkg_") as td:
            src, _ = _synthetic_tree(Path(td))
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = rpp.main(["build", "--source", str(src), "--root-name", "pkg", "--verify-reproducible",
                               "--extract-to", str(Path(td) / "e")])
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(buf.getvalue())["status"], "PASS")
            err = io.StringIO()
            with mock.patch("sys.stderr", err):
                rc2 = rpp.main(["build", "--source", str(Path(td) / "nope"), "--root-name", "pkg", "--output", str(Path(td) / "n.zip")])
            self.assertEqual(rc2, 1)
            self.assertEqual(json.loads(err.getvalue())["status"], "FAILED")


if __name__ == "__main__":
    unittest.main()
