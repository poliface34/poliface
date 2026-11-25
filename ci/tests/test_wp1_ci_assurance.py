"""Unit tests for hrAI @HukukSGK v1.0.6 WP-1 (CI Assurance, Deterministic ZIP & Immutability).

Verifies all WP-1 acceptance criteria (AC-1..AC-6):
  - AC-1: Frozen historical archive (`v1.0.5`, `v1.0.5.1`) & `xmldsig.py` exact SHA-256 / byte-size
          immutability plus fail-closed non-zero detection on single-byte tampering.
  - AC-2: Clean extraction and bit-for-bit deterministic rebuild of frozen `hrai_hukuk_sgk_v1.0.5.1.zip`
          reproducing `69b67a5f9aee3377f6bc50c0ae1463cb8d205b550a9a2a9b1cfe0b5af67369bc`.
  - AC-3: Deterministic ZIP invariance across differing mtimes/creation orders, exclusion of
          `__pycache__`/`.pyc`/`.DS_Store`, normalized UNIX ZipInfo headers, fail-closed rejection of
          symlinks, and odd-second DOS timestamp rejection.
  - AC-4: Active `hrai_hukuk_sgk/` double-build bit-for-bit reproducibility & 100% clean-extract parity.
  - AC-5: Static supply-chain audit of `.github/workflows/ci-assurance.yml` (pinned `ubuntu-24.04`,
          40-char commit-SHA GitHub Actions, pinned `pip==26.3`, `contents: read`, superseding
          legacy `verify-v1051.yml`).
"""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import unittest
import zipfile

from ci import deterministic_zip as dz
from ci import verify_immutability as vi

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class TestWp1CiAssurance(unittest.TestCase):
    def test_01_live_immutability_manifest_and_v1051_deterministic_rebuild_pass(self) -> None:
        ok, report = vi.verify_immutability(repo_root=REPO_ROOT)
        self.assertTrue(ok, json.dumps(report, indent=2))
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["failures"], [])

        by_rel = {a["release"]: a for a in report["frozen_archives"]}
        self.assertIn("v1.0.5", by_rel)
        self.assertIn("v1.0.5.1", by_rel)
        self.assertTrue(by_rel["v1.0.5"]["passed"])
        self.assertTrue(by_rel["v1.0.5.1"]["passed"])
        repro = by_rel["v1.0.5.1"]["deterministic_rebuild"]
        self.assertTrue(repro["bit_for_bit_reproducible"])
        self.assertEqual(
            repro["rebuilt_sha256"],
            "69b67a5f9aee3377f6bc50c0ae1463cb8d205b550a9a2a9b1cfe0b5af67369bc",
        )
        self.assertEqual(repro["size_bytes"], 782246)

        imm_files = {f["name"]: f for f in report["immutable_files"]}
        self.assertTrue(imm_files["xmldsig_core_invariant"]["passed"])
        self.assertEqual(
            imm_files["xmldsig_core_invariant"]["actual_sha256"],
            "b16207b5fb71d7c0d0372838411c7795459ac460c2ff232766ae230b9cbacf85",
        )

    def test_02_immutability_fails_closed_on_single_byte_tamper_zip_or_xmldsig(self) -> None:
        manifest_path = REPO_ROOT / "ci" / "release_immutability_manifest.json"
        with tempfile.TemporaryDirectory(prefix="hrai_wp1_tamper_") as td:
            fake_root = Path(td)
            shutil.copy2(REPO_ROOT / "kadroai_hukuk_sgk.zip", fake_root / "kadroai_hukuk_sgk.zip")
            shutil.copy2(REPO_ROOT / "hrai_hukuk_sgk_v1.0.5.1.zip", fake_root / "hrai_hukuk_sgk_v1.0.5.1.zip")
            xmldsig_dst = fake_root / "hrai_hukuk_sgk" / "engine" / "esign5070" / "xmldsig.py"
            xmldsig_dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO_ROOT / "hrai_hukuk_sgk" / "engine" / "esign5070" / "xmldsig.py", xmldsig_dst)

            # Baseline copy passes
            ok_base, _ = vi.verify_immutability(repo_root=fake_root, manifest_path=manifest_path)
            self.assertTrue(ok_base)

            # 1. Flip 1 byte in xmldsig.py -> must fail with non-zero CLI exit code (1)
            orig_xml = xmldsig_dst.read_bytes()
            tampered_xml = bytearray(orig_xml)
            tampered_xml[-1] ^= 0x01
            xmldsig_dst.write_bytes(bytes(tampered_xml))
            ok_xml, rep_xml = vi.verify_immutability(repo_root=fake_root, manifest_path=manifest_path)
            self.assertFalse(ok_xml)
            self.assertEqual(rep_xml["status"], "FAILED")
            self.assertTrue(any("xmldsig.py" in f for f in rep_xml["failures"]))
            cli_buf = io.StringIO()
            with redirect_stdout(cli_buf):
                cli_rc = vi.main(["--repo-root", str(fake_root), "--manifest", str(manifest_path)])
            self.assertEqual(cli_rc, 1)
            self.assertEqual(json.loads(cli_buf.getvalue())["status"], "FAILED")
            xmldsig_dst.write_bytes(orig_xml)

            # 2. Append 1 byte to frozen v1.0.5.1 ZIP -> must fail on both size and SHA-256
            zp = fake_root / "hrai_hukuk_sgk_v1.0.5.1.zip"
            orig_zip = zp.read_bytes()
            zp.write_bytes(orig_zip + b"\x00")
            ok_zip, rep_zip = vi.verify_immutability(repo_root=fake_root, manifest_path=manifest_path)
            self.assertFalse(ok_zip)
            self.assertTrue(any("byte size mismatch" in f for f in rep_zip["failures"]))
            self.assertTrue(any("SHA-256 mismatch" in f for f in rep_zip["failures"]))

    def test_03_deterministic_zip_mtime_invariance_exclusions_headers_and_symlink_rejection(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hrai_wp1_det_") as td:
            base = Path(td)
            src_a = base / "src_a" / "pkg"
            src_b = base / "src_b" / "pkg"
            for src, create_order, mtime_epoch in (
                (src_a, ["z.txt", "a.txt", "sub/b.txt"], 1700000000),
                (src_b, ["sub/b.txt", "a.txt", "z.txt"], 1790000000),
            ):
                (src / "sub").mkdir(parents=True)
                for rel in create_order:
                    p = src / rel
                    p.write_text(f"content:{rel}\n", encoding="utf-8")
                    os.utime(p, (mtime_epoch, mtime_epoch))
                # Inject build noise that MUST be excluded deterministically
                (src / "__pycache__").mkdir()
                (src / "__pycache__" / "mod.cpython-312.pyc").write_bytes(b"bytecode")
                (src / "sub" / "junk.pyo").write_bytes(b"pyo")
                (src / ".DS_Store").write_bytes(b"mac")

            zip_a = base / "a.zip"
            zip_b = base / "b.zip"
            meta_a = dz.build_deterministic_zip(src_a, zip_a, root_name="pkg")
            meta_b = dz.build_deterministic_zip(src_b, zip_b, root_name="pkg")

            self.assertEqual(meta_a["sha256"], meta_b["sha256"])
            self.assertEqual(zip_a.read_bytes(), zip_b.read_bytes())
            self.assertEqual(meta_a["file_count"], 3)
            self.assertEqual(meta_a["dir_count"], 2)

            with zipfile.ZipFile(zip_a, "r") as zf:
                names = zf.namelist()
                self.assertEqual(names, ["pkg/", "pkg/sub/", "pkg/a.txt", "pkg/sub/b.txt", "pkg/z.txt"])
                for zi in zf.infolist():
                    self.assertEqual(zi.create_system, 3)
                    self.assertEqual(zi.date_time, (2026, 11, 24, 12, 0, 0))
                    self.assertEqual(zi.extra, b"")
                    self.assertEqual(zi.comment, b"")
                    if zi.is_dir():
                        self.assertEqual(zi.external_attr, (0o40755 << 16) | 0x10)
                    else:
                        self.assertEqual(zi.external_attr, 0o100644 << 16)

            # Odd-second DOS timestamp rejected fail-closed
            with self.assertRaises(dz.DeterministicZipError):
                dz.parse_dos_timestamp("2026-11-24T12:00:01")

            # Symlink inside source tree rejected fail-closed
            os.symlink(src_a / "a.txt", src_a / "link_to_a.txt")
            with self.assertRaises(dz.DeterministicZipError):
                dz.build_deterministic_zip(src_a, base / "bad_symlink.zip", root_name="pkg")

    def test_04_active_branch_double_build_reproducibility_and_clean_extract_parity(self) -> None:
        report = dz.verify_reproducible_build(
            REPO_ROOT / "hrai_hukuk_sgk",
            root_name="hrai_hukuk_sgk",
        )
        self.assertTrue(report["reproducible"])
        self.assertEqual(report["build_1_sha256"], report["build_2_sha256"])
        self.assertTrue(report["parity"]["parity_verified"])
        self.assertEqual(report["parity"]["matched_files"], report["file_count"])
        self.assertGreaterEqual(report["file_count"], 159)

    def test_05_ci_assurance_workflow_supply_chain_and_policy_pins(self) -> None:
        wf_path = REPO_ROOT / ".github" / "workflows" / "ci-assurance.yml"
        legacy_wf = REPO_ROOT / ".github" / "workflows" / "verify-v1051.yml"
        self.assertTrue(wf_path.is_file(), "Missing .github/workflows/ci-assurance.yml")
        self.assertFalse(legacy_wf.exists(), "Legacy verify-v1051.yml should be superseded by ci-assurance.yml on v1.0.6")

        wf_text = wf_path.read_text(encoding="utf-8")
        # 1. Fixed runner (no floating ubuntu-latest)
        self.assertIn("runs-on: ubuntu-24.04", wf_text)
        self.assertNotIn("ubuntu-latest", wf_text)

        # 2. Least-privilege permissions
        self.assertRegex(wf_text, r"permissions:\s*\n\s*contents:\s*read")

        # 3. Every GitHub Action must be pinned to a 40-char commit SHA
        uses_matches = re.findall(r"^\s*uses:\s*([^\s#]+)", wf_text, flags=re.MULTILINE)
        self.assertGreaterEqual(len(uses_matches), 2)
        sha_pin_re = re.compile(r"^[^@]+@[0-9a-f]{40}$")
        for action_ref in uses_matches:
            self.assertRegex(
                action_ref,
                sha_pin_re,
                f"GitHub Action is not pinned to a 40-char commit SHA: {action_ref}",
            )

        # 4. Pinned pip (no floating --upgrade pip) and pinned crossval requirements
        self.assertNotIn("--upgrade pip", wf_text)
        self.assertIn("pip==26.3", wf_text)
        self.assertIn("hrai_hukuk_sgk/tests/requirements-crossval.txt", wf_text)

        # 5. Required verification gates present
        for required_step in (
            "python3 -m ci.verify_immutability",
            "python3 -m unittest discover -s ci/tests",
            "python3 -m ci.deterministic_zip",
            "--verify-reproducible",
            "tests.cross_validate_x509 --mode strict",
            "tests.cross_validate_x509 --mode offline",
            "engine.trust_root.integration_probe",
        ):
            self.assertIn(required_step, wf_text)


if __name__ == "__main__":
    unittest.main()
