"""Shared Thread-Safe, Process-Isolated Ephemeral OpenSSL 3 PKI Test Helpers (v1.0.4.5).

Extracted out of `test_esign_5070_v104.py` so `unittest discover -s tests` NEVER double-imports
test modules, and hardened for deterministic, fast, order-independent, parallel-safe execution:
  - Ephemeral CA slots and exclusive RSA-2048 key slots are checked out atomically under a
    `threading.Lock` (`acquire_ca_slot`/`release_ca_slot`, `acquire_rsa_key_slot`/`release_rsa_key_slot`)
    so concurrently active fixtures/tests NEVER share CA or RSA private keys (NEVER persisted to disk).
  - Every `Ephemeral5070PkiFixture` instance allocates its OWN isolated `TemporaryDirectory`
    with completely fresh `index.txt`, `serial`, `crlnumber`, `newcerts/`, and `ca.cnf`,
    cleaned up unconditionally via `__exit__` / `close()` and on init error.
  - OCSP responder key/cert is generated lazily only when `generate_ocsp_response_der()` is called.
  - Every OpenSSL `subprocess.run` enforces `stdin=subprocess.DEVNULL` and `timeout=30`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
from typing import Any

from engine.esign5070 import (
    AuthorizedSscdEvidenceIssuer,
    BtkEshsProviderRecord,
    DefaultCertificateRevocationProvider,
    DefaultSscdControlEvidenceVerifier,
    EshsCertificateChainBundle,
    SscdControlEvidenceVerificationResult,
    cert_pem_to_der_sha256,
    compute_bundle_sha256,
    create_signed_sscd_control_evidence_envelope,
)

NES_POLICY_OID = "2.16.792.1.2.1.1.5.7.1.1"
OTHER_POLICY_OID = "2.16.792.1.2.1.9.9.9.9"
OPENSSL_SUBPROCESS_TIMEOUT_S = 30


def _openssl() -> str:
    exe = shutil.which("openssl")
    if not exe:
        raise RuntimeError("OpenSSL 3 CLI is required for tests.")
    return exe


def _run_openssl(cmd: list[str]) -> str:
    proc = subprocess.run(
        cmd,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=OPENSSL_SUBPROCESS_TIMEOUT_S,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"OpenSSL failed ({' '.join(cmd[:4])}): {proc.stderr.strip()} {proc.stdout.strip()}")
    return proc.stdout


def _valid_external_sscd_evidence() -> dict[str, Any]:
    return {
        "signature_origin": "QUALIFIED_SIGNER_DEVICE",
        "signing_device_type": "SMART_CARD_QSCD",
        "sole_control_attested": True,
        "pin_or_biometric_activation_verified": True,
        "sscd_device_certified": True,
        "sscd_certification_ref": "TSE-CC-EAL4PLUS-QSCD-2026-001",
    }


class _ImmutableEphemeralTestMaterialBank:
    """Thread-safe in-memory store of immutable ephemeral CA & distinct RSA-2048 key PEM bytes for tests.

    Holds ONLY immutable bytes in RAM (zero shared filesystem directories, zero mutable state
    shared across tests). Concurrently active `Ephemeral5070PkiFixture` instances ALWAYS receive
    cryptographically disjoint CA slots (so multi-CA / rogue-OCSP / parallel-thread tests get
    completely distinct Root CAs, Intermediate CAs, and OCSP responders), while each fixture copies
    the immutable bytes into its own isolated `TemporaryDirectory` with fresh CA database files.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._ca_slots: dict[tuple[bool, int], dict[str, bytes]] = {}
        self._ocsp_slots: dict[tuple[bool, int], dict[str, bytes]] = {}
        self._checked_out: dict[bool, set[int]] = {False: set(), True: set()}
        self._rsa_key_slots: dict[int, bytes] = {}
        self._checked_out_rsa_slots: set[int] = set()

    def acquire_ca_slot(self, *, sandbox_dn: bool) -> tuple[int, dict[str, bytes]]:
        with self._lock:
            active = self._checked_out[sandbox_dn]
            slot = 0
            while slot in active:
                slot += 1
            active.add(slot)
            cached = self._ca_slots.get((sandbox_dn, slot))
        if cached is not None:
            return slot, cached
        try:
            mat = self._generate_ca_material(sandbox_dn=sandbox_dn)
        except Exception:
            self.release_ca_slot(sandbox_dn=sandbox_dn, slot=slot)
            raise
        with self._lock:
            self._ca_slots[(sandbox_dn, slot)] = mat
        return slot, mat

    def release_ca_slot(self, *, sandbox_dn: bool, slot: int) -> None:
        with self._lock:
            self._checked_out[sandbox_dn].discard(slot)

    def get_ocsp_material(self, *, sandbox_dn: bool, slot: int, ca_mat: dict[str, bytes]) -> dict[str, bytes]:
        with self._lock:
            cached = self._ocsp_slots.get((sandbox_dn, slot))
        if cached is not None:
            return cached
        mat = self._generate_ocsp_material(sandbox_dn=sandbox_dn, ca_mat=ca_mat)
        with self._lock:
            self._ocsp_slots.setdefault((sandbox_dn, slot), mat)
            return self._ocsp_slots[(sandbox_dn, slot)]

    def acquire_rsa_key_slot(self) -> tuple[int, bytes]:
        """Atomically check out an exclusive RSA-2048 key slot (zero concurrent key sharing or genrsa race)."""
        with self._lock:
            slot = 0
            while slot in self._checked_out_rsa_slots:
                slot += 1
            self._checked_out_rsa_slots.add(slot)
            cached = self._rsa_key_slots.get(slot)
        if cached is not None:
            return slot, cached
        try:
            openssl = _openssl()
            with tempfile.TemporaryDirectory(prefix="calisora_ephem_rsa_") as tmp:
                kp = Path(tmp) / "slot.key"
                _run_openssl([openssl, "genrsa", "-out", str(kp), "2048"])
                key_bytes = kp.read_bytes()
        except Exception:
            self.release_rsa_key_slot(slot)
            raise
        with self._lock:
            self._rsa_key_slots[slot] = key_bytes
        return slot, key_bytes

    def release_rsa_key_slot(self, slot: int) -> None:
        with self._lock:
            self._checked_out_rsa_slots.discard(slot)

    @staticmethod
    def _generate_ca_material(*, sandbox_dn: bool) -> dict[str, bytes]:
        openssl = _openssl()
        org = "CALISORA-MOCK-SANDBOX-CA" if sandbox_dn else "ORNEK-ESHS-TEST-AS"
        root_cn = "CALISORA-MOCK-SANDBOX-ROOT-CA" if sandbox_dn else "TR-ESHS-KOK-CA"
        inter_cn = "CALISORA-MOCK-SANDBOX-INTER-CA" if sandbox_dn else "TR-ESHS-NES-ALT-CA"

        with tempfile.TemporaryDirectory(prefix="calisora_ca_tpl_") as tmp:
            root = Path(tmp)
            root_key = root / "root.key"
            root_cert = root / "root.pem"
            inter_key = root / "inter.key"
            inter_csr = root / "inter.csr"
            inter_cert = root / "inter.pem"
            root_cnf = root / "root.cnf"
            inter_ext = root / "inter_ext.cnf"

            root_cnf.write_text(
                "[req]\n"
                "distinguished_name = dn\n"
                "x509_extensions = v3_root_ca\n"
                "prompt = no\n"
                "[dn]\n"
                f"CN = {root_cn}\n"
                f"O = {org}\n"
                "C = TR\n"
                "[v3_root_ca]\n"
                "subjectKeyIdentifier = hash\n"
                "authorityKeyIdentifier = keyid:always,issuer\n"
                "basicConstraints = critical, CA:TRUE\n"
                "keyUsage = critical, keyCertSign, cRLSign\n",
                encoding="utf-8",
            )
            inter_ext.write_text(
                "subjectKeyIdentifier = hash\n"
                "authorityKeyIdentifier = keyid:always,issuer\n"
                "basicConstraints = critical, CA:TRUE, pathlen:0\n"
                "keyUsage = critical, keyCertSign, cRLSign\n",
                encoding="utf-8",
            )

            _run_openssl(
                [
                    openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-config", str(root_cnf), "-extensions", "v3_root_ca",
                    "-keyout", str(root_key), "-out", str(root_cert), "-days", "3650",
                ]
            )
            _run_openssl(
                [
                    openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(inter_key), "-out", str(inter_csr),
                    "-subj", f"/CN={inter_cn}/O={org}/C=TR",
                ]
            )
            _run_openssl(
                [
                    openssl, "x509", "-req", "-in", str(inter_csr),
                    "-CA", str(root_cert), "-CAkey", str(root_key), "-CAcreateserial",
                    "-out", str(inter_cert), "-days", "1825", "-extfile", str(inter_ext),
                ]
            )
            return {
                "root_key": root_key.read_bytes(),
                "root_cert": root_cert.read_bytes(),
                "inter_key": inter_key.read_bytes(),
                "inter_cert": inter_cert.read_bytes(),
            }

    @staticmethod
    def _generate_ocsp_material(*, sandbox_dn: bool, ca_mat: dict[str, bytes]) -> dict[str, bytes]:
        openssl = _openssl()
        org = "CALISORA-MOCK-SANDBOX-CA" if sandbox_dn else "ORNEK-ESHS-TEST-AS"
        inter_cn = "CALISORA-MOCK-SANDBOX-INTER-CA" if sandbox_dn else "TR-ESHS-NES-ALT-CA"

        with tempfile.TemporaryDirectory(prefix="calisora_ocsp_tpl_") as tmp:
            root = Path(tmp)
            inter_key = root / "inter.key"
            inter_cert = root / "inter.pem"
            inter_key.write_bytes(ca_mat["inter_key"])
            inter_cert.write_bytes(ca_mat["inter_cert"])

            ocsp_key = root / "ocsp.key"
            ocsp_csr = root / "ocsp.csr"
            ocsp_cert = root / "ocsp.pem"
            ocsp_ext = root / "ocsp_ext.cnf"
            ocsp_ext.write_text(
                "subjectKeyIdentifier = hash\n"
                "authorityKeyIdentifier = keyid,issuer\n"
                "basicConstraints = critical, CA:FALSE\n"
                "keyUsage = critical, digitalSignature\n"
                "extendedKeyUsage = critical, OCSPSigning\n"
                "noCheck = yes\n",
                encoding="utf-8",
            )
            _run_openssl(
                [
                    openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(ocsp_key), "-out", str(ocsp_csr),
                    "-subj", f"/CN={inter_cn}-OCSP/O={org}/C=TR",
                ]
            )
            _run_openssl(
                [
                    openssl, "x509", "-req", "-in", str(ocsp_csr),
                    "-CA", str(inter_cert), "-CAkey", str(inter_key), "-CAcreateserial",
                    "-out", str(ocsp_cert), "-days", "365", "-extfile", str(ocsp_ext),
                ]
            )
            return {
                "ocsp_key": ocsp_key.read_bytes(),
                "ocsp_cert": ocsp_cert.read_bytes(),
            }


_MATERIAL_BANK = _ImmutableEphemeralTestMaterialBank()


class Ephemeral5070PkiFixture:
    """Isolated ephemeral OpenSSL 3 PKI fixture with strict RFC 5280 CA profiles, ASN.1 DER QCStatements, CRL, and OCSP."""

    def __init__(self, *, sandbox_dn: bool = False, fresh_ca: bool = False) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="calisora_5070_pki_")
        self.root = Path(self._tmpdir.name)
        self._openssl = _openssl()
        self.sandbox_dn = sandbox_dn
        self._fresh_ca = fresh_ca
        self._ca_slot: int | None = None
        self._ca_mat: dict[str, bytes] = {}
        self._checked_out_rsa_slots: list[int] = []
        self._ocsp_ready = False
        self._ocsp_cert_pem_cache: str = ""
        try:
            self._setup_pki()
        except Exception:
            self.close()
            raise

    def _run(self, cmd: list[str]) -> str:
        return _run_openssl(cmd)

    def _setup_pki(self) -> None:
        self.root_key = self.root / "root.key"
        self.root_cert = self.root / "root.pem"
        self.inter_key = self.root / "inter.key"
        self.inter_cert = self.root / "inter.pem"
        self.ocsp_key = self.root / "ocsp.key"
        self.ocsp_cert = self.root / "ocsp.pem"

        self.newcerts_dir = self.root / "newcerts"
        self.newcerts_dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.root / "index.txt"
        self.index_file.write_text("", encoding="utf-8")
        (self.root / "index.txt.attr").write_text("unique_subject = no\n", encoding="utf-8")
        self.serial_file = self.root / "serial"
        self.serial_file.write_text("1000\n", encoding="utf-8")
        self.crlnum_file = self.root / "crlnumber"
        self.crlnum_file.write_text("01\n", encoding="utf-8")

        self.ca_cnf = self.root / "ca.cnf"
        self.ca_cnf.write_text(
            "[ca]\n"
            "default_ca = CA_default\n"
            "[CA_default]\n"
            f"dir = {self.root}\n"
            f"new_certs_dir = {self.newcerts_dir}\n"
            f"database = {self.index_file}\n"
            f"serial = {self.serial_file}\n"
            f"crlnumber = {self.crlnum_file}\n"
            f"certificate = {self.inter_cert}\n"
            f"private_key = {self.inter_key}\n"
            "default_md = sha256\n"
            "default_days = 30\n"
            "default_crl_days = 7\n"
            "policy = policy_anything\n"
            "crl_extensions = crl_ext\n"
            "[policy_anything]\n"
            "countryName = optional\n"
            "organizationName = optional\n"
            "commonName = supplied\n"
            "serialNumber = optional\n"
            "[crl_ext]\n"
            "authorityKeyIdentifier = keyid:always\n",
            encoding="utf-8",
        )

        if self._fresh_ca:
            ca_mat = _ImmutableEphemeralTestMaterialBank._generate_ca_material(sandbox_dn=self.sandbox_dn)
            self._ca_slot = None
        else:
            self._ca_slot, ca_mat = _MATERIAL_BANK.acquire_ca_slot(sandbox_dn=self.sandbox_dn)
        self._ca_mat = ca_mat

        self.root_key.write_bytes(ca_mat["root_key"])
        self.root_cert.write_bytes(ca_mat["root_cert"])
        self.inter_key.write_bytes(ca_mat["inter_key"])
        self.inter_cert.write_bytes(ca_mat["inter_cert"])

        self.root_cert_pem = self.root_cert.read_text(encoding="utf-8")
        self.inter_cert_pem = self.inter_cert.read_text(encoding="utf-8")

    def _ensure_ocsp_cert(self) -> None:
        if self._ocsp_ready:
            return
        if self._fresh_ca or self._ca_slot is None:
            ocsp_mat = _ImmutableEphemeralTestMaterialBank._generate_ocsp_material(
                sandbox_dn=self.sandbox_dn, ca_mat=self._ca_mat
            )
        else:
            ocsp_mat = _MATERIAL_BANK.get_ocsp_material(
                sandbox_dn=self.sandbox_dn, slot=self._ca_slot, ca_mat=self._ca_mat
            )
        self.ocsp_key.write_bytes(ocsp_mat["ocsp_key"])
        self.ocsp_cert.write_bytes(ocsp_mat["ocsp_cert"])
        self._ocsp_cert_pem_cache = self.ocsp_cert.read_text(encoding="utf-8")
        self._ocsp_ready = True

    @property
    def ocsp_cert_pem(self) -> str:
        self._ensure_ocsp_cert()
        return self._ocsp_cert_pem_cache

    def issue_signer_cert(
        self,
        *,
        tag: str,
        common_name: str = "Ayse Yilmaz",
        serial_identifier: str | None = "TRID-12345678901",
        include_qc_compliance: bool = True,
        include_qc_sscd: bool = True,
        policy_oids: tuple[str, ...] = (NES_POLICY_OID,),
        startdate: str | None = None,
        enddate: str | None = None,
    ) -> tuple[str, str, Path]:
        key_path = self.root / f"{tag}.key"
        csr_path = self.root / f"{tag}.csr"
        cert_path = self.root / f"{tag}.pem"
        ext_path = self.root / f"{tag}_ext.cnf"

        subj = f"/CN={common_name}/C=TR"
        if serial_identifier:
            subj = f"/CN={common_name}/serialNumber={serial_identifier}/C=TR"

        ext_lines = [
            "[v3_signer]",
            "subjectKeyIdentifier = hash",
            "authorityKeyIdentifier = keyid,issuer",
            "basicConstraints = critical, CA:FALSE",
            "keyUsage = critical, digitalSignature, nonRepudiation",
        ]
        if policy_oids:
            ext_lines.append("certificatePolicies = " + ", ".join(policy_oids))

        qc_entries: list[str] = []
        qc_sections: list[str] = []
        if include_qc_compliance:
            qc_entries.append("stmt_comp = SEQUENCE:qc_comp_seq")
            qc_sections.extend(["[qc_comp_seq]", "oid = OID:0.4.0.1862.1.1"])
        if include_qc_sscd:
            qc_entries.append("stmt_sscd = SEQUENCE:qc_sscd_seq")
            qc_sections.extend(["[qc_sscd_seq]", "oid = OID:0.4.0.1862.1.4"])

        if qc_entries:
            ext_lines.append("1.3.6.1.5.5.7.1.3 = ASN1:SEQUENCE:qc_stmts_seq")
            ext_lines.append("[qc_stmts_seq]")
            ext_lines.extend(qc_entries)
            ext_lines.extend(qc_sections)

        ext_path.write_text("\n".join(ext_lines) + "\n", encoding="utf-8")

        # Atomically check out an exclusive 2048-bit RSA keypair slot (released in close())
        slot, key_bytes = _MATERIAL_BANK.acquire_rsa_key_slot()
        self._checked_out_rsa_slots.append(slot)
        key_path.write_bytes(key_bytes)

        self._run([self._openssl, "req", "-new", "-key", str(key_path), "-out", str(csr_path), "-subj", subj])
        ca_cmd = [
            self._openssl, "ca", "-batch", "-notext", "-config", str(self.ca_cnf),
            "-in", str(csr_path), "-out", str(cert_path),
            "-extfile", str(ext_path), "-extensions", "v3_signer",
        ]
        if startdate and enddate:
            ca_cmd.extend(["-startdate", startdate, "-enddate", enddate])
        self._run(ca_cmd)
        return cert_path.read_text(encoding="utf-8"), key_path.read_text(encoding="utf-8"), cert_path

    def revoke_cert(self, cert_path: Path, *, reason: str = "keyCompromise") -> None:
        self._run(
            [
                self._openssl, "ca", "-batch", "-config", str(self.ca_cnf),
                "-revoke", str(cert_path), "-crl_reason", reason,
            ]
        )

    def generate_crl_pem(self) -> str:
        crl_path = self.root / "current.crl"
        self._run([self._openssl, "ca", "-config", str(self.ca_cnf), "-gencrl", "-out", str(crl_path)])
        return crl_path.read_text(encoding="utf-8")

    def generate_ocsp_response_der(self, cert_path: Path) -> bytes:
        self._ensure_ocsp_cert()
        req_path = self.root / f"ocsp_req_{cert_path.stem}.der"
        resp_path = self.root / f"ocsp_resp_{cert_path.stem}.der"
        self._run(
            [
                self._openssl, "ocsp",
                "-issuer", str(self.inter_cert),
                "-cert", str(cert_path),
                "-no_nonce",
                "-reqout", str(req_path),
            ]
        )
        self._run(
            [
                self._openssl, "ocsp",
                "-index", str(self.index_file),
                "-CA", str(self.inter_cert),
                "-rkey", str(self.ocsp_key),
                "-rsigner", str(self.ocsp_cert),
                "-reqin", str(req_path),
                "-respout", str(resp_path),
                "-ndays", "1",
            ]
        )
        return resp_path.read_bytes()

    def build_btk_provider_record(
        self,
        *,
        eshs_id: str = "ESHS-TR-01",
        status: str = "ACTIVE",
        authorized_from_utc: str = "2020-01-01T00:00:00Z",
        authorized_until_utc: str = "2035-12-31T23:59:59Z",
        permitted_policy_oids: tuple[str, ...] = (NES_POLICY_OID,),
        trust_source_mode: str = "MOCK_SANDBOX",
    ) -> BtkEshsProviderRecord:
        return BtkEshsProviderRecord(
            eshs_id=eshs_id,
            provider_name="ORNEK-ESHS-TEST-AS",
            authorization_status=status,
            authorized_from_utc=authorized_from_utc,
            authorized_until_utc=authorized_until_utc,
            btk_registry_ref="BTK-ESHS-LIST-2026-01",
            btk_list_version="BTK-2026.11",
            permitted_policy_oids=permitted_policy_oids,
            country_code="TR",
            trust_source_mode=trust_source_mode,
        )

    def build_ca_bundle(
        self,
        *,
        eshs_id: str = "ESHS-TR-01",
        policy_oids: tuple[str, ...] = (NES_POLICY_OID,),
        trust_tier: str = "MOCK_SANDBOX_ONLY",
    ) -> EshsCertificateChainBundle:
        roots = (self.root_cert_pem,)
        inters = (self.inter_cert_pem,)
        return EshsCertificateChainBundle(
            eshs_id=eshs_id,
            bundle_id=f"BUNDLE-{eshs_id}-V1",
            root_ca_pems=roots,
            intermediate_ca_pems=inters,
            certificate_policy_oids=policy_oids,
            cps_urls=("https://example.tr/cps-nes.pdf",),
            bundle_sha256=compute_bundle_sha256(roots, inters, policy_oids),
            acquired_at_utc="2026-11-22T00:00:00Z",
            valid_from_utc="2020-01-01T00:00:00Z",
            valid_until_utc="2035-12-31T23:59:59Z",
            trust_tier=trust_tier,
        )

    def issue_ec_signer_cert(
        self,
        *,
        tag: str,
        curve: str = "prime256v1",
        common_name: str = "Mehmet Ozturk",
        serial_identifier: str | None = "TRID-98765432109",
        policy_oids: tuple[str, ...] = (NES_POLICY_OID,),
    ) -> tuple[str, str, Path]:
        key_path = self.root / f"{tag}_ec.key"
        csr_path = self.root / f"{tag}_ec.csr"
        cert_path = self.root / f"{tag}_ec.pem"
        ext_path = self.root / f"{tag}_ec_ext.cnf"

        subj = f"/CN={common_name}/C=TR"
        if serial_identifier:
            subj = f"/CN={common_name}/serialNumber={serial_identifier}/C=TR"

        ext_lines = [
            "[v3_signer]",
            "subjectKeyIdentifier = hash",
            "authorityKeyIdentifier = keyid,issuer",
            "basicConstraints = critical, CA:FALSE",
            "keyUsage = critical, digitalSignature, nonRepudiation",
            "certificatePolicies = " + ", ".join(policy_oids),
            "1.3.6.1.5.5.7.1.3 = ASN1:SEQUENCE:qc_stmts_seq",
            "[qc_stmts_seq]",
            "stmt_comp = SEQUENCE:qc_comp_seq",
            "stmt_sscd = SEQUENCE:qc_sscd_seq",
            "[qc_comp_seq]",
            "oid = OID:0.4.0.1862.1.1",
            "[qc_sscd_seq]",
            "oid = OID:0.4.0.1862.1.4",
        ]
        ext_path.write_text("\n".join(ext_lines) + "\n", encoding="utf-8")
        self._run([self._openssl, "ecparam", "-name", curve, "-genkey", "-noout", "-out", str(key_path)])
        self._run([self._openssl, "req", "-new", "-key", str(key_path), "-out", str(csr_path), "-subj", subj])
        self._run(
            [
                self._openssl, "ca", "-batch", "-notext", "-config", str(self.ca_cnf),
                "-in", str(csr_path), "-out", str(cert_path),
                "-extfile", str(ext_path), "-extensions", "v3_signer",
            ]
        )
        return cert_path.read_text(encoding="utf-8"), key_path.read_text(encoding="utf-8"), cert_path

    def ensure_sscd_issuer_cert(self) -> tuple[str, str, Path]:
        if not hasattr(self, "_sscd_issuer_bundle"):
            c_pem, k_pem, c_path = self.issue_signer_cert(
                tag="sscd_cab_issuer",
                common_name="TSE-QSCD-CONFORMITY-BODY",
                serial_identifier="CAB-TR-001",
                include_qc_compliance=False,
                include_qc_sscd=False,
                policy_oids=(NES_POLICY_OID,),
            )
            self._sscd_issuer_bundle = (c_pem, k_pem, c_path)
        return self._sscd_issuer_bundle

    def build_sscd_evidence_verifier(
        self,
        *,
        issuer_id: str = "TSE-QSCD-CAB-01",
        status: str = "ACTIVE",
        trust_tier: str = "MOCK_SANDBOX_ONLY",
        integration_mode: str = "MOCK_SANDBOX",
        authorized_scopes: tuple[str, ...] = ("LAW_5070_M4C_SOLE_CONTROL", "LAW_5070_M6_SSCD_CERTIFICATION"),
        authorized_from_utc: str = "2020-01-01T00:00:00Z",
        authorized_until_utc: str = "2035-12-31T23:59:59Z",
        crl_pem: str | None = None,
    ) -> DefaultSscdControlEvidenceVerifier:
        eff_crl = crl_pem if crl_pem is not None else self.generate_crl_pem()
        issuer_rec = AuthorizedSscdEvidenceIssuer(
            issuer_id=issuer_id,
            issuer_name="TSE QSCD Uygunluk Degerlendirme Kurulusu",
            issuer_role="QSCD_CONFORMITY_ASSESSMENT_BODY",
            authorized_scopes=authorized_scopes,
            root_ca_pems=(self.root_cert_pem,),
            intermediate_ca_pems=(self.inter_cert_pem,),
            authorized_from_utc=authorized_from_utc,
            authorized_until_utc=authorized_until_utc,
            status=status,
            trust_tier=trust_tier,
        )
        rev_prov = DefaultCertificateRevocationProvider(
            trusted_ca_pem=self.root_cert_pem + "\n" + self.inter_cert_pem,
            crl_fetcher=lambda _i, _vt: eff_crl,
            integration_mode=integration_mode,
        )
        return DefaultSscdControlEvidenceVerifier(
            authorized_issuers=[issuer_rec],
            revocation_provider=rev_prov,
            integration_mode=integration_mode,
        )

    def build_verified_sscd_evidence(
        self,
        signer_cert_pem: str,
        *,
        validation_time_utc: str | None = None,
        trust_tier: str = "MOCK_SANDBOX_ONLY",
        integration_mode: str = "MOCK_SANDBOX",
        runtime_environment: str = "TEST_SANDBOX_ONLY",
        signature_algorithm: str = "RSA-SHA256",
        valid_from_utc: str = "2020-01-01T00:00:00Z",
        valid_until_utc: str = "2035-12-31T23:59:59Z",
    ) -> SscdControlEvidenceVerificationResult:
        iss_cert, iss_key, _ = self.ensure_sscd_issuer_cert()
        val_t = validation_time_utc or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        signer_sha = cert_pem_to_der_sha256(signer_cert_pem)
        env = create_signed_sscd_control_evidence_envelope(
            evidence_id=f"SSCD-EV-{signer_sha[:10].upper()}",
            issuer_id="TSE-QSCD-CAB-01",
            issuer_cert_pem=iss_cert,
            issuer_key_pem=iss_key,
            bound_signer_cert_sha256=signer_sha,
            issued_at_utc=val_t,
            valid_from_utc=valid_from_utc,
            valid_until_utc=valid_until_utc,
            signature_algorithm=signature_algorithm,
        )
        verifier = self.build_sscd_evidence_verifier(
            trust_tier=trust_tier,
            integration_mode=integration_mode,
        )
        return verifier.verify_sscd_evidence_envelope(
            env,
            validation_time_utc=val_t,
            expected_signer_cert_sha256=signer_sha,
            runtime_environment=runtime_environment,
        )

    def close(self) -> None:
        if self._checked_out_rsa_slots:
            slots = list(self._checked_out_rsa_slots)
            self._checked_out_rsa_slots.clear()
            for s in slots:
                _MATERIAL_BANK.release_rsa_key_slot(s)
        if self._ca_slot is not None:
            slot = self._ca_slot
            self._ca_slot = None
            _MATERIAL_BANK.release_ca_slot(sandbox_dn=self.sandbox_dn, slot=slot)
        self._tmpdir.cleanup()

    def __enter__(self) -> "Ephemeral5070PkiFixture":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()
