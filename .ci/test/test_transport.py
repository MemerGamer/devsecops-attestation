#!/usr/bin/env python3
"""Local adversarial tests for the production F1 encoder and decoder."""

import base64
import gzip
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "transport.py"
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("transport", SCRIPT)
transport = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(transport)


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.names = ["chain.json", "decision.json"]
        for name in self.names:
            (self.source / name).write_bytes(b'{"result":"ok"}\n')

    def reject(self, payload, digests, names=None):
        destination = self.root / "decoded"
        with self.assertRaises((ValueError, OSError, EOFError, tarfile.TarError)):
            transport.decode(destination, names or self.names, payload, digests)
        self.assertFalse(destination.exists())

    def archive(self, entries):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for name, kind in entries:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.mode = 0o777
                if kind == tarfile.REGTYPE:
                    info.size = 2
                    tar.addfile(info, io.BytesIO(b"{}"))
                else:
                    info.linkname = "/etc/passwd"
                    tar.addfile(info)
        payload = base64.b64encode(gzip.compress(raw.getvalue())).decode("ascii")
        digests = {name: hashlib.sha256(b"{}").hexdigest() for name in self.names}
        return payload, digests

    def test_good_cli_round_trip_and_chunks(self):
        # Incompressible input crosses the 128 KiB env-string boundary. The
        # actual CLI must transport it successfully through smaller chunks.
        (self.source / self.names[0]).write_bytes(os.urandom(180_000))
        output = self.root / "outputs"
        env = dict(os.environ, GITHUB_OUTPUT=str(output))
        subprocess.run([sys.executable, str(SCRIPT), "encode", str(self.source), *self.names], env=env, check=True)
        values = dict(line.split("=", 1) for line in output.read_text().splitlines())
        payload = "".join(values[f"part{i}"] for i in range(transport.CHUNKS))
        self.assertGreater(len(payload), 200_000)
        self.assertLessEqual(len(payload), transport.MAX_ENCODED)
        env.update({f"PART{i}": values[f"part{i}"] for i in range(transport.CHUNKS)})
        env.update({f"SHA256_{i}": values[f"sha256_{i}"] for i in range(len(self.names))})
        destination = self.root / "decoded"
        subprocess.run([sys.executable, str(SCRIPT), "decode", str(destination), *self.names], env=env, check=True)
        for name in self.names:
            self.assertEqual((self.source / name).read_bytes(), (destination / name).read_bytes())
            self.assertEqual((destination / name).stat().st_mode & 0o777, 0o600)
        # A missing middle chunk must fail through the workflow's real CLI.
        env["PART1"] = ""
        result = subprocess.run([sys.executable, str(SCRIPT), "decode", str(self.root / "missing"), *self.names], env=env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_combined_encoded_bound(self):
        for name in self.names:
            (self.source / name).write_bytes(os.urandom(170_000))
        # Each file fits by itself, but the combined job bundle must not.
        with self.assertRaisesRegex(ValueError, "combined encoded"):
            transport.encode(self.source, self.names)
        output = self.root / "outputs"
        result = subprocess.run([sys.executable, str(SCRIPT), "encode", str(self.source), *self.names], env=dict(os.environ, GITHUB_OUTPUT=str(output)), capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())

    def test_decoded_size_bound(self):
        (self.source / self.names[0]).write_bytes(b"x" * (transport.MAX_DATA + 1))
        with self.assertRaisesRegex(ValueError, "16 MiB"):
            transport.encode(self.source, self.names)
        payload = base64.b64encode(gzip.compress(b"x" * (transport.MAX_TAR + 1))).decode("ascii")
        digests = {name: "0" * 64 for name in self.names}
        self.reject(payload, digests)

    def test_missing_empty_truncated_and_corrupt_outputs(self):
        payload, digests = transport.encode(self.source, self.names)
        for value in ["", payload[:-1], payload[:-16], "!" + payload[1:], "x" * (transport.MAX_ENCODED + 1)]:
            with self.subTest(value_length=len(value)):
                self.reject(value, digests)
        for value in ["", "0" * 64]:
            self.reject(payload, dict(digests, **{self.names[0]: value}))
        # Even a valid gzip/tar from a different report must fail the digest.
        (self.source / self.names[0]).write_bytes(b"tampered")
        changed, _ = transport.encode(self.source, self.names)
        self.reject(changed, digests)

    def test_encoder_rejects_extra_symlink_and_empty_inputs(self):
        extra = self.source / "extra.json"
        extra.write_bytes(b"{}")
        with self.assertRaisesRegex(ValueError, "extra entries"):
            transport.encode(self.source, self.names)
        extra.unlink()
        entry = self.source / self.names[0]
        entry.unlink()
        entry.symlink_to(self.source / self.names[1])
        with self.assertRaises(OSError):
            transport.encode(self.source, self.names)
        entry.unlink()
        entry.write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "empty input"):
            transport.encode(self.source, self.names)

    def test_extra_duplicate_missing_and_traversal_archive_entries(self):
        normal = [(name, tarfile.REGTYPE) for name in self.names]
        cases = [normal + [("extra.json", tarfile.REGTYPE)], normal + [normal[0]], normal[:1], [("../chain.json", tarfile.REGTYPE)]]
        for entries in cases:
            with self.subTest(entries=entries):
                self.reject(*self.archive(entries))

    def test_links_directories_devices_and_extended_headers(self):
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE]:
            with self.subTest(kind=kind):
                self.reject(*self.archive([(self.names[0], kind), (self.names[1], tarfile.REGTYPE)]))
        # PAX metadata must not be silently accepted by tarfile's iterator.
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for name in self.names:
                info = tarfile.TarInfo(name)
                info.size = 2
                info.pax_headers = {"comment": "unexpected metadata"}
                tar.addfile(info, io.BytesIO(b"{}"))
        payload = base64.b64encode(gzip.compress(raw.getvalue())).decode("ascii")
        self.reject(payload, {name: hashlib.sha256(b"{}").hexdigest() for name in self.names})

    def test_fresh_destination_required(self):
        payload, digests = transport.encode(self.source, self.names)
        destination = self.root / "decoded"
        destination.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            transport.decode(destination, self.names, payload, digests)
        destination.unlink()
        destination.mkdir()
        with self.assertRaises(FileExistsError):
            transport.decode(destination, self.names, payload, digests)


class SelectedKeyTests(unittest.TestCase):
    def test_missing_selected_secrets_fail_closed_with_exact_name(self):
        names = [
            f"{kind}_{suffix}"
            for kind in ["SAST", "SCA", "CONFIG", "SECRET_SCANNING"]
            for suffix in ["SIGNING_KEY", "PUBLIC_KEY"]
        ]
        script = SCRIPT.with_name("check-keys.sh")
        for key_set, prefix in [("production", ""), ("test", "TEST_")]:
            env = dict(os.environ, KEY_SET=key_set, **dict.fromkeys(names, "dummy-value"))
            subprocess.run(["bash", str(script)], env=env, check=True)
            for name in names:
                with self.subTest(key_set=key_set, missing=name):
                    result = subprocess.run(["bash", str(script)], env=dict(env, **{name: ""}), capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(f"secret {prefix}{name} is empty", result.stderr)
                    self.assertNotIn("dummy-value", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
