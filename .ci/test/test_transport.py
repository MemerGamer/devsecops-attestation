#!/usr/bin/env python3
"""Local adversarial tests for the production F1 encoder and decoder."""

import base64
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
import yaml

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
        env["MANIFEST"] = values["manifest"]
        destination = self.root / "decoded"
        subprocess.run([sys.executable, str(SCRIPT), "decode", str(destination), *self.names], env=env, check=True)
        for name in self.names:
            self.assertEqual((self.source / name).read_bytes(), (destination / name).read_bytes())
            self.assertEqual((destination / name).stat().st_mode & 0o777, 0o600)
        # A missing middle chunk must fail through the workflow's real CLI.
        env["PART1"] = ""
        result = subprocess.run([sys.executable, str(SCRIPT), "decode", str(self.root / "missing"), *self.names], env=env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"output chunk 1 missing, truncated or unexpected", result.stderr)

    def test_manifest_rejects_shifted_middle_chunk_before_decompression(self):
        # Four chunks, including three full chunks. Dropping then shifting a
        # full middle chunk leaves a plausible contiguous payload, but the
        # producer's original lengths identify the loss before gzip decoding.
        (self.source / self.names[0]).write_bytes(os.urandom(250_000))
        payload, digests = transport.encode(self.source, self.names)
        parts = [payload[i : i + transport.CHUNK_SIZE] for i in range(0, len(payload), transport.CHUNK_SIZE)]
        self.assertEqual(len(parts), 4)
        manifest = json.dumps({"chunks": list(map(len, parts)), "files": digests})
        shifted = [parts[0], parts[2], parts[3], ""]
        env = dict(os.environ, MANIFEST=manifest, **{f"PART{i}": part for i, part in enumerate(shifted)})
        result = subprocess.run([sys.executable, str(SCRIPT), "decode", str(self.root / "decoded"), *self.names], env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("output chunk 2 missing, truncated or unexpected", result.stderr)
        self.assertNotIn("gzip", result.stderr)
        self.assertFalse((self.root / "decoded").exists())

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


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workflow = yaml.safe_load((SCRIPT.parents[1] / ".github/workflows/devsecops-pipeline.yml").read_text())

    def collect(self, outcomes, reports=None):
        if reports is not None:
            (self.root / ".ci").mkdir()
            (self.root / ".ci/transport.py").write_bytes(SCRIPT.read_bytes())
            for name, data in reports.items():
                (self.root / name).write_text(data)
        step = next(step for step in self.workflow["jobs"]["sign"]["steps"] if step.get("id") == "bundle")
        command = step["run"].replace("${{ runner.temp }}", str(self.root))
        output = self.root / "outputs"
        env = dict(os.environ, GITHUB_OUTPUT=str(output), STEP_OUTCOMES=json.dumps({name: {"outcome": outcome} for name, outcome in outcomes.items()}))
        result = subprocess.run(["bash", "-euo", "pipefail", "-c", command], cwd=self.root, env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        values = dict(line.split("=", 1) for line in output.read_text().splitlines())
        return values, result

    def publish(self, values, result):
        env = dict(os.environ, SIGN_RESULT=result, SIGN_STATUS=values["status"], STATUS_SHA256=values["status_sha256"], MANIFEST=values.get("manifest", ""))
        env.update({f"PART{i}": values.get(f"part{i}", "") for i in range(transport.CHUNKS)})
        return subprocess.run([sys.executable, str(SCRIPT.with_name("publish-diagnostics.py")), str(self.root / "signed")], env=env, text=True, capture_output=True)

    def test_source_fetch_failure_still_publishes_clear_status(self):
        values, result = self.collect({"source": "failure", "gate": "skipped"})
        self.assertIn("sign failed before gate: source", result.stdout)
        result = self.publish(values, "failure")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sign failed before gate: source", result.stderr)
        self.assertNotIn("missing/empty payload", result.stderr)
        status = json.loads((self.root / "signed/sign-status.json").read_text())
        self.assertEqual(status["result"], "failure")
        self.assertTrue(any(step.get("uses", "").startswith("actions/upload-artifact@") and step.get("if") == "always()" for step in self.workflow["jobs"]["publish"]["steps"]))

    def test_pre_gate_failure_retains_partial_chain(self):
        values, _ = self.collect({"source": "success", "sign_sca": "failure", "gate": "skipped"}, {"attestation-chain.json": "[]"})
        result = self.publish(values, "failure")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sign failed before gate: sign_sca", result.stderr)
        self.assertEqual((self.root / "signed/attestation-chain.json").read_text(), "[]")
        self.assertFalse((self.root / "signed/gate-decision.json").exists())

    def test_successful_sign_requires_both_reports(self):
        values, _ = self.collect({"gate": "success"}, {"attestation-chain.json": "[]"})
        result = self.publish(values, "success")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("lacks a complete successful gate result", result.stderr)
        self.assertTrue((self.root / "signed/sign-status.json").is_file())

    def test_damaged_bundle_preserves_status_for_upload(self):
        values, _ = self.collect({"gate": "success"}, {"attestation-chain.json": "[]", "gate-decision.json": '{"allow":true}'})
        values["part0"] = values["part0"][:-4]
        result = self.publish(values, "success")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("output chunk 0 missing, truncated or unexpected", result.stderr)
        self.assertTrue((self.root / "signed/sign-status.json").is_file())

    def test_complete_success_and_deny_diagnostics_round_trip(self):
        for allow in [True, False]:
            with self.subTest(allow=allow), tempfile.TemporaryDirectory() as scratch:
                self.root = Path(scratch)
                decision = json.dumps({"allow": allow})
                values, _ = self.collect({"gate": "success" if allow else "failure"}, {"attestation-chain.json": "[]", "gate-decision.json": decision})
                result = self.publish(values, "success" if allow else "failure")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((self.root / "signed/gate-decision.json").read_text(), decision)
                self.assertEqual(set(path.name for path in (self.root / "signed").iterdir()), {"sign-status.json", "attestation-chain.json", "gate-decision.json"})

    def test_release_precheck_uses_decoded_boolean_allow(self):
        step = next(step for step in self.workflow["jobs"]["publish"]["steps"] if step.get("name") == "Require an allow decision before release build")
        self.assertEqual(step["if"], "needs.sign.result == 'success'")
        (self.root / "signed").mkdir()
        path = self.root / "signed/gate-decision.json"
        for value, accepted in [("true", True), ("false", False), ('"true"', False), ("null", False)]:
            with self.subTest(allow=value):
                path.write_text('{"allow":' + value + "}")
                result = subprocess.run(["bash", "-euo", "pipefail", "-c", step["run"].replace("${{ runner.temp }}", str(self.root))], capture_output=True)
                self.assertEqual(result.returncode == 0, accepted)


if __name__ == "__main__":
    unittest.main(verbosity=2)
