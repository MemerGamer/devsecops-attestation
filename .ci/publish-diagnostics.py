#!/usr/bin/env python3
"""Restore bounded signing diagnostics, including failures before gate evaluation."""

import hashlib
import json
import os
from pathlib import Path
import sys
import tarfile

sys.dont_write_bytecode = True
from transport import decode, read_outputs


def restore(directory):
    status = os.environ.get("SIGN_STATUS", "")
    digest = os.environ.get("STATUS_SHA256", "")
    if not status or len(status) > 16_000 or hashlib.sha256(status.encode()).hexdigest() != digest:
        raise ValueError("missing or corrupted signing status output; see sign job logs")
    document = json.loads(status)
    if (
        not isinstance(document, dict)
        or document.get("result") not in ("success", "failure")
        or not isinstance(document.get("message"), str)
        or not document["message"]
        or any(character in document["message"] for character in "\r\n")
    ):
        raise ValueError("invalid signing status output")
    result = os.environ["SIGN_RESULT"]
    message = document["message"]
    if result != "success" and document["result"] == "success":
        message = "sign failed while encoding diagnostics after gate; see sign job logs"
        document["result"] = "failure"
        document["message"] = message
    directory.mkdir(mode=0o700)
    path = directory / "sign-status.json"
    path.write_text(json.dumps(document, separators=(",", ":")) + "\n")
    path.chmod(0o600)
    if document["result"] != "success" or result != "success":
        print(message, file=sys.stderr)
    if not os.environ.get("MANIFEST"):
        if result != "success":
            raise ValueError(message + "; no encoded chain/decision diagnostics are available; signing status retained")
        raise ValueError("successful sign job did not emit a diagnostics manifest")
    payload, digests = read_outputs()
    expected = {"attestation-chain.json", "gate-decision.json"}
    if not set(digests) <= expected:
        raise ValueError("unexpected signing diagnostic file")
    if result == "success" and (set(digests) != expected or document["result"] != "success"):
        raise ValueError("successful sign job lacks a complete successful gate result")
    decode(directory / "reports", list(digests), payload, digests)
    for name in digests:
        (directory / "reports" / name).replace(directory / name)
    (directory / "reports").rmdir()


if __name__ == "__main__":
    try:
        restore(Path(sys.argv[1]))
    except (ValueError, OSError, EOFError, tarfile.TarError) as error:
        print(f"publish diagnostics: {error}", file=sys.stderr)
        sys.exit(1)
