#!/usr/bin/env python3
"""F1 data transport: bounded gzip/base64 tar bundles, with per-file SHA-256.

Only fixed, regular basenames are accepted. No archive extraction API is used:
validated bytes are written as non-executable files in a new directory. Producer
digests detect transport damage, not a malicious scanner. Four chunks avoid the
Linux per-environment-string limit while preserving the combined job budget.
"""

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile

MAX_ENCODED = 400_000
CHUNK_SIZE = 100_000
CHUNKS = 4
MAX_DATA = 16 * 1024 * 1024
MAX_TAR = MAX_DATA + 64 * 1024


def check_names(names):
    if not names or len(names) != len(set(names)):
        raise ValueError("expected a nonempty set of unique filenames")
    if any(not re.fullmatch(r"[a-zA-Z0-9_-]+\.json", name) for name in names):
        raise ValueError("expected simple JSON basenames")


def encode(directory, names):
    check_names(names)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("input must be a regular directory")
    if set(os.listdir(directory)) != set(names):
        raise ValueError("input directory contains missing or extra entries")
    archive = io.BytesIO()
    digests = {}
    total = 0
    with tarfile.open(fileobj=archive, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name in names:
            # O_NOFOLLOW rejects symlinks even if replaced between list and open.
            fd = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as source:
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    raise ValueError("input entries must be regular files")
                data = source.read(MAX_DATA - total + 1)
            total += len(data)
            if not data or total > MAX_DATA:
                raise ValueError("empty input or decoded data exceeds 16 MiB")
            digests[name] = hashlib.sha256(data).hexdigest()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o600
            tar.addfile(info, io.BytesIO(data))
    payload = base64.b64encode(gzip.compress(archive.getvalue(), mtime=0)).decode("ascii")
    if len(payload) > MAX_ENCODED:
        raise ValueError("combined encoded job outputs exceed 400000 characters")
    return payload, digests


def decode(directory, names, payload, digests):
    check_names(names)
    if not payload or len(payload) > MAX_ENCODED:
        raise ValueError("missing/empty payload or encoded job outputs exceed 400000 characters")
    if set(digests) != set(names) or any(
        not re.fullmatch(r"[0-9a-f]{64}", digest) for digest in digests.values()
    ):
        raise ValueError("missing or invalid SHA-256 output")
    compressed = base64.b64decode(payload, validate=True)
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as source:
        raw = source.read(MAX_TAR + 1)
    if len(raw) > MAX_TAR:
        raise ValueError("decoded archive exceeds size limit")
    files = {}
    offset = 0
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
        for member in tar:
            if (
                member.name not in names
                or member.name in files
                or member.type != tarfile.REGTYPE
                or member.linkname
                or member.pax_headers
                or member.offset != offset
                or member.offset_data != offset + 512
            ):
                raise ValueError("unexpected entry, link, duplicate or extended archive header")
            total += member.size
            if member.size <= 0 or total > MAX_DATA:
                raise ValueError("empty file or decoded data exceeds 16 MiB")
            data = raw[member.offset_data : member.offset_data + member.size]
            if hashlib.sha256(data).hexdigest() != digests[member.name]:
                raise ValueError("SHA-256 mismatch (missing, truncated or corrupted output)")
            files[member.name] = data
            offset = member.offset_data + ((member.size + 511) // 512) * 512
    if set(files) != set(names) or len(raw) - offset < 1024 or any(raw[offset:]):
        raise ValueError("missing files, extra entries or invalid archive trailer")
    # Validate everything before creating any destination. A pre-existing path,
    # including a symlink, is rejected by mkdir without exist_ok.
    directory.mkdir(mode=0o700)
    for name, data in files.items():
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(data)


def read_outputs(names=None):
    """Check the producer's chunk manifest before decoding gzip or tar data."""
    manifest = json.loads(os.environ.get("MANIFEST", ""))
    if not isinstance(manifest, dict) or set(manifest) != {"chunks", "files"}:
        raise ValueError("invalid output manifest")
    lengths = manifest["chunks"]
    digests = manifest["files"]
    if (
        not isinstance(lengths, list)
        or not 1 <= len(lengths) <= CHUNKS
        or any(type(size) is not int or not 1 <= size <= CHUNK_SIZE for size in lengths)
        or any(size != CHUNK_SIZE for size in lengths[:-1])
        or sum(lengths) > MAX_ENCODED
        or not isinstance(digests, dict)
    ):
        raise ValueError("invalid chunk lengths or file digests in output manifest")
    check_names(list(digests))
    if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in digests.values()):
        raise ValueError("missing or invalid SHA-256 output")
    if names is not None and set(digests) != set(names):
        raise ValueError("missing or unexpected files in output manifest")
    parts = [os.environ.get(f"PART{i}", "") for i in range(CHUNKS)]
    # Compare each slot with the original lengths. Reconstructing lengths from
    # received data alone cannot detect a dropped chunk if later chunks shift.
    for i, part in enumerate(parts):
        expected = lengths[i] if i < len(lengths) else 0
        if len(part) != expected:
            raise ValueError(f"output chunk {i} missing, truncated or unexpected (expected {expected} characters, got {len(part)})")
    return "".join(parts), digests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("encode", "decode"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("names", nargs="+")
    args = parser.parse_args()
    if args.mode == "encode":
        payload, digests = encode(args.directory, args.names)
        # One call emits the entire job bundle, so the limit is combined.
        lines = [f"part{i}={payload[i * CHUNK_SIZE : (i + 1) * CHUNK_SIZE]}\n" for i in range(CHUNKS)]
        lines += [f"sha256_{i}={digests[name]}\n" for i, name in enumerate(args.names)]
        manifest = {"chunks": [len(payload[i : i + CHUNK_SIZE]) for i in range(0, len(payload), CHUNK_SIZE)], "files": digests}
        lines.append("manifest=" + json.dumps(manifest, separators=(",", ":")) + "\n")
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="ascii") as output:
            output.writelines(lines)
    else:
        payload, digests = read_outputs(args.names)
        decode(args.directory, args.names, payload, digests)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, EOFError, tarfile.TarError) as error:
        print(f"transport: {error}", file=sys.stderr)
        sys.exit(1)
