#!/usr/bin/env bash
# Only reviewed linux/amd64 tools with repository-pinned digests are accepted.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(uname -s)/$(uname -m)" = Linux/x86_64 ] || { echo 'release builds require linux/amd64' >&2; exit 1; }
: "${RELEASE_TOOLS_DIR:?RELEASE_TOOLS_DIR is required}"
mkdir -p "${RELEASE_TOOLS_DIR}"
RELEASE_TOOLS_DIR="$(cd "${RELEASE_TOOLS_DIR}" && pwd)"
python3 - "${RELEASE_TOOLS_DIR}" "$@" <<'PY'
import hashlib, io, json, os, re, subprocess, sys, tarfile, tempfile
from pathlib import Path
pins = json.loads(Path('.ci/release-tools.json').read_text())
for name in sys.argv[2:] or ('goreleaser', 'syft'):
    pin = pins[name]
    if not re.fullmatch('[0-9a-f]{64}', pin['sha256']):
        raise SystemExit('release tool pin audit incomplete: '+name)
    # Pins name official GitHub release assets; refuse any other origin.
    if not pin['url'].startswith('https://github.com/'):
        raise SystemExit('release tool URL must be an https://github.com/ release asset: '+name)
    with tempfile.TemporaryDirectory(prefix='release-tool-') as scratch:
        archive = Path(scratch)/'tool.tar.gz'
        subprocess.run(['curl', '-fsSL', '--proto', '=https', '--tlsv1.2', '--retry', '5', '--connect-timeout', '20', '--max-time', '300', pin['url'], '-o', str(archive)], check=True)
        # Read once: the bytes that were hashed are the bytes written or extracted.
        data = archive.read_bytes()
        if hashlib.sha256(data).hexdigest() != pin['sha256']:
            raise SystemExit('release tool archive digest mismatch: '+name)
        destination = Path(sys.argv[1])/name
        if name.startswith('cosign-'):
            destination.write_bytes(data)
            destination.chmod(0o700)
            continue
        # Extract only the expected regular binary, never archive paths.
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
            matches = [m for m in tar if m.name == name and m.isfile()]
            if len(matches) != 1:
                raise SystemExit('missing or duplicate release tool binary: '+name)
            with destination.open('wb') as output:
                output.write(tar.extractfile(matches[0]).read())
            destination.chmod(0o700)
PY
