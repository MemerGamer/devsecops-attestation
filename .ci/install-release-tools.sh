#!/usr/bin/env bash
# Only reviewed linux/amd64 tools with repository-pinned digests are accepted.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(uname -s)/$(uname -m)" = Linux/x86_64 ] || { echo 'release builds require linux/amd64' >&2; exit 1; }
: "${RELEASE_TOOLS_DIR:?RELEASE_TOOLS_DIR is required}"
mkdir -p "${RELEASE_TOOLS_DIR}"
RELEASE_TOOLS_DIR="$(cd "${RELEASE_TOOLS_DIR}" && pwd)"
python3 - "${RELEASE_TOOLS_DIR}" "$@" <<'PY'
import hashlib, json, os, re, subprocess, sys, tempfile
from pathlib import Path
pins = json.loads(Path('.ci/release-tools.json').read_text())
for name in sys.argv[2:] or ('goreleaser', 'syft'):
    pin = pins[name]
    if not re.fullmatch('[0-9a-f]{64}', pin['sha256']):
        raise SystemExit('release tool pin audit incomplete: '+name)
    with tempfile.TemporaryDirectory(prefix='release-tool-') as scratch:
        archive = Path(scratch)/'tool.tar.gz'
        subprocess.run(['curl', '-fsSL', '--retry', '5', '--connect-timeout', '20', '--max-time', '300', pin['url'], '-o', str(archive)], check=True)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != pin['sha256']:
            raise SystemExit('release tool archive digest mismatch: '+name)
        destination = Path(sys.argv[1])/name
        if name.startswith('cosign-'):
            destination.write_bytes(archive.read_bytes())
            destination.chmod(0o700)
            continue
        # Extract only the expected regular binary, never archive paths.
        import tarfile
        with tarfile.open(archive, 'r:gz') as tar:
            matches = [m for m in tar if m.name == name and m.isfile()]
            if len(matches) != 1:
                raise SystemExit('missing or duplicate release tool binary: '+name)
            with destination.open('wb') as output:
                output.write(tar.extractfile(matches[0]).read())
            destination.chmod(0o700)
PY
