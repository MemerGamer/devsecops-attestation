#!/usr/bin/env bash
# Hunor runs this on a clean, current main checkout to prepare the release PR.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "${1:-}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
	echo 'usage: scripts/release-prep.sh VERSION' >&2; exit 1;
}
[ -z "$(git status --porcelain)" ] || { echo 'release preparation requires a clean checkout' >&2; exit 1; }
[ "$(git branch --show-current)" = main ] || { echo 'release preparation requires main' >&2; exit 1; }
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || { echo 'main must equal origin/main; fetch and review first' >&2; exit 1; }
! git rev-parse --verify "refs/tags/v$1" >/dev/null 2>&1 || { echo 'release tag already exists' >&2; exit 1; }
! rg -q "^## \\[$1\\]" CHANGELOG.md || { echo 'changelog already contains this version' >&2; exit 1; }
section="$(scripts/release-changelog.sh "$1")"
git switch -c "release/v$1"
CHANGELOG_SECTION="${section}" python3 - <<'PY'
import os
from pathlib import Path
p = Path('CHANGELOG.md')
old = p.read_text()
assert old.startswith('# Changelog\n')
p.write_text('# Changelog\n\n'+os.environ['CHANGELOG_SECTION']+'\n\n'+old[len('# Changelog\n'):].lstrip())
PY
printf 'prepared release/v%s; review CHANGELOG.md and open a PR; Hunor alone commits, tags and publishes\n' "$1"
