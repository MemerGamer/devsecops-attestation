#!/usr/bin/env bash
# Print a conventional-commit changelog section. Does not mutate refs or files.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "${1:-}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
	echo 'usage: scripts/release-changelog.sh VERSION [PREVIOUS_TAG]' >&2; exit 1;
}
previous="${2:-$(git describe --tags --abbrev=0 --match 'v[0-9]*')}"
git rev-parse --verify "${previous}^{commit}" >/dev/null
python3 - "$1" "${previous}" <<'PY'
import datetime, re, subprocess, sys
version, previous = sys.argv[1:]
base = 'https://forgejo.remote.kovacsbalinthunor.com/kbalinthunor/devsecops-attestation'
groups = dict.fromkeys(['Breaking Changes', 'Features', 'Bug Fixes', 'Performance Improvements', 'Refactoring', 'Documentation', 'Tests', 'CI/CD', 'Miscellaneous Chores'])
groups = {k: [] for k in groups}
types = {'feat': 'Features', 'fix': 'Bug Fixes', 'perf': 'Performance Improvements', 'refactor': 'Refactoring', 'docs': 'Documentation', 'test': 'Tests', 'ci': 'CI/CD', 'chore': 'Miscellaneous Chores'}
raw = subprocess.check_output(['git', 'log', '--no-merges', '--format=%H%x00%s%x00%b%x00', previous+'..HEAD']).decode()
parts = raw.split('\x00')
for i in range(0, len(parts)-2, 3):
    sha, subject, body = (s.strip() for s in parts[i:i+3])
    m = re.match(r'([a-z,]+)(?:\(([^)]*)\))?(!)?: (.+)', subject)
    if not m:
        group, text = 'Miscellaneous Chores', subject
    else:
        kind, scope, breaking, text = m.groups()
        if scope:
            text = f'**{scope}:** {text}'
        group = types.get(kind.split(',')[0], 'Miscellaneous Chores')
        if breaking or 'BREAKING CHANGE:' in body:
            groups['Breaking Changes'].append(text)
    groups[group].append(f'{text} ([{sha[:7]}]({base}/commit/{sha}))')
print(f'## [{version}]({base}/compare/{previous}...v{version}) ({datetime.date.today().isoformat()})')
for name, entries in groups.items():
    if entries:
        print('\n### '+name+'\n')
        print('\n'.join('* '+e for e in entries))
PY
