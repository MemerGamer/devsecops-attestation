#!/usr/bin/env bash
# Human-only local entry point. There is deliberately no noninteractive bypass.
set -euo pipefail
for name in CI GITHUB_ACTIONS FORGEJO_ACTIONS GITEA_ACTIONS GITHUB_RUN_ID GITEA_RUN_ID FORGEJO_RUN_ID RUNNER_ENVIRONMENT; do
	if [ "${!name+x}" ]; then
		printf 'error: release publisher is forbidden in CI (%s is set)\n' "${name}" >&2
		exit 1
	fi
done
[ -t 0 ] && [ -t 1 ] || { echo 'error: release publisher requires Hunor at an interactive terminal' >&2; exit 1; }
cd "$(dirname "$0")/.."
exec python3 scripts/release_publish.py "$@"
