#!/usr/bin/env bash
# Check only the event-selected key set; never fall back from test to production.
set -euo pipefail
case "${KEY_SET:?KEY_SET is required}" in
production) prefix='' ;;
test) prefix='TEST_' ;;
*) echo 'invalid signing key set' >&2; exit 1 ;;
esac
for name in SAST_SIGNING_KEY SCA_SIGNING_KEY CONFIG_SIGNING_KEY SECRET_SCANNING_SIGNING_KEY \
	SAST_PUBLIC_KEY SCA_PUBLIC_KEY CONFIG_PUBLIC_KEY SECRET_SCANNING_PUBLIC_KEY; do
	if [[ -z "${!name:-}" ]]; then
		printf 'selected %s secret %s%s is empty; refusing to sign\n' "${KEY_SET}" "${prefix}" "${name}" >&2
		exit 1
	fi
done
