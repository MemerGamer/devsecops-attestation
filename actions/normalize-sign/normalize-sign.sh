#!/usr/bin/env bash
# actions/normalize-sign/normalize-sign.sh
#
# Normalizes a raw security tool report (via `attest normalize`, for
# inspection) and signs it into the attestation chain (via `attest sign
# --tool-format`, which normalizes inline). Two calls because the action also
# publishes the normalized-but-unsigned result as an output/artifact for
# debugging, independent of the signing step.
set -euo pipefail

: "${INPUT_TOOL:?INPUT_TOOL is required}"
: "${INPUT_RAW_RESULT:?INPUT_RAW_RESULT is required}"
: "${INPUT_SIGNING_KEY:?INPUT_SIGNING_KEY is required}"
: "${INPUT_CHAIN:?INPUT_CHAIN is required}"
: "${INPUT_SUBJECT:?INPUT_SUBJECT is required}"
: "${INPUT_TARGET_REF:?INPUT_TARGET_REF is required}"
: "${INPUT_TOOL_VERSION:?INPUT_TOOL_VERSION is required}"
: "${INPUT_FAIL_ON:?INPUT_FAIL_ON is required}"

# Never let the signing key hit a trace log; mask it in the job log as early
# as possible. ::add-mask:: is honored by both GitHub Actions and Forgejo
# Actions runners.
printf '::add-mask::%s\n' "${INPUT_SIGNING_KEY}"

if [ ! -f "${INPUT_RAW_RESULT}" ]; then
	printf '[normalize-sign] error: raw-result not found: %s\n' "${INPUT_RAW_RESULT}" >&2
	exit 1
fi

normalized_result="${INPUT_RAW_RESULT}.normalized.json"

normalize_args=(--tool "${INPUT_TOOL}" --in "${INPUT_RAW_RESULT}" --out "${normalized_result}" --fail-on "${INPUT_FAIL_ON}")
printf '[normalize-sign] attest normalize --tool %s --in %s\n' "${INPUT_TOOL}" "${INPUT_RAW_RESULT}" >&2
attest normalize "${normalize_args[@]}"

sign_args=(
	--tool-format "${INPUT_TOOL}"
	--result "${INPUT_RAW_RESULT}"
	--chain "${INPUT_CHAIN}"
	--subject "${INPUT_SUBJECT}"
	--target-ref "${INPUT_TARGET_REF}"
	--tool-version "${INPUT_TOOL_VERSION}"
	--fail-on "${INPUT_FAIL_ON}"
)

if [ -n "${INPUT_CHECK_TYPE:-}" ]; then
	sign_args+=(--check-type "${INPUT_CHECK_TYPE}")
fi
if [ -n "${INPUT_SIGNER_ID:-}" ]; then
	sign_args+=(--signer-id "${INPUT_SIGNER_ID}")
fi
if [ -n "${INPUT_LOG_ENTRY:-}" ]; then
	sign_args+=(--log-entry "${INPUT_LOG_ENTRY}")
fi

printf '[normalize-sign] attest sign --tool-format %s --chain %s\n' "${INPUT_TOOL}" "${INPUT_CHAIN}" >&2
# Pass the signing key via ATTEST_SIGNING_KEY, not argv: an argv value is
# visible to any process that can read /proc/<pid>/cmdline for the
# lifetime of the attest process, which matters on shared runners.
# ::add-mask:: above still covers the job log; this covers argv exposure.
# The assignment is scoped to this one command and never touches the
# script's own environment beyond it.
ATTEST_SIGNING_KEY="${INPUT_SIGNING_KEY}" attest sign "${sign_args[@]}"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
	{
		printf 'chain=%s\n' "${INPUT_CHAIN}"
		printf 'normalized-result=%s\n' "${normalized_result}"
	} >>"${GITHUB_OUTPUT}"
fi

printf '[normalize-sign] appended %s attestation for %s to %s\n' "${INPUT_TOOL}" "${INPUT_SUBJECT}" "${INPUT_CHAIN}" >&2
