#!/usr/bin/env bash
# actions/gate/gate.sh
#
# Verifies an attestation chain and evaluates it against the deploy gate
# policy, then interprets the result according to INPUT_EXPECT.
#
# Decision vs. error: `gate evaluate` exits non-zero both when the policy
# denies deployment AND when evaluation itself cannot proceed (chain
# verification failure, unauthorized signer, missing log entry, policy/config
# hash mismatch, malformed --data, ...). Those two cases are told apart by
# whether a GateDecision JSON document was actually produced: on a policy
# allow or deny, `gate evaluate --output <path>` always writes that file
# (Allow: true/false plus Reasons) before it exits; on every pre-evaluation
# error it exits before ever writing that file. So: no output file, or an
# output file that fails to parse as GateDecision JSON, means "gate could not
# evaluate", which is always a hard failure regardless of --expect. Only a
# parsed GateDecision is treated as a decision subject to --expect.
set -euo pipefail

: "${INPUT_CHAIN:?INPUT_CHAIN is required}"
: "${INPUT_MAX_AGE:=}"
: "${INPUT_REQUIRE_LOG_ENTRIES:?INPUT_REQUIRE_LOG_ENTRIES is required}"
: "${INPUT_OUTPUT:?INPUT_OUTPUT is required}"
: "${INPUT_EXPECT:?INPUT_EXPECT is required}"

if [ -z "${INPUT_VERIFY_SIGNER:-}" ] && [ -z "${INPUT_AUTHORIZED_SIGNERS:-}" ]; then
	printf '[gate] error: one of verify-signer or authorized-signers is required\n' >&2
	exit 1
fi

case "${INPUT_EXPECT}" in
allow | deny | any) ;;
*)
	printf '[gate] error: expect must be allow, deny, or any (got %q)\n' "${INPUT_EXPECT}" >&2
	exit 1
	;;
esac

if [ ! -f "${INPUT_CHAIN}" ]; then
	printf '[gate] error: chain file not found: %s\n' "${INPUT_CHAIN}" >&2
	exit 1
fi

write_output() {
	if [ -n "${GITHUB_OUTPUT:-}" ]; then
		printf '%s=%s\n' "$1" "$2" >>"${GITHUB_OUTPUT}"
	fi
}

summary() {
	# Appends a line to GITHUB_STEP_SUMMARY when the runner provides one.
	if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
		printf '%s\n' "$1" >>"${GITHUB_STEP_SUMMARY}"
	fi
}

# --- step 1: independent chain verification, ahead of policy evaluation ---
# This mirrors what `gate evaluate` does internally (defense in depth: a
# dedicated `verify` run with its own exit code, kept separate from the
# policy decision below).
verify_args=(--chain "${INPUT_CHAIN}")
if [ -n "${INPUT_VERIFY_SIGNER:-}" ]; then
	verify_args+=(--verify-signer "${INPUT_VERIFY_SIGNER}")
fi

printf '[gate] verify %s\n' "${INPUT_CHAIN}" >&2
if ! verify "${verify_args[@]}"; then
	printf '[gate] error: chain verification failed, see output above\n' >&2
	summary "## Deploy gate: ERROR"
	summary ""
	summary "Chain verification failed before policy evaluation. See job log."
	write_output "decision" "error"
	exit 1
fi

# --- step 2: policy evaluation ---
evaluate_args=(--chain "${INPUT_CHAIN}" --output "${INPUT_OUTPUT}")

if [ -n "${INPUT_MAX_AGE:-}" ]; then
	evaluate_args+=(--max-age "${INPUT_MAX_AGE}")
fi
if [ -n "${INPUT_VERIFY_SIGNER:-}" ]; then
	evaluate_args+=(--verify-signer "${INPUT_VERIFY_SIGNER}")
fi
if [ -n "${INPUT_AUTHORIZED_SIGNERS:-}" ]; then
	evaluate_args+=(--authorized-signers "${INPUT_AUTHORIZED_SIGNERS}")
fi
if [ -n "${INPUT_POLICY:-}" ]; then
	evaluate_args+=(--policy "${INPUT_POLICY}")
fi
if [ -n "${INPUT_POLICY_HASH:-}" ]; then
	evaluate_args+=(--policy-hash "${INPUT_POLICY_HASH}")
fi
if [ -n "${INPUT_CONFIG_HASH:-}" ]; then
	evaluate_args+=(--config-hash "${INPUT_CONFIG_HASH}")
fi
if [ -n "${INPUT_DATA:-}" ]; then
	evaluate_args+=(--data "${INPUT_DATA}")
fi
if [ -n "${INPUT_REQUIRED_CHECKS:-}" ]; then
	evaluate_args+=(--required-checks "${INPUT_REQUIRED_CHECKS}")
fi
if [ -n "${INPUT_FAIL_ON_SEVERITY:-}" ]; then
	evaluate_args+=(--fail-on-severity "${INPUT_FAIL_ON_SEVERITY}")
fi
if [ -n "${INPUT_ZERO_TOLERANCE_CHECKS:-}" ]; then
	evaluate_args+=(--zero-tolerance-checks "${INPUT_ZERO_TOLERANCE_CHECKS}")
fi
if [ "${INPUT_REQUIRE_LOG_ENTRIES}" = "true" ]; then
	evaluate_args+=(--require-log-entries)
fi

printf '[gate] gate evaluate --chain %s --output %s\n' "${INPUT_CHAIN}" "${INPUT_OUTPUT}" >&2
rm -f "${INPUT_OUTPUT}"
eval_exit=0
gate evaluate "${evaluate_args[@]}" || eval_exit=$?

# --- step 3: interpret the result ---
decision_json=""
if [ -f "${INPUT_OUTPUT}" ]; then
	if command -v jq >/dev/null 2>&1; then
		if jq -e 'has("allow")' "${INPUT_OUTPUT}" >/dev/null 2>&1; then
			decision_json="ok"
		fi
	else
		if python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if "allow" in d else 1)' "${INPUT_OUTPUT}" 2>/dev/null; then
			decision_json="ok"
		fi
	fi
fi

if [ -z "${decision_json}" ]; then
	printf '[gate] error: gate evaluate did not produce a decision (exit %s); this is an evaluation error, not a policy deny\n' "${eval_exit}" >&2
	summary "## Deploy gate: ERROR"
	summary ""
	summary "\`gate evaluate\` exited ${eval_exit} without producing a decision. See job log for the cause (chain verification, signer authorization, log entries, or policy/config hash)."
	write_output "decision" "error"
	write_output "report" "${INPUT_OUTPUT}"
	exit 1
fi

if command -v jq >/dev/null 2>&1; then
	allow="$(jq -r '.allow' "${INPUT_OUTPUT}")"
	reasons="$(jq -r '.reasons[]? | "- " + .' "${INPUT_OUTPUT}")"
else
	allow="$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["allow"]).lower())' "${INPUT_OUTPUT}")"
	reasons="$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
for r in d.get("reasons") or []:
    print("- " + r)
' "${INPUT_OUTPUT}")"
fi

if [ "${allow}" = "true" ]; then
	decision="allow"
else
	decision="deny"
fi

write_output "decision" "${decision}"
write_output "report" "${INPUT_OUTPUT}"

# Chain summary stats (best-effort; chain already passed verify above).
if command -v jq >/dev/null 2>&1; then
	chain_length="$(jq 'length' "${INPUT_CHAIN}")"
	check_types="$(jq -r '[.[].result.check_type] | unique | join(", ")' "${INPUT_CHAIN}")"
else
	chain_length="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "${INPUT_CHAIN}")"
	check_types="$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
types = sorted({a["result"]["check_type"] for a in d})
print(", ".join(types))
' "${INPUT_CHAIN}")"
fi

summary_heading="Deploy gate: $(printf '%s' "${decision}" | tr '[:lower:]' '[:upper:]')"
summary "## ${summary_heading}"
summary ""
summary "- Chain: \`${INPUT_CHAIN}\` (${chain_length} attestations: ${check_types})"
summary "- Expected: \`${INPUT_EXPECT}\`"
if [ -n "${reasons}" ]; then
	summary ""
	summary "**Reasons:**"
	summary ""
	summary "${reasons}"
fi

printf '[gate] decision=%s expect=%s\n' "${decision}" "${INPUT_EXPECT}" >&2

case "${INPUT_EXPECT}" in
allow)
	if [ "${decision}" = "deny" ]; then
		printf '[gate] policy denied deployment, expected allow\n' >&2
		exit 1
	fi
	;;
deny)
	if [ "${decision}" = "allow" ]; then
		printf '[gate] policy allowed deployment, expected deny (demo mode)\n' >&2
		exit 1
	fi
	printf '[gate] denied as expected\n' >&2
	;;
any)
	printf '[gate] decision recorded, expect=any so no pass/fail check applied\n' >&2
	;;
esac

exit 0
