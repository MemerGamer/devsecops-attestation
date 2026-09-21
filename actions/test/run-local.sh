#!/usr/bin/env bash
# actions/test/run-local.sh
#
# Local, rerunnable exercise of the actions/*/*.sh scripts without an actual
# GitHub/Forgejo runner. Builds the CLI binaries, generates keys, normalizes
# and signs the four normalize-sign fixtures, and runs gate.sh through both
# allow and deny paths. Also exercises setup.sh's "source" build path and its
# download path against a locally served fake release.
#
# This script does not modify anything under actions/ or the repository
# root; all state lives in a temp directory.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ACTIONS_DIR="${REPO_ROOT}/actions"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/devsecops-actions-test.XXXXXX")"
PASS=0
FAIL=0

cleanup() {
	if [ -n "${HTTP_SERVER_PID:-}" ] && kill -0 "${HTTP_SERVER_PID}" 2>/dev/null; then
		kill "${HTTP_SERVER_PID}" 2>/dev/null || true
		wait "${HTTP_SERVER_PID}" 2>/dev/null || true
	fi
	rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

log() { printf '\n=== %s ===\n' "$*"; }

check() {
	# check <description> <expected_exit> <actual_exit>
	local desc="$1" expected="$2" actual="$3"
	if [ "${expected}" = "${actual}" ]; then
		printf 'PASS: %s (exit %s)\n' "${desc}" "${actual}"
		PASS=$((PASS + 1))
	else
		printf 'FAIL: %s (expected exit %s, got %s)\n' "${desc}" "${expected}" "${actual}"
		FAIL=$((FAIL + 1))
	fi
}

check_true() {
	# check_true <description> <bash-condition-as-string-already-evaluated-as-0/1>
	local desc="$1" ok="$2"
	if [ "${ok}" = "0" ]; then
		printf 'PASS: %s\n' "${desc}"
		PASS=$((PASS + 1))
	else
		printf 'FAIL: %s\n' "${desc}"
		FAIL=$((FAIL + 1))
	fi
}

# ---------------------------------------------------------------------------
# 0. Build binaries directly (used for normalize-sign/gate exercises; the
#    setup.sh "source" path is exercised separately below because it does
#    its own build into its own directory).
# ---------------------------------------------------------------------------
log "building CLI binaries"
BIN_DIR="${WORK_DIR}/bin"
mkdir -p "${BIN_DIR}"
(cd "${REPO_ROOT}" && go build -o "${BIN_DIR}/" ./cmd/...)
mv "${BIN_DIR}/sign" "${BIN_DIR}/attest"
export PATH="${BIN_DIR}:${PATH}"
attest --help >/dev/null
gate --help >/dev/null
verify --help >/dev/null
keygen --help >/dev/null
printf 'binaries on PATH: %s\n' "${BIN_DIR}"

# ---------------------------------------------------------------------------
# 1. Generate 4 keys (sast, sca, config, secret)
# ---------------------------------------------------------------------------
log "generating keys"
KEYS_DIR="${WORK_DIR}/keys"
declare -A PRIV PUB
for check in sast sca config secret; do
	mkdir -p "${KEYS_DIR}/${check}"
	keygen --out "${KEYS_DIR}/${check}" >/dev/null
	PRIV[${check}]="$(cat "${KEYS_DIR}/${check}/private.hex")"
	PUB[${check}]="$(cat "${KEYS_DIR}/${check}/public.hex")"
done
AUTHORIZED_SIGNERS="sast=${PUB[sast]},sca=${PUB[sca]},config=${PUB[config]},secret=${PUB[secret]}"

run_normalize_sign() {
	# run_normalize_sign <tool> <check-type> <raw-fixture> <chain-file>
	local tool="$1" check_type="$2" fixture="$3" chain="$4"
	local out_dir
	out_dir="$(mktemp -d "${WORK_DIR}/ns-XXXXXX")"
	local raw="${out_dir}/raw.json"
	cp "${fixture}" "${raw}"

	# Simulate the CI environment attest derives --signer-id/--log-entry
	# from (GITHUB_SERVER_URL, GITHUB_REPOSITORY, GITHUB_WORKFLOW,
	# GITHUB_JOB, GITHUB_RUN_ID), same vars GitHub and Forgejo runners both
	# set, so require-log-entries behaves the same locally as in CI.
	env \
		GITHUB_SERVER_URL="https://example.invalid" \
		GITHUB_REPOSITORY="test/subject" \
		GITHUB_WORKFLOW="local-test" \
		GITHUB_JOB="normalize-sign-test" \
		GITHUB_RUN_ID="1" \
		INPUT_TOOL="${tool}" \
		INPUT_RAW_RESULT="${raw}" \
		INPUT_CHECK_TYPE="" \
		INPUT_SIGNING_KEY="${PRIV[${check_type}]}" \
		INPUT_CHAIN="${chain}" \
		INPUT_SUBJECT="test/subject" \
		INPUT_TARGET_REF="deadbeef" \
		INPUT_TOOL_VERSION="test" \
		INPUT_FAIL_ON="critical" \
		bash "${ACTIONS_DIR}/normalize-sign/normalize-sign.sh"
}

# ---------------------------------------------------------------------------
# 2. normalize-sign.sh x4 (clean fixtures) -> expect=allow chain
# ---------------------------------------------------------------------------
log "normalize-sign: clean fixtures (allow chain)"
ALLOW_CHAIN="${WORK_DIR}/allow-chain.json"
rm -f "${ALLOW_CHAIN}"
rc=0
run_normalize_sign semgrep sast "${REPO_ROOT}/pkg/normalize/testdata/semgrep/clean.json" "${ALLOW_CHAIN}" || rc=$?
check "normalize-sign semgrep clean" 0 "${rc}"
rc=0
run_normalize_sign trivy sca "${REPO_ROOT}/pkg/normalize/testdata/trivy/clean.json" "${ALLOW_CHAIN}" || rc=$?
check "normalize-sign trivy clean" 0 "${rc}"
rc=0
run_normalize_sign checkov config "${REPO_ROOT}/pkg/normalize/testdata/checkov/clean.json" "${ALLOW_CHAIN}" || rc=$?
check "normalize-sign checkov clean" 0 "${rc}"
rc=0
run_normalize_sign gitleaks secret "${REPO_ROOT}/pkg/normalize/testdata/gitleaks/clean.json" "${ALLOW_CHAIN}" || rc=$?
check "normalize-sign gitleaks clean" 0 "${rc}"

chain_len="$(jq 'length' "${ALLOW_CHAIN}" 2>/dev/null || python3 -c "import json;print(len(json.load(open('${ALLOW_CHAIN}'))))")"
check "allow-chain has 4 attestations" 4 "${chain_len}"

# ---------------------------------------------------------------------------
# 3. normalize-sign.sh x4 with gitleaks findings -> expect=deny chain
# ---------------------------------------------------------------------------
log "normalize-sign: gitleaks findings (deny chain)"
DENY_CHAIN="${WORK_DIR}/deny-chain.json"
rm -f "${DENY_CHAIN}"
run_normalize_sign semgrep sast "${REPO_ROOT}/pkg/normalize/testdata/semgrep/clean.json" "${DENY_CHAIN}"
run_normalize_sign trivy sca "${REPO_ROOT}/pkg/normalize/testdata/trivy/clean.json" "${DENY_CHAIN}"
run_normalize_sign checkov config "${REPO_ROOT}/pkg/normalize/testdata/checkov/clean.json" "${DENY_CHAIN}"
run_normalize_sign gitleaks secret "${REPO_ROOT}/pkg/normalize/testdata/gitleaks/findings.json" "${DENY_CHAIN}"
printf 'deny-chain built with %s attestations\n' "$(jq 'length' "${DENY_CHAIN}" 2>/dev/null || echo '?')"

run_gate() {
	# run_gate <chain> <expect> <output>
	# Uses target-ref "deadbeef" by default, matching the fixtures built by
	# run_normalize_sign above (which also signs with target-ref "deadbeef").
	local chain="$1" expect="$2" output="$3"
	rm -f "${output}"
	env \
		INPUT_CHAIN="${chain}" \
		INPUT_AUTHORIZED_SIGNERS="${AUTHORIZED_SIGNERS}" \
		INPUT_VERIFY_SIGNER="" \
		INPUT_POLICY="" \
		INPUT_POLICY_HASH="" \
		INPUT_CONFIG_HASH="" \
		INPUT_DATA="" \
		INPUT_REQUIRED_CHECKS="" \
		INPUT_FAIL_ON_SEVERITY="" \
		INPUT_ZERO_TOLERANCE_CHECKS="" \
		INPUT_TARGET_REF="deadbeef" \
		INPUT_MAX_AGE="24h" \
		INPUT_REQUIRE_LOG_ENTRIES="true" \
		INPUT_OUTPUT="${output}" \
		INPUT_EXPECT="${expect}" \
		bash "${ACTIONS_DIR}/gate/gate.sh"
}

# ---------------------------------------------------------------------------
# 4. gate.sh expect=allow on the clean chain -> should pass (exit 0)
# ---------------------------------------------------------------------------
log "gate: allow-chain, expect=allow (should PASS)"
rc=0
run_gate "${ALLOW_CHAIN}" allow "${WORK_DIR}/allow-decision.json" || rc=$?
check "gate allow-chain expect=allow" 0 "${rc}"

# ---------------------------------------------------------------------------
# 5. gate.sh expect=deny on the findings chain -> should pass (exit 0,
#    "denied as expected")
# ---------------------------------------------------------------------------
log "gate: deny-chain, expect=deny (should PASS, denied as expected)"
rc=0
run_gate "${DENY_CHAIN}" deny "${WORK_DIR}/deny-decision.json" || rc=$?
check "gate deny-chain expect=deny" 0 "${rc}"

# ---------------------------------------------------------------------------
# 6. gate.sh expect=allow on the findings chain -> should FAIL (exit 1)
# ---------------------------------------------------------------------------
log "gate: deny-chain, expect=allow (should FAIL, policy denies)"
rc=0
run_gate "${DENY_CHAIN}" allow "${WORK_DIR}/deny-as-allow-decision.json" || rc=$?
check "gate deny-chain expect=allow" 1 "${rc}"

# ---------------------------------------------------------------------------
# 7. gate.sh expect=any never fails on decision, either chain
# ---------------------------------------------------------------------------
log "gate: expect=any on both chains (should PASS both)"
rc=0
run_gate "${ALLOW_CHAIN}" any "${WORK_DIR}/any-allow-decision.json" || rc=$?
check "gate allow-chain expect=any" 0 "${rc}"
rc=0
run_gate "${DENY_CHAIN}" any "${WORK_DIR}/any-deny-decision.json" || rc=$?
check "gate deny-chain expect=any" 0 "${rc}"

# ---------------------------------------------------------------------------
# 7b. gate.sh with an empty max-age (documented as "no limit") must not pass
#     --max-age "" to `gate evaluate` (an empty string is not a valid Go
#     duration and would fail to parse).
# ---------------------------------------------------------------------------
log "gate: empty max-age means no limit (should PASS)"
rc=0
env \
	INPUT_CHAIN="${ALLOW_CHAIN}" \
	INPUT_AUTHORIZED_SIGNERS="${AUTHORIZED_SIGNERS}" \
	INPUT_VERIFY_SIGNER="" \
	INPUT_POLICY="" \
	INPUT_POLICY_HASH="" \
	INPUT_CONFIG_HASH="" \
	INPUT_DATA="" \
	INPUT_REQUIRED_CHECKS="" \
	INPUT_FAIL_ON_SEVERITY="" \
	INPUT_ZERO_TOLERANCE_CHECKS="" \
	INPUT_TARGET_REF="deadbeef" \
	INPUT_MAX_AGE="" \
	INPUT_REQUIRE_LOG_ENTRIES="true" \
	INPUT_OUTPUT="${WORK_DIR}/empty-max-age-decision.json" \
	INPUT_EXPECT="allow" \
	bash "${ACTIONS_DIR}/gate/gate.sh" || rc=$?
check "gate empty max-age (no limit)" 0 "${rc}"

# ---------------------------------------------------------------------------
# 7c. gate.sh commit binding: a target-ref that does not match the chain's
#     attestations (all signed with target-ref "deadbeef" above) must fail
#     closed with decision=error, before policy evaluation, regardless of
#     --expect.
# ---------------------------------------------------------------------------
log "gate: target-ref mismatch (should FAIL, evaluation error not deny)"
rc=0
env \
	INPUT_CHAIN="${ALLOW_CHAIN}" \
	INPUT_AUTHORIZED_SIGNERS="${AUTHORIZED_SIGNERS}" \
	INPUT_VERIFY_SIGNER="" \
	INPUT_POLICY="" \
	INPUT_POLICY_HASH="" \
	INPUT_CONFIG_HASH="" \
	INPUT_DATA="" \
	INPUT_REQUIRED_CHECKS="" \
	INPUT_FAIL_ON_SEVERITY="" \
	INPUT_ZERO_TOLERANCE_CHECKS="" \
	INPUT_TARGET_REF="some-other-commit" \
	INPUT_MAX_AGE="24h" \
	INPUT_REQUIRE_LOG_ENTRIES="true" \
	INPUT_OUTPUT="${WORK_DIR}/target-ref-mismatch-decision.json" \
	INPUT_EXPECT="any" \
	bash "${ACTIONS_DIR}/gate/gate.sh" || rc=$?
check "gate target-ref mismatch fails even with expect=any" 1 "${rc}"

# ---------------------------------------------------------------------------
# 8. gate.sh evaluation error case (unauthorized signer key) must fail
#    regardless of expect, and must be reported as decision=error, not deny.
# ---------------------------------------------------------------------------
log "gate: wrong authorized-signers (evaluation error, should FAIL even with expect=any)"
BAD_KEYGEN_DIR="${WORK_DIR}/badkey"
mkdir -p "${BAD_KEYGEN_DIR}"
keygen --out "${BAD_KEYGEN_DIR}" >/dev/null
BAD_PUB="$(cat "${BAD_KEYGEN_DIR}/public.hex")"
rc=0
env \
	INPUT_CHAIN="${ALLOW_CHAIN}" \
	INPUT_AUTHORIZED_SIGNERS="sast=${BAD_PUB},sca=${PUB[sca]},config=${PUB[config]},secret=${PUB[secret]}" \
	INPUT_VERIFY_SIGNER="" \
	INPUT_POLICY="" \
	INPUT_POLICY_HASH="" \
	INPUT_CONFIG_HASH="" \
	INPUT_DATA="" \
	INPUT_REQUIRED_CHECKS="" \
	INPUT_FAIL_ON_SEVERITY="" \
	INPUT_ZERO_TOLERANCE_CHECKS="" \
	INPUT_TARGET_REF="deadbeef" \
	INPUT_MAX_AGE="24h" \
	INPUT_REQUIRE_LOG_ENTRIES="true" \
	INPUT_OUTPUT="${WORK_DIR}/error-decision.json" \
	INPUT_EXPECT="any" \
	bash "${ACTIONS_DIR}/gate/gate.sh" || rc=$?
check "gate wrong-signer expect=any still fails" 1 "${rc}"

# ---------------------------------------------------------------------------
# 9. setup.sh "source" build path
# ---------------------------------------------------------------------------
log "setup.sh: source build path"
SOURCE_INSTALL_DIR="${WORK_DIR}/setup-source-install"
rc=0
env \
	INPUT_VERSION="source" \
	INPUT_REPOSITORY="MemerGamer/devsecops-attestation" \
	INPUT_DOWNLOAD_BASE_URL="unused" \
	INPUT_INSTALL_DIR="${SOURCE_INSTALL_DIR}" \
	INPUT_VERIFY_SIGNATURE="false" \
	GITHUB_ACTION_PATH="${ACTIONS_DIR}/setup" \
	bash "${ACTIONS_DIR}/setup/setup.sh" || rc=$?
check "setup.sh source build" 0 "${rc}"
for bin in keygen attest verify gate; do
	ok=1
	[ -x "${SOURCE_INSTALL_DIR}/${bin}" ] && ok=0
	check_true "setup.sh source installed ${bin}" "${ok}"
done
ok=1
[ -f "${SOURCE_INSTALL_DIR}/deploy.rego" ] && ok=0
check_true "setup.sh source installed deploy.rego" "${ok}"

if command -v shellcheck >/dev/null 2>&1; then
	rc=0
	shellcheck "${ACTIONS_DIR}/setup/setup.sh" || rc=$?
	check "shellcheck setup.sh (post-edit)" 0 "${rc}"
fi

# ---------------------------------------------------------------------------
# 10. setup.sh download path against a fake local release served over HTTP
# ---------------------------------------------------------------------------
log "setup.sh: download path against fake local release"

FAKE_RELEASE_ROOT="${WORK_DIR}/fake-release"
FAKE_VERSION="9.9.9"
FAKE_TAG="v${FAKE_VERSION}"
RELEASE_DIR="${FAKE_RELEASE_ROOT}/releases/download/${FAKE_TAG}"
mkdir -p "${RELEASE_DIR}"

# Build the archive contents: reuse the already-built binaries, named the
# way the real goreleaser archive names them (attest, not sign).
FAKE_OS="linux"
case "$(uname -m)" in
x86_64) FAKE_ARCH="amd64" ;;
aarch64 | arm64) FAKE_ARCH="arm64" ;;
*) FAKE_ARCH="amd64" ;;
esac
ARCHIVE_STAGE="${WORK_DIR}/archive-stage"
mkdir -p "${ARCHIVE_STAGE}/policies"
cp "${BIN_DIR}/keygen" "${BIN_DIR}/attest" "${BIN_DIR}/verify" "${BIN_DIR}/gate" "${ARCHIVE_STAGE}/"
cp "${REPO_ROOT}/policies/deploy.rego" "${ARCHIVE_STAGE}/policies/deploy.rego"
ARCHIVE_NAME="devsecops-attestation_${FAKE_VERSION}_${FAKE_OS}_${FAKE_ARCH}.tar.gz"
(cd "${ARCHIVE_STAGE}" && tar -czf "${RELEASE_DIR}/${ARCHIVE_NAME}" keygen attest verify gate policies)

# goreleaser also emits a sibling "<archive>.sbom.json" checksum line in the
# real checksums.txt; include one here so the checksum lookup regression
# (a plain substring grep matching this sibling entry too, and choking
# sha256sum -c with two lines) is covered.
SBOM_NAME="${ARCHIVE_NAME}.sbom.json"
printf '{}' >"${RELEASE_DIR}/${SBOM_NAME}"
(
	cd "${RELEASE_DIR}"
	sha256sum "${ARCHIVE_NAME}" "${SBOM_NAME}" >checksums.txt
)

# Use a random high port and start the server without an enclosing subshell
# so $! is the actual python process (a subshelled `(...) &` backgrounds the
# subshell, not python, which makes `kill "$!"` unreliable on rerun).
PORT=$((20000 + RANDOM % 20000))
python3 -m http.server "${PORT}" --directory "${FAKE_RELEASE_ROOT}" --bind 127.0.0.1 >/dev/null 2>&1 &
HTTP_SERVER_PID=$!
for _ in $(seq 1 20); do
	if curl -fsS "http://127.0.0.1:${PORT}/" >/dev/null 2>&1; then
		break
	fi
	sleep 0.2
done

DL_INSTALL_DIR="${WORK_DIR}/setup-download-install"
rc=0
env \
	INPUT_VERSION="${FAKE_VERSION}" \
	INPUT_REPOSITORY="MemerGamer/devsecops-attestation" \
	INPUT_DOWNLOAD_BASE_URL="http://127.0.0.1:${PORT}/releases/download" \
	INPUT_INSTALL_DIR="${DL_INSTALL_DIR}" \
	INPUT_VERIFY_SIGNATURE="false" \
	RUNNER_OS="Linux" \
	RUNNER_ARCH="$([ "${FAKE_ARCH}" = "amd64" ] && echo X64 || echo ARM64)" \
	RUNNER_TEMP="${WORK_DIR}" \
	GITHUB_ACTION_PATH="${ACTIONS_DIR}/setup" \
	bash "${ACTIONS_DIR}/setup/setup.sh" || rc=$?
check "setup.sh download path (valid checksum)" 0 "${rc}"
ok=1
[ -x "${DL_INSTALL_DIR}/attest" ] && ok=0
check_true "setup.sh download installed attest" "${ok}"

# Tampered checksums.txt must fail closed.
TAMPER_TAG_DIR="${FAKE_RELEASE_ROOT}/releases/download/v8.8.8"
mkdir -p "${TAMPER_TAG_DIR}"
TAMPER_ARCHIVE="devsecops-attestation_8.8.8_${FAKE_OS}_${FAKE_ARCH}.tar.gz"
cp "${RELEASE_DIR}/${ARCHIVE_NAME}" "${TAMPER_TAG_DIR}/${TAMPER_ARCHIVE}"
printf '0000000000000000000000000000000000000000000000000000000000000  %s\n' "${TAMPER_ARCHIVE}" >"${TAMPER_TAG_DIR}/checksums.txt"

TAMPER_INSTALL_DIR="${WORK_DIR}/setup-tampered-install"
rc=0
env \
	INPUT_VERSION="8.8.8" \
	INPUT_REPOSITORY="MemerGamer/devsecops-attestation" \
	INPUT_DOWNLOAD_BASE_URL="http://127.0.0.1:${PORT}/releases/download" \
	INPUT_INSTALL_DIR="${TAMPER_INSTALL_DIR}" \
	INPUT_VERIFY_SIGNATURE="false" \
	RUNNER_OS="Linux" \
	RUNNER_ARCH="$([ "${FAKE_ARCH}" = "amd64" ] && echo X64 || echo ARM64)" \
	RUNNER_TEMP="${WORK_DIR}" \
	GITHUB_ACTION_PATH="${ACTIONS_DIR}/setup" \
	bash "${ACTIONS_DIR}/setup/setup.sh" || rc=$?
check "setup.sh download path (tampered checksum must fail)" 1 "${rc}"

kill "${HTTP_SERVER_PID}" 2>/dev/null || true
wait "${HTTP_SERVER_PID}" 2>/dev/null || true
unset HTTP_SERVER_PID

# ---------------------------------------------------------------------------
# 11. static checks: shellcheck the run scripts, validate action.yml files
# ---------------------------------------------------------------------------
log "static checks"
if command -v shellcheck >/dev/null 2>&1; then
	rc=0
	shellcheck "${ACTIONS_DIR}/setup/setup.sh" "${ACTIONS_DIR}/normalize-sign/normalize-sign.sh" "${ACTIONS_DIR}/gate/gate.sh" || rc=$?
	check "shellcheck" 0 "${rc}"
else
	printf 'SKIP: shellcheck not installed\n'
fi

rc=0
python3 - "${ACTIONS_DIR}" <<'EOF' || rc=$?
import sys, yaml, pathlib
actions_dir = pathlib.Path(sys.argv[1])
for name in ("setup", "normalize-sign", "gate"):
    p = actions_dir / name / "action.yml"
    with open(p) as f:
        d = yaml.safe_load(f)
    assert d["runs"]["using"] == "composite", p
    # The runner evaluates expressions in metadata and rejects contexts such
    # as github.* inside descriptions, so descriptions must stay literal.
    sections = [d.get("inputs") or {}, d.get("outputs") or {}]
    for section in sections:
        for key, spec in section.items():
            desc = (spec or {}).get("description", "")
            assert "${{" not in desc, f"{p}: expression in description of {key}"
    assert "${{" not in d.get("description", ""), f"{p}: expression in description"
    print(f"{p}: OK")
EOF
check "action.yml validation" 0 "${rc}"

if command -v act >/dev/null 2>&1; then
	printf 'NOTE: act is installed; not run automatically by this script.\n'
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log "summary"
printf 'passed: %d, failed: %d\n' "${PASS}" "${FAIL}"
if [ "${FAIL}" -gt 0 ]; then
	exit 1
fi
exit 0
