#!/usr/bin/env bash
# benchmarks/run_local.sh — measure per-stage wall-clock of the real CLI flow.
# Produces benchmarks/results/e2e_local.csv with header:
#   stage,rep,duration_ms
# Default repetitions: R=30 (override with R=<n> ./benchmarks/run_local.sh)
set -euo pipefail

# ── 0. Environment ────────────────────────────────────────────────────────────
export PATH=/home/hunor/.local/go/bin:$PATH

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${REPO_ROOT}/bin"
RESULTS_DIR="${REPO_ROOT}/benchmarks/results"
CSV_OUT="${RESULTS_DIR}/e2e_local.csv"
R="${R:-30}"

mkdir -p "${BIN_DIR}" "${RESULTS_DIR}"

# ── 1. Build binaries ─────────────────────────────────────────────────────────
echo "[run_local.sh] Building binaries into ${BIN_DIR} ..."
for pkg_name in keygen sign verify gate; do
    out="${BIN_DIR}/${pkg_name}"
    # cmd/sign builds the attest binary; keep the output name consistent
    if [[ "${pkg_name}" == "sign" ]]; then
        out="${BIN_DIR}/attest"
    fi
    go build -o "${out}" "${REPO_ROOT}/cmd/${pkg_name}"
    echo "  built ${out}"
done

KEYGEN="${BIN_DIR}/keygen"
ATTEST="${BIN_DIR}/attest"
VERIFY="${BIN_DIR}/verify"
GATE="${BIN_DIR}/gate"

# ── 2. Generate key pair into temp dir ───────────────────────────────────────
TMPDIR="$(mktemp -d /tmp/devsecops-bench-XXXXXX)"
trap 'rm -rf "${TMPDIR}"' EXIT

KEYS_DIR="${TMPDIR}/keys"
mkdir -p "${KEYS_DIR}"
"${KEYGEN}" --out "${KEYS_DIR}"
PRIV_HEX="$(cat "${KEYS_DIR}/private.hex")"
PUB_HEX="$(cat  "${KEYS_DIR}/public.hex")"

# ── 3. Write minimal passing result JSON for each check type ─────────────────
SAST_JSON="${TMPDIR}/sast.json"
SCA_JSON="${TMPDIR}/sca.json"
CONFIG_JSON="${TMPDIR}/config.json"
SECRET_JSON="${TMPDIR}/secret.json"
for f in "${SAST_JSON}" "${SCA_JSON}" "${CONFIG_JSON}" "${SECRET_JSON}"; do
    printf '{"passed":true,"findings":[]}' > "${f}"
done

CHAIN_PATH="${TMPDIR}/chain.json"

# ── 4. Freshly write CSV header ───────────────────────────────────────────────
printf 'stage,rep,duration_ms\n' > "${CSV_OUT}"

# ── 5. Helper: time a command and append a CSV row ───────────────────────────
# Usage: time_stage <stage_name> <rep> <cmd...>
# Uses date +%s%N for integer nanoseconds — avoids locale decimal-separator issues.
time_stage() {
    local stage="$1"
    local rep="$2"
    shift 2

    local t_start t_end duration_ms
    t_start="$(date +%s%N)"
    "$@"
    t_end="$(date +%s%N)"

    # Compute ms: integer nanoseconds → milliseconds
    duration_ms="$(awk "BEGIN { printf \"%.3f\", (${t_end} - ${t_start}) / 1000000 }")"
    printf '%s,%s,%s\n' "${stage}" "${rep}" "${duration_ms}" >> "${CSV_OUT}"
}

# ── 6. Measurement loop ───────────────────────────────────────────────────────
echo "[run_local.sh] Running ${R} repetitions of sign×4 → verify → gate ..."

for rep in $(seq 1 "${R}"); do
    # Fresh chain for each repetition
    rm -f "${CHAIN_PATH}"

    time_stage "sign_sast"   "${rep}" \
        "${ATTEST}" \
            --check-type sast --tool semgrep --result "${SAST_JSON}" \
            --target-ref abc123 --subject myapp \
            --signing-key "${PRIV_HEX}" --chain "${CHAIN_PATH}"

    time_stage "sign_sca"    "${rep}" \
        "${ATTEST}" \
            --check-type sca --tool trivy --result "${SCA_JSON}" \
            --target-ref abc123 --subject myapp \
            --signing-key "${PRIV_HEX}" --chain "${CHAIN_PATH}"

    time_stage "sign_config" "${rep}" \
        "${ATTEST}" \
            --check-type config --tool checkov --result "${CONFIG_JSON}" \
            --target-ref abc123 --subject myapp \
            --signing-key "${PRIV_HEX}" --chain "${CHAIN_PATH}"

    time_stage "sign_secret" "${rep}" \
        "${ATTEST}" \
            --check-type secret --tool gitleaks --result "${SECRET_JSON}" \
            --target-ref abc123 --subject myapp \
            --signing-key "${PRIV_HEX}" --chain "${CHAIN_PATH}"

    time_stage "verify"         "${rep}" \
        "${VERIFY}" \
            --chain "${CHAIN_PATH}" --verify-signer "${PUB_HEX}"

    time_stage "gate_evaluate"  "${rep}" \
        "${GATE}" evaluate \
            --chain "${CHAIN_PATH}" --verify-signer "${PUB_HEX}"
done

# ── 7. Summary stats ─────────────────────────────────────────────────────────
echo "[run_local.sh] Done.  Results written to ${CSV_OUT}"
echo "[run_local.sh] Row count (data only): $(tail -n +2 "${CSV_OUT}" | wc -l)"

echo ""
echo "Per-stage mean (ms):"
awk -F',' 'NR>1 { sum[$1]+=$3; cnt[$1]++ }
     END   { for (s in sum) printf "  %-20s %.3f ms\n", s, sum[s]/cnt[s] }
' "${CSV_OUT}" | sort
