#!/usr/bin/env bash
# benchmarks/harvest_ci.sh — harvest per-job durations from GitHub Actions.
# Uses GitHub REST API via curl + jq (no gh CLI required).
# Writes benchmarks/results/ci_runs.csv with header:
#   repo,run_id,run_conclusion,job,job_conclusion,duration_s
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="${REPO_ROOT}/benchmarks/results"
CSV_OUT="${RESULTS_DIR}/ci_runs.csv"
PER_PAGE=20

REPOS=(
    "MemerGamer/Phoenix-DevSecOps-Demo"
    "MemerGamer/Rust-DevSecOps-Demo"
)

mkdir -p "${RESULTS_DIR}"

# ── Set up auth header if $GITHUB_TOKEN is set ───────────────────────────────
AUTH_HEADER=""
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    AUTH_HEADER="-H \"Authorization: Bearer ${GITHUB_TOKEN}\""
    echo "[harvest_ci.sh] Using \$GITHUB_TOKEN for higher rate limits."
else
    echo "[harvest_ci.sh] No \$GITHUB_TOKEN set; proceeding unauthenticated."
fi

# ── Write CSV header (overwrite) ──────────────────────────────────────────────
printf 'repo,run_id,run_conclusion,job,job_conclusion,duration_s\n' > "${CSV_OUT}"

# ── Helper: check for API errors ─────────────────────────────────────────────
check_error() {
    local response="$1"
    local context="$2"
    # Check if response contains "message" field indicating error
    if echo "${response}" | jq -e '.message' &>/dev/null 2>&1; then
        local msg="$(echo "${response}" | jq -r '.message' 2>/dev/null || echo 'unknown')"
        if [[ "${msg}" == *"rate limit"* ]]; then
            echo "[harvest_ci.sh] WARNING: ${context} — ${msg}" >&2
            return 1
        elif [[ "${msg}" == *"Not Found"* ]]; then
            echo "[harvest_ci.sh] WARNING: ${context} — ${msg}" >&2
            return 1
        else
            echo "[harvest_ci.sh] WARNING: ${context} — ${msg}" >&2
            return 1
        fi
    fi
    return 0
}

# ── Helper: parse ISO8601 and compute duration ───────────────────────────────
compute_duration() {
    local started="$1"
    local completed="$2"
    if [[ -z "${started}" ]] || [[ -z "${completed}" ]]; then
        echo "-1"
        return 0
    fi
    # Parse ISO8601 timestamps and compute duration in seconds
    local start_epoch=$(date -d "${started}" +%s 2>/dev/null || echo "0")
    local end_epoch=$(date -d "${completed}" +%s 2>/dev/null || echo "0")
    if [[ "${start_epoch}" -eq 0 ]] || [[ "${end_epoch}" -eq 0 ]]; then
        echo "-1"
    else
        local duration=$((end_epoch - start_epoch))
        echo "${duration}"
    fi
}

# ── Harvest each repo ────────────────────────────────────────────────────────
for repo in "${REPOS[@]}"; do
    echo "[harvest_ci.sh] Fetching last ${PER_PAGE} runs for ${repo} ..."

    # Get recent runs
    runs_response=$(eval "curl -s ${AUTH_HEADER} \"https://api.github.com/repos/${repo}/actions/runs?per_page=${PER_PAGE}\"" || echo '{"workflow_runs":[]}')

    if ! check_error "${runs_response}" "GET /repos/${repo}/actions/runs"; then
        echo "[harvest_ci.sh]   Skipping ${repo} due to API error."
        continue
    fi

    run_count=$(echo "${runs_response}" | jq '.workflow_runs | length' 2>/dev/null || echo 0)
    echo "[harvest_ci.sh]   ${run_count} runs found."

    if [[ "${run_count}" -eq 0 ]]; then
        continue
    fi

    # Iterate over each run
    echo "${runs_response}" | jq -c '.workflow_runs[]' 2>/dev/null | while read -r run_obj; do
        run_id=$(echo "${run_obj}" | jq -r '.id' 2>/dev/null)
        run_conclusion=$(echo "${run_obj}" | jq -r '.conclusion' 2>/dev/null)

        if [[ -z "${run_id}" ]] || [[ "${run_id}" == "null" ]]; then
            continue
        fi

        # Be polite: sleep before detailed request
        sleep 0.5

        # Get jobs for this run
        jobs_response=$(eval "curl -s ${AUTH_HEADER} \"https://api.github.com/repos/${repo}/actions/runs/${run_id}/jobs\"" || echo '{"jobs":[]}')

        if ! check_error "${jobs_response}" "GET /repos/${repo}/actions/runs/${run_id}/jobs"; then
            continue
        fi

        # Extract each job's name, conclusion, and duration
        echo "${jobs_response}" | jq -c '.jobs[]' 2>/dev/null | while read -r job_obj; do
            job_name=$(echo "${job_obj}" | jq -r '.name' 2>/dev/null)
            job_conclusion=$(echo "${job_obj}" | jq -r '.conclusion' 2>/dev/null)
            started_at=$(echo "${job_obj}" | jq -r '.started_at' 2>/dev/null)
            completed_at=$(echo "${job_obj}" | jq -r '.completed_at' 2>/dev/null)

            # Sanitise: replace commas in job names with semicolons
            job_name="${job_name//,/;}"

            # Compute duration
            duration_s=$(compute_duration "${started_at}" "${completed_at}")

            # Write row to CSV
            printf '%s,%s,%s,%s,%s,%s\n' \
                "${repo}" "${run_id}" "${run_conclusion}" "${job_name}" "${job_conclusion}" "${duration_s}" \
                >> "${CSV_OUT}"
        done
    done
done

row_count="$(tail -n +2 "${CSV_OUT}" 2>/dev/null | wc -l || echo 0)"
echo "[harvest_ci.sh] Done. ${row_count} data rows written to ${CSV_OUT}"
