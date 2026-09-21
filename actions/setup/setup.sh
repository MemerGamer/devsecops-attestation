#!/usr/bin/env bash
# actions/setup/setup.sh
#
# Installs the devsecops-attestation CLI binaries (keygen, attest, verify,
# gate) plus the bundled deploy.rego policy, either by downloading a release
# archive or by building from source (INPUT_VERSION=source, used for
# dogfooding / PR testing against the action's own checkout).
#
# All configuration arrives via INPUT_* environment variables set by the
# composite action's action.yml, matching the convention GitHub and Forgejo
# both use for `run:` steps. GITHUB_OUTPUT, GITHUB_PATH, RUNNER_OS,
# RUNNER_ARCH and RUNNER_TEMP are provided by the runner itself.
set -euo pipefail

: "${INPUT_VERSION:?INPUT_VERSION is required}"
: "${INPUT_REPOSITORY:?INPUT_REPOSITORY is required}"
: "${INPUT_DOWNLOAD_BASE_URL:?INPUT_DOWNLOAD_BASE_URL is required}"
: "${INPUT_INSTALL_DIR:?INPUT_INSTALL_DIR is required}"
: "${INPUT_VERIFY_SIGNATURE:=false}"
: "${GITHUB_ACTION_PATH:?GITHUB_ACTION_PATH is required (set by the runner for composite actions)}"

install_dir="${INPUT_INSTALL_DIR}"
mkdir -p "${install_dir}"

log() {
	printf '[setup] %s\n' "$*" >&2
}

fail() {
	printf '[setup] error: %s\n' "$*" >&2
	exit 1
}

write_output() {
	# $1 = name, $2 = value. GITHUB_OUTPUT may be unset when this script is
	# exercised outside a real workflow step (e.g. local testing).
	if [ -n "${GITHUB_OUTPUT:-}" ]; then
		printf '%s=%s\n' "$1" "$2" >>"${GITHUB_OUTPUT}"
	fi
}

if [ "${INPUT_VERSION}" = "source" ]; then
	log "building from source (INPUT_VERSION=source)"

	if ! command -v go >/dev/null 2>&1; then
		fail "INPUT_VERSION=source requires a Go toolchain on PATH"
	fi

	repo_root="${GITHUB_ACTION_PATH}/../.."
	if [ ! -f "${repo_root}/go.mod" ]; then
		fail "expected go.mod at ${repo_root} (action checkout layout unexpected)"
	fi

	(
		cd "${repo_root}"
		go build -o "${install_dir}/" ./cmd/...
	)

	# go build names binaries after their cmd/ directory (keygen, sign,
	# verify, gate); the released archives ship the sign binary as
	# "attest", so normalize the name here to keep the two install paths
	# interchangeable for consumers.
	if [ -f "${install_dir}/sign" ]; then
		mv "${install_dir}/sign" "${install_dir}/attest"
	fi

	resolved_version="source"
	src_policy_path="${repo_root}/policies/deploy.rego"
	if [ ! -f "${src_policy_path}" ]; then
		fail "bundled policy not found at ${src_policy_path}"
	fi
	cp "${src_policy_path}" "${install_dir}/deploy.rego"
	policy_path="${install_dir}/deploy.rego"
else
	version="${INPUT_VERSION#v}"
	tag="v${version}"

	case "${RUNNER_OS:-}" in
	Linux) os="linux" ;;
	macOS) os="darwin" ;;
	Windows) os="windows" ;;
	*) fail "unsupported RUNNER_OS: ${RUNNER_OS:-<unset>}" ;;
	esac

	case "${RUNNER_ARCH:-}" in
	X64) arch="amd64" ;;
	ARM64) arch="arm64" ;;
	*) fail "unsupported RUNNER_ARCH: ${RUNNER_ARCH:-<unset>}" ;;
	esac

	if [ "${os}" = "windows" ]; then
		archive_ext="zip"
	else
		archive_ext="tar.gz"
	fi

	archive_name="devsecops-attestation_${version}_${os}_${arch}.${archive_ext}"
	base_url="${INPUT_DOWNLOAD_BASE_URL}/${tag}"
	archive_url="${base_url}/${archive_name}"
	checksums_url="${base_url}/checksums.txt"

	work_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/devsecops-attestation-setup.XXXXXX")"
	trap 'rm -rf "${work_dir}"' EXIT

	log "downloading ${archive_url}"
	curl -fsSL -o "${work_dir}/${archive_name}" "${archive_url}"
	log "downloading ${checksums_url}"
	curl -fsSL -o "${work_dir}/checksums.txt" "${checksums_url}"

	if [ "${INPUT_VERIFY_SIGNATURE}" = "true" ]; then
		command -v cosign >/dev/null 2>&1 || fail "verify-signature=true but cosign is not on PATH"

		log "verifying checksums.txt signature with cosign"
		curl -fsSL -o "${work_dir}/checksums.txt.sig" "${base_url}/checksums.txt.sig"
		curl -fsSL -o "${work_dir}/checksums.txt.pem" "${base_url}/checksums.txt.pem"
		# INPUT_REPOSITORY is interpolated into a regex; escape any regex
		# metacharacters it may contain (a repository name should never have
		# any, but this keeps the check from silently over-matching or
		# breaking if it does).
		escaped_repository="$(printf '%s' "${INPUT_REPOSITORY}" | sed -e 's/[.[\*^$/]/\\&/g')"
		cosign verify-blob \
			--signature "${work_dir}/checksums.txt.sig" \
			--certificate "${work_dir}/checksums.txt.pem" \
			--certificate-identity-regexp "^https://github\\.com/${escaped_repository}/\\.github/workflows/.+$" \
			--certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
			"${work_dir}/checksums.txt" \
			|| fail "cosign verify-blob failed for checksums.txt"
	fi

	log "verifying checksum for ${archive_name}"
	# Exact match on the checksums.txt filename column only: a plain
	# substring grep for " <archive_name>" also matches sibling entries such
	# as goreleaser's "<archive_name>.sbom.json" line, which breaks
	# `sha256sum -c` on every real release. awk compares the filename column
	# ($2) exactly, accepting both the plain and the "*"-prefixed
	# (binary-mode) sha256sum formats.
	entry="$(awk -v f="${archive_name}" '$2 == f || $2 == ("*" f) { print; count++ } END { if (count != 1) exit 1 }' "${work_dir}/checksums.txt")" \
		|| fail "expected exactly one checksum entry for ${archive_name} in checksums.txt"
	(
		cd "${work_dir}"
		printf '%s\n' "${entry}" | sha256sum -c - || fail "checksum verification failed for ${archive_name}"
	)

	log "extracting ${archive_name}"
	case "${archive_ext}" in
	tar.gz)
		tar -xzf "${work_dir}/${archive_name}" -C "${work_dir}"
		;;
	zip)
		if command -v unzip >/dev/null 2>&1; then
			unzip -q "${work_dir}/${archive_name}" -d "${work_dir}"
		else
			fail "unzip is required to extract windows archives"
		fi
		;;
	esac

	for bin in keygen attest verify gate; do
		bin_name="${bin}"
		[ "${os}" = "windows" ] && bin_name="${bin}.exe"
		src="${work_dir}/${bin_name}"
		[ -f "${src}" ] || fail "expected binary ${bin_name} not found in archive"
		cp "${src}" "${install_dir}/${bin_name}"
		chmod +x "${install_dir}/${bin_name}" 2>/dev/null || true
	done

	policy_src="${work_dir}/policies/deploy.rego"
	[ -f "${policy_src}" ] || fail "bundled policy not found in archive at policies/deploy.rego"
	cp "${policy_src}" "${install_dir}/deploy.rego"
	policy_path="${install_dir}/deploy.rego"

	resolved_version="${version}"
fi

if [ -n "${GITHUB_PATH:-}" ]; then
	printf '%s\n' "${install_dir}" >>"${GITHUB_PATH}"
else
	log "GITHUB_PATH not set, skipping PATH registration (add ${install_dir} to PATH manually)"
fi

write_output "bin-dir" "${install_dir}"
write_output "policy-path" "${policy_path}"
write_output "version" "${resolved_version}"

log "installed devsecops-attestation ${resolved_version} into ${install_dir}"
