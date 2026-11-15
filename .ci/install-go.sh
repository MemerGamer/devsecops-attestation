#!/usr/bin/env bash
# Install only the repository-pinned linux/amd64 toolchain, without shared caches.
set -euo pipefail
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_ENV:?GITHUB_ENV is required}"
: "${GITHUB_PATH:?GITHUB_PATH is required}"
cd "$(dirname "$0")/.."
[[ "$(uname -s)/$(uname -m)" == Linux/x86_64 ]] || { echo 'unsupported signing runner platform' >&2; exit 1; }
version="$(awk '$1 == "toolchain" { print $2 }' go.mod)"
[[ "${version}" =~ ^go[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'missing or invalid go.mod toolchain' >&2; exit 1; }
asset="${version}.linux-amd64.tar.gz"
checksum="$(awk -v asset="${asset}" '$2 == asset { print $1; count++ } END { if (count != 1) exit 1 }' .ci/go-toolchain.sha256)" \
	|| { echo 'no unique pinned SHA-256 for go.mod toolchain' >&2; exit 1; }
[[ "${checksum}" =~ ^[0-9a-f]{64}$ ]] || { echo 'invalid pinned toolchain SHA-256' >&2; exit 1; }
install_dir="$(mktemp -d "${RUNNER_TEMP}/sign-go.XXXXXX")"
curl -fsSL --retry 5 --retry-delay 3 --connect-timeout 20 --max-time 300 \
	"https://go.dev/dl/${asset}" -o "${install_dir}/${asset}"
printf '%s  %s\n' "${checksum}" "${install_dir}/${asset}" | sha256sum -c -
tar -xzf "${install_dir}/${asset}" -C "${install_dir}"
mkdir "${install_dir}/modcache" "${install_dir}/buildcache"
{
	printf 'GOROOT=%s/go\n' "${install_dir}"
	printf 'GOTOOLCHAIN=local\nGOENV=off\nGOWORK=off\nGOFLAGS=-mod=readonly\n'
	printf 'GOMODCACHE=%s/modcache\nGOCACHE=%s/buildcache\n' "${install_dir}" "${install_dir}"
} >>"${GITHUB_ENV}"
printf '%s/go/bin\n' "${install_dir}" >>"${GITHUB_PATH}"
