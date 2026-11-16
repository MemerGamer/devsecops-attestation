#!/usr/bin/env bash
# Build only. This script never signs, uploads, publishes, creates or moves tags.
set -euo pipefail
cd "$(dirname "$0")/.."
mode="${1:-release}"
case "${mode}" in release | --build-only) ;; *) echo 'invalid release build mode' >&2; exit 1 ;; esac
umask 077
build_home="$(mktemp -d "${TMPDIR:-/tmp}/release-build.XXXXXX")"
trap 'rm -rf "${build_home}"' EXIT
mkdir -p "${build_home}/cache" "${build_home}/modules"
# Reuse the checksum-pinned Go installer with fresh output files and no caches.
RUNNER_TEMP="${build_home}" GITHUB_ENV="${build_home}/env" GITHUB_PATH="${build_home}/path" bash .ci/install-go.sh
set -a
# shellcheck disable=SC1091
source "${build_home}/env"
set +a
export RELEASE_TOOLS_DIR="${PWD}/.release-tools"
bash .ci/install-release-tools.sh
tool_path="${RELEASE_TOOLS_DIR}:$(cat "${build_home}/path"):/usr/bin:/bin"
build_env=(env -i "PATH=${tool_path}" "HOME=${build_home}" LC_ALL=C
	"GOROOT=${GOROOT}" GOTOOLCHAIN=local GOENV=off GOWORK=off GOFLAGS=-mod=readonly
	"GOCACHE=${GOCACHE}" "GOMODCACHE=${GOMODCACHE}" CGO_ENABLED=0 GOAMD64=v1 GOARM64=v8.0
	"GOPROXY=https://proxy.golang.org,direct" GOSUMDB=sum.golang.org)
"${build_env[@]}" go mod verify
"${build_env[@]}" goreleaser check
if [ "${mode}" = --build-only ]; then
	"${build_env[@]}" goreleaser build --clean
else
	"${build_env[@]}" goreleaser release --clean --skip=publish,sign,docker
fi
