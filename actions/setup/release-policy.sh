#!/usr/bin/env bash
# Shared release verification policy. No caller-selected keys or trust roots.

release_version_check() {
	[[ "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
		echo 'invalid stable release version' >&2; return 1;
	}
	case "$1" in
	0.4.0 | 0.4.1 | 0.4.2) return 0 ;;
	0.[0-4].*) echo 'unsupported release version: only 0.4.0 to 0.4.2 have legacy signed archives' >&2; return 1 ;;
	esac
	# Version deny-list: add revoked versions here in a reviewed action release.
	case "$1" in
	# 0.5.0) echo 'release version has been revoked' >&2; return 1 ;;
	*) return 0 ;;
	esac
}

release_legacy_digest() {
	# Sources: https://github.com/MemerGamer/devsecops-attestation/releases/download/v<V>/checksums.txt
	# Downloaded and verified with Cosign v3.0.2 and v3.1.4 on 2026-11-16.
	case "$1" in
	0.4.0) echo 645ec419a451f30dabbfef01ff4b29bd4a64fa0c184fd21fec11e904e5a344ff ;;
	0.4.1) echo 0329efc0b18445a8ae673c82eeddfb726e20597bc54bded7bfbddc32fbd6a37d ;;
	0.4.2) echo 64095824245057b24696b93a8a169872cf7ddfcba8e90b7c70ac46219248627f ;;
	esac
}

release_names() {
	local target ext name
	for target in darwin_amd64 darwin_arm64 linux_amd64 linux_arm64 windows_amd64; do
		ext=tar.gz
		[ "${target}" != windows_amd64 ] || ext=zip
		name="devsecops-attestation_$1_${target}.${ext}"
		printf '%s\n%s.sbom.json\n' "${name}" "${name}"
	done | LC_ALL=C sort
}

release_manifest_check() {
	# Validate bytes and exact inventory before any checksum tool sees names.
	local manifest="$1" version="$2" expected actual
	expected="$(release_names "${version}")"
	actual="$(LC_ALL=C awk '
		length($0) != 0 {
			if (length($0) < 67 || substr($0,65,2) != "  " ||
			    substr($0,1,64) ~ /[^0-9a-f]/ ||
			    substr($0,67) !~ /^[A-Za-z0-9_.-]+$/ ||
			    substr($0,67) ~ /\.\./) exit 1
			print substr($0,67); n++
			next
		}
		{exit 1}
		END {if (n != 10) exit 1}
	' "${manifest}" | LC_ALL=C sort)" || { echo 'malformed release manifest' >&2; return 1; }
	[ "$(tail -c 1 "${manifest}" | od -An -tu1 | tr -d ' ')" = 10 ] || {
		echo 'manifest must end with a newline' >&2; return 1;
	}
	[ "${actual}" = "${expected}" ] || { echo 'release manifest inventory differs from requested version' >&2; return 1; }
}

release_cosign() (
	# Consumer verification: any stable Cosign v3 >= v3.0.2 on PATH.
	set -euo pipefail
	local cosign_bin
	cosign_bin="$(command -v cosign)" || { echo 'cosign is not on PATH (stable v3.0.2 or later required)' >&2; exit 1; }
	case "${cosign_bin}" in
	/*) ;;
	*) cosign_bin="$(cd "$(dirname "${cosign_bin}")" && pwd)/$(basename "${cosign_bin}")" ;;
	esac
	release_cosign_exec "${cosign_bin}" '' '' "$@"
)

release_cosign_pinned() (
	# Release signing: only the exact binary pinned in .ci/release-tools.json.
	# Arguments: absolute binary path, SHA-256 pin, exact version, Cosign arguments.
	set -euo pipefail
	[[ "$1" == /* && "$2" =~ ^[0-9a-f]{64}$ && "$3" =~ ^v3\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
		echo 'pinned cosign requires an absolute path, a SHA-256 pin and an exact stable v3 version' >&2; exit 1;
	}
	release_cosign_exec "$@"
)

release_cosign_exec() (
	# A subshell confines traps and deletes the private home on every exit.
	# Arguments: absolute binary, SHA-256 pin or empty, exact version or empty, Cosign arguments.
	set -euo pipefail
	local cosign_bin="$1" expected_digest="$2" pinned_version="$3" cosign_home version
	shift 3
	umask 077
	cosign_home="$(mktemp -d "${TMPDIR:-/tmp}/release-cosign.XXXXXX")" || exit 1
	trap 'rm -rf "${cosign_home}"' EXIT
	chmod 700 "${cosign_home}" || exit 1
	check_digest() {
		# Recheck the pinned bytes immediately before every execution.
		[ -n "${expected_digest}" ] || return 0
		[ -f "${cosign_bin}" ] && [ ! -L "${cosign_bin}" ] || {
			echo "pinned cosign binary is missing: ${cosign_bin}" >&2; exit 1;
		}
		[ "$(sha256sum -- "${cosign_bin}" | cut -d ' ' -f 1)" = "${expected_digest}" ] || {
			echo "cosign SHA-256 does not match the pin in .ci/release-tools.json: ${cosign_bin}" >&2; exit 1;
		}
	}
	clean_cosign() {
		check_digest
		env -i PATH=/usr/bin:/bin LC_ALL=C \
			HOME="${cosign_home}" USERPROFILE="${cosign_home}" \
			XDG_CACHE_HOME="${cosign_home}/cache" XDG_CONFIG_HOME="${cosign_home}/config" \
			XDG_DATA_HOME="${cosign_home}/data" \
			LOCALAPPDATA="${cosign_home}/cache" APPDATA="${cosign_home}/config" \
			"${cosign_bin}" "$@"
	}
	version="$(clean_cosign version | awk '$1 == "GitVersion:" {print $2}')"
	if [ -n "${pinned_version}" ]; then
		[ "${version}" = "${pinned_version}" ] || {
			echo "cosign version ${version:-unknown} differs from the pin ${pinned_version}" >&2; exit 1;
		}
	fi
	[[ "${version}" =~ ^v3\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
		echo 'cosign must be stable v3, at least v3.0.2' >&2; exit 1;
	}
	case "${version}" in
	v3.0.0 | v3.0.1) echo 'cosign must be at least v3.0.2' >&2; exit 1 ;;
	esac
	clean_cosign "$@"
)

release_verify() {
	# Arguments: action directory, version, manifest, bundle. All paths absolute.
	local action_dir="$1" version="$2" manifest="$3" bundle="$4"
	local identity_args=()
	case "${version}" in
	0.4.0 | 0.4.1 | 0.4.2)
		identity_args=(
			--certificate-identity=https://github.com/MemerGamer/devsecops-attestation/.github/workflows/release-please.yml@refs/heads/main
			--certificate-oidc-issuer=https://token.actions.githubusercontent.com
			--certificate-github-workflow-trigger=push
			--certificate-github-workflow-repository=MemerGamer/devsecops-attestation
		) ;;
	*)
		if grep -q PLACEHOLDER "${action_dir}/release-keys/release-v1.pub"; then
			echo 'release public key contains PLACEHOLDER; complete the release-key ceremony first' >&2
			return 1
		fi
		identity_args=(--key "${action_dir}/release-keys/release-v1.pub") ;;
	esac
	release_cosign verify-blob "${identity_args[@]}" --bundle "${bundle}" \
		--new-bundle-format=true --insecure-ignore-tlog=false --private-infrastructure=false \
		--use-signed-timestamps=false --trusted-root="" --rekor-url=https://rekor.sigstore.dev "${manifest}"
}
