#!/usr/bin/env bash
# Human-only initial release-key ceremony. Cosign alone handles passphrases.
set -euo pipefail
umask 077
set +x

fail() { printf 'error: %s\n' "$*" >&2; exit 1; }
usage() {
	cat <<'HELP'
Usage: scripts/release-key-ceremony.sh [--dry-run | --rotate | --help]

Run personally in a terminal on Linux/amd64. Never run through an agent.
Creates ~/.local/share/devsecops-release/cosign.{key,pub}, offers an offline
backup, checks signing locally, and replaces only the repository public key.
Cosign prompts for the passphrase directly; use a strong, nonempty passphrase.
--dry-run  Describe all steps without writes, downloads, or Cosign execution.
--rotate   Stop and refer to SECURITY.md; rotation requires a reviewed plan.
--help     Show this help.
HELP
}

dry_run=false
rotate=false
for arg in "$@"; do
	case "$arg" in
	--dry-run) dry_run=true ;;
	--rotate) rotate=true ;;
	--help | -h) usage; exit 0 ;;
	*) fail "unknown argument: $arg" ;;
	esac
done
[[ ! ${COSIGN_PASSWORD+x} ]] || fail 'COSIGN_PASSWORD is set; unset it so Cosign prompts directly'
[[ ! ${COSIGN_KEY+x} ]] || fail 'COSIGN_KEY is set; unset it before the ceremony'
[[ $EUID != 0 ]] || fail 'do not run the ceremony as root'
[[ -t 0 ]] || fail 'stdin must be a TTY; Hunor must run the ceremony personally'
$rotate && fail 'rotation never overwrites keys here; follow SECURITY.md: Release key and distribution trust (rotation, deny-list, advisory, hardware custody)'
[[ $(uname -s)/$(uname -m) == Linux/x86_64 ]] || fail 'the pinned ceremony tool requires linux/amd64'

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
target="$repo_root/actions/setup/release-keys/release-v1.pub"
: "${HOME:?HOME is required}"
[[ $HOME == /* ]] || fail 'HOME must be absolute'
key_dir="$HOME/.local/share/devsecops-release"

# Ask Git from the closest existing ancestor, including linked worktrees and
# submodules. Ignore caller Git configuration and environment overrides.
outside_git() {
	local path="$1" inside
	command -v git >/dev/null || fail 'git is required to check key storage paths'
	while [[ ! -d $path ]]; do
		path="$(dirname -- "$path")"
	done
	if inside="$(env -i PATH="$PATH" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
		GIT_CONFIG_GLOBAL=/dev/null GIT_DISCOVERY_ACROSS_FILESYSTEM=1 \
		git -c safe.directory='*' -C "$path" rev-parse --is-inside-work-tree 2>&1)"; then
		[[ $inside != true ]] || fail "key storage must not be inside a git work tree: $1"
	elif [[ $inside != 'fatal: not a git repository'* ]]; then
		fail "cannot check whether key storage is inside a git work tree: $1"
	fi
}
check_key_dir() {
	[[ ! -L $key_dir ]] || fail 'key directory must not be a symlink'
	if [[ -e $key_dir ]]; then
		[[ -d $key_dir && -O $key_dir && $(stat -c %a -- "$key_dir") == 700 ]] || fail 'key directory must be owned by you with mode 0700'
	fi
	local name
	for name in cosign.key cosign.pub; do
		[[ ! -e $key_dir/$name && ! -L $key_dir/$name ]] || fail 'release key already exists; see SECURITY.md rotation instructions (--rotate never overwrites)'
	done
}
check_target() {
	[[ -f $target && ! -L $target ]] || fail 'repository public-key target must be a regular placeholder file'
	cmp -s -- "$target" <(printf '%s\n' \
		'PLACEHOLDER: NOT A PUBLIC KEY' \
		'Hunor replaces this file after the off-Forgejo release-key ceremony.' \
		'Release verification must fail until the real public key is reviewed and pinned.') || fail 'repository public-key target is not the PLACEHOLDER; follow SECURITY.md rotation instructions'
}
outside_git "$(realpath -m -- "$key_dir")"
check_key_dir
check_target

# Match the selected release/test pin. Never execute an unverified PATH tool.
pin_name=cosign-v3.1.4
pin="$(python3 - "$repo_root/.ci/release-tools.json" "$pin_name" <<'PY'
import json, re, sys
pin = json.load(open(sys.argv[1]))[sys.argv[2]]
if not re.fullmatch(r'[0-9a-f]{64}', pin['sha256']):
    raise SystemExit('invalid cosign SHA-256 pin')
print(pin['version'], pin['sha256'])
PY
)"
read -r version expected_digest <<< "$pin"
digest() { sha256sum -- "$1" | cut -d ' ' -f 1; }

if $dry_run; then
	cat <<PLAN
DRY RUN: no files will be written and no Cosign command will be executed.
1. Verify a PATH Cosign against .ci/release-tools.json ($version, SHA-256 $expected_digest),
   or install $pin_name with .ci/install-release-tools.sh in a private temporary directory.
   Check SHA-256 before executing; print cosign version and require $version.
2. Create or verify owned 0700 directory $key_dir outside all git work trees.
   Run cosign generate-key-pair there interactively; Cosign prompts for a strong,
   nonempty passphrase directly. Require owned regular cosign.key and cosign.pub;
   chmod 0600 both. Never overwrite an existing key.
3. Prompt for an existing removable-media directory (or SKIP). Resolve its path,
   reject /tmp and git work trees, create a fresh 0700 backup directory there,
   copy both keys as 0600 files, and compare SHA-256 of each copy.
   Skipping prints a warning and leaves the merge checklist open.
4. Sign a random temporary blob with cosign.key, --tlog-upload=false,
   --use-signing-config=false, --timestamp-server-url='', and a local bundle.
   Cosign prompts directly again. Verify with cosign.pub, --offline=true,
   --insecure-ignore-tlog=true, --use-signed-timestamps=false; delete temporary files.
5. Recheck the exact PLACEHOLDER, copy only cosign.pub to $target (0600),
   print its SHA-256 and paste-ready SECURITY.md, PR and release-note lines.
   SECURITY.md is updated manually. No git add, commit, tag or push.
PLAN
	exit 0
fi

scratch="$(mktemp -d /tmp/release-key-ceremony.XXXXXX)"
generation_started=false
cleanup() {
	local status=$?
	rm -rf -- "$scratch"
	if [[ $status != 0 ]] && $generation_started; then
		printf '\nWARNING: ceremony incomplete; any generated keys remain at %s. The merge checklist stays open; review recovery manually before rerunning.\n' "$key_dir" >&2
	fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
chmod 700 "$scratch"
cosign_bin="$(type -P cosign || true)"
if [[ -n $cosign_bin ]]; then
	# Verify and execute the same private copy, even if PATH changes later.
	cp -- "$cosign_bin" "$scratch/cosign"
	cosign_bin="$scratch/cosign"
	chmod 700 -- "$cosign_bin"
	[[ $(digest "$cosign_bin") == "$expected_digest" ]] || fail 'PATH cosign SHA-256 does not match the pin; remove it from PATH to use the verified installer'
else
	RELEASE_TOOLS_DIR="$scratch/tools" bash "$repo_root/.ci/install-release-tools.sh" "$pin_name"
	cosign_bin="$scratch/tools/$pin_name"
	[[ $(digest "$cosign_bin") == "$expected_digest" ]] || fail 'installed cosign SHA-256 does not match the pin'
fi
# Do not inherit Cosign/Sigstore overrides, password providers or cached config.
# Terminal file descriptors pass through unchanged; no passphrase is read here.
cosign_run() {
	env -i PATH=/usr/bin:/bin LC_ALL=C HOME="$scratch" \
		XDG_CONFIG_HOME="$scratch/config" XDG_CACHE_HOME="$scratch/cache" \
		"$cosign_bin" "$@"
}
version_output="$(cosign_run version)"
printf '%s\n' "$version_output"
[[ $(awk '$1 == "GitVersion:" {print $2}' <<< "$version_output") == "$version" ]] || fail 'cosign version differs from the release tool pin'

check_key_dir
mkdir -p -- "$key_dir"
check_key_dir
outside_git "$(realpath -e -- "$key_dir")"
printf '\nCosign will prompt directly. Use a strong, nonempty passphrase.\n'
generation_started=true
(cd -- "$key_dir" && cosign_run generate-key-pair)
for name in cosign.key cosign.pub; do
	[[ -f $key_dir/$name && ! -L $key_dir/$name && -O $key_dir/$name && -s $key_dir/$name ]] || fail "generated $name must be a nonempty owned regular file"
	chmod 600 -- "$key_dir/$name"
	[[ $(stat -c %a -- "$key_dir/$name") == 600 ]] || fail 'custody filesystem must support 0600 files'
done

printf '\nMount your offline removable media. Enter its existing directory path,\nor type SKIP to leave the backup merge checklist item open: '
IFS= read -r backup_path || fail 'no backup choice received; keys remain in the custody directory, keep the merge checklist open'
backup_done=false
if [[ $backup_path == SKIP ]]; then
	printf '\nWARNING: NO OFFLINE BACKUP. THE MERGE CHECKLIST STAYS OPEN.\n' >&2
else
	[[ -n $backup_path && -d $backup_path ]] || fail 'backup path must be an existing directory'
	backup_path="$(realpath -e -- "$backup_path")"
	outside_git "$backup_path"
	case "$backup_path" in
	/tmp | /tmp/*) fail 'backup path must not be under /tmp' ;;
	esac
	# Resolve aliases of /tmp as well (for example /var -> another mount).
	case "$backup_path/" in
	"$(realpath -e /tmp)/"*) fail 'backup path must not be under /tmp' ;;
	esac
	backup_dir="$(mktemp -d "$backup_path/devsecops-release-backup.XXXXXX")"
	chmod 700 -- "$backup_dir"
	[[ -O $backup_dir && $(stat -c %a -- "$backup_dir") == 700 ]] || fail 'backup filesystem must support owned 0700 directories'
	for name in cosign.key cosign.pub; do
		cp -- "$key_dir/$name" "$backup_dir/$name"
		chmod 600 -- "$backup_dir/$name"
		[[ -O $backup_dir/$name && $(stat -c %a -- "$backup_dir/$name") == 600 ]] || fail 'backup filesystem must support owned 0600 files'
		source_digest="$(digest "$key_dir/$name")"
		backup_digest="$(digest "$backup_dir/$name")"
		[[ $source_digest == "$backup_digest" ]] || fail "backup SHA-256 mismatch: $name"
	done
	backup_done=true
	printf 'Backup verified at %s; unmount and store the media offline.\n' "$backup_dir"
fi

printf '\nChecking a random blob locally. Cosign will prompt directly again.\n'
dd if=/dev/urandom of="$scratch/blob" bs=32 count=1 status=none
cosign_run sign-blob --key "$key_dir/cosign.key" --tlog-upload=false \
	--use-signing-config=false --timestamp-server-url='' \
	--bundle "$scratch/blob.sigstore.json" "$scratch/blob"
cosign_run verify-blob --key "$key_dir/cosign.pub" --offline=true \
	--insecure-ignore-tlog=true --use-signed-timestamps=false \
	--bundle "$scratch/blob.sigstore.json" "$scratch/blob"
rm -- "$scratch/blob" "$scratch/blob.sigstore.json"

check_target
cp -- "$key_dir/cosign.pub" "$target"
chmod 600 -- "$target"
public_digest="$(digest "$target")"
[[ $public_digest == "$(digest "$key_dir/cosign.pub")" ]] || fail 'repository public key copy differs'
printf '\nPublic-key file SHA-256: %s\n' "$public_digest"
cat <<LINES

Update SECURITY.md manually: replace the PLACEHOLDER/no-production-fingerprint
paragraph under "Release key and distribution trust" with these exact lines:

The production release public key is \`actions/setup/release-keys/release-v1.pub\`.
Its public-key file SHA-256 is \`$public_digest\`.
Hunor generated the passphrase-protected key outside all repositories; custody
uses an owned 0700 directory and 0600 files. The local sign/verify check passed
without transparency-log upload.

Paste into the PR description and release notes:

Release public key: \`actions/setup/release-keys/release-v1.pub\`.
Public-key file SHA-256: \`$public_digest\`.
Local release-key sign/verify round trip: passed without transparency-log upload.
LINES
if $backup_done; then
	printf 'Offline backup: copied with 0700/0600 permissions and SHA-256 verified.\n'
else
	printf 'Offline backup: NOT COMPLETED; the merge checklist stays OPEN.\n'
	printf '\nWARNING: complete and verify an offline backup before merging.\n' >&2
fi
printf '\nReview the public key and documentation manually. No git add, commit, tag or push was performed.\n'
