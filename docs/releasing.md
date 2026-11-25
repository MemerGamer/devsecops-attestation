# G7 release procedure

This tooling prepares v0.5.0 and later releases with Forgejo canonical and a
byte-identical GitHub distribution copy. It has not published a release.
Hunor alone commits, tags, signs, publishes and makes the copy. No new
container image is built; ghcr.io stays at v0.4.2. The release-please files
are removed. The separate Dependabot workflow is unchanged.

## Implementation gates

The production public key is deliberately `PLACEHOLDER` in
`actions/setup/release-keys/release-v1.pub`. Hunor must complete the ceremony
and record the real file's SHA-256 in SECURITY.md, the PR and release notes
before merging the tooling. The placeholder has no usable fingerprint.

The release-build tool pins in `.ci/release-tools.json` were audited against
official release archives, published checksums and signed checksum bundles
on 2026-11-16. The installer checks each repository-pinned SHA-256 before
extracting or executing the binary. See the V6 evidence below.

The Forgejo workflow uses unsigned CI artifacts rather than release API
writes. V1/V2 (installed Forgejo API, status contexts, protected-tag behavior,
and tag events), V6 (runner-image syft execution), V7/V8 (gh failure
behavior and artifact API transport), V7a (CI/local reproducibility), V12
(mirror latency and complete distribution checks) still need the public
rehearsal. No server settings or credentials were changed. Artifact API
support must be demonstrated before relying on `--run-id`; `--ci-output`
accepts a fresh private download for independent checking.

## V5 evidence (2026-11-16)

The initial task proved section 3.1 before implementing the tooling, using
the upstream Linux amd64 binaries below. SHA-256 was compared with each
release's `cosign_checksums.txt`; the continuation rechecked the local bytes.
The selected tooling/test pin is v3.1.4; the minimum remains v3.0.2.

| Version | Binary SHA-256 |
|---|---|
| v3.1.4 | `424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa` |
| v3.0.2 | `46dbdcb5467a3dfec2526923d0b3365e40c8d9dc00ec23d5aca3437449e8cbfd` |

Sources are `https://github.com/sigstore/cosign/releases/download/v<V>/cosign-linux-amd64`
and `cosign_checksums.txt` at the same release URL, substituting the version
without its leading v for `<V>`.

Both versions passed these checks with throwaway keys and existing fixtures:

- All specified signing and verification flags exist and behave as required,
  including `--trusted-root=""`, `--private-infrastructure=false`,
  `--use-signed-timestamps=false` and `--new-bundle-format=true`.
- Public-Rekor bundles verify; valid same-key bundles with no log entry fail
  specifically with `not enough verified log entries ... 0 < 1`.
- Each bypass variable, both together, caller roots, poisoned home/TUF cache,
  proxy and TLS-root overrides cannot change the enforced public-root policy.
  The logged positive still verifies with the poisoned caller environment.
- The private-log fixture verifies with its explicit test root as a control,
  and fails log verification under the enforced public-root policy. Automated
  tests cover all 16 combinations of COSIGN_TRUSTED_ROOT, SIGSTORE_ROOT_FILE,
  COSIGN_INSECURE_IGNORE_TLOG and COSIGN_PRIVATE_INFRASTRUCTURE, plus other
  Sigstore key overrides and a poisoned home/cache/proxy/TLS environment.
- All three legacy manifests verify with the fixed certificate identity,
  issuer and workflow constraints. Their SHA-256 pins and source are recorded
  in `actions/setup/release-policy.sh`.

The installer tests separately reject old, prerelease, other-major and
unparseable Cosign versions. Rekor integrated time is available at
`verificationMaterial.tlogEntries[].integratedTime`; it is not a revocation
cutoff. v3.1.4 emits deprecation warnings for several required flags; no flag
was weakened or removed.

The initial task uploaded three signatures to public Rekor: one positive
probe per Cosign version and one positive manifest for the five-target
installer fixture. These used only throwaway data and a throwaway key.
The no-Rekor and private-log fixtures required no public upload. The
continuation performed no signing or uploads. No real release key was used.
The scratch publication, real-key mismatch and validly signed mixed-version
manifest assertions remain Hunor's rehearsal gates described below.

CI's actions-selftest installs both digest-pinned Cosign versions through
`.ci/install-release-tools.sh` and runs the composite suite with each binary
selected by COSIGN_TEST_BIN. Missing or nonexecutable Cosign is a failure
whenever CI is set, including CI=false. Local runs may skip real-Cosign
tests only when CI is absent. All three legacy fixtures have positive tests
using the shared policy and the pinned manifest digests.

## V6 local evidence (2026-11-16)

Official Linux amd64 archives are pinned as follows:

| Tool | Version | Archive SHA-256 |
|---|---|---|
| GoReleaser | v2.18.2 | `0a96edc9d9bc594e4a41cc4d59467c182062910ab24d9d1f6dd7b667d32606d3` |
| syft | v1.57.1 | `bf52519eb57f675d47c07d43213cb6dff6449f3d6d1147ff6701ed91f44eef0c` |

Archive, checksum and bundle URLs and the exact expected certificate
identities are recorded in `.ci/release-tools.json`. Both archive digests
matched the upstream checksum files. Cosign v3.1.4 verified both checksum
bundles with the GitHub Actions OIDC issuer and exact upstream workflow
identities, through release_cosign's clean environment, public trust roots
and required transparency-log verification. Both returned Verified OK.
No signatures were created and nothing was uploaded during this audit.

Rechecked independently on 2026-11-25: the GoReleaser, syft and Go archive
digests match the upstream checksum files and go.dev metadata; both checksum
bundles verified again with Cosign v3.1.4 against the identities above. The
two Cosign binaries match their GitHub release asset digests, and their
`cosign-linux-amd64.sigstore.json` bundles verified against the upstream
signer `keyless@projectsigstore.iam.gserviceaccount.com` (issuer
`https://accounts.google.com`). Both installers download over HTTPS only
(TLS 1.2 or later), and pins must name `https://github.com/` assets. The
release workflow has no default token scopes; its job requests
`contents: read`. Each action reference names its source explicitly and is
pinned to the commit of its tag (checkout v7.0.1, Forgejo upload-artifact v5).

The installed official binaries passed `goreleaser check` and completed
`goreleaser release --snapshot --clean --skip=publish,sign,docker --parallelism 2`
under `env -i`, with no token. The environment used pinned Go 1.26.8,
GOTOOLCHAIN=local, GOENV=off, GOWORK=off, GOFLAGS=-mod=readonly, a private
home and fresh isolated module/build caches. Module verification and the
tidy-with-no-diff hook passed. The configured force_token=gitea was accepted.
The run produced 20 binaries, five archives, five SBOMs and checksums.txt;
no Docker daemon was needed. The existing non-semver cutover tag supplied
the snapshot version, so these local outputs are diagnostic artifacts only.
No ref or release was created. Real Forgejo runner-image execution, token
detection there and CI/local reproducibility remain rehearsal checks.

## Key ceremony and trust

Hunor records the DG-3 supersession decision in the human-owned decisions
repository. Outside all repositories, set umask 077, create
`~/.local/share/devsecops-release/` with mode 0700, and generate a
passphrase-protected Cosign key interactively. The private key and custody
copy of the public key, and their offline backups, must be owned 0600 files
inside owned 0700 directories. Copy only the public key into the action.
No agent handles a real private key or passphrase. The release key is
independent of the pipeline's four TEST attestation keys and never enters CI.

Pin and review the action SHA. For >=0.5.0, setup uses its fixed
`release-keys/release-v1.pub`; no action input or environment variable can
select a key. Public Rekor evidence must verify cryptographically. A
version deny-list in `release-policy.sh` is the revocation mechanism; a
pre-release flag does not revoke a version. See SECURITY.md for the blast
radius and rotation requirements.

### Run the ceremony

Hunor runs `scripts/release-key-ceremony.sh` himself at an interactive
terminal on pc (Linux/amd64), with `COSIGN_PASSWORD` and `COSIGN_KEY` unset.
Use `--dry-run` first to review the steps without writes or Cosign execution.
The script verifies the pinned Cosign digest before execution and prints its
version. Cosign prompts directly for a strong, nonempty passphrase during
generation and the local sign/verify check; no agent runs the generation path.

Mount removable media and provide an existing directory when prompted. It
must be outside git work trees and `/tmp`, and support owned 0700 directories
and 0600 files. The script copies both keys and verifies the backup digests;
unmount and store the media offline afterward. Typing `SKIP` leaves the merge
checklist open. The local round trip does not upload to Rekor; release
publication still requires public Rekor evidence.

Only the public key replaces the action's exact placeholder. Paste the printed
fingerprint lines into SECURITY.md, the PR description and release notes,
replacing the outdated placeholder/no-fingerprint text manually. The script
does not stage, commit, tag or push. Existing keys or a replaced placeholder
cause refusal; `--rotate` stops with the SECURITY.md rotation procedure.
If interrupted after generation, the custody keys remain in place and the
merge checklist remains open; review backup and verification manually rather
than deleting keys to rerun the ceremony.

## Prepare and build

1. On a clean, freshly fetched main equal to origin/main, Hunor runs
   `scripts/release-prep.sh 0.5.0`. It creates `release/v0.5.0` and writes a
   conventional-commit CHANGELOG section with the plain git-log script.
   Review the notes and open a PR; it does not commit, tag or push.
2. Merge through a branch PR with all eight required checks. Hunor creates
   an annotated tag on that merge commit and pushes it to Forgejo only.
   Never move or reuse a release tag. Verify the mirrored tag object and
   peeled commit on GitHub before creating any GitHub release.
3. `release.yml` validates an existing annotated stable tag, resolves its
   commit once, checks ancestry against origin/main and checks out that SHA.
   It uses fresh caches, the SHA-pinned Go toolchain and SHA-pinned
   GoReleaser/syft. `go mod verify` and a tidy-with-no-diff hook are required.
   GoReleaser runs with `--skip=publish,sign,docker`; publishing is also
   disabled in its configuration and SCM detection is fixed to gitea.
   Dispatch only from main with an existing tag after failure.

Build reproducibility uses `-trimpath`, `-buildvcs=false`, tag-derived
`-X main.version`, CGO_ENABLED=0, GOAMD64=v1, GOARM64=v8.0, GOENV=off,
GOWORK=off and the go.mod toolchain. VCS stamping is explicitly disabled so
checkout paths and dirty-tree metadata cannot change binaries. The local
rebuild uses the same script in a clean detached clone at the tagged SHA.
CI output remains untrusted until the publisher completes all comparisons.

## Local publication

After the key and build-tool pin audits, Hunor runs on pc at an interactive
terminal (the script refuses CI and noninteractive callers):

```sh
scripts/release-publish.sh v0.5.0 \
  --run-id RUN_ID \
  --baseline /absolute/private/release-v0.5.0/baseline.json \
  --key /home/hunor/.local/share/devsecops-release/cosign.key \
  --notes /absolute/reviewed-release-notes.md
```

Use `--ci-output /absolute/fresh/private/artifact-directory` instead of
`--run-id` for a manually downloaded artifact. Supply the Forgejo token in
the local environment, never in argv or a new credentials file. GitHub
writes use Hunor's existing gh login. Passphrases are entered interactively
by Hunor into Cosign; the clean Cosign environment inherits no password.

The publisher requires both `DevSecOps Attested Pipeline / sign (push)` and
`DevSecOps Attested Pipeline / publish (push)` to succeed on the tagged SHA.
The latest status for each context wins. Published releases and existing
drafts cause a stop for rollback review; stale drafts are never reused.

It derives five archive names from the validated tag, for darwin/amd64,
darwin/arm64, linux/amd64, linux/arm64 and windows/amd64. Each has exactly one
`<full-archive-name>.sbom.json`. Before signing it requires exactly ten
regular payload files and ten manifest entries, each lowercase SHA-256,
two ASCII spaces, an expected basename and newline. Extra, missing,
duplicate, other-version, unsafe-path, malformed and symlink entries fail.
It hashes validated names only. It compares all 20 independently rebuilt
binaries, exact archive member sets and the tagged LICENSE, README and
policy bytes. It regenerates SBOMs twice. If local outputs differ, notes
must contain exactly: "SBOMs are signed but not independently checked".
A deterministic mismatch stops publication.

Only after all checks does it rebuild the canonical local checksums.txt in
bytewise filename order. Hunor confirms the tag and signs with the enforced
clean Cosign policy, including public Rekor upload. The resulting bundle
must verify.

Signing uses only the Cosign pinned for the key ceremony
(`cosign-v3.1.4` in `.ci/release-tools.json`), resolved the same way: a
private 0700 copy of the PATH `cosign`, or, if none is on PATH, a download
through `.ci/install-release-tools.sh`. The publisher resolves it once,
before the "publish <tag>" prompt, and refuses there, before anything is
signed or uploaded to Rekor, when the copy's SHA-256 differs from the pin or
the binary cannot be installed; the signing policy also refuses a version
other than the pinned one. `release_cosign_pinned` rechecks the SHA-256
before every Cosign execution. Post-signing and distribution verification
keep using `release_cosign`, the consumer policy (any stable Cosign v3 from
v3.0.2 on PATH), so they check what users of the setup action check. They
run with the same private copy, named `cosign` and alone in its directory,
first on PATH (SHA-256 rechecked before each verification), so a publisher
without a PATH `cosign` can verify what it signed. The private copy lives in
`$TMPDIR` (or `/tmp`), which must allow execution. A separate
`--check-distribution` run still uses the PATH `cosign`. `gh` is not digest-pinned: no reviewed `gh` pin exists, and
the publisher relies on Hunor's installed, logged-in `gh`. A baseline outside the upload directory records all twelve
names, sizes and digests. Checked files become read-only; hashes are checked
before every upload. Build metadata and diagnostics are not release assets.

Forgejo is published from these verified local files. The GitHub command
uses `gh release create --verify-tag`, the same notes and exactly the same
twelve files. It never creates a missing tag. On a failed GitHub command,
a remaining draft is deleted without `--cleanup-tag`, with a ref check
after cleanup. Published releases and tags are not deleted by failure cleanup.

## Distribution checks and external dependency

After GitHub writes the publisher requires this existing migration-repo
checker, without an allow-list:

```sh
bash /home/hunor/Documents/GitHub/phd-lab-forgejo-migration/scripts/mirror-check.sh \
  https://forgejo.remote.kovacsbalinthunor.com/kbalinthunor/devsecops-attestation.git \
  https://github.com/MemerGamer/devsecops-attestation.git
```

It must exit zero and report identical refs. Missing checker, network or
ref failures block completion. This file is not copied into this repository.
The publisher also checks the recorded annotated tag object and peeled
commit on both remotes, looks up each published release by exact tag and
enumerates every page of attached assets by release ID. Exactly one of each
of the twelve expected names and matching sizes is required. Generated
source snapshots are not attached assets.

All twelve assets are downloaded anonymously over HTTPS into separate fresh
directories, compared by size, SHA-256 and bytes against the local baseline
and directly against each other. Both downloaded manifests and bundles must
verify and authorize exactly the ten payloads. Setup installs all five
target selections from each explicit URL; binary bytes, extraction, policy
and outputs are checked. Both inventories are listed again and must retain
the same IDs, names and sizes. Nothing is re-signed to repair a mismatch.

Read-only repetition uses the saved baseline:

```sh
scripts/release-publish.sh v0.5.0 --check-distribution \
  --baseline /absolute/private/release-v0.5.0/baseline.json
```

## Public rehearsal and rollback

Hunor creates public `kbalinthunor/g7-release-rehearsal` and its unfiltered
mirror `MemerGamer/scratch-mirror-test-public`; require both to lack tag and
release v0.5.0 before starting. Stop on any collision. Hunor alone tags,
signs and publishes with a separate scratch key. Use `--forgejo-repo
kbalinthunor/g7-release-rehearsal` for the publisher. The mirror checker uses
these scratch URLs with no allow-list.

Copy the entire candidate checkout locally and swap only the public key in
that copy. There is no production test-key or root override. Use explicit
scratch release download URLs on both forges, version 0.5.0, verification
true and a fresh install directory per run. Capture URLs, HTTP results,
exit status, stderr and outputs. The swapped-key copy must install all five
targets. After the real public key replaces the placeholder, the unmodified
candidate must reach signature verification and fail specifically with a
key/signature mismatch, with no installed files or output registration.
A placeholder-key loading error is not that rehearsal assertion.

Require the same-key/no-Rekor bundle to fail log verification under every
bypass/root/cache case in section 3.1 of the reviewed design; the logged
positive must still pass. Altered archives must fail checksums. A validly
scratch-signed mixed current/future-version manifest must fail inventory
validation. Hunor provides that negative signed fixture; no negative-only
Rekor upload was made by the agent. Release failures must never build Go
source. Test defaults separately: all three legacy versions always GitHub;
0.5.0 on github.com GitHub; other servers Forgejo; unset server fails.

Hunor also rehearses a missing SBOM, extra asset and byte-different but
validly formatted bundle. Each must fail distribution checking. Repair the
scratch publications only as Hunor, then repeat the complete checks.

Before a canonical tag exists, close/revert the PR. Before publication,
delete a failed draft; any unreleased-tag deletion is Hunor's choice. After
canonical publication, never delete or move the tag: deny-list a bad version
in the next setup release and fix forward. Delete malicious assets only for
compromise. A bad GitHub copy may be deleted without deleting its tag and
recreated from the verified baseline, followed by mirror-check. A compromised
key requires rotation, deny-list and advisory; old action SHA pins remain
exposed until consumers update. Demo bump PRs follow the approved rehearsal
and canonical release, changing both the action SHA and version together.
