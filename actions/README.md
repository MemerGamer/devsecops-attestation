# devsecops-attestation actions

Bash-only composite actions for consumer CI/CD pipelines. Consumer repos use
these instead of cloning and building this repository themselves. Because
every step is a plain bash script invoked through `shell: bash`, none of
these actions require Node.js, so they run unmodified on both GitHub Actions
and Forgejo Actions runners.

Reference on GitHub as:

```
MemerGamer/devsecops-attestation/actions/<name>@<ref>
```

Reference on Forgejo (once mirrored) as:

```
https://forgejo.remote.kovacsbalinthunor.com/kbalinthunor/devsecops-attestation/actions/<name>@<ref>
```

`<ref>` is a tag (e.g. `v1.2.3`), branch, or commit SHA, exactly as with any
other GitHub/Forgejo Action. This project does not publish a floating major
tag (e.g. `@v1`) that moves across releases; pin to an exact release tag
(e.g. `@v0.4.0`) as shown below, or, for the strongest guarantee, to the
release commit SHA itself.

Only `github.*` contexts and `GITHUB_*` / `RUNNER_*` environment variables
that Forgejo Actions also provides are used: `GITHUB_SERVER_URL`,
`GITHUB_REPOSITORY`, `GITHUB_RUN_ID`, `GITHUB_WORKFLOW`, `GITHUB_JOB`,
`GITHUB_SHA`, `GITHUB_REF`, `RUNNER_OS`, `RUNNER_ARCH`, `RUNNER_TEMP`,
`GITHUB_PATH`, `GITHUB_OUTPUT`, `GITHUB_STEP_SUMMARY`, and
`${{ github.action_path }}` (also supported by Forgejo).

## Actions

### `actions/setup`

Downloads a release archive (or builds from source) and puts `keygen`,
`attest`, `verify`, `gate`, and the bundled `deploy.rego` policy on `PATH`.

Each action's `run:` step is a thin call into a script in the action's own
directory (`setup.sh`, `normalize-sign.sh`, `gate.sh`) that reads its
configuration from `INPUT_*` environment variables. This keeps the actual
logic shellcheck-able and independently testable (see `actions/test/`)
instead of living inline in YAML.

| Input | Required | Default | Description |
|---|---|---|---|
| `version` | yes | - | Release version (`1.2.3` or `v1.2.3`), or `source` to build from this action's own checkout with `go build` (requires Go on `PATH`; useful for dogfooding and PR testing). |
| `repository` | no | `MemerGamer/devsecops-attestation` | `owner/repo`, used for the cosign certificate-identity check. |
| `download-base-url` | no | `${{ github.server_url }}/MemerGamer/devsecops-attestation/releases/download` | Base URL archives are downloaded from. Override for Forgejo or a private mirror. |
| `install-dir` | no | `${{ runner.temp }}/devsecops-attestation/bin` | Install directory, added to `PATH`. |
| `verify-signature` | no | `true` | When `true` (the default), verifies `checksums.txt` against its cosign `sign-blob` Sigstore bundle (`checksums.txt.sigstore.json`), pinned to the release-please workflow's exact signer identity, before trusting it; fails the step with guidance if `cosign` is not on `PATH` (add `sigstore/cosign-installer`, or set this to `false` explicitly to skip verification). |

| Output | Description |
|---|---|
| `bin-dir` | Directory containing the installed binaries. |
| `policy-path` | Path to the installed `deploy.rego`. |
| `version` | Resolved version (`source` when built from source). |

The download path: maps `RUNNER_OS`/`RUNNER_ARCH` to goreleaser's
`<os>_<arch>` naming, downloads
`devsecops-attestation_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows) and
`checksums.txt` from `<download-base-url>/v<version>/`, verifies the archive
against `checksums.txt` with `sha256sum -c` (hard failure on a missing entry
or mismatch), extracts, and installs `keygen`, `attest`, `verify`, `gate`,
and `policies/deploy.rego` from the archive.

### `actions/normalize-sign`

Runs `attest normalize` (writes `<raw-result>.normalized.json` for
inspection) and `attest sign --tool-format` (which normalizes inline and
appends the signed attestation to the chain). Requires `attest` on `PATH`
(run `actions/setup` first).

| Input | Required | Default | Description |
|---|---|---|---|
| `tool` | yes | - | Normalize adapter name (`attest tools` lists them: `semgrep`, `sobelow`, `trivy`, `cargo-audit`, `mix-audit`, `checkov`, `gitleaks`, `generic`). |
| `raw-result` | yes | - | Path to the raw tool report. |
| `check-type` | no | `""` | Override check type; the adapter supplies its own default (e.g. `semgrep` -> `sast`) when omitted. |
| `signing-key` | yes | - | 128-char hex Ed25519 private key for this check type. Pass from a secret; the action masks it with `::add-mask::` and passes it to `attest sign` via the `ATTEST_SIGNING_KEY` environment variable, never on argv (argv is visible in `/proc/<pid>/cmdline` for the life of the process, which matters on shared runners). |
| `chain` | no | `attestation-chain.json` | Chain file to append to. |
| `subject` | no | `${{ github.repository }}` | Artifact/application name. |
| `target-ref` | no | `${{ github.sha }}` | Git SHA or artifact digest. |
| `tool-version` | no | `unknown` | Underlying tool's version string. |
| `fail-on` | no | `high` | Minimum severity (inclusive) that marks the signed attestation's `result.passed` as `false`. Not merely informational: the bundled policy's failed-checks rule denies deployment for any attestation with `passed=false`, so this threshold directly affects the gate's blocking decision. Should match the gate action's `fail-on-severity`. |
| `signer-id` | no | `""` | Human-readable signer identity. Omit to let `attest` derive it from `GITHUB_SERVER_URL`/`GITHUB_REPOSITORY`/`GITHUB_WORKFLOW`/`GITHUB_JOB`, which works unchanged on Forgejo. |
| `log-entry` | no | `""` | Transparency log reference. Omit to let `attest` derive a run URL from `GITHUB_SERVER_URL`/`GITHUB_REPOSITORY`/`GITHUB_RUN_ID`. |

| Output | Description |
|---|---|
| `chain` | Path to the chain file that was appended to. |
| `normalized-result` | Path to the normalized-but-unsigned JSON (for artifact upload/debugging). |

`attest sign` always exits `0` on a successful sign regardless of finding
severity; the pass/fail decision belongs to the `actions/gate` step, not to
individual scanner jobs.

### `actions/gate`

Runs `verify` then `gate evaluate` against the assembled chain, writes a
`GateDecision` JSON report, and writes a markdown summary to
`GITHUB_STEP_SUMMARY`. Requires `verify` and `gate` on `PATH`.

| Input | Required | Default | Description |
|---|---|---|---|
| `chain` | yes | - | Path to the attestation chain JSON file. |
| `authorized-signers` | one of this or `verify-signer` | `""` | `check-type=hex` pairs, e.g. `sast=<hex>,sca=<hex>,config=<hex>,secret=<hex>`. |
| `verify-signer` | one of this or `authorized-signers` | `""` | Single hex public key every attestation must be signed with. |
| `policy` | no | `""` | Path to a Rego policy file; empty uses the bundled default. |
| `policy-hash` | no | `""` | Expected SHA-256 hex of the policy file (see `gate policy-hash`). |
| `config-hash` | no | `""` | Expected SHA-256 hex of the effective policy config (see `gate config-hash`); required alongside `policy-hash` when the effective config is non-default. |
| `data` | no | `""` | Path to a JSON file whose object becomes `data.config`. |
| `required-checks` | no | `""` | Comma-separated required check types. |
| `fail-on-severity` | no | `""` | Minimum blocking severity (`info`\|`low`\|`medium`\|`high`\|`critical`). |
| `zero-tolerance-checks` | no | `""` | Comma-separated check types with zero finding tolerance. |
| `target-ref` | no | `${{ github.sha }}` | Commit or artifact digest every attestation's `result.target_ref` must equal (commit binding), passed as `--target-ref`. Set to an empty string to disable the check. |
| `max-age` | no | `24h` | Maximum allowed attestation age; empty means no limit. |
| `require-log-entries` | no | `true` | Fail if any attestation lacks a transparency log entry. |
| `output` | no | `gate-decision.json` | Path to write the `GateDecision` JSON report. |
| `expect` | no | `allow` | `allow` fails the step on a deny; `deny` fails the step on an allow (demo/negative-test mode, prints `gate denied as expected` on the expected deny); `any` never fails on the decision. An evaluation *error* (bad signer, hash mismatch, missing log entry, malformed chain - as opposed to a policy decision) always fails the step, regardless of `expect`. |

| Output | Description |
|---|---|
| `decision` | `allow`, `deny`, or `error` (evaluation could not complete - not a policy decision). |
| `report` | Path to the `GateDecision` JSON report. |

`gate evaluate` exits non-zero both for a policy deny and for a
pre-evaluation error (unverified chain, unauthorized signer, missing log
entry, policy/config hash mismatch). The two are distinguished by whether a
`GateDecision` JSON document (with an `allow` field) was actually written to
`--output`: it is written for both an allow and a deny, but never for a
pre-evaluation error. `actions/gate/gate.sh` uses exactly this rule so
`expect: deny` demo jobs never mistake a broken pipeline for an intentional
policy deny.

## Consumer workflow example

This example follows the hardening this repository's own pipeline
(`.github/workflows/devsecops-pipeline.yml`) applies to itself: no
`continue-on-error` masking a scanner crash, each output file removed
before the scanner runs so a stale file from a previous run cannot be
mistaken for this run's output, `if-no-files-found: error` on every upload
so a missing report fails loudly instead of silently uploading nothing, and
each artifact downloaded by its exact `name:` into its own directory rather
than merged into a shared one. See "Scanner configuration trust" below for
why these matter and what report substitution looks like without them.

```yaml
name: devsecops-pipeline
on:
  push:
    branches: [main]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          set -euo pipefail
          rm -f semgrep-results.json
          # No --error, so exit 0 covers both "no findings" and "some
          # findings"; a nonzero exit is a genuine scan failure and is
          # left to fail the step (the gate decides pass/fail, not this
          # step). --disable-nosem: report findings a `# nosemgrep`
          # comment would otherwise suppress, so a suppression comment in
          # the repo cannot hide a real finding from the signed report.
          semgrep --config auto --disable-nosem --json --output semgrep-results.json .
      - uses: actions/upload-artifact@v4
        with:
          name: sast-raw
          path: semgrep-results.json
          if-no-files-found: error

  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          set -euo pipefail
          rm -f trivy-results.json
          trivy fs --format json --output trivy-results.json --exit-code 0 .
      - uses: actions/upload-artifact@v4
        with:
          name: sca-raw
          path: trivy-results.json
          if-no-files-found: error

  config:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          set -euo pipefail
          rm -rf checkov-out checkov-results.json
          checkov -d . --output json --output-file-path checkov-out --soft-fail
          mv checkov-out/results_json.json checkov-results.json
      - uses: actions/upload-artifact@v4
        with:
          name: config-raw
          path: checkov-results.json
          if-no-files-found: error

  secret:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          set -euo pipefail
          rm -f gitleaks-results.json
          gitleaks detect --report-format json --report-path gitleaks-results.json --exit-code 0
      - uses: actions/upload-artifact@v4
        with:
          name: secret-raw
          path: gitleaks-results.json
          if-no-files-found: error

  deploy-gate:
    needs: [sast, sca, config, secret]
    runs-on: ubuntu-latest
    # Excludes forks and dependabot/renovate: this job holds every signing
    # key secret, so it must not run for a pull_request whose head is not
    # this same repository. See "Deploy gate secret exposure" below.
    if: >-
      (github.event_name == 'push' ||
        (github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository)) &&
      github.actor != 'dependabot[bot]' && github.actor != 'renovate[bot]'
    steps:
      # No checkout here: this job only needs the released binaries
      # (version: "1.2.3" below, not "source"), not this repository's
      # source. Add one only if your gate step also needs repo files, e.g.
      # a custom --policy or --data file.
      - uses: MemerGamer/devsecops-attestation/actions/setup@v0.4.0
        with:
          version: "1.2.3"

      - uses: actions/download-artifact@v4
        with: { name: sast-raw, path: ${{ runner.temp }}/raw/sast }
      - uses: actions/download-artifact@v4
        with: { name: sca-raw, path: ${{ runner.temp }}/raw/sca }
      - uses: actions/download-artifact@v4
        with: { name: config-raw, path: ${{ runner.temp }}/raw/config }
      - uses: actions/download-artifact@v4
        with: { name: secret-raw, path: ${{ runner.temp }}/raw/secret }

      - uses: MemerGamer/devsecops-attestation/actions/normalize-sign@v0.4.0
        with:
          tool: semgrep
          raw-result: ${{ runner.temp }}/raw/sast/semgrep-results.json
          signing-key: ${{ secrets.SAST_SIGNING_KEY }}
          fail-on: high

      - uses: MemerGamer/devsecops-attestation/actions/normalize-sign@v0.4.0
        with:
          tool: trivy
          raw-result: ${{ runner.temp }}/raw/sca/trivy-results.json
          signing-key: ${{ secrets.SCA_SIGNING_KEY }}
          fail-on: high

      - uses: MemerGamer/devsecops-attestation/actions/normalize-sign@v0.4.0
        with:
          tool: checkov
          raw-result: ${{ runner.temp }}/raw/config/checkov-results.json
          signing-key: ${{ secrets.CONFIG_SIGNING_KEY }}
          fail-on: high

      - uses: MemerGamer/devsecops-attestation/actions/normalize-sign@v0.4.0
        with:
          tool: gitleaks
          raw-result: ${{ runner.temp }}/raw/secret/gitleaks-results.json
          signing-key: ${{ secrets.SECRET_SIGNING_KEY }}
          fail-on: high

      - uses: MemerGamer/devsecops-attestation/actions/gate@v0.4.0
        with:
          chain: attestation-chain.json
          authorized-signers: >-
            sast=${{ vars.SAST_PUBLIC_KEY }},
            sca=${{ vars.SCA_PUBLIC_KEY }},
            config=${{ vars.CONFIG_PUBLIC_KEY }},
            secret=${{ vars.SECRET_PUBLIC_KEY }}
          fail-on-severity: high
          # target-ref defaults to ${{ github.sha }} already; shown here
          # for legibility.
          target-ref: ${{ github.sha }}

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: attestation-chain
          path: |
            attestation-chain.json
            gate-decision.json
          if-no-files-found: error
```

### Scanner configuration trust

Every scanner in the jobs above honours in-repo suppression files it finds
during its own checkout: `.gitleaks.toml` allowlists, `.checkov.yaml`
`skip-check` entries, `# nosemgrep` comments, `.semgrepignore`, and
`.trivyignore`. Anyone who can open a pull request that edits one of those
files (or plants a `# nosemgrep` comment next to a real vulnerability) can
suppress a finding before it ever reaches the signed attestation - the
scanner step itself never sees it, so no amount of hardening downstream of
the scanner recovers it. This is a different, earlier trust boundary than
the "report substitution" concerns the changes above address (a forged
*output* file); this is about influencing what the scanner produces in the
first place.

Mitigate this the same way you would any other change to CI-trusted
configuration:

- **CODEOWNERS** on `.gitleaks.toml`, `.checkov.yaml`, `.semgrepignore`,
  `.trivyignore`, and any custom `data.config` / `--data` file the gate
  reads, so a suppression change requires review from someone who owns the
  security posture, not just anyone with write access to the branch.
- **Pin a trusted, out-of-band config** the scanner step reads instead of
  (or in addition to) the one checked out with the PR - `gitleaks --config
  <trusted-path>`, semgrep `--disable-nosem` (already used above, which
  ignores `# nosemgrep` entirely rather than trusting it), trivy
  `--ignorefile <trusted-path>`, checkov `--config-file <trusted-path>`.
  A config fetched from a separate, protected location (a release asset,
  an organization-level repository) cannot be altered by a PR against this
  repository.
- **Protect the signing environment** (see `environment: production` on
  `deploy-gate` in this repository's own workflow, and "Deploy gate secret
  exposure" below): even a suppressed finding still has to pass through
  signing before it reaches a decision, so required reviewers on the
  environment that holds the signing keys are a second checkpoint
  independent of the scanner configuration.

### Deploy gate secret exposure

The `deploy-gate` job above builds the attestation tooling and handles every
signing key secret (`SAST_SIGNING_KEY`, `SCA_SIGNING_KEY`, ...). GitHub
exposes secrets to `pull_request`-triggered jobs even for forked PRs when
the base repository's workflow defines them, so without a guard, a forked
PR that modifies this workflow (or a dependency it pulls in) could exfiltrate
every signing key. The `if:` on `deploy-gate` above restricts it to `push`
events and to `pull_request` events whose head repository is this same
repository (i.e., not a fork), and excludes dependabot/renovate PRs the same
way the scanner jobs already are.

Additionally, configure the environment referenced by `deploy-gate` (e.g.
`production`, as this repository's own pipeline does) as a **protected
GitHub environment** with required reviewers and, ideally, deployment
branch restrictions limited to `main`. This adds a human approval gate in
front of the job that holds the signing keys, independent of the `if:`
condition above. Configuring the environment itself is a repository
settings change, not something this composite action or workflow file can
enforce - see `SECURITY.md` for the recommendation in this repository's own
context.

### Forgejo usage

Once this repository is mirrored to Forgejo, point `uses:` at the Forgejo
form instead of the GitHub one:

```yaml
- uses: https://forgejo.remote.kovacsbalinthunor.com/kbalinthunor/devsecops-attestation/actions/setup@v0.4.0
  with:
    version: "1.2.3"
    download-base-url: https://forgejo.remote.kovacsbalinthunor.com/kbalinthunor/devsecops-attestation/releases/download
```

`download-base-url` must be overridden explicitly on Forgejo: the action's
own default only points at the GitHub release, and the two forges normally
have different owners/orgs for the same project. Everything else in the
action (env var derivation, signer identity, log entry URLs) works unchanged
because it only relies on the `GITHUB_*` variables Forgejo Actions also
exports.

### Secret naming convention

Per-check-type signing keys are private repository/organization secrets, one
per check type, named `<CHECK_TYPE>_SIGNING_KEY` (upper-cased):

- `SAST_SIGNING_KEY`
- `SCA_SIGNING_KEY`
- `CONFIG_SIGNING_KEY`
- `SECRET_SIGNING_KEY`

The corresponding public keys used by `actions/gate`'s `authorized-signers`
are not secret and are best kept as repository/organization *variables*
(`vars.*`), named `<CHECK_TYPE>_PUBLIC_KEY`:

- `SAST_PUBLIC_KEY`
- `SCA_PUBLIC_KEY`
- `CONFIG_PUBLIC_KEY`
- `SECRET_PUBLIC_KEY`

Generate a key pair per check type with `keygen --out <dir>` (from
`actions/setup`'s installed `bin-dir`, or any local build); `keygen` writes
`private.hex` and `public.hex`.

## Testing

`actions/test/run-local.sh` is a rerunnable local exercise of all three
scripts, without a real GitHub/Forgejo runner:

- builds the CLI binaries from this checkout;
- generates four Ed25519 key pairs (sast, sca, config, secret);
- runs `normalize-sign.sh` four times against the clean fixtures in
  `pkg/normalize/testdata/` to build an allow-chain, and again with
  `gitleaks/findings.json` to build a deny-chain (secret is zero-tolerance
  in the bundled policy, so any secret finding blocks deployment);
- runs `gate.sh` through `expect=allow`/`deny`/`any` on both chains, plus an
  unauthorized-signer case, and checks that an evaluation *error* fails the
  step even under `expect=any`;
- runs `gate.sh` with an empty `max-age` and checks it is treated as "no
  limit" rather than being passed through to `gate evaluate` as an invalid
  empty duration;
- exercises `setup.sh`'s `source` build path directly against this
  checkout;
- exercises `setup.sh`'s download path against a fake release directory
  served over `http://127.0.0.1:<random-port>/` (`python3 -m http.server`),
  including a sibling `<archive>.sbom.json` checksums.txt entry (as
  goreleaser produces) to guard against the checksum lookup matching it
  instead of the archive, and a tampered `checksums.txt` that must fail
  closed;
- runs `shellcheck` on all three scripts and validates all three
  `action.yml` files parse as YAML with `runs.using: composite`.

Run it with:

```bash
bash actions/test/run-local.sh
```

It prints `PASS`/`FAIL` per check and a final `passed: N, failed: N` summary,
exiting non-zero if anything failed. If the [`act`](https://github.com/nektos/act)
tool is installed, `run-local.sh` notes that but does not depend on or invoke
it; `act` requires Docker and a GitHub Actions-compatible image, which is out
of scope for a Forgejo-portable local test.
