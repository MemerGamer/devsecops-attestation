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
other GitHub/Forgejo Action.

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
| `verify-signature` | no | `false` | When `true` and `cosign` is on `PATH`, verifies `checksums.txt` against its cosign `sign-blob` signature/certificate before trusting it. No-op (with a log notice) if cosign is unavailable. |

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
| `fail-on` | no | `critical` | Informational severity threshold recorded at normalize time; the gate action's `fail-on-severity` is the actual policy decision. |
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
      - run: semgrep --config auto --json --output semgrep-results.json .
        continue-on-error: true
      - uses: actions/upload-artifact@v4
        with:
          name: sast-raw
          path: semgrep-results.json

  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: trivy fs --format json --output trivy-results.json .
        continue-on-error: true
      - uses: actions/upload-artifact@v4
        with:
          name: sca-raw
          path: trivy-results.json

  config:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          checkov -d . --output json --output-file-path checkov-out
          mv checkov-out/results_json.json checkov-results.json
        continue-on-error: true
      - uses: actions/upload-artifact@v4
        with:
          name: config-raw
          path: checkov-results.json

  secret:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: gitleaks detect --report-format json --report-path gitleaks-results.json
        continue-on-error: true
      - uses: actions/upload-artifact@v4
        with:
          name: secret-raw
          path: gitleaks-results.json

  deploy-gate:
    needs: [sast, sca, config, secret]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: MemerGamer/devsecops-attestation/actions/setup@v1
        with:
          version: "1.2.3"

      - uses: actions/download-artifact@v4
        with:
          pattern: "*-raw"
          merge-multiple: true

      - uses: MemerGamer/devsecops-attestation/actions/normalize-sign@v1
        with:
          tool: semgrep
          raw-result: semgrep-results.json
          signing-key: ${{ secrets.SAST_SIGNING_KEY }}

      - uses: MemerGamer/devsecops-attestation/actions/normalize-sign@v1
        with:
          tool: trivy
          raw-result: trivy-results.json
          signing-key: ${{ secrets.SCA_SIGNING_KEY }}

      - uses: MemerGamer/devsecops-attestation/actions/normalize-sign@v1
        with:
          tool: checkov
          raw-result: checkov-results.json
          signing-key: ${{ secrets.CONFIG_SIGNING_KEY }}

      - uses: MemerGamer/devsecops-attestation/actions/normalize-sign@v1
        with:
          tool: gitleaks
          raw-result: gitleaks-results.json
          signing-key: ${{ secrets.SECRET_SIGNING_KEY }}

      - uses: MemerGamer/devsecops-attestation/actions/gate@v1
        with:
          chain: attestation-chain.json
          authorized-signers: >-
            sast=${{ vars.SAST_PUBLIC_KEY }},
            sca=${{ vars.SCA_PUBLIC_KEY }},
            config=${{ vars.CONFIG_PUBLIC_KEY }},
            secret=${{ vars.SECRET_PUBLIC_KEY }}

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: attestation-chain
          path: |
            attestation-chain.json
            gate-decision.json
```

### Forgejo usage

Once this repository is mirrored to Forgejo, point `uses:` at the Forgejo
form instead of the GitHub one:

```yaml
- uses: https://forgejo.remote.kovacsbalinthunor.com/kbalinthunor/devsecops-attestation/actions/setup@v1
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
