# Integration Guide

This guide is for operators who want to consume the devsecops-attestation
pipeline from another repository, on GitHub or on a Forgejo mirror, without
cloning or building this repository themselves.

## Trust Model Overview

Each security check produces a raw scanner report, which is normalized into
a canonical shape and signed with an Ed25519 key dedicated to that check
type. Signed attestations are linked into a chain by SHA-256 digest, so
insertion, deletion, or reordering is detectable. The deploy gate verifies
every signature and the chain linkage, checks that each attestation was
signed by its check type's authorized key, enforces transparency log
references, pins the SHA-256 of the policy file and of the effective policy
configuration, and only then evaluates the chain against an OPA/Rego policy
to produce an ALLOW or BLOCK decision. Consuming the pipeline means
installing the CLI tools, provisioning one key pair per check type, and
wiring the three composite actions (`setup`, `normalize-sign`, `gate`) or
their CLI equivalents into your own workflow. See
[architecture.md](architecture.md) for the full data flow and cryptographic
guarantees, and [SECURITY.md](../SECURITY.md) for the threat model and key
rotation procedure.

## Prerequisites

- A GitHub Actions or Forgejo Actions workflow (or any CI system able to run
  a container image or a downloaded binary).
- One or more security scanners already producing JSON output (semgrep,
  trivy, checkov, gitleaks, cargo-audit, mix_audit, sobelow, or any tool
  whose output you normalize yourself).
- Ability to store secrets (signing keys) and, ideally, repository/org
  variables (public keys) in your forge.

## Key Generation

Generate one Ed25519 key pair per check type. Each pair is independent, so a
compromised key affects only its own check type:

```shell
for check in sast sca config secret; do
  keygen --out "keys/$check"
done
```

`keygen` writes `private.hex` and `public.hex` in each directory. Store the
private key as a repository or organization secret and the public key as a
repository or organization variable, named `<CHECK_TYPE>_SIGNING_KEY` and
`<CHECK_TYPE>_PUBLIC_KEY` respectively:

| Check type | Signing key secret | Public key variable |
|---|---|---|
| `sast` | `SAST_SIGNING_KEY` | `SAST_PUBLIC_KEY` |
| `sca` | `SCA_SIGNING_KEY` | `SCA_PUBLIC_KEY` |
| `config` | `CONFIG_SIGNING_KEY` | `CONFIG_PUBLIC_KEY` |
| `secret` | `SECRET_SIGNING_KEY` | `SECRET_PUBLIC_KEY` |

Never commit `private.hex` files. Custom check types follow the same
convention with their own uppercased name (see
[Custom Check Types](#custom-check-types) below). This repository's own
pipeline additionally recognizes `SECRET_SCANNING_SIGNING_KEY` /
`SECRET_SCANNING_PUBLIC_KEY` as historical names for the `secret` check
type's key pair; new consumers should use the shorter `SECRET_*` names the
composite actions document.

## Installation Options

Pick whichever fits your CI environment. All three install the same four
binaries (`keygen`, `attest`, `verify`, `gate`) plus the bundled
`policies/deploy.rego`.

### Composite action: `setup`

The simplest path for a GitHub or Forgejo Actions workflow. Downloads a
tagged release archive matching the runner's OS/architecture, verifies it
against `checksums.txt` (hard failure on a missing entry or mismatch), and
optionally verifies the checksums file's cosign signature:

```yaml
- uses: MemerGamer/devsecops-attestation/actions/setup@v0.4.0
  with:
    version: "1.2.3"
    # verify-signature defaults to "true" and requires cosign on PATH (add
    # sigstore/cosign-installer before this step); set to "false" explicitly
    # to skip signature verification, e.g. for local/demo runs.
```

This project does not publish a floating major tag (e.g. `@v1`) that moves
across releases; pin `@<ref>` to an exact release tag as shown above, or,
for the strongest guarantee, to the release commit SHA itself.

`version: source` builds the binaries with `go build` from the action's own
checkout instead of downloading a release; useful for dogfooding this
repository's own pipeline or testing a PR against the composite actions
themselves. See [`actions/README.md`](../actions/README.md#actionssetup)
for the full input/output reference.

### Container image

`ghcr.io/memergamer/devsecops-attestation:<version>` (also tagged
`<major>.<minor>`, `<major>`, and `latest`) bundles all four binaries and
the default policy under a distroless, non-root runtime. Mount your working
directory at `/work` and invoke whichever binary you need by name:

```shell
docker run --rm -v "$PWD:/work" ghcr.io/memergamer/devsecops-attestation:1.2.3 \
  keygen --out /work/keys

docker run --rm -v "$PWD:/work" ghcr.io/memergamer/devsecops-attestation:1.2.3 \
  attest tools

docker run --rm -v "$PWD:/work" ghcr.io/memergamer/devsecops-attestation:1.2.3 \
  verify --chain /work/attestation-chain.json

docker run --rm -v "$PWD:/work" ghcr.io/memergamer/devsecops-attestation:1.2.3 \
  gate evaluate --chain /work/attestation-chain.json \
    --authorized-signers "sast=<hex>,sca=<hex>,config=<hex>,secret=<hex>" \
    --max-age 24h --require-log-entries
```

The image has no fixed entrypoint binary (`ENTRYPOINT []`); the first
argument selects `keygen`, `attest`, `verify`, or `gate`. A self-hosted
registry mirror can override the registry with `vars.REGISTRY` when
building the image with goreleaser (see [structure.md](structure.md)).

### GoReleaser archives

Each tagged release publishes per-OS/arch `.tar.gz` (`.zip` on Windows)
archives containing all four binaries, `LICENSE`, `README.md`, and
`policies/deploy.rego`, plus a `checksums.txt` and cosign
signature/certificate. Download, verify, and extract manually, or let
`actions/setup` do it for you.

### `go install`

For a Go toolchain-equipped environment that does not need a pinned
release, install directly from module paths:

```shell
go install github.com/MemerGamer/devsecops-attestation/cmd/keygen@latest
go install github.com/MemerGamer/devsecops-attestation/cmd/sign@latest
go install github.com/MemerGamer/devsecops-attestation/cmd/verify@latest
go install github.com/MemerGamer/devsecops-attestation/cmd/gate@latest
```

The `sign` module builds the `attest` binary name used elsewhere in this
guide; `go install` names it `sign` after the module path unless you
`mv`/alias it.

## Minimal Consumer Workflow

A full worked example (four scanner jobs plus a gate job) lives in
[`actions/README.md`](../actions/README.md#consumer-workflow-example); it is
not duplicated here. The essential shape is:

```yaml
jobs:
  sast:
    steps:
      - run: |
          set -euo pipefail
          rm -f semgrep-results.json
          semgrep --config auto --disable-nosem --json --output semgrep-results.json .
      - uses: actions/upload-artifact@v4
        with: { name: sast-raw, path: semgrep-results.json, if-no-files-found: error }
  # ... sca, config, secret jobs follow the same pattern: rm -f the output
  # file first, no continue-on-error / || true masking a crash (the tool's
  # own findings-vs-crash exit code semantics decide that), and
  # if-no-files-found: error on the upload.

  deploy-gate:
    needs: [sast, sca, config, secret]
    # Excludes forks and dependabot/renovate: this job holds the signing
    # key secrets. See actions/README.md's "Deploy gate secret exposure".
    if: >-
      (github.event_name == 'push' ||
        (github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository)) &&
      github.actor != 'dependabot[bot]' && github.actor != 'renovate[bot]'
    steps:
      # No checkout: only the released binaries are needed here.
      - uses: MemerGamer/devsecops-attestation/actions/setup@v0.4.0
        with: { version: "1.2.3" }
      # Each artifact downloaded by exact name into its own directory, not
      # merged, so one artifact cannot silently overwrite another's file.
      - uses: actions/download-artifact@v4
        with: { name: sast-raw, path: ${{ runner.temp }}/raw/sast }
      # ... one download-artifact step per scanner artifact
      - uses: MemerGamer/devsecops-attestation/actions/normalize-sign@v0.4.0
        with:
          tool: semgrep
          raw-result: ${{ runner.temp }}/raw/sast/semgrep-results.json
          signing-key: ${{ secrets.SAST_SIGNING_KEY }}
          fail-on: high
      # ... one normalize-sign step per scanner
      - uses: MemerGamer/devsecops-attestation/actions/gate@v0.4.0
        with:
          chain: attestation-chain.json
          authorized-signers: >-
            sast=${{ vars.SAST_PUBLIC_KEY }},sca=${{ vars.SCA_PUBLIC_KEY }},
            config=${{ vars.CONFIG_PUBLIC_KEY }},secret=${{ vars.SECRET_PUBLIC_KEY }}
          fail-on-severity: high
          target-ref: ${{ github.sha }}
```

See [`actions/README.md`](../actions/README.md#scanner-configuration-trust)
for why each of these steps is shaped this way ("report substitution" and
scanner configuration trust), and for the full worked example.

## Adding a Scanner

Three options, in order of effort:

1. **Use a built-in adapter.** `attest tools` lists the registered
   normalize adapters (`semgrep`, `trivy`, `checkov`, `gitleaks`,
   `cargo-audit`, `mix-audit`, `sobelow`, `generic`). Pass the adapter name
   as `--tool-format` to `attest sign` (or as `tool:` to
   `actions/normalize-sign`) and point `--result` / `raw-result` at the raw
   tool report; normalization happens inline before signing.
2. **Emit canonical JSON yourself and use `generic`.** If your scanner
   already produces (or you can script it to produce) the canonical
   `{ "passed": bool, "findings": [...] }` shape described in the root
   [README.md](../README.md#sign-security-results), use the `generic`
   adapter, which re-validates and passes the findings through unchanged.
3. **Contribute a new adapter.** See
   [`pkg/normalize/doc.go`](../pkg/normalize/doc.go) for the steps
   (implement `Normalizer`, map the tool's severity vocabulary per
   [severity-mapping.md](severity-mapping.md), register in an `init()`,
   add fixtures) and open a pull request.

## Custom Check Types

A check type is not limited to `sast`/`sca`/`config`/`secret`. Any
identifier matching `^[a-z][a-z0-9-]{0,31}$` is accepted by `attest sign
--check-type`, but the bundled policy seals the chain against undeclared
check types: any attestation whose `check_type` is not in
`data.config.required_checks` denies deployment outright, with reasons
listing the check types it did not expect, rather than being silently
ignored. This means a custom check type is not optional bookkeeping - it is
mandatory the moment you sign one. Before adding a new check type to the
pipeline, you must also add it to `data.config.required_checks` (via `gate
evaluate --required-checks` or a `--data` JSON file); see [Policy
Configuration](#policy-configuration) below. Each custom check type still
needs its own key pair and its own entry in `--authorized-signers`.

## Policy Configuration

The bundled `policies/deploy.rego` is parameterized through `data.config`:

| Key | Default | Meaning |
|---|---|---|
| `required_checks` | `["sast", "sca", "config", "secret"]` | Check types that must appear in the chain. |
| `fail_on_severity` | `"high"` | Minimum finding severity that blocks deployment. |
| `zero_tolerance_checks` | `["secret"]` | Check types where any finding, of any severity, blocks deployment. |

Set these via `gate evaluate --required-checks` / `--fail-on-severity` /
`--zero-tolerance-checks`, or via a JSON file passed to `--data` (the flags
override individual keys from `--data`). A malformed value (wrong type, an
unrecognized severity, an empty array) is rejected fail-closed, both by the
gate CLI (for `--data` files) and by the bundled policy itself (for any path
that reaches OPA).

`--policy-hash` pins the SHA-256 of the Rego source being evaluated. Use it
whenever you evaluate the bundled default policy unmodified. Write and pin
your own policy file (`--policy path/to/custom.rego --policy-hash <hash>`)
only when the parameterization above cannot express what you need, for
example a rule that is not just a threshold or a required-check-type list.
Compute the hash with `gate policy-hash [--policy <path>]`.

`--config-hash` pins the SHA-256 of the fully resolved configuration
(defaults filled in). It is required whenever `--policy-hash` is set and the
effective configuration is not the bundled defaults; compute it with
`gate config-hash` using the same override flags you pass to
`gate evaluate`. See
[SECURITY.md](../SECURITY.md#policy-configuration-integrity-trust-boundary)
for why the two hashes are separate trust boundaries.

## Threshold Alignment

`attest`'s `--fail-on` (default `high`) decides the `passed` field baked
into each signed attestation. The gate's `--fail-on-severity` (also default
`high`) is evaluated independently against the raw findings, but the
gate's "failed checks" deny reason also fires whenever any attestation
carries `passed == false`. Keep the two thresholds equal, or a finding can
fail one check without tripping the other. See
[severity-mapping.md](severity-mapping.md#--fail-on-default) for the full
rationale.

## Demo Mode

`actions/gate`'s `expect` input supports negative testing: `expect: deny`
fails the step on an allow and succeeds (printing `gate denied as
expected`) on an intentional deny, useful for demonstrating that a known-bad
chain is actually blocked. `expect: any` never fails on the policy decision
itself. In every mode, an evaluation *error* (bad signer, hash mismatch,
missing log entry, malformed chain) still fails the step, distinguished from
a policy decision by whether a `GateDecision` JSON document was written to
`--output` (see [Troubleshooting](#troubleshooting)).

## Forge Portability

The composite actions use only `github.*` contexts and `GITHUB_*`/`RUNNER_*`
environment variables that Forgejo Actions also provides:
`GITHUB_SERVER_URL`, `GITHUB_REPOSITORY`, `GITHUB_RUN_ID`,
`GITHUB_WORKFLOW`, `GITHUB_JOB`, `GITHUB_SHA`, `GITHUB_REF`, `RUNNER_OS`,
`RUNNER_ARCH`, `RUNNER_TEMP`, `GITHUB_PATH`, `GITHUB_OUTPUT`,
`GITHUB_STEP_SUMMARY`, and `${{ github.action_path }}`. `attest` derives
`--signer-id` and `--log-entry` from these same variables when the flags are
omitted, so both work unchanged on a Forgejo runner.

On Forgejo, reference the actions by their full mirror URL instead of the
GitHub shorthand, and override `download-base-url` on `actions/setup`
explicitly (its default only points at the GitHub release):

```yaml
- uses: https://forgejo.remote.kovacsbalinthunor.com/kbalinthunor/devsecops-attestation/actions/setup@v0.4.0
  with:
    version: "1.2.3"
    download-base-url: https://forgejo.remote.kovacsbalinthunor.com/kbalinthunor/devsecops-attestation/releases/download
```

A few steps are GitHub-only and guarded with
`if: github.server_url == 'https://github.com'` so they degrade gracefully
elsewhere:

- **Codecov upload** - requires an org token that only exists on
  github.com.
- **`actions/attest-build-provenance`** - a GitHub-native Sigstore/Rekor
  feature with no Forgejo equivalent.
- **Dependabot auto-merge** - Dependabot itself is a GitHub-only bot;
  Forgejo mirrors use Renovate or an equivalent instead.

The container image registry is configurable via `vars.REGISTRY` (defaults
to `ghcr.io`), so a Forgejo publish job can push to a self-hosted registry
instead.

## Worked Examples

Two demo repositories exercise this integration end to end, one per
ecosystem:

- [Phoenix-DevSecOps-Demo](https://github.com/MemerGamer/Phoenix-DevSecOps-Demo)
  - an Elixir/Phoenix application using `sobelow` and `mix_audit`.
- [Rust-DevSecOps-Demo](https://github.com/MemerGamer/Rust-DevSecOps-Demo) -
  a Rust application using `cargo-audit`.

Both consume the composite actions exactly as described in this guide and
are a good reference for wiring a real scanner into `normalize-sign`.

## Troubleshooting

**Gate step fails but no `gate-decision.json` was produced (or it fails to
parse).** This is an evaluation *error*, not a policy deny: an unverified
chain, an unauthorized signer, a policy/config hash mismatch, or a missing
transparency log entry. `gate evaluate --output` only writes a
`GateDecision` document on an actual allow/deny decision; a pre-evaluation
error exits before that file is written. Check the job log for the specific
failed check, listed in order (chain verification, signer authorization,
log entries, policy hash, config hash, then OPA).

**A scanner produced empty output and the sign step still failed.** Every
normalize adapter requires a schema marker unique to its tool's report
format (see [severity-mapping.md](severity-mapping.md#schema-marker-requirement-fail-closed-on-unrecognized-input))
and fails closed instead of silently returning zero findings. An empty or
malformed report (crashed scanner, wrong `--tool-format`, truncated output)
is rejected rather than treated as a clean scan.

**"unrecognized input" or a schema-marker error from `attest normalize` /
`attest sign --tool-format`.** The raw report does not carry the marker the
selected adapter expects; either the wrong `--tool-format` was passed, or
the underlying tool's output format changed. Confirm the tool version
matches what the adapter was written against and compare with the fixtures
under `pkg/normalize/testdata/<tool>/`.

**"policy hash mismatch" or "config hash mismatch".** The Rego file (or the
effective `data.config`) evaluated at runtime does not match the pinned
hash. Recompute with `gate policy-hash [--policy <path>]` and
`gate config-hash [same override flags as gate evaluate]`, and update the
pinned value in your workflow. This is expected the first time you change
`policies/deploy.rego` or the gate's configuration flags and forget to
re-pin.

**"attestation exceeds max-age" or a stale chain rejection.** An
attestation in the chain is older than `--max-age` (default `24h` in the
bundled workflow). This usually means the chain file was reused across
runs, or a scan step ran long before the gate step. Regenerate the chain
within a single pipeline run, or increase `--max-age` deliberately if a
longer window is legitimate for your pipeline.
