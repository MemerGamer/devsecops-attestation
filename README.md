# DevSecOps Attestation

![Go version](https://img.shields.io/badge/go-1.26-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
[![DevSecOps Attested Pipeline](https://github.com/MemerGamer/devsecops-attestation/actions/workflows/devsecops-pipeline.yml/badge.svg)](https://github.com/MemerGamer/devsecops-attestation/actions/workflows/devsecops-pipeline.yml)
[![codecov](https://codecov.io/gh/MemerGamer/devsecops-attestation/graph/badge.svg)](https://codecov.io/gh/MemerGamer/devsecops-attestation)

Cryptographically verifiable security decisions in CI/CD pipelines.

**MSc Thesis:** Cryptographically Verifiable Security Decisions in CI/CD-based DevSecOps Pipelines
**Author:** Kovács Bálint-Hunor - Sapientia EMTE, Marosvásárhelyi Kar

---

## Table of Contents

- [Overview](#overview)
- [Zero-Trust Design](#zero-trust-design)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [GitHub Actions Setup](#github-actions-setup)
- [Running Tests](#running-tests)
- [Documentation](#documentation)
- [License](#license)

---

## Overview

Each security check in the CI/CD pipeline (SAST, SCA, config scan, secret scan)
produces an Ed25519-signed JSON attestation. Attestations are linked into a chain:
each one includes the SHA-256 digest of the previous, making insertion, deletion,
or reordering detectable. A deployment gate loads the chain, verifies every
signature and the chain linkage, then evaluates the result against an OPA/Rego
policy to produce an ALLOW or BLOCK decision.

---

## Zero-Trust Design

The system applies zero-trust principles throughout the attestation lifecycle:

| Control | Mechanism |
|---------|-----------|
| Per-check-type signing keys | Each check type (sast, sca, config, secret) uses a dedicated Ed25519 key pair. A compromised SAST key cannot forge SCA attestations. |
| Cryptographically bound signer identity | `SignerID` (e.g. `github-runner:Linux`) is included in the canonical payload and covered by the Ed25519 signature. Injection after signing is detectable. |
| Timestamp enforcement | `VerifyChainWithOptions` rejects future timestamps (60 s clock skew tolerance), timestamp regressions, and attestations older than `--max-age`. |
| Policy file integrity | `--policy-hash` pins the SHA-256 of the Rego policy file. A modified policy file is rejected before evaluation. |
| Policy configuration integrity | `--config-hash` pins the SHA-256 of the fully resolved policy configuration (`required_checks`, `fail_on_severity`, `zero_tolerance_checks`, defaults filled in). If `--policy-hash` is set and the effective configuration is not the bundled defaults, `--config-hash` is required; omitting it is a misconfiguration and the gate exits 1 before OPA runs. `gate config-hash` prints the value to pin. |
| Fail-closed policy configuration | The bundled policy denies deployment (instead of silently loosening a rule) when `data.config.fail_on_severity` is not a recognized severity, or `data.config.required_checks` / `data.config.zero_tolerance_checks` is present but not a non-empty array of strings. The gate CLI applies the same validation to `--data` files before they reach OPA. |
| Fail-closed finding severity | A finding whose severity is not one of `info`, `low`, `medium`, `high`, `critical` always blocks deployment; it is never silently treated as passing. |
| Signer/gate threshold alignment | `attest`'s `--fail-on` decides the `passed` field baked into each attestation ("no finding at or above the signing threshold"). The gate's own severity check runs independently on the findings, but its `failed checks` deny reason also fires whenever an attestation has `passed == false`. Keep `--fail-on` on the signer side and `--fail-on-severity` on the gate side set to the same value (both default to `critical`), or a finding could fail the signer's threshold without also being at or above the gate's blocking threshold, and vice versa. |
| Transparency log references | Each attestation carries a `log_entry` URL (the GitHub Actions run). `--require-log-entries` makes this mandatory at the gate. |
| Explicit signer authorization | The gate requires either `--verify-signer` (single shared key) or `--authorized-signers` (per-check-type map). Neither can be omitted. Authorization is enforced in Go before the policy runs. |
| Chain pre-verification | The policy is never evaluated on an unverified chain. A broken chain causes the gate to exit 1 without consulting OPA. |
| No duplicate check types | `VerifyChain` rejects chains where the same check type appears more than once, preventing replay of individual steps. |

---

## Prerequisites

- Go 1.26 or later

---

## Quick Start

### Generate key pairs

Generate one key pair per check type. Each pair is independent so a key
compromise is contained to a single check type.

```shell
mkdir -p keys
for check in sast sca config secret; do
  go run ./cmd/keygen --out "keys/$check"
done
# Each directory contains private.hex (keep secret) and public.hex
```

### Sign security results

Each result file must be a JSON object with the following shape:

```json
{ "passed": true, "findings": [] }
```

Findings (optional) have the shape:

```json
{ "id": "CWE-89", "severity": "critical", "title": "SQL injection", "location": "src/db.go:42" }
```

Sign all four checks using their respective keys. Prefer `--signing-key-file`
(or the `ATTEST_SIGNING_KEY` environment variable) over `--signing-key`:
a value passed on argv stays visible in `/proc/<pid>/cmdline` for the life
of the process, which matters on shared runners. `--signing-key` is kept
only for backward compatibility.

```shell
REF=$(git rev-parse HEAD)
LOG_URL="https://github.com/org/repo/actions/runs/12345"

go run ./cmd/sign \
  --check-type sast --tool semgrep \
  --result results/sast.json \
  --target-ref "$REF" --subject myapp \
  --signing-key-file keys/sast/private.hex \
  --signer-id "local:$(whoami)" \
  --log-entry "$LOG_URL" \
  --chain chain.json

go run ./cmd/sign \
  --check-type sca --tool trivy \
  --result results/sca.json \
  --target-ref "$REF" --subject myapp \
  --signing-key-file keys/sca/private.hex \
  --signer-id "local:$(whoami)" \
  --log-entry "$LOG_URL" \
  --chain chain.json

go run ./cmd/sign \
  --check-type config --tool checkov \
  --result results/config.json \
  --target-ref "$REF" --subject myapp \
  --signing-key-file keys/config/private.hex \
  --signer-id "local:$(whoami)" \
  --log-entry "$LOG_URL" \
  --chain chain.json

go run ./cmd/sign \
  --check-type secret --tool gitleaks \
  --result results/secret.json \
  --target-ref "$REF" --subject myapp \
  --signing-key-file keys/secret/private.hex \
  --signer-id "local:$(whoami)" \
  --log-entry "$LOG_URL" \
  --chain chain.json
```

### Verify chain integrity

```shell
go run ./cmd/verify --chain chain.json
```

This verifies all Ed25519 signatures, chain linkage, subject consistency,
and timestamp ordering. Pass `--verify-signer <hex>` to also check that
every attestation was signed by a specific key.

### Evaluate the deploy gate

```shell
SAST_PUB=$(cat keys/sast/public.hex)
SCA_PUB=$(cat keys/sca/public.hex)
CONFIG_PUB=$(cat keys/config/public.hex)
SECRET_PUB=$(cat keys/secret/public.hex)

go run ./cmd/gate evaluate \
  --chain chain.json \
  --authorized-signers "sast=$SAST_PUB,sca=$SCA_PUB,config=$CONFIG_PUB,secret=$SECRET_PUB" \
  --policy policies/deploy.rego \
  --policy-hash "$(sha256sum policies/deploy.rego | cut -d' ' -f1)" \
  --max-age 24h \
  --require-log-entries
```

Exit code 0 means the gate allows deployment. Exit code 1 means it was blocked
(chain invalid, policy denied, or a zero-trust check failed). The `--output`
flag writes the full decision JSON, including the `effective_config` and
`config_hash` that were used for the evaluation.

**`gate evaluate` flags:**

| Flag | Purpose |
|---|---|
| `--chain` | Path to the chain JSON file (required). |
| `--verify-signer` | Hex public key that every attestation must be signed with. Mutually exclusive alternative to `--authorized-signers`; one of the two is required. |
| `--authorized-signers` | `check_type=hex_pubkey` pairs, comma-separated, e.g. `sast=<hex>,sca=<hex>`. Every check type in the chain must have a matching entry. |
| `--policy` | Path to a Rego policy file. Uses the bundled `policies/deploy.rego` when omitted. |
| `--policy-hash` | Expected SHA-256 hex of the policy source that will be evaluated (the file at `--policy`, or the bundled policy when `--policy` is omitted). A mismatch fails closed before OPA loads the policy. |
| `--data` | Path to a JSON file whose object becomes `data.config` for the policy. Validated the same way as the override flags below: unknown keys, a malformed `fail_on_severity`, or a `required_checks` / `zero_tolerance_checks` value that is not a non-empty array of valid check types are all rejected. |
| `--required-checks` | Comma-separated required check types, e.g. `sast,sca,config,secret`. Overrides `data.config.required_checks` (from `--data`, if given). |
| `--fail-on-severity` | Minimum finding severity that blocks deployment: `info`, `low`, `medium`, `high`, or `critical`. Overrides `data.config.fail_on_severity`. |
| `--zero-tolerance-checks` | Comma-separated check types with zero finding tolerance, e.g. `secret`. Overrides `data.config.zero_tolerance_checks`. |
| `--config-hash` | Expected SHA-256 hex of the fully resolved policy configuration (see `gate config-hash`). Required whenever `--policy-hash` is set and the effective configuration is not the bundled defaults. |
| `--max-age` | Maximum allowed attestation age, e.g. `24h`. No limit when omitted. |
| `--require-log-entries` | Fail if any attestation lacks a transparency log entry (`log_entry`). |
| `--output` | Write the full `GateDecision` JSON (allow, reasons, effective config, config hash) to this path. |

**Subcommands:**

```shell
# Print the SHA-256 of a policy file (or the bundled default policy).
go run ./cmd/gate policy-hash [--policy policies/deploy.rego]

# Print the SHA-256 of the effective policy configuration for a given set
# of --data / --required-checks / --fail-on-severity / --zero-tolerance-checks
# overrides, with defaults filled in. Use this to compute the value for
# --config-hash.
go run ./cmd/gate config-hash \
  --required-checks sast,sca,config,secret \
  --fail-on-severity critical \
  --zero-tolerance-checks secret
```

**Alternative: single shared key** (simpler, less isolation)

```shell
go run ./cmd/gate evaluate \
  --chain chain.json \
  --verify-signer "$(cat keys/shared/public.hex)"
```

---

## GitHub Actions Setup

`.github/workflows/devsecops-pipeline.yml` dogfoods this repository's own
composite actions rather than hand-rolled steps: `sast`, `sca`, `config` and
`secret` run in parallel jobs and upload raw scanner JSON as artifacts; the
`deploy-gate` job downloads them, calls `./actions/setup` with
`version: source` (so the CLI binaries are built from the same commit the
job is running), normalizes and signs each raw result with
`./actions/normalize-sign`, and evaluates the assembled chain with
`./actions/gate`. An `actions-selftest` job runs
`actions/test/run-local.sh` on every push and pull request so a change to
the composite actions themselves is validated before the jobs that depend
on them run. See [`actions/README.md`](actions/README.md) for the full
input/output reference of each action, including how to consume them from
another repository (`uses: MemerGamer/devsecops-attestation/actions/<name>@<ref>`)
or from a Forgejo mirror.

The pipeline uses per-check-type key pairs. Each check type has its own
dedicated signing key so a compromise is contained to a single check.

**1. Generate four key pairs locally:**

```shell
for check in sast sca config secret; do
  go run ./cmd/keygen --out "keys/$check"
done
```

**2. Add all eight secrets to your repository:**

Go to: **Settings > Secrets and variables > Actions > New repository secret**

| Secret name | Value |
|---|---|
| `SAST_SIGNING_KEY` | Contents of `keys/sast/private.hex` |
| `SCA_SIGNING_KEY` | Contents of `keys/sca/private.hex` |
| `CONFIG_SIGNING_KEY` | Contents of `keys/config/private.hex` |
| `SECRET_SCANNING_SIGNING_KEY` | Contents of `keys/secret/private.hex` |
| `SAST_PUBLIC_KEY` | Contents of `keys/sast/public.hex` |
| `SCA_PUBLIC_KEY` | Contents of `keys/sca/public.hex` |
| `CONFIG_PUBLIC_KEY` | Contents of `keys/config/public.hex` |
| `SECRET_SCANNING_PUBLIC_KEY` | Contents of `keys/secret/public.hex` |

Never commit any `private.hex` file. The `keys/` directory is already in `.gitignore`.

**3. Policy hash (keep in sync):**

The gate step pins the SHA-256 of `deploy.rego` via `--policy-hash`. If you
update the policy, recompute the hash and update the workflow:

```shell
go run ./cmd/gate policy-hash --policy policies/deploy.rego
```

Then update `--policy-hash` in `.github/workflows/devsecops-pipeline.yml`.

If the pipeline also passes `--data`, `--required-checks`,
`--fail-on-severity`, or `--zero-tolerance-checks` (a non-default policy
configuration), `--config-hash` must be pinned alongside `--policy-hash`;
compute it with `go run ./cmd/gate config-hash` using the same flags. The
bundled workflow uses the default configuration, so no `--config-hash` is
needed there.

**4. Production environment (optional):**

The `deploy-gate` job targets the `production` environment, which can be
configured to require manual approval before deployment. Set this up under
**Settings > Environments > production > Required reviewers**.

**Consuming this pipeline from another repository:** you do not need to
clone or build this repository to use its attestation pipeline. Reference
the composite actions directly (`actions/setup`, `actions/normalize-sign`,
`actions/gate`) from your own workflow; see
[`actions/README.md`](actions/README.md#consumer-workflow-example) for a
complete example workflow and the full input reference.

---

## Running Tests

### Unit tests

```shell
go test ./...
```

### With race detector

```shell
go test -race ./...
```

### Integration tests

```shell
go test -tags integration ./test/integration/...
```

Integration tests build the CLI binaries and run end-to-end pipeline scenarios
including tamper-detection attack simulations.

---

## Documentation

- [Architecture](docs/architecture.md) - system design, data flow, and cryptographic guarantees
- [Architecture diagram](docs/devsecops_attestation_architecture.svg) - visual overview
- [Integration Guide](docs/integration-guide.md) - consuming the pipeline from another repository
- [Severity Mapping](docs/severity-mapping.md) - how tool-native severities map to the canonical scale
- [Project Structure](docs/structure.md) - package layout, responsibilities, and key design decisions
- [Implementation Plan](docs/implementation-plan.md) - development phases and current status
- [PhD Extension Path](docs/phd-extension.md) - planned research extensions beyond the MSc scope
- [Related Work](docs/related-work.md) - prior art and relevant standards

---

## License

MIT - see [LICENSE](LICENSE)
