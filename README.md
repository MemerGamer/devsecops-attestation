# DevSecOps Attestation

![Go version](https://img.shields.io/badge/go-1.26-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
[![DevSecOps Attested Pipeline](https://github.com/MemerGamer/devsecops-attestation/actions/workflows/devsecops-pipeline.yml/badge.svg)](https://github.com/MemerGamer/devsecops-attestation/actions/workflows/devsecops-pipeline.yml)
[![codecov](https://codecov.io/gh/MemerGamer/devsecops-attestation/graph/badge.svg)](https://codecov.io/gh/MemerGamer/devsecops-attestation)

Cryptographically verifiable security decisions in CI/CD pipelines.

**MSc Thesis:** Cryptographically Verifiable Security Decisions in CI/CD-based DevSecOps Pipelines
**Author:** Kovács Bálint-Hunor — Sapientia EMTE, Marosvásárhelyi Kar

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

Sign all four checks using their respective keys:

```shell
REF=$(git rev-parse HEAD)
LOG_URL="https://github.com/org/repo/actions/runs/12345"

go run ./cmd/sign \
  --check-type sast --tool semgrep \
  --result results/sast.json \
  --target-ref "$REF" --subject myapp \
  --signing-key "$(cat keys/sast/private.hex)" \
  --signer-id "local:$(whoami)" \
  --log-entry "$LOG_URL" \
  --chain chain.json

go run ./cmd/sign \
  --check-type sca --tool trivy \
  --result results/sca.json \
  --target-ref "$REF" --subject myapp \
  --signing-key "$(cat keys/sca/private.hex)" \
  --signer-id "local:$(whoami)" \
  --log-entry "$LOG_URL" \
  --chain chain.json

go run ./cmd/sign \
  --check-type config --tool checkov \
  --result results/config.json \
  --target-ref "$REF" --subject myapp \
  --signing-key "$(cat keys/config/private.hex)" \
  --signer-id "local:$(whoami)" \
  --log-entry "$LOG_URL" \
  --chain chain.json

go run ./cmd/sign \
  --check-type secret --tool gitleaks \
  --result results/secret.json \
  --target-ref "$REF" --subject myapp \
  --signing-key "$(cat keys/secret/private.hex)" \
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
  --policy .github/policies/deploy.rego \
  --policy-hash "$(sha256sum .github/policies/deploy.rego | cut -d' ' -f1)" \
  --max-age 24h \
  --require-log-entries
```

Exit code 0 means the gate allows deployment. Exit code 1 means it was blocked
(chain invalid, policy denied, or a zero-trust check failed). The `--output`
flag writes the full decision JSON.

**Alternative: single shared key** (simpler, less isolation)

```shell
go run ./cmd/gate evaluate \
  --chain chain.json \
  --verify-signer "$(cat keys/shared/public.hex)"
```

---

## GitHub Actions Setup

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
sha256sum .github/policies/deploy.rego
```

Then update `--policy-hash` in `.github/workflows/devsecops-pipeline.yml`.

**4. Production environment (optional):**

The `deploy-gate` job targets the `production` environment, which can be
configured to require manual approval before deployment. Set this up under
**Settings > Environments > production > Required reviewers**.

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
- [Project Structure](docs/structure.md) - package layout, responsibilities, and key design decisions
- [Implementation Plan](docs/implementation-plan.md) - development phases and current status
- [PhD Extension Path](docs/phd-extension.md) - planned research extensions beyond the MSc scope
- [Related Work](docs/related-work.md) - prior art and relevant standards

---

## License

MIT - see [LICENSE](LICENSE)
