# DevSecOps Attestation

![Go version](https://img.shields.io/badge/go-1.26-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen)

Cryptographically verifiable security decisions in CI/CD pipelines.

**MSc Thesis:** Cryptographically Verifiable Security Decisions in CI/CD-based DevSecOps Pipelines
**Author:** Kovacs Balint-Hunor — Sapientia EMTE, Marosvásárhelyi Kar

---

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [GitHub Actions Setup](#github-actions-setup)
- [Running Tests](#running-tests)
- [Documentation](#documentation)
- [License](#license)

---

## Overview

Each security check in the CI/CD pipeline (SAST, SCA, config scan) produces an
Ed25519-signed JSON attestation. Attestations are linked into a chain: each one
includes the SHA-256 digest of the previous, making insertion, deletion, or
reordering detectable. A deployment gate loads the chain, verifies every signature
and the chain linkage, then evaluates the result against an OPA/Rego policy to
produce an ALLOW or BLOCK decision.

---

## Prerequisites

- Go 1.26 or later

---

## Quick Start

### Generate a key pair

```bash
go run ./cmd/keygen --out keys/
# Writes keys/private.hex and keys/public.hex
# Store private.hex in GitHub Actions secrets as ATTESTATION_SIGNING_KEY
```

### Sign security results

The default policy requires three checks: `sast`, `sca`, and `config`. Create a result
file for each and sign them all into the chain before evaluating the gate.

Each result file must be a JSON object with the following shape:

```json
{ "passed": true, "findings": [] }
```

Findings (optional) have the shape:

```json
{ "id": "CWE-89", "severity": "critical", "title": "SQL injection", "location": "src/db.go:42" }
```

Sign all three checks:

```bash
go run ./cmd/sign \
  --check-type sast \
  --tool semgrep \
  --result results/sast.json \
  --target-ref $(git rev-parse HEAD) \
  --subject myapp \
  --signing-key $(cat keys/private.hex) \
  --chain chain.json

go run ./cmd/sign \
  --check-type sca \
  --tool trivy \
  --result results/sca.json \
  --target-ref $(git rev-parse HEAD) \
  --subject myapp \
  --signing-key $(cat keys/private.hex) \
  --chain chain.json

go run ./cmd/sign \
  --check-type config \
  --tool checkov \
  --result results/config.json \
  --target-ref $(git rev-parse HEAD) \
  --subject myapp \
  --signing-key $(cat keys/private.hex) \
  --chain chain.json
```

### Verify and evaluate the gate

```bash
go run ./cmd/gate evaluate \
  --chain chain.json \
  --verify-signer $(cat keys/public.hex) \
  --policy .github/policies/deploy.rego
```

Exit code 0 means the gate allows deployment. Exit code 1 means it was blocked
(chain invalid or policy denied). The `--output` flag writes the full decision JSON.

---

## GitHub Actions Setup

The pipeline requires two repository secrets. Without them, the signing step will fail
with "signing key must be 64 bytes (128 hex chars), got 0 bytes".

**1. Generate a key pair locally:**

```bash
go run ./cmd/keygen --out keys/
```

**2. Add the secrets to your repository:**

Go to your repository on GitHub: **Settings > Secrets and variables > Actions > New repository secret**

| Secret name | Value |
| --- | --- |
| `ATTESTATION_SIGNING_KEY` | Contents of `keys/private.hex` |
| `ATTESTATION_PUBLIC_KEY` | Contents of `keys/public.hex` |

Keep `keys/private.hex` secret and never commit it. The `keys/` directory is already
in `.gitignore`.

**3. Production environment (optional):**

The `deploy-gate` job targets the `production` environment, which can be configured
to require manual approval before deployment. Set this up under
**Settings > Environments > production > Required reviewers**.

---

## Running Tests

### Unit tests

```bash
go test ./...
```

### With race detector

```bash
go test -race ./...
```

### Integration tests

```bash
go test -tags integration ./test/integration/...
```

Integration tests build the CLI binaries and run end-to-end pipeline scenarios
including tamper-detection attack simulations.

---

## Documentation

- [Architecture](docs/architecture.md) - system design, data flow diagram, and cryptographic guarantees
- [Project Structure](docs/structure.md) - package layout, responsibilities, and key design decisions
- [Implementation Plan](docs/implementation-plan.md) - development phases and current status
- [PhD Extension Path](docs/phd-extension.md) - planned research extensions beyond the MSc scope
- [Related Work](docs/related-work.md) - prior art and relevant standards

---

## License

MIT - see [LICENSE](LICENSE)
