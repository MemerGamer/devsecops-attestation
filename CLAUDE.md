# CLAUDE.md
# DevSecOps Attestation - MSc Thesis Project
# Cryptographically Verifiable Security Decisions in CI/CD-based DevSecOps Pipelines
# Author: Kovács Bálint-Hunor, Sapientia EMTE

## Project Identity

This is an MSc thesis project. The crypto layer is designed as the foundation for a PhD
that will extend the system with distributed/network features. Implementation decisions
prioritize correctness and extensibility over convenience.

## Module

```
module github.com/MemerGamer/devsecops-attestation
go 1.26
```

## Build and Test Commands

```bash
# Build everything
go build ./...

# Run all unit tests
go test ./...

# Run unit tests with race detector
go test -race ./...

# Run integration tests (requires build tag)
go test -tags integration ./test/integration/...

# Run integration tests with race detector
go test -tags integration -race ./test/integration/...

# Run a specific package's tests verbosely
go test -v -count=1 ./internal/crypto/...

# Vet all packages
go vet ./...

# Build all CLI binaries
mkdir -p bin
go build -o ./bin/keygen ./cmd/keygen
go build -o ./bin/attest ./cmd/sign
go build -o ./bin/verify ./cmd/verify
go build -o ./bin/gate ./cmd/gate
```

## Commit Conventions

Use conventional commits. Prefix all commit messages with one of:

- `feat:` new functionality
- `fix:` bug fixes
- `test:` adding or fixing tests
- `docs:` documentation only
- `chore:` maintenance, dependencies, build
- `ci:` CI/CD workflow changes
- `refactor:` code restructuring without behavior change

## Style Rules

- No em dashes in code comments, documentation, or commit messages. Use a plain hyphen or rewrite the sentence.
- No emojis anywhere in the codebase.
- Professional academic tone in all comments and documentation.
- Error messages use lowercase, no trailing period.
- Use `fmt.Errorf("context: %w", err)` wrapping throughout.

## Phase Ownership

| Phase | Commit type | Scope | Status |
|-------|-------------|-------|--------|
| 0 | chore | scaffolding | MSc core |
| 1 | feat | Ed25519 + tests | MSc core |
| 2 | feat | chain + tests | MSc core |
| 3 | feat | CLI tools | MSc core |
| 4 | feat | OPA policy + tests | MSc core |
| 5 | ci | GitHub Actions | MSc core |
| 6 | feat | threshold multisig | MSc stretch / PhD seed |
| 7 | test | integration tests | MSc core |

## Architecture

The system works as follows:

1. Each CI step (SAST, SCA, config, secret scan) runs a security tool and writes a JSON result.
2. The `sign` binary wraps the result in a `types.Attestation`, signs it with Ed25519, links it
   to the previous attestation via SHA-256 digest, and appends it to `attestation-chain.json`.
3. The `gate evaluate` binary loads the chain, verifies all signatures and chain linkage via
   `attestation.VerifyChain`, then evaluates the chain against a Rego policy via OPA.
4. If the policy allows, deployment proceeds. If blocked, the pipeline fails with reasons.

## Package Structure

```
pkg/types/          -- core data structures (Attestation, SecurityResult, etc.)
internal/crypto/    -- Ed25519 sign, verify, digest
internal/attestation/ -- chain building (Chain.Add) and verification (VerifyChain)
internal/policy/    -- OPA integration (Evaluator, EvaluateFromFile)
internal/threshold/ -- threshold signing interfaces (MSc: simple multisig; PhD: FROST)
cmd/keygen/         -- CLI: generate Ed25519 key pair
cmd/sign/           -- CLI: sign a scan result and append to chain
cmd/verify/         -- CLI: verify chain integrity
cmd/gate/           -- CLI: evaluate chain against deploy gate policy
test/integration/   -- integration tests (build tag: integration)
.github/workflows/  -- GitHub Actions pipeline
.github/policies/   -- Rego policy files
```

## PhD Extension Points

The following are intentionally unimplemented and marked with `TODO(phd):` comments:

- `internal/threshold/threshold.go`: `GossipProtocol` interface -- network-level partial
  signature propagation, peer discovery, Byzantine fault detection.
- `ThresholdAttestation.CombinedSignature`: reserved for FROST group signature aggregation.

Phase 6 implements `SimpleParticipant` and `SimpleAggregator` (t independent Ed25519 signatures)
as the MSc contribution. FROST and network gossip are PhD territory.

## Key Design Decisions

- `canonicalPayload` (crypto package) excludes `Signature` and `SignerPublicKey` so these fields
  can be set after signing without invalidating the signature.
- `Digest` covers the full attestation including signature, making the chain link depend on
  the cryptographic proof as well as the payload.
- The OPA `Evaluator` only receives a chain that has already passed `VerifyChain`. The gate CLI
  must enforce this ordering -- policy evaluation on an unverified chain is a security defect.
- Before Phase 6: export `CanonicalPayload` (capital C) from `internal/crypto` so the threshold
  package can call it without replicating the canonical JSON logic.
