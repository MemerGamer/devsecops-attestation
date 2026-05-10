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
| 8 | feat | zero-trust hardening | MSc core |

## Architecture

The system works as follows:

1. Each CI step (SAST, SCA, config, secret scan) runs a security tool and writes a JSON result.
2. The `sign` binary wraps the result in a `types.Attestation`, sets `SignerID` and `LogEntry`,
   signs the canonical payload with the check-type-specific Ed25519 key, links it to the previous
   attestation via SHA-256 digest, and appends it to `attestation-chain.json`.
3. The `gate evaluate` binary runs a layered verification sequence before OPA evaluation:
   a. `VerifyChainWithOptions` -- signatures, chain linkage, subject consistency, timestamp
      ordering, max-age, no duplicate check types.
   b. Signer authorization -- per-check-type (`--authorized-signers`) or shared key (`--verify-signer`).
   c. Log entry enforcement -- `--require-log-entries` rejects attestations without a `LogEntry`.
   d. Policy hash check -- `--policy-hash` pins the SHA-256 of the Rego file before OPA loads it.
   e. OPA policy evaluation -- the verified, authorized chain is evaluated against Rego.
4. If the policy allows, deployment proceeds. If blocked, the pipeline fails with reasons.

## Package Structure

```
pkg/types/          -- core data structures (Attestation, SecurityResult, PolicyInput, etc.)
internal/crypto/    -- Ed25519 sign, verify, digest, CanonicalPayload
internal/attestation/ -- chain building (Chain.Add, SetNextSignerID, SetNextLogEntry)
                         and verification (VerifyChain, VerifyChainWithOptions)
internal/policy/    -- OPA integration (Evaluator, EvaluateFromFile, DefaultPolicy)
internal/threshold/ -- threshold signing interfaces (MSc: simple multisig; PhD: FROST)
cmd/keygen/         -- CLI: generate Ed25519 key pair
cmd/sign/           -- CLI: sign a scan result and append to chain
cmd/verify/         -- CLI: verify chain integrity
cmd/gate/           -- CLI: verify chain, authorize signers, enforce log entries,
                         check policy hash, evaluate OPA policy
test/integration/   -- integration tests (build tag: integration)
.github/workflows/  -- GitHub Actions pipeline
.github/policies/   -- Rego policy files
```

## PhD Extension Points

The following are intentionally unimplemented and marked with `TODO(phd):` comments:

- `internal/threshold/threshold.go`: `GossipProtocol` interface -- network-level partial
  signature propagation, peer discovery, Byzantine fault detection.
- `ThresholdAttestation.CombinedSignature`: reserved for FROST group signature aggregation.
- `LogEntry` plumbing exists; actual submission to Rekor/Sigstore and inclusion proof
  verification at the gate are PhD-phase extensions.

Phase 6 implements `SimpleParticipant` and `SimpleAggregator` (t independent Ed25519 signatures)
as the MSc contribution. FROST and network gossip are PhD territory.

## Key Design Decisions

- `canonicalPayload` (crypto package) excludes `Signature` and `SignerPublicKey` so these fields
  can be set after signing without invalidating the signature. `SignerID` is included so signer
  identity is cryptographically bound. `LogEntry` is excluded because it is a post-signing
  reference, not part of the security proof.
- `Digest` covers the full attestation including signature, making the chain link depend on
  the cryptographic proof as well as the payload.
- The OPA `Evaluator` only receives a chain that has already passed `VerifyChainWithOptions` and
  signer authorization. The gate CLI must enforce this ordering -- policy evaluation on an
  unverified or unauthorized chain is a security defect.
- `CanonicalPayload` (capital C) is exported from `internal/crypto` so the threshold package
  can call it without replicating the canonical JSON logic.
- `toMap` in `internal/policy` injects `signer_public_key_hex` into each attestation map before
  passing input to OPA. JSON encodes `[]byte` as base64 but policy authors use hex strings.
- `Chain.SetNextSignerID` and `Chain.SetNextLogEntry` use a one-shot pattern: the value is
  consumed and reset to "" by the next `Chain.Add` call.
- The gate accepts either `--verify-signer` (single shared key) or `--authorized-signers`
  (per-check-type map). Neither can be omitted. The Go-level check runs before OPA.

## Test Coverage

Current total coverage is approximately 93%. The remaining uncovered statements (~7%) are all
justified unreachable defensive error paths:

| Pattern | Location | Why unreachable |
|---------|----------|-----------------|
| `main()` bodies | all 4 CLIs | Process entry points - only testable via subprocess |
| `ed25519.GenerateKey` error | `internal/crypto` `GenerateKeyPair` | Never fails with `crypto/rand.Reader` on any supported OS |
| `json.Marshal` / `json.MarshalIndent` errors | `chain_io`, `crypto.Digest`, `cmd/gate`, `cmd/verify` | All marshaled types are concrete structs with no custom marshaler that can fail |
| `canonicalPayload` errors | `crypto.Sign`, `crypto.Verify`, `threshold.Sign`, `threshold.VerifyThreshold` | Same reason - marshaling always succeeds |
| `crypto.Digest`/`crypto.Sign` errors | `attestation.Add`, `attestation.VerifyChain` | Calls with concrete `*types.Attestation` values which always marshal |
| `crypto.KeyPairFromBytes` error | `cmd/sign` `runSign` | Caller always passes exactly 32 + 64 validated bytes |
| `denyQuery.Eval` error | `internal/policy` `Evaluate` | Both queries compile the same module; if one fails both fail - the second never runs independently |

To add coverage for a new feature, write tests before or alongside the implementation. For CLI
commands, test both the `runX()` function directly (fast, isolated) and via `rootCmd.Execute()`
(covers cobra RunE lambda, serves as a light integration test).
