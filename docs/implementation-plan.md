# Implementation Plan

## Phase 1 -- Sign + Verify (MSc core)
- [x] `internal/crypto/signer.go` -- Ed25519 sign, verify, digest, `CanonicalPayload`
- [x] `cmd/sign` -- CLI wrapper with `--check-type`, `--tool`, `--signing-key`, `--signer-id`, `--log-entry`
- [x] `cmd/keygen` -- key generation utility
- [x] Unit tests: tamper detection, key mismatch, canonical payload determinism

## Phase 2 -- Attestation Chains (MSc core)
- [x] `internal/attestation/chain.go` -- chain building (`Chain.Add`, `SetNextSignerID`, `SetNextLogEntry`)
- [x] `internal/attestation/chain.go` -- `VerifyChainWithOptions` with max-age, clock skew, subject consistency, timestamp ordering, duplicate check type detection
- [x] `cmd/verify` -- CLI chain verifier
- [x] `cmd/gate` -- deployment gate with OPA policy evaluation
- [x] Unit tests: all tamper attack vectors, `VerifyChainWithOptions` options matrix
- [x] Integration tests: full pipeline to chain to gate

## Phase 3 -- Zero-Trust Hardening (MSc core)
- [x] Per-check-type Ed25519 key pairs -- each check type uses a dedicated signing key
- [x] `SignerID` in canonical payload -- signer identity is cryptographically bound
- [x] `LogEntry` plumbing -- transparency log reference attached after signing; enforced at gate with `--require-log-entries`
- [x] `--authorized-signers` on gate -- per-check-type Go-level key authorization before policy evaluation
- [x] `verifyAuthorizedSignersCoverage` -- rejects chains with unconfigured check types
- [x] `--policy-hash` on gate -- SHA-256 pin of Rego policy file; prevents policy substitution
- [x] `--max-age` on gate -- rejects chains containing attestations older than the limit
- [x] `deploy.rego` authorized_signers rules -- policy-level check mirrors the Go-level check
- [x] CI workflow updated -- per-check-type secrets, `--signer-id`, `--log-entry`, `--authorized-signers`, `--policy-hash`, `--max-age`, `--require-log-entries`

## Phase 4 -- Threshold Signatures (MSc stretch / PhD seed)
- [x] `internal/threshold/threshold.go` -- interfaces and types
- [x] Simple t-of-n: collect t independent Ed25519 signatures (`internal/threshold/multisig.go`)
- [x] `VerifyThreshold` -- verify t-of-n partial signatures, deduplicated and sorted by participant ID
- [ ] FROST threshold scheme (proper single group signature) -- PhD scope
- [ ] Distribute over network with `GossipProtocol` -- PhD scope

## Phase 5 -- External Transparency Log (PhD scope)
- [ ] Submit each attestation to Rekor/Sigstore on signing
- [ ] Store the returned inclusion proof URL in `LogEntry`
- [ ] Verify inclusion proof at the gate before policy evaluation
