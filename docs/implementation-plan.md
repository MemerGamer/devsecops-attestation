# Implementation Plan

## Phase 1 — Sign + Verify (MSc core)
- [x] `internal/crypto/signer.go` — Ed25519 sign, verify, digest
- [x] `cmd/sign` — CLI wrapper
- [x] `cmd/keygen` — key generation utility
- [x] Unit tests: tamper detection, key mismatch

## Phase 2 — Attestation Chains (MSc core)
- [x] `internal/attestation/chain.go` — chain building + verification
- [x] `cmd/verify` — CLI chain verifier
- [x] `cmd/gate` — deployment gate with OPA policy evaluation
- [x] Unit tests: all tamper attack vectors covered
- [x] Integration tests: full pipeline to chain to gate
- [ ] Transparency log submission (Rekor)

## Phase 3 — Threshold Signatures (MSc stretch / PhD seed)
- [x] `internal/threshold/threshold.go` — interfaces and types
- [x] Simple t-of-n: collect t independent Ed25519 signatures (`internal/threshold/multisig.go`)
- [ ] FROST threshold scheme (proper single group signature)
- [ ] PhD: distribute over network with `GossipProtocol`
