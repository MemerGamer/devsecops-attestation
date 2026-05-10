# Security Policy

## Supported Versions

This is an MSc thesis research prototype. The current development version
on the `main` branch is the only supported version.

## Reporting a Vulnerability

To report a security vulnerability, please open a GitHub issue with the
title prefixed `[SECURITY]`. For sensitive disclosures, contact the author
directly via the email listed on their GitHub profile.

Please include:

- A description of the vulnerability
- Steps to reproduce
- Potential impact

You can expect an acknowledgement within 48 hours and a resolution timeline
within 7 days for confirmed vulnerabilities.

## Key Material

Never commit private key material. The `keys/` directory and all `*.hex`
files are listed in `.gitignore` for this reason. If key material is
accidentally committed, rotate the affected key pair immediately and treat
the old private key as compromised.

### Per-Check-Type Key Pairs

The pipeline uses four independent Ed25519 key pairs, one per check type:

| Secret name | Used by |
|---|---|
| `SAST_SIGNING_KEY` | SAST (semgrep) sign step |
| `SCA_SIGNING_KEY` | SCA (trivy) sign step |
| `CONFIG_SIGNING_KEY` | Config (checkov) sign step |
| `SECRET_SCANNING_SIGNING_KEY` | Secret scan (gitleaks) sign step |
| `SAST_PUBLIC_KEY` | Gate `--authorized-signers` |
| `SCA_PUBLIC_KEY` | Gate `--authorized-signers` |
| `CONFIG_PUBLIC_KEY` | Gate `--authorized-signers` |
| `SECRET_SCANNING_PUBLIC_KEY` | Gate `--authorized-signers` |

A compromise of one private key affects only that check type. Rotate the
affected key pair without changing the others:

1. Generate a new key pair: `go run ./cmd/keygen --out keys/new/`
2. Update the two affected GitHub Actions secrets (signing key and public key).
3. The gate's `--authorized-signers` reads the public key secret at runtime,
   so no code change is needed.

### Policy File Integrity

The gate pins the SHA-256 of `deploy.rego` via `--policy-hash`. If you update
the policy, recompute the hash and update the workflow before merging:

```shell
sha256sum .github/policies/deploy.rego
```

Paste the output hex into the `--policy-hash` argument in
`.github/workflows/devsecops-pipeline.yml`. A mismatch causes the gate to exit 1
before OPA loads the policy.

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| Forged attestation for a check type | Per-check-type keys; gate rejects any attestation not signed by the authorized key for that check type |
| Injected or modified `SignerID` | `SignerID` is in the canonical payload; changing it after signing invalidates the Ed25519 signature |
| Replay of a stale chain from a previous run | `--max-age 24h` on the gate; timestamps are monotonic and verified |
| Future-dated attestation | `VerifyChainWithOptions` rejects timestamps beyond `now + 60s` clock skew |
| Insertion, deletion, or reordering of attestations | SHA-256 chain linkage; any modification breaks the digest at that position |
| Substituted Rego policy at evaluation time | `--policy-hash` pins the expected SHA-256; a modified policy file is rejected |
| Missing transparency log reference | `--require-log-entries` causes the gate to reject any attestation without a `log_entry` |
| Duplicate check types (e.g. two SAST steps) | `VerifyChainWithOptions` rejects chains with duplicate check types |
