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
go run ./cmd/gate policy-hash --policy policies/deploy.rego
```

Paste the output hex into the `--policy-hash` argument in
`.github/workflows/devsecops-pipeline.yml`. A mismatch causes the gate to exit 1
before OPA loads the policy.

The policy file is read exactly once per `gate evaluate` invocation: the same
in-memory bytes are hashed and evaluated, so there is no window between the
hash check and policy evaluation in which the on-disk file could be swapped
(TOCTOU).

### Policy Configuration Integrity (Trust Boundary)

`--policy-hash` pins the policy's *logic* (the Rego source). It does not, by
itself, pin the policy's *parameters* (`data.config.required_checks`,
`data.config.fail_on_severity`, `data.config.zero_tolerance_checks`), which
can be supplied separately via `--data`, `--required-checks`,
`--fail-on-severity`, or `--zero-tolerance-checks`. `--config-hash` pins the
fully resolved configuration (defaults filled in explicitly) the same way
`--policy-hash` pins the file.

The gate enforces the boundary between the two: if `--policy-hash` is set and
the effective configuration is not the bundled policy's defaults, the gate
requires `--config-hash` too and exits 1 before evaluating anything if it is
missing. Pinning the policy's logic while leaving a non-default configuration
unpinned would let a change to the CI invocation (not the policy file itself)
silently change what the gate allows, without tripping `--policy-hash`.

```shell
go run ./cmd/gate config-hash \
  --required-checks sast,sca,config,secret \
  --fail-on-severity critical \
  --zero-tolerance-checks secret
```

The gate also fails closed on a malformed configuration itself: an
unrecognized `fail_on_severity`, or a `required_checks` /
`zero_tolerance_checks` value that is not a non-empty array of check-type
strings, is rejected by the CLI (for `--data` files) and denied by the
bundled policy (for any path that reaches OPA), rather than silently
disabling the check the parameter was meant to configure. A finding with an
unrecognized severity is treated the same way: it always blocks deployment
instead of being silently ignored.

### Signer-Side and Gate-Side Severity Thresholds

`attest`'s `--fail-on` (default `critical`) decides the `passed` field baked
into each signed attestation: "no finding at or above the signing threshold."
The gate's `fail_on_severity` (default `critical`, via `--fail-on-severity` or
`data.config.fail_on_severity`) is evaluated independently against the raw
findings, but the gate's `failed checks` deny reason also fires whenever any
attestation carries `passed == false`. In effect, the signer-side threshold
also blocks deployment through that rule. Operators must keep `--fail-on` on
the signing side and `--fail-on-severity` on the gate side set to the same
value; letting them drift means a finding can fail one threshold without
being caught by the other.

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
| Policy logic pinned but its parameters silently changed | `--config-hash` pins the effective `data.config`; required whenever `--policy-hash` is set and the configuration is not the bundled defaults |
| Malformed `data.config` (unrecognized severity, or a required/zero-tolerance value that is not a non-empty array of check types) | The gate CLI validates `--data` files before evaluation; the bundled policy's `config_valid` rule denies deployment for any malformed override that reaches OPA |
| Finding with an unrecognized severity (typo, unsupported scale, empty string) | The bundled policy always blocks deployment for such a finding instead of silently ignoring it |
