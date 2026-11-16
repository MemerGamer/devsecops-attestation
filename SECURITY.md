# Security Policy

## Supported Versions

This is an MSc thesis research prototype. The current development version
on the `main` branch is the only supported version.

## Reporting a Vulnerability

To report a security vulnerability, please open a Forgejo issue with the
title prefixed `[SECURITY]`. For sensitive disclosures, contact the author
directly via the email listed on their profile.

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
2. Update the two affected Forgejo Actions secrets (TEST keys only) (signing key and public key).
3. The gate's `--authorized-signers` reads the public key secret at runtime,
   so no code change is needed.

### Policy File Integrity

The gate pins the SHA-256 of `deploy.rego` via `--policy-hash`. If you update
the policy, recompute the hash and update the workflow before merging:

```shell
go run ./cmd/gate policy-hash --policy policies/deploy.rego
```

Paste the output hex into the `--policy-hash` argument in
`.forgejo/workflows/devsecops-pipeline.yml`. A mismatch causes the gate to exit 1
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

`attest`'s `--fail-on` (default `high`) decides the `passed` field baked
into each signed attestation: "no finding at or above the signing threshold."
The gate's `fail_on_severity` (default `high`, via `--fail-on-severity` or
`data.config.fail_on_severity`) is evaluated independently against the raw
findings, but the gate's `failed checks` deny reason also fires whenever any
attestation carries `passed == false`. In effect, the signer-side threshold
also blocks deployment through that rule. Operators must keep `--fail-on` on
the signing side and `--fail-on-severity` on the gate side set to the same
value; letting them drift means a finding can fail one threshold without
being caught by the other.

### Transparency Log Entry Semantics (Non-Authenticated Reference)

`--require-log-entries` checks presence only: it rejects an attestation
whose `log_entry` field is empty, and nothing more. It does not verify that
the referenced entry exists, that it actually corresponds to this
attestation, or that it has not been altered or removed since the
attestation was signed. `LogEntry` is intentionally excluded from the
canonical payload (see "Key Design Decisions" below), so it carries no
cryptographic binding to the attestation at all; an attacker who can modify
a stored chain after signing can rewrite `log_entry` to point anywhere
without invalidating the Ed25519 signature. Today `log_entry` is populated
with the GitHub Actions run URL, a human-auditable reference an operator
can follow up on manually, not a machine-verified proof.

Turning this into an actual guarantee requires submitting each attestation
to a transparency log (Rekor/Sigstore) at signing time and verifying its
inclusion proof at the gate - both are PhD-phase extensions (see
`docs/phd-extension.md` and the `TODO(phd):` markers in
`internal/attestation`); `--require-log-entries` alone provides no
tamper-evidence for the referenced entry itself.

`SignerID` is different: it is included in the canonical payload and
therefore covered by the Ed25519 signature (see "Injected or modified
`SignerID`" in the threat table below), so it cannot be altered after
signing without invalidating the signature. But the bundled policy does not
read or constrain `SignerID` at all - policy-level signer authorization is
enforced entirely through the signing key (`--verify-signer` /
`--authorized-signers` / `signer_public_key_hex`), not through the
human-readable `SignerID` string. `SignerID` is authentic but not itself
policy-checked; treat it as an audit trail, not an authorization mechanism.

### Signing Job: Secret Exposure

`.forgejo/workflows/devsecops-pipeline.yml`'s `sign` job (DG-8 design A)
holds the four per-check-type signing keys. On Forgejo these are the
`TEST_*` keys only; no production key exists on Forgejo and the workflow
references none. `sign` runs on `push` to `main`, on `workflow_dispatch`
and on a `pull_request` whose head repository is this repository, and never
for the Dependabot or Renovate actors. Forgejo withholds secrets from fork
pull requests (which also need the owner's approval to run) and from AGit
pull requests, so `sign` fails closed there. The job fetches the exact
source commit without credentials, installs a checksum-pinned Go, verifies
modules and runs only run steps and this commit's local composite actions.
Scanner reports reach it through the F1 transport (bounded gzip/base64 job
outputs with per-file SHA-256 digests and a chunk manifest), which `sign`
verifies before signing. `publish` holds no signing secrets.

These guards live in the workflow file and are only as trustworthy as its
protection: the Forgejo branch protection on `main` (required checks, no
direct pushes) and review of changes under `.forgejo/workflows/`. A chain
signed on Forgejo is TEST-signed CI evidence; `verify: OK` or an
`allow: true` decision from this workflow is not release authorization.

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| Forged attestation for a check type | Per-check-type keys; gate rejects any attestation not signed by the authorized key for that check type |
| Injected or modified `SignerID` | `SignerID` is in the canonical payload; changing it after signing invalidates the Ed25519 signature |
| Replay of a stale chain from a previous run | `--max-age 24h` on the gate; timestamps are monotonic and verified |
| Replay of a verified, internally-consistent chain produced against a different commit or artifact digest than the one about to be deployed | `VerifyChainWithOptions` rejects a chain whose attestations disagree with each other on `result.target_ref`; `gate evaluate --target-ref <ref>` additionally binds the whole chain to the caller's expected commit, enforced in Go before policy evaluation |
| Future-dated attestation | `VerifyChainWithOptions` rejects timestamps beyond `now + 60s` clock skew |
| Insertion, deletion, or reordering of attestations in the interior of the chain | SHA-256 chain linkage; any modification breaks the digest at that position |
| Truncation of one or more attestations from the tail of an otherwise verified chain (chain linkage alone does not protect a suffix: dropping the last entries leaves the remaining links internally consistent) | The bundled policy seals the chain against the declared `required_checks` set: any attestation whose `check_type` is not in `required_checks` is denied outright as an "undeclared check type" the moment it appears, and dropping a declared check type from the tail is caught as "missing required checks". Residual risk: a check type an operator never adds to `required_checks` carries no seal at all - a chain that never ran it is indistinguishable from one that had it truncated, so every check type the policy is meant to enforce must be declared in `required_checks` |
| Substituted Rego policy at evaluation time | `--policy-hash` pins the expected SHA-256; a modified policy file is rejected |
| Missing transparency log reference | `--require-log-entries` causes the gate to reject any attestation without a `log_entry`. Presence only: this does not verify the referenced entry's existence or integrity - see "Transparency Log Entry Semantics" above |
| Duplicate check types (e.g. two SAST steps) | `VerifyChainWithOptions` rejects chains with duplicate check types |
| Policy logic pinned but its parameters silently changed | `--config-hash` pins the effective `data.config`; required whenever `--policy-hash` is set and the configuration is not the bundled defaults |
| Malformed `data.config` (unrecognized severity, or a required/zero-tolerance value that is not a non-empty array of check types) | The gate CLI validates `--data` files before evaluation; the bundled policy's `config_valid` rule denies deployment for any malformed override that reaches OPA |
| Finding with an unrecognized severity (typo, unsupported scale, empty string) | The bundled policy always blocks deployment for such a finding instead of silently ignoring it |
| Forged or overwritten scanner report between the scan job and the signing job ("report substitution") | Each scanner job encodes its own output through the F1 transport (gzip/base64 job outputs with per-file SHA-256 digests and a chunk-length manifest); `sign` decodes and verifies digests and manifest before signing and fails closed on any mismatch; the scan step removes its own output file before the scanner runs so a stale file cannot be mistaken for this run's output; raw reports are also uploaded with `if-no-files-found: error` for diagnosis |
| Suppressed finding via an in-repo scanner configuration change (`.gitleaks.toml` allowlist, `.checkov.yaml` skip-check, `# nosemgrep`, `.semgrepignore`, `.trivyignore`) | Outside this tool's control at the crypto/policy layer: mitigated operationally via CODEOWNERS on those files, an out-of-band trusted config passed explicitly to the scanner, and required review on the signing environment; see `actions/README.md`'s "Scanner configuration trust" |
| Forked pull request or dependabot/renovate PR reaching the signing job and exfiltrating signing keys | `sign` runs only on `push` to `main`, `workflow_dispatch` and same-repository pull requests, never for Dependabot or Renovate; Forgejo withholds secrets from fork and AGit pull requests; Forgejo holds TEST keys only, so no production key is exposed (see "Signing Job" above) |

## Release key and distribution trust

G7 uses a separate, passphrase-protected Cosign key held only by Hunor on
pc with an offline backup. It never enters Forgejo, the runner or this
repository. This is independent of the TEST attestation keys above.
`actions/setup/release-keys/release-v1.pub` is currently **PLACEHOLDER**.
There is no production fingerprint yet. Hunor must replace it and record
SHA-256 of the real public-key file here, in the tooling PR and release
notes after the 0700-directory/0600-file ceremony in
[docs/releasing.md](docs/releasing.md). New signed release installs fail
closed until this is done.

For >=0.5.0, the pinned action maps versions to that fixed key file and
requires a verified public Rekor log entry bound to the signature and
manifest. It uses stable Cosign v3 >=3.0.2 through env -i, a fresh private
home and public TUF roots, with bypasses explicitly false. Caller root,
cache, proxy and COSIGN/SIGSTORE/TUF overrides are not inherited. The exact
ten-file tag-derived manifest inventory and archive checksum are required.
Legacy 0.4.0, 0.4.1 and 0.4.2 require their fixed GitHub workflow identity
and pinned manifest digests, even from an explicit mirror URL. Unsupported
old versions and deny-listed versions fail. Explicit verify-signature=false
skips signature and Rekor checks only, not version, inventory or checksum
rules. Failed release installs never switch source, hosts or versions.

Rotate a compromised key with a reviewed public-key/version mapping update,
an explicit revoked-version deny-list in release-policy.sh, a new setup
release and an advisory. Rekor integrated time is observable but is not a
revocation cutoff. Pre-release status alone does not revoke a version.
A stolen key can sign every non-legacy version, retroactively on either
host; consumers pinned to older action SHAs remain exposed until they
update to a pin carrying the deny-list and replacement key. pc also holds
the Forgejo SSH key and gh login, so pc compromise reaches all three.
The first key rotation should move custody to hardware.

Source mode is a separately selected trust path: version must equal source.
It trusts the action's own checkout, local changes, Go and module
dependencies, and provides no release-key, pinned legacy manifest or Rekor
guarantee. It works with default verification and needs Go instead of Cosign.
Pin and review the source/action SHA. This path is preserved for PR checks
and dogfooding; no release verification failure can select it.
