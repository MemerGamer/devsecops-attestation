# Severity mapping

This document is the canonical reference for how `pkg/normalize` adapters
translate a security tool's native severity vocabulary into the package's
canonical `Severity` scale (`info < low < medium < high < critical`). The
mapping is also mirrored, in condensed form, in the doc comment above the
`Severity` type in `pkg/normalize/severity.go`; keep both in sync.

Adapter authors implementing a new tool integration in `pkg/normalize`
should follow this table rather than inventing a new mapping, so that
findings from different tools remain comparable once normalized.

| Tool | Native value | Canonical severity |
|------|---------------|---------------------|
| semgrep | `ERROR` | high |
| semgrep | `WARNING` | medium |
| semgrep | `INFO` | low |
| semgrep | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` (case-insensitive) | as reported, via `ParseSeverity` |
| trivy | its own severity field, used directly | as reported |
| trivy | `UNKNOWN` | low |
| checkov | a failed check with no severity reported by the tool | medium |
| checkov | a failed check with a severity reported by the tool | as reported, via `ParseSeverity` |
| gitleaks | any finding | critical |
| cargo-audit | a vulnerability with a CVSS score | `FromCVSS(score)` |
| cargo-audit | a vulnerability without a CVSS score | high |
| cargo-audit | an informational warning (unmaintained, yanked) | low |
| cargo-audit | an informational warning (unsound) | medium |
| sobelow | confidence `High` | high |
| sobelow | confidence `Medium` | medium |
| sobelow | confidence `Low` | low |
| mix_audit | an advisory with a CVSS score | `FromCVSS(score)` |
| mix_audit | an advisory without a CVSS score but with a reported severity string | as reported, via `ParseSeverity` |
| mix_audit | an advisory with neither a CVSS score nor a reported severity | high |
| generic adapter | already-canonical severity string | passthrough, re-validated (and rewritten to canonical lowercase) with `ParseSeverity` |

## Rationale

- Secret leaks (gitleaks) are always treated as critical regardless of any
  severity the tool itself might report, because a committed secret is a
  hard failure condition independent of the tool's own risk scoring.
- When a tool provides a CVSS base score, `FromCVSS` is preferred over a
  fixed mapping because it captures the actual severity gradient rather
  than collapsing all vulnerabilities from a tool into a single bucket.
- When a tool reports a boolean pass/fail per check with no finer-grained
  severity (e.g. checkov's failed checks with no severity field), the
  finding maps to medium: severe enough to be actionable, but not assumed
  to be as severe as a scored vulnerability or a leaked secret.
- cargo-audit's `unsound` warnings (a soundness hole, e.g. unsafe code with
  no safety validation) map to medium rather than low: unlike an
  unmaintained or yanked crate, an unsound crate is a concrete defect in the
  crate itself, not just a supply-chain staleness signal.
- mix_audit does not guarantee every advisory carries a CVSS vector.
  `mixAuditSeverity` therefore falls back in order: a CVSS vector (via
  `FromCVSS`), then a reported severity string (via `ParseSeverity`), and
  only maps to high when an advisory supplies neither.
- semgrep's legacy three-level vocabulary (`ERROR`/`WARNING`/`INFO`) keeps
  its historical mapping rather than being routed through `ParseSeverity`,
  because `error` alone would otherwise parse to high (see the synonym
  table below) which happens to match, but `warning` would parse to medium
  (correct) while `info` has no synonym entry at all and would be rejected.
  Current semgrep releases can also emit the canonical five-level
  vocabulary directly (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) for some rule
  sources; these are recognized as a fallback through `ParseSeverity`,
  case-insensitively.

## Schema-marker requirement (fail-closed on unrecognized input)

Every adapter requires at least one field or value that only the real
tool's native report format carries, and rejects the input with an error
when that marker is absent, rather than silently returning zero findings.
A report that "normalizes" to zero findings is otherwise indistinguishable
from a genuinely clean scan, which would let a misconfigured pipeline (or
another tool's raw output accidentally fed to the wrong `--tool-format`)
pass undetected instead of failing the signing step.

| Tool | Required marker |
|------|------------------|
| trivy | `SchemaVersion == 2` |
| semgrep | top-level `results` key present; an `errors` entry at `level: "error"` (or with no `level` at all, treated as blocking to stay fail-closed) is rejected as an incomplete scan, but a `level: "warn"`/`"warning"` entry (e.g. a single-file `PartialParsing`/syntax-error notice, `{"code":3,"level":"warn","type":"Syntax error",...}`) does not block, since it means one target was degraded, not that the run failed |
| sobelow | non-empty `sobelow_version` |
| mix_audit | top-level `pass` key present |
| cargo-audit | top-level `database` and `lockfile` keys present; `vulnerabilities.count` must match `len(vulnerabilities.list)`, and a positive count with an empty list is rejected |
| checkov | the bare empty-scan summary object must carry `checkov_version` or `resource_count`; a `summary.parsing_errors` count greater than zero is rejected as an incomplete scan (for both the empty-scan and per-framework report shapes) unless that framework's `resource_count`, `passed` and `failed` are all zero, in which case the parsing errors are ignored: this is the real-world `terraform_plan`-style case where a framework attempts to parse files that turn out not to belong to it (e.g. arbitrary `.json` files) and contributes nothing either way, so a parsing error there cannot be hiding a real finding. Any framework that scanned resources or reported checks still fails on parsing errors. |
| gitleaks | a zero-byte or whitespace-only report file is rejected: a genuine clean gitleaks scan always writes at least `[]`, so an empty file means the scanner crashed or was killed before writing its report |

## Tool-reported pass state

A minority of tools report their own pass/fail verdict independently of the
translated findings list (mix_audit's top-level `pass` boolean; a canonical
generic report's own `passed` field). These adapters implement the optional
`ToolPassNormalizer` interface, and `Run` combines that verdict with its own
threshold-based verdict via logical AND: the run passes only when both
agree. This closes a gap where, for example, a canonical report with
`"passed": false` and no findings above the caller's `--fail-on` threshold
would otherwise be silently upgraded to an overall pass.

## Canonical severity scale

Defined in `pkg/normalize/severity.go` as `Severity`, ordered from least to
most severe:

```
info < low < medium < high < critical
```

`ParseSeverity` additionally recognizes these synonyms, case-insensitively:

- `moderate` -> medium
- `warning` -> medium
- `error` -> high
- `unknown` -> low
- `informational` -> info

`FromCVSS` maps a CVSS v3 base score using the standard qualitative rating
scale:

```
0.0        -> info
0.1 - 3.9  -> low
4.0 - 6.9  -> medium
7.0 - 8.9  -> high
9.0 - 10.0 -> critical
```

## --fail-on default

Both `attest sign --fail-on` (used with `--tool-format`) and
`attest normalize --fail-on` default to `high`, matching the gate's
default `--fail-on-severity`. `Passed` means "no finding at or above this
threshold"; the threshold is inclusive, so `--fail-on critical` only fails a
run on a critical finding, while `--fail-on high` fails on both high and
critical findings. The signer-side and gate-side thresholds are independent
checks (the signer decides what gets signed as `passed: true`; the gate
independently decides what it allows to deploy), so a signer that defaults
to a laxer threshold than the gate would make the signer-side pass
determination misleading even though the gate still catches it. Keeping the
two defaults aligned avoids that mismatch; operators who intentionally want
a stricter signer-side threshold can still pass `--fail-on high` (or lower)
explicitly.
