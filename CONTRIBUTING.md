# Contributing

## Prerequisites

- Go 1.26 or later
- `jq` (for local pipeline testing)

## Go toolchain pin

`go.mod` carries both a `go 1.26.0` directive (the minimum language version)
and a `toolchain go1.26.8` directive (the exact patch used to build signed
releases; see `.github/workflows/release-please.yml`). This keeps release
builds reproducible: the same toolchain is downloaded and checksum-verified
against sum.golang.org on every build, rather than drifting to whatever
`1.26.x` happens to be newest at release time.

It is not confirmed whether Dependabot's `gomod` updates bump the
`toolchain` line on its own (it manages `require` entries reliably; the
`toolchain` directive is not a dependency in the usual sense). Treat a Go
security release as a manual action item until this is verified: bump
`toolchain go1.26.x` in `go.mod` to the latest patch, run `go mod tidy`,
and open a `chore:` PR.

## Build

```shell
go build ./...

# Or build individual CLI binaries:
mkdir -p bin
go build -o ./bin/keygen ./cmd/keygen
go build -o ./bin/attest ./cmd/sign
go build -o ./bin/verify ./cmd/verify
go build -o ./bin/gate   ./cmd/gate
```

## Test

```shell
# Unit tests
go test ./...

# Unit tests with race detector
go test -race ./...

# Unit tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

# Integration tests (builds CLI binaries via os/exec)
go test -tags integration ./test/integration/...

# Vet all packages
go vet ./...
```

## Local Pipeline Walkthrough

Generate four key pairs (one per check type), sign some results, and evaluate
the gate locally:

```shell
mkdir -p keys
for check in sast sca config secret; do
  go run ./cmd/keygen --out "keys/$check"
done

REF=$(git rev-parse HEAD)
LOG_URL="https://example.com/local-run"

for check in sast sca config secret; do
  echo '{"passed":true,"findings":[]}' > /tmp/${check}-result.json
  go run ./cmd/sign \
    --check-type "$check" --tool "test-tool" \
    --result /tmp/${check}-result.json \
    --target-ref "$REF" --subject myapp \
    --signing-key "$(cat keys/$check/private.hex)" \
    --signer-id "local:$(whoami)" \
    --log-entry "$LOG_URL" \
    --chain /tmp/chain.json
done

go run ./cmd/gate evaluate \
  --chain /tmp/chain.json \
  --authorized-signers "sast=$(cat keys/sast/public.hex),sca=$(cat keys/sca/public.hex),config=$(cat keys/config/public.hex),secret=$(cat keys/secret/public.hex)" \
  --policy policies/deploy.rego \
  --policy-hash "$(sha256sum policies/deploy.rego | cut -d' ' -f1)" \
  --max-age 1h \
  --require-log-entries
```

## Updating the Deploy Policy

If you modify `policies/deploy.rego`, you must update the `--policy-hash`
value in `.github/workflows/devsecops-pipeline.yml`:

```shell
go run ./cmd/gate policy-hash --policy policies/deploy.rego
```

Paste the resulting hex string as the `--policy-hash` argument in the
`Evaluate deploy gate` step.

If the gate invocation also passes `--data`, `--required-checks`,
`--fail-on-severity`, or `--zero-tolerance-checks` (a non-default policy
configuration), `--config-hash` must be pinned alongside `--policy-hash`; see
[SECURITY.md](SECURITY.md#policy-configuration-integrity-trust-boundary) for
why. Compute it with `go run ./cmd/gate config-hash` using the same flags.

## Adding a Scanner Adapter

New tool integrations live in `pkg/normalize/`, one file per tool (e.g.
`semgrep.go`). Follow the steps documented in
[`pkg/normalize/doc.go`](pkg/normalize/doc.go):

1. Define an unexported type implementing the `Normalizer` interface
   (`Name`, `CheckType`, `Normalize`).
2. Map the tool's native severity vocabulary onto the canonical `Severity`
   scale (`info < low < medium < high < critical`). Follow the table in
   [`docs/severity-mapping.md`](docs/severity-mapping.md) rather than
   inventing a new mapping, and update that document (and the mirrored
   summary in `pkg/normalize/severity.go`) when you add a tool.
3. Register the adapter with `Register` in an `init()` function so it is
   available via `Get` and `Names` (and therefore `attest tools`) as soon as
   the package is imported.
4. Require a schema marker unique to the tool's native report format and
   reject input that lacks it. An adapter must fail closed on unrecognized
   input rather than silently returning zero findings; see the "Schema
   marker requirement" section of `docs/severity-mapping.md` for the
   rationale and existing examples.
5. Add fixture files under `pkg/normalize/testdata/<tool>/`: at minimum a
   clean report with no findings, a findings report exercising every
   severity the adapter maps, and a malformed report exercising the schema-
   marker rejection path. Add a corresponding `<tool>_test.go` exercising
   `Normalize` directly and through `Run`, including that `{}` and another
   tool's fixture are both rejected.
6. Match the project's overall coverage expectation (currently ~97%,
   see [Test Coverage](CLAUDE.md#test-coverage) in CLAUDE.md): a new
   adapter's happy path, severity mapping, schema-marker rejection, and (if
   applicable) `ToolPassNormalizer` combination logic should all be covered.

## Releasing

Releases are driven by [release-please](https://github.com/googleapis/release-please):
merging its release PR (generated automatically against `main` from
conventional commits) tags a release and triggers the `publish` job in
`.github/workflows/release-please.yml`, which runs GoReleaser to build the
per-OS/arch archives, checksums, SBOMs, and a signed OCI image
(`ghcr.io/memergamer/devsecops-attestation`, keyless-signed with cosign),
and uploads them to the GitHub release release-please already created.

To dry-run the release packaging locally without publishing or signing:

```shell
make snapshot
```

This runs `goreleaser release --snapshot --clean`, producing local archives
and images under `dist/` for inspection. Validate `.goreleaser.yaml` itself
with `goreleaser check`.

## Commit Conventions

This project uses [Conventional Commits](https://www.conventionalcommits.org/).
All commit messages must be prefixed with one of:

| Prefix | Use for |
|---|---|
| `feat:` | new functionality |
| `fix:` | bug fixes |
| `test:` | adding or fixing tests |
| `docs:` | documentation only |
| `chore:` | maintenance, dependencies, build |
| `ci:` | CI/CD workflow changes |
| `refactor:` | code restructuring without behavior change |

## Style Rules

- No em dashes in comments, documentation, or commit messages. Use a plain
  hyphen or rewrite the sentence.
- No emojis anywhere in the codebase.
- Professional academic tone in all comments and documentation.
- Error messages: lowercase, no trailing period.
- Use `fmt.Errorf("context: %w", err)` for error wrapping throughout.

## Branch Policy

- `main` is the primary branch. All PRs target `main`.
- The `production` GitHub environment on `deploy-gate` requires manual
  approval before deployment proceeds.

## PhD Extension Points

Interfaces marked `TODO(phd):` in `internal/threshold/threshold.go` are
intentionally unimplemented. The `GossipProtocol` interface and FROST
threshold scheme are reserved for PhD-phase research. Do not implement
them as part of MSc contributions.
