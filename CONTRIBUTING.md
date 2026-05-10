# Contributing

## Prerequisites

- Go 1.26 or later
- `jq` (for local pipeline testing)

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
  --policy .github/policies/deploy.rego \
  --policy-hash "$(sha256sum .github/policies/deploy.rego | cut -d' ' -f1)" \
  --max-age 1h \
  --require-log-entries
```

## Updating the Deploy Policy

If you modify `.github/policies/deploy.rego`, you must update the `--policy-hash`
value in `.github/workflows/devsecops-pipeline.yml`:

```shell
sha256sum .github/policies/deploy.rego
```

Paste the resulting hex string as the `--policy-hash` argument in the
`Evaluate deploy gate` step.

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
