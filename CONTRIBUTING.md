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

## Commit Conventions

This project uses [Conventional Commits](https://www.conventionalcommits.org/).
All commit messages must be prefixed with one of:

| Prefix | Use for |
| --- | --- |
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
