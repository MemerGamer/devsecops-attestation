# Makefile - build, test, lint, and packaging helpers for
# devsecops-attestation.
#
# MSc thesis project (Kovács Bálint-Hunor, Sapientia EMTE). See CLAUDE.md
# for the full project context and phase ownership.

MODULE      := github.com/MemerGamer/devsecops-attestation
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X main.version=$(VERSION)
BIN_DIR     := ./bin
DOCKER_IMAGE := devsecops-attestation:dev

.PHONY: all build test test-integration cover lint docker policy-hash snapshot clean

all: build

## build: compile keygen, attest, verify, gate into ./bin with the current VERSION.
build:
	mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/keygen ./cmd/keygen
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/attest ./cmd/sign
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/verify ./cmd/verify
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/gate ./cmd/gate

## test: run unit tests with the race detector.
test:
	go test -race ./...

## test-integration: run integration tests (build tag: integration).
test-integration:
	go test -tags integration -race ./test/integration/...

## cover: generate a coverage profile and print the total coverage.
cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

## lint: gofmt, go vet, and govulncheck/golangci-lint when installed.
lint:
	@echo "==> gofmt"
	@fmt_out="$$(gofmt -l .)"; \
	if [ -n "$$fmt_out" ]; then \
		echo "gofmt: the following files are not formatted:"; \
		echo "$$fmt_out"; \
		exit 1; \
	fi
	@echo "==> go vet"
	go vet ./...
	@echo "==> govulncheck"
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not installed, skipping"; \
	fi
	@echo "==> golangci-lint"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed, skipping"; \
	fi

## docker: build the local development image.
docker:
	docker build --build-arg VERSION=$(VERSION) -t $(DOCKER_IMAGE) .

## policy-hash: print the SHA-256 hex hash of the bundled default policy.
policy-hash:
	go run ./cmd/gate policy-hash

## snapshot: build a local, unpublished release with goreleaser.
snapshot:
	goreleaser release --snapshot --clean

## clean: remove build, release, and coverage artifacts.
clean:
	rm -rf $(BIN_DIR) dist coverage.out
