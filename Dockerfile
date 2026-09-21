# Dockerfile - multi-stage build for the devsecops-attestation CLI suite
# (keygen, attest, verify, gate).
#
# Base images are pinned by digest so the build is reproducible and not
# subject to upstream tag mutation. Refresh the digests deliberately (for
# example with `docker buildx imagetools inspect <image>:<tag>`) rather than
# letting them drift silently.
#
# Usage:
#   docker build --build-arg VERSION=$(git describe --tags --always --dirty) -t devsecops-attestation .
#   docker run --rm -v "$PWD:/work" devsecops-attestation gate evaluate --chain /work/attestation-chain.json ...
#   docker run --rm -v "$PWD:/work" devsecops-attestation attest tools
#   docker run --rm -v "$PWD:/work" devsecops-attestation keygen --out /work/keys
#   docker run --rm -v "$PWD:/work" devsecops-attestation verify --chain /work/attestation-chain.json

# golang:1.26-alpine, resolved 2026-09-21 via `docker pull golang:1.26-alpine`
# followed by `docker inspect --format='{{index .RepoDigests 0}}'`.
FROM golang:1.26-alpine@sha256:51a7c389a5ddaf82f527191a1e9bff9928655130a44e4975dd1d7e0acf59f1ae AS build

ARG VERSION=dev

WORKDIR /src

# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=0

RUN mkdir -p /out && \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/keygen ./cmd/keygen && \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/attest ./cmd/sign && \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/verify ./cmd/verify && \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/gate ./cmd/gate

# gcr.io/distroless/static-debian12:nonroot, resolved 2026-09-21 via
# `docker pull gcr.io/distroless/static-debian12:nonroot` followed by
# `docker inspect --format='{{index .RepoDigests 0}}'`.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS runtime

ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/MemerGamer/devsecops-attestation" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.title="devsecops-attestation" \
      org.opencontainers.image.description="Cryptographically verifiable security decisions for CI/CD-based DevSecOps pipelines (keygen, attest, verify, gate)."

COPY --from=build /out/keygen /usr/local/bin/keygen
COPY --from=build /out/attest /usr/local/bin/attest
COPY --from=build /out/verify /usr/local/bin/verify
COPY --from=build /out/gate /usr/local/bin/gate
COPY policies/deploy.rego /policies/deploy.rego

WORKDIR /work

USER nonroot

# No fixed entrypoint binary: the image bundles four CLIs and the caller
# picks one, e.g.
#   docker run --rm -v "$PWD:/work" IMAGE gate evaluate --chain /work/attestation-chain.json ...
# The distroless static base sets PATH to include /usr/local/bin, so the
# binaries resolve by name without needing the absolute path.
ENTRYPOINT []
CMD ["attest", "tools"]
