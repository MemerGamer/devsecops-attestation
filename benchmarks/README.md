# Benchmarks

Measurement artefacts for the MSc thesis evaluation (Chapter 5).

## Machine Specification

| Property       | Value                                    |
|----------------|------------------------------------------|
| CPU            | AMD Ryzen 7 5800X 8-Core Processor       |
| Logical CPUs   | 16                                       |
| RAM            | 31 GiB                                   |
| Kernel         | Linux 7.0.11-zen1-1-zen                  |
| Go version     | go1.26.4 linux/amd64                     |
| Measurement date | 2026-06-13                             |

## Results Files

| File | Description |
|------|-------------|
| `results/e2e_local.csv` | Per-stage wall-clock times for 30 repetitions of the full sign→verify→gate pipeline. Columns: `stage`, `rep`, `duration_ms`. Stages: `sign_sast`, `sign_sca`, `sign_config`, `sign_secret`, `verify`, `gate_evaluate`. |
| `results/efficacy.csv` | Security efficacy matrix: one row per attack vector. Columns: `attack_vector`, `simulated`, `detected`, `mechanism`. |
| `results/ci_runs.csv` | Per-job durations harvested from GitHub Actions for `MemerGamer/Phoenix-DevSecOps-Demo` and `MemerGamer/Rust-DevSecOps-Demo`. Columns: `repo`, `run_id`, `conclusion`, `job`, `duration_s`. Requires `gh` CLI authenticated. |
| `results/go-bench.txt` | Raw output of `go test -bench=.` micro-benchmarks (Ed25519, chain scaling, OPA). |
| `results/key_sizes.csv` | Key and signature sizes for Ed25519, ECDSA P-256, RSA-2048, RSA-3072. |

## Reproducing Each Artefact

### Security efficacy matrix (`results/efficacy.csv`)

```bash
cd /path/to/devsecops-attestation
export PATH=/home/hunor/.local/go/bin:$PATH
go test -tags integration -run TestSecurityEfficacyMatrix ./test/integration/ -v
```

Source: `test/integration/efficacy_test.go`

### Local e2e timing harness (`results/e2e_local.csv`)

```bash
cd /path/to/devsecops-attestation
bash benchmarks/run_local.sh
# Override repetitions: R=50 bash benchmarks/run_local.sh
```

Builds `keygen`, `attest`, `verify`, `gate` binaries into `./bin/`, generates a key pair,
runs sign×4 → verify → gate_evaluate for R=30 repetitions, and writes one row per stage per rep.

### CI run harvest (`results/ci_runs.csv`)

```bash
cd /path/to/devsecops-attestation
gh auth login   # one-time setup
bash benchmarks/harvest_ci.sh
```

Requires the `gh` CLI to be installed and authenticated.
Fetches the last 20 GitHub Actions runs for each demo repository and extracts
per-job startedAt/completedAt durations.

### Go micro-benchmarks (`results/go-bench.txt`)

```bash
cd /path/to/devsecops-attestation
export PATH=/home/hunor/.local/go/bin:$PATH
go test -bench=. -benchmem -count=5 ./internal/... ./pkg/... | tee benchmarks/results/go-bench.txt
```
