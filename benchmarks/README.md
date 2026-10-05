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
EFFICACY_CSV="$PWD/benchmarks/results/efficacy.csv" \
  go test -tags integration -run '^TestSecurityEfficacyMatrix$' -count=1 ./test/integration/ -v
```

Source: `test/integration/efficacy_test.go`. Without `EFFICACY_CSV`, the CSV is
written into `t.TempDir()` and removed after the test.

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

### Key and signature sizes (`results/key_sizes.csv`)

From the repository root, explicitly regenerate the archive:

```bash
KEY_SIZES_CSV="$PWD/benchmarks/results/key_sizes.csv" \
  go test ./internal/crypto -run '^TestEmitKeySizes$' -count=1 -v
```

Without `KEY_SIZES_CSV`, the CSV is written into `t.TempDir()` and removed after
the test. The columns remain `algorithm,sig_bytes,pubkey_bytes`; ECDSA DER
signature length can vary between runs. `-count=1` ensures regeneration runs
instead of reusing cached test results.

`aggregate.py` reads the archived CSVs by default. Set `KEY_SIZES_CSV` and/or
`EFFICACY_CSV` when aggregating retained CSVs from other paths. It does not
regenerate them. `run_local.sh` regenerates only `e2e_local.csv`; run the explicit
commands above to regenerate key sizes and efficacy before aggregation.

## Storage and policy size measurements

Run the two size benchmarks with allocation reporting:

```bash
go test ./internal/attestation ./internal/policy -run '^$' \
  -bench '^(BenchmarkStorageSizes|BenchmarkEvaluatePolicySize)$' \
  -benchmem -benchtime=100ms -count=1
```

`BenchmarkStorageSizes` emits `storage_sizes.csv` into a temporary directory by
default, removed at the end of the run. Set `STORAGE_SIZES_CSV` to retain it.
To deliberately write the archive path:

```bash
STORAGE_SIZES_CSV="$PWD/benchmarks/results/storage_sizes.csv" \
  go test ./internal/attestation -run '^$' -bench '^BenchmarkStorageSizes$' \
  -benchmem -benchtime=100ms -count=1
```

The CSV records N, standalone first-attestation bytes, linked-attestation bytes,
the sum of individual object sizes, compact chain-array bytes, and chain bytes
per attestation. N is 1, 4, 16, 64, 256, or 1024. Serialization includes the real
JSON fields, base64 signatures and public keys, signer ID, and log reference.
The fixture uses fixed-width UUID-shaped IDs and synthetic unique check names,
whole-second timestamps, fixed subject/commit strings, and no findings. It is a
valid signed and linked Ed25519 chain. Findings and optional-field content can
change real storage considerably; these numbers measure this fixture only.

Sizes are obtained from production `SaveChain` output followed by `json.Compact`,
with equality checked against `json.Marshal`. The timed loop measures compact
JSON serialization without signing, verification, file IO, or CSV writing.
Production `SaveChain` uses indented JSON, so its on-disk files are larger than
this requested compact representation. Single objects omit array delimiters;
chain size includes brackets, commas, and previous-digest linkage.

`BenchmarkEvaluatePolicySize` keeps the same four passing attestations fixed
across R = 1, 4, 16, 64, and 256. R=1 means the unchanged deploy.rego baseline;
each larger policy adds R-1 contradictory, non-matching `deny_reasons` rules.
The baseline already contains multiple rules, so `total_rules` reports actual
OPA AST rule count, including defaults. R is a baseline-plus-added-rules scale,
not a claim that deploy.rego has one rule. `TestPolicySizeEquivalent` checks rule
counts and allow/deny decisions with sorted reasons across multiple scenarios.

The benchmark calls the real `Evaluator.Evaluate`. That method converts input
and independently parses, compiles, and evaluates the allow and deny queries on
every call. Results therefore include compilation rather than isolating prepared
query execution. OPA may simplify/index the contradictory rules, so they measure
source growth without promising linear evaluation work. The existing
`BenchmarkEvaluate` remains unchanged. These short runs are functional checks,
not controlled measurements under the PhD repetition protocol.

Tests and benchmarks write size and efficacy CSVs into temporary directories
unless their output paths are explicitly configured. Plain `go test ./...`
leaves the archived results unchanged. Integration tests require the
`integration` build tag and are not included in the plain full-suite command.
