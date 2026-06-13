#!/usr/bin/env python3
"""
aggregate.py — Parse benchmark result files and emit pgfplots .dat files + summary.
stdlib only: no pandas/numpy.
All output values derive from input files.
"""

import csv
import math
import os
import re
import shutil
import statistics

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
THESIS_DATA_DIR = os.path.join(
    os.path.dirname(__file__),
    "..",
    "..",
    "..",
    "Documents",
    "Msc - Docs",
    "Diplomatervek_MSc",
    "images",
    "data",
)

# Resolve relative to this script's location
_script_dir = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(_script_dir, "results")
THESIS_DATA_DIR = os.path.join(
    os.path.expanduser("~"), "Documents", "Msc - Docs", "Diplomatervek_MSc", "images", "data"
)
THESIS_DATA_DIR = os.path.normpath(THESIS_DATA_DIR)


def median(values):
    s = sorted(values)
    n = len(s)
    if n == 0:
        return float("nan")
    mid = n // 2
    if n % 2 == 1:
        return s[mid]
    return (s[mid - 1] + s[mid]) / 2.0


def stddev_population(values):
    """Population standard deviation."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return math.sqrt(sum((x - mean) ** 2 for x in values) / n)


def stddev_sample(values):
    """Sample standard deviation (Bessel-corrected)."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return math.sqrt(sum((x - mean) ** 2 for x in values) / (n - 1))


def mean(values):
    if not values:
        return float("nan")
    return sum(values) / len(values)


def sig3(x):
    """Format to 3 significant figures."""
    if x == 0:
        return "0"
    if math.isnan(x):
        return "nan"
    mag = math.floor(math.log10(abs(x)))
    factor = 10 ** (2 - mag)
    rounded = round(x * factor) / factor
    # Determine decimal places needed
    decimals = max(0, 2 - mag)
    return f"{rounded:.{decimals}f}"


# ---------------------------------------------------------------------------
# 1. Parse go-bench.txt
# ---------------------------------------------------------------------------

def parse_go_bench(path):
    """
    Returns dict: benchmark_name -> list of ns_op floats.
    Strips -16 (GOMAXPROCS) suffix. Sub-benchmarks keep /N<number>.
    """
    pattern = re.compile(
        r'^(Benchmark\S+?)-\d+\s+\d+\s+([\d.]+)\s+ns/op'
    )
    data = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            m = pattern.match(line)
            if m:
                name = m.group(1)
                ns_op = float(m.group(2))
                data.setdefault(name, []).append(ns_op)
    return data


# ---------------------------------------------------------------------------
# 2. Parse key_sizes.csv
# ---------------------------------------------------------------------------

def parse_key_sizes(path):
    result = {}
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            result[row["algorithm"]] = {
                "sig_bytes": int(row["sig_bytes"]),
                "pubkey_bytes": int(row["pubkey_bytes"]),
            }
    return result


# ---------------------------------------------------------------------------
# 3. Parse e2e_local.csv
# ---------------------------------------------------------------------------

def parse_e2e_local(path):
    """Returns dict: stage -> list of duration_ms floats."""
    data = {}
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            stage = row["stage"].strip()
            dur = float(row["duration_ms"])
            data.setdefault(stage, []).append(dur)
    return data


# ---------------------------------------------------------------------------
# 4. Parse ci_runs.csv
# ---------------------------------------------------------------------------

def parse_ci_runs(path):
    """
    Returns:
      per_repo_job: dict (repo, job) -> list of duration_s (excluding skipped=-1)
      per_run: dict (repo, run_id) -> list of duration_s for that run
    """
    per_repo_job = {}
    per_run = {}
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            repo = row["repo"].strip()
            run_id = row["run_id"].strip()
            job = row["job"].strip()
            dur = float(row["duration_s"])
            if dur < 0:
                # skipped jobs (duration_s == -1) — exclude from averages
                continue
            key = (repo, job)
            per_repo_job.setdefault(key, []).append(dur)
            run_key = (repo, run_id)
            per_run.setdefault(run_key, []).append(dur)
    return per_repo_job, per_run


# ---------------------------------------------------------------------------
# 5. Parse efficacy.csv
# ---------------------------------------------------------------------------

def parse_efficacy(path):
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# WRITE HELPERS
# ---------------------------------------------------------------------------

def write_dat(path, header_comment, col_headers, rows):
    """Write a space-separated .dat file with a leading comment."""
    with open(path, "w") as f:
        f.write(f"# {header_comment}\n")
        f.write(" ".join(col_headers) + "\n")
        for row in rows:
            f.write(" ".join(str(v) for v in row) + "\n")
    print(f"  Written: {path}")


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():
    os.makedirs(THESIS_DATA_DIR, exist_ok=True)

    # ---- Load inputs ----
    bench_data = parse_go_bench(os.path.join(RESULTS_DIR, "go-bench.txt"))
    key_sizes = parse_key_sizes(os.path.join(RESULTS_DIR, "key_sizes.csv"))
    e2e_data = parse_e2e_local(os.path.join(RESULTS_DIR, "e2e_local.csv"))
    per_repo_job, per_run = parse_ci_runs(os.path.join(RESULTS_DIR, "ci_runs.csv"))
    efficacy_rows = parse_efficacy(os.path.join(RESULTS_DIR, "efficacy.csv"))

    # ---- Aggregated Go benchmark stats ----
    bench_stats = {}
    for name, values in bench_data.items():
        bench_stats[name] = {
            "median_ns": median(values),
            "stddev_ns": stddev_population(values),
            "n": len(values),
        }

    # ---- 1. crypto_ops.dat ----
    # Rows: Ed25519, ECDSA-P256, RSA-2048
    # Columns: idx algo sign_us verify_us keygen_us
    algo_map = [
        ("Ed25519",    "BenchmarkSign_Ed25519",    "BenchmarkVerify_Ed25519",    "BenchmarkKeygen_Ed25519"),
        ("ECDSA-P256", "BenchmarkSign_ECDSAP256",  "BenchmarkVerify_ECDSAP256",  "BenchmarkKeygen_ECDSAP256"),
        ("RSA-2048",   "BenchmarkSign_RSA2048",    "BenchmarkVerify_RSA2048",    "BenchmarkKeygen_RSA2048"),
    ]

    crypto_rows = []
    crypto_stats_for_summary = {}
    for idx, (algo, sign_key, verify_key, keygen_key) in enumerate(algo_map, 1):
        sign_ns = bench_stats[sign_key]["median_ns"]
        verify_ns = bench_stats[verify_key]["median_ns"]
        keygen_ns = bench_stats[keygen_key]["median_ns"]
        sign_us = sign_ns / 1000.0
        verify_us = verify_ns / 1000.0
        keygen_us = keygen_ns / 1000.0
        crypto_rows.append([
            idx,
            algo,
            sig3(sign_us),
            sig3(verify_us),
            sig3(keygen_us),
        ])
        crypto_stats_for_summary[algo] = {
            "sign_ns": sign_ns,
            "verify_ns": verify_ns,
            "keygen_ns": keygen_ns,
            "sign_us": sign_us,
            "verify_us": verify_us,
            "keygen_us": keygen_us,
            "sign_stddev_ns": bench_stats[sign_key]["stddev_ns"],
            "verify_stddev_ns": bench_stats[verify_key]["stddev_ns"],
            "keygen_stddev_ns": bench_stats[keygen_key]["stddev_ns"],
        }

    write_dat(
        os.path.join(RESULTS_DIR, "crypto_ops.dat"),
        "Crypto primitive latency (median of 10 runs). sign_us/verify_us/keygen_us in microseconds (3 sig figs).",
        ["idx", "algo", "sign_us", "verify_us", "keygen_us"],
        crypto_rows,
    )

    # ---- 2. chain_scaling.dat ----
    # BenchmarkVerifyChain/N1, N4, N16, N64, N256, N1024
    chain_ns = [1, 4, 16, 64, 256, 1024]
    chain_rows = []
    chain_stats_for_summary = {}
    for N in chain_ns:
        key = f"BenchmarkVerifyChain/N{N}"
        stats = bench_stats.get(key, {})
        ns = stats.get("median_ns", float("nan"))
        sd = stats.get("stddev_ns", float("nan"))
        us = ns / 1000.0
        chain_rows.append([N, sig3(ns), sig3(us), sig3(sd)])
        chain_stats_for_summary[N] = {"median_ns": ns, "stddev_ns": sd, "us_per_op": us}

    write_dat(
        os.path.join(RESULTS_DIR, "chain_scaling.dat"),
        "VerifyChain scaling: median ns/op and stddev (population) across 10 runs.",
        ["N", "ns_per_op", "us_per_op", "stddev_ns"],
        chain_rows,
    )

    # ---- 3. opa_scaling.dat ----
    # BenchmarkEvaluate/N1, N4, N16, N64, N256, N1024
    opa_ns_list = [1, 4, 16, 64, 256, 1024]
    opa_rows = []
    opa_stats_for_summary = {}
    for N in opa_ns_list:
        key = f"BenchmarkEvaluate/N{N}"
        stats = bench_stats.get(key, {})
        ns = stats.get("median_ns", float("nan"))
        sd = stats.get("stddev_ns", float("nan"))
        ms = ns / 1_000_000.0
        opa_rows.append([N, sig3(ns), sig3(ms), sig3(sd)])
        opa_stats_for_summary[N] = {"median_ns": ns, "stddev_ns": sd, "ms_per_op": ms}

    write_dat(
        os.path.join(RESULTS_DIR, "opa_scaling.dat"),
        "OPA Evaluate scaling: median ns/op and stddev (population) across 10 runs.",
        ["N", "ns_per_op", "ms_per_op", "stddev_ns"],
        opa_rows,
    )

    # ---- 4. e2e_stages.dat ----
    stage_order = ["sign_sast", "sign_sca", "sign_config", "sign_secret", "verify", "gate_evaluate"]
    e2e_agg = {}
    for stage in stage_order:
        vals = e2e_data.get(stage, [])
        m = mean(vals)
        # sample stddev (n-1) — stated in summary
        sd = stddev_sample(vals)
        e2e_agg[stage] = {"mean_ms": m, "std_ms": sd, "n": len(vals)}

    e2e_rows = []
    for idx, stage in enumerate(stage_order, 1):
        agg = e2e_agg[stage]
        e2e_rows.append([idx, stage, f"{agg['mean_ms']:.4f}", f"{agg['std_ms']:.4f}"])

    write_dat(
        os.path.join(RESULTS_DIR, "e2e_stages.dat"),
        "End-to-end local stage latency. mean_ms and std_ms (sample stddev, n-1) over 30 repetitions.",
        ["idx", "stage", "mean_ms", "std_ms"],
        e2e_rows,
    )

    # ---- 5. ci_jobs.dat ----
    # Collect all repos and jobs
    repos = sorted(set(k[0] for k in per_repo_job.keys()))
    jobs_all = sorted(set(k[1] for k in per_repo_job.keys()))

    # Short names for repos
    repo_short = {}
    for r in repos:
        short = r.split("/")[-1]
        # Phoenix -> phoenix, Rust -> rust
        if "Phoenix" in short:
            repo_short[r] = "phoenix"
        elif "Rust" in short:
            repo_short[r] = "rust"
        else:
            repo_short[r] = short.lower()

    # Shorten job names: keep parenthetical tool name to distinguish variants
    # e.g. "SAST (Sobelow)" -> "SAST_Sobelow", "SCA (mix audit)" -> "SCA_mix_audit"
    def shorten_job(job):
        m = re.match(r'^(.*?)\s*\(([^)]+)\)\s*$', job)
        if m:
            base = m.group(1).strip()
            tool = re.sub(r'\s+', '_', m.group(2).strip())
            return f"{base}_{tool}"
        return job.strip()

    jobs_short = {j: shorten_job(j) for j in jobs_all}

    # Build per-run summed job seconds per repo
    per_repo_run_sums = {}
    for (repo, run_id), durations in per_run.items():
        per_repo_run_sums.setdefault(repo, []).append(sum(durations))

    ci_jobs_rows = []
    for idx, job in enumerate(jobs_all, 1):
        row = [idx, f'"{jobs_short[job]}"']
        for r in ["MemerGamer/Phoenix-DevSecOps-Demo", "MemerGamer/Rust-DevSecOps-Demo"]:
            vals = per_repo_job.get((r, job), [])
            if vals:
                row.append(f"{mean(vals):.1f}")
            else:
                row.append("-")
        ci_jobs_rows.append(row)

    write_dat(
        os.path.join(RESULTS_DIR, "ci_jobs.dat"),
        "CI job mean duration (seconds) per repo. '-' = job absent in that repo. Values exclude skipped runs (duration_s=-1).",
        ["idx", "job", "phoenix_s", "rust_s"],
        ci_jobs_rows,
    )

    # ---- CI per-repo summed job-seconds ----
    ci_repo_summary = {}
    for r in repos:
        run_sums = per_repo_run_sums.get(r, [])
        ci_repo_summary[r] = {
            "mean_summed_job_s": mean(run_sums),
            "n_runs": len(run_sums),
        }

    # ---- Efficacy ----
    total_tests = len(efficacy_rows)
    detected_yes = sum(1 for row in efficacy_rows if row["detected"].strip().lower() == "yes")
    detected_no = total_tests - detected_yes

    # ---- Write summary.txt ----
    summary_lines = []
    summary_lines.append("=" * 70)
    summary_lines.append("BENCHMARK AGGREGATE SUMMARY")
    summary_lines.append(f"Generated from: {RESULTS_DIR}")
    summary_lines.append("=" * 70)
    summary_lines.append("")

    summary_lines.append("--- CRYPTO PRIMITIVE LATENCY (median over 10 runs, population stddev) ---")
    summary_lines.append(f"{'Algo':<14} {'Sign(ns)':>12} {'Sign(µs)':>10} {'±stddev(ns)':>12} "
                         f"{'Verify(ns)':>12} {'Verify(µs)':>11} {'±stddev(ns)':>12} "
                         f"{'Keygen(ns)':>12} {'Keygen(µs)':>11} {'±stddev(ns)':>12}")
    summary_lines.append("-" * 120)
    for algo, s in crypto_stats_for_summary.items():
        summary_lines.append(
            f"{algo:<14} {s['sign_ns']:>12.1f} {s['sign_us']:>10.3f} {s['sign_stddev_ns']:>12.1f} "
            f"{s['verify_ns']:>12.1f} {s['verify_us']:>11.3f} {s['verify_stddev_ns']:>12.1f} "
            f"{s['keygen_ns']:>12.1f} {s['keygen_us']:>11.3f} {s['keygen_stddev_ns']:>12.1f}"
        )
    summary_lines.append("")

    summary_lines.append("--- VERIFY CHAIN SCALING (median ns/op, population stddev, 10 runs) ---")
    summary_lines.append(f"{'N':>6} {'median_ns':>12} {'us_per_op':>12} {'stddev_ns':>12}")
    summary_lines.append("-" * 44)
    for N, s in chain_stats_for_summary.items():
        summary_lines.append(f"{N:>6} {s['median_ns']:>12.1f} {s['us_per_op']:>12.3f} {s['stddev_ns']:>12.1f}")
    summary_lines.append("")

    summary_lines.append("--- OPA EVALUATE SCALING (median ns/op, population stddev, 10 runs) ---")
    summary_lines.append(f"{'N':>6} {'median_ns':>12} {'ms_per_op':>12} {'stddev_ns':>12}")
    summary_lines.append("-" * 44)
    for N, s in opa_stats_for_summary.items():
        summary_lines.append(f"{N:>6} {s['median_ns']:>12.1f} {s['ms_per_op']:>12.4f} {s['stddev_ns']:>12.1f}")
    summary_lines.append("")

    summary_lines.append("--- E2E LOCAL STAGE LATENCY (sample stddev n-1, 30 repetitions) ---")
    summary_lines.append(f"{'Stage':<18} {'mean_ms':>10} {'std_ms':>10} {'n':>5}")
    summary_lines.append("-" * 45)
    for stage in stage_order:
        agg = e2e_agg[stage]
        summary_lines.append(f"{stage:<18} {agg['mean_ms']:>10.4f} {agg['std_ms']:>10.4f} {agg['n']:>5}")
    summary_lines.append("")

    summary_lines.append("--- CI JOB MEAN DURATIONS (seconds, skipped jobs excluded) ---")
    summary_lines.append(f"{'Job':<30} {'Phoenix':>10} {'Rust':>10}")
    summary_lines.append("-" * 52)
    for job in jobs_all:
        ph = per_repo_job.get(("MemerGamer/Phoenix-DevSecOps-Demo", job), [])
        ru = per_repo_job.get(("MemerGamer/Rust-DevSecOps-Demo", job), [])
        ph_str = f"{mean(ph):.1f}" if ph else "-"
        ru_str = f"{mean(ru):.1f}" if ru else "-"
        summary_lines.append(f"{job:<30} {ph_str:>10} {ru_str:>10}")
    summary_lines.append("")

    summary_lines.append("--- CI PER-REPO SUMMED JOB-SECONDS (mean across runs) ---")
    summary_lines.append("  Note: jobs run partly in parallel; this is 'summed job-seconds', not wall-clock.")
    for r in repos:
        s = ci_repo_summary[r]
        summary_lines.append(f"  {r}: mean={s['mean_summed_job_s']:.1f}s over {s['n_runs']} run(s)")
    summary_lines.append("")

    summary_lines.append("--- EFFICACY (tamper detection) ---")
    summary_lines.append(f"  Total attack scenarios tested: {total_tests}")
    summary_lines.append(f"  Detected (yes):                {detected_yes}")
    summary_lines.append(f"  Not detected (no):             {detected_no}")
    summary_lines.append(f"  Detection rate:                {100.0*detected_yes/total_tests:.1f}%")
    summary_lines.append("")

    summary_lines.append("--- KEY SIZES ---")
    for algo, ks in key_sizes.items():
        summary_lines.append(f"  {algo}: sig={ks['sig_bytes']} bytes, pubkey={ks['pubkey_bytes']} bytes")
    summary_lines.append("")

    summary_txt = "\n".join(summary_lines)

    summary_path = os.path.join(RESULTS_DIR, "summary.txt")
    with open(summary_path, "w") as f:
        f.write(summary_txt)
    print(f"  Written: {summary_path}")

    # ---- Write summary.csv ----
    csv_rows = [("metric", "value")]

    for algo, s in crypto_stats_for_summary.items():
        tag = algo.replace("-", "_").replace(" ", "_")
        csv_rows.append((f"{tag}_sign_median_ns", f"{s['sign_ns']:.2f}"))
        csv_rows.append((f"{tag}_sign_median_us", f"{s['sign_us']:.4f}"))
        csv_rows.append((f"{tag}_sign_stddev_ns", f"{s['sign_stddev_ns']:.2f}"))
        csv_rows.append((f"{tag}_verify_median_ns", f"{s['verify_ns']:.2f}"))
        csv_rows.append((f"{tag}_verify_median_us", f"{s['verify_us']:.4f}"))
        csv_rows.append((f"{tag}_verify_stddev_ns", f"{s['verify_stddev_ns']:.2f}"))
        csv_rows.append((f"{tag}_keygen_median_ns", f"{s['keygen_ns']:.2f}"))
        csv_rows.append((f"{tag}_keygen_median_us", f"{s['keygen_us']:.4f}"))
        csv_rows.append((f"{tag}_keygen_stddev_ns", f"{s['keygen_stddev_ns']:.2f}"))

    for N, s in chain_stats_for_summary.items():
        csv_rows.append((f"chain_N{N}_median_ns", f"{s['median_ns']:.2f}"))
        csv_rows.append((f"chain_N{N}_us_per_op", f"{s['us_per_op']:.4f}"))
        csv_rows.append((f"chain_N{N}_stddev_ns", f"{s['stddev_ns']:.2f}"))

    for N, s in opa_stats_for_summary.items():
        csv_rows.append((f"opa_N{N}_median_ns", f"{s['median_ns']:.2f}"))
        csv_rows.append((f"opa_N{N}_ms_per_op", f"{s['ms_per_op']:.6f}"))
        csv_rows.append((f"opa_N{N}_stddev_ns", f"{s['stddev_ns']:.2f}"))

    for stage in stage_order:
        agg = e2e_agg[stage]
        csv_rows.append((f"e2e_{stage}_mean_ms", f"{agg['mean_ms']:.4f}"))
        csv_rows.append((f"e2e_{stage}_std_ms", f"{agg['std_ms']:.4f}"))
        csv_rows.append((f"e2e_{stage}_n", str(agg["n"])))

    for job in jobs_all:
        ph = per_repo_job.get(("MemerGamer/Phoenix-DevSecOps-Demo", job), [])
        ru = per_repo_job.get(("MemerGamer/Rust-DevSecOps-Demo", job), [])
        tag = re.sub(r'[^a-zA-Z0-9]', '_', job).lower().strip('_')
        if ph:
            csv_rows.append((f"ci_phoenix_{tag}_mean_s", f"{mean(ph):.2f}"))
        if ru:
            csv_rows.append((f"ci_rust_{tag}_mean_s", f"{mean(ru):.2f}"))

    for r in repos:
        s = ci_repo_summary[r]
        tag = repo_short[r]
        csv_rows.append((f"ci_{tag}_summed_job_s_mean", f"{s['mean_summed_job_s']:.2f}"))
        csv_rows.append((f"ci_{tag}_n_runs", str(s["n_runs"])))

    csv_rows.append(("efficacy_total_tests", str(total_tests)))
    csv_rows.append(("efficacy_detected_yes", str(detected_yes)))
    csv_rows.append(("efficacy_detected_no", str(detected_no)))
    csv_rows.append(("efficacy_detection_rate_pct", f"{100.0*detected_yes/total_tests:.1f}"))

    for algo, ks in key_sizes.items():
        tag = algo.replace("-", "_").replace(" ", "_")
        csv_rows.append((f"keysize_{tag}_sig_bytes", str(ks["sig_bytes"])))
        csv_rows.append((f"keysize_{tag}_pubkey_bytes", str(ks["pubkey_bytes"])))

    summary_csv_path = os.path.join(RESULTS_DIR, "summary.csv")
    with open(summary_csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        for row in csv_rows:
            writer.writerow(row)
    print(f"  Written: {summary_csv_path}")

    # ---- Copy .dat files + efficacy.csv to thesis images/data/ ----
    dat_files = [
        "crypto_ops.dat",
        "chain_scaling.dat",
        "opa_scaling.dat",
        "e2e_stages.dat",
        "ci_jobs.dat",
    ]
    extra_files = ["efficacy.csv"]

    print(f"\nCopying files to thesis data dir: {THESIS_DATA_DIR}")
    os.makedirs(THESIS_DATA_DIR, exist_ok=True)
    for fname in dat_files + extra_files:
        src = os.path.join(RESULTS_DIR, fname)
        dst = os.path.join(THESIS_DATA_DIR, fname)
        shutil.copy2(src, dst)
        print(f"  Copied: {fname} -> {dst}")

    print("\nDone.")
    print("\n" + summary_txt)


if __name__ == "__main__":
    main()
