#!/usr/bin/env python3
import sys
import subprocess
import json
import csv
import statistics

def run_dnspyre(server, duration, concurrency):
    cmd = [
        "dnspyre",
        "--duration", duration,
        "-c", concurrency,
        "--server", server,
        "--json",
        "https://raw.githubusercontent.com/zer0h/top-1000000-domains/refs/heads/master/top-10000-domains"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("dnspyre failed:")
        print(result.stderr)
        sys.exit(1)
    return json.loads(result.stdout)

def extract_principal_fields(data):
    out = {}
    out['totalRequests'] = data.get('totalRequests', 0)
    out['queriesPerSecond'] = data.get('queriesPerSecond', 0.0)

    latency = data.get('latencyStats', {})
    out['latency_mean_ms'] = latency.get('meanMs', 0.0)
    out['latency_p99_ms']  = latency.get('p99Ms', 0.0)
    out['latency_p95_ms']  = latency.get('p95Ms', 0.0)
    out['latency_p90_ms']  = latency.get('p90Ms', 0.0)
    out['latency_p75_ms']  = latency.get('p75Ms', 0.0)
    out['latency_p50_ms']  = latency.get('p50Ms', 0.0)
    return out

def main():
    if len(sys.argv) < 6:
        print(f"Usage: {sys.argv[0]} output.csv num_runs server duration concurrency")
        sys.exit(1)

    output_csv = sys.argv[1]
    num_runs = int(sys.argv[2])
    server = sys.argv[3]
    duration = sys.argv[4]
    concurrency = sys.argv[5]

    results = []
    print("Starting tests...")
    for run in range(1, num_runs + 1):
        print(f"  Run {run} of {num_runs}...")
        data = run_dnspyre(server, duration,  str(256))
        data = run_dnspyre(server, duration, concurrency)
        extracted = extract_principal_fields(data)
        results.append(extracted)

    # Compute mean and std for each field
    metrics = results[0].keys()
    summary_rows = []
    for metric in metrics:
        values = [r[metric] for r in results]
        mean_val = statistics.mean(values)
        std_val = statistics.stdev(values) if len(values) > 1 else 0.0
        summary_rows.append({
            "metric": metric,
            "mean": mean_val,
            "std": std_val
        })

    # Write summary to CSV
    with open(output_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["metric", "mean", "std"])
        writer.writeheader()
        writer.writerows(summary_rows)

    print(f"Summary (mean, std) written to {output_csv}")

if __name__ == "__main__":
    main()
