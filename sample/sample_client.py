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
        "https://raw.githubusercontent.com/opendns/public-domain-lists/refs/heads/master/opendns-top-domains.txt"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("dnspyre failed:")
        print(result.stderr)
        sys.exit(1)
    return json.loads(result.stdout)

def extract_principal_fields(data):
    # Flatten and pick main fields
    out = {}
    out['totalRequests'] = data.get('totalRequests', 0)
    out['totalSuccessResponses'] = data.get('totalSuccessResponses', 0)
    out['totalNegativeResponses'] = data.get('totalNegativeResponses', 0)
    out['totalErrorResponses'] = data.get('totalErrorResponses', 0)
    out['totalIOErrors'] = data.get('totalIOErrors', 0)

    rcodes = data.get('responseRcodes', {})
    out['NOERROR'] = rcodes.get('NOERROR', 0)
    out['SERVFAIL'] = rcodes.get('SERVFAIL', 0)

    out['queriesPerSecond'] = data.get('queriesPerSecond', 0.0)
    out['benchmarkDurationSeconds'] = data.get('benchmarkDurationSeconds', 0.0)

    latency = data.get('latencyStats', {})
    out['latency_min_ms'] = latency.get('minMs', 0.0)
    out['latency_mean_ms'] = latency.get('meanMs', 0.0)
    out['latency_std_ms'] = latency.get('stdMs', 0.0)
    out['latency_max_ms'] = latency.get('maxMs', 0.0)
    out['latency_p99_ms'] = latency.get('p99Ms', 0.0)
    out['latency_p95_ms'] = latency.get('p95Ms', 0.0)
    out['latency_p90_ms'] = latency.get('p90Ms', 0.0)
    out['latency_p75_ms'] = latency.get('p75Ms', 0.0)
    out['latency_p50_ms'] = latency.get('p50Ms', 0.0)

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
    for run in range(1, num_runs + 1):
        print(f"Running test {run} of {num_runs}...")
        data = run_dnspyre(server, duration, concurrency)
        extracted = extract_principal_fields(data)
        extracted['run'] = run
        results.append(extracted)

    # Write raw results to CSV with 'run' as first column
    other_fields = [k for k in results[0].keys() if k != 'run']
    fieldnames = ['run'] + sorted(other_fields)

    with open(output_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"Raw test results saved to {output_csv}")

    # Optionally compute mean and std per column (excluding 'run')
    summary = {}
    numeric_fields = [f for f in fieldnames if f != 'run']
    for field in numeric_fields:
        values = [r[field] for r in results if isinstance(r[field], (int, float))]
        if values:
            summary[field+"_mean"] = statistics.mean(values)
            summary[field+"_std"] = statistics.stdev(values) if len(values) > 1 else 0.0

    print("\nSummary statistics (mean and std):")
    for key, val in summary.items():
        print(f"{key}: {val}")

if __name__ == "__main__":
    main()

