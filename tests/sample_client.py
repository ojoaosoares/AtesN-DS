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
        "--edns0=1232",
        "--no-dnssec",
        "--ednsopt=10:11223344556677889900aabb",
        "https://raw.githubusercontent.com/zer0h/top-1000000-domains/refs/heads/master/top-10000-domains"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("dnspyre failed:")
        print(result.stderr)
        sys.exit(1)
    return result.stdout


import re

def parse_duration_to_ms(value, unit):
    unit = unit.strip()
    value = float(value)
    if unit == "µs":
        return value / 1000
    elif unit == "ms":
        return value
    elif unit == "s":
        return value * 1000
    return value


def strip_ansi(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text)

def extract_principal_fields(text):
    text = strip_ansi(text)
    print("DEBUG CLEAN:", text[text.find("DNS timings"):text.find("DNS distribution")])

    def get_float(pattern):
        m = re.search(pattern, text)
        return float(m.group(1)) if m else 0.0

    def get_latency(label):
        m = re.search(rf"{label}:\s+([\d.]+)(µs|ms|s)", text)
        if m:
            return parse_duration_to_ms(m.group(1), m.group(2))
        return 0.0

    return {
        "totalRequests":    get_float(r"Total requests:\s+([\d.]+)"),
        "queriesPerSecond": get_float(r"Questions per second:\s+([\d.]+)"),
        "latency_mean_ms":  get_latency("mean"),
        "latency_p50_ms":   get_latency("p50"),
        "latency_p75_ms":   get_latency("p75"),
        "latency_p90_ms":   get_latency("p90"),
        "latency_p95_ms":   get_latency("p95"),
        "latency_p99_ms":   get_latency("p99"),
    }


def execute_measured_run(server, duration, concurrency):
    print("  Warmup run...")

    # Warmup run intentionally discarded
    run_dnspyre(
        server=server,
        duration=duration,
        concurrency=concurrency
    )

    print("  Measured run...")

    return run_dnspyre(
        server=server,
        duration=duration,
        concurrency=concurrency
    )


def compute_summary(results):
    metrics = results[0].keys()
    summary = []

    for metric in metrics:
        values = [r[metric] for r in results]

        summary.append({
            "metric": metric,
            "mean": statistics.mean(values),
            "std": statistics.stdev(values) if len(values) > 1 else 0.0
        })

    return summary


def write_summary_csv(path, rows):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["metric", "mean", "std"]
        )

        writer.writeheader()
        writer.writerows(rows)


def main():
    if len(sys.argv) < 6:
        print(
            f"Usage: {sys.argv[0]} "
            "output.csv num_runs server duration concurrency"
        )
        sys.exit(1)

    output_csv = sys.argv[1]
    num_runs = int(sys.argv[2])

    server = sys.argv[3]
    duration = sys.argv[4]
    concurrency = sys.argv[5]

    print("Starting benchmark...")
    print("EDNS0 size fixed at 1232 bytes")

    results = []

    for run in range(1, num_runs + 1):

        print(f"\n=== Run {run}/{num_runs} ===")

        data = execute_measured_run(
            server=server,
            duration=duration,
            concurrency=concurrency
        )

        extracted = extract_principal_fields(data)
        results.append(extracted)

        print(
            f"  QPS={extracted['queriesPerSecond']:.2f} | "
            f"P50={extracted['latency_p50_ms']:.2f} ms | "
            f"P99={extracted['latency_p99_ms']:.2f} ms"
        )

    summary = compute_summary(results)

    write_summary_csv(output_csv, summary)

    print(f"\nSummary written to {output_csv}")


if __name__ == "__main__":
    main()


