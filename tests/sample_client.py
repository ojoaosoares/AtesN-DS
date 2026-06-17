import sys
import subprocess
import json
import csv
import statistics
import re
import argparse
import io

# Suas funções de execução e parsing, mantidas intactas
def run_dnspyre(server, duration, concurrency):
    # O comando exato que você especificou
    cmd = [
        "dnspyre",
        "--duration", str(duration) + "s",
        "-c", str(concurrency),
        "--server", server,
        "--edns0=1232",
        "--no-dnssec",
        "--ednsopt=10:11223344556677889900aabb",
        "https://raw.githubusercontent.com/zer0h/top-1000000-domains/refs/heads/master/top-10000-domains"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("dnspyre failed:", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout

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

def execute_measured_run(server, duration, concurrency, warmup):
    if warmup:
        print("  Warmup run...", file=sys.stderr)
        run_dnspyre(
            server=server,
            duration=duration,
            concurrency=concurrency
        )

    print("  Measured run...", file=sys.stderr)
    return run_dnspyre(
        server=server,
        duration=duration,
        concurrency=concurrency
    )

# Nova função main, adaptada para o fluxo do test.sh
def main():
    parser = argparse.ArgumentParser(description='Run a single DNS benchmark using a specific dnspyre command.')
    parser.add_argument('--server', type=str, required=True)
    parser.add_argument('--duration', type=int, required=True)
    parser.add_argument('--concurrency', type=int, required=True)
    parser.add_argument('--warmup', action='store_true')

    args = parser.parse_args()

    raw_output = execute_measured_run(
        server=args.server,
        duration=args.duration,
        concurrency=args.concurrency,
        warmup=args.warmup
    )

    extracted_data = extract_principal_fields(raw_output)

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=extracted_data.keys())
    writer.writeheader()
    writer.writerow(extracted_data)
    
    print(output.getvalue(), end='')


if __name__ == "__main__":
    main()