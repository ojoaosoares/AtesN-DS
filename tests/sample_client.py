#!/usr/bin/env python3

import sys
import subprocess
import json
import csv
import statistics
import re
import argparse
import io


import os


def get_warmup_file():
    if os.path.exists("unicos.txt"):
        return "@unicos.txt"
    if os.path.exists("tests/unicos.txt"):
        return "@tests/unicos.txt"
    return "@unicos.txt"


def run_warmup(server, duration, concurrency):
    cmd = [
        "dnspyre",
        "--duration", str(duration) + "s",
        "--concurrency", str(concurrency),
        "--server", server,
        "--type", "A",
        "--ednsopt=10:11223344556677889900aabb",
        get_warmup_file()
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("dnspyre warmup failed:", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout


def get_trace_file():
    if os.path.exists("tracefile.txt"):
        return "@tracefile.txt"
    if os.path.exists("tests/tracefile.txt"):
        return "@tests/tracefile.txt"
    return "@tracefile.txt"


def run_dnspyre(server, duration, concurrency):
    cmd = [
        "dnspyre",
        "--duration", str(duration) + "s",
        "--concurrency", str(concurrency),
        "--server", server,
        "--type", "A",
        "--ednsopt=10:11223344556677889900aabb",
        get_trace_file()
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
        run_warmup(
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
