#!/usr/bin/env python3

import sys
import time
import csv
import statistics
import psutil
import subprocess
import re


SAMPLE_INTERVAL = 0.2


def reset_bpf_dns_misses():
    try:
        subprocess.run(
            [
                "sudo", "bpftool", "map", "update", "pinned",
                "/sys/fs/bpf/dns_misses",
                "key", "hex", "00", "00", "00", "00",
                "value", "hex", "00", "00", "00", "00", "00", "00", "00", "00"
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print("  BPF dns_misses map reset to 0 at start of measurement window.")
    except Exception as e:
        print(f"  Warning: Failed to reset BPF dns_misses map: {e}", file=sys.stderr)


def get_bpf_dns_misses():
    try:
        res = subprocess.run(
            ["sudo", "bpftool", "map", "dump", "pinned", "/sys/fs/bpf/dns_misses"],
            capture_output=True,
            text=True,
            check=True
        )
        total = 0
        for line in res.stdout.splitlines():
            m = re.search(r"value \(CPU \d+\):\s*([0-9a-fA-F ]{23,24})", line)
            if m:
                raw = bytes.fromhex(m.group(1).replace(" ", ""))
                total += int.from_bytes(raw, byteorder="little")
        return total
    except Exception as e:
        print(f"  Warning: Failed to dump BPF dns_misses map: {e}", file=sys.stderr)
        return 0


def sample(duration):
    cpu_user_samples = []
    cpu_system_samples = []
    cpu_softirq_samples = []
    cpu_irq_samples = []
    mem_used_samples = []
    per_core_max_samples = []

    # Initialize counters before the loop to avoid dummy 0.0 value on the first call
    psutil.cpu_times_percent(interval=None)
    psutil.cpu_percent(interval=None, percpu=True)

    end_time = time.time() + duration

    while time.time() < end_time:
        start_time = time.time()

        cpu_times = psutil.cpu_times_percent(interval=None)
        cpu_user_samples.append(cpu_times.user)
        cpu_system_samples.append(cpu_times.system)
        cpu_softirq_samples.append(getattr(cpu_times, "softirq", 0.0))
        cpu_irq_samples.append(getattr(cpu_times, "irq", 0.0))

        mem = psutil.virtual_memory()
        mem_used_samples.append(mem.percent)

        # Capture per-core saturation
        per_core = psutil.cpu_percent(interval=None, percpu=True)
        per_core_max_samples.append(max(per_core))

        # Control the sampling interval manually
        elapsed = time.time() - start_time
        remaining_time = SAMPLE_INTERVAL - elapsed
        if remaining_time > 0:
            time.sleep(remaining_time)

    return {
        "cpu_user": cpu_user_samples,
        "cpu_system": cpu_system_samples,
        "cpu_softirq": cpu_softirq_samples,
        "cpu_irq": cpu_irq_samples,
        "mem_used": mem_used_samples,
        "max_core_usage": per_core_max_samples
    }


def summarize(samples):
    n = len(samples)
    if n == 0:
        return {
            "mean": 0.0,
            "std": 0.0,
            "max": 0.0,
            "p50": 0.0,
            "p75": 0.0,
            "p90": 0.0,
            "p99": 0.0
        }

    mean_val = statistics.mean(samples)
    std_val = statistics.stdev(samples) if n >= 2 else 0.0
    max_val = max(samples)
    p50_val = statistics.median(samples)

    if n >= 100:
        q = statistics.quantiles(samples, n=100)
        p75_val = q[74]
        p90_val = q[89]
        p99_val = q[98]
    else:
        sorted_samples = sorted(samples)
        p75_val = sorted_samples[int(n * 0.75)]
        p90_val = sorted_samples[int(n * 0.90)]
        p99_val = sorted_samples[int(n * 0.99)]

    return {
        "mean": mean_val,
        "std": std_val,
        "max": max_val,
        "p50": p50_val,
        "p75": p75_val,
        "p90": p90_val,
        "p99": p99_val
    }


def main():
    if len(sys.argv) not in (3, 4):
        print(
            f"Usage: {sys.argv[0]} <output.csv> <duration_seconds> [warmup_seconds]",
            file=sys.stderr
        )
        sys.exit(1)

    output_file = sys.argv[1]

    try:
        duration = int(sys.argv[2])
        if duration <= 0:
            raise ValueError("Duration must be a positive integer.")
    except ValueError as e:
        print(f"Error: Invalid duration: {e}", file=sys.stderr)
        sys.exit(1)

    warmup_seconds = 60
    if len(sys.argv) == 4:
        try:
            warmup_seconds = int(sys.argv[3])
            if warmup_seconds < 0:
                raise ValueError("Warmup seconds must be a non-negative integer.")
        except ValueError as e:
            print(f"Error: Invalid warmup seconds: {e}", file=sys.stderr)
            sys.exit(1)

    print("Starting benchmark monitor")
    print(f"Warmup time: {warmup_seconds}s")
    print(f"Sampling interval: {SAMPLE_INTERVAL}s")
    print(f"Measurement duration: {duration}s")
    print()

    if warmup_seconds > 0:
        print(f"Waiting {warmup_seconds}s for external benchmark warmup...")
        time.sleep(warmup_seconds)

    # Immediately reset BPF dns_misses after cache warmup phase
    reset_bpf_dns_misses()

    print("Collecting samples...")
    data = sample(duration)

    cache_misses = get_bpf_dns_misses()
    print(f"  Cache misses collected: {cache_misses}")

    run_summary = {
        "cpu_user": summarize(data["cpu_user"]),
        "cpu_system": summarize(data["cpu_system"]),
        "cpu_softirq": summarize(data["cpu_softirq"]),
        "cpu_irq": summarize(data["cpu_irq"]),
        "mem_used": summarize(data["mem_used"]),
        "max_core_usage": summarize(data["max_core_usage"])
    }

    print(f"  CPU user mean: {run_summary['cpu_user']['mean']:.2f}%")
    print(f"  CPU softirq mean: {run_summary['cpu_softirq']['mean']:.2f}%")
    print(f"  Max core usage p99: {run_summary['max_core_usage']['p99']:.2f}%")

    # Flatten the summary for CSV output
    rows = []
    for metric, stats in run_summary.items():
        for stat_name, value in stats.items():
            rows.append({
                "metric": f"{metric}_{stat_name}",
                "value": round(value, 2)
            })

    rows.append({
        "metric": "cache_misses",
        "value": cache_misses
    })

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["metric", "value"])
        writer.writeheader()
        writer.writerows(rows)

    print()
    print(f"Summary written to {output_file}")


if __name__ == "__main__":
    main()