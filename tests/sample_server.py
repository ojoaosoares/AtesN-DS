#!/usr/bin/env python3

import sys
import time
import csv
import statistics
import psutil


SAMPLE_INTERVAL = 0.2


def sample(duration):
    cpu_user_samples = []
    cpu_system_samples = []
    cpu_softirq_samples = []
    cpu_irq_samples = []
    mem_used_samples = []

    per_core_max_samples = []

    # Initialize cpu_percent to avoid dummy 0.0 value on the first call
    psutil.cpu_percent(interval=None, percpu=True)

    end_time = time.time() + duration

    while time.time() < end_time:

        cpu_times = psutil.cpu_times_percent(
            interval=SAMPLE_INTERVAL
        )

        cpu_user_samples.append(cpu_times.user)
        cpu_system_samples.append(cpu_times.system)
        cpu_softirq_samples.append(getattr(cpu_times, "softirq", 0.0))
        cpu_irq_samples.append(getattr(cpu_times, "irq", 0.0))

        mem = psutil.virtual_memory()
        mem_used_samples.append(mem.percent)

        # Capture per-core saturation
        per_core = psutil.cpu_percent(
            interval=None,
            percpu=True
        )

        per_core_max_samples.append(max(per_core))

    return {
        "cpu_user": cpu_user_samples,
        "cpu_system": cpu_system_samples,
        "cpu_softirq": cpu_softirq_samples,
        "cpu_irq": cpu_irq_samples,
        "mem_used": mem_used_samples,
        "max_core_usage": per_core_max_samples
    }


def summarize(samples):
    if len(samples) >= 100:
        q = statistics.quantiles(samples, n=100)
        p50 = q[49]
        p75 = q[74]
        p90 = q[89]
        p99 = q[98]
    else:
        sorted_samples = sorted(samples)
        n = len(sorted_samples)
        p50 = statistics.median(sorted_samples) if n > 0 else 0.0
        p75 = sorted_samples[int(n * 0.75)] if n > 0 else 0.0
        p90 = sorted_samples[int(n * 0.90)] if n > 0 else 0.0
        p99 = max(sorted_samples) if n > 0 else 0.0

    return {
        "mean": statistics.mean(samples) if len(samples) > 0 else 0.0,
        "std": statistics.stdev(samples) if len(samples) > 1 else 0.0,
        "max": max(samples) if len(samples) > 0 else 0.0,
        "p50": p50,
        "p75": p75,
        "p90": p90,
        "p99": p99
    }


def main():

    if len(sys.argv) not in (3, 4):
        print(
            f"Usage: {sys.argv[0]} "
            "output.csv duration_seconds [warmup_seconds]"
        )
        sys.exit(1)

    output_file = sys.argv[1]
    duration = int(sys.argv[2])
    warmup_seconds = int(sys.argv[3]) if len(sys.argv) == 4 else 60

    print(f"Starting benchmark monitor")
    print(f"Warmup time: {warmup_seconds}s")
    print(f"Sampling interval: {SAMPLE_INTERVAL}s")
    print(f"Measurement duration: {duration}s")
    print()

    print(
        f"Waiting {warmup_seconds}s "
        f"for external benchmark warmup..."
    )

    if warmup_seconds > 0:
        time.sleep(warmup_seconds)

    print("Collecting samples...")

    data = sample(duration)

    run_summary = {
        "cpu_user": summarize(data["cpu_user"]),
        "cpu_system": summarize(data["cpu_system"]),
        "cpu_softirq": summarize(data["cpu_softirq"]),
        "cpu_irq": summarize(data["cpu_irq"]),
        "mem_used": summarize(data["mem_used"]),
        "max_core_usage": summarize(data["max_core_usage"])
    }

    print(
        f"  CPU user mean: "
        f"{run_summary['cpu_user']['mean']:.2f}%"
    )
    print(
        f"  CPU softirq mean: "
        f"{run_summary['cpu_softirq']['mean']:.2f}%"
    )
    print(
        f"  Max core usage p99: "
        f"{run_summary['max_core_usage']['p99']:.2f}%"
    )

    # Flatten the summary for CSV output
    rows = []
    for metric, stats in run_summary.items():
        for stat_name, value in stats.items():
            rows.append({
                "metric": f"{metric}_{stat_name}",
                "value": round(value, 2)
            })

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["metric", "value"]
        )
        writer.writeheader()
        writer.writerows(rows)

    print()
    print(f"Summary written to {output_file}")


if __name__ == "__main__":
    main()