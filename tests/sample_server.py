#!/usr/bin/env python3

import sys
import time
import csv
import statistics
import psutil


WARMUP_SECONDS = 60
SAMPLE_INTERVAL = 0.2


def sample(duration):
    cpu_user_samples = []
    cpu_system_samples = []
    mem_used_samples = []

    per_core_max_samples = []

    end_time = time.time() + duration

    while time.time() < end_time:

        cpu_times = psutil.cpu_times_percent(
            interval=SAMPLE_INTERVAL
        )

        cpu_user_samples.append(cpu_times.user)
        cpu_system_samples.append(cpu_times.system)

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
        "mem_used": mem_used_samples,
        "max_core_usage": per_core_max_samples
    }


def summarize(samples):
    return {
        "mean": statistics.mean(samples),
        "std": statistics.stdev(samples) if len(samples) > 1 else 0.0,
        "max": max(samples),
        "p99": statistics.quantiles(samples, n=100)[98]
        if len(samples) >= 100 else max(samples)
    }


def main():

    if len(sys.argv) != 4:
        print(
            f"Usage: {sys.argv[0]} "
            "output.csv duration_seconds num_runs"
        )
        sys.exit(1)

    output_file = sys.argv[1]
    duration = int(sys.argv[2])
    num_runs = int(sys.argv[3])

    all_runs = []

    print(f"Starting benchmark monitor")
    print(f"Warmup time: {WARMUP_SECONDS}s")
    print(f"Sampling interval: {SAMPLE_INTERVAL}s")
    print(f"Measurement duration: {duration}s")
    print()

    for run in range(1, num_runs + 1):

        print(f"=== Run {run}/{num_runs} ===")

        print(
            f"Waiting {WARMUP_SECONDS}s "
            f"for external benchmark warmup..."
        )

        time.sleep(WARMUP_SECONDS)

        print("Collecting samples...")

        data = sample(duration)

        run_summary = {
            "cpu_user": summarize(data["cpu_user"]),
            "cpu_system": summarize(data["cpu_system"]),
            "mem_used": summarize(data["mem_used"]),
            "max_core_usage": summarize(data["max_core_usage"])
        }

        all_runs.append(run_summary)

        print(
            f"  CPU user mean: "
            f"{run_summary['cpu_user']['mean']:.2f}%"
        )

        print(
            f"  Max core usage p99: "
            f"{run_summary['max_core_usage']['p99']:.2f}%"
        )

    # Aggregate across runs
    rows = []

    metrics = [
        "cpu_user",
        "cpu_system",
        "mem_used",
        "max_core_usage"
    ]

    stats_fields = [
        "mean",
        "std",
        "max",
        "p99"
    ]

    for metric in metrics:
        for stat in stats_fields:

            values = [
                run[metric][stat]
                for run in all_runs
            ]

            rows.append({
                "metric": f"{metric}_{stat}",
                "mean": round(statistics.mean(values), 2),
                "std": round(
                    statistics.stdev(values),
                    2
                ) if len(values) > 1 else 0.0
            })

    with open(output_file, "w", newline="") as f:

        writer = csv.DictWriter(
            f,
            fieldnames=["metric", "mean", "std"]
        )

        writer.writeheader()
        writer.writerows(rows)

    print()
    print(f"Summary written to {output_file}")


if __name__ == "__main__":
    main()