#!/usr/bin/env python3

import sys
import time
import csv
import statistics
import psutil

def sample(duration):
    cpu_user_samples = []
    cpu_system_samples = []
    mem_used_samples = []

    for _ in range(duration):
        cpu_times = psutil.cpu_times_percent(interval=1)
        cpu_user_samples.append(cpu_times.user)
        cpu_system_samples.append(cpu_times.system)

        mem = psutil.virtual_memory()
        mem_used_samples.append(mem.percent)

    return cpu_user_samples, cpu_system_samples, mem_used_samples

def summarize(samples):
    return statistics.mean(samples)

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} output.csv duration_seconds num_runs")
        sys.exit(1)

    output_file = sys.argv[1]
    duration = int(sys.argv[2])
    num_runs = int(sys.argv[3])

    # Store the *mean* of each run for aggregation
    user_means = []
    system_means = []
    mem_means = []

    print(f"Starting {num_runs} runs, each {duration} seconds...")
    for run in range(1, num_runs + 1):
        print(f"  Run {run} of {num_runs}...")
        time.sleep(60)
        user_samples, system_samples, mem_samples = sample(duration)

        user_means.append(summarize(user_samples))
        system_means.append(summarize(system_samples))
        mem_means.append(summarize(mem_samples))

    # Compute mean and std across runs
    summary = []
    for label, values in [
        ("mean_cpu_user", user_means),
        ("mean_cpu_system", system_means),
        ("mean_mem_used_percent", mem_means)
    ]:
        mean_val = statistics.mean(values)
        std_val = statistics.stdev(values) if len(values) > 1 else 0.0
        summary.append({
            "metric": label,
            "mean": round(mean_val, 2),
            "std": round(std_val, 2)
        })

    # Write single summary CSV
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["metric", "mean", "std"])
        writer.writeheader()
        writer.writerows(summary)

    print(f"Summary (mean and std) written to {output_file}")

if __name__ == "__main__":
    main()
