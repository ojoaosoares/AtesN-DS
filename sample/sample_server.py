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
        mem_used_samples.append(mem.used / (1024 * 1024))  # MB

    return cpu_user_samples, cpu_system_samples, mem_used_samples


def summarize(samples):
    mean = statistics.mean(samples)
    std = statistics.stdev(samples) if len(samples) > 1 else 0.0
    return round(mean, 2), round(std, 2)


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} output.csv duration_seconds num_runs")
        sys.exit(1)

    output_file = sys.argv[1]
    duration = int(sys.argv[2])
    num_runs = int(sys.argv[3])

    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            "run",
            "mean_cpu_user", "std_cpu_user",
            "mean_cpu_system", "std_cpu_system",
            "mean_mem_used_mb", "std_mem_used_mb"
        ])

        for run in range(1, num_runs + 1):
            print(f"Starting test run {run}...")
            user_samples, system_samples, mem_samples = sample(duration)

            mean_user, std_user = summarize(user_samples)
            mean_system, std_system = summarize(system_samples)
            mean_mem, std_mem = summarize(mem_samples)

            writer.writerow([
                run,
                mean_user, std_user,
                mean_system, std_system,
                mean_mem, std_mem
            ])

    print(f"All {num_runs} runs complete. Results saved to {output_file}")


if __name__ == "__main__":
    main()

