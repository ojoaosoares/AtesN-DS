#!/usr/bin/env python3
import sys
import os
import time
import subprocess
import json
import csv

CONCURRENCIES = [512, 1024, 2048]
DURATION = 5
WORKERS = 8
CLIENT_HOST = "150.164.2.81"
CLIENT_USER = "soares"

def read_proc_stat():
    cores = {}
    with open("/proc/stat", "r") as f:
        for line in f:
            parts = line.strip().split()
            if not parts:
                continue
            name = parts[0]
            if name == "cpu" or name.startswith("cpu"):
                vals = [int(x) for x in parts[1:8]]
                cores[name] = vals
    return cores

def compute_cpu_pct(stat_pre, stat_post):
    results = {}
    for name in stat_pre:
        if name not in stat_post:
            continue
        pre = stat_pre[name]
        post = stat_post[name]
        diffs = [post[i] - pre[i] for i in range(len(pre))]
        total = sum(diffs)
        if total <= 0:
            continue
        user = (diffs[0] + diffs[1]) / total * 100.0
        system = diffs[2] / total * 100.0
        idle = diffs[3] / total * 100.0
        softirq = diffs[6] / total * 100.0
        results[name] = {
            "user": user,
            "system": system,
            "idle": idle,
            "softirq": softirq,
            "total_busy": 100.0 - idle
        }
    return results

def set_mode(mode_name, ratio=0):
    cmd = ["python3", "tests/manage_overload.py", mode_name]
    if mode_name == "prop":
        cmd.append(str(ratio))
    subprocess.run(cmd, check=True)
    time.sleep(1)

def run_bench():
    print("=" * 105)
    print("🔥 COMPARATIVE BENCHMARK: DRIVER OVERLOAD SHEDDING POLICIES UNDER SATURATION")
    print(f"Workload: 2M ISP Trace | Client: {CLIENT_HOST} | Duration per test: {DURATION}s")
    print("=" * 105)

    test_configs = [
        ("Normal Driver (No Shedding)", "normal", 0),
        ("Hybrid Miss-Shedding (Shed Misses)", "misses", 0),
        ("Hybrid Proportional (50% Pre-Lookup Shed)", "prop", 50),
        ("Hybrid Early-Pass (100% Pre-Lookup Shed)", "early", 100),
    ]

    for label, mode_cmd, ratio in test_configs:
        print(f"\n▶ Testing Configuration: {label}")
        set_mode(mode_cmd, ratio)

        print(f"{'Conc':>5} | {'QPS':>9} | {'Mean(ms)':>8} | {'p50(ms)':>7} | {'p90(ms)':>7} | {'p99(ms)':>7} | {'p99.9(ms)':>9} | {'SoftIRQ%':>8} | {'User%':>6} | {'Idle%':>6}")
        print("-" * 95)

        for conc in CONCURRENCIES:
            stat_pre = read_proc_stat()

            cmd_run = (
                f"ssh {CLIENT_USER}@{CLIENT_HOST} "
                f"'cd /home/soares/Documentos/AtesN-DS/tests && "
                f"python3 sample_client.py --server 192.168.0.1 --duration {DURATION} --concurrency {conc} --workers {WORKERS}'"
            )
            proc = subprocess.Popen(cmd_run, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = proc.communicate()

            stat_post = read_proc_stat()
            cpu_usage = compute_cpu_pct(stat_pre, stat_post)
            total_softirq = cpu_usage.get("cpu", {}).get("softirq", 0.0)
            user_cpu = cpu_usage.get("cpu", {}).get("user", 0.0)
            idle_cpu = cpu_usage.get("cpu", {}).get("idle", 0.0)

            qps = 0.0
            lat_mean = 0.0
            p50 = 0.0
            p90 = 0.0
            p99 = 0.0
            p99_9 = 0.0

            reader = csv.DictReader([l for l in stdout.splitlines() if "," in l])
            for row_dict in reader:
                try:
                    qps = float(row_dict.get("queriesPerSecond", 0.0))
                    lat_mean = float(row_dict.get("latency_mean_ms", 0.0))
                    p50 = float(row_dict.get("latency_p50_ms", 0.0))
                    p90 = float(row_dict.get("latency_p90_ms", 0.0))
                    p99 = float(row_dict.get("latency_p99_ms", 0.0))
                    p99_9 = float(row_dict.get("latency_p99_9_ms", 0.0))
                    break
                except Exception:
                    pass

            print(f"{conc:>5} | {qps:>9.1f} | {lat_mean:>8.2f} | {p50:>7.2f} | {p90:>7.2f} | {p99:>7.2f} | {p99_9:>9.2f} | {total_softirq:>7.1f}% | {user_cpu:>5.1f}% | {idle_cpu:>5.1f}%")
            time.sleep(1)

    # Restore normal mode at the end
    set_mode("normal", 0)
    print("\n✅ Benchmark completed. Restored normal driver mode.")

if __name__ == "__main__":
    run_bench()
