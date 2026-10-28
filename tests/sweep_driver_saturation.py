#!/usr/bin/env python3
import sys
import os
import time
import subprocess
import json
import re

CONCURRENCIES = [64, 128, 256, 512, 768, 1024, 1536, 2048, 3072, 4096]
DURATION = 5  # seconds per test
WORKERS = 8
CLIENT_HOST = "150.164.2.81"
CLIENT_USER = "soares"
SERVER_IFACE = "enp1s0np1"

def read_proc_stat():
    """Reads /proc/stat and returns per-core tick counts."""
    cores = {}
    with open("/proc/stat", "r") as f:
        for line in f:
            parts = line.strip().split()
            if not parts:
                continue
            name = parts[0]
            if name == "cpu" or name.startswith("cpu"):
                # user, nice, system, idle, iowait, irq, softirq, steal
                vals = [int(x) for x in parts[1:8]]
                cores[name] = vals
    return cores

def compute_cpu_pct(stat_pre, stat_post):
    """Computes overall and per-core CPU percentages."""
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

def get_nic_drops():
    """Reads ethtool drop counters on SERVER_IFACE."""
    drops = 0
    try:
        out = subprocess.check_output(["sudo", "ethtool", "-S", SERVER_IFACE], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            line = line.strip()
            if any(k in line.lower() for k in ["drop", "discard", "miss", "err"]):
                parts = line.split(":")
                if len(parts) == 2:
                    try:
                        drops += int(parts[1].strip())
                    except ValueError:
                        pass
    except Exception:
        pass
    return drops

def run_sweep():
    print("=" * 80)
    print("🔍 PROFILING ATESN-DS DRIVER MODE SATURATION CURVE")
    print(f"Server: {SERVER_IFACE} | Client: {CLIENT_HOST} | Duration per step: {DURATION}s")
    print("=" * 80)

    # First, warm up the driver cache
    print("-> Warming up driver cache (83k domains)...")
    cmd_warmup = (
        f"ssh {CLIENT_USER}@{CLIENT_HOST} "
        f"'cd /home/soares/Documentos/AtesN-DS/tests && "
        f"python3 sample_client.py --server 192.168.0.1 --duration 5 --concurrency 512 --workers 8'"
    )
    subprocess.run(cmd_warmup, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    print(f"{'Conc':>5} | {'QPS':>9} | {'Mean (ms)':>9} | {'p50 (ms)':>8} | {'p90 (ms)':>8} | {'p99 (ms)':>8} | {'p99.9 (ms)':>10} | {'SoftIRQ%':>8} | {'MaxCore%':>8} | {'Drops':>6}")
    print("-" * 96)

    records = []

    for conc in CONCURRENCIES:
        # Pre snapshot
        stat_pre = read_proc_stat()
        drops_pre = get_nic_drops()

        # Run client dnspyre
        cmd_run = (
            f"ssh {CLIENT_USER}@{CLIENT_HOST} "
            f"'cd /home/soares/Documentos/AtesN-DS/tests && "
            f"python3 sample_client.py --server 192.168.0.1 --duration {DURATION} --concurrency {conc} --workers {WORKERS}'"
        )
        proc = subprocess.Popen(cmd_run, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Wait for run to finish
        stdout, stderr = proc.communicate()

        # Post snapshot
        stat_post = read_proc_stat()
        drops_post = get_nic_drops()
        drop_delta = drops_post - drops_pre

        # Parse CPU
        cpu_usage = compute_cpu_pct(stat_pre, stat_post)
        total_softirq = cpu_usage.get("cpu", {}).get("softirq", 0.0)
        core_softirqs = [v["softirq"] for k, v in cpu_usage.items() if k.startswith("cpu") and k != "cpu"]
        max_core_softirq = max(core_softirqs) if core_softirqs else 0.0

        # Parse Client CSV output
        qps = 0.0
        lat_mean = 0.0
        p50 = 0.0
        p90 = 0.0
        p99 = 0.0
        p99_9 = 0.0

        import csv as csv_mod
        reader = csv_mod.DictReader([l for l in stdout.splitlines() if "," in l])
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

        row = {
            "concurrency": conc,
            "qps": qps,
            "mean_ms": lat_mean,
            "p50_ms": p50,
            "p90_ms": p90,
            "p99_ms": p99,
            "p99_9_ms": p99_9,
            "softirq_pct": total_softirq,
            "max_core_softirq_pct": max_core_softirq,
            "drops": drop_delta
        }
        records.append(row)

        print(f"{conc:>5} | {qps:>9.1f} | {lat_mean:>9.2f} | {p50:>8.2f} | {p90:>8.2f} | {p99:>8.2f} | {p99_9:>10.2f} | {total_softirq:>7.1f}% | {max_core_softirq:>7.1f}% | {drop_delta:>6}")
        time.sleep(1)

    print("-" * 96)
    
    # Analyze saturation point
    # Knee detection: point where p99 latency increases sharply relative to QPS gain
    print("\n📊 SATURATION POINT ANALYSIS:")
    max_qps_row = max(records, key=lambda r: r["qps"])
    print(f"  • Maximum Sustained Throughput (Q_max): {max_qps_row['qps']:.1f} QPS at Concurrency {max_qps_row['concurrency']}")

    knee_row = None
    for i in range(1, len(records)):
        prev = records[i-1]
        curr = records[i]
        qps_growth = (curr["qps"] - prev["qps"]) / max(1.0, prev["qps"])
        lat_growth = (curr["p99_ms"] - prev["p99_ms"]) / max(0.1, prev["p99_ms"])
        
        # If latency grows > 3x faster than QPS, or MaxCore SoftIRQ > 80%
        if (lat_growth > 2.0 and qps_growth < 0.15) or curr["max_core_softirq_pct"] >= 80.0:
            knee_row = curr
            print(f"  • Driver Saturation Knee detected at Concurrency {curr['concurrency']}:")
            print(f"      QPS = {curr['qps']:.1f} | p99 = {curr['p99_ms']:.2f} ms | MaxCore SoftIRQ = {curr['max_core_softirq_pct']:.1f}%")
            print(f"      Reason: {'Single core SoftIRQ >= 80%' if curr['max_core_softirq_pct'] >= 80 else 'p99 latency slope hockey-stick'}")
            break

    if not knee_row:
        knee_row = max_qps_row
        print(f"  • Saturation reached at plateau: {knee_row['qps']:.1f} QPS")

    return records

if __name__ == "__main__":
    run_sweep()
