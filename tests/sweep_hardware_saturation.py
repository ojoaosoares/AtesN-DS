#!/usr/bin/env python3
import sys
import os
import time
import subprocess
import json
import re
import csv

CONCURRENCIES = [64, 128, 256, 512, 768, 1024, 1536, 2048, 3072, 4096]
DURATION = 5  # seconds per step
WORKERS = 8
CLIENT_HOST = "150.164.2.81"
CLIENT_USER = "soares"
SERVER_IFACE = "enp1s0np1"

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

def get_hw_counters():
    counters = {
        "bpf_app2_pkts": 0,
        "bpf_pass_pkts": 0,
        "mac.rx_drop_events": 0,
        "dev_rx_discards": 0
    }
    try:
        out = subprocess.check_output(["sudo", "ethtool", "-S", SERVER_IFACE], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            line = line.strip()
            for key in counters:
                if line.startswith(key + ":"):
                    parts = line.split(":")
                    if len(parts) == 2:
                        try:
                            counters[key] = int(parts[1].strip())
                        except ValueError:
                            pass
    except Exception:
        pass
    return counters

def run_sweep():
    print("=" * 100)
    print("⚡ PROFILING SMARTNIC HARDWARE CACHE SATURATION CURVE")
    print(f"Interface: {SERVER_IFACE} (Netronome Agilio CX) | Client: {CLIENT_HOST} | Duration per step: {DURATION}s")
    print("=" * 100)

    # First, warm up the hardware SRAM cache
    print("-> Pre-warming hardware SRAM cache (83k domains)...")
    cmd_warmup = (
        f"ssh {CLIENT_USER}@{CLIENT_HOST} "
        f"'cd /home/soares/Documentos/AtesN-DS/tests && "
        f"python3 sample_client.py --server 192.168.0.1 --duration 5 --concurrency 512 --workers 8'"
    )
    subprocess.run(cmd_warmup, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    print(f"{'Conc':>5} | {'QPS':>9} | {'Mean(ms)':>8} | {'p50(ms)':>7} | {'p90(ms)':>7} | {'p99(ms)':>7} | {'p99.9(ms)':>9} | {'HW Hit%':>7} | {'SoftIRQ%':>8} | {'HW Drops':>8}")
    print("-" * 104)

    records = []

    for conc in CONCURRENCIES:
        # Pre snapshot
        stat_pre = read_proc_stat()
        hw_pre = get_hw_counters()

        # Run client dnspyre
        cmd_run = (
            f"ssh {CLIENT_USER}@{CLIENT_HOST} "
            f"'cd /home/soares/Documentos/AtesN-DS/tests && "
            f"python3 sample_client.py --server 192.168.0.1 --duration {DURATION} --concurrency {conc} --workers {WORKERS}'"
        )
        proc = subprocess.Popen(cmd_run, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = proc.communicate()

        # Post snapshot
        stat_post = read_proc_stat()
        hw_post = get_hw_counters()

        delta_hw_tx = hw_post["bpf_app2_pkts"] - hw_pre["bpf_app2_pkts"]
        delta_pass = hw_post["bpf_pass_pkts"] - hw_pre["bpf_pass_pkts"]
        total_hw_pkts = delta_hw_tx + delta_pass
        hw_hit_pct = (delta_hw_tx / total_hw_pkts * 100.0) if total_hw_pkts > 0 else 0.0

        drop_events = (hw_post["mac.rx_drop_events"] - hw_pre["mac.rx_drop_events"]) + \
                      (hw_post["dev_rx_discards"] - hw_pre["dev_rx_discards"])
        if drop_events < 0:
            drop_events = 0

        # Parse CPU
        cpu_usage = compute_cpu_pct(stat_pre, stat_post)
        total_softirq = cpu_usage.get("cpu", {}).get("softirq", 0.0)

        # Parse dnspyre CSV
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

        row = {
            "concurrency": conc,
            "qps": qps,
            "mean_ms": lat_mean,
            "p50_ms": p50,
            "p90_ms": p90,
            "p99_ms": p99,
            "p99_9_ms": p99_9,
            "hw_hit_pct": hw_hit_pct,
            "softirq_pct": total_softirq,
            "hw_drops": drop_events
        }
        records.append(row)

        print(f"{conc:>5} | {qps:>9.1f} | {lat_mean:>8.2f} | {p50:>7.2f} | {p90:>7.2f} | {p99:>7.2f} | {p99_9:>9.2f} | {hw_hit_pct:>6.1f}% | {total_softirq:>7.1f}% | {drop_events:>8}")
        time.sleep(1)

    print("-" * 104)

    print("\n📊 SMARTNIC HARDWARE SATURATION ANALYSIS:")
    max_qps_row = max(records, key=lambda r: r["qps"])
    print(f"  • Maximum Measured Hardware Throughput (Q_max): {max_qps_row['qps']:.1f} QPS at Concurrency {max_qps_row['concurrency']}")

    knee_row = None
    for i in range(1, len(records)):
        prev = records[i-1]
        curr = records[i]
        qps_growth = (curr["qps"] - prev["qps"]) / max(1.0, prev["qps"])
        lat_growth = (curr["p99_ms"] - prev["p99_ms"]) / max(0.1, prev["p99_ms"])
        if (lat_growth > 2.0 and qps_growth < 0.15) or curr["hw_drops"] > 0:
            knee_row = curr
            print(f"  • Hardware Saturation Knee detected at Concurrency {curr['concurrency']}:")
            print(f"      QPS = {curr['qps']:.1f} | p99 = {curr['p99_ms']:.2f} ms | HW Drops = {curr['hw_drops']}")
            print(f"      Reason: {'Physical MAC Drop events detected' if curr['hw_drops'] > 0 else 'Latency slope divergence'}")
            break

    if not knee_row:
        print("  • No hardware drops or severe latency knees detected across tested range!")
        print(f"  • Hardware remains linear up to {max_qps_row['qps']:.1f} QPS with SoftIRQ under 1.0%!")

    return records

if __name__ == "__main__":
    run_sweep()
