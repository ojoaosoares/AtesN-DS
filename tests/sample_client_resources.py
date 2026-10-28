#!/usr/bin/env python3

import sys
import os
import time
import csv
import statistics
import psutil
import subprocess
import re

SAMPLE_INTERVAL = 0.2


def read_udp_snmp():
    stats = {"InErrors": 0, "RcvbufErrors": 0, "SndbufErrors": 0, "InDatagrams": 0, "OutDatagrams": 0}
    try:
        with open("/proc/net/snmp", "r") as f:
            lines = f.readlines()
        for i in range(len(lines)):
            if lines[i].startswith("Udp: ") and not lines[i].startswith("Udp: InDatagrams"):
                headers = lines[i - 1].split()[1:]
                values = lines[i].split()[1:]
                for h, v in zip(headers, values):
                    if h in stats:
                        stats[h] = int(v)
    except Exception:
        pass
    return stats


def read_client_nic_drops(iface="enp1s0f0"):
    stats = {"rx_dropped": 0, "tx_dropped": 0, "rx_errors": 0}
    try:
        res = subprocess.run(["ethtool", "-S", iface], capture_output=True, text=True)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                m = re.match(r"\s*([a-zA-Z0-9_.]+):\s*(\d+)", line)
                if m and m.group(1) in stats:
                    stats[m.group(1)] = int(m.group(2))
    except Exception:
        pass
    return stats


def sample(output_file, duration, warmup_duration=0, iface="enp1s0f0"):
    if warmup_duration > 0:
        time.sleep(warmup_duration)

    start_udp = read_udp_snmp()
    start_nic = read_client_nic_drops(iface)

    cpu_user_samples = []
    cpu_sys_samples = []
    cpu_idle_samples = []
    max_core_samples = []
    mem_used_samples = []

    # Prime psutil
    psutil.cpu_percent(percpu=True)
    psutil.cpu_times_percent()

    start_time = time.time()
    while time.time() - start_time < duration:
        per_core = psutil.cpu_percent(interval=SAMPLE_INTERVAL, percpu=True)
        times = psutil.cpu_times_percent()
        mem = psutil.virtual_memory()

        cpu_user_samples.append(times.user)
        cpu_sys_samples.append(times.system)
        cpu_idle_samples.append(times.idle)
        max_core_samples.append(max(per_core) if per_core else 0.0)
        mem_used_samples.append(mem.percent)

    end_udp = read_udp_snmp()
    end_nic = read_client_nic_drops(iface)

    def summarize(data):
        if not data:
            return {"mean": 0.0, "max": 0.0, "p99": 0.0}
        s = sorted(data)
        idx_p99 = min(int(len(s) * 0.99), len(s) - 1)
        return {
            "mean": round(statistics.mean(data), 2),
            "max": round(max(data), 2),
            "p99": round(s[idx_p99], 2)
        }

    summary = {
        "client_cpu_user": summarize(cpu_user_samples),
        "client_cpu_system": summarize(cpu_sys_samples),
        "client_cpu_idle": summarize(cpu_idle_samples),
        "client_max_core": summarize(max_core_samples),
        "client_mem_used": summarize(mem_used_samples),
        "client_udp_rcvbuf_drops": end_udp.get("RcvbufErrors", 0) - start_udp.get("RcvbufErrors", 0),
        "client_udp_in_errors": end_udp.get("InErrors", 0) - start_udp.get("InErrors", 0),
        "client_nic_rx_dropped": end_nic.get("rx_dropped", 0) - start_nic.get("rx_dropped", 0),
    }

    if output_file:
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        with open(output_file, "w") as f:
            for k, v in summary.items():
                if isinstance(v, dict):
                    for subk, subv in v.items():
                        f.write(f"{k}_{subk},{subv}\n")
                else:
                    f.write(f"{k},{v}\n")

    print(f"  [Client Telemetry] CPU User: {summary['client_cpu_user']['mean']:.1f}% | System: {summary['client_cpu_system']['mean']:.1f}% | Idle: {summary['client_cpu_idle']['mean']:.1f}% | Max Core: {summary['client_max_core']['max']:.1f}% | UDP Drops: {summary['client_udp_rcvbuf_drops']}")
    return summary


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/client_res.csv"
    dur = float(sys.argv[2]) if len(sys.argv) > 2 else 10.0
    warm = float(sys.argv[3]) if len(sys.argv) > 3 else 0.0
    iface = sys.argv[4] if len(sys.argv) > 4 else "enp1s0f0"
    sample(out, dur, warm, iface)
