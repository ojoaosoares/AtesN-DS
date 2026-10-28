#!/usr/bin/env python3
import sys
import os
import time
import subprocess
import struct
import json

MAP_PIN = "/sys/fs/bpf/overload_ctrl"
HIGH_WATERMARK_SOFTIRQ = 85.0  # % SoftIRQ on any core
LOW_WATERMARK_SOFTIRQ = 65.0   # % SoftIRQ on all cores
POLL_INTERVAL = 0.1           # 100 ms

def read_proc_stat():
    cores = {}
    try:
        with open("/proc/stat", "r") as f:
            for line in f:
                parts = line.strip().split()
                if not parts:
                    continue
                name = parts[0]
                if name.startswith("cpu") and name != "cpu":
                    # user, nice, system, idle, iowait, irq, softirq, steal
                    vals = [int(x) for x in parts[1:8]]
                    cores[name] = vals
    except Exception:
        pass
    return cores

def compute_softirqs(stat_pre, stat_post):
    core_softirqs = {}
    for name in stat_pre:
        if name not in stat_post:
            continue
        p = stat_pre[name]
        c = stat_post[name]
        diffs = [c[i] - p[i] for i in range(len(p))]
        total = sum(diffs)
        if total > 0:
            softirq_pct = diffs[6] / total * 100.0
            core_softirqs[name] = softirq_pct
    return core_softirqs

LOG_FILE = "/tmp/governor.log"

def log(msg):
    ts = time.strftime('%X')
    entry = f"[{ts}] {msg}"
    print(entry)
    sys.stdout.flush()
    try:
        with open(LOG_FILE, "a") as f:
            f.write(entry + "\n")
    except Exception:
        pass

def set_overload_ctrl(is_ovl, mode=2, ratio=100):
    val_bytes = struct.pack("<IIII", 1 if is_ovl else 0, mode, ratio, 0)
    cmd = [
        "sudo", "-n", "bpftool", "map", "update", "pinned", MAP_PIN,
        "key", "hex", "00", "00", "00", "00",
        "value", "hex"
    ] + [f"{b:02x}" for b in val_bytes]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        log(f"WARN: bpftool update failed (rc={res.returncode}): {res.stderr.strip()}")
    else:
        log(f"INFO: set_overload_ctrl updated: is_ovl={is_ovl}, mode={mode}, ratio={ratio}")

def run_governor():
    print(f"🛡️  Starting AtesN-DS Adaptive Overload Governor...")
    print(f"   Thresholds: High={HIGH_WATERMARK_SOFTIRQ}% (Trigger) | Low={LOW_WATERMARK_SOFTIRQ}% (Restore)")
    print(f"   Poll Interval: {POLL_INTERVAL*1000:.0f} ms")
    
    # Initialize to normal state
    set_overload_ctrl(False, 0, 0)
    currently_overloaded = False

    stat_prev = read_proc_stat()
    time.sleep(POLL_INTERVAL)

    try:
        while True:
            stat_curr = read_proc_stat()
            softirqs = compute_softirqs(stat_prev, stat_curr)
            stat_prev = stat_curr

            if not softirqs:
                time.sleep(POLL_INTERVAL)
                continue

            max_softirq = max(softirqs.values()) if softirqs else 0.0

            # State machine with hysteresis
            if not currently_overloaded:
                if max_softirq >= HIGH_WATERMARK_SOFTIRQ:
                    currently_overloaded = True
                    set_overload_ctrl(True, 2, 100) # Mode 2 = SHED_EARLY_PRE_LOOKUP
                    log(f"🚨 OVERLOAD TRIGGERED! MaxCore SoftIRQ = {max_softirq:.1f}% >= {HIGH_WATERMARK_SOFTIRQ}%. Enabled Early Pre-Lookup Pass.")
            else:
                if max_softirq < LOW_WATERMARK_SOFTIRQ:
                    currently_overloaded = False
                    set_overload_ctrl(False, 0, 0)
                    log(f"🟢 LOAD NORMALIZED! MaxCore SoftIRQ = {max_softirq:.1f}% < {LOW_WATERMARK_SOFTIRQ}%. Restored Normal Driver XDP.")

            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        set_overload_ctrl(False, 0, 0)
        print("\nGovernor stopped. Restored normal mode.")

if __name__ == "__main__":
    run_governor()
