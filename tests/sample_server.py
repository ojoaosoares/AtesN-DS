#!/usr/bin/env python3

import sys
import os
import time
import csv
import statistics
import psutil
import subprocess
import re
import json


SAMPLE_INTERVAL = 0.2

# Hardware footprint specifications for Netronome Agilio CX 2x10GbE
HW_EBPF_INSTRUCTIONS = 589
HW_INSTRUCTION_BUDGET = 1536
HW_INSTRUCTION_UTILIZATION_PCT = 38.35
HW_KEY_SIZE_BYTES = 56
HW_VALUE_SIZE_BYTES = 8
HW_ENTRY_SIZE_BYTES = 64
HW_TABLE_CAPACITY = 2000000
HW_DRAM_ALLOCATED_MB = 128
HW_DRAM_TOTAL_MB = 2048
HW_DRAM_UTILIZATION_PCT = 6.25


def reset_bpf_dns_misses():
    for target in [["pinned", "/sys/fs/bpf/dns_misses"], ["name", "dns_misses"]]:
        try:
            res = subprocess.run(
                [
                    "sudo", "bpftool", "map", "update", target[0], target[1],
                    "key", "hex", "00", "00", "00", "00",
                    "value", "hex", "00", "00", "00", "00", "00", "00", "00", "00"
                ],
                capture_output=True,
                text=True
            )
            if res.returncode == 0:
                print(f"  BPF dns_misses map reset to 0 ({target[0]} {target[1]}).")
                return
        except Exception:
            pass
    print("  Warning: Failed to reset BPF dns_misses map.", file=sys.stderr)


def _parse_bpf_json(content):
    try:
        data = json.loads(content)
    except Exception:
        return 0

    if not isinstance(data, list):
        return 0

    total = 0
    for item in data:
        # 1. Prefer formatted BTF values if available
        if "formatted" in item and isinstance(item["formatted"], dict) and "values" in item["formatted"]:
            subtotal = 0
            for v in item["formatted"]["values"]:
                if isinstance(v, dict) and "value" in v:
                    try:
                        subtotal += int(v["value"])
                    except Exception:
                        pass
            if subtotal > 0:
                return subtotal

        # 2. Parse raw values array
        if "values" in item and isinstance(item["values"], list):
            for v in item["values"]:
                if not isinstance(v, dict) or "value" not in v:
                    continue
                val = v["value"]
                if isinstance(val, list):
                    # Array of hex bytes like ['0x95', '0xa4', '0x00', ...]
                    try:
                        b = bytes([int(x, 16) for x in val])
                        total += int.from_bytes(b, byteorder="little")
                    except Exception:
                        pass
                elif isinstance(val, (int, float)):
                    total += int(val)
                elif isinstance(val, str):
                    try:
                        total += int(val, 0)
                    except Exception:
                        pass

    return total


def get_bpf_dns_misses():
    for target in [["pinned", "/sys/fs/bpf/dns_misses"], ["name", "dns_misses"]]:
        for bpftool_bin in ["bpftool", "/usr/sbin/bpftool", "/sbin/bpftool"]:
            try:
                res = subprocess.run(
                    ["sudo", bpftool_bin, "-j", "map", "dump", target[0], target[1]],
                    capture_output=True,
                    text=True
                )
                if res.returncode == 0 and res.stdout.strip():
                    total = _parse_bpf_json(res.stdout)
                    if total > 0:
                        return total
            except Exception:
                pass

    return 0


def get_target_interface(specified_iface=None):
    if specified_iface and os.path.exists(f"/sys/class/net/{specified_iface}"):
        return specified_iface
    if os.environ.get("NIC_INTERFACE") and os.path.exists(f"/sys/class/net/{os.environ.get('NIC_INTERFACE')}"):
        return os.environ.get("NIC_INTERFACE")
    for iface in ["enp1s0np1", "enp1s0np0", "enp1s0f0"]:
        if os.path.exists(f"/sys/class/net/{iface}"):
            return iface
    try:
        for iface in os.listdir("/sys/class/net"):
            if iface != "lo":
                return iface
    except Exception:
        pass
    return "enp1s0np1"


def read_sysfs_stats(iface):
    stats = {
        "rx_packets": 0,
        "tx_packets": 0,
        "rx_dropped": 0,
        "tx_dropped": 0,
        "rx_errors": 0,
        "tx_errors": 0,
    }
    base_path = f"/sys/class/net/{iface}/statistics"
    for k in stats.keys():
        path = os.path.join(base_path, k)
        try:
            with open(path, "r") as f:
                stats[k] = int(f.read().strip())
        except Exception:
            pass
    return stats


def read_softirqs():
    stats = {"NET_RX": 0, "NET_TX": 0}
    try:
        with open("/proc/softirqs", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) == 2:
                    name = parts[0].strip()
                    if name in stats:
                        counts = [int(x) for x in parts[1].split() if x.isdigit()]
                        stats[name] = sum(counts)
    except Exception:
        pass
    return stats


def read_nic_interrupts(iface):
    total = 0
    try:
        with open("/proc/interrupts", "r") as f:
            for line in f:
                if iface in line or "ctrl-rxtx" in line:
                    parts = line.split()
                    for p in parts[1:]:
                        if p.isdigit():
                            total += int(p)
                        else:
                            break
    except Exception:
        pass
    return total


def read_ethtool_stats(iface):
    stats = {
        "bpf_pass_pkts": 0,
        "bpf_app2_pkts": 0,
        "dev_rx_discards": 0,
        "mac.rx_drop_events": 0,
    }
    try:
        res = subprocess.run(["sudo", "ethtool", "-S", iface], capture_output=True, text=True)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                m = re.match(r"\s*([a-zA-Z0-9_.]+):\s*(\d+)", line)
                if m and m.group(1) in stats:
                    stats[m.group(1)] = int(m.group(2))
    except Exception:
        pass
    return stats


def count_bpftool_map_keys(map_name):
    for bpftool_bin in ["bpftool", "/usr/sbin/bpftool", "/sbin/bpftool"]:
        try:
            res = subprocess.run(
                ["sudo", bpftool_bin, "map", "dump", "name", map_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            if res.returncode == 0:
                return res.stdout.count("key:")
        except Exception:
            pass
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
    if len(sys.argv) not in (3, 4, 5):
        print(
            f"Usage: {sys.argv[0]} <output.csv> <duration_seconds> [warmup_seconds] [interface]",
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
    if len(sys.argv) >= 4:
        try:
            warmup_seconds = int(sys.argv[3])
            if warmup_seconds < 0:
                raise ValueError("Warmup seconds must be a non-negative integer.")
        except ValueError as e:
            print(f"Error: Invalid warmup seconds: {e}", file=sys.stderr)
            sys.exit(1)

    cli_iface = sys.argv[4] if len(sys.argv) == 5 else None
    iface = get_target_interface(cli_iface)

    print("Starting benchmark monitor")
    print(f"Monitoring NIC interface: {iface}")
    print(f"Warmup time: {warmup_seconds}s")
    print(f"Sampling interval: {SAMPLE_INTERVAL}s")
    print(f"Measurement duration: {duration}s")
    print()

    if warmup_seconds > 0:
        print(f"Waiting {warmup_seconds}s for external benchmark warmup...")
        time.sleep(warmup_seconds)

    # Immediately reset BPF dns_misses after cache warmup phase
    reset_bpf_dns_misses()

    # Pre-measurement hardware and OS telemetry snapshots
    sysfs_start = read_sysfs_stats(iface)
    softirq_start = read_softirqs()
    irq_start = read_nic_interrupts(iface)
    ethtool_start = read_ethtool_stats(iface)

    print("Collecting samples...")
    data = sample(duration)

    # Post-measurement hardware and OS telemetry snapshots
    sysfs_end = read_sysfs_stats(iface)
    softirq_end = read_softirqs()
    irq_end = read_nic_interrupts(iface)
    ethtool_end = read_ethtool_stats(iface)

    cache_misses = get_bpf_dns_misses()
    print(f"  Cache misses collected: {cache_misses}")

    # Compute hardware & networking deltas
    nic_rx_packets = max(0, sysfs_end.get("rx_packets", 0) - sysfs_start.get("rx_packets", 0))
    nic_tx_packets = max(0, sysfs_end.get("tx_packets", 0) - sysfs_start.get("tx_packets", 0))
    nic_rx_dropped = max(0, sysfs_end.get("rx_dropped", 0) - sysfs_start.get("rx_dropped", 0))
    nic_tx_dropped = max(0, sysfs_end.get("tx_dropped", 0) - sysfs_start.get("tx_dropped", 0))
    nic_rx_errors = max(0, sysfs_end.get("rx_errors", 0) - sysfs_start.get("rx_errors", 0))
    nic_tx_errors = max(0, sysfs_end.get("tx_errors", 0) - sysfs_start.get("tx_errors", 0))

    net_rx_softirqs = max(0, softirq_end.get("NET_RX", 0) - softirq_start.get("NET_RX", 0))
    net_tx_softirqs = max(0, softirq_end.get("NET_TX", 0) - softirq_start.get("NET_TX", 0))
    nic_interrupts = max(0, irq_end - irq_start)

    nic_bpf_pass_pkts = max(0, ethtool_end.get("bpf_pass_pkts", 0) - ethtool_start.get("bpf_pass_pkts", 0))
    nic_hw_tx_pkts = max(0, ethtool_end.get("bpf_app2_pkts", 0) - ethtool_start.get("bpf_app2_pkts", 0))
    nic_dev_rx_discards = max(0, ethtool_end.get("dev_rx_discards", 0) - ethtool_start.get("dev_rx_discards", 0))
    hw_cached_domains = count_bpftool_map_keys("level_one_cache")
    driver_cached_domains = count_bpftool_map_keys("cache_arecords")

    print(f"  NIC Interrupts delta: {nic_interrupts}")
    print(f"  Host NET_RX SoftIRQs delta: {net_rx_softirqs}")
    print(f"  NIC RX dropped delta: {nic_rx_dropped}")
    print(f"  NIC BPF passed packets: {nic_bpf_pass_pkts}")
    print(f"  SmartNIC HW Cache TX packets: {nic_hw_tx_pkts}")
    print(f"  SmartNIC HW Cached domains: {hw_cached_domains}")
    print(f"  Driver Cached domains: {driver_cached_domains}")

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

    # Dynamic hardware and kernel network counters
    rows.extend([
        {"metric": "nic_rx_packets", "value": nic_rx_packets},
        {"metric": "nic_tx_packets", "value": nic_tx_packets},
        {"metric": "nic_rx_dropped", "value": nic_rx_dropped},
        {"metric": "nic_tx_dropped", "value": nic_tx_dropped},
        {"metric": "nic_rx_errors", "value": nic_rx_errors},
        {"metric": "nic_tx_errors", "value": nic_tx_errors},
        {"metric": "nic_interrupts", "value": nic_interrupts},
        {"metric": "net_rx_softirqs", "value": net_rx_softirqs},
        {"metric": "net_tx_softirqs", "value": net_tx_softirqs},
        {"metric": "nic_bpf_pass_pkts", "value": nic_bpf_pass_pkts},
        {"metric": "nic_hw_tx_pkts", "value": nic_hw_tx_pkts},
        {"metric": "hw_cached_domains", "value": hw_cached_domains},
        {"metric": "driver_cached_domains", "value": driver_cached_domains},
        {"metric": "nic_dev_rx_discards", "value": nic_dev_rx_discards},
    ])

    # Static NIC hardware resource footprint metrics
    rows.extend([
        {"metric": "hw_ebpf_instructions", "value": HW_EBPF_INSTRUCTIONS},
        {"metric": "hw_instruction_budget", "value": HW_INSTRUCTION_BUDGET},
        {"metric": "hw_instruction_utilization_pct", "value": HW_INSTRUCTION_UTILIZATION_PCT},
        {"metric": "hw_key_size_bytes", "value": HW_KEY_SIZE_BYTES},
        {"metric": "hw_value_size_bytes", "value": HW_VALUE_SIZE_BYTES},
        {"metric": "hw_entry_size_bytes", "value": HW_ENTRY_SIZE_BYTES},
        {"metric": "hw_table_capacity", "value": HW_TABLE_CAPACITY},
        {"metric": "hw_dram_allocated_mb", "value": HW_DRAM_ALLOCATED_MB},
        {"metric": "hw_dram_total_mb", "value": HW_DRAM_TOTAL_MB},
        {"metric": "hw_dram_utilization_pct", "value": HW_DRAM_UTILIZATION_PCT},
    ])

    if os.path.dirname(output_file):
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["metric", "value"])
        writer.writeheader()
        writer.writerows(rows)

    print()
    print(f"Summary written to {output_file}")


if __name__ == "__main__":
    main()