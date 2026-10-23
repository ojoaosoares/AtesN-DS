#!/usr/bin/env python3
# ==============================================================================
# plot_multicore_xdnsperf.py
#
# Publication-quality plotting for multi-core xdnsperf benchmarks:
#   1. Achieved Throughput vs Target QPS (by core count: 1, 2, 4 cores)
#   2. Server CPU Utilization across cores vs Throughput (saturation curve)
#   3. Tail Latency (p99 and p99.9) vs QPS
# ==============================================================================

import os
import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SUMMARY_CSV = os.path.join(BASE_DIR, "summary_multicore_xdnsperf.csv")
RAW_CSV = os.path.join(BASE_DIR, "raw_multicore_xdnsperf.csv")

if not os.path.exists(SUMMARY_CSV) and not os.path.exists(RAW_CSV):
    print(f"Error: Neither {SUMMARY_CSV} nor {RAW_CSV} found.")
    sys.exit(1)

# Color and style definitions
MODE_COLORS = {
    'unbound_standalone': '#d95f02',   # Orange
    'ates_driver':        '#7570b3',   # Purple
    'unbound_hw_cache':   '#1b9e77',   # Green
    'ates_hw_cache':      '#e7298a',   # Magenta / Pink
}

MODE_LABELS = {
    'unbound_standalone': 'Unbound (Userspace)',
    'ates_driver':        'AtesN-DS (XDP Driver)',
    'unbound_hw_cache':   'Unbound + SmartNIC HW',
    'ates_hw_cache':      'AtesN-DS + SmartNIC HW',
}

LINE_STYLES = {
    '1': '-',
    '2': '--',
    '4': '-.',
}

plt.rcParams.update({
    'font.size': 11,
    'axes.labelsize': 12,
    'axes.titlesize': 13,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 9,
    'figure.titlesize': 14,
    'grid.alpha': 0.3,
})

df = pd.read_csv(SUMMARY_CSV if os.path.exists(SUMMARY_CSV) else RAW_CSV)

# Convert types
df['num_cores'] = df['num_cores'].astype(str)
if 'achieved_qps_mean' in df.columns:
    qps_col = 'achieved_qps_mean'
    cpu_col = 'srv_all_busy_mean'
    p99_col = 'lat_p99_ms'
    loss_col = 'loss_pct_mean'
else:
    qps_col = 'achieved_qps'
    cpu_col = 'srv_all_busy'
    p99_col = 'lat_p99_ms'
    loss_col = 'packet_loss_pct'

# Plot 1: Throughput scaling across Cores and Modes
fig, axes = plt.subplots(1, 3, figsize=(18, 5), sharey=True)
core_counts = sorted(df['num_cores'].unique())

for idx, cores in enumerate(['1', '2', '4']):
    if cores not in core_counts:
        continue
    ax = axes[idx]
    cdf = df[df['num_cores'] == cores]

    for mode in ['unbound_standalone', 'ates_driver', 'unbound_hw_cache', 'ates_hw_cache']:
        mdf = cdf[cdf['mode'] == mode]
        if mdf.empty:
            continue
        # Sort by target_qps numerically (handle UNLIMITED as max)
        mdf = mdf.copy()
        mdf['qps_sort'] = mdf['target_qps'].apply(lambda x: 9999999 if str(x) == 'UNLIMITED' or str(x) == '0' else float(x))
        mdf = mdf.sort_values('qps_sort')

        x = range(len(mdf))
        labels = [str(r['target_qps']) for _, r in mdf.iterrows()]
        y = mdf[qps_col] / 1000.0  # kQPS

        ax.plot(x, y, marker='o', linewidth=2, color=MODE_COLORS.get(mode, 'black'), label=MODE_LABELS.get(mode, mode))

    ax.set_title(f"Server: {cores} Core(s)")
    ax.set_xlabel("Target Rate")
    if idx == 0:
        ax.set_ylabel("Achieved Throughput (kQPS)")
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45)
    ax.grid(True)
    if idx == 0:
        ax.legend(loc='upper left')

plt.suptitle("Multi-Core Throughput Scaling with xdnsperf (10GbE Wire Rate)")
plt.tight_layout()
fig_path = os.path.join(BASE_DIR, "multicore_throughput_scaling.png")
plt.savefig(fig_path, dpi=300)
print(f"Saved: {fig_path}")

# Plot 2: CPU Saturation vs Achieved Throughput
plt.figure(figsize=(10, 6))
for cores in ['1', '2', '4']:
    for mode in ['ates_driver', 'ates_hw_cache']:
        mdf = df[(df['num_cores'] == cores) & (df['mode'] == mode)]
        if mdf.empty:
            continue
        mdf = mdf.sort_values(qps_col)
        x = mdf[qps_col] / 1000.0
        y = mdf[cpu_col]
        label = f"{MODE_LABELS[mode]} ({cores}C)"
        plt.plot(x, y, marker='s', linestyle=LINE_STYLES.get(cores, '-'),
                 color=MODE_COLORS[mode], label=label, linewidth=2)

plt.title("Server CPU Saturation vs Achieved Throughput")
plt.xlabel("Achieved Throughput (kQPS)")
plt.ylabel("Server CPU Utilization (%)")
plt.grid(True)
plt.legend()
plt.tight_layout()
fig_cpu = os.path.join(BASE_DIR, "multicore_cpu_saturation.png")
plt.savefig(fig_cpu, dpi=300)
print(f"Saved: {fig_cpu}")
