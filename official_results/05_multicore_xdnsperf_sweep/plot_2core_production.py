#!/usr/bin/env python3
# ==============================================================================
# plot_2core_production.py
#
# Generates publication-ready figures for the 2-Core Production Benchmark (n=30)
# using xdnsperf results:
#   1. Achieved Throughput vs Target QPS (with error bars)
#   2. Tail Latency (p99 and p99.9) vs Target QPS
#   3. Server CPU Saturation and SoftIRQ vs Throughput
# ==============================================================================

import os
import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SUMMARY_CSV = os.path.join(BASE_DIR, "summary_2core_production_30reps.csv")

if not os.path.exists(SUMMARY_CSV):
    print(f"Error: {SUMMARY_CSV} not found.")
    sys.exit(1)

df = pd.read_csv(SUMMARY_CSV)

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
    'unbound_hw_cache':   'Unbound + SmartNIC HW Cache',
    'ates_hw_cache':      'AtesN-DS + SmartNIC HW Cache',
}

MODE_ORDER = ['unbound_standalone', 'unbound_hw_cache', 'ates_driver', 'ates_hw_cache']

RATE_ORDER = ['200000', '500000', '1000000', '2000000', 'UNLIMITED']
RATE_LABELS = ['200k', '500k', '1M', '2M', 'UNLIMITED\n(Line Rate)']

plt.rcParams.update({
    'font.size': 11,
    'axes.labelsize': 12,
    'axes.titlesize': 13,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 10,
    'figure.titlesize': 14,
    'grid.alpha': 0.3,
})

# ==============================================================================
# Figure 1: Achieved Throughput (kQPS) vs Target Rate
# ==============================================================================
fig, ax = plt.subplots(figsize=(9, 5.5))

x_indices = np.arange(len(RATE_ORDER))
width = 0.18

for idx, mode in enumerate(MODE_ORDER):
    mdf = df[df['mode'] == mode].copy()
    mdf['target_qps'] = mdf['target_qps'].astype(str)
    
    # Align by RATE_ORDER
    qps_means = []
    qps_stds = []
    for r in RATE_ORDER:
        row = mdf[mdf['target_qps'] == r]
        if not row.empty:
            qps_means.append(row['achieved_qps_mean'].values[0] / 1000.0)
            qps_stds.append(row['achieved_qps_std'].values[0] / 1000.0)
        else:
            qps_means.append(0.0)
            qps_stds.append(0.0)
            
    pos = x_indices + (idx - 1.5) * width
    ax.bar(pos, qps_means, width, yerr=qps_stds, capsize=4,
           label=MODE_LABELS[mode], color=MODE_COLORS[mode], edgecolor='black', linewidth=0.8)

ax.set_ylabel("Achieved Throughput (kQPS)")
ax.set_title("2-Core DNS Server Throughput Scaling (xdnsperf, n=30, 60s per run)")
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS)
ax.set_xlabel("Target Load Level")
ax.grid(axis='y', linestyle='--', alpha=0.5)
ax.legend(loc='upper left', framealpha=0.9)
plt.tight_layout()

out1 = os.path.join(BASE_DIR, "production_2core_throughput_bars.png")
plt.savefig(out1, dpi=300)
print(f"Saved: {out1}")
plt.close()

# ==============================================================================
# Figure 2: Tail Latency (p99 in ms) vs Target Rate
# ==============================================================================
fig, ax = plt.subplots(figsize=(9, 5.5))

for mode in MODE_ORDER:
    mdf = df[df['mode'] == mode].copy()
    mdf['target_qps'] = mdf['target_qps'].astype(str)
    
    p99_vals = []
    for r in RATE_ORDER:
        row = mdf[mdf['target_qps'] == r]
        if not row.empty:
            p99_vals.append(row['lat_p99_ms'].values[0])
        else:
            p99_vals.append(np.nan)
            
    ax.plot(x_indices, p99_vals, marker='o', linewidth=2.2, markersize=7,
            label=MODE_LABELS[mode], color=MODE_COLORS[mode])

ax.set_ylabel("99th Percentile Response Latency (ms)")
ax.set_yscale('log')
ax.set_title("Tail Latency (p99) Across Load Levels (2 Dedicated Cores, n=30)")
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS)
ax.set_xlabel("Target Load Level")
ax.grid(True, which='both', linestyle='--', alpha=0.4)
ax.legend(loc='upper left', framealpha=0.9)
plt.tight_layout()

out2 = os.path.join(BASE_DIR, "production_2core_tail_latency.png")
plt.savefig(out2, dpi=300)
print(f"Saved: {out2}")
plt.close()

# ==============================================================================
# Figure 3: CPU Saturation vs Achieved Throughput
# ==============================================================================
fig, ax = plt.subplots(figsize=(9, 5.5))

for mode in MODE_ORDER:
    mdf = df[df['mode'] == mode].copy()
    mdf['qps_k'] = mdf['achieved_qps_mean'] / 1000.0
    mdf = mdf.sort_values('qps_k')
    
    ax.plot(mdf['qps_k'], mdf['srv_all_busy_mean'], marker='s', linewidth=2.2, markersize=7,
            label=MODE_LABELS[mode], color=MODE_COLORS[mode])

ax.set_xlabel("Achieved Throughput (kQPS)")
ax.set_ylabel("Total Server CPU Utilization (%)")
ax.set_title("Server CPU Saturation Curve (2 Cores: Core 0 & Core 1, n=30)")
ax.grid(True, linestyle='--', alpha=0.5)
ax.legend(loc='lower right', framealpha=0.9)
plt.tight_layout()

out3 = os.path.join(BASE_DIR, "production_2core_cpu_saturation.png")
plt.savefig(out3, dpi=300)
print(f"Saved: {out3}")
plt.close()

print("All publication figures generated successfully.")
