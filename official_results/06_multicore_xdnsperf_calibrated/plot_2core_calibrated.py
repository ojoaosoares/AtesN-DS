#!/usr/bin/env python3
# ==============================================================================
# plot_2core_calibrated.py
#
# Generates publication-ready figures for the 2-Core Benchmark using xdnsperf:
#   1. Achieved Throughput vs Target QPS (with error bars)
#   2. Tail Latency (p99 and p99.9) vs Target QPS (log scale)
#   3. Server CPU Saturation vs Achieved Throughput (Cores 0 & 1)
#   4. Packet Loss Rate (%) vs Target QPS
#
# Generates both 300-DPI PNGs and vector PDFs in both the script directory
# and the top-level results/ directory.
# ==============================================================================

import os
import sys
import shutil
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
RESULTS_DIR = os.path.join(PROJECT_ROOT, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

summary_arg = sys.argv[1] if len(sys.argv) > 1 else "summary_2core_realtrace_10reps.csv"
SUMMARY_CSV = summary_arg if os.path.isabs(summary_arg) else os.path.join(BASE_DIR, summary_arg)

out_dir_arg = sys.argv[2] if len(sys.argv) > 2 else os.path.join(PROJECT_ROOT, "results", "official_post_outliers")
OUTPUT_DIR = out_dir_arg if os.path.isabs(out_dir_arg) else os.path.join(PROJECT_ROOT, out_dir_arg)
os.makedirs(OUTPUT_DIR, exist_ok=True)

if not os.path.exists(SUMMARY_CSV):
    print(f"Error: {SUMMARY_CSV} not found.")
    sys.exit(1)

base_name = os.path.basename(SUMMARY_CSV)
if "busywait" in base_name:
    prefix = "busywait_"
    dataset_title = "Production ISP Trace (Busy-Wait)"
elif "realtrace" in base_name:
    prefix = "realtrace_"
    dataset_title = "Production ISP Trace"
elif "progression" in base_name:
    prefix = "progression_"
    dataset_title = "Traffic Progression"
elif "fast" in base_name:
    prefix = "fast_"
    dataset_title = "Fast Profile"
else:
    prefix = "calibrated_"
    dataset_title = "Synthetic Calibration"

df = pd.read_csv(SUMMARY_CSV)

# Detect repetitions
reps_val = df['reps'].iloc[0] if 'reps' in df.columns and not df.empty else 10

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

def parse_rate(val):
    try:
        return int(val)
    except:
        return 99999999

RATE_ORDER = sorted(df['target_qps'].astype(str).unique(), key=parse_rate)
RATE_LABELS = []
for r in RATE_ORDER:
    if r in ('0', 'UNLIMITED'):
        RATE_LABELS.append('UNLIMITED\n(Line Rate)')
    else:
        try:
            val = int(r)
            if val >= 1000000:
                RATE_LABELS.append(f"{val // 1000000}M" if val % 1000000 == 0 else f"{val / 1000000:.1f}M")
            elif val >= 1000:
                RATE_LABELS.append(f"{val // 1000}k")
            else:
                RATE_LABELS.append(str(val))
        except:
            RATE_LABELS.append(r)

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

def save_and_sync(fig, filename_base):
    for ext in ('.png', '.pdf'):
        fname = f"{filename_base}{ext}"
        p1 = os.path.join(BASE_DIR, fname)
        p2 = os.path.join(RESULTS_DIR, fname)
        p3 = os.path.join(OUTPUT_DIR, fname)
        dpi = 300 if ext == '.png' else None
        fig.savefig(p1, dpi=dpi, bbox_inches='tight')
        fig.savefig(p2, dpi=dpi, bbox_inches='tight')
        fig.savefig(p3, dpi=dpi, bbox_inches='tight')
        print(f"Saved: {p1}")
        print(f"Copied: {p2}")
        print(f"Copied to Output: {p3}")
    plt.close(fig)

# ==============================================================================
# Figure 1: Achieved Throughput (kQPS) vs Target Rate
# ==============================================================================
fig, ax = plt.subplots(figsize=(9, 5.5))
x_indices = np.arange(len(RATE_ORDER))
width = 0.18

for idx, mode in enumerate(MODE_ORDER):
    mdf = df[df['mode'] == mode].copy()
    mdf['target_qps'] = mdf['target_qps'].astype(str)
    
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
ax.set_title(f"2-Core DNS Server Throughput Scaling ({dataset_title}, n={reps_val}, 180s per run)")
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS)
ax.set_xlabel("Target Load Level")
ax.grid(axis='y', linestyle='--', alpha=0.5)
ax.legend(loc='upper left', framealpha=0.92)
plt.tight_layout()
save_and_sync(fig, f"{prefix}2core_throughput_bars")

# ==============================================================================
# Figure 2: Tail Latency (p99 and p99.9 in ms) vs Target Rate
# ==============================================================================
fig, ax = plt.subplots(figsize=(9.5, 5.8))

for mode in MODE_ORDER:
    mdf = df[df['mode'] == mode].copy()
    mdf['target_qps'] = mdf['target_qps'].astype(str)
    
    p99_vals = []
    p99_9_vals = []
    for r in RATE_ORDER:
        row = mdf[mdf['target_qps'] == r]
        if not row.empty:
            p99_vals.append(row['lat_p99_ms'].values[0])
            p99_9_vals.append(row['lat_p99_9_ms'].values[0])
        else:
            p99_vals.append(np.nan)
            p99_9_vals.append(np.nan)
            
    # Solid line with filled circle for p99
    ax.plot(x_indices, p99_vals, marker='o', linewidth=2.2, markersize=6.5, linestyle='-',
            label=f"{MODE_LABELS[mode]} ($p_{{99}}$)", color=MODE_COLORS[mode])
    # Dashed line with open triangle for p99.9
    ax.plot(x_indices, p99_9_vals, marker='^', linewidth=1.8, markersize=6.5, linestyle='--',
            fillstyle='none', label=f"{MODE_LABELS[mode]} ($p_{{99.9}}$)", color=MODE_COLORS[mode], alpha=0.85)

ax.set_ylabel("Response Latency (ms) [Log Scale]")
ax.set_yscale('log')
ax.set_title(f"Tail Latency ($p_{{99}}$ and $p_{{99.9}}$) Across Offered Load ({dataset_title}, n={reps_val})")
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS)
ax.set_xlabel("Target Load Level")
ax.grid(True, which='both', linestyle='--', alpha=0.4)
ax.legend(loc='upper left', ncol=2, framealpha=0.93, fontsize=9.2)
plt.tight_layout()
save_and_sync(fig, f"{prefix}2core_tail_latency")

# ==============================================================================
# Figure 3: Server CPU Saturation vs Achieved Throughput
# ==============================================================================
fig, ax = plt.subplots(figsize=(9, 5.5))

for mode in MODE_ORDER:
    mdf = df[df['mode'] == mode].copy()
    mdf['qps_k'] = mdf['achieved_qps_mean'] / 1000.0
    
    # Calculate utilization of dedicated Core 0 and Core 1
    if 'srv_c0_busy_mean' in mdf.columns and 'srv_c1_busy_mean' in mdf.columns:
        mdf['dedicated_cpu'] = (mdf['srv_c0_busy_mean'] + mdf['srv_c1_busy_mean']) / 2.0
    else:
        mdf['dedicated_cpu'] = mdf['srv_all_busy_mean']
        
    mdf = mdf.sort_values('qps_k')
    
    ax.plot(mdf['qps_k'], mdf['dedicated_cpu'], marker='s', linewidth=2.2, markersize=7,
            label=MODE_LABELS[mode], color=MODE_COLORS[mode])

ax.set_xlabel("Achieved Throughput (kQPS)")
ax.set_ylabel("Dedicated Server Core Utilization (%) [Cores 0 & 1]")
ax.set_title(f"Server CPU Saturation Curve (Cores 0 & 1, 4 RSS Queues, n={reps_val})")
ax.grid(True, linestyle='--', alpha=0.5)
ax.legend(loc='lower right', framealpha=0.92)
plt.tight_layout()
save_and_sync(fig, f"{prefix}2core_cpu_saturation")

# ==============================================================================
# Figure 4: Packet Loss Rate (%) vs Target Rate
# ==============================================================================
fig, ax = plt.subplots(figsize=(9, 5.5))

for mode in MODE_ORDER:
    mdf = df[df['mode'] == mode].copy()
    mdf['target_qps'] = mdf['target_qps'].astype(str)
    
    loss_vals = []
    loss_stds = []
    for r in RATE_ORDER:
        row = mdf[mdf['target_qps'] == r]
        if not row.empty:
            loss_vals.append(row['loss_pct_mean'].values[0])
            loss_stds.append(row['loss_pct_std'].values[0] if 'loss_pct_std' in row else 0.0)
        else:
            loss_vals.append(np.nan)
            loss_stds.append(0.0)
            
    ax.plot(x_indices, loss_vals, marker='D', linewidth=2.2, markersize=6,
            label=MODE_LABELS[mode], color=MODE_COLORS[mode])

ax.set_ylabel("Packet Loss Rate (%)")
ax.set_title(f"Packet Loss Rate vs. Offered Load ({dataset_title}, n={reps_val}, 180s per run)")
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS)
ax.set_xlabel("Target Load Level")
ax.set_ylim(-2, 105)
ax.grid(True, linestyle='--', alpha=0.5)
ax.legend(loc='upper left', framealpha=0.92)
plt.tight_layout()
save_and_sync(fig, f"{prefix}2core_packet_loss")

print("\nAll publication open-loop figures generated and synced successfully.")
