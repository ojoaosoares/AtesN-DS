#!/usr/bin/env python3
# ==============================================================================
# plot_1core_calibrated.py
#
# Generates publication-ready figures for the 1-Core Benchmark using xdnsperf:
#   1. Achieved Throughput vs Target QPS (with error bars)
#   2. Tail Latency (p99 and p99.9) vs Target QPS (log scale)
#   3. Server CPU Saturation vs Achieved Throughput (Core 0)
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
import matplotlib.ticker as ticker

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
RESULTS_DIR = os.path.join(PROJECT_ROOT, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

summary_arg = sys.argv[1] if len(sys.argv) > 1 else "summary_1core_clean_warmup_10reps.csv"
SUMMARY_CSV = summary_arg if os.path.isabs(summary_arg) else os.path.join(BASE_DIR, summary_arg)

out_dir_arg = sys.argv[2] if len(sys.argv) > 2 else BASE_DIR
OUTPUT_DIR = out_dir_arg if os.path.isabs(out_dir_arg) else os.path.join(PROJECT_ROOT, out_dir_arg)
os.makedirs(OUTPUT_DIR, exist_ok=True)

if not os.path.exists(SUMMARY_CSV):
    print(f"Error: {SUMMARY_CSV} not found.")
    sys.exit(1)

dataset_title = "Single-Core Maximum Capacity"
prefix = "calibrated_"

df = pd.read_csv(SUMMARY_CSV)
if df.empty:
    print("CSV is empty.")
    sys.exit(0)

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
    'unbound_standalone': 'Unbound',
    'ates_driver':        'AtesN-DS',
    'unbound_hw_cache':   'Unbound + HW Cache',
    'ates_hw_cache':      'AtesN-DS + HW Cache',
}

MODE_ORDER = ['unbound_standalone', 'unbound_hw_cache', 'ates_driver', 'ates_hw_cache']

def parse_rate(val):
    try:
        v = int(val)
        return 999999999 if v == 0 else v
    except:
        return 999999999

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
    'font.size': 13,
    'axes.labelsize': 15,
    'axes.titlesize': 16,
    'axes.labelweight': 'bold',
    'xtick.labelsize': 13,
    'ytick.labelsize': 13,
    'legend.fontsize': 13,
    'figure.titlesize': 17,
    'font.family': 'sans-serif',
    'lines.linewidth': 2.8,
    'lines.markersize': 8.5,
    'grid.alpha': 0.4,
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
# Figure 1: Achieved Throughput (MQPS) vs Target Rate
# ==============================================================================
fig, ax = plt.subplots(figsize=(10, 6.2))
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
            qps_means.append(row['achieved_qps_mean'].values[0] / 1000000.0)
            qps_stds.append(row['achieved_qps_std'].values[0] / 1000000.0)
        else:
            qps_means.append(0.0)
            qps_stds.append(0.0)
            
    pos = x_indices + (idx - 1.5) * width
    ax.bar(pos, qps_means, width, yerr=qps_stds, capsize=4,
           label=MODE_LABELS[mode], color=MODE_COLORS[mode], edgecolor='black', linewidth=0.8)

ax.set_ylabel("Achieved Throughput (MQPS)", fontsize=15, fontweight='bold', labelpad=8)
ax.set_xlim(-0.65, len(RATE_ORDER) - 0.35)
ax.set_ylim(0, 8.5)
ax.set_yticks(np.arange(0, 9.0, 1.0))
ax.set_title("Achieved DNS Throughput vs. Offered Load", fontweight='bold', pad=12, fontsize=16)
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS, fontsize=13)
ax.tick_params(axis='both', which='major', labelsize=13)
ax.set_xlabel("Target Offered Load", labelpad=10, fontsize=15, fontweight='bold')
ax.grid(axis='y', linestyle='--', alpha=0.5)
ax.legend(loc='upper left', framealpha=0.94, fontsize=13)
plt.tight_layout()
save_and_sync(fig, f"{prefix}1core_throughput_bars")

# ==============================================================================
# Figure 2a: Tail Latency (p99 in ms) vs Target Rate - SEPARATE
# ==============================================================================
fig, ax = plt.subplots(figsize=(10, 6.2))
ticks = [2, 3, 5, 7, 10, 15, 20, 30, 50, 75, 100]

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
            
    ax.plot(x_indices, p99_vals, marker='o', linewidth=2.8, markersize=8.5, linestyle='-',
            label=MODE_LABELS[mode], color=MODE_COLORS[mode])

ax.set_ylabel("Tail Latency $p_{99}$ (ms) [Log Scale]", fontsize=15, fontweight='bold', labelpad=8)
ax.set_yscale('log')
ax.set_ylim(bottom=1.8, top=135)
ax.set_yticks(ticks)
ax.yaxis.set_major_formatter(ticker.ScalarFormatter())
ax.yaxis.set_minor_formatter(ticker.NullFormatter())
ax.set_title("Tail Latency $p_{99}$ vs. Offered Load", fontweight='bold', pad=12, fontsize=16)
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS, fontsize=13)
ax.tick_params(axis='both', which='major', labelsize=13)
ax.set_xlabel("Target Offered Load", labelpad=10, fontsize=15, fontweight='bold')
ax.grid(True, which='both', linestyle='--', alpha=0.5)
ax.legend(loc='upper right', framealpha=0.94, fontsize=13)
plt.tight_layout()
save_and_sync(fig, f"{prefix}1core_tail_latency_p99")

# ==============================================================================
# Figure 2b: Tail Latency (p99.9 in ms) vs Target Rate - SEPARATE
# ==============================================================================
fig, ax = plt.subplots(figsize=(10, 6.2))

for mode in MODE_ORDER:
    mdf = df[df['mode'] == mode].copy()
    mdf['target_qps'] = mdf['target_qps'].astype(str)
    
    p99_9_vals = []
    for r in RATE_ORDER:
        row = mdf[mdf['target_qps'] == r]
        if not row.empty:
            p99_9_vals.append(row['lat_p99_9_ms'].values[0])
        else:
            p99_9_vals.append(np.nan)
            
    ax.plot(x_indices, p99_9_vals, marker='^', linewidth=2.8, markersize=8.5, linestyle='-',
            label=MODE_LABELS[mode], color=MODE_COLORS[mode])

ax.set_ylabel("Tail Latency $p_{99.9}$ (ms) [Log Scale]", fontsize=15, fontweight='bold', labelpad=8)
ax.set_yscale('log')
ax.set_ylim(bottom=1.8, top=135)
ax.set_yticks(ticks)
ax.yaxis.set_major_formatter(ticker.ScalarFormatter())
ax.yaxis.set_minor_formatter(ticker.NullFormatter())
ax.set_title("Tail Latency $p_{99.9}$ vs. Offered Load", fontweight='bold', pad=12, fontsize=16)
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS, fontsize=13)
ax.tick_params(axis='both', which='major', labelsize=13)
ax.set_xlabel("Target Offered Load", labelpad=10, fontsize=15, fontweight='bold')
ax.grid(True, which='both', linestyle='--', alpha=0.5)
ax.legend(loc='upper right', framealpha=0.94, fontsize=13)
plt.tight_layout()
save_and_sync(fig, f"{prefix}1core_tail_latency_p99_9")

# Also maintain combined figure for reference
fig, ax = plt.subplots(figsize=(10, 6.2))
for mode in MODE_ORDER:
    mdf = df[df['mode'] == mode].copy()
    mdf['target_qps'] = mdf['target_qps'].astype(str)
    p99_vals = [mdf[mdf['target_qps'] == r]['lat_p99_ms'].values[0] if not mdf[mdf['target_qps'] == r].empty else np.nan for r in RATE_ORDER]
    p99_9_vals = [mdf[mdf['target_qps'] == r]['lat_p99_9_ms'].values[0] if not mdf[mdf['target_qps'] == r].empty else np.nan for r in RATE_ORDER]
    ax.plot(x_indices, p99_vals, marker='o', linewidth=2.6, markersize=8, linestyle='-',
            label=f"{MODE_LABELS[mode]} ($p_{{99}}$)", color=MODE_COLORS[mode])
    ax.plot(x_indices, p99_9_vals, marker='^', linewidth=2.2, markersize=8, linestyle='--',
            fillstyle='none', label=f"{MODE_LABELS[mode]} ($p_{{99.9}}$)", color=MODE_COLORS[mode], alpha=0.85)
ax.set_ylabel("Response Latency (ms) [Log Scale]", fontsize=15, fontweight='bold', labelpad=8)
ax.set_yscale('log')
ax.set_ylim(bottom=1.8, top=135)
ax.set_yticks(ticks)
ax.yaxis.set_major_formatter(ticker.ScalarFormatter())
ax.yaxis.set_minor_formatter(ticker.NullFormatter())
ax.set_title("Tail Latency vs. Offered Load", fontweight='bold', pad=12, fontsize=16)
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS, fontsize=13)
ax.tick_params(axis='both', which='major', labelsize=13)
ax.set_xlabel("Target Offered Load", labelpad=10, fontsize=15, fontweight='bold')
ax.grid(True, which='both', linestyle='--', alpha=0.4)
ax.legend(loc='upper right', ncol=2, framealpha=0.94, fontsize=11.5)
plt.tight_layout()
save_and_sync(fig, f"{prefix}1core_tail_latency")

# ==============================================================================
# Figure 3: Server CPU Saturation vs Achieved Throughput
# ==============================================================================
fig, ax = plt.subplots(figsize=(10, 6.2))

for mode in MODE_ORDER:
    mdf = df[df['mode'] == mode].copy()
    mdf['qps_m'] = mdf['achieved_qps_mean'] / 1000000.0
    
    if 'srv_c0_busy_mean' in mdf.columns:
        mdf['dedicated_cpu'] = mdf['srv_c0_busy_mean']
    else:
        mdf['dedicated_cpu'] = mdf['srv_all_busy_mean']
        
    mdf = mdf.sort_values('qps_m')
    
    ax.plot(mdf['qps_m'], mdf['dedicated_cpu'], marker='s', linewidth=2.8, markersize=8.5,
            label=MODE_LABELS[mode], color=MODE_COLORS[mode])

ax.set_xlabel("Achieved Throughput (MQPS)", fontsize=15, fontweight='bold', labelpad=10)
ax.set_xlim(-0.35, 8.35)
ax.set_xticks(np.arange(0, 9.0, 1.0))
ax.tick_params(axis='both', which='major', labelsize=13)
ax.set_ylabel("Dedicated Server Core Utilization (%)", fontsize=15, fontweight='bold', labelpad=8)
ax.set_ylim(-2, 103)
ax.set_title("Server CPU Saturation Curve", fontweight='bold', pad=12, fontsize=16)
ax.grid(True, linestyle='--', alpha=0.5)
ax.legend(loc='lower right', framealpha=0.94, fontsize=13)
plt.tight_layout()
save_and_sync(fig, f"{prefix}1core_cpu_saturation")

# ==============================================================================
# Figure 4: Packet Loss Rate (%) vs Target Rate
# ==============================================================================
fig, ax = plt.subplots(figsize=(10, 6.2))

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
            
    ax.plot(x_indices, loss_vals, marker='D', linewidth=2.8, markersize=8.5,
            label=MODE_LABELS[mode], color=MODE_COLORS[mode])

ax.set_ylabel("Packet Loss Rate (%)", fontsize=15, fontweight='bold', labelpad=8)
ax.set_title("Packet Loss Rate vs. Offered Load", fontweight='bold', pad=12, fontsize=16)
ax.set_xlim(-0.5, len(RATE_ORDER) - 0.5)
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS, fontsize=13)
ax.tick_params(axis='both', which='major', labelsize=13)
ax.set_xlabel("Target Offered Load", labelpad=10, fontsize=15, fontweight='bold')
ax.set_ylim(-2, 105)
ax.grid(True, linestyle='--', alpha=0.5)
ax.legend(loc='center right', bbox_to_anchor=(0.96, 0.68), framealpha=0.95, fontsize=13)
plt.tight_layout()
save_and_sync(fig, f"{prefix}1core_packet_loss")

print("\nAll publication 1-core figures generated and synced successfully.")
