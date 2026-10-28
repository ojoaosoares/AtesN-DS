#!/usr/bin/env python3
# ==============================================================================
# plot_suite_10rep_identical.py
#
# Generates the exact same publication-ready suite of 20+ figures as the
# calibrated 10-repetition benchmark, adapted to the PCIe Gen 2 sweep dataset.
# ==============================================================================

import os
import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import matplotlib.patches as mpatches

plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams.update({
    'font.size': 15,
    'axes.labelsize': 19,
    'axes.titlesize': 21,
    'axes.labelweight': 'bold',
    'xtick.labelsize': 15,
    'ytick.labelsize': 15,
    'legend.fontsize': 14.5,
    'figure.titlesize': 22,
    'font.family': 'sans-serif',
    'lines.linewidth': 3.2,
    'lines.markersize': 9.5,
    'grid.alpha': 0.45,
})

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PLOTS_DIR = os.path.join(BASE_DIR, "plots_pcie2_sweep")
os.makedirs(PLOTS_DIR, exist_ok=True)
RAW_CSV = os.path.join(BASE_DIR, "raw_official_pcie2_sweep.csv")

if not os.path.exists(RAW_CSV):
    print(f"Error: {RAW_CSV} not found.")
    sys.exit(1)

df = pd.read_csv(RAW_CSV)
df['srv_dedicated_busy'] = (df['srv_c0_busy'] + df['srv_c1_busy']) / 2.0

MODE_COLORS = {
    'unbound_standalone': '#d95f02',   # Orange
    'ates_driver':        '#7570b3',   # Purple
    'unbound_hw_cache':   '#1b9e77',   # Green
    'ates_hw_cache':      '#e7298a',   # Magenta
}

MODE_LABELS = {
    'unbound_standalone': 'Unbound',
    'ates_driver':        'AtesN-DS Driver',
    'unbound_hw_cache':   'Unbound + HW Cache',
    'ates_hw_cache':      'AtesN-DS + HW Cache',
}

MODE_MARKERS = {
    'unbound_standalone': 'o',
    'ates_driver':        's',
    'unbound_hw_cache':   '^',
    'ates_hw_cache':      'D',
}

MODE_ORDER = ['unbound_standalone', 'unbound_hw_cache', 'ates_driver', 'ates_hw_cache']

def parse_rate(val):
    try:
        v = int(val)
        return 999999999 if v == 0 else v
    except:
        return 999999999

RATE_ORDER = sorted(df['target_qps'].unique(), key=parse_rate)
RATE_LABELS = []
for r in RATE_ORDER:
    if r in (0, '0', 'UNLIMITED'):
        RATE_LABELS.append('UNLIMITED\n(Line Rate)')
    elif r >= 1000000:
        RATE_LABELS.append(f"{r // 1000000}M" if r % 1000000 == 0 else f"{r / 1000000:.1f}M")
    elif r >= 1000:
        RATE_LABELS.append(f"{r // 1000}k")
    else:
        RATE_LABELS.append(str(r))

x_indices = np.arange(len(RATE_ORDER))

def save_plot(fig, filename_base):
    p_png = os.path.join(PLOTS_DIR, f"{filename_base}.png")
    p_pdf = os.path.join(PLOTS_DIR, f"{filename_base}.pdf")
    fig.savefig(p_png, dpi=300, bbox_inches='tight')
    fig.savefig(p_pdf, bbox_inches='tight')
    print(f"✓ Generated: {filename_base}.png & .pdf")
    plt.close(fig)

def plot_line_metric(col_name, ylabel, title, filename_base, log_scale=False, y_min=None, y_max=None,
                     legend_loc='best', bbox_to_anchor=None, custom_yticks=None):
    if bbox_to_anchor is not None and bbox_to_anchor[0] > 1.0:
        fig, ax = plt.subplots(figsize=(10.2, 5.6))
    else:
        fig, ax = plt.subplots(figsize=(8.6, 5.6))
    for mode in MODE_ORDER:
        mdf = df[df['mode'] == mode]
        means = []
        stds = []
        for r in RATE_ORDER:
            sub = mdf[mdf['target_qps'] == r]
            if not sub.empty:
                means.append(sub[col_name].mean())
                stds.append(sub[col_name].std())
            else:
                means.append(np.nan)
                stds.append(np.nan)
        ax.errorbar(x_indices, means, yerr=stds, marker=MODE_MARKERS[mode],
                    linewidth=3.2, markersize=9.5, capsize=4.5,
                    label=MODE_LABELS[mode], color=MODE_COLORS[mode])
    
    if log_scale:
        ax.set_yscale('log')
    
    if custom_yticks is not None:
        ax.set_yticks(custom_yticks)
        
    if y_min is not None or y_max is not None:
        ax.set_ylim(bottom=y_min, top=y_max)
        
    ax.set_ylabel(ylabel, fontsize=19, fontweight='bold', labelpad=10)
    ax.set_title(title, fontweight='bold', pad=14, fontsize=20)
    ax.set_xlim(-0.5, len(RATE_ORDER) - 0.5)
    ax.set_xticks(x_indices)
    ax.set_xticklabels(RATE_LABELS, fontsize=15)
    ax.tick_params(axis='both', which='major', labelsize=15)
    ax.set_xlabel("Target Offered Load", labelpad=12, fontsize=19, fontweight='bold')
    ax.grid(True, which='both', linestyle='--', alpha=0.45)
    if bbox_to_anchor is not None:
        ax.legend(loc=legend_loc, bbox_to_anchor=bbox_to_anchor, framealpha=0.95, fontsize=14)
    else:
        ax.legend(loc=legend_loc, framealpha=0.94, fontsize=14)
    plt.tight_layout()
    save_plot(fig, filename_base)

# 1. CCDF Suite
print("\n--- 1. Generating CCDF Suite ---")
P_MAP = [
    ('lat_min_ms',   1.0),
    ('lat_p50_ms',   0.50),
    ('lat_p75_ms',   0.25),
    ('lat_p90_ms',   0.10),
    ('lat_p95_ms',   0.05),
    ('lat_p99_ms',   0.01),
    ('lat_p99_9_ms', 0.001),
    ('lat_max_ms',   0.0001),
]

for rate in RATE_ORDER:
    fig, ax = plt.subplots(figsize=(8.6, 5.6))
    if rate >= 1000000:
        r_str = f"{rate//1000000}MQPS" if rate % 1000000 == 0 else f"{rate/1000000:.1f}MQPS"
        r_title = f"{rate/1000000:.1f} MQPS".replace(".0", "")
    else:
        r_str = f"{rate//1000}kQPS"
        r_title = f"{rate//1000} kQPS"
        
    for mode in MODE_ORDER:
        if mode == 'unbound_standalone' and rate > 1000000:
            continue
        sub = df[(df['mode'] == mode) & (df['target_qps'] == rate)]
        if sub.empty: continue
        lat_coords = [sub[col].mean() for col, _ in P_MAP]
        ccdf_coords = [c for _, c in P_MAP]
        ax.plot(lat_coords, ccdf_coords, label=MODE_LABELS[mode], color=MODE_COLORS[mode],
                marker=MODE_MARKERS[mode], linewidth=3.2, markersize=9.5, alpha=0.9)
                
    ax.set_yscale('log')
    ax.set_ylim(0.00008, 1.3)
    ax.set_ylabel(r"CCDF: $P(\mathrm{Latency} > x)$", fontsize=18, fontweight='bold', labelpad=10)
    ax.set_yticks([1.0, 0.5, 0.1, 0.01, 0.001, 0.0001])
    ax.set_yticklabels(['1.0 (min)', '0.50 ($p_{50}$)', '0.10 ($p_{90}$)', '0.01 ($p_{99}$)', '0.001 ($p_{99.9}$)', '0.0001 (max)'], fontsize=14)
    ax.tick_params(axis='x', which='major', labelsize=15)
    ax.set_xlabel("Response Latency (ms)", fontsize=18, fontweight='bold', labelpad=12)
    ax.set_title(f"Latency CCDF at {r_title}", fontweight='bold', pad=14, fontsize=20)
    ax.grid(True, which='both', linestyle='--', alpha=0.5)
    if rate in [500000, 1000000]:
        ax.legend(loc='lower left', bbox_to_anchor=(-0.008, 0.02), borderpad=0.35, handletextpad=0.4, framealpha=0.94, fontsize=13)
    else:
        ax.legend(loc='upper right', framealpha=0.94, fontsize=14)
    plt.tight_layout()
    save_plot(fig, f"calibrated_2core_ccdf_{r_str}")

# Combined 2x2 CCDF Grid
SCENARIOS = [
    (500000,  "500 kQPS Offered Load"),
    (1000000, "1.0 MQPS Offered Load"),
    (2500000, "2.5 MQPS Offered Load"),
    (4000000, "4.0 MQPS Offered Load"),
]

fig, axes = plt.subplots(2, 2, figsize=(15, 11), sharey=True)
axes_flat = axes.flatten()

for idx, (qps, title) in enumerate(SCENARIOS):
    ax = axes_flat[idx]
    for mode in MODE_ORDER:
        if mode == 'unbound_standalone' and qps > 1000000:
            continue
        sub = df[(df['mode'] == mode) & (df['target_qps'] == qps)]
        if sub.empty: continue
        lat_coords = [sub[col].mean() for col, _ in P_MAP]
        ccdf_coords = [c for _, c in P_MAP]
        ax.plot(lat_coords, ccdf_coords, label=MODE_LABELS[mode], color=MODE_COLORS[mode],
                marker=MODE_MARKERS[mode], linewidth=2.8, markersize=8.0, alpha=0.9)
    ax.set_yscale('log')
    ax.set_ylim(0.00008, 1.3)
    ax.set_title(title, fontweight='bold', pad=10, fontsize=17)
    ax.set_xlabel("Response Latency (ms)", fontsize=16, fontweight='bold', labelpad=8)
    ax.tick_params(axis='both', which='major', labelsize=14)
    ax.grid(True, which='both', linestyle='--', alpha=0.5)
    if idx % 2 == 0:
        ax.set_ylabel(r"CCDF: $P(\mathrm{Latency} > x)$", fontsize=16, fontweight='bold', labelpad=8)
        ax.set_yticks([1.0, 0.5, 0.1, 0.01, 0.001, 0.0001])
        ax.set_yticklabels(['1.0 (min)', '0.50 ($p_{50}$)', '0.10 ($p_{90}$)', '0.01 ($p_{99}$)', '0.001 ($p_{99.9}$)', '0.0001 (max)'], fontsize=13)
    if qps in [500000, 1000000]:
        ax.legend(loc='lower left', bbox_to_anchor=(-0.008, 0.02), borderpad=0.35, handletextpad=0.4, framealpha=0.94, fontsize=12)
    else:
        ax.legend(loc='upper right', framealpha=0.94, fontsize=13)

plt.suptitle("Latency Complementary Cumulative Distribution Function (CCDF)", fontsize=20, y=0.99, fontweight='bold')
plt.tight_layout()
save_plot(fig, "calibrated_2core_ccdf_operational_2x2")

# 2. Latency Suite
print("\n--- 2. Generating Latency Suite (Separated) ---")
plot_line_metric('lat_mean_ms', "Mean Latency (ms) [Log Scale]",
                 "Mean Response Latency vs. Offered Load",
                 "calibrated_2core_latency_mean", log_scale=True)
plot_line_metric('lat_p50_ms', "Median ($p_{50}$) Latency (ms) [Log Scale]",
                 "Median ($p_{50}$) Latency vs. Offered Load",
                 "calibrated_2core_latency_p50", log_scale=True)
plot_line_metric('lat_p90_ms', "90th Percentile ($p_{90}$) Latency (ms)",
                 "90th Percentile ($p_{90}$) Latency vs. Offered Load",
                 "calibrated_2core_latency_p90", log_scale=True)
plot_line_metric('lat_p99_ms', "Tail Latency $p_{99}$ (ms) [Log Scale]",
                 "Tail Latency $p_{99}$ vs. Offered Load",
                 "calibrated_2core_latency_p99_separate", log_scale=True, legend_loc='upper right')
plot_line_metric('lat_p99_ms', "Tail Latency $p_{99}$ (ms) [Log Scale]",
                 "Tail Latency $p_{99}$ vs. Offered Load",
                 "calibrated_2core_tail_latency_p99", log_scale=True, legend_loc='upper right')
plot_line_metric('lat_p99_ms', "Tail Latency $p_{99}$ (ms)",
                 "Tail Latency $p_{99}$ vs. Offered Load",
                 "calibrated_2core_tail_latency_p99_linear", log_scale=False, y_min=0, y_max=110,
                 custom_yticks=np.arange(0, 120, 10), legend_loc='upper right')
plot_line_metric('lat_p99_9_ms', "Tail Latency $p_{99.9}$ (ms) [Log Scale]",
                 "Tail Latency $p_{99.9}$ vs. Offered Load",
                 "calibrated_2core_latency_p99_9_separate", log_scale=True, legend_loc='upper right')
plot_line_metric('lat_p99_9_ms', "Tail Latency $p_{99.9}$ (ms) [Log Scale]",
                 "Tail Latency $p_{99.9}$ vs. Offered Load",
                 "calibrated_2core_tail_latency_p99_9", log_scale=True, legend_loc='upper right')
plot_line_metric('lat_max_ms', "Maximum Latency (ms) [Log Scale]",
                 "Maximum Recorded Latency vs. Offered Load",
                 "calibrated_2core_latency_max_separate", log_scale=True)
plot_line_metric('lat_std_ms', "Latency Std Dev (ms) [Log Scale]",
                 "Response Latency Std Dev vs. Offered Load",
                 "calibrated_2core_latency_std", log_scale=True)

# 3. Throughput & Packet Loss Suite
print("\n--- 3. Generating Throughput & Packet Loss Suite ---")
fig, ax = plt.subplots(figsize=(8.8, 5.6))
width = 0.18
for idx, mode in enumerate(MODE_ORDER):
    mdf = df[df['mode'] == mode]
    qps_means = []
    qps_stds = []
    for r in RATE_ORDER:
        sub = mdf[mdf['target_qps'] == r]
        qps_means.append(sub['achieved_qps'].mean() / 1e6 if not sub.empty else 0)
        qps_stds.append(sub['achieved_qps'].std() / 1e6 if not sub.empty else 0)
    pos = x_indices + (idx - 1.5) * width
    ax.bar(pos, qps_means, width, yerr=qps_stds, capsize=4.5,
           label=MODE_LABELS[mode], color=MODE_COLORS[mode], edgecolor='black', linewidth=0.8)

ax.set_ylabel("Achieved Throughput (MQPS)", fontsize=19, fontweight='bold', labelpad=10)
ax.set_xlim(-0.65, len(RATE_ORDER) - 0.35)
ax.set_ylim(0, 5.0)
ax.set_title("Achieved DNS Throughput vs. Offered Load", fontweight='bold', pad=14, fontsize=20)
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS, fontsize=15)
ax.tick_params(axis='both', which='major', labelsize=15)
ax.set_xlabel("Target Offered Load", labelpad=12, fontsize=19, fontweight='bold')
ax.grid(axis='y', linestyle='--', alpha=0.5)
ax.legend(loc='upper left', framealpha=0.94, fontsize=14)
plt.tight_layout()
save_plot(fig, "calibrated_2core_throughput_bars")

# Throughput Scaling Line
fig, ax = plt.subplots(figsize=(8.6, 5.6))
ideal_qps = [r / 1e6 for r in RATE_ORDER]
ax.plot(x_indices, ideal_qps, 'k--', linewidth=2.2, alpha=0.6, label='Ideal Offered Load')
for mode in ['ates_hw_cache', 'ates_driver', 'unbound_hw_cache', 'unbound_standalone']:
    mdf = df[df['mode'] == mode]
    means = [mdf[mdf['target_qps'] == r]['achieved_qps'].mean() / 1e6 for r in RATE_ORDER]
    stds = [mdf[mdf['target_qps'] == r]['achieved_qps'].std() / 1e6 for r in RATE_ORDER]
    ax.errorbar(x_indices, means, yerr=stds, marker=MODE_MARKERS[mode], linewidth=3.2, markersize=9.5,
                capsize=4.5, label=MODE_LABELS[mode], color=MODE_COLORS[mode])

ax.set_ylabel("Achieved Throughput (MQPS)", fontsize=19, fontweight='bold', labelpad=10)
ax.set_xlim(-0.5, len(RATE_ORDER) - 0.5)
ax.set_ylim(-0.15, 4.8)
major_y = np.arange(0.0, 5.0, 0.5)
ax.set_yticks(major_y)
ax.set_title("Throughput Scaling Curve vs. Offered Load", fontweight='bold', pad=14, fontsize=20)
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS, fontsize=15)
ax.tick_params(axis='both', which='major', labelsize=15)
ax.set_xlabel("Target Offered Load", labelpad=12, fontsize=19, fontweight='bold')
ax.grid(True, which='major', axis='y', linestyle='--', alpha=0.6, color='#aaaaaa', linewidth=1.1)
ax.legend(loc='upper left', framealpha=0.95, fontsize=14)
plt.tight_layout()
save_plot(fig, "calibrated_2core_throughput_scaling_line")

# Packet Loss
plot_line_metric('packet_loss_pct', "Packet Loss Rate (%)",
                 "Packet Loss Rate vs. Offered Load",
                 "calibrated_2core_packet_loss_linear", y_min=-2, y_max=103,
                 legend_loc='center left', bbox_to_anchor=(0.04, 0.28))
save_plot(fig, "calibrated_2core_packet_loss")

# CPU Suite
print("\n--- 4. Generating Hardware & CPU Suite ---")
plot_line_metric('srv_dedicated_busy', "Dedicated CPU Utilization (%)",
                 "Dedicated Server Core Utilization vs. Offered Load",
                 "calibrated_2core_cpu_cores_active", y_min=-2, y_max=103,
                 legend_loc='center left', bbox_to_anchor=(0.04, 0.55))

fig, ax = plt.subplots(figsize=(8.6, 5.6))
for mode in MODE_ORDER:
    mdf = df[df['mode'] == mode].copy()
    grouped = mdf.groupby('target_qps')[['achieved_qps', 'srv_dedicated_busy']].mean().reset_index()
    grouped['qps_m'] = grouped['achieved_qps'] / 1e6
    grouped = grouped.sort_values('qps_m')
    ax.plot(grouped['qps_m'], grouped['srv_dedicated_busy'], marker=MODE_MARKERS[mode],
            linewidth=3.2, markersize=9.5, label=MODE_LABELS[mode], color=MODE_COLORS[mode])

ax.set_xlabel("Achieved Throughput (MQPS)", fontsize=19, fontweight='bold', labelpad=12)
ax.set_xlim(-0.2, 4.5)
ax.tick_params(axis='both', which='major', labelsize=15)
ax.set_ylabel("Dedicated CPU Utilization (%)", fontsize=19, fontweight='bold', labelpad=10)
ax.set_ylim(-2, 103)
ax.set_title("Server CPU Saturation Curve", fontweight='bold', pad=14, fontsize=20)
ax.grid(True, linestyle='--', alpha=0.5)
ax.legend(loc='lower right', framealpha=0.94, fontsize=14)
plt.tight_layout()
save_plot(fig, "calibrated_2core_cpu_saturation_curve")

# Hardware Hit Rate
fig, ax = plt.subplots(figsize=(8.6, 5.6))
for mode in ['unbound_hw_cache', 'ates_hw_cache']:
    mdf = df[df['mode'] == mode]
    hit_rates = []
    for r in RATE_ORDER:
        sub = mdf[mdf['target_qps'] == r]
        hr = (sub['hw_cache_hits'] / sub['queries_sent'] * 100.0).mean()
        hit_rates.append(hr)
    ax.plot(x_indices, hit_rates, marker=MODE_MARKERS[mode], linewidth=3.2, markersize=9.5,
            label=f"{MODE_LABELS[mode]}", color=MODE_COLORS[mode])

ax.set_ylabel("HW Ingress Hit Rate (%)", fontsize=19, fontweight='bold', labelpad=10)
ax.set_title("Hardware Cache Ingress Hit Rate", fontweight='bold', pad=14, fontsize=20)
ax.set_xlim(-0.5, len(RATE_ORDER) - 0.5)
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS, fontsize=15)
ax.tick_params(axis='both', which='major', labelsize=15)
ax.set_xlabel("Target Offered Load", labelpad=12, fontsize=19, fontweight='bold')
ax.set_ylim(35, 65)
ax.grid(True, linestyle='--', alpha=0.5)
ax.legend(loc='lower left', framealpha=0.94, fontsize=14)
plt.tight_layout()
save_plot(fig, "calibrated_2core_hardware_hit_rate")

# Query Resolution Breakdown Stack (1x2 Subplots)
fig, axes = plt.subplots(1, 2, figsize=(15, 6.8), sharey=True)
for i, mode in enumerate(['unbound_hw_cache', 'ates_hw_cache']):
    ax = axes[i]
    mdf = df[df['mode'] == mode]
    hw_hits = []
    drv_hits = []
    usr_hits = []
    drops = []
    for r in RATE_ORDER:
        sub = mdf[mdf['target_qps'] == r]
        tot = sub['queries_sent'].mean()
        hw_hits.append(sub['hw_cache_hits'].mean() / tot * 100.0)
        drv_hits.append(sub['driver_hits'].mean() / tot * 100.0)
        usr_hits.append(sub['userspace_hits'].mean() / tot * 100.0)
        drops.append(sub['queries_lost'].mean() / tot * 100.0)
    
    ax.bar(x_indices, hw_hits, color='#1b9e77', edgecolor='black', width=0.55)
    if mode == 'ates_hw_cache':
        ax.bar(x_indices, drv_hits, bottom=hw_hits, color='#7570b3', edgecolor='black', width=0.55)
        bottom_next = np.array(hw_hits) + np.array(drv_hits)
    else:
        ax.bar(x_indices, usr_hits, bottom=hw_hits, color='#d95f02', edgecolor='black', width=0.55)
        bottom_next = np.array(hw_hits) + np.array(usr_hits)
    
    ax.bar(x_indices, drops, bottom=bottom_next, color='#e41a1c', edgecolor='black', width=0.55)
    ax.set_title(MODE_LABELS[mode], fontweight='bold', pad=12, fontsize=17)
    ax.set_xticks(x_indices)
    ax.set_xticklabels(RATE_LABELS, fontsize=14)
    ax.tick_params(axis='both', which='major', labelsize=14)
    ax.set_xlabel("Target Offered Load", labelpad=10, fontsize=16, fontweight='bold')
    if i == 0:
        ax.set_ylabel("Share of Queries (%)", fontsize=17, fontweight='bold', labelpad=8)
    ax.set_ylim(0, 100)
    ax.grid(axis='y', linestyle='--', alpha=0.5)

legend_handles = [
    mpatches.Patch(facecolor='#1b9e77', edgecolor='black', label='HW Cache (NIC SRAM)'),
    mpatches.Patch(facecolor='#7570b3', edgecolor='black', label='Ates Driver (Host XDP)'),
    mpatches.Patch(facecolor='#d95f02', edgecolor='black', label='Unbound (User Socket)'),
    mpatches.Patch(facecolor='#e41a1c', edgecolor='black', label='Dropped'),
]
fig.legend(handles=legend_handles, loc='upper center', bbox_to_anchor=(0.5, 0.95),
           ncol=4, framealpha=0.96, fontsize=14)

plt.suptitle("Ingress Query Resolution Breakdown Across Layers",
             fontsize=19, y=1.01, fontweight='bold')
plt.tight_layout(rect=[0, 0, 1, 0.88])
save_plot(fig, "calibrated_2core_query_resolution_breakdown")

print(f"\n🎉 All calibrated suite graphs generated in: {PLOTS_DIR}")
