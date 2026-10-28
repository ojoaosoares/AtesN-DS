#!/usr/bin/env python3
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams.update({
    'font.size': 11,
    'axes.labelsize': 12,
    'axes.titlesize': 13,
    'xtick.labelsize': 11,
    'ytick.labelsize': 11,
    'legend.fontsize': 10.5,
    'figure.titlesize': 14,
    'font.family': 'sans-serif'
})

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RAW_CSV = os.path.join(SCRIPT_DIR, "raw_3levels_5reps.csv")
SUMMARY_CSV = os.path.join(SCRIPT_DIR, "summary_3levels_5reps.csv")
OUT_DIR = os.path.join(SCRIPT_DIR, "plots_3levels_5reps")
os.makedirs(OUT_DIR, exist_ok=True)

df_raw = pd.read_csv(RAW_CSV)
df_sum = pd.read_csv(SUMMARY_CSV)

MODES = ['unbound_standalone', 'unbound_hw_cache', 'ates_driver', 'ates_hw_cache']
MODE_LABELS = {
    'unbound_standalone': 'Unbound Standalone',
    'unbound_hw_cache':   'Unbound + SmartNIC HW',
    'ates_driver':        'AtesN-DS Driver Mode',
    'ates_hw_cache':      'AtesN-DS + SmartNIC HW',
}
MODE_COLORS = {
    'unbound_standalone': '#d95f02',   # Orange
    'unbound_hw_cache':   '#1b9e77',   # Teal/Green
    'ates_driver':        '#7570b3',   # Purple
    'ates_hw_cache':      '#e7298a',   # Magenta
}

RATES = [1000000, 4000000, 0]
RATE_LABELS = ['1.0 MQPS', '4.0 MQPS', 'Line-Rate\n(Offered ~7.5M)']

# Helper to query summary stats
def get_stat(mode, rate, col_mean, col_ci=None):
    row = df_sum[(df_sum['mode'] == mode) & (df_sum['target_qps'] == rate)]
    if len(row) == 0:
        return 0, 0
    m = row[col_mean].values[0]
    ci = row[col_ci].values[0] if col_ci else 0
    return m, ci

# ==============================================================================
# 1. Throughput (Achieved QPS) - Grouped Bar Chart
# ==============================================================================
fig, ax = plt.subplots(figsize=(9, 5.5))
x = np.arange(len(RATES))
width = 0.20

for i, mode in enumerate(MODES):
    means = []
    cis = []
    for r in RATES:
        m, ci = get_stat(mode, r, 'achieved_qps_mean', 'achieved_qps_ci95')
        means.append(m / 1e6)
        cis.append(ci / 1e6)
    
    pos = x + (i - 1.5) * width
    bars = ax.bar(pos, means, width, yerr=cis, capsize=4,
                  label=MODE_LABELS[mode], color=MODE_COLORS[mode], edgecolor='black', linewidth=0.8, alpha=0.9)
    
    for bar in bars:
        h = bar.get_height()
        if h > 0.05:
            ax.annotate(f"{h:.2f}M",
                        xy=(bar.get_x() + bar.get_width() / 2, h),
                        xytext=(0, 4), textcoords="offset points",
                        ha='center', va='bottom', fontsize=8.5, fontweight='bold')
        elif h > 0:
            ax.annotate(f"{h*1e6:.0f}",
                        xy=(bar.get_x() + bar.get_width() / 2, h),
                        xytext=(0, 4), textcoords="offset points",
                        ha='center', va='bottom', fontsize=8, color='#d95f02')

ax.set_xticks(x)
ax.set_xticklabels(RATE_LABELS, fontweight='bold')
ax.set_ylabel('Achieved Throughput (Million QPS)', fontweight='bold')
ax.set_title('Sustained DNS Throughput under Variable TTL Eviction (n=5, 95% CI)', fontweight='bold')
ax.set_ylim(0, 6.0)
ax.legend(loc='upper left', frameon=True)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "fig_3levels_throughput.png"), dpi=300)
plt.close()

# ==============================================================================
# 2. Packet Loss (%) - Grouped Bar Chart
# ==============================================================================
fig, ax = plt.subplots(figsize=(9, 5.2))
for i, mode in enumerate(MODES):
    means = []
    cis = []
    for r in RATES:
        m, ci = get_stat(mode, r, 'packet_loss_pct_mean', 'packet_loss_pct_ci95')
        means.append(m)
        cis.append(ci)
    
    pos = x + (i - 1.5) * width
    bars = ax.bar(pos, means, width, yerr=cis, capsize=4,
                  label=MODE_LABELS[mode], color=MODE_COLORS[mode], edgecolor='black', linewidth=0.8, alpha=0.9)
    
    for bar in bars:
        h = bar.get_height()
        ax.annotate(f"{h:.1f}%",
                    xy=(bar.get_x() + bar.get_width() / 2, h),
                    xytext=(0, 3), textcoords="offset points",
                    ha='center', va='bottom', fontsize=8.5, fontweight='bold')

ax.set_xticks(x)
ax.set_xticklabels(RATE_LABELS, fontweight='bold')
ax.set_ylabel('Packet Loss Ratio (%)', fontweight='bold')
ax.set_title('Packet Loss under Variable TTL Dynamic Eviction (n=5, 95% CI)', fontweight='bold')
ax.set_ylim(0, 115)
ax.legend(loc='upper left', frameon=True)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "fig_3levels_packet_loss.png"), dpi=300)
plt.close()

# ==============================================================================
# 3. Latency Percentiles (p50, p90, p99) for AtesN-DS HW Cache vs Driver
# ==============================================================================
fig, axes = plt.subplots(1, 3, figsize=(14, 4.8), sharey=True)
percentiles = [('lat_p50_ms_mean', 'Median ($p_{50}$) Latency'),
               ('lat_p90_ms_mean', '$p_{90}$ Tail Latency'),
               ('lat_p99_ms_mean', '$p_{99}$ Worst-Case Tail Latency')]

eval_modes = ['ates_hw_cache', 'ates_driver', 'unbound_hw_cache']

for ax_idx, (col, title) in enumerate(percentiles):
    ax = axes[ax_idx]
    x_sub = np.arange(len(RATES))
    w_sub = 0.25
    for i, mode in enumerate(eval_modes):
        vals = [get_stat(mode, r, col)[0] for r in RATES]
        pos = x_sub + (i - 1) * w_sub
        bars = ax.bar(pos, vals, w_sub, label=MODE_LABELS[mode],
                      color=MODE_COLORS[mode], edgecolor='black', linewidth=0.8, alpha=0.9)
        for b in bars:
            h = b.get_height()
            if h > 0.1:
                ax.annotate(f"{h:.1f}", xy=(b.get_x() + b.get_width()/2, h),
                            xytext=(0, 3), textcoords="offset points",
                            ha='center', va='bottom', fontsize=8, fontweight='bold')
    
    ax.set_xticks(x_sub)
    ax.set_xticklabels(RATE_LABELS, fontsize=9.5)
    ax.set_title(title, fontweight='bold')
    if ax_idx == 0:
        ax.set_ylabel('Latency (ms)', fontweight='bold')
        ax.legend(loc='upper right', frameon=True)

fig.suptitle('End-to-End Latency Profiles across Load Levels (120s Sustained Runs)', fontweight='bold', y=1.02)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "fig_3levels_latency.png"), dpi=300)
plt.close()

# ==============================================================================
# 4. Multi-Tier Resolution Breakdown (HW vs Driver vs Userspace)
# ==============================================================================
fig, ax = plt.subplots(figsize=(10, 5.5))
breakdown_modes = ['ates_hw_cache', 'ates_driver', 'unbound_hw_cache']
x_b = np.arange(len(RATES))
w_b = 0.25

tier_colors = {
    'hw':        '#2ca02c',  # Green (SmartNIC Silicon)
    'driver':    '#1f77b4',  # Blue (Host Driver XDP)
    'userspace': '#ff7f0e',  # Orange (Host Userspace)
}

for i, mode in enumerate(breakdown_modes):
    hw_vals = [get_stat(mode, r, 'hw_cache_hits_mean')[0] / 1e6 for r in RATES]
    dr_vals = [get_stat(mode, r, 'driver_hits_mean')[0] / 1e6 for r in RATES]
    us_vals = [get_stat(mode, r, 'userspace_hits_mean')[0] / 1e6 for r in RATES]
    
    pos = x_b + (i - 1) * w_b
    
    p1 = ax.bar(pos, hw_vals, w_b, color=tier_colors['hw'], edgecolor='black', linewidth=0.6,
                label='SmartNIC HW Cache Hit' if i == 0 else "")
    p2 = ax.bar(pos, dr_vals, w_b, bottom=hw_vals, color=tier_colors['driver'], edgecolor='black', linewidth=0.6,
                label='Host Driver Mode Hit' if i == 0 else "")
    p3 = ax.bar(pos, us_vals, w_b, bottom=np.array(hw_vals) + np.array(dr_vals), color=tier_colors['userspace'],
                edgecolor='black', linewidth=0.6, label='Userspace / Upstream' if i == 0 else "")
    
    for idx, (h_val, d_val, u_val) in enumerate(zip(hw_vals, dr_vals, us_vals)):
        tot = h_val + d_val + u_val
        if tot > 0.5:
            # Short label under bar
            short_mode = "AtesN HW" if "hw_cache" in mode and "ates" in mode else ("AtesN Drv" if "driver" in mode else "Unbound HW")
            ax.annotate(short_mode, xy=(pos[idx], 5), rotation=90, ha='center', va='bottom', fontsize=8, color='white', fontweight='bold')
            ax.annotate(f"{tot:.0f}M", xy=(pos[idx], tot), xytext=(0, 3), textcoords="offset points",
                        ha='center', va='bottom', fontsize=8.5, fontweight='bold')

ax.set_xticks(x_b)
ax.set_xticklabels(RATE_LABELS, fontweight='bold')
ax.set_ylabel('Total Answered Queries per 120s Run (Millions)', fontweight='bold')
ax.set_title('Multi-Tier Query Resolution Breakdown (Hardware vs Driver vs Userspace)', fontweight='bold')
ax.legend(loc='upper left', frameon=True)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "fig_3levels_tier_breakdown.png"), dpi=300)
plt.close()

# ==============================================================================
# 5. Server CPU Utilization & NIC Ring Buffer Discards
# ==============================================================================
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

# CPU Busy
for i, mode in enumerate(MODES):
    means = [get_stat(mode, r, 'srv_all_busy_mean')[0] for r in RATES]
    cis = [get_stat(mode, r, 'srv_all_busy_ci95')[0] for r in RATES]
    pos = x + (i - 1.5) * width
    ax1.bar(pos, means, width, yerr=cis, capsize=3,
            label=MODE_LABELS[mode], color=MODE_COLORS[mode], edgecolor='black', linewidth=0.8, alpha=0.9)

ax1.set_xticks(x)
ax1.set_xticklabels(RATE_LABELS, fontweight='bold')
ax1.set_ylabel('Total Server CPU Busy (%)', fontweight='bold')
ax1.set_title('(a) Server CPU Utilization Across Cores', fontweight='bold')
ax1.set_ylim(0, 80)
ax1.legend(loc='upper left', frameon=True, fontsize=9.5)

# Discards
for i, mode in enumerate(MODES):
    discards = [get_stat(mode, r, 'nic_rx_discards_mean')[0] / 1e6 for r in RATES]
    pos = x + (i - 1.5) * width
    ax2.bar(pos, discards, width,
            label=MODE_LABELS[mode], color=MODE_COLORS[mode], edgecolor='black', linewidth=0.8, alpha=0.9)

ax2.set_xticks(x)
ax2.set_xticklabels(RATE_LABELS, fontweight='bold')
ax2.set_ylabel('NIC RX Ring Buffer Discards (Millions)', fontweight='bold')
ax2.set_title('(b) Hardware Ring Buffer Packet Drops', fontweight='bold')
ax2.legend(loc='upper left', frameon=True, fontsize=9.5)

plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "fig_3levels_cpu_discards.png"), dpi=300)
plt.close()

print(f"Successfully generated all 5 publication-ready plots in: {OUT_DIR}")
