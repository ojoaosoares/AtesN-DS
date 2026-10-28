#!/usr/bin/env python3
# ==============================================================================
# plot_comprehensive_suite.py
#
# Generates complete suite of individual publication-ready figures for the
# 10-repetition 2-Core real-trace DNS benchmark:
#
# Latency Suite (Separated):
#   - Mean Latency (lat_mean_ms)
#   - Median Latency (p50)
#   - 90th Percentile Latency (p90)
#   - 99th Percentile Latency (p99) [SEPARATE]
#   - 99.9th Percentile Latency (p99.9) [SEPARATE]
#   - Maximum Latency (lat_max_ms) [SEPARATE]
#   - Standard Deviation of Latency (lat_std_ms)
#
# Throughput & Loss Suite:
#   - Achieved Throughput vs Target (Bar chart)
#   - Achieved Throughput vs Target (Line chart)
#   - Packet Loss Rate (%) [Linear scale]
#   - Packet Loss Rate (%) [Log scale]
#
# Hardware & CPU Suite:
#   - Dedicated Server CPU (Cores 0 & 1) vs Target
#   - CPU Saturation Curve (Cores 0 & 1 vs Achieved Throughput)
#   - Server SoftIRQ (%) vs Target
#   - Client CPU Utilization (%) vs Target
#   - Hardware Cache Hit Rate (%) vs Target
#   - Answer Breakdown (HW Hits vs Driver Hits vs Userspace Hits)
#
# CCDF Suite:
#   - 2x2 Operational CCDF Grid
#   - Separate CCDF plots for each load level (200k, 500k, 1M, 2M, 3M, 4M)
# ==============================================================================

import os
import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams.update({
    'font.size': 11,
    'axes.labelsize': 12,
    'axes.titlesize': 13,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 10,
    'figure.titlesize': 14,
    'font.family': 'sans-serif',
    'grid.alpha': 0.35,
})

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
RESULTS_DIR = os.path.join(PROJECT_ROOT, "results")
SEPARATE_DIR = os.path.join(RESULTS_DIR, "individual_plots")
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(SEPARATE_DIR, exist_ok=True)

raw_arg = sys.argv[1] if len(sys.argv) > 1 else "raw_2core_busywait_10reps.csv"
RAW_CSV = raw_arg if os.path.isabs(raw_arg) else os.path.join(BASE_DIR, raw_arg)
if not os.path.exists(RAW_CSV):
    RAW_CSV = os.path.join(BASE_DIR, "raw_2core_realtrace_10reps.csv")
if not os.path.exists(RAW_CSV):
    print(f"Error: {RAW_CSV} not found.")
    sys.exit(1)

out_dir_arg = sys.argv[2] if len(sys.argv) > 2 else os.path.join(PROJECT_ROOT, "results", "official_post_outliers")
OUTPUT_DIR = out_dir_arg if os.path.isabs(out_dir_arg) else os.path.join(PROJECT_ROOT, out_dir_arg)
os.makedirs(OUTPUT_DIR, exist_ok=True)

df = pd.read_csv(RAW_CSV)

# Active dedicated cores CPU: (srv_c0_busy + srv_c1_busy) / 2
df['srv_dedicated_busy'] = (df['srv_c0_busy'] + df['srv_c1_busy']) / 2.0

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

MODE_MARKERS = {
    'unbound_standalone': 'o',
    'ates_driver':        's',
    'unbound_hw_cache':   '^',
    'ates_hw_cache':      'D',
}

MODE_ORDER = ['unbound_standalone', 'unbound_hw_cache', 'ates_driver', 'ates_hw_cache']

def parse_rate(val):
    try:
        return int(val)
    except:
        return 99999999

RATE_ORDER = sorted(df['target_qps'].unique(), key=parse_rate)
RATE_LABELS = []
for r in RATE_ORDER:
    if r >= 1000000:
        RATE_LABELS.append(f"{r // 1000000}M" if r % 1000000 == 0 else f"{r / 1000000:.1f}M")
    elif r >= 1000:
        RATE_LABELS.append(f"{r // 1000}k")
    else:
        RATE_LABELS.append(str(r))

x_indices = np.arange(len(RATE_ORDER))

def save_plot(fig, filename_base, subfolder=True):
    target_dirs = [RESULTS_DIR, OUTPUT_DIR]
    if subfolder:
        target_dirs.append(SEPARATE_DIR)
        
    for d in target_dirs:
        p_png = os.path.join(d, f"{filename_base}.png")
        p_pdf = os.path.join(d, f"{filename_base}.pdf")
        fig.savefig(p_png, dpi=300, bbox_inches='tight')
        fig.savefig(p_pdf, bbox_inches='tight')
    print(f"Generated: {filename_base}.png & .pdf -> {OUTPUT_DIR}")
    plt.close(fig)

# Helper function to plot line graphs with error bars (mean +/- std)
def plot_line_metric(col_name, ylabel, title, filename_base, log_scale=False, y_min=None, y_max=None):
    fig, ax = plt.subplots(figsize=(9, 5.5))
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
                    linewidth=2.2, markersize=7, capsize=3.5,
                    label=MODE_LABELS[mode], color=MODE_COLORS[mode])
    
    if log_scale:
        ax.set_yscale('log')
    if y_min is not None or y_max is not None:
        ax.set_ylim(bottom=y_min, top=y_max)
        
    ax.set_ylabel(ylabel)
    ax.set_title(title, fontweight='bold', pad=10)
    ax.set_xticks(x_indices)
    ax.set_xticklabels(RATE_LABELS)
    ax.set_xlabel("Offered Load (QPS)")
    ax.grid(True, which='both', linestyle='--', alpha=0.4)
    ax.legend(loc='best', framealpha=0.92)
    plt.tight_layout()
    save_plot(fig, filename_base)

print("--- Generating Latency Suite (Separated) ---")
# 1. Mean Latency
plot_line_metric('lat_mean_ms', "Mean Response Latency (ms) [Log Scale]",
                 "Mean Response Latency vs. Offered Load (Production ISP Trace, n=10)",
                 "plot_latency_mean", log_scale=True)

# 2. Median (p50) Latency
plot_line_metric('lat_p50_ms', "Median (p50) Response Latency (ms) [Log Scale]",
                 "Median (p50) Latency vs. Offered Load (Production ISP Trace, n=10)",
                 "plot_latency_p50", log_scale=True)

# 3. 90th Percentile (p90) Latency
plot_line_metric('lat_p90_ms', "90th Percentile (p90) Latency (ms) [Log Scale]",
                 "90th Percentile (p90) Latency vs. Offered Load (Production ISP Trace, n=10)",
                 "plot_latency_p90", log_scale=True)

# 4. 99th Percentile (p99) Latency - SEPARATE
plot_line_metric('lat_p99_ms', "99th Percentile (p99) Latency (ms) [Log Scale]",
                 "Tail Latency (p99) vs. Offered Load (Production ISP Trace, n=10, 180s per run)",
                 "plot_latency_p99_separate", log_scale=True)

# 5. 99.9th Percentile (p99.9) Latency - SEPARATE
plot_line_metric('lat_p99_9_ms', "99.9th Percentile (p99.9) Latency (ms) [Log Scale]",
                 "Tail Latency (p99.9) vs. Offered Load (Production ISP Trace, n=10, 180s per run)",
                 "plot_latency_p99_9_separate", log_scale=True)

# 6. Maximum Latency (lat_max_ms) - SEPARATE
plot_line_metric('lat_max_ms', "Maximum Response Latency (ms) [Log Scale]",
                 "Maximum Recorded Latency vs. Offered Load (Production ISP Trace, n=10)",
                 "plot_latency_max_separate", log_scale=True)

# 7. Standard Deviation of Latency
plot_line_metric('lat_std_ms', "Latency Standard Deviation (ms) [Log Scale]",
                 "Response Latency Dispersion (Std Dev) vs. Offered Load (n=10)",
                 "plot_latency_std", log_scale=True)

print("--- Generating Throughput & Packet Loss Suite ---")
# 8. Throughput Bar Chart
fig, ax = plt.subplots(figsize=(9.5, 5.5))
width = 0.18
for idx, mode in enumerate(MODE_ORDER):
    mdf = df[df['mode'] == mode]
    qps_means = []
    qps_stds = []
    for r in RATE_ORDER:
        sub = mdf[mdf['target_qps'] == r]
        qps_means.append(sub['achieved_qps'].mean() / 1000.0)
        qps_stds.append(sub['achieved_qps'].std() / 1000.0)
    pos = x_indices + (idx - 1.5) * width
    ax.bar(pos, qps_means, width, yerr=qps_stds, capsize=4,
           label=MODE_LABELS[mode], color=MODE_COLORS[mode], edgecolor='black', linewidth=0.8)

ax.set_ylabel("Achieved Throughput (kQPS)")
ax.set_title("Achieved DNS Throughput vs. Offered Load (Production ISP Trace, n=10, 180s sustained)", fontweight='bold')
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS)
ax.set_xlabel("Offered Load (QPS)")
ax.grid(axis='y', linestyle='--', alpha=0.5)
ax.legend(loc='upper left', framealpha=0.92)
plt.tight_layout()
save_plot(fig, "plot_throughput_bars")
# Also overwrite main figure
save_plot(fig, "realtrace_2core_throughput_bars", subfolder=False)

# 9. Throughput Scaling Line Chart
fig, ax = plt.subplots(figsize=(9, 5.5))
ideal_qps = [r / 1000.0 for r in RATE_ORDER]
ax.plot(x_indices, ideal_qps, 'k--', linewidth=1.5, alpha=0.7, label='Ideal 1:1 Line Rate')
for mode in MODE_ORDER:
    mdf = df[df['mode'] == mode]
    means = [mdf[mdf['target_qps'] == r]['achieved_qps'].mean() / 1000.0 for r in RATE_ORDER]
    ax.plot(x_indices, means, marker=MODE_MARKERS[mode], linewidth=2.2, markersize=7,
            label=MODE_LABELS[mode], color=MODE_COLORS[mode])
ax.set_ylabel("Achieved Throughput (kQPS)")
ax.set_title("Throughput Scaling Curve vs. Ideal Line Rate (2 Cores, 4 RSS Queues)", fontweight='bold')
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS)
ax.set_xlabel("Offered Load (QPS)")
ax.grid(True, linestyle='--', alpha=0.5)
ax.legend(loc='upper left', framealpha=0.92)
plt.tight_layout()
save_plot(fig, "plot_throughput_scaling_line")

# 10. Packet Loss Rate (Linear)
plot_line_metric('packet_loss_pct', "Packet Loss Rate (%)",
                 "Packet Loss Rate (%) vs. Offered Load (Production ISP Trace, n=10)",
                 "plot_packet_loss_linear", y_min=-2, y_max=103)
# Also overwrite main figure
fig, ax = plt.subplots(figsize=(9, 5.5))
for mode in MODE_ORDER:
    mdf = df[df['mode'] == mode]
    means = [mdf[mdf['target_qps'] == r]['packet_loss_pct'].mean() for r in RATE_ORDER]
    ax.plot(x_indices, means, marker=MODE_MARKERS[mode], linewidth=2.2, markersize=7,
            label=MODE_LABELS[mode], color=MODE_COLORS[mode])
ax.set_ylabel("Packet Loss Rate (%)")
ax.set_title("Packet Loss Rate vs. Offered Load (Production ISP Trace, n=10, 180s per run)", fontweight='bold')
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS)
ax.set_xlabel("Offered Load (QPS)")
ax.set_ylim(-2, 103)
ax.grid(True, linestyle='--', alpha=0.5)
ax.legend(loc='upper left', framealpha=0.92)
plt.tight_layout()
save_plot(fig, "realtrace_2core_packet_loss", subfolder=False)

# 11. Packet Loss Rate (Log Scale)
fig, ax = plt.subplots(figsize=(9, 5.5))
for mode in MODE_ORDER:
    mdf = df[df['mode'] == mode]
    means = [max(mdf[mdf['target_qps'] == r]['packet_loss_pct'].mean(), 0.001) for r in RATE_ORDER]
    ax.plot(x_indices, means, marker=MODE_MARKERS[mode], linewidth=2.2, markersize=7,
            label=MODE_LABELS[mode], color=MODE_COLORS[mode])
ax.set_yscale('log')
ax.set_ylabel("Packet Loss Rate (%) [Log Scale]")
ax.set_title("Packet Loss Rate (Log Scale) Across Offered Load (n=10)", fontweight='bold')
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS)
ax.set_xlabel("Offered Load (QPS)")
ax.grid(True, which='both', linestyle='--', alpha=0.4)
ax.legend(loc='upper left', framealpha=0.92)
plt.tight_layout()
save_plot(fig, "plot_packet_loss_log")

print("--- Generating Hardware & CPU Suite ---")
# 12. Dedicated CPU (Cores 0 & 1) vs Target Rate
plot_line_metric('srv_dedicated_busy', "Dedicated CPU Utilization (%) [Cores 0 & 1]",
                 "Dedicated Server Core Utilization (Cores 0 & 1) vs. Offered Load (n=10)",
                 "plot_cpu_cores_active", y_min=-2, y_max=103)

# 13. CPU Saturation Curve (Cores 0 & 1 vs Achieved Throughput)
fig, ax = plt.subplots(figsize=(9, 5.5))
for mode in MODE_ORDER:
    mdf = df[df['mode'] == mode].copy()
    grouped = mdf.groupby('target_qps')[['achieved_qps', 'srv_dedicated_busy']].mean().reset_index()
    grouped['qps_k'] = grouped['achieved_qps'] / 1000.0
    grouped = grouped.sort_values('qps_k')
    ax.plot(grouped['qps_k'], grouped['srv_dedicated_busy'], marker=MODE_MARKERS[mode],
            linewidth=2.2, markersize=7, label=MODE_LABELS[mode], color=MODE_COLORS[mode])

ax.set_xlabel("Achieved Throughput (kQPS)")
ax.set_ylabel("Dedicated Server Core Utilization (%) [Cores 0 & 1]")
ax.set_title("Server CPU Saturation Curve (Cores 0 & 1, 4 RSS Queues, n=10)", fontweight='bold')
ax.grid(True, linestyle='--', alpha=0.5)
ax.legend(loc='lower right', framealpha=0.92)
plt.tight_layout()
save_plot(fig, "plot_cpu_saturation_curve")
save_plot(fig, "realtrace_2core_cpu_saturation", subfolder=False)

# 14. Server SoftIRQ vs Target Rate
plot_line_metric('srv_softirq', "Server SoftIRQ Load (%)",
                 "Host Kernel SoftIRQ CPU Utilization vs. Offered Load (n=10)",
                 "plot_cpu_softirq")

# 15. Client CPU Utilization
plot_line_metric('client_cpu_busy', "Client CPU Utilization (%)",
                 "Load Generator (xdnsperf, 4 Cores) CPU Utilization vs. Offered Load (n=10)",
                 "plot_client_cpu")

# 16. Ingress Hardware Hit Rate
fig, ax = plt.subplots(figsize=(9, 5.5))
for mode in ['unbound_hw_cache', 'ates_hw_cache']:
    mdf = df[df['mode'] == mode]
    # True ingress hit rate = hw_cache_hits / queries_sent * 100
    hit_rates = []
    for r in RATE_ORDER:
        sub = mdf[mdf['target_qps'] == r]
        hr = (sub['hw_cache_hits'] / sub['queries_sent'] * 100.0).mean()
        hit_rates.append(hr)
    ax.plot(x_indices, hit_rates, marker=MODE_MARKERS[mode], linewidth=2.2, markersize=7,
            label=f"{MODE_LABELS[mode]} (Ingress HW Hit %)", color=MODE_COLORS[mode])

ax.set_ylabel("Ingress Hardware Cache Hit Rate (%)")
ax.set_title("Hardware Cache Ingress Hit Rate vs. Offered Load (Production ISP Trace, n=10)", fontweight='bold')
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS)
ax.set_xlabel("Offered Load (QPS)")
ax.set_ylim(40, 102)
ax.grid(True, linestyle='--', alpha=0.5)
ax.legend(loc='lower left', framealpha=0.92)
plt.tight_layout()
save_plot(fig, "plot_hardware_hit_rate")

# 17. Answer Breakdown Stack for HW Cache Modes
fig, axes = plt.subplots(1, 2, figsize=(14, 5.5), sharey=True)
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
    
    ax.bar(x_indices, hw_hits, label='HW Cache Hits (NIC)', color='#1b9e77', edgecolor='black')
    if mode == 'ates_hw_cache':
        ax.bar(x_indices, drv_hits, bottom=hw_hits, label='Ates Driver Hits (Host XDP)', color='#7570b3', edgecolor='black')
        bottom_next = np.array(hw_hits) + np.array(drv_hits)
    else:
        ax.bar(x_indices, usr_hits, bottom=hw_hits, label='Unbound Hits (User Socket)', color='#d95f02', edgecolor='black')
        bottom_next = np.array(hw_hits) + np.array(usr_hits)
    
    ax.bar(x_indices, drops, bottom=bottom_next, label='Dropped Queries', color='#e41a1c', edgecolor='black')
    ax.set_title(MODE_LABELS[mode], fontweight='bold')
    ax.set_xticks(x_indices)
    ax.set_xticklabels(RATE_LABELS)
    ax.set_xlabel("Offered Load (QPS)")
    if i == 0:
        ax.set_ylabel("Share of Offered Queries (%)")
    ax.set_ylim(0, 100)
    ax.legend(loc='upper right', framealpha=0.9)
    ax.grid(axis='y', linestyle='--', alpha=0.5)

plt.suptitle("Ingress Query Resolution Breakdown Across Layers (10GbE Wire, n=10)", fontsize=14, y=0.98)
plt.tight_layout()
save_plot(fig, "plot_query_resolution_breakdown")

print("--- Generating CCDF Suite (Separated & Grid) ---")
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

# Separate CCDF plot for each rate
for rate in [200000, 500000, 1000000, 2000000, 3000000, 4000000]:
    fig, ax = plt.subplots(figsize=(8.5, 5.5))
    r_str = f"{rate//1000}k" if rate < 1000000 else f"{rate/1000000:.1f}M".replace(".0", "")
    
    # Active modes for this rate
    if rate <= 200000:
        modes = MODE_ORDER
    else:
        # Unbound standalone dropped >76% to 100%, exclude or annotate
        modes = ['unbound_hw_cache', 'ates_driver', 'ates_hw_cache']
        
    for mode in modes:
        sub = df[(df['mode'] == mode) & (df['target_qps'] == rate)]
        if sub.empty: continue
        lat_coords = [sub[col].mean() for col, _ in P_MAP]
        ccdf_coords = [c for _, c in P_MAP]
        ax.plot(lat_coords, ccdf_coords, label=MODE_LABELS[mode], color=MODE_COLORS[mode],
                marker=MODE_MARKERS[mode], linewidth=2.4, markersize=7, alpha=0.9)
                
    ax.set_yscale('log')
    ax.set_ylim(0.00008, 1.3)
    ax.set_ylabel(r"CCDF: $P(\mathrm{Latency} > x)$ [Fraction of Queries]")
    ax.set_yticks([1.0, 0.5, 0.1, 0.01, 0.001, 0.0001])
    ax.set_yticklabels(['1.0 (min)', '0.50 ($p_{50}$)', '0.10 ($p_{90}$)', '0.01 ($p_{99}$)', '0.001 ($p_{99.9}$)', '0.0001 (max)'])
    ax.set_xlabel("Response Latency (ms)")
    ax.set_title(f"Latency CCDF at {r_str} QPS Offered Load (Production ISP Trace, n=10)", fontweight='bold')
    ax.grid(True, which='both', linestyle='--', alpha=0.5)
    ax.legend(loc='upper right', framealpha=0.92)
    plt.tight_layout()
    save_plot(fig, f"plot_ccdf_{r_str}QPS")

# Combined 2x2 CCDF Grid
SCENARIOS = [
    (200000,  "(a) Moderate Load: 200 kQPS\n(All 4 modes operational)",
     ['unbound_standalone', 'unbound_hw_cache', 'ates_driver', 'ates_hw_cache']),
    (1000000, "(b) High Load: 1.0 MQPS\n(Unbound standalone excluded: >99.9% loss)",
     ['unbound_hw_cache', 'ates_driver', 'ates_hw_cache']),
    (2000000, "(c) High-Stress: 2.0 MQPS\n(Unbound standalone excluded: >99.9% loss)",
     ['unbound_hw_cache', 'ates_driver', 'ates_hw_cache']),
    (3000000, "(d) Peak Line-Rate: 3.0 MQPS\n(Unbound standalone excluded: 100% loss)",
     ['unbound_hw_cache', 'ates_driver', 'ates_hw_cache']),
]

fig, axes = plt.subplots(2, 2, figsize=(14, 10), sharey=True)
axes_flat = axes.flatten()

for idx, (qps, title, active_modes) in enumerate(SCENARIOS):
    ax = axes_flat[idx]
    for mode in active_modes:
        sub = df[(df['mode'] == mode) & (df['target_qps'] == qps)]
        if sub.empty: continue
        lat_coords = [sub[col].mean() for col, _ in P_MAP]
        ccdf_coords = [c for _, c in P_MAP]
        ax.plot(lat_coords, ccdf_coords, label=MODE_LABELS[mode], color=MODE_COLORS[mode],
                marker=MODE_MARKERS[mode], linewidth=2.4, markersize=6.5, alpha=0.9)
    ax.set_yscale('log')
    ax.set_ylim(0.00008, 1.3)
    ax.set_title(title, fontweight='bold', pad=8)
    ax.set_xlabel("Response Latency (ms)")
    ax.grid(True, which='both', linestyle='--', alpha=0.5)
    if idx % 2 == 0:
        ax.set_ylabel(r"CCDF: $P(\mathrm{Latency} > x)$ [Fraction of Queries]")
        ax.set_yticks([1.0, 0.5, 0.1, 0.01, 0.001, 0.0001])
        ax.set_yticklabels(['1.0 (min)', '0.50 ($p_{50}$)', '0.10 ($p_{90}$)', '0.01 ($p_{99}$)', '0.001 ($p_{99.9}$)', '0.0001 (max)'])
    ax.legend(loc='upper right', framealpha=0.92)

plt.suptitle(r"Complementary Cumulative Distribution Function (CCDF) of Latency Across Operational Modes ($n=10$, 180s per run)", fontsize=14, y=0.99)
plt.tight_layout()
save_plot(fig, "realtrace_2core_ccdf_operational", subfolder=False)
save_plot(fig, "plot_ccdf_operational_2x2", subfolder=True)

print("\nAll individual and aggregated publication figures generated successfully.")
