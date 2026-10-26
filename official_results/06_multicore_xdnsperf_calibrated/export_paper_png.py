#!/usr/bin/env python3
# ==============================================================================
# export_paper_png.py
#
# Generates ALL 2-Core calibrated benchmark figures in high-resolution PNG only,
# saved to results/paper_png/.
#
# Typography is slightly reduced from the previous extra-large version to achieve
# the ideal balanced paper aesthetic:
#   - Titles: 18pt bold
#   - Axis Labels: 16pt bold
#   - Ticks: 13.5pt
#   - Legends: 13pt
#   - Linewidth: 2.8pt, Markersize: 8.5pt
#   - Canvas: 8.8 x 5.6 inches (proportional for paper columns)
# ==============================================================================

import os
import sys
import shutil
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import matplotlib.patches as mpatches

# Global Style
plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams.update({
    'font.size': 13,
    'axes.labelsize': 16,
    'axes.titlesize': 18,
    'axes.labelweight': 'bold',
    'xtick.labelsize': 13.5,
    'ytick.labelsize': 13.5,
    'legend.fontsize': 13,
    'figure.titlesize': 19,
    'font.family': 'sans-serif',
    'lines.linewidth': 2.8,
    'lines.markersize': 8.5,
    'grid.alpha': 0.45,
})

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
PAPER_PNG_DIR = os.path.join(PROJECT_ROOT, "results", "paper_png")

# Ensure clean dedicated folder for PNGs only
if os.path.exists(PAPER_PNG_DIR):
    # Clean old files in folder
    for f in os.listdir(PAPER_PNG_DIR):
        p = os.path.join(PAPER_PNG_DIR, f)
        if os.path.isfile(p):
            os.remove(p)
else:
    os.makedirs(PAPER_PNG_DIR, exist_ok=True)

RAW_CSV = os.path.join(BASE_DIR, "raw_2core_clean_warmup_10reps.csv")
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
    'ates_driver':        'AtesN-DS',
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
        RATE_LABELS.append('UNLIMITED\n(7.66 MQPS)')
    elif r >= 1000000:
        RATE_LABELS.append(f"{r // 1000000}M" if r % 1000000 == 0 else f"{r / 1000000:.1f}M")
    elif r >= 1000:
        RATE_LABELS.append(f"{r // 1000}k")
    else:
        RATE_LABELS.append(str(r))

x_indices = np.arange(len(RATE_ORDER))

def save_png(fig, base_name, alt_numbered_name=None):
    p1 = os.path.join(PAPER_PNG_DIR, f"{base_name}.png")
    fig.savefig(p1, dpi=300, bbox_inches='tight')
    if alt_numbered_name:
        p2 = os.path.join(PAPER_PNG_DIR, f"{alt_numbered_name}.png")
        shutil.copy2(p1, p2)
    print(f"  ✓ {base_name}.png")
    plt.close(fig)

def plot_line_metric(col_name, ylabel, title, filename_base, num_prefix=None, log_scale=False,
                     y_min=None, y_max=None, legend_loc='best', bbox_to_anchor=None, custom_yticks=None):
    fig, ax = plt.subplots(figsize=(8.8, 5.6))
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
                    linewidth=2.8, markersize=8.5, capsize=4,
                    label=MODE_LABELS[mode], color=MODE_COLORS[mode])
    
    if log_scale:
        ax.set_yscale('log')
        if 'lat_' in col_name:
            ticks = [2, 3, 5, 7, 10, 15, 20, 30, 50, 75, 100]
            ax.set_ylim(bottom=1.8, top=135)
            ax.set_yticks(ticks)
            ax.yaxis.set_major_formatter(ticker.ScalarFormatter())
            ax.yaxis.set_minor_formatter(ticker.NullFormatter())
    
    if custom_yticks is not None:
        ax.set_yticks(custom_yticks)
        
    if y_min is not None or y_max is not None:
        ax.set_ylim(bottom=y_min, top=y_max)
        
    ax.set_ylabel(ylabel, fontsize=16, fontweight='bold', labelpad=9)
    ax.set_title(title, fontweight='bold', pad=12, fontsize=18)
    ax.set_xlim(-0.5, len(RATE_ORDER) - 0.5)
    ax.set_xticks(x_indices)
    ax.set_xticklabels(RATE_LABELS, fontsize=13.5)
    ax.tick_params(axis='both', which='major', labelsize=13.5)
    ax.set_xlabel("Target Offered Load", labelpad=10, fontsize=16, fontweight='bold')
    ax.grid(True, which='both', linestyle='--', alpha=0.45)
    if bbox_to_anchor is not None:
        ax.legend(loc=legend_loc, bbox_to_anchor=bbox_to_anchor, framealpha=0.95, fontsize=13)
    else:
        ax.legend(loc=legend_loc, framealpha=0.94, fontsize=13)
    plt.tight_layout()
    save_png(fig, filename_base, num_prefix)

print(f"\n--- Generating All Figures for Paper in: {PAPER_PNG_DIR} ---")

# =========================================================================
# 1. THROUGHPUT SUITE
# =========================================================================
print("\n[1/5] Throughput Figures...")
# 1.1 Throughput Scaling Line (Log Scale - Default)
fig, ax = plt.subplots(figsize=(8.8, 5.6))
ideal_qps_raw = [r if r != 0 else 7660888 for r in RATE_ORDER]
ax.plot(x_indices, ideal_qps_raw, 'k--', linewidth=2.0, alpha=0.6, label='Ideal Offered Load')
for mode in ['ates_hw_cache', 'unbound_hw_cache', 'ates_driver', 'unbound_standalone']:
    mdf = df[df['mode'] == mode]
    means = [mdf[mdf['target_qps'] == r]['achieved_qps'].mean() for r in RATE_ORDER]
    stds = [mdf[mdf['target_qps'] == r]['achieved_qps'].std() for r in RATE_ORDER]
    ax.errorbar(x_indices, means, yerr=stds, marker=MODE_MARKERS[mode], linewidth=2.8, markersize=8.5,
                capsize=4, label=MODE_LABELS[mode], color=MODE_COLORS[mode])

ax.set_yscale('log')
ax.set_ylim(15, 25000000)
log_ticks = [10, 100, 1000, 10000, 100000, 1000000, 10000000]
log_labels = ['10 QPS', '100 QPS', '1 kQPS', '10 kQPS', '100 kQPS', '1 MQPS', '10 MQPS']
ax.set_yticks(log_ticks)
ax.set_yticklabels(log_labels, fontsize=13.5)
ax.set_ylabel("Achieved Throughput [Log Scale]", fontsize=16, fontweight='bold', labelpad=9)
ax.set_title("Throughput Scaling Curve vs. Offered Load", fontweight='bold', pad=12, fontsize=18)
ax.set_xlim(-0.5, len(RATE_ORDER) - 0.5)
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS, fontsize=13.5)
ax.tick_params(axis='both', which='major', labelsize=13.5)
ax.set_xlabel("Target Offered Load", labelpad=10, fontsize=16, fontweight='bold')
ax.grid(True, which='both', linestyle='--', alpha=0.45)
ax.legend(loc='upper left', framealpha=0.95, fontsize=13)
plt.tight_layout()
save_png(fig, "calibrated_2core_throughput_scaling_log", "01_throughput_scaling_curve")
save_png(fig, "01_throughput_scaling_curve_log")

# 1.1b Throughput Scaling Line (Linear Scale - MQPS)
fig, ax = plt.subplots(figsize=(8.8, 5.6))
ideal_qps_m = [r / 1e6 if r != 0 else 7.66 for r in RATE_ORDER]
ax.plot(x_indices, ideal_qps_m, 'k--', linewidth=2.0, alpha=0.6, label='Ideal Offered Load')
for mode in ['ates_hw_cache', 'unbound_hw_cache', 'ates_driver', 'unbound_standalone']:
    mdf = df[df['mode'] == mode]
    means = [mdf[mdf['target_qps'] == r]['achieved_qps'].mean() / 1e6 for r in RATE_ORDER]
    stds = [mdf[mdf['target_qps'] == r]['achieved_qps'].std() / 1e6 for r in RATE_ORDER]
    ax.errorbar(x_indices, means, yerr=stds, marker=MODE_MARKERS[mode], linewidth=2.8, markersize=8.5,
                capsize=4, label=MODE_LABELS[mode], color=MODE_COLORS[mode])

ax.set_ylabel("Achieved Throughput (MQPS)", fontsize=16, fontweight='bold', labelpad=9)
ax.set_xlim(-0.5, len(RATE_ORDER) - 0.5)
ax.set_ylim(-0.15, 8.2)
major_y = np.arange(0.0, 8.5, 0.5)
ax.set_yticks(major_y)
ax.set_yticklabels([f'{y:.1f}' if y != int(y) else f'{int(y)}' for y in major_y], fontsize=13.5)
ax.yaxis.set_minor_locator(ticker.MultipleLocator(0.1))
ax.set_title("Throughput Scaling Curve vs. Offered Load", fontweight='bold', pad=12, fontsize=18)
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS, fontsize=13.5)
ax.tick_params(axis='both', which='major', labelsize=13.5)
ax.set_xlabel("Target Offered Load", labelpad=10, fontsize=16, fontweight='bold')
ax.grid(True, which='major', axis='y', linestyle='--', alpha=0.6, color='#aaaaaa', linewidth=1.0)
ax.grid(True, which='minor', axis='y', linestyle=':', alpha=0.35, color='#cccccc')
ax.grid(True, which='major', axis='x', linestyle='--', alpha=0.4, color='#aaaaaa')
ax.legend(loc='upper left', framealpha=0.95, fontsize=13)
plt.tight_layout()
save_png(fig, "calibrated_2core_throughput_scaling_line", "01_throughput_scaling_curve_linear")

# 1.2 Throughput Bar Chart (Realistic Linear Scale with Numeric Value Labels)
fig, ax = plt.subplots(figsize=(11.8, 6.2))
width = 0.18
for idx, mode in enumerate(MODE_ORDER):
    mdf = df[df['mode'] == mode]
    means = [mdf[mdf['target_qps'] == r]['achieved_qps'].mean() / 1e6 for r in RATE_ORDER]
    stds = [mdf[mdf['target_qps'] == r]['achieved_qps'].std() / 1e6 for r in RATE_ORDER]
    pos = x_indices + (idx - 1.5) * width
    rects = ax.bar(pos, means, width, yerr=stds, capsize=3,
                   label=MODE_LABELS[mode], color=MODE_COLORS[mode], edgecolor='black', linewidth=0.8)
    for rect, val in zip(rects, means):
        qps = val * 1e6
        if qps >= 1e6:
            text = f'{val:.2f}M'
        elif qps >= 1e3:
            text = f'{qps/1e3:.0f}k'
        elif qps > 0:
            text = f'{qps:.0f}'
        else:
            text = '0'
        ax.annotate(text,
                    xy=(rect.get_x() + rect.get_width() / 2, max(rect.get_height(), 0.08)),
                    xytext=(0, 5), textcoords='offset points',
                    ha='center', va='bottom', fontsize=12.0, fontweight='bold', rotation=90)

ax.set_ylim(0, 10.5)
ax.set_yticks(np.arange(0.0, 11.0, 1.0))
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS, fontsize=14, fontweight='bold')
ax.tick_params(axis='both', which='major', labelsize=13.5)
ax.set_ylabel("Achieved Throughput (MQPS)", fontsize=16, fontweight='bold', labelpad=9)
ax.set_title("2-Core Achieved DNS Throughput vs. Offered Load", fontweight='bold', pad=14, fontsize=18)
ax.set_xlabel("Target Offered Load", labelpad=10, fontsize=16, fontweight='bold')
ax.grid(axis='y', linestyle='--', alpha=0.5)
ax.legend(loc='upper left', ncol=2, framealpha=0.95, fontsize=13)
plt.tight_layout()
save_png(fig, "calibrated_2core_throughput_bars", "02_throughput_bars")
save_png(fig, "calibrated_2core_throughput_bars_linear", "02_throughput_bars_linear")

# 1.2b Log Version (Preserved for Reference)
fig, ax = plt.subplots(figsize=(11.8, 6.2))
for idx, mode in enumerate(MODE_ORDER):
    mdf = df[df['mode'] == mode]
    means = [mdf[mdf['target_qps'] == r]['achieved_qps'].mean() for r in RATE_ORDER]
    pos = x_indices + (idx - 1.5) * width
    rects = ax.bar(pos, means, width,
                   label=MODE_LABELS[mode], color=MODE_COLORS[mode], edgecolor='black', linewidth=0.8)
    for rect, val in zip(rects, means):
        if val >= 1e6:
            text = f'{val/1e6:.2f}M'
        elif val >= 1e3:
            text = f'{val/1e3:.0f}k'
        else:
            text = f'{val:.0f}'
        ax.annotate(text,
                    xy=(rect.get_x() + rect.get_width() / 2, rect.get_height()),
                    xytext=(0, 5), textcoords='offset points',
                    ha='center', va='bottom', fontsize=11.5, fontweight='bold', rotation=90)

ax.set_yscale('log')
ax.set_ylim(10, 350000000)
log_ticks = [10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000]
log_labels = ['10 QPS', '100 QPS', '1 kQPS', '10 kQPS', '100 kQPS', '1 MQPS', '10 MQPS', '100 MQPS']
ax.set_yticks(log_ticks)
ax.set_yticklabels(log_labels, fontsize=13)
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS, fontsize=14, fontweight='bold')
ax.tick_params(axis='both', which='major', labelsize=13.5)
ax.set_ylabel("Achieved Throughput [Log Scale]", fontsize=16, fontweight='bold', labelpad=9)
ax.set_title("2-Core Achieved DNS Throughput vs. Offered Load (Log Bars)", fontweight='bold', pad=14, fontsize=18)
ax.set_xlabel("Target Offered Load", labelpad=10, fontsize=16, fontweight='bold')
ax.grid(True, which='both', axis='y', linestyle='--', alpha=0.45)
ax.legend(loc='upper left', ncol=2, framealpha=0.95, fontsize=13)
plt.tight_layout()
save_png(fig, "calibrated_2core_throughput_bars_log", "02_throughput_bars_log")

# =========================================================================
# 2. PACKET LOSS SUITE
# =========================================================================
print("\n[2/5] Packet Loss Figures...")
# 2.1 Packet Loss Linear (Legend Center Left - Lowered)
plot_line_metric('packet_loss_pct', "Packet Loss Rate (%)",
                 "Packet Loss Rate vs. Offered Load",
                 "calibrated_2core_packet_loss_linear", "03_packet_loss_linear",
                 y_min=-2, y_max=103, legend_loc='center left', bbox_to_anchor=(0.04, 0.48))

# 2.2 Packet Loss Log (Legend Center Left - Lowered)
fig, ax = plt.subplots(figsize=(8.8, 5.6))
for mode in MODE_ORDER:
    mdf = df[df['mode'] == mode]
    means = [max(mdf[mdf['target_qps'] == r]['packet_loss_pct'].mean(), 0.001) for r in RATE_ORDER]
    ax.plot(x_indices, means, marker=MODE_MARKERS[mode], linewidth=2.8, markersize=8.5,
            label=MODE_LABELS[mode], color=MODE_COLORS[mode])
ax.set_yscale('log')
ax.set_ylabel("Packet Loss Rate (%) [Log Scale]", fontsize=16, fontweight='bold', labelpad=9)
ax.set_title("Packet Loss Rate vs. Offered Load", fontweight='bold', pad=12, fontsize=18)
ax.set_xlim(-0.5, len(RATE_ORDER) - 0.5)
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS, fontsize=13.5)
ax.tick_params(axis='both', which='major', labelsize=13.5)
ax.set_xlabel("Target Offered Load", labelpad=10, fontsize=16, fontweight='bold')
ax.grid(True, which='both', linestyle='--', alpha=0.45)
ax.legend(loc='center left', bbox_to_anchor=(0.04, 0.48), framealpha=0.95, fontsize=13)
plt.tight_layout()
save_png(fig, "calibrated_2core_packet_loss_log", "04_packet_loss_log")

# =========================================================================
# 3. LATENCY SUITE
# =========================================================================
print("\n[3/5] Latency Suite...")
# 3.1 Tail Latency p99 (Log)
plot_line_metric('lat_p99_ms', "Tail Latency $p_{99}$ (ms) [Log Scale]",
                 "Tail Latency $p_{99}$ vs. Offered Load",
                 "calibrated_2core_tail_latency_p99", "05_tail_latency_p99_log",
                 log_scale=True, legend_loc='upper right')

# 3.2 Tail Latency p99 (Linear 0-110 ms)
plot_line_metric('lat_p99_ms', "Tail Latency $p_{99}$ (ms)",
                 "Tail Latency $p_{99}$ vs. Offered Load",
                 "calibrated_2core_tail_latency_p99_linear", "06_tail_latency_p99_linear",
                 log_scale=False, y_min=0, y_max=110, custom_yticks=np.arange(0, 120, 10), legend_loc='upper right')

# 3.3 Tail Latency p99.9 (Log)
plot_line_metric('lat_p99_9_ms', "Tail Latency $p_{99.9}$ (ms) [Log Scale]",
                 "Tail Latency $p_{99.9}$ vs. Offered Load",
                 "calibrated_2core_tail_latency_p99_9", "07_tail_latency_p99_9_log",
                 log_scale=True, legend_loc='upper right')

# 3.4 Tail Latency p99.9 (Linear 0-110 ms)
plot_line_metric('lat_p99_9_ms', "Tail Latency $p_{99.9}$ (ms)",
                 "Tail Latency $p_{99.9}$ vs. Offered Load",
                 "calibrated_2core_tail_latency_p99_9_linear", "08_tail_latency_p99_9_linear",
                 log_scale=False, y_min=0, y_max=110, custom_yticks=np.arange(0, 120, 10), legend_loc='upper right')

# 3.5 Mean Latency
plot_line_metric('lat_mean_ms', "Mean Latency (ms) [Log Scale]",
                 "Mean Response Latency vs. Offered Load",
                 "calibrated_2core_latency_mean", "09_latency_mean", log_scale=True)

# 3.6 Median Latency (p50)
plot_line_metric('lat_p50_ms', "Median ($p_{50}$) Latency (ms) [Log Scale]",
                 "Median ($p_{50}$) Latency vs. Offered Load",
                 "calibrated_2core_latency_p50", "10_latency_p50", log_scale=True)

# 3.7 90th Percentile Latency (p90)
plot_line_metric('lat_p90_ms', "90th Percentile ($p_{90}$) Latency (ms)",
                 "90th Percentile ($p_{90}$) Latency vs. Offered Load",
                 "calibrated_2core_latency_p90", "11_latency_p90", log_scale=True)

# 3.8 Max Latency & Std Dev
plot_line_metric('lat_max_ms', "Maximum Latency (ms) [Log Scale]",
                 "Maximum Recorded Latency vs. Offered Load",
                 "calibrated_2core_latency_max", "12_latency_max", log_scale=True)
plot_line_metric('lat_std_ms', "Latency Std Dev (ms) [Log Scale]",
                 "Response Latency Std Dev vs. Offered Load",
                 "calibrated_2core_latency_std", "13_latency_std", log_scale=True)

# =========================================================================
# 4. HARDWARE & CPU SUITE
# =========================================================================
print("\n[4/5] Hardware & CPU Suite...")
# 4.1 Server CPU Saturation Curve
fig, ax = plt.subplots(figsize=(8.8, 5.6))
for mode in MODE_ORDER:
    mdf = df[df['mode'] == mode].copy()
    grouped = mdf.groupby('target_qps')[['achieved_qps', 'srv_dedicated_busy']].mean().reset_index()
    grouped['qps_m'] = grouped['achieved_qps'] / 1e6
    grouped = grouped.sort_values('qps_m')
    ax.plot(grouped['qps_m'], grouped['srv_dedicated_busy'], marker=MODE_MARKERS[mode],
            linewidth=2.8, markersize=8.5, label=MODE_LABELS[mode], color=MODE_COLORS[mode])

ax.set_xlabel("Achieved Throughput (MQPS)", fontsize=16, fontweight='bold', labelpad=10)
ax.set_xlim(-0.35, 8.35)
ax.set_xticks(np.arange(0, 9.0, 1.0))
ax.tick_params(axis='both', which='major', labelsize=13.5)
ax.set_ylabel("Dedicated CPU Utilization (%)", fontsize=16, fontweight='bold', labelpad=9)
ax.set_ylim(-2, 103)
ax.set_title("Server CPU Saturation Curve", fontweight='bold', pad=12, fontsize=18)
ax.grid(True, linestyle='--', alpha=0.5)
ax.legend(loc='lower right', framealpha=0.94, fontsize=13)
plt.tight_layout()
save_png(fig, "calibrated_2core_cpu_saturation_curve", "14_cpu_saturation_curve")

# 4.2 Dedicated CPU Utilization vs Rate (Legend on the Left)
plot_line_metric('srv_dedicated_busy', "Dedicated CPU Utilization (%)",
                 "Dedicated Server Core Utilization vs. Offered Load",
                 "calibrated_2core_cpu_cores_active", "15_cpu_dedicated_cores",
                 y_min=-2, y_max=103, legend_loc='center left', bbox_to_anchor=(0.04, 0.55))

# 4.3 SoftIRQ Load (Legend Center Left - In the Middle)
plot_line_metric('srv_softirq', "Server SoftIRQ Load (%)",
                 "Host Kernel SoftIRQ CPU Load vs. Offered Load",
                 "calibrated_2core_cpu_softirq", "16_cpu_softirq_load",
                 y_min=-3, y_max=56, legend_loc='center left', bbox_to_anchor=(0.04, 0.40))

# 4.4 Client CPU Utilization
plot_line_metric('client_cpu_busy', "Client CPU Utilization (%)",
                 "Client Generator CPU Utilization vs. Offered Load",
                 "calibrated_2core_client_cpu", "17_client_cpu_load")

# 4.5 SmartNIC Hardware Hit Rate
fig, ax = plt.subplots(figsize=(8.8, 5.6))
for mode in ['unbound_hw_cache', 'ates_hw_cache']:
    mdf = df[df['mode'] == mode]
    hit_rates = []
    for r in RATE_ORDER:
        sub = mdf[mdf['target_qps'] == r]
        hr = (sub['hw_cache_hits'] / sub['queries_sent'] * 100.0).mean()
        hit_rates.append(hr)
    ax.plot(x_indices, hit_rates, marker=MODE_MARKERS[mode], linewidth=2.8, markersize=8.5,
            label=f"{MODE_LABELS[mode]}", color=MODE_COLORS[mode])

ax.set_ylabel("HW Ingress Hit Rate (%)", fontsize=16, fontweight='bold', labelpad=9)
ax.set_title("Hardware Cache Ingress Hit Rate", fontweight='bold', pad=12, fontsize=18)
ax.set_xlim(-0.5, len(RATE_ORDER) - 0.5)
ax.set_xticks(x_indices)
ax.set_xticklabels(RATE_LABELS, fontsize=13.5)
ax.tick_params(axis='both', which='major', labelsize=13.5)
ax.set_xlabel("Target Offered Load", labelpad=10, fontsize=16, fontweight='bold')
ax.set_ylim(40, 102)
ax.grid(True, linestyle='--', alpha=0.5)
ax.legend(loc='lower left', framealpha=0.94, fontsize=13)
plt.tight_layout()
save_png(fig, "calibrated_2core_hardware_hit_rate", "18_hardware_cache_hit_rate")

# 4.6 Query Resolution Breakdown at UNLIMITED (2 Bars Only: Unbound HW vs Ates HW)
modes_breakdown = ['unbound_hw_cache', 'ates_hw_cache']
labels_breakdown = ['Unbound + HW Cache', 'AtesN-DS + HW Cache']
x_bd = np.arange(len(modes_breakdown))
width_bd = 0.42

sub_ub = df[(df['mode'] == 'unbound_hw_cache') & (df['target_qps'] == 0)]
sub_at = df[(df['mode'] == 'ates_hw_cache') & (df['target_qps'] == 0)]

tot_ub = sub_ub['queries_sent'].mean()
hw_ub = sub_ub['hw_cache_hits'].mean() / tot_ub * 100.0
usr_ub = sub_ub['userspace_hits'].mean() / tot_ub * 100.0
drop_ub = sub_ub['queries_lost'].mean() / tot_ub * 100.0

tot_at = sub_at['queries_sent'].mean()
hw_at = sub_at['hw_cache_hits'].mean() / tot_at * 100.0
drv_at = sub_at['driver_hits'].mean() / tot_at * 100.0
usr_at = sub_at['userspace_hits'].mean() / tot_at * 100.0
drop_at = sub_at['queries_lost'].mean() / tot_at * 100.0

fig, (ax_top, ax_bot) = plt.subplots(2, 1, figsize=(8.0, 4.2), sharex=True,
                                     gridspec_kw={'height_ratios': [2.6, 1], 'hspace': 0.10})
width_bd = 0.44

for ax in [ax_top, ax_bot]:
    # Bar 1: Unbound + HW Cache
    ax.bar(0, hw_ub, width_bd, color='#1b9e77', edgecolor='black', linewidth=1.0, label='HW Cache (SmartNIC)')
    ax.bar(0, usr_ub, width_bd, bottom=hw_ub, color='#d95f02', edgecolor='black', linewidth=1.0, label='Unbound (User Socket)')
    ax.bar(0, drop_ub, width_bd, bottom=hw_ub+usr_ub, color='#e41a1c', edgecolor='black', linewidth=1.0, label='Dropped Queries')

    # Bar 2: AtesN-DS + HW Cache
    ax.bar(1, hw_at, width_bd, color='#1b9e77', edgecolor='black', linewidth=1.0)
    ax.bar(1, drv_at, width_bd, bottom=hw_at, color='#7570b3', edgecolor='black', linewidth=1.0, label='Ates Driver (Host XDP)')
    ax.bar(1, drop_at, width_bd, bottom=hw_at+drv_at, color='#e41a1c', edgecolor='black', linewidth=1.0)

# Bottom panel: squashed base (0 to 12%)
ax_bot.set_ylim(0, 12)
ax_bot.set_yticks([0, 10])
ax_bot.tick_params(axis='both', which='major', labelsize=11.5)
ax_bot.text(0, 5.5, f'{hw_ub:.2f}% (HW Cache)', ha='center', va='center', color='white', fontweight='bold', fontsize=11.5)
ax_bot.text(1, 5.5, f'{hw_at:.2f}% (HW Cache)', ha='center', va='center', color='white', fontweight='bold', fontsize=11.5)

# Top panel: expanded resolution layer (95.2 to 101.8%)
ax_top.set_ylim(95.2, 101.8)
ax_top.set_yticks([96, 98, 100])
ax_top.tick_params(axis='both', which='major', labelsize=11.5)

# Numbers inside expanded layers
ax_top.text(0, hw_ub + usr_ub/2, f'{usr_ub:.2f}%', ha='center', va='center', color='white', fontweight='bold', fontsize=11)
ax_top.text(0, hw_ub + usr_ub + drop_ub/2, f'{drop_ub:.2f}%', ha='center', va='center', color='white', fontweight='bold', fontsize=11)
ax_top.text(1, hw_at + drv_at/2, f'{drv_at:.2f}%', ha='center', va='center', color='white', fontweight='bold', fontsize=11.5)
ax_top.text(1, 100.12, f'{drop_at:.2f}%', ha='center', va='bottom', color='#e41a1c', fontweight='bold', fontsize=10.5)

# X-axis ticks
ax_bot.set_xticks([0, 1])
ax_bot.set_xticklabels(labels_breakdown, fontsize=12.5, fontweight='bold')
ax_bot.set_xlim(-0.6, 1.65)

# Spines and break slashes for broken axis
ax_top.spines['bottom'].set_visible(False)
ax_bot.spines['top'].set_visible(False)
ax_top.tick_params(labelbottom=False, bottom=False)

d = 0.015
kwargs = dict(transform=ax_top.transAxes, color='k', clip_on=False, linewidth=1.2)
ax_top.plot((-d, +d), (-d, +d), **kwargs)
ax_top.plot((1 - d, 1 + d), (-d, +d), **kwargs)

kwargs.update(transform=ax_bot.transAxes)
ax_bot.plot((-d, +d), (1 - d, 1 + d), **kwargs)
ax_bot.plot((1 - d, 1 + d), (1 - d, 1 + d), **kwargs)

ax_top.grid(axis='y', linestyle='--', alpha=0.45)
ax_bot.grid(axis='y', linestyle='--', alpha=0.45)

fig.text(0.015, 0.52, 'Share of Total Ingress Queries (%)', va='center', rotation='vertical', fontsize=13, fontweight='bold')
ax_top.set_title('Query Resolution Breakdown at UNLIMITED (7.66 MQPS)', fontweight='bold', pad=10, fontsize=14)

handles, leg_labels = ax_top.get_legend_handles_labels()
order = [0, 1, 2, 3] # [HW Cache, Ates Driver, Unbound, Dropped Queries]
ax_top.legend([handles[idx] for idx in order], [leg_labels[idx] for idx in order],
              loc='upper right', ncol=2, framealpha=0.96, fontsize=10, columnspacing=0.8, handletextpad=0.4)

plt.subplots_adjust(left=0.10, right=0.98, top=0.92, bottom=0.10)
save_png(fig, "calibrated_2core_query_resolution_breakdown_bars", "19_query_resolution_breakdown_bars")

# Publication-Grade Table Image: Query Resolution Breakdown at UNLIMITED
miss_ub = usr_ub + drop_ub
miss_at = drv_at + usr_at + drop_at

table_data = [
    ['Resolution Layer / Pipeline Stage', 'Unbound + HW Cache', 'AtesN-DS + HW Cache', 'Architectural Impact'],
    ['SmartNIC Silicon Cache (XDP_HW)', f'{sub_ub["hw_cache_hits"].mean():,.0f}  ({hw_ub:.2f}%)', f'{sub_at["hw_cache_hits"].mean():,.0f}  ({hw_at:.2f}%)', 'Hardware wire-speed hit (<18 µs)'],
    ['Host In-Kernel Driver (XDP_DRV)', '0  (0.00%)', f'{sub_at["driver_hits"].mean():,.0f}  ({drv_at:.2f}%)', 'Kernel fast-path absorbs HW misses'],
    ['User-Space Socket (Unbound)', f'{sub_ub["userspace_hits"].mean():,.0f}  ({usr_ub:.2f}%)', f'{sub_at["userspace_hits"].mean():,.0f}  ({usr_at:.3f}%)', 'Bypasses user-space socket queue bottleneck'],
    ['Ingress Query Drops (Loss)', f'{sub_ub["queries_lost"].mean():,.0f}  ({drop_ub:.2f}%)', f'{sub_at["queries_lost"].mean():,.0f}  ({drop_at:.2f}%)', f'{drop_ub/drop_at:.1f}x query loss reduction (24.5M saved)'],
    ['Total Ingress Queries (180s avg)', f'{tot_ub:,.0f}  (100.0%)', f'{tot_at:,.0f}  (100.0%)', 'Full 10GbE Line Rate (7.66 MQPS)'],
    ['Non-Hit Fallback Fate (3.82% Traffic)', f'Served: {usr_ub/miss_ub*100:.1f}% | Dropped: {drop_ub/miss_ub*100:.1f}%', f'Served: {(drv_at+usr_at)/miss_at*100:.1f}% | Dropped: {drop_at/miss_at*100:.1f}%', f'Host XDP resolves {drv_at/miss_at*100:.1f}% of HW misses']
]

fig_tbl, ax_tbl = plt.subplots(figsize=(13.2, 4.4))
ax_tbl.axis('off')
col_widths = [0.29, 0.22, 0.22, 0.35]
tbl = ax_tbl.table(cellText=table_data, loc='center', colWidths=col_widths)
tbl.auto_set_font_size(False)
tbl.set_fontsize(12.0)

for (r, c), cell in tbl.get_celld().items():
    cell.set_edgecolor('#d0d5dd')
    cell.set_linewidth(0.8)
    cell.set_height(0.125)
    
    # Text alignment
    if c == 0:
        cell.set_text_props(ha='left')
    elif c in [1, 2]:
        cell.set_text_props(ha='center')
    else:
        cell.set_text_props(ha='left')
        
    if r == 0:
        cell.set_facecolor('#1e293b') # Slate 800
        cell.set_text_props(color='white', fontweight='bold', fontsize=12.5, ha='center' if c in [1, 2] else ('left' if c == 0 else 'center'))
        cell.set_edgecolor('#0f172a')
        cell.set_linewidth(1.5)
    elif r == 4: # Dropped
        cell.set_facecolor('#fef2f2') # Soft red
        if c in [1, 2, 3]:
            cell.set_text_props(fontweight='bold')
            if c == 2:
                cell.set_text_props(color='#15803d', fontweight='bold')
            elif c == 1:
                cell.set_text_props(color='#b91c1c', fontweight='bold')
    elif r == 5: # Total
        cell.set_facecolor('#f1f5f9') # Light slate
        cell.set_text_props(fontweight='bold')
    elif r == 6: # Miss Fate
        cell.set_facecolor('#ecfdf5') # Soft emerald
        cell.set_text_props(fontweight='bold')
        if c == 2:
            cell.set_text_props(color='#047857', fontweight='bold')
    else:
        if r % 2 == 1:
            cell.set_facecolor('#ffffff')
        else:
            cell.set_facecolor('#f8fafc')

plt.title('Query Resolution Breakdown at UNLIMITED (7.66 MQPS, n=10 Repetitions)', fontsize=15, fontweight='bold', pad=16)
plt.tight_layout()
save_png(fig_tbl, "calibrated_2core_query_resolution_table", "19_query_resolution_table")
save_png(fig_tbl, "calibrated_2core_query_resolution_breakdown", "19_query_resolution_breakdown")

# Alternative: Dual-Panel Macro Ingress + Micro Fallback Breakdown
fig_dual, (ax1, ax2) = plt.subplots(1, 2, figsize=(12.0, 5.5), gridspec_kw={'width_ratios': [1, 1]})

# Panel 1: Total Ingress
ax1.bar(0, hw_ub, width_bd, color='#1b9e77', edgecolor='black', linewidth=1.0, label='HW Cache (SmartNIC)')
ax1.bar(0, usr_ub + drop_ub, width_bd, bottom=hw_ub, color='#fdae61', edgecolor='black', linewidth=1.0, label='Fallback & Misses')
ax1.bar(1, hw_at, width_bd, color='#1b9e77', edgecolor='black', linewidth=1.0)
ax1.bar(1, drv_at + drop_at, width_bd, bottom=hw_at, color='#fdae61', edgecolor='black', linewidth=1.0)

ax1.text(0, 48, f'{hw_ub:.1f}%\nHW Cache', ha='center', va='center', color='white', fontweight='bold', fontsize=13)
ax1.text(1, 48, f'{hw_at:.1f}%\nHW Cache', ha='center', va='center', color='white', fontweight='bold', fontsize=13)
ax1.text(0, 101, f'3.8%', ha='center', va='bottom', color='#333333', fontweight='bold', fontsize=11)
ax1.text(1, 101, f'3.8%', ha='center', va='bottom', color='#333333', fontweight='bold', fontsize=11)

ax1.set_ylabel('Total Ingress Traffic (%)', fontsize=14, fontweight='bold')
ax1.set_ylim(0, 108)
ax1.set_xticks([0, 1])
ax1.set_xticklabels(labels_breakdown, fontsize=12.5, fontweight='bold')
ax1.set_title('(a) Total Traffic Ingress at UNLIMITED', fontweight='bold', fontsize=14, pad=10)
ax1.grid(axis='y', linestyle='--', alpha=0.45)
ax1.legend(loc='lower center', framealpha=0.95, fontsize=11)

# Panel 2: Miss Fallback Handling (Normalized to 100% of misses)
tot_miss_ub = usr_ub + drop_ub
miss_usr_pct_ub = usr_ub / tot_miss_ub * 100.0
miss_drop_pct_ub = drop_ub / tot_miss_ub * 100.0

tot_miss_at = drv_at + drop_at
miss_drv_pct_at = drv_at / tot_miss_at * 100.0
miss_drop_pct_at = drop_at / tot_miss_at * 100.0

ax2.bar(0, miss_usr_pct_ub, width_bd, color='#d95f02', edgecolor='black', linewidth=1.0, label='Unbound (User Socket)')
ax2.bar(0, miss_drop_pct_ub, width_bd, bottom=miss_usr_pct_ub, color='#e41a1c', edgecolor='black', linewidth=1.0, label='Dropped Queries')
ax2.bar(1, miss_drv_pct_at, width_bd, color='#7570b3', edgecolor='black', linewidth=1.0, label='Ates Driver (Host XDP)')
ax2.bar(1, miss_drop_pct_at, width_bd, bottom=miss_drv_pct_at, color='#e41a1c', edgecolor='black', linewidth=1.0)

ax2.text(0, miss_usr_pct_ub/2, f'{miss_usr_pct_ub:.1f}%\nUserspace', ha='center', va='center', color='white', fontweight='bold', fontsize=11.5)
ax2.text(0, miss_usr_pct_ub + miss_drop_pct_ub/2, f'{miss_drop_pct_ub:.1f}%\nDropped', ha='center', va='center', color='white', fontweight='bold', fontsize=11.5)
ax2.text(1, miss_drv_pct_at/2, f'{miss_drv_pct_at:.1f}%\nHost XDP', ha='center', va='center', color='white', fontweight='bold', fontsize=12)
ax2.text(1, 101, f'{miss_drop_pct_at:.1f}% Drop', ha='center', va='bottom', color='#e41a1c', fontweight='bold', fontsize=11)

ax2.set_ylabel('Share of Fallback/Miss Queries (%)', fontsize=14, fontweight='bold')
ax2.set_ylim(0, 108)
ax2.set_xticks([0, 1])
ax2.set_xticklabels(labels_breakdown, fontsize=12.5, fontweight='bold')
ax2.set_title('(b) Fallback Resolution (3.82% of Traffic)', fontweight='bold', fontsize=14, pad=10)
ax2.grid(axis='y', linestyle='--', alpha=0.45)
ax2.legend(loc='lower left', bbox_to_anchor=(0.02, 0.03), framealpha=0.95, fontsize=10.5)

plt.tight_layout()
save_png(fig_dual, "calibrated_2core_query_resolution_dual_panel", "19_query_resolution_dual_panel")

# =========================================================================
# 5. CCDF SUITE
# =========================================================================
print("\n[5/5] CCDF Figures...")
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

# 5.1 2x2 CCDF Grid
SCENARIOS = [
    (500000,  "500 kQPS Offered Load",
     ['unbound_standalone', 'unbound_hw_cache', 'ates_driver', 'ates_hw_cache']),
    (1000000, "1.0 MQPS Offered Load",
     ['unbound_hw_cache', 'ates_driver', 'ates_hw_cache']),
    (3000000, "3.0 MQPS Offered Load",
     ['unbound_hw_cache', 'ates_driver', 'ates_hw_cache']),
    (0,       "UNLIMITED Offered Load (7.66 MQPS)",
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
                marker=MODE_MARKERS[mode], linewidth=2.6, markersize=7.5, alpha=0.9)
    ax.set_yscale('log')
    ax.set_ylim(0.00008, 1.3)
    ax.set_title(title, fontweight='bold', pad=8, fontsize=15)
    ax.set_xlabel("Response Latency (ms)", fontsize=14, fontweight='bold', labelpad=6)
    ax.tick_params(axis='both', which='major', labelsize=12.5)
    ax.grid(True, which='both', linestyle='--', alpha=0.5)
    if idx % 2 == 0:
        ax.set_ylabel(r"CCDF: $P(\mathrm{Latency} > x)$", fontsize=15, fontweight='bold', labelpad=6)
        ax.set_yticks([1.0, 0.5, 0.1, 0.01, 0.001, 0.0001])
        ax.set_yticklabels(['1.0 (min)', '0.50 ($p_{50}$)', '0.10 ($p_{90}$)', '0.01 ($p_{99}$)', '0.001 ($p_{99.9}$)', '0.0001 (max)'], fontsize=12)
    if idx == 0:
        ax.legend(loc='lower left', bbox_to_anchor=(0.006, 0.015), borderaxespad=0.15, framealpha=0.94, fontsize=12)
    else:
        ax.legend(loc='upper right', framealpha=0.94, fontsize=12)

plt.suptitle("Latency Complementary Cumulative Distribution Function (CCDF)", fontsize=18, y=0.99, fontweight='bold')
plt.tight_layout()
save_png(fig, "calibrated_2core_ccdf_operational_2x2", "20_latency_ccdf_operational_2x2")

# 5.1b 1x3 CCDF Grid (500k, 5M, UNLIMITED - Key Operational Regimes)
SCENARIOS_1X3 = [
    (500000,  "(a) 500 kQPS Offered Load", ['unbound_standalone', 'unbound_hw_cache', 'ates_driver', 'ates_hw_cache']),
    (5000000, "(b) 5.0 MQPS Offered Load", ['unbound_hw_cache', 'ates_driver', 'ates_hw_cache']),
    (0,       "(c) UNLIMITED (7.66 MQPS)",  ['unbound_hw_cache', 'ates_driver', 'ates_hw_cache']),
]

fig, axes = plt.subplots(1, 3, figsize=(16, 5.2), sharey=True)
for idx, (qps, title, active_modes) in enumerate(SCENARIOS_1X3):
    ax = axes[idx]
    for mode in active_modes:
        sub = df[(df['mode'] == mode) & (df['target_qps'] == qps)]
        if sub.empty: continue
        lat_coords = [sub[col].mean() for col, _ in P_MAP]
        ccdf_coords = [c for _, c in P_MAP]
        ax.plot(lat_coords, ccdf_coords, label=MODE_LABELS[mode], color=MODE_COLORS[mode],
                marker=MODE_MARKERS[mode], linewidth=2.6, markersize=7.5, alpha=0.9)
    ax.set_yscale('log')
    ax.set_ylim(0.00008, 1.3)
    ax.set_title(title, fontweight='bold', pad=10, fontsize=15)
    ax.set_xlabel("Response Latency (ms)", fontsize=14, fontweight='bold', labelpad=8)
    ax.tick_params(axis='both', which='major', labelsize=12.5)
    ax.grid(True, which='both', linestyle='--', alpha=0.5)
    if idx == 0:
        ax.set_ylabel(r"CCDF: $P(\mathrm{Latency} > x)$", fontsize=15, fontweight='bold', labelpad=6)
        ax.set_yticks([1.0, 0.5, 0.1, 0.01, 0.001, 0.0001])
        ax.set_yticklabels(['1.0 (min)', '0.50 ($p_{50}$)', '0.10 ($p_{90}$)', '0.01 ($p_{99}$)', '0.001 ($p_{99.9}$)', '0.0001 (max)'], fontsize=11.5)
        ax.legend(loc='lower left', bbox_to_anchor=(0.006, 0.015), borderaxespad=0.15, framealpha=0.94, fontsize=11.5)
    else:
        ax.legend(loc='upper right', framealpha=0.94, fontsize=12)

plt.suptitle("Latency Complementary Cumulative Distribution Function (CCDF) Across Operational Regimes", fontsize=17, y=1.01, fontweight='bold')
plt.tight_layout()
save_png(fig, "calibrated_2core_ccdf_1x3_key_rates", "20_latency_ccdf_1x3_key_rates")

# 5.2 Individual CCDF plots
for rate_idx, rate in enumerate(RATE_ORDER):
    fig, ax = plt.subplots(figsize=(8.8, 5.6))
    if rate in (0, '0', 'UNLIMITED'):
        r_str = "UNLIMITED_7_66MQPS"
        r_num = "25_ccdf_unlimited"
        r_title = "UNLIMITED (7.66 MQPS)"
    elif rate >= 1000000:
        r_str = f"{rate//1000000}MQPS" if rate % 1000000 == 0 else f"{rate/1000000:.1f}MQPS"
        r_title = f"{rate/1000000:.1f} MQPS".replace(".0", "")
        r_num = f"{21 + rate_idx}_ccdf_{rate//1000000}M"
    else:
        r_str = f"{rate//1000}kQPS"
        r_title = f"{rate//1000} kQPS"
        r_num = "21_ccdf_500k"
    
    modes = MODE_ORDER if rate == 500000 else ['unbound_hw_cache', 'ates_driver', 'ates_hw_cache']
        
    for mode in modes:
        sub = df[(df['mode'] == mode) & (df['target_qps'] == rate)]
        if sub.empty: continue
        lat_coords = [sub[col].mean() for col, _ in P_MAP]
        ccdf_coords = [c for _, c in P_MAP]
        ax.plot(lat_coords, ccdf_coords, label=MODE_LABELS[mode], color=MODE_COLORS[mode],
                marker=MODE_MARKERS[mode], linewidth=2.8, markersize=8.5, alpha=0.9)
                
    ax.set_yscale('log')
    ax.set_ylim(0.00008, 1.3)
    ax.set_ylabel(r"CCDF: $P(\mathrm{Latency} > x)$", fontsize=16, fontweight='bold', labelpad=9)
    ax.set_yticks([1.0, 0.5, 0.1, 0.01, 0.001, 0.0001])
    ax.set_yticklabels(['1.0 (min)', '0.50 ($p_{50}$)', '0.10 ($p_{90}$)', '0.01 ($p_{99}$)', '0.001 ($p_{99.9}$)', '0.0001 (max)'], fontsize=13)
    ax.tick_params(axis='x', which='major', labelsize=13.5)
    ax.set_xlabel("Response Latency (ms)", fontsize=16, fontweight='bold', labelpad=10)
    ax.set_title(f"Latency CCDF at {r_title}", fontweight='bold', pad=12, fontsize=18)
    ax.grid(True, which='both', linestyle='--', alpha=0.5)
    if rate == 500000:
        ax.legend(loc='lower left', bbox_to_anchor=(0.006, 0.015), borderaxespad=0.15, framealpha=0.94, fontsize=13)
    else:
        ax.legend(loc='upper right', framealpha=0.94, fontsize=13)
    plt.tight_layout()
    save_png(fig, f"calibrated_2core_ccdf_{r_str}", r_num)

# =========================================================================
# 6. 1-CORE BENCHMARK FIGURES
# =========================================================================
ONECORE_CSV = os.path.join(PROJECT_ROOT, "official_results", "07_single_core_max_throughput", "summary_1core_clean_warmup_10reps.csv")
if os.path.exists(ONECORE_CSV):
    print("\n[6/6] Generating 1-Core Benchmark Figures...")
    df1 = pd.read_csv(ONECORE_CSV)
    df1['target_qps_str'] = df1['target_qps'].astype(str)
    
    r1_order = ['70000', '2000000', '0']
    r1_labels = ['70k', '2M', 'UNLIMITED\n(7.69 MQPS)']
    x1_indices = np.arange(len(r1_order))
    
    # 6.1a 1-Core Throughput Scaling Line (Log Scale - Default matching Figure 1)
    fig, ax = plt.subplots(figsize=(8.8, 5.6))
    ideal_qps_raw = [70000, 2000000, 7689807]
    ax.plot(x1_indices, ideal_qps_raw, 'k--', linewidth=2.0, alpha=0.6, label='Ideal Offered Load')
    for mode in ['ates_hw_cache', 'unbound_hw_cache', 'ates_driver', 'unbound_standalone']:
        mdf = df1[df1['mode'] == mode]
        means = [mdf[mdf['target_qps_str'] == r]['achieved_qps_mean'].values[0] for r in r1_order]
        stds = [mdf[mdf['target_qps_str'] == r]['achieved_qps_std'].values[0] if 'achieved_qps_std' in mdf else 0 for r in r1_order]
        ax.errorbar(x1_indices, means, yerr=stds, marker=MODE_MARKERS[mode], linewidth=2.8, markersize=8.5,
                    capsize=4, label=MODE_LABELS[mode], color=MODE_COLORS[mode])
    ax.set_yscale('log')
    ax.set_ylim(15, 25000000)
    log_ticks = [10, 100, 1000, 10000, 100000, 1000000, 10000000]
    log_labels = ['10 QPS', '100 QPS', '1 kQPS', '10 kQPS', '100 kQPS', '1 MQPS', '10 MQPS']
    ax.set_yticks(log_ticks)
    ax.set_yticklabels(log_labels, fontsize=13.5)
    ax.set_ylabel("Achieved Throughput [Log Scale]", fontsize=16, fontweight='bold', labelpad=9)
    ax.set_title("1-Core Throughput Scaling vs. Offered Load", fontweight='bold', pad=12, fontsize=18)
    ax.set_xlim(-0.18, len(r1_order) - 1 + 0.18)
    ax.set_xticks(x1_indices)
    ax.set_xticklabels(r1_labels, fontsize=13.5)
    ax.tick_params(axis='both', which='major', labelsize=13.5)
    ax.set_xlabel("Target Offered Load", labelpad=10, fontsize=16, fontweight='bold')
    ax.grid(True, which='both', linestyle='--', alpha=0.45)
    ax.legend(loc='upper left', framealpha=0.95, fontsize=13)
    plt.tight_layout()
    save_png(fig, "calibrated_1core_throughput_scaling_curve", "26_1core_throughput_scaling_curve")
    save_png(fig, "calibrated_1core_throughput_scaling_log", "26_1core_throughput_scaling_curve_log")

    # 6.1a2 1-Core Throughput Scaling Line (Linear Scale - MQPS)
    fig, ax = plt.subplots(figsize=(8.8, 5.6))
    ideal_qps_m = [0.07, 2.0, 7.69]
    ax.plot(x1_indices, ideal_qps_m, 'k--', linewidth=2.0, alpha=0.6, label='Ideal Offered Load')
    for mode in ['ates_hw_cache', 'unbound_hw_cache', 'ates_driver', 'unbound_standalone']:
        mdf = df1[df1['mode'] == mode]
        means = [mdf[mdf['target_qps_str'] == r]['achieved_qps_mean'].values[0] / 1e6 for r in r1_order]
        stds = [mdf[mdf['target_qps_str'] == r]['achieved_qps_std'].values[0] / 1e6 if 'achieved_qps_std' in mdf else 0 for r in r1_order]
        ax.errorbar(x1_indices, means, yerr=stds, marker=MODE_MARKERS[mode], linewidth=2.8, markersize=8.5,
                    capsize=4, label=MODE_LABELS[mode], color=MODE_COLORS[mode])

    ax.set_ylabel("Achieved Throughput (MQPS)", fontsize=16, fontweight='bold', labelpad=9)
    ax.set_xlim(-0.25, len(r1_order) - 1 + 0.25)
    ax.set_ylim(-0.15, 8.5)
    major_y = np.arange(0.0, 9.0, 1.0)
    ax.set_yticks(major_y)
    ax.set_yticklabels([f'{y:.1f}' if y != int(y) else f'{int(y)}' for y in major_y], fontsize=13.5)
    ax.yaxis.set_minor_locator(ticker.MultipleLocator(0.2))
    ax.set_title("1-Core Throughput Scaling vs. Offered Load", fontweight='bold', pad=12, fontsize=18)
    ax.set_xticks(x1_indices)
    ax.set_xticklabels(r1_labels, fontsize=14, fontweight='bold')
    ax.tick_params(axis='both', which='major', labelsize=13.5)
    ax.set_xlabel("Target Offered Load", labelpad=10, fontsize=16, fontweight='bold')
    ax.grid(True, which='major', axis='y', linestyle='--', alpha=0.6, color='#aaaaaa', linewidth=1.0)
    ax.grid(True, which='minor', axis='y', linestyle=':', alpha=0.35, color='#cccccc')
    ax.grid(True, which='major', axis='x', linestyle='--', alpha=0.4, color='#aaaaaa')
    ax.legend(loc='upper left', framealpha=0.95, fontsize=13)
    plt.tight_layout()
    save_png(fig, "calibrated_1core_throughput_scaling_line", "26_1core_throughput_scaling_curve_linear")

    # 6.1b 1-Core Throughput Bar Chart (Realistic Linear Scale with Numeric Value Labels)
    fig, ax = plt.subplots(figsize=(10.5, 6.0))
    width = 0.18
    for idx, mode in enumerate(MODE_ORDER):
        mdf = df1[df1['mode'] == mode]
        means = [mdf[mdf['target_qps_str'] == r]['achieved_qps_mean'].values[0] / 1e6 for r in r1_order]
        stds = [mdf[mdf['target_qps_str'] == r]['achieved_qps_std'].values[0] / 1e6 if 'achieved_qps_std' in mdf else 0 for r in r1_order]
        pos = x1_indices + (idx - 1.5) * width
        rects = ax.bar(pos, means, width, yerr=stds, capsize=3, label=MODE_LABELS[mode], color=MODE_COLORS[mode], edgecolor='black', linewidth=0.8)
        for rect, val in zip(rects, means):
            qps = val * 1e6
            if qps >= 1e6:
                text = f'{val:.2f}M'
            elif qps >= 1e3:
                text = f'{qps/1e3:.1f}k'
            elif qps > 0:
                text = f'{qps:.0f}'
            else:
                text = '0'
            ax.annotate(text,
                        xy=(rect.get_x() + rect.get_width() / 2, max(rect.get_height(), 0.08)),
                        xytext=(0, 5), textcoords='offset points',
                        ha='center', va='bottom', fontsize=12.0, fontweight='bold', rotation=90)

    ax.set_ylim(0, 10.5)
    ax.set_yticks(np.arange(0.0, 11.0, 1.0))
    ax.set_xticks(x1_indices)
    ax.set_xticklabels(r1_labels, fontsize=14, fontweight='bold')
    ax.tick_params(axis='both', which='major', labelsize=13.5)
    ax.set_ylabel("Achieved Throughput (MQPS)", fontsize=16, fontweight='bold', labelpad=9)
    ax.set_title("1-Core Achieved DNS Throughput vs. Offered Load", fontweight='bold', pad=14, fontsize=18)
    ax.set_xlabel("Target Offered Load", labelpad=10, fontsize=16, fontweight='bold')
    ax.grid(axis='y', linestyle='--', alpha=0.5)
    ax.legend(loc='upper left', ncol=2, framealpha=0.95, fontsize=13)
    plt.tight_layout()
    save_png(fig, "calibrated_1core_throughput_bars", "26_1core_throughput_bars")
    save_png(fig, "calibrated_1core_throughput_bars_linear", "26_1core_throughput_bars_linear")

    # 6.1b2 1-Core Log Bar Chart (Preserved for Reference)
    fig, ax = plt.subplots(figsize=(10.5, 6.0))
    for idx, mode in enumerate(MODE_ORDER):
        mdf = df1[df1['mode'] == mode]
        means = [mdf[mdf['target_qps_str'] == r]['achieved_qps_mean'].values[0] for r in r1_order]
        pos = x1_indices + (idx - 1.5) * width
        rects = ax.bar(pos, means, width, label=MODE_LABELS[mode], color=MODE_COLORS[mode], edgecolor='black', linewidth=0.8)
        for rect, val in zip(rects, means):
            if val >= 1e6:
                text = f'{val/1e6:.2f}M'
            elif val >= 1e3:
                text = f'{val/1e3:.1f}k'
            else:
                text = f'{val:.0f}'
            ax.annotate(text,
                        xy=(rect.get_x() + rect.get_width() / 2, rect.get_height()),
                        xytext=(0, 5), textcoords='offset points',
                        ha='center', va='bottom', fontsize=11.5, fontweight='bold', rotation=90)
    ax.set_yscale('log')
    ax.set_ylim(10, 350000000)
    ax.set_yticks(log_ticks)
    ax.set_yticklabels(log_labels, fontsize=13)
    ax.set_ylabel("Achieved Throughput [Log Scale]", fontsize=16, fontweight='bold', labelpad=9)
    ax.set_xlim(-0.5, len(r1_order) - 0.5)
    ax.set_xticks(x1_indices)
    ax.set_xticklabels(r1_labels, fontsize=14, fontweight='bold')
    ax.tick_params(axis='both', which='major', labelsize=13.5)
    ax.set_xlabel("Target Offered Load", labelpad=10, fontsize=16, fontweight='bold')
    ax.set_title("1-Core Achieved DNS Throughput (Log Bars)", fontweight='bold', pad=14, fontsize=18)
    ax.grid(True, which='both', axis='y', linestyle='--', alpha=0.45)
    ax.legend(loc='upper left', ncol=2, framealpha=0.95, fontsize=13)
    plt.tight_layout()
    save_png(fig, "calibrated_1core_throughput_bars_log", "26_1core_throughput_bars_log")

    # 6.1c 1-Core Throughput Dual-Panel (Left: 70k in kQPS, Right: 2M & UNLIMITED in MQPS)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14.5, 7.0), gridspec_kw={'width_ratios': [1, 2.1]})
    width_dp = 0.22
    step_dp = 0.28
    x1_dp = np.array([0])
    for idx, mode in enumerate(MODE_ORDER):
        mdf = df1[(df1['mode'] == mode) & (df1['target_qps_str'] == '70000')]
        val = mdf['achieved_qps_mean'].values[0] / 1000.0 if not mdf.empty else 0
        err = mdf['achieved_qps_std'].values[0] / 1000.0 if not mdf.empty and 'achieved_qps_std' in mdf else 0
        pos = x1_dp + (idx - 1.5) * step_dp
        rects = ax1.bar(pos, [val], width_dp, yerr=[err], capsize=4, label=MODE_LABELS[mode], color=MODE_COLORS[mode], edgecolor='black', linewidth=1.0)
        for rect in rects:
            ax1.annotate(f'{val:.1f}k',
                         xy=(rect.get_x() + rect.get_width() / 2, max(val, 2.0)),
                         xytext=(0, 6), textcoords='offset points',
                         ha='center', va='bottom', fontsize=15.0, fontweight='bold', rotation=0)
    ax1.set_ylabel("Achieved Throughput (kQPS)", fontsize=18, fontweight='bold', labelpad=10)
    ax1.set_ylim(0, 95)
    ax1.set_yticks(np.arange(0, 100, 10))
    ax1.set_xticks([0])
    ax1.set_xticklabels(['70k Offered'], fontsize=17, fontweight='bold')
    ax1.tick_params(axis='both', which='major', labelsize=16)
    ax1.set_title("Low Load (70k)", fontweight='bold', fontsize=18, pad=12)
    ax1.grid(axis='y', linestyle='--', alpha=0.5)

    x2_dp = np.array([0, 1.15])
    r2_order = ['2000000', '0']
    r2_labels = ['2M Offered', 'UNLIMITED\n(7.69 MQPS)']
    for idx, mode in enumerate(MODE_ORDER):
        mdf = df1[df1['mode'] == mode]
        vals = [mdf[mdf['target_qps_str'] == r]['achieved_qps_mean'].values[0] / 1e6 for r in r2_order]
        errs = [mdf[mdf['target_qps_str'] == r]['achieved_qps_std'].values[0] / 1e6 if 'achieved_qps_std' in mdf else 0 for r in r2_order]
        pos = x2_dp + (idx - 1.5) * step_dp
        rects = ax2.bar(pos, vals, width_dp, yerr=errs, capsize=4, label=MODE_LABELS[mode], color=MODE_COLORS[mode], edgecolor='black', linewidth=1.0)
        for rect, val in zip(rects, vals):
            qps = val * 1e6
            if qps >= 1e6:
                text = f'{val:.2f}M'
            elif qps >= 1e3:
                text = f'{qps/1e3:.1f}k'
            elif qps > 0:
                text = f'{qps:.0f}'
            else:
                text = '0'
            ax2.annotate(text,
                         xy=(rect.get_x() + rect.get_width() / 2, max(val, 0.12)),
                         xytext=(0, 6), textcoords='offset points',
                         ha='center', va='bottom', fontsize=15.0, fontweight='bold', rotation=0)
    ax2.set_ylabel("Achieved Throughput (MQPS)", fontsize=18, fontweight='bold', labelpad=10)
    ax2.set_ylim(0, 10.2)
    ax2.set_xlim(-0.60, 1.75)
    ax2.set_yticks(np.arange(0.0, 11.0, 1.0))
    ax2.set_xticks(x2_dp)
    ax2.set_xticklabels(r2_labels, fontsize=17, fontweight='bold')
    ax2.tick_params(axis='both', which='major', labelsize=16)
    ax2.set_title("High & Maximum Load", fontweight='bold', fontsize=18, pad=12)
    ax2.grid(axis='y', linestyle='--', alpha=0.5)
    ax2.legend(loc='upper left', ncol=2, fontsize=14.5, framealpha=0.96)
    plt.suptitle("1-Core Achieved DNS Throughput", fontweight='bold', fontsize=20, y=0.99)
    plt.tight_layout()
    save_png(fig, "calibrated_1core_throughput_dual_panel", "26_1core_throughput_dual_panel")
    
    # 6.2 1-Core Packet Loss
    fig, ax = plt.subplots(figsize=(8.8, 5.6))
    for mode in MODE_ORDER:
        mdf = df1[df1['mode'] == mode]
        loss_vals = [mdf[mdf['target_qps_str'] == r]['loss_pct_mean'].values[0] if not mdf[mdf['target_qps_str'] == r].empty else np.nan for r in r1_order]
        ax.plot(x1_indices, loss_vals, marker=MODE_MARKERS[mode], linewidth=2.8, markersize=8.5,
                label=MODE_LABELS[mode], color=MODE_COLORS[mode])
    ax.set_ylabel("Packet Loss Rate (%)", fontsize=16, fontweight='bold', labelpad=9)
    ax.set_title("1-Core Packet Loss Rate vs. Offered Load", fontweight='bold', pad=12, fontsize=18)
    ax.set_xlim(-0.18, len(r1_order) - 1 + 0.18)
    ax.set_xticks(x1_indices)
    ax.set_xticklabels(r1_labels, fontsize=13.5)
    ax.tick_params(axis='both', which='major', labelsize=13.5)
    ax.set_xlabel("Target Offered Load", labelpad=10, fontsize=16, fontweight='bold')
    ax.set_ylim(-2, 105)
    ax.grid(True, linestyle='--', alpha=0.5)
    ax.legend(loc='center left', bbox_to_anchor=(0.04, 0.48), framealpha=0.95, fontsize=13)
    plt.tight_layout()
    save_png(fig, "calibrated_1core_packet_loss", "27_1core_packet_loss")
    
    # 6.3 1-Core Tail Latency p99
    fig, ax = plt.subplots(figsize=(8.8, 5.6))
    ticks = [2, 3, 5, 7, 10, 15, 20, 30, 50, 75, 100, 200, 400]
    for mode in MODE_ORDER:
        mdf = df1[df1['mode'] == mode]
        p99_vals = [mdf[mdf['target_qps_str'] == r]['lat_p99_ms'].values[0] if not mdf[mdf['target_qps_str'] == r].empty else np.nan for r in r1_order]
        ax.plot(x1_indices, p99_vals, marker=MODE_MARKERS[mode], linewidth=2.8, markersize=8.5,
                label=MODE_LABELS[mode], color=MODE_COLORS[mode])
    ax.set_ylabel("Tail Latency $p_{99}$ (ms) [Log Scale]", fontsize=16, fontweight='bold', labelpad=9)
    ax.set_yscale('log')
    ax.set_ylim(bottom=1.8, top=500)
    ax.set_yticks(ticks)
    ax.yaxis.set_major_formatter(ticker.ScalarFormatter())
    ax.yaxis.set_minor_formatter(ticker.NullFormatter())
    ax.set_title("1-Core Tail Latency $p_{99}$ vs. Offered Load", fontweight='bold', pad=12, fontsize=18)
    ax.set_xlim(-0.18, len(r1_order) - 1 + 0.18)
    ax.set_xticks(x1_indices)
    ax.set_xticklabels(r1_labels, fontsize=13.5)
    ax.tick_params(axis='both', which='major', labelsize=13.5)
    ax.set_xlabel("Target Offered Load", labelpad=10, fontsize=16, fontweight='bold')
    ax.grid(True, which='both', linestyle='--', alpha=0.5)
    ax.legend(loc='upper right', framealpha=0.94, fontsize=13)
    plt.tight_layout()
    save_png(fig, "calibrated_1core_tail_latency_p99", "28_1core_tail_latency_p99")
    
    # 6.4 1-Core Tail Latency p99.9
    fig, ax = plt.subplots(figsize=(8.8, 5.6))
    for mode in MODE_ORDER:
        mdf = df1[df1['mode'] == mode]
        p99_9_vals = [mdf[mdf['target_qps_str'] == r]['lat_p99_9_ms'].values[0] if not mdf[mdf['target_qps_str'] == r].empty else np.nan for r in r1_order]
        ax.plot(x1_indices, p99_9_vals, marker=MODE_MARKERS[mode], linewidth=2.8, markersize=8.5,
                label=MODE_LABELS[mode], color=MODE_COLORS[mode])
    ax.set_ylabel("Tail Latency $p_{99.9}$ (ms) [Log Scale]", fontsize=16, fontweight='bold', labelpad=9)
    ax.set_yscale('log')
    ax.set_ylim(bottom=1.8, top=500)
    ax.set_yticks(ticks)
    ax.yaxis.set_major_formatter(ticker.ScalarFormatter())
    ax.yaxis.set_minor_formatter(ticker.NullFormatter())
    ax.set_title("1-Core Tail Latency $p_{99.9}$ vs. Offered Load", fontweight='bold', pad=12, fontsize=18)
    ax.set_xlim(-0.18, len(r1_order) - 1 + 0.18)
    ax.set_xticks(x1_indices)
    ax.set_xticklabels(r1_labels, fontsize=13.5)
    ax.tick_params(axis='both', which='major', labelsize=13.5)
    ax.set_xlabel("Target Offered Load", labelpad=10, fontsize=16, fontweight='bold')
    ax.grid(True, which='both', linestyle='--', alpha=0.5)
    ax.legend(loc='upper right', framealpha=0.94, fontsize=13)
    plt.tight_layout()
    save_png(fig, "calibrated_1core_tail_latency_p99_9", "29_1core_tail_latency_p99_9")
    
    # 6.5 1-Core Server CPU Saturation
    fig, ax = plt.subplots(figsize=(8.8, 5.6))
    for mode in MODE_ORDER:
        mdf = df1[df1['mode'] == mode].copy()
        mdf['qps_m'] = mdf['achieved_qps_mean'] / 1e6
        mdf['dedicated_cpu'] = mdf['srv_c0_busy_mean'] if 'srv_c0_busy_mean' in mdf.columns else mdf['srv_all_busy_mean']
        mdf = mdf.sort_values('qps_m')
        ax.plot(mdf['qps_m'], mdf['dedicated_cpu'], marker=MODE_MARKERS[mode], linewidth=2.8, markersize=8.5,
                label=MODE_LABELS[mode], color=MODE_COLORS[mode])
    ax.set_xlabel("Achieved Throughput (MQPS)", fontsize=16, fontweight='bold', labelpad=10)
    ax.set_xlim(-0.35, 8.35)
    ax.set_xticks(np.arange(0, 9.0, 1.0))
    ax.tick_params(axis='both', which='major', labelsize=13.5)
    ax.set_ylabel("Dedicated Core 0 Utilization (%)", fontsize=16, fontweight='bold', labelpad=9)
    ax.set_ylim(-2, 103)
    ax.set_title("1-Core Server CPU Saturation Curve", fontweight='bold', pad=12, fontsize=18)
    ax.grid(True, linestyle='--', alpha=0.5)
    ax.legend(loc='lower right', framealpha=0.94, fontsize=13)
    plt.tight_layout()
    save_png(fig, "calibrated_1core_cpu_saturation", "30_1core_cpu_saturation")

    # 6.6 1-Core Dedicated Core 0 Utilization vs Target Rate
    fig, ax = plt.subplots(figsize=(8.8, 5.6))
    for mode in MODE_ORDER:
        mdf = df1[df1['mode'] == mode]
        cpu_vals = [mdf[mdf['target_qps_str'] == r]['srv_c0_busy_mean'].values[0] if not mdf[mdf['target_qps_str'] == r].empty else np.nan for r in r1_order]
        ax.plot(x1_indices, cpu_vals, marker=MODE_MARKERS[mode], linewidth=2.8, markersize=8.5,
                label=MODE_LABELS[mode], color=MODE_COLORS[mode])
    ax.set_ylabel("Dedicated Core 0 Utilization (%)", fontsize=16, fontweight='bold', labelpad=9)
    ax.set_title("1-Core Dedicated Server Core Utilization", fontweight='bold', pad=12, fontsize=18)
    ax.set_xlim(-0.18, len(r1_order) - 1 + 0.18)
    ax.set_xticks(x1_indices)
    ax.set_xticklabels(r1_labels, fontsize=13.5)
    ax.tick_params(axis='both', which='major', labelsize=13.5)
    ax.set_xlabel("Target Offered Load", labelpad=10, fontsize=16, fontweight='bold')
    ax.set_ylim(-2, 103)
    ax.grid(True, linestyle='--', alpha=0.5)
    ax.legend(loc='upper left', framealpha=0.95, fontsize=13)
    plt.tight_layout()
    save_png(fig, "calibrated_1core_cpu_dedicated_core", "31_1core_cpu_dedicated_core")

    # 6.7 1-Core SoftIRQ Load vs Target Rate
    fig, ax = plt.subplots(figsize=(8.8, 5.6))
    for mode in MODE_ORDER:
        mdf = df1[df1['mode'] == mode]
        sirq_vals = [mdf[mdf['target_qps_str'] == r]['srv_softirq_mean'].values[0] if not mdf[mdf['target_qps_str'] == r].empty else np.nan for r in r1_order]
        ax.plot(x1_indices, sirq_vals, marker=MODE_MARKERS[mode], linewidth=2.8, markersize=8.5,
                label=MODE_LABELS[mode], color=MODE_COLORS[mode])
    ax.set_ylabel("Server SoftIRQ Load (%)", fontsize=16, fontweight='bold', labelpad=9)
    ax.set_title("1-Core Host Kernel SoftIRQ Load", fontweight='bold', pad=12, fontsize=18)
    ax.set_xlim(-0.18, len(r1_order) - 1 + 0.18)
    ax.set_xticks(x1_indices)
    ax.set_xticklabels(r1_labels, fontsize=13.5)
    ax.tick_params(axis='both', which='major', labelsize=13.5)
    ax.set_xlabel("Target Offered Load", labelpad=10, fontsize=16, fontweight='bold')
    ax.set_ylim(-1, 30)
    ax.grid(True, linestyle='--', alpha=0.5)
    ax.legend(loc='upper left', framealpha=0.95, fontsize=13)
    plt.tight_layout()
    save_png(fig, "calibrated_1core_cpu_softirq_load", "32_1core_cpu_softirq_load")

print(f"\n✅ All PNG figures generated successfully in: {PAPER_PNG_DIR}")
