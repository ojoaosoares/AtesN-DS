#!/usr/bin/env python3
# ==============================================================================
# plot_dynamic_eviction_suite.py
#
# Publication-ready figure suite for Dynamic TTL Cache Eviction Benchmark.
# Formatted specifically for IEEE/ACM 2-column paper inclusion:
#   - Large typography matching static TTL benchmark suite (21pt titles, 19pt labels)
#   - High-contrast color palette and distinct markers
#   - Clean academic titles (omitting PCIe, 2 cores, 4 queues)
#   - Dual export: High-res PNG (300 DPI) and vector PDF
# ==============================================================================

import os
import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

# Configure global style and PAPER-READY LARGE typography
plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams.update({
    'font.size': 15,
    'axes.labelsize': 18,
    'axes.titlesize': 20,
    'axes.labelweight': 'bold',
    'xtick.labelsize': 15,
    'ytick.labelsize': 15,
    'legend.fontsize': 13.5,
    'figure.titlesize': 21,
    'font.family': 'sans-serif',
    'lines.linewidth': 3.0,
    'lines.markersize': 9.0,
    'grid.alpha': 0.45,
})

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))

RAW_CSV = os.path.join(SCRIPT_DIR, "raw_3levels_5reps.csv")
SUMMARY_CSV = os.path.join(SCRIPT_DIR, "summary_3levels_5reps.csv")

OUT_DIR = os.path.join(SCRIPT_DIR, "plots_dynamic_suite")
PAPER_FIGS_DIR = os.path.join(PROJECT_ROOT, "figs")
os.makedirs(OUT_DIR, exist_ok=True)
os.makedirs(PAPER_FIGS_DIR, exist_ok=True)

MODE_ORDER = ['unbound_standalone', 'unbound_hw_cache', 'ates_driver', 'ates_hw_cache']
MODE_LABELS = {
    'unbound_standalone': 'Unbound Standalone',
    'unbound_hw_cache':   'Unbound + SmartNIC HW',
    'ates_driver':        'AtesN-DS Driver Mode',
    'ates_hw_cache':      'AtesN-DS + SmartNIC HW',
}
MODE_COLORS = {
    'unbound_standalone': '#d95f02',   # Orange
    'unbound_hw_cache':   '#1b9e77',   # Green/Teal
    'ates_driver':        '#7570b3',   # Purple
    'ates_hw_cache':      '#e7298a',   # Magenta
}
MODE_MARKERS = {
    'unbound_standalone': 'o',
    'unbound_hw_cache':   '^',
    'ates_driver':        's',
    'ates_hw_cache':      'D',
}

RATE_ORDER = [1000000, 4000000, 0]
RATE_LABELS = ['1.0M', '4.0M', 'Line-Rate']

def save_fig(fig, base_name):
    for d in [OUT_DIR, PAPER_FIGS_DIR]:
        png_path = os.path.join(d, f"{base_name}.png")
        pdf_path = os.path.join(d, f"{base_name}.pdf")
        fig.savefig(png_path, dpi=300, bbox_inches='tight')
        fig.savefig(pdf_path, bbox_inches='tight')
    print(f"✓ Saved: {base_name}.png & {base_name}.pdf")
    plt.close(fig)

def load_data():
    if not os.path.exists(RAW_CSV):
        print(f"Error: {RAW_CSV} not found.")
        sys.exit(1)
    df_raw = pd.read_csv(RAW_CSV)
    df_sum = pd.read_csv(SUMMARY_CSV) if os.path.exists(SUMMARY_CSV) else None
    return df_raw, df_sum

# Helper to query summary stats
def get_stat(df_sum, df_raw, mode, rate, col):
    if df_sum is not None:
        sub = df_sum[(df_sum['mode'] == mode) & (df_sum['target_qps'] == rate)]
        if not sub.empty and f"{col}_mean" in sub.columns:
            m = sub[f"{col}_mean"].values[0]
            ci = sub[f"{col}_ci95"].values[0] if f"{col}_ci95" in sub.columns else 0
            return m, ci
    sub_raw = df_raw[(df_raw['mode'] == mode) & (df_raw['target_qps'] == rate)]
    if not sub_raw.empty and col in sub_raw.columns:
        m = sub_raw[col].mean()
        std = sub_raw[col].std()
        ci = 1.96 * (std / np.sqrt(len(sub_raw))) if len(sub_raw) > 1 else 0
        return m, ci
    return 0.0, 0.0

def generate_plots():
    df_raw, df_sum = load_data()
    x = np.arange(len(RATE_ORDER))
    width = 0.20

    # ==============================================================================
    # 1. Throughput (Achieved QPS) - Grouped Bar Chart
    # ==============================================================================
    fig, ax = plt.subplots(figsize=(8.6, 5.6))
    for i, mode in enumerate(MODE_ORDER):
        means = []
        cis = []
        for r in RATE_ORDER:
            m, ci = get_stat(df_sum, df_raw, mode, r, 'achieved_qps')
            means.append(m / 1e6)
            cis.append(ci / 1e6)
        pos = x + (i - 1.5) * width
        bars = ax.bar(pos, means, width, yerr=cis, capsize=4,
                      label=MODE_LABELS[mode], color=MODE_COLORS[mode],
                      edgecolor='black', linewidth=0.9, alpha=0.92)
        for b in bars:
            h = b.get_height()
            if h > 0.15:
                ax.annotate(f"{h:.2f}M", xy=(b.get_x() + b.get_width()/2, h),
                            xytext=(0, 4), textcoords="offset points",
                            ha='center', va='bottom', fontsize=11, fontweight='bold')
            elif h > 0:
                ax.annotate(f"{h*1e6:.0f}", xy=(b.get_x() + b.get_width()/2, h),
                            xytext=(0, 4), textcoords="offset points",
                            ha='center', va='bottom', fontsize=9.5, color='#d95f02')

    ax.set_xticks(x)
    ax.set_xticklabels(RATE_LABELS, fontweight='bold')
    ax.set_ylabel('Achieved Throughput (Million QPS)', fontweight='bold', labelpad=10)
    ax.set_xlabel('Target Offered Load', fontweight='bold', labelpad=10)
    ax.set_title('Sustained DNS Throughput under Dynamic Eviction', fontweight='bold', pad=14)
    ax.set_ylim(0, 6.2)
    ax.legend(loc='upper left', frameon=True, framealpha=0.95)
    plt.tight_layout()
    save_fig(fig, "fig_dynamic_throughput")

    # ==============================================================================
    # 2. Packet Loss (%) - Grouped Bar Chart
    # ==============================================================================
    fig, ax = plt.subplots(figsize=(8.6, 5.6))
    for i, mode in enumerate(MODE_ORDER):
        means = []
        cis = []
        for r in RATE_ORDER:
            m, ci = get_stat(df_sum, df_raw, mode, r, 'packet_loss_pct')
            means.append(m)
            cis.append(ci)
        pos = x + (i - 1.5) * width
        bars = ax.bar(pos, means, width, yerr=cis, capsize=4,
                      label=MODE_LABELS[mode], color=MODE_COLORS[mode],
                      edgecolor='black', linewidth=0.9, alpha=0.92)
        for b in bars:
            h = b.get_height()
            ax.annotate(f"{h:.1f}%", xy=(b.get_x() + b.get_width()/2, h),
                        xytext=(0, 4), textcoords="offset points",
                        ha='center', va='bottom', fontsize=10.5, fontweight='bold')

    ax.set_xticks(x)
    ax.set_xticklabels(RATE_LABELS, fontweight='bold')
    ax.set_ylabel('Packet Loss Ratio (%)', fontweight='bold', labelpad=10)
    ax.set_xlabel('Target Offered Load', fontweight='bold', labelpad=10)
    ax.set_title('Packet Loss Ratio under Dynamic Eviction', fontweight='bold', pad=14)
    ax.set_ylim(0, 115)
    ax.legend(loc='upper left', frameon=True, framealpha=0.95)
    plt.tight_layout()
    save_fig(fig, "fig_dynamic_packet_loss")

    # ==============================================================================
    # 3. Tail Latency Profiles (p50, p90, p99)
    # ==============================================================================
    fig, axes = plt.subplots(1, 3, figsize=(16, 5.5), sharey=True)
    percentiles = [('lat_p50_ms', 'Median ($p_{50}$) Latency'),
                   ('lat_p90_ms', '$p_{90}$ Tail Latency'),
                   ('lat_p99_ms', '$p_{99}$ Operational Tail Latency')]
    eval_modes = ['ates_hw_cache', 'ates_driver', 'unbound_hw_cache']
    w_sub = 0.26
    x_sub = np.arange(len(RATE_ORDER))

    for ax_idx, (col, title) in enumerate(percentiles):
        ax = axes[ax_idx]
        for i, mode in enumerate(eval_modes):
            vals = [get_stat(df_sum, df_raw, mode, r, col)[0] for r in RATE_ORDER]
            pos = x_sub + (i - 1) * w_sub
            bars = ax.bar(pos, vals, w_sub, label=MODE_LABELS[mode],
                          color=MODE_COLORS[mode], edgecolor='black', linewidth=0.8, alpha=0.92)
            for b in bars:
                h = b.get_height()
                if h > 0.1:
                    ax.annotate(f"{h:.1f}", xy=(b.get_x() + b.get_width()/2, h),
                                xytext=(0, 3), textcoords="offset points",
                                ha='center', va='bottom', fontsize=10, fontweight='bold')
        ax.set_xticks(x_sub)
        ax.set_xticklabels(RATE_LABELS, fontweight='bold')
        ax.set_title(title, fontweight='bold', pad=12)
        ax.set_xlabel('Target Offered Load', fontweight='bold', labelpad=8)
        if ax_idx == 0:
            ax.set_ylabel('Latency (ms)', fontweight='bold', labelpad=10)
            ax.legend(loc='upper right', frameon=True, framealpha=0.95, fontsize=12)

    fig.suptitle('Tail Latency Distributions under Dynamic Eviction', fontweight='bold', y=1.02)
    plt.tight_layout()
    save_fig(fig, "fig_dynamic_tail_latency")

    # ==============================================================================
    # 4. System Resources: Server CPU Utilization & NIC Ring Buffer Discards
    # ==============================================================================
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 5.5))

    # (a) CPU Busy
    for i, mode in enumerate(MODE_ORDER):
        means = [get_stat(df_sum, df_raw, mode, r, 'srv_all_busy')[0] for r in RATE_ORDER]
        cis = [get_stat(df_sum, df_raw, mode, r, 'srv_all_busy')[1] for r in RATE_ORDER]
        pos = x + (i - 1.5) * width
        ax1.bar(pos, means, width, yerr=cis, capsize=3,
                label=MODE_LABELS[mode], color=MODE_COLORS[mode], edgecolor='black', linewidth=0.8, alpha=0.92)

    ax1.set_xticks(x)
    ax1.set_xticklabels(RATE_LABELS, fontweight='bold')
    ax1.set_ylabel('Total Server CPU Utilization (%)', fontweight='bold', labelpad=10)
    ax1.set_xlabel('Target Offered Load', fontweight='bold', labelpad=8)
    ax1.set_title('(a) Server CPU Utilization across Cores', fontweight='bold', pad=12)
    ax1.set_ylim(0, 80)
    ax1.legend(loc='upper left', frameon=True, framealpha=0.95, fontsize=12)

    # (b) Ring Buffer Discards
    for i, mode in enumerate(MODE_ORDER):
        discards = [get_stat(df_sum, df_raw, mode, r, 'nic_rx_discards')[0] / 1e6 for r in RATE_ORDER]
        pos = x + (i - 1.5) * width
        ax2.bar(pos, discards, width,
                label=MODE_LABELS[mode], color=MODE_COLORS[mode], edgecolor='black', linewidth=0.8, alpha=0.92)

    ax2.set_xticks(x)
    ax2.set_xticklabels(RATE_LABELS, fontweight='bold')
    ax2.set_ylabel('Hardware Ring Buffer Discards (Millions)', fontweight='bold', labelpad=10)
    ax2.set_xlabel('Target Offered Load', fontweight='bold', labelpad=8)
    ax2.set_title('(b) Hardware Ring Buffer Packet Drops', fontweight='bold', pad=12)
    ax2.legend(loc='upper left', frameon=True, framealpha=0.95, fontsize=12)

    plt.tight_layout()
    save_fig(fig, "fig_dynamic_system_resources")

    # ==============================================================================
    # 5. Multi-Tier Resolution Breakdown
    # ==============================================================================
    fig, ax = plt.subplots(figsize=(9.2, 5.8))
    breakdown_modes = ['ates_hw_cache', 'ates_driver', 'unbound_hw_cache']
    w_b = 0.25
    x_b = np.arange(len(RATE_ORDER))
    tier_colors = {
        'hw':        '#2ca02c',  # Green (SmartNIC Silicon)
        'driver':    '#1f77b4',  # Blue (Host Driver XDP)
        'userspace': '#ff7f0e',  # Orange (Host Userspace)
    }

    for i, mode in enumerate(breakdown_modes):
        hw_vals = [get_stat(df_sum, df_raw, mode, r, 'hw_cache_hits')[0] / 1e6 for r in RATE_ORDER]
        dr_vals = [get_stat(df_sum, df_raw, mode, r, 'driver_hits')[0] / 1e6 for r in RATE_ORDER]
        us_vals = [get_stat(df_sum, df_raw, mode, r, 'userspace_hits')[0] / 1e6 for r in RATE_ORDER]
        pos = x_b + (i - 1) * w_b

        ax.bar(pos, hw_vals, w_b, color=tier_colors['hw'], edgecolor='black', linewidth=0.7,
               label='SmartNIC HW Cache Hit' if i == 0 else "")
        ax.bar(pos, dr_vals, w_b, bottom=hw_vals, color=tier_colors['driver'], edgecolor='black', linewidth=0.7,
               label='Host Driver Mode Hit' if i == 0 else "")
        ax.bar(pos, us_vals, w_b, bottom=np.array(hw_vals) + np.array(dr_vals), color=tier_colors['userspace'],
               edgecolor='black', linewidth=0.7, label='Userspace / Upstream' if i == 0 else "")

        for idx, (h_val, d_val, u_val) in enumerate(zip(hw_vals, dr_vals, us_vals)):
            tot = h_val + d_val + u_val
            if tot > 0.5:
                short_mode = "AtesN HW" if "hw_cache" in mode and "ates" in mode else ("AtesN Drv" if "driver" in mode else "Unbound HW")
                ax.annotate(short_mode, xy=(pos[idx], 5), rotation=90, ha='center', va='bottom', fontsize=9.5, color='white', fontweight='bold')
                ax.annotate(f"{tot:.0f}M", xy=(pos[idx], tot), xytext=(0, 3), textcoords="offset points",
                            ha='center', va='bottom', fontsize=10, fontweight='bold')

    ax.set_xticks(x_b)
    ax.set_xticklabels(RATE_LABELS, fontweight='bold')
    ax.set_ylabel('Total Answered Queries per 120s Run (Millions)', fontweight='bold', labelpad=10)
    ax.set_xlabel('Target Offered Load', fontweight='bold', labelpad=8)
    ax.set_title('Multi-Tier Query Resolution Breakdown', fontweight='bold', pad=14)
    ax.legend(loc='upper left', frameon=True, framealpha=0.95, fontsize=12.5)
    plt.tight_layout()
    save_fig(fig, "fig_dynamic_tier_breakdown")

    print("\n🎉 Complete Dynamic TTL Figure Suite generated successfully with large typography!")

if __name__ == "__main__":
    generate_plots()
