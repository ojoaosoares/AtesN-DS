#!/usr/bin/env python3
# ==============================================================================
# plot_closed_loop_dnspyre.py
#
# Generates publication-ready figures for the Closed-Loop Benchmark (dnspyre):
#   1. Throughput (kQPS) vs Concurrency Window (W)
#   2. Latency (p50 and p99) vs Concurrency Window (W)
#   3. Packet Loss (%) vs Concurrency Window (W)
#   4. CCDF of Latency (P(Latency > x)) across operational modes
# ==============================================================================

import os
import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams.update({
    'font.size': 13,
    'axes.labelsize': 15,
    'axes.titlesize': 16,
    'xtick.labelsize': 13,
    'ytick.labelsize': 13,
    'legend.fontsize': 12,
    'figure.titlesize': 17,
    'font.family': 'sans-serif'
})

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SUMMARY_CSV = os.path.join(BASE_DIR, "summary_closed_loop_dnspyre_10reps.csv")
RAW_CSV = os.path.join(BASE_DIR, "raw_closed_loop_dnspyre_10reps.csv")
OUT_DEST = "/home/joaosoares/Documents/Github/AtesN-DS/results/official_closed_loop_dnspyre"
os.makedirs(OUT_DEST, exist_ok=True)

if not os.path.exists(SUMMARY_CSV) and not os.path.exists(RAW_CSV):
    print("No data found yet to plot.")
    sys.exit(0)

# Colors and styles
MODE_COLORS = {
    'unbound_standalone': '#d95f02',   # Orange
    'unbound_hw_cache':   '#1b9e77',   # Green
    'ates_driver':        '#7570b3',   # Purple
    'ates_hw_cache':      '#e7298a',   # Magenta
}

MODE_LABELS = {
    'unbound_standalone': 'Unbound Standalone',
    'unbound_hw_cache':   'Unbound + HW Cache',
    'ates_driver':        'AtesN-DS Driver (XDP_DRV)',
    'ates_hw_cache':      'AtesN-DS HW Cache (Hybrid)',
}

MODE_MARKERS = {
    'unbound_standalone': 's',
    'unbound_hw_cache':   '^',
    'ates_driver':        'D',
    'ates_hw_cache':      'o',
}

MODE_ORDER = ['unbound_standalone', 'ates_driver', 'unbound_hw_cache', 'ates_hw_cache']

def save_fig(fig, basename):
    for d in [BASE_DIR, OUT_DEST]:
        png_p = os.path.join(d, f"{basename}.png")
        pdf_p = os.path.join(d, f"{basename}.pdf")
        fig.savefig(png_p, dpi=300, bbox_inches='tight')
        fig.savefig(pdf_p, bbox_inches='tight')
        print(f"Saved: {png_p} and .pdf")

if os.path.exists(SUMMARY_CSV):
    try:
        df_sum = pd.read_csv(SUMMARY_CSV)
        if not df_sum.empty:
            windows = sorted(df_sum['window'].unique())
            x_indices = np.arange(len(windows))
            
            # --------------------------------------------------------------------------
            # Fig 1: Throughput vs Window W
            # --------------------------------------------------------------------------
            fig, ax = plt.subplots(figsize=(12, 6))
            width = 0.20
            
            for idx, mode in enumerate(MODE_ORDER):
                mdf = df_sum[df_sum['mode'] == mode]
                if mdf.empty: continue
                
                qps_means = []
                qps_stds = []
                for w in windows:
                    row = mdf[mdf['window'] == w]
                    if not row.empty:
                        qps_means.append(row['achieved_qps_mean'].values[0] / 1000.0)
                        qps_stds.append(row['achieved_qps_std'].values[0] / 1000.0)
                    else:
                        qps_means.append(0.0)
                        qps_stds.append(0.0)
                        
                pos = x_indices + (idx - 1.5) * width
                ax.bar(pos, qps_means, width, yerr=qps_stds, capsize=3,
                       label=MODE_LABELS[mode], color=MODE_COLORS[mode], edgecolor='black', linewidth=0.7)
                       
            ax.set_ylabel("Achieved Throughput (kQPS)")
            ax.set_xlabel("Concurrency Window Size $W$ (In-Flight Queries)")
            ax.set_title("Closed-Loop Throughput Scaling Across Concurrency Windows ($n=10$ reps, dnspyre)")
            ax.set_xticks(x_indices)
            ax.set_xticklabels([f"{w}" for w in windows], rotation=30)
            ax.grid(axis='y', linestyle='--', alpha=0.5)
            ax.legend(loc='upper left', framealpha=0.9)
            plt.tight_layout()
            save_fig(fig, "closed_loop_dnspyre_throughput_bars")
            plt.close()

            # --------------------------------------------------------------------------
            # Fig 1b: Packet Loss vs Window W
            # --------------------------------------------------------------------------
            fig, ax = plt.subplots(figsize=(9, 5))
            for mode in MODE_ORDER:
                mdf = df_sum[df_sum['mode'] == mode]
                if mdf.empty: continue
                w_sorted = mdf.sort_values('window')
                ax.plot(w_sorted['window'], w_sorted['loss_pct_mean'], marker=MODE_MARKERS[mode],
                        label=MODE_LABELS[mode], color=MODE_COLORS[mode], linewidth=2.2, markersize=7)
            ax.set_xlabel("Concurrency Window $W$")
            ax.set_ylabel("Packet Loss Rate (%)")
            ax.set_title("Closed-Loop Packet Loss Across Concurrency Windows ($n=10$, dnspyre)")
            ax.set_xscale('log', base=2)
            ax.set_ylim(-1, 50)
            ax.grid(True, which='both', linestyle='--', alpha=0.5)
            ax.legend(loc='upper left', framealpha=0.9)
            plt.tight_layout()
            save_fig(fig, "closed_loop_dnspyre_packet_loss")
            plt.close()

            # --------------------------------------------------------------------------
            # Fig 2: Latency (p50 and p99) vs Window W
            # --------------------------------------------------------------------------
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
            
            for mode in MODE_ORDER:
                mdf = df_sum[df_sum['mode'] == mode]
                if mdf.empty: continue
                
                w_sorted = mdf.sort_values('window')
                ax1.plot(w_sorted['window'], w_sorted['lat_p50_ms'], marker=MODE_MARKERS[mode],
                         label=MODE_LABELS[mode], color=MODE_COLORS[mode], linewidth=2.2, markersize=7)
                ax2.plot(w_sorted['window'], w_sorted['lat_p99_ms'], marker=MODE_MARKERS[mode],
                         label=MODE_LABELS[mode], color=MODE_COLORS[mode], linewidth=2.2, markersize=7)
                         
            ax1.set_xlabel("Concurrency Window $W$")
            ax1.set_ylabel("Median Latency $p_{50}$ (ms)")
            ax1.set_title("(a) Median Response Latency ($p_{50}$)")
            ax1.set_xscale('log', base=2)
            ax1.grid(True, which='both', linestyle='--', alpha=0.5)
            ax1.legend(loc='upper left')

            ax2.set_xlabel("Concurrency Window $W$")
            ax2.set_ylabel("Tail Latency $p_{99}$ (ms)")
            ax2.set_title("(b) 99th Percentile Tail Latency ($p_{99}$)")
            ax2.set_xscale('log', base=2)
            ax2.grid(True, which='both', linestyle='--', alpha=0.5)
            ax2.legend(loc='upper left')
            
            plt.tight_layout()
            save_fig(fig, "closed_loop_dnspyre_latency_scaling")
            plt.close()
    except Exception as e:
        print(f"Warning in summary plotting: {e}")

# --------------------------------------------------------------------------
# Fig 3: CCDF Plots for Specific Windows (W=64, W=1024, W=8192, W=65536)
# --------------------------------------------------------------------------
if os.path.exists(RAW_CSV):
    try:
        df_raw = pd.read_csv(RAW_CSV)
        target_windows = [16, 64, 256, 512, 1024]
        available_windows = [w for w in target_windows if w in df_raw['window'].values]
        
        if available_windows:
            fig, axes = plt.subplots(1, len(available_windows), figsize=(5.0 * len(available_windows), 5), sharey=True)
            if len(available_windows) == 1:
                axes = [axes]
                
            PERCENTILES = [
                ('lat_min_ms', 1.000),
                ('lat_p50_ms', 0.500),
                ('lat_p75_ms', 0.250),
                ('lat_p90_ms', 0.100),
                ('lat_p95_ms', 0.050),
                ('lat_p99_ms', 0.010),
                ('lat_p99_9_ms', 0.001)
            ]
            
            for ax_idx, win in enumerate(available_windows):
                ax = axes[ax_idx]
                wdf = df_raw[df_raw['window'] == win]
                
                for mode in MODE_ORDER:
                    sub = wdf[wdf['mode'] == mode]
                    if sub.empty: continue
                    
                    lat_coords = []
                    ccdf_coords = []
                    for col, ccdf_val in PERCENTILES:
                        lat_coords.append(sub[col].mean())
                        ccdf_coords.append(ccdf_val)
                        
                    ax.plot(lat_coords, ccdf_coords,
                            label=MODE_LABELS[mode],
                            color=MODE_COLORS[mode],
                            marker=MODE_MARKERS[mode],
                            linewidth=2.4,
                            markersize=7,
                            alpha=0.9)
                            
                ax.set_yscale('log')
                ax.set_ylim(0.0008, 1.2)
                ax.set_title(f"Window $W={win}$", fontweight='bold')
                ax.set_xlabel("Response Latency (ms)")
                ax.grid(True, which='both', linestyle='--', alpha=0.5)
                
                if ax_idx == 0:
                    ax.set_ylabel(r"CCDF: $P(\mathrm{Latency} > x)$")
                    ax.set_yticks([1.0, 0.5, 0.1, 0.01, 0.001])
                    ax.set_yticklabels(['1.0 (min)', '0.50 ($p_{50}$)', '0.10 ($p_{90}$)', '0.01 ($p_{99}$)', '0.001 ($p_{99.9}$)'])

                ax.legend(loc='upper right', framealpha=0.9, fontsize=10.5)

            plt.suptitle(r"Closed-Loop CCDF of Query Latency Across Operational Modes ($n=10$, dnspyre)", fontsize=15, y=1.02)
            plt.tight_layout()
            save_fig(fig, "closed_loop_dnspyre_ccdf_operational")
            plt.close()
    except Exception as e:
        print(f"Warning in CCDF plotting: {e}")
