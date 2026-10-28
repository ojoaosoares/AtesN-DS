#!/usr/bin/env python3
"""
Plots the empirical results of the User-Space Fallback study.
Generates publication-quality figures demonstrating the architectural penalty
of cascading queries to user space (XDP_PASS) under high load.
"""

import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams.update({
    'font.size': 14,
    'axes.labelsize': 16,
    'axes.titlesize': 17,
    'xtick.labelsize': 15,
    'ytick.labelsize': 15,
    'legend.fontsize': 13.5,
    'figure.titlesize': 18,
    'font.family': 'sans-serif'
})

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SUM_CSV = os.path.join(BASE_DIR, "summary_fallback_penalty.csv")
OUT_PNG = os.path.join(BASE_DIR, "figure_fallback_penalty.png")
OUT_PDF = os.path.join(BASE_DIR, "figure_fallback_penalty.pdf")

if not os.path.exists(SUM_CSV):
    print(f"Error: {SUM_CSV} not found. Run run_fallback_study.sh first.")
    exit(1)

df = pd.read_csv(SUM_CSV)

# Create 3-panel horizontal figure
fig, axes = plt.subplots(1, 3, figsize=(18, 5.2))

colors = {250000: "#1f77b4", 400000: "#ff7f0e", 500000: "#d62728"}
markers = {250000: "o", 400000: "s", 500000: "^"}

# Panel 1: Throughput and Loss
ax1 = axes[0]
for qps in sorted(df['target_qps'].unique()):
    sub = df[df['target_qps'] == qps].sort_values('fallback_ratio_pct')
    ax1.plot(sub['fallback_ratio_pct'], sub['achieved_qps_mean'] / 1000.0,
             label=f'Achieved QPS ({qps//1000}k Target)', color=colors[qps], marker=markers[qps], lw=2.5, ms=7)

ax1.set_xlabel("Fallback to User Space (%) [XDP_PASS]")
ax1.set_ylabel("Achieved Throughput (kQPS)")
ax1.set_title("(a) Throughput Degradation Under Fallback")
ax1.legend(loc="upper right")
ax1.set_ylim(bottom=0)

# Panel 2: Latency p99
ax2 = axes[1]
for qps in sorted(df['target_qps'].unique()):
    sub = df[df['target_qps'] == qps].sort_values('fallback_ratio_pct')
    ax2.plot(sub['fallback_ratio_pct'], sub['lat_p99_ms_mean'],
             label=f'Target {qps//1000}k QPS', color=colors[qps], marker=markers[qps], lw=2.5, ms=7)

ax2.set_xlabel("Fallback to User Space (%) [XDP_PASS]")
ax2.set_ylabel("Tail Latency $p_{99}$ (ms)")
ax2.set_title("(b) Tail Latency Inflation ($p_{99}$)")
ax2.legend(loc="upper left")

# Panel 3: Server CPU SoftIRQ & Socket Drops
ax3 = axes[2]
ax3_twin = ax3.twinx()

for qps in sorted(df['target_qps'].unique()):
    sub = df[df['target_qps'] == qps].sort_values('fallback_ratio_pct')
    ax3.plot(sub['fallback_ratio_pct'], sub['srv_core0_softirq_pct_mean'],
             label=f'SoftIRQ% ({qps//1000}k)', color=colors[qps], marker=markers[qps], lw=2, linestyle='-')
    ax3_twin.plot(sub['fallback_ratio_pct'], sub['udp_rcvbuf_errors_delta_mean'],
                  label=f'Rcvbuf Errors ({qps//1000}k)', color=colors[qps], marker=markers[qps], lw=1.8, linestyle='--')

ax3.set_xlabel("Fallback to User Space (%) [XDP_PASS]")
ax3.set_ylabel("Core 0 SoftIRQ CPU (%)", color="#333333")
ax3_twin.set_ylabel("Socket Rcvbuf Errors (Drops)", color="#666666")
ax3.set_title("(c) Host CPU Saturation & Socket Queue Overflow")
ax3.set_ylim(0, 105)

plt.tight_layout()
plt.savefig(OUT_PNG, dpi=300)
plt.savefig(OUT_PDF)
print(f"✅ Figures saved successfully to:\n  - {OUT_PNG}\n  - {OUT_PDF}")
