#!/usr/bin/env python3
# ==============================================================================
# plot_ccdf_operational.py
#
# Generates publication-ready 2x2 grid CCDF (Complementary Cumulative Distribution
# Function, P(Latency > x)) plots for the operational modes from the calibrated
# 10-repetition benchmark under production ISP trace traffic.
# ==============================================================================

import os
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
    'figure.titlesize': 15,
    'font.family': 'sans-serif'
})

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
RESULTS_DIR = os.path.join(PROJECT_ROOT, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

RAW_CSV = os.path.join(BASE_DIR, "raw_2core_realtrace_10reps.csv")
OUT_PNG = os.path.join(BASE_DIR, "realtrace_2core_ccdf_operational.png")
OUT_PDF = os.path.join(BASE_DIR, "realtrace_2core_ccdf_operational.pdf")
RES_PNG = os.path.join(RESULTS_DIR, "realtrace_2core_ccdf_operational.png")
RES_PDF = os.path.join(RESULTS_DIR, "realtrace_2core_ccdf_operational.pdf")

df = pd.read_csv(RAW_CSV)

# Modes and styles
MODE_COLORS = {
    'unbound_standalone': '#d95f02',   # Orange
    'unbound_hw_cache':   '#1b9e77',   # Green
    'ates_driver':        '#7570b3',   # Purple
    'ates_hw_cache':      '#e7298a',   # Magenta
}

MODE_LABELS = {
    'unbound_standalone': 'Unbound (Userspace)',
    'unbound_hw_cache':   'Unbound + SmartNIC HW Cache',
    'ates_driver':        'AtesN-DS (XDP Driver)',
    'ates_hw_cache':      'AtesN-DS + SmartNIC HW Cache',
}

MODE_MARKERS = {
    'unbound_standalone': 'o',
    'unbound_hw_cache':   '^',
    'ates_driver':        's',
    'ates_hw_cache':      'D',
}

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

# 4 Key Scenarios in 2x2 grid
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
        
        lat_coords = []
        ccdf_coords = []
        for col, ccdf_val in P_MAP:
            mean_lat = sub[col].mean()
            lat_coords.append(mean_lat)
            ccdf_coords.append(ccdf_val)
            
        ax.plot(lat_coords, ccdf_coords,
                label=MODE_LABELS[mode],
                color=MODE_COLORS[mode],
                marker=MODE_MARKERS[mode],
                linewidth=2.4,
                markersize=6.5,
                alpha=0.9)

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
plt.savefig(OUT_PNG, dpi=300, bbox_inches='tight')
plt.savefig(OUT_PDF, bbox_inches='tight')
plt.savefig(RES_PNG, dpi=300, bbox_inches='tight')
plt.savefig(RES_PDF, bbox_inches='tight')
print(f"✅ Publication-quality CCDF figures successfully generated:")
print(f"   - {OUT_PNG}")
print(f"   - {OUT_PDF}")
print(f"   - {RES_PNG}")
print(f"   - {RES_PDF}")
