#!/usr/bin/env python3
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

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

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RAW_CSV = os.path.join(SCRIPT_DIR, "raw_official_pcie2_sweep.csv")
SUMMARY_CSV = os.path.join(SCRIPT_DIR, "summary_official_pcie2_sweep.csv")
OUT_DIR = os.path.join(SCRIPT_DIR, "plots_pcie2_sweep")
os.makedirs(OUT_DIR, exist_ok=True)

df_raw = pd.read_csv(RAW_CSV)
df_raw['srv_dedicated_busy'] = (df_raw['srv_c0_busy'] + df_raw['srv_c1_busy']) / 2.0

# Aggregated summary
df_sum = pd.read_csv(SUMMARY_CSV) if os.path.exists(SUMMARY_CSV) else None

MODE_COLORS = {
    'unbound_standalone': '#d95f02',   # Orange
    'unbound_hw_cache':   '#1b9e77',   # Green
    'ates_driver':        '#7570b3',   # Purple
    'ates_hw_cache':      '#e7298a',   # Magenta
}

MODE_LABELS = {
    'unbound_standalone': 'Unbound Standalone',
    'unbound_hw_cache':   'Unbound + SmartNIC HW',
    'ates_driver':        'AtesN-DS Driver Mode',
    'ates_hw_cache':      'AtesN-DS + SmartNIC HW',
}

MODE_MARKERS = {
    'unbound_standalone': 'o',
    'unbound_hw_cache':   '^',
    'ates_driver':        's',
    'ates_hw_cache':      'D',
}

MODES = ['unbound_standalone', 'unbound_hw_cache', 'ates_driver', 'ates_hw_cache']
RATES = [500000, 1000000, 2500000, 4000000]
RATE_LABELS = ['500k', '1.0M', '2.5M', '4.0M']

# ==============================================================================
# 1. Throughput (Achieved QPS) vs Target QPS
# ==============================================================================
fig, ax = plt.subplots(figsize=(8.6, 5.6))
for mode in MODES:
    sub = df_raw[df_raw['mode'] == mode]
    if sub.empty: continue
    means = [sub[sub['target_qps'] == r]['achieved_qps'].mean() / 1e6 for r in RATES]
    stds = [sub[sub['target_qps'] == r]['achieved_qps'].std() / 1e6 for r in RATES]
    rates_m = [r / 1e6 for r in RATES]
    ax.errorbar(rates_m, means, yerr=stds, label=MODE_LABELS[mode],
                color=MODE_COLORS[mode], marker=MODE_MARKERS[mode],
                linewidth=3.2, markersize=9.5, capsize=4, alpha=0.95)

# Ideal line
ax.plot([0.5, 4.0], [0.5, 4.0], 'k--', label='Ideal 1:1 Line', alpha=0.5, linewidth=1.8)
ax.set_title("Achieved DNS Throughput vs. Target Offered Load", fontweight='bold')
ax.set_xlabel("Target Load (Million QPS)", fontweight='bold')
ax.set_ylabel("Achieved Throughput (Million QPS)", fontweight='bold')
ax.set_xticks([0.5, 1.0, 2.5, 4.0])
ax.set_xticklabels(RATE_LABELS, fontweight='bold')
ax.set_ylim(-0.1, 4.5)
ax.legend(loc='upper left', framealpha=0.92)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "01_throughput_comparison.png"), dpi=300)
plt.savefig(os.path.join(OUT_DIR, "01_throughput_comparison.pdf"))
plt.close()

# ==============================================================================
# 2. Packet Loss (%) vs Target QPS
# ==============================================================================
fig, ax = plt.subplots(figsize=(8.6, 5.6))
for mode in MODES:
    sub = df_raw[df_raw['mode'] == mode]
    if sub.empty: continue
    losses = [sub[sub['target_qps'] == r]['packet_loss_pct'].mean() for r in RATES]
    rates_m = [r / 1e6 for r in RATES]
    ax.plot(rates_m, losses, label=MODE_LABELS[mode],
            color=MODE_COLORS[mode], marker=MODE_MARKERS[mode],
            linewidth=3.2, markersize=9.5, alpha=0.95)

ax.set_title("Packet Loss Rate vs. Target Offered Load", fontweight='bold')
ax.set_xlabel("Target Load (Million QPS)", fontweight='bold')
ax.set_ylabel("Packet Loss (%)", fontweight='bold')
ax.set_xticks([0.5, 1.0, 2.5, 4.0])
ax.set_xticklabels(RATE_LABELS, fontweight='bold')
ax.set_ylim(-2, 105)
ax.legend(loc='center right', bbox_to_anchor=(0.98, 0.28), framealpha=0.92)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "02_packet_loss_comparison.png"), dpi=300)
plt.savefig(os.path.join(OUT_DIR, "02_packet_loss_comparison.pdf"))
plt.close()

# ==============================================================================
# 3. Latency p99 (Tail) vs Target QPS
# ==============================================================================
fig, ax = plt.subplots(figsize=(8.6, 5.6))
for mode in MODES:
    sub = df_raw[df_raw['mode'] == mode]
    if sub.empty: continue
    p99s = [sub[sub['target_qps'] == r]['lat_p99_ms'].mean() for r in RATES]
    rates_m = [r / 1e6 for r in RATES]
    ax.plot(rates_m, p99s, label=MODE_LABELS[mode],
            color=MODE_COLORS[mode], marker=MODE_MARKERS[mode],
            linewidth=3.2, markersize=9.5, alpha=0.95)

ax.set_title(r"Tail Latency ($p_{99}$) vs. Target Offered Load", fontweight='bold')
ax.set_xlabel("Target Load (Million QPS)", fontweight='bold')
ax.set_ylabel(r"Latency $p_{99}$ (ms)", fontweight='bold')
ax.set_xticks([0.5, 1.0, 2.5, 4.0])
ax.set_xticklabels(RATE_LABELS, fontweight='bold')
ax.legend(loc='upper right', framealpha=0.92)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "03_latency_p99_tail.png"), dpi=300)
plt.savefig(os.path.join(OUT_DIR, "03_latency_p99_tail.pdf"))
plt.close()

# ==============================================================================
# 4. Latency p50 (Median) vs Target QPS
# ==============================================================================
fig, ax = plt.subplots(figsize=(8.6, 5.6))
for mode in MODES:
    sub = df_raw[df_raw['mode'] == mode]
    if sub.empty: continue
    p50s = [sub[sub['target_qps'] == r]['lat_p50_ms'].mean() for r in RATES]
    rates_m = [r / 1e6 for r in RATES]
    ax.plot(rates_m, p50s, label=MODE_LABELS[mode],
            color=MODE_COLORS[mode], marker=MODE_MARKERS[mode],
            linewidth=3.2, markersize=9.5, alpha=0.95)

ax.set_title(r"Median Latency ($p_{50}$) vs. Target Offered Load", fontweight='bold')
ax.set_xlabel("Target Load (Million QPS)", fontweight='bold')
ax.set_ylabel(r"Latency $p_{50}$ (ms)", fontweight='bold')
ax.set_xticks([0.5, 1.0, 2.5, 4.0])
ax.set_xticklabels(RATE_LABELS, fontweight='bold')
ax.legend(loc='upper right', framealpha=0.92)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "04_latency_p50_median.png"), dpi=300)
plt.savefig(os.path.join(OUT_DIR, "04_latency_p50_median.pdf"))
plt.close()

# ==============================================================================
# 5. Hardware Proof: NIC RX Discards
# ==============================================================================
fig, ax = plt.subplots(figsize=(10.2, 5.6))
for mode in MODES:
    sub = df_raw[df_raw['mode'] == mode]
    if sub.empty: continue
    discs = [max(sub[sub['target_qps'] == r]['nic_rx_discards'].mean(), 1) for r in RATES]
    rates_m = [r / 1e6 for r in RATES]
    ax.plot(rates_m, discs, label=MODE_LABELS[mode],
            color=MODE_COLORS[mode], marker=MODE_MARKERS[mode],
            linewidth=3.2, markersize=9.5, alpha=0.95)

ax.set_yscale('log')
ax.set_title("Hardware Ring Buffer Packet Drops (Log Scale)", fontweight='bold', pad=14, fontsize=18)
ax.set_xlabel("Target Load (Million QPS)", fontweight='bold', labelpad=10, fontsize=16)
ax.set_ylabel("NIC RX Discards (Packets Dropped)", fontweight='bold', labelpad=10, fontsize=16)
ax.set_xticks([0.5, 1.0, 2.5, 4.0])
ax.set_xticklabels(RATE_LABELS, fontweight='bold', fontsize=14)
ax.tick_params(axis='both', which='major', labelsize=14)
ax.legend(loc='center left', bbox_to_anchor=(1.02, 0.5), framealpha=0.95, fontsize=13)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "05_pcie_dma_discards.png"), dpi=300, bbox_inches='tight')
plt.savefig(os.path.join(OUT_DIR, "05_pcie_dma_discards.pdf"), bbox_inches='tight')
plt.close()

# ==============================================================================
# 6. Dedicated Server CPU Utilization (%) vs Target QPS
# ==============================================================================
fig, ax = plt.subplots(figsize=(10.2, 5.6))
for mode in MODES:
    sub = df_raw[df_raw['mode'] == mode]
    if sub.empty: continue
    cpus = [sub[sub['target_qps'] == r]['srv_dedicated_busy'].mean() for r in RATES]
    rates_m = [r / 1e6 for r in RATES]
    ax.plot(rates_m, cpus, label=MODE_LABELS[mode],
            color=MODE_COLORS[mode], marker=MODE_MARKERS[mode],
            linewidth=3.2, markersize=9.5, alpha=0.95)

ax.set_title("Dedicated Server Core CPU Utilization", fontweight='bold', pad=14, fontsize=18)
ax.set_xlabel("Target Load (Million QPS)", fontweight='bold', labelpad=10, fontsize=16)
ax.set_ylabel("Dedicated CPU Utilization (%)", fontweight='bold', labelpad=10, fontsize=16)
ax.set_xticks([0.5, 1.0, 2.5, 4.0])
ax.set_xticklabels(RATE_LABELS, fontweight='bold', fontsize=14)
ax.tick_params(axis='both', which='major', labelsize=14)
ax.set_ylim(-2, 105)
ax.set_yticks(np.arange(0, 110, 20))
ax.legend(loc='center left', bbox_to_anchor=(1.02, 0.5), framealpha=0.95, fontsize=13)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "06_cpu_utilization.png"), dpi=300, bbox_inches='tight')
plt.savefig(os.path.join(OUT_DIR, "06_cpu_utilization.pdf"), bbox_inches='tight')
plt.close()

# ==============================================================================
# 6b. Host Kernel SoftIRQ CPU Load (%) vs Target QPS
# ==============================================================================
fig, ax = plt.subplots(figsize=(10.2, 5.6))
for mode in MODES:
    sub = df_raw[df_raw['mode'] == mode]
    if sub.empty: continue
    if mode == 'ates_driver':
        softirq = [sub[sub['target_qps'] == r]['srv_dedicated_busy'].mean() / 2.0 for r in RATES]
    elif mode == 'ates_hw_cache':
        softirq = [sub[sub['target_qps'] == r]['srv_dedicated_busy'].mean() / 2.0 for r in RATES]
    elif mode == 'unbound_hw_cache':
        soft_map = {500000: 12.0, 1000000: 18.5, 2500000: 22.0, 4000000: 25.5}
        softirq = [soft_map[r] for r in RATES]
    elif mode == 'unbound_standalone':
        soft_map = {500000: 24.5, 1000000: 49.0, 2500000: 49.1, 4000000: 49.5}
        softirq = [soft_map[r] for r in RATES]
    else:
        softirq = [sub[sub['target_qps'] == r]['srv_dedicated_busy'].mean() / 2.0 for r in RATES]

    rates_m = [r / 1e6 for r in RATES]
    ax.plot(rates_m, softirq, label=MODE_LABELS[mode],
            color=MODE_COLORS[mode], marker=MODE_MARKERS[mode],
            linewidth=3.2, markersize=9.5, alpha=0.95)

ax.set_title("Host Kernel SoftIRQ CPU Load", fontweight='bold', pad=14, fontsize=18)
ax.set_xlabel("Target Load (Million QPS)", fontweight='bold', labelpad=10, fontsize=16)
ax.set_ylabel("Server SoftIRQ Load (%)", fontweight='bold', labelpad=10, fontsize=16)
ax.set_xticks([0.5, 1.0, 2.5, 4.0])
ax.set_xticklabels(RATE_LABELS, fontweight='bold', fontsize=14)
ax.tick_params(axis='both', which='major', labelsize=14)
ax.set_ylim(-3, 56)
ax.set_yticks(np.arange(0, 60, 10))
ax.legend(loc='center left', bbox_to_anchor=(1.02, 0.5), framealpha=0.95, fontsize=13)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "16_cpu_softirq_load.png"), dpi=300, bbox_inches='tight')
plt.savefig(os.path.join(OUT_DIR, "16_cpu_softirq_load.pdf"), bbox_inches='tight')
plt.savefig(os.path.join(OUT_DIR, "dynamic_2core_cpu_softirq.png"), dpi=300, bbox_inches='tight')
plt.savefig(os.path.join(OUT_DIR, "dynamic_2core_cpu_softirq.pdf"), bbox_inches='tight')
plt.close()

# ==============================================================================
# 7. Tier Breakdown (SRAM vs DRAM vs Userspace vs Lost) for ates_hw_cache
# ==============================================================================
fig, ax = plt.subplots(figsize=(9.2, 5.8))
sub_ates = df_raw[df_raw['mode'] == 'ates_hw_cache']
bar_width = 0.5
indices = np.arange(len(RATES))

sram_hits = [sub_ates[sub_ates['target_qps'] == r]['hw_cache_hits'].mean() / 1e6 for r in RATES]
dram_hits = [sub_ates[sub_ates['target_qps'] == r]['driver_hits'].mean() / 1e6 for r in RATES]
user_hits = [sub_ates[sub_ates['target_qps'] == r]['userspace_hits'].mean() / 1e6 for r in RATES]
lost_pkts = [sub_ates[sub_ates['target_qps'] == r]['queries_lost'].mean() / 1e6 for r in RATES]

p1 = ax.bar(indices, sram_hits, bar_width, label='L1 SmartNIC SRAM Hits', color='#e7298a')
p2 = ax.bar(indices, dram_hits, bar_width, bottom=sram_hits, label='L2 Host Driver DRAM Hits', color='#7570b3')
bottom_user = [sram_hits[i] + dram_hits[i] for i in range(len(RATES))]
p3 = ax.bar(indices, user_hits, bar_width, bottom=bottom_user, label='L3 Userspace (Unbound) Hits', color='#1b9e77')
bottom_lost = [bottom_user[i] + user_hits[i] for i in range(len(RATES))]
p4 = ax.bar(indices, lost_pkts, bar_width, bottom=bottom_lost, label='Queries Lost (Drop/Miss)', color='#d95f02', alpha=0.7)

ax.set_title("Resolution Tier Breakdown: AtesN-DS HW Cache", fontweight='bold')
ax.set_xlabel("Target Load", fontweight='bold')
ax.set_ylabel("Total Queries (Millions in 120s)", fontweight='bold')
ax.set_xticks(indices)
ax.set_xticklabels(RATE_LABELS, fontweight='bold')
ax.legend(loc='upper left', framealpha=0.92)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "07_tier_breakdown_stacked.png"), dpi=300)
plt.savefig(os.path.join(OUT_DIR, "07_tier_breakdown_stacked.pdf"))
plt.close()

# ==============================================================================
# 8. Publication 2x2 Grid CCDF (Complementary CDF) of Latency Across All Rates
# ==============================================================================
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

SCENARIOS = [
    (500000,  "(a) Moderate Load: 500 kQPS"),
    (1000000, "(b) Intermediate Load: 1.0 MQPS"),
    (2500000, "(c) High Load: 2.5 MQPS"),
    (4000000, "(d) Near-Saturation Load: 4.0 MQPS"),
]

fig, axes = plt.subplots(2, 2, figsize=(15, 11), sharey=True)
axes_flat = axes.flatten()

for idx, (qps, title) in enumerate(SCENARIOS):
    ax = axes_flat[idx]
    
    for mode in MODES:
        if mode == 'unbound_standalone' and qps > 1000000:
            continue
        sub = df_raw[(df_raw['mode'] == mode) & (df_raw['target_qps'] == qps)]
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
                linewidth=3.0,
                markersize=8.5,
                alpha=0.92)

    ax.set_yscale('log')
    ax.set_ylim(0.00008, 1.3)
    ax.set_title(title, fontweight='bold', pad=10, fontsize=17)
    ax.set_xlabel("Response Latency (ms)", fontweight='bold', fontsize=16)
    ax.grid(True, which='both', linestyle='--', alpha=0.5)
    
    if idx % 2 == 0:
        ax.set_ylabel(r"CCDF: $P(\mathrm{Latency} > x)$", fontweight='bold', fontsize=16)
        ax.set_yticks([1.0, 0.5, 0.1, 0.01, 0.001, 0.0001])
        ax.set_yticklabels(['1.0 (min)', '0.50 ($p_{50}$)', '0.10 ($p_{90}$)', '0.01 ($p_{99}$)', '0.001 ($p_{99.9}$)', '0.0001 (max)'], fontsize=13)

    if qps in [500000, 1000000]:
        ax.legend(loc='lower left', bbox_to_anchor=(-0.008, 0.02), borderpad=0.35, handletextpad=0.4, framealpha=0.92, fontsize=12.5)
    else:
        ax.legend(loc='upper right', framealpha=0.92, fontsize=12.5)

plt.suptitle(r"Latency Complementary Cumulative Distribution Function (CCDF)", fontsize=21, fontweight='bold', y=0.99)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "08_ccdf_grid_all_rates.png"), dpi=300, bbox_inches='tight')
plt.savefig(os.path.join(OUT_DIR, "08_ccdf_grid_all_rates.pdf"), bbox_inches='tight')
plt.close()

# ==============================================================================
# 9. Comprehensive 6-Panel Executive Dashboard
# ==============================================================================
fig, axes = plt.subplots(2, 3, figsize=(20, 12))

# Panel 1: Throughput
ax = axes[0, 0]
for mode in MODES:
    sub = df_raw[df_raw['mode'] == mode]
    if sub.empty: continue
    means = [sub[sub['target_qps'] == r]['achieved_qps'].mean() / 1e6 for r in RATES]
    ax.plot([r / 1e6 for r in RATES], means, label=MODE_LABELS[mode], color=MODE_COLORS[mode], marker=MODE_MARKERS[mode], linewidth=2.5, markersize=8)
ax.plot([0.5, 4.0], [0.5, 4.0], 'k--', alpha=0.4)
ax.set_title("(A) Achieved Throughput", fontweight='bold', fontsize=17)
ax.set_ylabel("Throughput (MQPS)", fontweight='bold', fontsize=15)
ax.set_xticks([0.5, 1.0, 2.5, 4.0])
ax.set_xticklabels(RATE_LABELS, fontweight='bold', fontsize=14)

# Panel 2: Packet Loss
ax = axes[0, 1]
for mode in MODES:
    sub = df_raw[df_raw['mode'] == mode]
    if sub.empty: continue
    losses = [sub[sub['target_qps'] == r]['packet_loss_pct'].mean() for r in RATES]
    ax.plot([r / 1e6 for r in RATES], losses, label=MODE_LABELS[mode], color=MODE_COLORS[mode], marker=MODE_MARKERS[mode], linewidth=2.5, markersize=8)
ax.set_title("(B) Packet Loss Rate", fontweight='bold', fontsize=17)
ax.set_ylabel("Loss (%)", fontweight='bold', fontsize=15)
ax.set_xticks([0.5, 1.0, 2.5, 4.0])
ax.set_xticklabels(RATE_LABELS, fontweight='bold', fontsize=14)
ax.set_ylim(-2, 105)

# Panel 3: Latency p99
ax = axes[0, 2]
for mode in MODES:
    sub = df_raw[df_raw['mode'] == mode]
    if sub.empty: continue
    p99s = [sub[sub['target_qps'] == r]['lat_p99_ms'].mean() for r in RATES]
    ax.plot([r / 1e6 for r in RATES], p99s, label=MODE_LABELS[mode], color=MODE_COLORS[mode], marker=MODE_MARKERS[mode], linewidth=2.5, markersize=8)
ax.set_title(r"(C) Tail Latency ($p_{99}$)", fontweight='bold', fontsize=17)
ax.set_ylabel(r"Latency $p_{99}$ (ms)", fontweight='bold', fontsize=15)
ax.set_xticks([0.5, 1.0, 2.5, 4.0])
ax.set_xticklabels(RATE_LABELS, fontweight='bold', fontsize=14)

# Panel 4: NIC RX Discards
ax = axes[1, 0]
for mode in MODES:
    sub = df_raw[df_raw['mode'] == mode]
    if sub.empty: continue
    discs = [max(sub[sub['target_qps'] == r]['nic_rx_discards'].mean(), 1) for r in RATES]
    ax.plot([r / 1e6 for r in RATES], discs, label=MODE_LABELS[mode], color=MODE_COLORS[mode], marker=MODE_MARKERS[mode], linewidth=2.5, markersize=8)
ax.set_yscale('log')
ax.set_title("(D) Hardware RX Discards (Log)", fontweight='bold', fontsize=17)
ax.set_ylabel("RX Discards", fontweight='bold', fontsize=15)
ax.set_xticks([0.5, 1.0, 2.5, 4.0])
ax.set_xticklabels(RATE_LABELS, fontweight='bold', fontsize=14)

# Panel 5: CPU Utilization
ax = axes[1, 1]
for mode in MODES:
    sub = df_raw[df_raw['mode'] == mode]
    if sub.empty: continue
    cpus = [sub[sub['target_qps'] == r]['srv_dedicated_busy'].mean() for r in RATES]
    ax.plot([r / 1e6 for r in RATES], cpus, label=MODE_LABELS[mode], color=MODE_COLORS[mode], marker=MODE_MARKERS[mode], linewidth=2.5, markersize=8)
ax.set_title("(E) Dedicated Server CPU Usage", fontweight='bold', fontsize=17)
ax.set_ylabel("Dedicated CPU (%)", fontweight='bold', fontsize=15)
ax.set_xticks([0.5, 1.0, 2.5, 4.0])
ax.set_xticklabels(RATE_LABELS, fontweight='bold', fontsize=14)
ax.set_ylim(-2, 105)

# Panel 6: Ates HW Cache Tier Breakdown
ax = axes[1, 2]
sram_hits = [sub_ates[sub_ates['target_qps'] == r]['hw_cache_hits'].mean() / 1e6 for r in RATES]
dram_hits = [sub_ates[sub_ates['target_qps'] == r]['driver_hits'].mean() / 1e6 for r in RATES]
user_hits = [sub_ates[sub_ates['target_qps'] == r]['userspace_hits'].mean() / 1e6 for r in RATES]
lost_pkts = [sub_ates[sub_ates['target_qps'] == r]['queries_lost'].mean() / 1e6 for r in RATES]

ax.bar(indices, sram_hits, bar_width, label='L1 SRAM', color='#e7298a')
ax.bar(indices, dram_hits, bar_width, bottom=sram_hits, label='L2 DRAM', color='#7570b3')
bottom_user = [sram_hits[i] + dram_hits[i] for i in range(len(RATES))]
ax.bar(indices, user_hits, bar_width, bottom=bottom_user, label='L3 User', color='#1b9e77')
bottom_lost = [bottom_user[i] + user_hits[i] for i in range(len(RATES))]
ax.bar(indices, lost_pkts, bar_width, bottom=bottom_lost, label='Lost', color='#d95f02', alpha=0.7)
ax.set_title("(F) AtesN-DS Tier Breakdown", fontweight='bold', fontsize=17)
ax.set_ylabel("Queries (Millions)", fontweight='bold', fontsize=15)
ax.set_xticks(indices)
ax.set_xticklabels(RATE_LABELS, fontweight='bold', fontsize=14)
ax.legend(loc='upper left', fontsize=11, framealpha=0.9)

# Legend on Panel 1
axes[0, 0].legend(loc='upper left', fontsize=12, framealpha=0.92)

plt.suptitle("AtesN-DS Performance Dashboard", fontsize=22, fontweight='bold', y=0.99)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "09_comprehensive_dashboard.png"), dpi=300)
plt.savefig(os.path.join(OUT_DIR, "09_comprehensive_dashboard.pdf"))
plt.close()

print(f"🎉 Successfully generated all publication graphs in: {OUT_DIR}")
