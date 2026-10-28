#!/usr/bin/env python3
import csv
from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SUMMARY_CSV = os.path.join(SCRIPT_DIR, "summary_official_pcie2_sweep.csv")

if not os.path.exists(SUMMARY_CSV):
    print(f"Error: {SUMMARY_CSV} not found")
    exit(1)

# Color and style definitions
COLORS = {
    'ates_hw_cache': '#1f77b4',       # Blue
    'ates_driver': '#2ca02c',         # Green
    'unbound_hw_cache': '#ff7f0e',    # Orange
    'unbound_standalone': '#d62728'   # Red
}

LABELS = {
    'ates_hw_cache': 'AtesN-DS (HW Cache)',
    'ates_driver': 'AtesN-DS (Driver XDP)',
    'unbound_hw_cache': 'Unbound (HW Cache)',
    'unbound_standalone': 'Unbound (Standalone)'
}

MARKERS = {
    'ates_hw_cache': 'o',
    'ates_driver': 's',
    'unbound_hw_cache': '^',
    'unbound_standalone': 'x'
}

# Read summary data
data = defaultdict(dict)
rates_set = set()

with open(SUMMARY_CSV, 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        mode = row['mode']
        try:
            rate = int(row['target_qps'])
        except ValueError:
            continue
        rates_set.add(rate)
        data[mode][rate] = {
            'achieved_qps': float(row['achieved_qps_mean']),
            'loss_pct': float(row['packet_loss_pct_mean']),
            'p99': float(row['lat_p99_ms_mean']),
            'cpu': float(row['srv_all_busy_mean']),
            'hw_hits': float(row['hw_cache_hits_mean']),
            'drv_hits': float(row['driver_hits_mean']),
            'usr_hits': float(row['userspace_hits_mean']),
            'q_lost': float(row['queries_lost_mean']),
            'nic_disc': float(row['nic_rx_discards_mean']),
            'hw_pass': float(row['hw_pass_pkts_mean'])
        }

rates = sorted(list(rates_set))
rate_labels = [f"{r//1000}k" if r < 1000000 else f"{r/1000000:.1f}M" for r in rates]

plt.rcParams.update({
    'font.size': 11,
    'axes.labelsize': 12,
    'axes.titlesize': 13,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 10,
    'figure.titlesize': 14
})

# ==============================================================================
# Figure 1: Throughput and Packet Loss (2 subplots)
# ==============================================================================
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5), dpi=300)

for mode in ['ates_hw_cache', 'ates_driver', 'unbound_hw_cache', 'unbound_standalone']:
    if mode not in data: continue
    qps_vals = [data[mode].get(r, {}).get('achieved_qps', 0) / 1e6 for r in rates]
    loss_vals = [data[mode].get(r, {}).get('loss_pct', 0) for r in rates]
    
    ax1.plot(rates, qps_vals, marker=MARKERS[mode], color=COLORS[mode], 
             label=LABELS[mode], linewidth=2.2, markersize=7)
    ax2.plot(rates, loss_vals, marker=MARKERS[mode], color=COLORS[mode], 
             label=LABELS[mode], linewidth=2.2, markersize=7)

# Ideal line
ax1.plot(rates, [r / 1e6 for r in rates], 'k--', alpha=0.5, label='Ideal (Zero Loss)')

ax1.set_xlabel('Taxa Alvo de Injeção (QPS)')
ax1.set_ylabel('Vazão Efetiva Alcançada (Milhões QPS)')
ax1.set_title('(a) Vazão Efetiva de Resolução')
ax1.set_xticks(rates)
ax1.set_xticklabels(rate_labels)
ax1.grid(True, linestyle=':', alpha=0.6)
ax1.legend(loc='upper left', framealpha=0.9)

ax2.set_xlabel('Taxa Alvo de Injeção (QPS)')
ax2.set_ylabel('Perda de Pacotes (%)')
ax2.set_title('(b) Taxa de Perda de Pacotes')
ax2.set_xticks(rates)
ax2.set_xticklabels(rate_labels)
ax2.set_ylim(-2, 105)
ax2.grid(True, linestyle=':', alpha=0.6)
ax2.legend(loc='center right', framealpha=0.9)

plt.tight_layout()
out_fig1 = os.path.join(SCRIPT_DIR, "fig_pcie2_throughput_loss.png")
plt.savefig(out_fig1)
plt.close()
print(f"✓ Saved: {out_fig1}")

# ==============================================================================
# Figure 2: Tier Breakdown Stacked Bar Chart (Ates HW vs Unbound HW)
# ==============================================================================
fig, (ax_ates, ax_unbound) = plt.subplots(1, 2, figsize=(14, 5.5), dpi=300)

x = np.arange(len(rates))
width = 0.55

# Ates HW Cache Breakdown
hw_hits_ates = [data['ates_hw_cache'].get(r, {}).get('hw_hits', 0) / 1e6 for r in rates]
drv_hits_ates = [data['ates_hw_cache'].get(r, {}).get('drv_hits', 0) / 1e6 for r in rates]
usr_hits_ates = [data['ates_hw_cache'].get(r, {}).get('usr_hits', 0) / 1e6 for r in rates]
lost_ates = [data['ates_hw_cache'].get(r, {}).get('q_lost', 0) / 1e6 for r in rates]

ax_ates.bar(x, hw_hits_ates, width, label='L1 SmartNIC SRAM (HW)', color='#1f77b4')
ax_ates.bar(x, drv_hits_ates, width, bottom=hw_hits_ates, label='L2 Host DRAM (Driver XDP)', color='#2ca02c')
bottom_usr = np.array(hw_hits_ates) + np.array(drv_hits_ates)
ax_ates.bar(x, usr_hits_ates, width, bottom=bottom_usr, label='L3 Userspace (Unbound)', color='#9467bd')
bottom_lost = bottom_usr + np.array(usr_hits_ates)
ax_ates.bar(x, lost_ates, width, bottom=bottom_lost, label='Queries Perdidas', color='#d62728', alpha=0.8)

ax_ates.set_xlabel('Taxa Alvo de Injeção')
ax_ates.set_ylabel('Total de Queries (Milhões em 120s)')
ax_ates.set_title('(a) AtesN-DS (HW Cache) — Atendimento Hierárquico')
ax_ates.set_xticks(x)
ax_ates.set_xticklabels(rate_labels)
ax_ates.grid(True, axis='y', linestyle=':', alpha=0.6)
ax_ates.legend(loc='upper left', framealpha=0.9)

# Unbound HW Cache Breakdown
hw_hits_ub = [data['unbound_hw_cache'].get(r, {}).get('hw_hits', 0) / 1e6 for r in rates]
usr_hits_ub = [data['unbound_hw_cache'].get(r, {}).get('usr_hits', 0) / 1e6 for r in rates]
lost_ub = [data['unbound_hw_cache'].get(r, {}).get('q_lost', 0) / 1e6 for r in rates]

ax_unbound.bar(x, hw_hits_ub, width, label='L1 SmartNIC SRAM (HW)', color='#1f77b4')
ax_unbound.bar(x, usr_hits_ub, width, bottom=hw_hits_ub, label='L3 Userspace (Unbound)', color='#9467bd')
bottom_ub_lost = np.array(hw_hits_ub) + np.array(usr_hits_ub)
ax_unbound.bar(x, lost_ub, width, bottom=bottom_ub_lost, label='Queries Perdidas (Gargalo Host)', color='#d62728', alpha=0.8)

ax_unbound.set_xlabel('Taxa Alvo de Injeção')
ax_unbound.set_ylabel('Total de Queries (Milhões em 120s)')
ax_unbound.set_title('(b) Unbound (HW Cache) — Colapso por Falta de L2 DRAM')
ax_unbound.set_xticks(x)
ax_unbound.set_xticklabels(rate_labels)
ax_unbound.grid(True, axis='y', linestyle=':', alpha=0.6)
ax_unbound.legend(loc='upper left', framealpha=0.9)

plt.tight_layout()
out_fig2 = os.path.join(SCRIPT_DIR, "fig_pcie2_tier_breakdown.png")
plt.savefig(out_fig2)
plt.close()
print(f"✓ Saved: {out_fig2}")

# ==============================================================================
# Figure 3: PCIe Discards and Host CPU Utilization
# ==============================================================================
fig, (ax_disc, ax_cpu) = plt.subplots(1, 2, figsize=(14, 5.5), dpi=300)

for mode in ['ates_hw_cache', 'ates_driver', 'unbound_hw_cache', 'unbound_standalone']:
    if mode not in data: continue
    disc_vals = [data[mode].get(r, {}).get('nic_disc', 0) / 1e6 for r in rates]
    cpu_vals = [data[mode].get(r, {}).get('cpu', 0) for r in rates]
    
    ax_disc.plot(rates, disc_vals, marker=MARKERS[mode], color=COLORS[mode], 
                 label=LABELS[mode], linewidth=2.2, markersize=7)
    ax_cpu.plot(rates, cpu_vals, marker=MARKERS[mode], color=COLORS[mode], 
                label=LABELS[mode], linewidth=2.2, markersize=7)

ax_disc.set_xlabel('Taxa Alvo de Injeção (QPS)')
ax_disc.set_ylabel('Descartes no Anel DMA da NIC (Milhões)')
ax_disc.set_title('(a) Descartes de Buffer PCIe (DMA Backpressure)')
ax_disc.set_xticks(rates)
ax_disc.set_xticklabels(rate_labels)
ax_disc.grid(True, linestyle=':', alpha=0.6)
ax_disc.legend(loc='upper left', framealpha=0.9)

ax_cpu.set_xlabel('Taxa Alvo de Injeção (QPS)')
ax_cpu.set_ylabel('Uso de CPU do Servidor (%)')
ax_cpu.set_title('(b) Utilização de CPU do Servidor (2 Cores)')
ax_cpu.set_xticks(rates)
ax_cpu.set_xticklabels(rate_labels)
ax_cpu.set_ylim(0, 100)
ax_cpu.grid(True, linestyle=':', alpha=0.6)
ax_cpu.legend(loc='upper left', framealpha=0.9)

plt.tight_layout()
out_fig3 = os.path.join(SCRIPT_DIR, "fig_pcie2_pcie_discards_cpu.png")
plt.savefig(out_fig3)
plt.close()
print(f"✓ Saved: {out_fig3}")
print("All plots generated successfully!")
