#!/usr/bin/env python3
"""
Official Workload & Trace Characterization Script (ISP Dataset Only)
Analyzes the production ISP DNS trace (Žiža et al., 2023) in RFC 1035 wire format:
  - Wire-format QNAME length = sum(1 + len(label) for label in domain.split('.')) + 1
  - Generates exact CDF CSV, summary statistics CSV, and publication-quality CDF plot (56B key).
"""

import os
import csv
from collections import Counter
import numpy as np
import matplotlib.pyplot as plt

# Set matplotlib publication style with large readable text and numbers
plt.rcParams.update({
    'font.family': 'serif',
    'font.size': 15,
    'axes.labelsize': 17,
    'axes.titlesize': 17,
    'xtick.labelsize': 15,
    'ytick.labelsize': 15,
    'legend.fontsize': 14,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'axes.grid': True,
    'grid.alpha': 0.3,
    'grid.linestyle': '--'
})

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT_DIR = os.path.dirname(os.path.abspath(__file__))
GRAPHS_DIR = os.path.join(BASE_DIR, "results")

ISP_TRACE = os.path.join(BASE_DIR, "tests", "isp_queries_2m.txt")


def wire_length(domain: str) -> int:
    """
    Computes exact RFC 1035 wire-format length of a QNAME in bytes.
    Each label is preceded by a 1-byte length octet, terminated by a 1-byte root null octet (0x00).
    Example: 'www.example.com' -> [3]'www'[7]'example'[3]'com'[0] = 17 bytes.
    """
    d = domain.strip().rstrip('.')
    if not d:
        return 1
    labels = d.split('.')
    return sum(1 + len(lbl) for lbl in labels) + 1


def analyze_file(filepath: str, label: str):
    all_lengths = []
    domain_counts = Counter()

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            d = line.strip().rstrip('.')
            if not d:
                continue
            wlen = wire_length(d)
            all_lengths.append(wlen)
            domain_counts[d] += 1

    all_lengths = np.array(all_lengths, dtype=np.int32)
    unique_domains = list(domain_counts.keys())
    unique_lengths = np.array([wire_length(d) for d in unique_domains], dtype=np.int32)

    total_queries = len(all_lengths)
    num_unique = len(unique_domains)

    # Key limit breakdown (all queries)
    fit_24 = int(np.sum(all_lengths <= 24))
    rej_24 = int(np.sum(all_lengths > 24))
    fit_56 = int(np.sum(all_lengths <= 56))
    rej_56 = int(np.sum(all_lengths > 56))

    # Key limit breakdown (unique domains)
    ufit_24 = int(np.sum(unique_lengths <= 24))
    urej_24 = int(np.sum(unique_lengths > 24))
    ufit_56 = int(np.sum(unique_lengths <= 56))
    urej_56 = int(np.sum(unique_lengths > 56))

    # Top-K popularity skew
    sorted_counts = [c for _, c in domain_counts.most_common()]
    cum_counts = np.cumsum(sorted_counts)
    skew = {}
    for k in [10, 100, 1000, 5000, 10000, 32768]:
        if k <= len(cum_counts):
            skew[k] = (int(cum_counts[k - 1]), float(cum_counts[k - 1] / total_queries * 100.0))
        else:
            skew[k] = (total_queries, 100.0)

    return {
        'label': label,
        'filepath': filepath,
        'total_queries': total_queries,
        'unique_domains': num_unique,
        'min_len': int(all_lengths.min()),
        'max_len': int(all_lengths.max()),
        'mean_len': float(all_lengths.mean()),
        'std_len': float(all_lengths.std()),
        'p10': float(np.percentile(all_lengths, 10)),
        'p25': float(np.percentile(all_lengths, 25)),
        'p50': float(np.percentile(all_lengths, 50)),
        'p75': float(np.percentile(all_lengths, 75)),
        'p90': float(np.percentile(all_lengths, 90)),
        'p95': float(np.percentile(all_lengths, 95)),
        'p99': float(np.percentile(all_lengths, 99)),
        'p999': float(np.percentile(all_lengths, 99.9)),
        'fit_24': fit_24,
        'fit_24_pct': fit_24 / total_queries * 100.0,
        'rej_24': rej_24,
        'rej_24_pct': rej_24 / total_queries * 100.0,
        'fit_56': fit_56,
        'fit_56_pct': fit_56 / total_queries * 100.0,
        'rej_56': rej_56,
        'rej_56_pct': rej_56 / total_queries * 100.0,
        'ufit_24': ufit_24,
        'ufit_24_pct': ufit_24 / num_unique * 100.0,
        'ufit_56': ufit_56,
        'ufit_56_pct': ufit_56 / num_unique * 100.0,
        'urej_56': urej_56,
        'urej_56_pct': urej_56 / num_unique * 100.0,
        'skew': skew,
        'all_lengths': all_lengths,
        'unique_lengths': unique_lengths,
    }


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    os.makedirs(GRAPHS_DIR, exist_ok=True)

    print("Analyzing Production ISP Trace...")
    s = analyze_file(ISP_TRACE, "ISP Trace (Žiža et al., 2023)")

    # 1. Save summary metrics CSV
    summary_csv = os.path.join(OUT_DIR, "trace_summary_metrics.csv")
    fieldnames = [
        'trace_name', 'total_queries', 'unique_domains',
        'min_wire_bytes', 'max_wire_bytes', 'mean_wire_bytes', 'std_wire_bytes',
        'p10_bytes', 'p25_bytes', 'p50_median_bytes', 'p75_bytes', 'p90_bytes', 'p95_bytes', 'p99_bytes', 'p99_9_bytes',
        'queries_lte_56B', 'queries_lte_56B_pct', 'queries_gt_56B_rejected', 'queries_gt_56B_rejected_pct',
        'unique_lte_56B', 'unique_lte_56B_pct', 'unique_gt_56B_rejected', 'unique_gt_56B_rejected_pct',
        'top_100_pct', 'top_1000_pct', 'top_5000_pct', 'top_32768_sram_pct'
    ]
    with open(summary_csv, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow({
            'trace_name': s['label'],
            'total_queries': s['total_queries'],
            'unique_domains': s['unique_domains'],
            'min_wire_bytes': s['min_len'],
            'max_wire_bytes': s['max_len'],
            'mean_wire_bytes': f"{s['mean_len']:.2f}",
            'std_wire_bytes': f"{s['std_len']:.2f}",
            'p10_bytes': f"{s['p10']:.1f}",
            'p25_bytes': f"{s['p25']:.1f}",
            'p50_median_bytes': f"{s['p50']:.1f}",
            'p75_bytes': f"{s['p75']:.1f}",
            'p90_bytes': f"{s['p90']:.1f}",
            'p95_bytes': f"{s['p95']:.1f}",
            'p99_bytes': f"{s['p99']:.1f}",
            'p99_9_bytes': f"{s['p999']:.1f}",
            'queries_lte_56B': s['fit_56'],
            'queries_lte_56B_pct': f"{s['fit_56_pct']:.2f}",
            'queries_gt_56B_rejected': s['rej_56'],
            'queries_gt_56B_rejected_pct': f"{s['rej_56_pct']:.2f}",
            'unique_lte_56B': s['ufit_56'],
            'unique_lte_56B_pct': f"{s['ufit_56_pct']:.2f}",
            'unique_gt_56B_rejected': s['urej_56'],
            'unique_gt_56B_rejected_pct': f"{s['urej_56_pct']:.2f}",
            'top_100_pct': f"{s['skew'][100][1]:.2f}",
            'top_1000_pct': f"{s['skew'][1000][1]:.2f}",
            'top_5000_pct': f"{s['skew'][5000][1]:.2f}",
            'top_32768_sram_pct': f"{s['skew'][32768][1]:.2f}",
        })

    # 2. Save exact byte-by-byte CDF CSV (1 to max_len bytes)
    cdf_csv = os.path.join(OUT_DIR, "trace_wire_length_cdf.csv")
    max_b = s['max_len']
    byte_bins = np.arange(1, max_b + 1)

    isp_all_counts = np.bincount(s['all_lengths'], minlength=max_b + 1)[1:]
    isp_all_cdf = np.cumsum(isp_all_counts) / s['total_queries'] * 100.0

    isp_uniq_counts = np.bincount(s['unique_lengths'], minlength=max_b + 1)[1:]
    isp_uniq_cdf = np.cumsum(isp_uniq_counts) / s['unique_domains'] * 100.0

    with open(cdf_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'wire_length_bytes',
            'isp_queries_count', 'isp_queries_cdf_pct',
            'isp_unique_count', 'isp_unique_cdf_pct'
        ])
        for i, b in enumerate(byte_bins):
            writer.writerow([
                b,
                int(isp_all_counts[i]), f"{isp_all_cdf[i]:.4f}",
                int(isp_uniq_counts[i]), f"{isp_uniq_cdf[i]:.4f}"
            ])

    # 3. Generate Publication-Quality CDF Plot (ISP Trace Only, 56B Key Only)
    fig, ax = plt.subplots(figsize=(8.4, 5.4))

    x_vals = byte_bins
    ax.plot(x_vals, isp_all_cdf / 100.0,
            label="All Replayed Queries ($N = 2{,}000{,}000$)",
            color="#1f77b4", linewidth=3.0, linestyle="-")
    ax.plot(x_vals, isp_uniq_cdf / 100.0,
            label="Unique Domain Names ($U = 83{,}659$)",
            color="#2ca02c", linewidth=2.8, linestyle="--")

    # Vertical line for 56-byte Hardware Key Limit
    ax.axvline(x=56, color="#d95f02", linestyle="-.", linewidth=2.6,
               label="SmartNIC Hardware Key Limit ($56\\,\\mathrm{B}$)")

    ax.set_xlim(0, 110)
    ax.set_ylim(0.0, 1.04)
    ax.set_xlabel("QNAME Wire-Format Length (Bytes)", fontsize=17, labelpad=9)
    ax.set_ylabel("CDF", fontsize=17, labelpad=9)
    ax.set_title("CDF of DNS QNAME Lengths", fontsize=17, pad=12)
    ax.tick_params(axis='both', which='major', labelsize=15)
    ax.legend(loc="lower right", frameon=True, facecolor="white", framealpha=0.95, fontsize=13.5)

    plt.tight_layout()

    out_png = os.path.join(OUT_DIR, "qname_length_cdf.png")
    out_pdf = os.path.join(OUT_DIR, "qname_length_cdf.pdf")
    results_png = os.path.join(GRAPHS_DIR, "qname_length_cdf.png")
    results_pdf = os.path.join(GRAPHS_DIR, "qname_length_cdf.pdf")

    fig.savefig(out_png)
    fig.savefig(out_pdf)
    fig.savefig(results_png)
    fig.savefig(results_pdf)
    plt.close(fig)

    print(f"Saved plots to:\n  {out_png}\n  {out_pdf}\n  {results_png}")
    print(f"Saved CSVs to:\n  {summary_csv}\n  {cdf_csv}")


if __name__ == "__main__":
    main()
