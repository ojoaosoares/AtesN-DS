import pandas as pd
import matplotlib.pyplot as plt
import glob
import os
import re

import math

rows = []

for file in glob.glob("*.csv"):
    name = os.path.basename(file)

    if "no_hw_cache" in name:
        cache_type = "No HW Cache"
    elif "hw_cache" in name:
        cache_type = "HW Cache"
    else:
        continue

    match = re.search(r"(\d+)\.csv$", name)

    if not match:
        continue

    concurrency = int(match.group(1))

    metrics_df = pd.read_csv(file)

    metrics = {
        "cache_type": cache_type,
        "concurrency": concurrency,
    }

    for _, row in metrics_df.iterrows():
        metric_name = str(row["metric"])

        metrics[metric_name] = float(row["mean"]) if "mean" in row else float(row["value"])
        if "std" in row and pd.notna(row["std"]):
            metrics[f"{metric_name}_std"] = float(row["std"])
        if "ci95" in row and pd.notna(row["ci95"]):
            metrics[f"{metric_name}_ci95"] = float(row["ci95"])
        elif "std" in row and pd.notna(row["std"]):
            # Fallback: calculate 95% CI from std assuming n=30 runs (t_crit=2.0452)
            n_runs = float(row["count"]) if ("count" in row and pd.notna(row["count"]) and float(row["count"]) > 1) else 30.0
            metrics[f"{metric_name}_ci95"] = 2.0452 * (float(row["std"]) / (n_runs ** 0.5))

    rows.append(metrics)

if not rows:
    raise ValueError(
        "Nenhum CSV foi carregado. Verifique se o script está na pasta correta."
    )

df = pd.DataFrame(rows)

print("\n=== COLUNAS DO DATAFRAME ===")
for c in sorted(df.columns):
    print(c)

print("\nDados carregados:")
print(df[["cache_type", "concurrency"]].sort_values("concurrency"))

df = df.sort_values(["cache_type", "concurrency"])

# =====================================================
# Throughput
# =====================================================

plt.figure(figsize=(12, 6))

for cache in df["cache_type"].unique():
    subset = df[df["cache_type"] == cache]

    x = subset["concurrency"].to_numpy()
    y = subset["queriesPerSecond"].to_numpy()

    plt.plot(
        x,
        y,
        marker="o",
        linewidth=2,
        label=cache,
    )

    if "queriesPerSecond_ci95" in subset.columns:
        ci = subset["queriesPerSecond_ci95"].fillna(0).to_numpy()
        plt.fill_between(x, y - ci, y + ci, alpha=0.25)
    elif "queriesPerSecond_std" in subset.columns:
        ci = (subset["queriesPerSecond_std"].fillna(0).to_numpy() / (30.0 ** 0.5)) * 2.0452
        plt.fill_between(x, y - ci, y + ci, alpha=0.25)

plt.xlabel("Concurrent Connections")
plt.ylabel("Queries/s")
plt.title("Throughput vs Concurrency (Mean ± 95% Confidence Interval)")
plt.grid(True, alpha=0.3)
plt.legend()
plt.tight_layout()
plt.savefig("throughput_vs_concurrency.png", dpi=300)
plt.close()

# =====================================================
# Mean Latency
# =====================================================

plt.figure(figsize=(12, 6))

for cache in df["cache_type"].unique():
    subset = df[df["cache_type"] == cache]

    x = subset["concurrency"].to_numpy()
    y = subset["latency_mean_ms"].to_numpy()

    plt.plot(
        x,
        y,
        marker="o",
        linewidth=2,
        label=cache,
    )

    if "latency_mean_ms_ci95" in subset.columns:
        ci = subset["latency_mean_ms_ci95"].fillna(0).to_numpy()
        plt.fill_between(x, y - ci, y + ci, alpha=0.25)
    elif "latency_mean_ms_std" in subset.columns:
        ci = (subset["latency_mean_ms_std"].fillna(0).to_numpy() / (30.0 ** 0.5)) * 2.0452
        plt.fill_between(x, y - ci, y + ci, alpha=0.25)

plt.xlabel("Concurrent Connections")
plt.ylabel("Mean Latency (ms)")
plt.title("Mean Latency vs Concurrency (Mean ± 95% Confidence Interval)")
plt.grid(True, alpha=0.3)
plt.legend()
plt.tight_layout()
plt.savefig("latency_mean_vs_concurrency.png", dpi=300)
plt.close()

# =====================================================
# Percentis
# =====================================================

percentiles = [
    "latency_p50_ms",
    "latency_p75_ms",
    "latency_p90_ms",
    "latency_p95_ms",
    "latency_p99_ms",
]

for metric in percentiles:
    if metric not in df.columns:
        continue

    plt.figure(figsize=(12, 6))

    for cache in df["cache_type"].unique():
        subset = df[df["cache_type"] == cache]

        x = subset["concurrency"].to_numpy()
        y = subset[metric].to_numpy()

        plt.plot(
            x,
            y,
            marker="o",
            linewidth=2,
            label=cache,
        )

        ci_col = f"{metric}_ci95"
        std_col = f"{metric}_std"
        if ci_col in subset.columns:
            ci = subset[ci_col].fillna(0).to_numpy()
            plt.fill_between(x, y - ci, y + ci, alpha=0.25)
        elif std_col in subset.columns:
            ci = (subset[std_col].fillna(0).to_numpy() / (30.0 ** 0.5)) * 2.0452
            plt.fill_between(x, y - ci, y + ci, alpha=0.25)

    plt.xlabel("Concurrent Connections")
    plt.ylabel("Latency (ms)")
    plt.title(f"{metric} (Mean ± 95% Confidence Interval)")
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"{metric}.png", dpi=300)
    plt.close()

# =====================================================
# Total Requests
# =====================================================

if "totalRequests" in df.columns:
    plt.figure(figsize=(12, 6))

    for cache in df["cache_type"].unique():
        subset = df[df["cache_type"] == cache]

        x = subset["concurrency"].to_numpy()
        y = subset["totalRequests"].to_numpy()

        plt.plot(
            x,
            y,
            marker="o",
            linewidth=2,
            label=cache,
        )

        if "totalRequests_ci95" in subset.columns:
            ci = subset["totalRequests_ci95"].fillna(0).to_numpy()
            plt.fill_between(x, y - ci, y + ci, alpha=0.25)
        elif "totalRequests_std" in subset.columns:
            ci = (subset["totalRequests_std"].fillna(0).to_numpy() / (30.0 ** 0.5)) * 2.0452
            plt.fill_between(x, y - ci, y + ci, alpha=0.25)

    plt.xlabel("Concurrent Connections")
    plt.ylabel("Total Requests")
    plt.title("Total Requests vs Concurrency (Mean ± 95% Confidence Interval)")
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig("total_requests_vs_concurrency.png", dpi=300)
    plt.close()

# =====================================================
# Speedup
# =====================================================

if "HW Cache" in df["cache_type"].values and "No HW Cache" in df["cache_type"].values:
    hw = (
        df[df["cache_type"] == "HW Cache"]
        .set_index("concurrency")
        .sort_index()
    )

    no_hw = (
        df[df["cache_type"] == "No HW Cache"]
        .set_index("concurrency")
        .sort_index()
    )

    common = hw.index.intersection(no_hw.index)

    if not common.empty and "queriesPerSecond" in hw.columns:
        speedup = (
            hw.loc[common, "queriesPerSecond"]
            / no_hw.loc[common, "queriesPerSecond"]
        )

        plt.figure(figsize=(12, 6))

        plt.plot(
            common,
            speedup,
            marker="o",
            linewidth=2,
        )

        plt.axhline(1.0, linestyle="--")

        plt.xlabel("Concurrent Connections")
        plt.ylabel("Speedup")
        plt.title("HW Cache Speedup")
        plt.grid(True)
        plt.tight_layout()
        plt.savefig("speedup.png", dpi=300)
        plt.close()

print("\nGráficos gerados:")
print("throughput_vs_concurrency.png")
print("latency_mean_vs_concurrency.png")
print("latency_p50_ms.png")
print("latency_p75_ms.png")
print("latency_p90_ms.png")
print("latency_p95_ms.png")
print("latency_p99_ms.png")
print("total_requests_vs_concurrency.png")
print("speedup.png")
