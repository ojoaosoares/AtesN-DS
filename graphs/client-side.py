import pandas as pd
import matplotlib.pyplot as plt
import glob
import os
import re

# Set general font settings for paper figures (extra large, bold and readable)
plt.rcParams.update({
    "font.size": 17,
    "axes.labelsize": 19,
    "axes.labelweight": "bold",
    "axes.titlesize": 20,
    "axes.titleweight": "bold",
    "xtick.labelsize": 16,
    "ytick.labelsize": 16,
    "legend.fontsize": 16,
    "figure.titlesize": 21,
})

rows = []
seen_files = set()
files = glob.glob("client_results*.csv") + glob.glob("client_output*.csv")

for file in files:
    name = os.path.basename(file)
    if name in seen_files:
        continue
    seen_files.add(name)

    if "no_hw_cache" in name:
        cache_type = "Driver-mode"
    elif "hw_cache" in name:
        cache_type = "Offloaded-mode"
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
        if "std" in row:
            metrics[f"{metric_name}_std"] = float(row["std"])

    rows.append(metrics)

if not rows:
    raise ValueError("Nenhum CSV foi carregado. Verifique se o script está na pasta correta.")

df = pd.DataFrame(rows).sort_values(["cache_type", "concurrency"])
concurrencies = sorted(df["concurrency"].unique())

def plot_client_metric(metric, ylabel, filename, title=None, max_c=None, min_c=None):
    if metric not in df.columns:
        return

    subset_df = df.copy()
    if max_c is not None:
        subset_df = subset_df[subset_df["concurrency"] <= max_c]
    if min_c is not None:
        subset_df = subset_df[subset_df["concurrency"] >= min_c]

    plt.figure(figsize=(9.5, 5.8))

    for cache in sorted(subset_df["cache_type"].unique()):
        subset = subset_df[subset_df["cache_type"] == cache].sort_values("concurrency")
        x = subset["concurrency"].to_numpy()
        y = subset[metric].to_numpy()

        marker = "o" if cache in ["Offloaded-mode", "Offloaded mode", "HW Cache", "offloaded-mode"] else "s"
        color = "#1f77b4" if cache in ["Offloaded-mode", "Offloaded mode", "HW Cache", "offloaded-mode"] else "#ff7f0e"

        std_col = f"{metric}_std"
        if std_col in subset.columns:
            std = subset[std_col].fillna(0).to_numpy()
            plt.fill_between(x, y - std, y + std, alpha=0.40, color=color)

        plt.plot(
            x,
            y,
            marker=marker,
            markersize=7.5,
            linewidth=2.8,
            label=cache,
            color=color,
        )

    c_ticks = sorted(subset_df["concurrency"].unique())
    plt.xscale("log", base=2)
    plt.xticks(c_ticks, labels=[str(c) for c in c_ticks], rotation=45 if len(c_ticks) > 5 else 0, fontsize=16)
    plt.yticks(fontsize=16)
    
    if max_c and not min_c:
        plt.xlabel(f"Concurrent Connections (1 to {max_c})", fontweight="bold")
    elif min_c and not max_c:
        plt.xlabel(f"Concurrent Connections ({min_c} to 16384)", fontweight="bold")
    elif min_c and max_c:
        plt.xlabel(f"Concurrent Connections ({min_c} to {max_c})", fontweight="bold")
    else:
        plt.xlabel("Concurrent Connections", fontweight="bold")

    plt.ylabel(ylabel, fontweight="bold")
    plt.title(title if title else f"{metric} vs Concurrency", fontweight="bold", pad=12)
    plt.grid(True, which="both", alpha=0.3)
    plt.legend(frameon=True, facecolor="white", edgecolor="#cccccc", framealpha=0.9, fontsize=16)
    plt.tight_layout()
    plt.savefig(filename, dpi=300)
    plt.close()

# =====================================================
# Plots
# =====================================================

plot_client_metric("queriesPerSecond", "Throughput (Queries/s)", "throughput_vs_concurrency.png", "Throughput vs Concurrency")

# Latência Média Completa e Dividida
plot_client_metric("latency_mean_ms", "Mean Latency (ms)", "latency_mean_vs_concurrency.png", "Mean Latency vs Concurrency (Full Range)")
plot_client_metric("latency_mean_ms", "Mean Latency (ms)", "latency_mean_low_concurrency.png", "Mean Latency: Low to Moderate Load (≤ 4096)", max_c=4096)
plot_client_metric("latency_mean_ms", "Mean Latency (ms)", "latency_mean_high_concurrency.png", "Mean Latency: High-Load Overload Regime (≥ 4096)", min_c=4096)

# Latência P99 Completa e Dividida
plot_client_metric("latency_p99_ms", "Latency P99 (ms)", "latency_p99_ms.png", "Latency P99 vs Concurrency (Full Range)")
plot_client_metric("latency_p99_ms", "Latency P99 (ms)", "latency_p99_low_concurrency.png", "Latency P99: Low to Moderate Load (≤ 4096)", max_c=4096)
plot_client_metric("latency_p99_ms", "Latency P99 (ms)", "latency_p99_high_concurrency.png", "Latency P99: High-Load Overload Regime (≥ 4096)", min_c=4096)

# Latência Mediana (P50) e Percentis
plot_client_metric("latency_p50_ms", "Median Latency (ms)", "latency_p50_ms.png", "Median Latency ($p50$) vs Concurrency")
plot_client_metric("latency_p75_ms", "Latency P75 (ms)", "latency_p75_ms.png", "Latency P75 vs Concurrency")
plot_client_metric("latency_p90_ms", "Latency P90 (ms)", "latency_p90_ms.png", "Latency P90 vs Concurrency")
plot_client_metric("latency_p95_ms", "Latency P95 (ms)", "latency_p95_ms.png", "Latency P95 vs Concurrency")

plot_client_metric("totalRequests", "Total Requests", "total_requests_vs_concurrency.png", "Total Requests vs Concurrency")

# =====================================================
# Speedup
# =====================================================

hw_key = "Offloaded-mode" if "Offloaded-mode" in df["cache_type"].values else ("HW Cache" if "HW Cache" in df["cache_type"].values else None)
nohw_key = "Driver-mode" if "Driver-mode" in df["cache_type"].values else ("No HW Cache" if "No HW Cache" in df["cache_type"].values else None)

if hw_key and nohw_key:
    hw = df[df["cache_type"] == hw_key].set_index("concurrency").sort_index()
    no_hw = df[df["cache_type"] == nohw_key].set_index("concurrency").sort_index()
    common = hw.index.intersection(no_hw.index)

    if not common.empty and "queriesPerSecond" in hw.columns:
        speedup = hw.loc[common, "queriesPerSecond"] / no_hw.loc[common, "queriesPerSecond"]
        
        std_hw = hw.loc[common, "queriesPerSecond_std"] if "queriesPerSecond_std" in hw.columns else 0.0
        std_nohw = no_hw.loc[common, "queriesPerSecond_std"] if "queriesPerSecond_std" in no_hw.columns else 0.0
        rel_hw = (std_hw / hw.loc[common, "queriesPerSecond"]).fillna(0)
        rel_nohw = (std_nohw / no_hw.loc[common, "queriesPerSecond"]).fillna(0)
        speedup_std = speedup * ((rel_hw**2 + rel_nohw**2)**0.5)

        plt.figure(figsize=(9.5, 5.8))
        plt.fill_between(common, speedup - speedup_std, speedup + speedup_std, alpha=0.40, color="#1f77b4")
        plt.plot(
            common,
            speedup,
            marker="o",
            markersize=7.5,
            linewidth=2.8,
            color="#1f77b4",
            label="Offloaded-mode Speedup",
        )

        plt.axhline(1.0, linestyle="--", color="gray", linewidth=1.5, label="Baseline (1.0x)")

        plt.xscale("log", base=2)
        plt.xticks(common, labels=[str(c) for c in common], rotation=45, fontsize=16)
        plt.yticks(fontsize=16)
        plt.xlabel("Concurrent Connections", fontweight="bold")
        plt.ylabel("Speedup (Multiplicative Factor)", fontweight="bold")
        plt.title("Throughput Speedup (Offloaded-mode / Driver-mode)", fontweight="bold", pad=12)
        plt.grid(True, which="both", alpha=0.3)
        plt.legend(frameon=True, facecolor="white", edgecolor="#cccccc", framealpha=0.9, fontsize=16)
        plt.tight_layout()
        plt.savefig("speedup.png", dpi=300)
        plt.close()

print("\nTodos os gráficos de cliente foram gerados com sucesso com sombra destacada!")
