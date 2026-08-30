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

# =====================================================
# LEITURA DOS DADOS DO SERVIDOR
# =====================================================

rows = []
seen_files = set()
files = glob.glob("server_results*.csv") + glob.glob("server_output*.csv")

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

    try:
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
    except Exception as e:
        print(f"Erro ao processar {name}: {e}")

if not rows:
    raise RuntimeError("Nenhum CSV encontrado.")

df = pd.DataFrame(rows).sort_values(["cache_type", "concurrency"])

# =====================================================
# MÉTRICA DERIVADA (CPU TOTAL)
# =====================================================

if "cpu_user_mean" in df.columns and "cpu_system_mean" in df.columns:
    softirq_mean = df["cpu_softirq_mean"] if "cpu_softirq_mean" in df.columns else 0.0
    irq_mean = df["cpu_irq_mean"] if "cpu_irq_mean" in df.columns else 0.0
    softirq_std = df["cpu_softirq_mean_std"] if "cpu_softirq_mean_std" in df.columns else 0.0
    irq_std = df["cpu_irq_mean_std"] if "cpu_irq_mean_std" in df.columns else 0.0

    df["cpu_total_mean"] = (
        df["cpu_user_mean"]
        + df["cpu_system_mean"]
        + softirq_mean
        + irq_mean
    )

    if "cpu_user_mean_std" in df.columns and "cpu_system_mean_std" in df.columns:
        df["cpu_total_mean_std"] = (
            (
                df["cpu_user_mean_std"] ** 2
                + df["cpu_system_mean_std"] ** 2
                + softirq_std ** 2
                + irq_std ** 2
            ) ** 0.5
        )

# =====================================================
# PLOT FUNCTION
# =====================================================

def plot_metric(metric, ylabel, filename, title=None, cache_types=None, ylim=None):
    if metric not in df.columns:
        return

    plt.figure(figsize=(9.5, 5.8))
    types_to_plot = cache_types if cache_types is not None else sorted(df["cache_type"].unique())

    for cache in types_to_plot:
        subset = df[df["cache_type"] == cache].sort_values("concurrency")
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

    concurrencies = sorted(df["concurrency"].unique())
    plt.xscale("log", base=2)
    plt.xticks(concurrencies, labels=[str(c) for c in concurrencies], rotation=45, fontsize=16)
    plt.yticks(fontsize=16)
    plt.xlabel("Concurrent Connections", fontweight="bold")
    plt.ylabel(ylabel, fontweight="bold")
    if ylim:
        plt.ylim(ylim)
    plt.title(title if title else f"{metric} vs Concurrency", fontweight="bold", pad=12)
    plt.grid(True, which="both", alpha=0.3)
    plt.legend(frameon=True, facecolor="white", edgecolor="#cccccc", framealpha=0.9, fontsize=16)
    plt.tight_layout()
    plt.savefig(filename, dpi=300)
    plt.close()

# =====================================================
# CPU
# =====================================================

plot_metric("cpu_user_mean", "CPU User (%)", "cpu_user_mean.png", "Host CPU User Utilization")
plot_metric("cpu_system_mean", "CPU System (%)", "cpu_system_mean.png", "Host CPU System Utilization")
plot_metric("cpu_softirq_mean", "CPU SoftIRQ (%)", "cpu_softirq_mean.png", "Host CPU SoftIRQ Overhead")
plot_metric("cpu_irq_mean", "CPU IRQ (%)", "cpu_irq_mean.png", "Host CPU HardIRQ Overhead")
plot_metric("cpu_total_mean", "Total CPU (%)", "cpu_total_mean.png", "Global Host CPU Utilization")
plot_metric("max_core_usage_mean", "Max Core Usage (%)", "max_core_usage_mean.png", "Maximum Core Utilization")

# =====================================================
# MEMÓRIA
# =====================================================

plot_metric("mem_used_mean", "Memory Used (%)", "mem_used_mean.png", "Host Memory Utilization")

# =====================================================
# CACHE MISSES & HIT RATE
# =====================================================

plot_metric("cache_misses", "Cache Misses", "cache_misses.png", "Cache Misses vs Concurrency")
plot_metric("cache_hits", "Cache Hits", "cache_hits.png", "Cache Hits vs Concurrency")

hit_rate_type = ["Offloaded-mode"] if "Offloaded-mode" in df["cache_type"].values else ["HW Cache"]
plot_metric("cache_hit_rate", "Cache Hit Rate (%)", "cache_hit_rate.png", "Offloaded-mode Hit Rate vs Concurrency", cache_types=hit_rate_type, ylim=(55, 78))

# =====================================================
# MÉTRICAS COMBINADAS (SE CLIENT FILES EXISTIREM)
# =====================================================

client_rows = []
cfiles = glob.glob("client_results*.csv") + glob.glob("client_output*.csv")
for f in sorted(cfiles):
    name = os.path.basename(f)
    ctype = "Offloaded-mode" if ("hw_cache" in name and "no_hw_cache" not in name) else ("Driver-mode" if "no_hw_cache" in name else None)
    if not ctype:
        continue
    m = re.search(r"(\d+)\.csv$", name)
    if not m:
        continue
    c = int(m.group(1))
    cdf = pd.read_csv(f)
    crow = {"cache_type": ctype, "concurrency": c}
    for _, r in cdf.iterrows():
        mname = str(r["metric"])
        crow[mname] = float(r["mean"]) if "mean" in r else float(r["value"])
        if "std" in r:
            crow[f"{mname}_std"] = float(r["std"])
    client_rows.append(crow)

if client_rows:
    merged_df = pd.merge(pd.DataFrame(client_rows).drop_duplicates(["cache_type", "concurrency"]), df, on=["cache_type", "concurrency"])
    
    # 1. Throughput vs Latency Trade-off Profile (Log-Log)
    fig, ax = plt.subplots(figsize=(9.5, 5.8))
    for ctype in sorted(merged_df["cache_type"].unique()):
        s = merged_df[merged_df["cache_type"] == ctype].sort_values("concurrency")
        x = s["queriesPerSecond"].to_numpy()
        y = s["latency_mean_ms"].to_numpy()
        color = "#1f77b4" if ctype in ["Offloaded-mode", "Offloaded mode", "HW Cache", "offloaded-mode"] else "#ff7f0e"
        marker = "o" if ctype in ["Offloaded-mode", "Offloaded mode", "HW Cache", "offloaded-mode"] else "s"
        ax.plot(
            x,
            y,
            marker=marker,
            markersize=7.5,
            linewidth=2.8,
            label=ctype,
            color=color,
        )

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Throughput (Queries/s) [Log Scale]", fontweight="bold")
    ax.set_ylabel("Mean Latency (ms) [Log Scale]", fontweight="bold")
    ax.set_title("Throughput vs Latency Trade-off Profile", fontweight="bold", pad=12)

    y_ticks = [0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0]
    ax.set_yticks(y_ticks)
    ax.set_yticklabels(["0.1", "0.2", "0.5", "1.0", "2.0", "5.0", "10.0"], fontsize=16)
    ax.tick_params(axis="both", which="major", labelsize=16)

    ax.grid(True, which="both", alpha=0.3)
    ax.legend(frameon=True, facecolor="white", edgecolor="#cccccc", framealpha=0.9, fontsize=16)
    plt.tight_layout()
    plt.savefig("throughput_vs_latency.png", dpi=300)
    plt.close()

    # 2. Computational Efficiency (QPS per 1% Total Host CPU)
    merged_df["qps_per_cpu"] = merged_df["queriesPerSecond"] / merged_df["cpu_total_mean"]
    
    # Error propagation for QPS / CPU
    rel_q = (merged_df["queriesPerSecond_std"] / merged_df["queriesPerSecond"]).fillna(0) if "queriesPerSecond_std" in merged_df.columns else 0.0
    rel_c = (merged_df["cpu_total_mean_std"] / merged_df["cpu_total_mean"]).fillna(0) if "cpu_total_mean_std" in merged_df.columns else 0.0
    merged_df["qps_per_cpu_std"] = merged_df["qps_per_cpu"] * ((rel_q**2 + rel_c**2)**0.5)

    plt.figure(figsize=(9.5, 5.8))
    for ctype in sorted(merged_df["cache_type"].unique()):
        s = merged_df[merged_df["cache_type"] == ctype].sort_values("concurrency")
        x = s["concurrency"].to_numpy()
        y = s["qps_per_cpu"].to_numpy()
        std = s["qps_per_cpu_std"].to_numpy()
        color = "#1f77b4" if ctype in ["Offloaded-mode", "Offloaded mode", "HW Cache", "offloaded-mode"] else "#ff7f0e"
        marker = "o" if ctype in ["Offloaded-mode", "Offloaded mode", "HW Cache", "offloaded-mode"] else "s"

        plt.fill_between(x, y - std, y + std, alpha=0.40, color=color)
        plt.plot(
            x,
            y,
            marker=marker,
            markersize=7.5,
            linewidth=2.8,
            label=ctype,
            color=color,
        )

    concurrencies = sorted(merged_df["concurrency"].unique())
    plt.xscale("log", base=2)
    plt.xticks(concurrencies, labels=[str(c) for c in concurrencies], rotation=45, fontsize=16)
    plt.yticks(fontsize=16)
    plt.xlabel("Concurrent Connections", fontweight="bold")
    plt.ylabel("Queries/s per 1% Host CPU", fontweight="bold")
    plt.title("Computational Efficiency (QPS / Host CPU %)", fontweight="bold", pad=12)
    plt.grid(True, which="both", alpha=0.3)
    plt.legend(frameon=True, facecolor="white", edgecolor="#cccccc", framealpha=0.9, fontsize=16)
    plt.tight_layout()
    plt.savefig("cpu_efficiency.png", dpi=300)
    plt.close()

print("\nGráficos de servidor gerados com sucesso com sombra destacada!")
