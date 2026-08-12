import pandas as pd
import matplotlib.pyplot as plt
import glob
import os
import re

# =====================================================
# LEITURA DOS DADOS
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
        cache_type = "No HW Cache"
    elif "hw_cache" in name:
        cache_type = "HW Cache"
    else:
        continue

    match = re.search(r"(\d+)\.csv$", name)

    if not match:
        print(f"Não consegui extrair concorrência de {name}")
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

df = pd.DataFrame(rows)

df = df.sort_values(["cache_type", "concurrency"])

print("\nDados carregados:")
print(df[["cache_type", "concurrency"]])

# =====================================================
# MÉTRICA DERIVADA (CPU TOTAL)
# =====================================================

if (
    "cpu_user_mean" in df.columns
    and "cpu_system_mean" in df.columns
):
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

    # Calcular percentis para o CPU Total como a soma dos percentis dos componentes
    for p in ["p50", "p75", "p90", "p99"]:
        user_p = df[f"cpu_user_{p}"] if f"cpu_user_{p}" in df.columns else 0.0
        system_p = df[f"cpu_system_{p}"] if f"cpu_system_{p}" in df.columns else 0.0
        softirq_p = df[f"cpu_softirq_{p}"] if f"cpu_softirq_{p}" in df.columns else 0.0
        irq_p = df[f"cpu_irq_{p}"] if f"cpu_irq_{p}" in df.columns else 0.0

        user_p_std = df[f"cpu_user_{p}_std"] if f"cpu_user_{p}_std" in df.columns else 0.0
        system_p_std = df[f"cpu_system_{p}_std"] if f"cpu_system_{p}_std" in df.columns else 0.0
        softirq_p_std = df[f"cpu_softirq_{p}_std"] if f"cpu_softirq_{p}_std" in df.columns else 0.0
        irq_p_std = df[f"cpu_irq_{p}_std"] if f"cpu_irq_{p}_std" in df.columns else 0.0

        df[f"cpu_total_{p}"] = user_p + system_p + softirq_p + irq_p
        df[f"cpu_total_{p}_std"] = (
            user_p_std ** 2
            + system_p_std ** 2
            + softirq_p_std ** 2
            + irq_p_std ** 2
        ) ** 0.5

# =====================================================
# PLOT FUNCTION
# =====================================================

def plot_metric(metric, ylabel, filename):
    plt.figure(figsize=(12, 6))

    for cache in sorted(df["cache_type"].unique()):

        subset = (
            df[df["cache_type"] == cache]
            .sort_values("concurrency")
        )

        if metric not in subset.columns:
            continue

        x = subset["concurrency"].to_numpy()
        y = subset[metric].to_numpy()

        plt.plot(
            x,
            y,
            marker="o",
            linewidth=2,
            label=cache,
        )

        std_col = f"{metric}_std"

        if std_col in subset.columns:
            std = subset[std_col].fillna(0).to_numpy()

            plt.fill_between(
                x,
                y - std,
                y + std,
                alpha=0.30,
            )

    plt.xlabel("Concurrent Connections")
    plt.ylabel(ylabel)
    plt.title(f"{metric} (Mean ± Std Dev)")
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(filename, dpi=300)
    plt.close()

# =====================================================
# CPU
# =====================================================

plot_metric("cpu_user_mean", "CPU User (%)", "cpu_user_mean.png")
plot_metric("cpu_system_mean", "CPU System (%)", "cpu_system_mean.png")
plot_metric("cpu_softirq_mean", "CPU SoftIRQ (%)", "cpu_softirq_mean.png")
plot_metric("cpu_irq_mean", "CPU IRQ (%)", "cpu_irq_mean.png")
plot_metric("cpu_total_mean", "Total CPU (%)", "cpu_total_mean.png")
plot_metric("max_core_usage_mean", "Max Core Usage (%)", "max_core_usage_mean.png")

# =====================================================
# MEMÓRIA
# =====================================================

plot_metric("mem_used_mean", "Memory Used (%)", "mem_used_mean.png")

# =====================================================
# CACHE MISSES & HIT RATE
# =====================================================

plot_metric("cache_misses", "Cache Misses", "cache_misses.png")
plot_metric("cache_hits", "Cache Hits", "cache_hits.png")
plot_metric("cache_hit_rate", "Cache Hit Rate (%)", "cache_hit_rate.png")

# =====================================================
# Percentis (P50, P75, P90, P99)
# =====================================================

percentiles = ["p50", "p75", "p90", "p99"]
generated_files = [
    "cpu_user_mean.png",
    "cpu_system_mean.png",
    "cpu_softirq_mean.png",
    "cpu_irq_mean.png",
    "cpu_total_mean.png",
    "max_core_usage_mean.png",
    "mem_used_mean.png",
    "cache_misses.png",
    "cache_hits.png",
    "cache_hit_rate.png",
]

for p in percentiles:
    plot_metric(f"cpu_user_{p}", f"CPU User {p.upper()} (%)", f"cpu_user_{p}.png")
    plot_metric(f"cpu_system_{p}", f"CPU System {p.upper()} (%)", f"cpu_system_{p}.png")
    plot_metric(f"cpu_softirq_{p}", f"CPU SoftIRQ {p.upper()} (%)", f"cpu_softirq_{p}.png")
    plot_metric(f"cpu_irq_{p}", f"CPU IRQ {p.upper()} (%)", f"cpu_irq_{p}.png")
    plot_metric(f"cpu_total_{p}", f"Total CPU {p.upper()} (%)", f"cpu_total_{p}.png")
    plot_metric(f"max_core_usage_{p}", f"Max Core Usage {p.upper()} (%)", f"max_core_usage_{p}.png")
    plot_metric(f"mem_used_{p}", f"Memory Used {p.upper()} (%)", f"mem_used_{p}.png")
    
    generated_files.extend([
        f"cpu_user_{p}.png",
        f"cpu_system_{p}.png",
        f"cpu_softirq_{p}.png",
        f"cpu_irq_{p}.png",
        f"cpu_total_{p}.png",
        f"max_core_usage_{p}.png",
        f"mem_used_{p}.png",
    ])

print("\nGráficos gerados:")
for f in generated_files:
    print(f)
