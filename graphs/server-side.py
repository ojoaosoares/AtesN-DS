import pandas as pd
import matplotlib.pyplot as plt
import glob
import os
import re

# =====================================================
# LEITURA DOS DADOS
# =====================================================

rows = []

for file in glob.glob("server_output*.csv"):
    name = os.path.basename(file)

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

            metrics[metric_name] = float(row["mean"])
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
# MÉTRICA DERIVADA
# =====================================================

if (
    "cpu_user_mean" in df.columns
    and "cpu_system_mean" in df.columns
):
    df["cpu_total_mean"] = (
        df["cpu_user_mean"]
        + df["cpu_system_mean"]
    )

    df["cpu_total_mean_std"] = (
        (
            df["cpu_user_mean_std"] ** 2
            + df["cpu_system_mean_std"] ** 2
        ) ** 0.5
    )

# =====================================================
# PLOT
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

plot_metric(
    "cpu_user_mean",
    "CPU User (%)",
    "cpu_user_mean.png",
)

plot_metric(
    "cpu_system_mean",
    "CPU System (%)",
    "cpu_system_mean.png",
)

plot_metric(
    "cpu_total_mean",
    "Total CPU (%)",
    "cpu_total_mean.png",
)

plot_metric(
    "max_core_usage_mean",
    "Max Core Usage (%)",
    "max_core_usage_mean.png",
)

# =====================================================
# MEMÓRIA
# =====================================================

plot_metric(
    "mem_used_mean",
    "Memory Used (GB)",
    "mem_used_mean.png",
)

# =====================================================
# P99
# =====================================================

plot_metric(
    "cpu_user_p99",
    "CPU User P99 (%)",
    "cpu_user_p99.png",
)

plot_metric(
    "cpu_system_p99",
    "CPU System P99 (%)",
    "cpu_system_p99.png",
)

plot_metric(
    "max_core_usage_p99",
    "Max Core Usage P99 (%)",
    "max_core_usage_p99.png",
)

plot_metric(
    "mem_used_p99",
    "Memory Used P99 (GB)",
    "mem_used_p99.png",
)

print("\nGráficos gerados:")
print("cpu_user_mean.png")
print("cpu_system_mean.png")
print("cpu_total_mean.png")
print("max_core_usage_mean.png")
print("mem_used_mean.png")
print("cpu_user_p99.png")
print("cpu_system_p99.png")
print("max_core_usage_p99.png")
print("mem_used_p99.png")