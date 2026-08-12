import glob
import os
import re
import pandas as pd
import matplotlib.pyplot as plt


# =====================================================
# CONFIGURAÇÕES DE PLOTAGEM
# =====================================================

plt.rcParams.update({
    "font.size": 26,
    "axes.labelsize": 24,
    "xtick.labelsize": 22,
    "ytick.labelsize": 22,
    "legend.fontsize": 22,
    "lines.linewidth": 2.5,
    "lines.markersize": 8,
})


# =====================================================
# LEITURA DOS DADOS DO SERVIDOR
# =====================================================

rows = []

files = glob.glob(
    "server_results_*.csv"
)

if not files:

    raise ValueError(
        "Nenhum server_results_*.csv encontrado."
    )


for file in files:

    name = os.path.basename(file)


    if "no_hw_cache" in name:

        cache_type = "driver-mode"

    elif "hw_cache" in name:

        cache_type = "offloaded-mode"

    else:

        continue


    match = re.search(
        r"(\d+)\.csv$",
        name
    )

    if not match:
        continue


    concurrency = int(
        match.group(1)
    )


    try:

        metrics_df = pd.read_csv(
            file
        )


        metrics = {
            "cache_type": cache_type,
            "concurrency": concurrency,
        }


        for _, row in metrics_df.iterrows():

            metric_name = str(
                row["metric"]
            )

            metrics[metric_name] = float(
                row["mean"]
            )

            metrics[
                f"{metric_name}_std"
            ] = float(
                row["std"]
            )


        rows.append(metrics)


    except Exception as e:

        print(
            f"Erro ao processar {name}: {e}"
        )


if not rows:

    raise ValueError(
        "Nenhum resultado de servidor foi carregado."
    )


df = pd.DataFrame(
    rows
)

df = df.sort_values(
    [
        "cache_type",
        "concurrency"
    ]
)


print(
    "\nDados carregados:"
)

print(
    df[
        [
            "cache_type",
            "concurrency"
        ]
    ]
)


# =====================================================
# FUNÇÃO DE PLOTAGEM
# =====================================================

def plot_metric(
    metric,
    ylabel,
    title,
    filename
):

    plt.figure(
        figsize=(12, 6)
    )


    for cache in sorted(
        df["cache_type"].unique()
    ):

        subset = df[
            df["cache_type"] == cache
        ].sort_values(
            "concurrency"
        )


        if metric not in subset.columns:
            continue


        x = subset[
            "concurrency"
        ].to_numpy()


        y = subset[
            metric
        ].to_numpy()


        plt.plot(
            x,
            y,
            marker="o",
            linewidth=2,
            label=cache
        )


        std_col = (
            f"{metric}_std"
        )


        if std_col in subset.columns:

            std = (
                subset[std_col]
                .fillna(0)
                .to_numpy()
            )


            plt.fill_between(
                x,
                y - std,
                y + std,
                alpha=0.30
            )


    plt.xlabel(
        "Concurrent Connections"
    )

    plt.ylabel(
        ylabel
    )

    plt.title(
        f"{title} (Mean ± Std Dev)"
    )

    plt.grid(
        True,
        alpha=0.3
    )

    plt.legend()

    plt.tight_layout()

    plt.savefig(
        filename,
        dpi=300
    )

    plt.close()


# =====================================================
# GRÁFICOS
# =====================================================

generated_files = []


# =====================================================
# SERVER METRICS
# =====================================================

plot_metric(
    "queriesPerSecond",
    "Queries/s",
    "Throughput vs Concurrency",
    "server_throughput_vs_concurrency.png"
)

generated_files.append(
    "server_throughput_vs_concurrency.png"
)


plot_metric(
    "latency_mean_ms",
    "Mean Latency (ms)",
    "Mean Latency vs Concurrency",
    "server_latency_mean_vs_concurrency.png"
)

generated_files.append(
    "server_latency_mean_vs_concurrency.png"
)


# =====================================================
# CACHE HIT RATE
# =====================================================

plot_metric(
    "cache_hit_rate",
    "Cache Hit Rate (%)",
    "Cache Hit Rate vs Concurrency",
    "cache_hit_rate_vs_concurrency.png"
)

generated_files.append(
    "cache_hit_rate_vs_concurrency.png"
)


# =====================================================
# CACHE MISS RATE
# =====================================================

plot_metric(
    "cache_miss_rate",
    "Cache Miss Rate (%)",
    "Cache Miss Rate vs Concurrency",
    "cache_miss_rate_vs_concurrency.png"
)

generated_files.append(
    "cache_miss_rate_vs_concurrency.png"
)


# =====================================================
# CACHE MISSES ABSOLUTOS
# =====================================================

plot_metric(
    "cache_misses",
    "Cache Misses",
    "Cache Misses vs Concurrency",
    "cache_misses_vs_concurrency.png"
)

generated_files.append(
    "cache_misses_vs_concurrency.png"
)


# =====================================================
# RELATÓRIO
# =====================================================

print(
    "\nGráficos gerados:"
)

for f in generated_files:

    print(f)
