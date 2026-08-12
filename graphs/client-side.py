import glob
import os
import re
import pandas as pd
import matplotlib.pyplot as plt

# =====================================================
# CONFIGURAÇÕES DE PLOTAGEM (ESTILO)
# =====================================================
plt.rcParams.update({
    "font.size": 26,          # Fonte padrão
    "axes.labelsize": 24,     # Labels dos eixos
    "xtick.labelsize": 22,    # Números do eixo X
    "ytick.labelsize": 22,    # Números do eixo Y
    "legend.fontsize": 22,    # Legenda
    "lines.linewidth": 2.5,
    "lines.markersize": 8,
})

# =====================================================
# LEITURA DOS DADOS
# =====================================================
rows = []
files = glob.glob("client_results_*.csv")
if not files:
    files = [f for f in glob.glob("*.csv") if "server" not in os.path.basename(f)]

for file in files:
    name = os.path.basename(file)

    if "no_hw_cache" in name:
        cache_type = "driver-mode"
    elif "hw_cache" in name:
        cache_type = "offloaded-mode"
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
            metrics[metric_name] = float(row["mean"])
            metrics[f"{metric_name}_std"] = float(row["std"])

        rows.append(metrics)
    except Exception as e:
        print(f"Erro ao processar {name}: {e}")

if not rows:
    raise ValueError(
        "Nenhum CSV foi carregado. Verifique se o script está na pasta correta."
    )

df = pd.DataFrame(rows)
df = df.sort_values(["cache_type", "concurrency"])

print("\nDados carregados:")
print(df[["cache_type", "concurrency"]].drop_duplicates())

# =====================================================
# FUNÇÃO REUTILIZÁVEL DE PLOTAGEM (COM DESVIO PADRÃO)
# =====================================================
def plot_metric(metric, ylabel, title, filename):
    plt.figure(figsize=(12, 6))

    for cache in sorted(df["cache_type"].unique()):
        subset = df[df["cache_type"] == cache].sort_values("concurrency")

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
    plt.title(f"{title} (Mean ± Std Dev)")
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(filename, dpi=300)
    plt.close()

# Lista para acompanhar arquivos gerados
generated_files = []

# =====================================================
# THROUGHPUT & LATÊNCIA MÉDIA & TOTAL REQUESTS
# =====================================================
plot_metric("queriesPerSecond", "Queries/s", "Throughput vs Concurrency", "throughput_vs_concurrency.png")
generated_files.append("throughput_vs_concurrency.png")

plot_metric("latency_mean_ms", "Mean Latency (ms)", "Mean Latency vs Concurrency", "latency_mean_vs_concurrency.png")
generated_files.append("latency_mean_vs_concurrency.png")

plot_metric("totalRequests", "Total Requests", "Total Requests vs Concurrency", "total_requests_vs_concurrency.png")
generated_files.append("total_requests_vs_concurrency.png")

# =====================================================
# PERCENTIS DE LATÊNCIA
# =====================================================
percentiles = [
    ("latency_p50_ms", "Latency P50 (ms)", "Latency P50"),
    ("latency_p75_ms", "Latency P75 (ms)", "Latency P75"),
    ("latency_p90_ms", "Latency P90 (ms)", "Latency P90"),
    ("latency_p95_ms", "Latency P95 (ms)", "Latency P95"),
    ("latency_p99_ms", "Latency P99 (ms)", "Latency P99"),
]

for metric_key, ylabel, title in percentiles:
    fname = f"{metric_key}.png"
    plot_metric(metric_key, ylabel, title, fname)
    generated_files.append(fname)

# =====================================================
# SPEEDUP (COM PROPAGAÇÃO DE INERTEZA/STD)
# =====================================================
hw = df[df["cache_type"] == "offloaded-mode"].set_index("concurrency").sort_index()
no_hw = df[df["cache_type"] == "driver-mode"].set_index("concurrency").sort_index()

common = hw.index.intersection(no_hw.index)

if not common.empty:
    y_hw = hw.loc[common, "queriesPerSecond"].to_numpy()
    y_no_hw = no_hw.loc[common, "queriesPerSecond"].to_numpy()

    speedup = y_hw / y_no_hw

    # Cálculo da incerteza do Speedup (S = A/B => std_S = S * sqrt((std_A/A)^2 + (std_B/B)^2))
    std_hw = hw.loc[common, "queriesPerSecond_std"].fillna(0).to_numpy()
    std_no_hw = no_hw.loc[common, "queriesPerSecond_std"].fillna(0).to_numpy()

    speedup_std = speedup * (
        (std_hw / y_hw) ** 2 + (std_no_hw / y_no_hw) ** 2
    ) ** 0.5

    plt.figure(figsize=(12, 6))
    plt.plot(common, speedup, marker="o", linewidth=2, label="Speedup")
    plt.fill_between(
        common,
        speedup - speedup_std,
        speedup + speedup_std,
        alpha=0.30,
    )
    plt.axhline(1.0, linestyle="--", color="gray", alpha=0.7)

    plt.xlabel("Concurrent Connections")
    plt.ylabel("Speedup")
    plt.title("Offloaded-mode Speedup vs Driver-mode (Mean ± Std Dev)")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig("speedup.png", dpi=300)
    plt.close()

    generated_files.append("speedup.png")

# =====================================================
# RELATÓRIO FINAL
# =====================================================
print("\nGráficos gerados:")
for f in generated_files:
    print(f)
