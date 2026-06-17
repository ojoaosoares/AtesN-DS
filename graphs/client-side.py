import pandas as pd
import matplotlib.pyplot as plt
import glob
import os
import re

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

        metrics[metric_name] = float(row["mean"])
        metrics[f"{metric_name}_std"] = float(row["std"])

    rows.append(metrics)

df = pd.DataFrame(rows)

print("\n=== COLUNAS DO DATAFRAME ===")
for c in sorted(df.columns):
    print(c)

print("\n=== PRIMEIRA LINHA ===")
print(df.head(1).T)

if not rows:
    raise ValueError(
        "Nenhum CSV foi carregado. Verifique se o script está na pasta correta."
    )

df = pd.DataFrame(rows)

print("\nDados carregados:")
print(df[["cache_type", "concurrency"]].sort_values("concurrency"))

df = df.sort_values(["cache_type", "concurrency"])

# =====================================================
# Throughput
# =====================================================

plt.figure(figsize=(12, 6))

for cache in df["cache_type"].unique():
    subset = df[df["cache_type"] == cache]

    plt.plot(
        subset["concurrency"],
        subset["queriesPerSecond"],
        marker="o",
        linewidth=2,
        label=cache,
    )

plt.xlabel("Concurrent Connections")
plt.ylabel("Queries/s")
plt.title("Throughput vs Concurrency")
plt.grid(True)
plt.legend()
plt.tight_layout()
plt.savefig("throughput_vs_concurrency.png", dpi=300)

# =====================================================
# Mean Latency
# =====================================================

plt.figure(figsize=(12, 6))

for cache in df["cache_type"].unique():
    subset = df[df["cache_type"] == cache]

    plt.plot(
        subset["concurrency"],
        subset["latency_mean_ms"],
        marker="o",
        linewidth=2,
        label=cache,
    )

plt.xlabel("Concurrent Connections")
plt.ylabel("Mean Latency (ms)")
plt.title("Mean Latency vs Concurrency")
plt.grid(True)
plt.legend()
plt.tight_layout()
plt.savefig("latency_mean_vs_concurrency.png", dpi=300)

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

    plt.figure(figsize=(12, 6))

    for cache in df["cache_type"].unique():
        subset = df[df["cache_type"] == cache]

        plt.plot(
            subset["concurrency"],
            subset[metric],
            marker="o",
            linewidth=2,
            label=cache,
        )

    plt.xlabel("Concurrent Connections")
    plt.ylabel("Latency (ms)")
    plt.title(metric)
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"{metric}.png", dpi=300)

# =====================================================
# Total Requests
# =====================================================

plt.figure(figsize=(12, 6))

for cache in df["cache_type"].unique():
    subset = df[df["cache_type"] == cache]

    plt.plot(
        subset["concurrency"],
        subset["totalRequests"],
        marker="o",
        linewidth=2,
        label=cache,
    )

plt.xlabel("Concurrent Connections")
plt.ylabel("Total Requests")
plt.title("Total Requests vs Concurrency")
plt.grid(True)
plt.legend()
plt.tight_layout()
plt.savefig("total_requests_vs_concurrency.png", dpi=300)

# =====================================================
# Speedup
# =====================================================

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

print(df[
    [
        "concurrency",
        "latency_p90_ms",
        "latency_p90_ms_std"
    ]
])

plt.show()




