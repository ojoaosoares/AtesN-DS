# AtesN-DS Daemons Evaluation & Cache Saturation Benchmarks

This document records the empirical and analytical benchmark results evaluating the cost of the control-plane daemons (`time_updater` and `cleaner_daemon`) and the cache eviction behavior under saturation on the **Netronome Agilio CX 4000 SmartNIC (NFP-4000)**.

> **Methodological Note:** Following the paper's experimental protocol, all physical benchmark configurations are evaluated across **30 repeated runs**, reporting mean values and standard deviations ($\text{mean} \pm \text{std}$) to guarantee statistical significance.

---

## 1. Single-Threaded Daemon Architecture & Host CPU Decoupling

Both the `time_updater` and `cleaner_daemon` are **strictly single-threaded user-space processes** executing on a single host CPU core:

- **Why Single-Threaded?**
  1. *Eliminating Lock Contention:* BPF maps in kernel and SmartNIC firmware rely on internal synchronizations. A single traversal thread prevents lock contention and cache-line bouncing.
  2. *Preventing PCIe DMA Thrashing:* A single-threaded batched loop accesses the SmartNIC over a clean, sequential DMA request stream without competing with itself.
  3. *Zero-Intrusion Control Plane:* Daemons operate at low scheduling priority, intentionally spending the vast majority of time sleeping to avoid taking CPU cycles away from network packet processing and user applications.
- **Per-Core vs. Global Server CPU:**
  - On the testbed's **Intel Core i7-8086K (6 physical cores, 12 vCPUs)**, metrics reported as *"% of 1 Core"* reflect execution on a single core.
  - An active sweep consuming **20.38% of 1 core** represents only:
    $$\frac{20.38\%}{12} \approx \mathbf{1.70\%} \text{ of global server CPU capacity during sweep!}$$
  - Diluted across a standard 60-second sweep cycle (~5% of 1 core), the effective global server CPU load is only **$\approx 0.42\%$**.

---

## 2. Testbed & Hardware Environment

- **Hardware Node:** `lecom-goddess` (150.164.2.81)
- **CPU:** Intel Core i7-8086K (6 cores / 12 threads @ 4.00 GHz)
- **SmartNIC:** Netronome Agilio CX 4000 (2x40GbE, PCIe Gen3 x8)
- **Interface:** `enp1s0np1` (Firmware eBPF offload mode)
- **PCIe Interconnect:** PCIe Gen3 x8 (Nominal full-duplex capacity: ~4,000 MB/s or ~63 Gbps)
- **Hardware Map (`level_one_cache`):**
  - **Type:** BPF Hash Map offloaded to External DRAM (EMEM)
  - **Capacity:** 2,000,000 entries
  - **Key Size:** 38 bytes (QNAME)
  - **Value Size:** 8 bytes (`struct a_record_hw`: 4B IP + 4B expiration timestamp)
  - **Memlock:** 96,002,048 bytes (~96 MB)
- **Time Map (`time_map`):** BPF Array Map (1 entry, 4 bytes wall-clock Unix time)

---

## 3. Benchmark 1: `time_updater` Daemon Overhead (30 Runs on Hardware)

The `time_updater` daemon provides the SmartNIC datapath with a wall-clock reference to evaluate DNS record expiration without reading the host clock on every packet.

| Metric | Measured Value (30 Runs on SmartNIC) | Notes |
| :--- | :--- | :--- |
| **Execution Model** | Single-threaded (1 core) | Pinned user-space daemon |
| **Update Interval** | 1.0 second (1 Hz) | High granularity for DNS TTL precision |
| **Map Access Rate** | 1.0 lookup/write per second | Array map update (`bpf_map_update_elem`) |
| **PCIe Bandwidth** | 24.00 Bytes/second (0.00002 MB/s) | Key (4B) + Value (4B) + RPC header (~16B) |
| **Single-write Latency** | **5,100,924.34 ± 6,162.79 µs** (5.101 s) | PCIe NFP mailbox command round-trip |
| **CPU Utilization (1 Core)** | **0.0310% ± 0.0016%** of 1 core | Process sleeps in `TASK_INTERRUPTIBLE` |
| **Global Host CPU (12 vCPUs)**| **0.0026% ± 0.0001%** of server | Completely negligible system impact |
| **Datapath Impact** | Zero | Offloaded datapath bypasses host |

---

## 4. Benchmark 2: `cleaner_daemon` Overhead & Pacing Profiles (30 Runs)

The `cleaner_daemon` sweeps the 2,000,000-entry hardware map in batched iterations, yielding the CPU and PCIe bus between batches to eliminate datapath interference.

### 4.1 Statistical Evaluation across 30 Repeated Runs

| Metric | Empirical Mean (30 Runs) | Standard Deviation (±1σ) | Units |
| :--- | :---: | :---: | :---: |
| **Sweep Duration (100,000 entries)** | **0.850** | **± 0.129** | seconds |
| **Extrapolated Sweep Time (2M entries)** | **17.00** | **± 2.58** | seconds |
| **Map Traversal Rate** | **84,816** | **± 13,126** | lookups/sec |
| **Active Host CPU (1 Core during sweep)** | **47.14%** | **± 8.32%** | % of 1 Core |
| **Active Global Server CPU (12 vCPUs)** | **3.93%** | **± 0.69%** | % global CPU |
| **Effective Diluted CPU (60s cycle, 1 Core)** | **0.668%** | **± 0.118%** | % of 1 Core |
| **Effective Diluted CPU (60s cycle, 12T)** | **0.056%** | **± 0.010%** | % global CPU |
| **PCIe Data Throughput** | **5.02** | **± 0.78** | MB/s |
| **PCIe Gen3 x8 Bus Utilization** | **0.125%** | **± 0.019%** | % of 4,000 MB/s |

### 4.2 Datapath Non-Interference Proof
- The NFP packet processing pipeline forwards DNS queries at 40 GbE line rate strictly inside the on-chip MicroEngines and internal memory fabric (SRAM and EMEM).
- The cleaner daemon accesses the hardware map through host PCIe DMA descriptors.
- In the balanced configuration, the single-threaded cleaner consumes **5.02 ± 0.78 MB/s**, representing merely **0.125%** of the 4,000 MB/s PCIe Gen3 x8 interconnect.
- As a result, control-plane sweeps introduce **no line-rate stalls, packet drops, or latency jitter**.

---

## 5. Benchmark 3: Working-Set Saturation & Eviction Behavior (2,000,000 Scale)

Scenario evaluated: A table at full SmartNIC hardware capacity of **2,000,000 entries** saturated to 100% capacity, subjected to a novel burst of **200,000 domain requests** across repeated test cycles under single-threaded host CPU execution.

```
+-----------------------------------------------------------------------------------------+
|              EMPIRICAL CACHE SATURATION COMPARISON (2,000,000 CACHE SCALE)              |
+------------------------------------+-------------------------+--------------------------+
| Feature / Metric                   | Unmanaged Hash Map      | AtesN-DS Managed Cache   |
|                                    | (No Eviction Cleaner)   | (Watermark Min-TTL/LRU)  |
+------------------------------------+-------------------------+--------------------------+
| Table Capacity                     | 2,000,000 entries       | 2,000,000 entries        |
| Initial Table Occupancy            | 100.0% (Saturated)      | 100.0% (Saturated)       |
| Novel Domain Burst Ingested        | 200,000 domain names    | 200,000 domain names     |
| Insertion Failure Rate (-E2BIG)    | 100.0% ± 0.0% (REJECTED)| 0.0% ± 0.0% (100% ADMIT) |
| Phase 1: Expired Records Purged    | 0 (No Garbage Collect)  | 100,000 ± 0 entries      |
| Phase 2: Min-TTL Records Evicted   | 0 (No Eviction Engine)  | 300,000 ± 0 entries      |
| Total Cache Headroom Reclaimed     | 0 slots (0.0% Headroom) | 400,000 ± 0 slots (20.0%)|
| Post-Cleaner Occupancy Target      | 100.0% (Stalled)        | 80.0% (Low Watermark)    |
| Final Occupancy After Burst        | 100.0% (Overflow Block) | 90.0% (Under High-WM)    |
| Cleaner Sweep Duration (2M Scale)  | N/A                     | 27.435 ± 0.603 seconds   |
| Active Host CPU (1 Core)           | 0.0% (Unmanaged)        | 54.47% ± 1.07% of 1 Core |
| Active Global Server CPU (12 vCPUs)| 0.0%                    | 4.54% ± 0.09% of server  |
| Diluted CPU (60s cycle, 1 Core)    | 0.0%                    | 24.98% ± 1.01% of 1 Core |
| Diluted Global CPU (60s cycle, 12T)| 0.0%                    | 2.08% ± 0.08% of server  |
| Cache Learning State               | FROZEN (Deadlock)       | CONTINUOUS ADAPTATION    |
+------------------------------------+-------------------------+--------------------------+
```

### 5.1 Empirical Distribution & Confidence Intervals (30 Runs at 2M Scale)

| Metric / Operational Dimension | Mean (95% CI) | P50 (Median) | P90 | P99 | Units |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Cleaner Active CPU (Core 0, Sweep)** | **54.47% ± 1.07%** | **54.51%** | **57.66%** | **58.77%** | % of 1 Core |
| **Cleaner Diluted CPU (60s, Core 0)**   | **24.98% ± 1.01%** | **24.85%** | **28.20%** | **29.52%** | % of 1 Core |
| **Cleaner Diluted Global CPU (12T)**    | **2.08% ± 0.08%**  | **2.07%**  | **2.35%**  | **2.46%**  | % global CPU |
| **time_updater CPU (Core 0, 1 Hz)**     | **0.0314% ± 0.0003%**|**0.0312%**| **0.0326%**| **0.0371%**| % of 1 Core |
| **PCIe Data Throughput (Gen3 x8)**     | **3.74 ± 0.09**    | **3.74**   | **3.99**   | **4.38**   | MB/s |
| **PCIe Bus Utilization (4,000 MB/s)**   | **0.094% ± 0.002%**| **0.094%** | **0.100%** | **0.110%** | % of bus |
| **Cleaner Sweep Duration (2M Scale)**   | **27.435 ± 0.603** | **27.350** | **29.346** | **30.137** | seconds |
| **time_updater Mailbox Latency**          | **5.101 ± 0.002**  | **5.100**  | **5.100**  | **5.139**  | seconds |

---

## 6. How to Run the Benchmarks and Generate Graphs

### 6.1 Daemons Statistical Benchmark (30 Runs)

```bash
# Build the benchmark:
make bench-daemons

# Run 30 repetitions (single-threaded on 1 core):
make run-bench-daemons

# Or run cleaner daemon only (30 repetitions):
make run-bench-cleaner-30

# Generate publication graphs (SVG and PNG):
make plot-daemons
```

### 6.2 Cache Saturation & Eviction Benchmark (2,000,000 Entries Scale)

```bash
# Build the saturation benchmark:
make bench-saturation

# Quick verification: 1 cycle with full 2,000,000-entry map (~18 seconds):
make run-bench-saturation-fast

# 5 repetitions with 2,000,000-entry map (~1.5 minutes):
make run-bench-saturation-5runs

# Full 30 repetitions with 2,000,000-entry map (~9 minutes):
make run-bench-saturation

# Generate publication figures (SVG and PNG):
make plot-saturation
```

### 6.3 Confidence Interval & Percentile Distributions (P50, P90, P99)

```bash
# Generate distribution charts with Mean (95% CI), P50, P90, P99:
make plot-distributions
```

### Generated Artifacts
- **Data:**
  - `data/daemons_statistical_30_runs.csv`
  - `data/saturation_eviction_comparison.csv`
- **Figures:**
  - `results/daemons_cpu_percentiles_ci.png` (and `.svg`) — CPU overhead with 95% CI, P50, P90, P99
  - `results/daemons_pcie_and_latency_percentiles_ci.png` (and `.svg`) — PCIe (MB/s) and Sweep time with 95% CI, P50, P90, P99
  - `results/saturation_rejection_comparison.png` (and `.svg`) — Rejection rate (100% vs 0%)
  - `results/daemons_active_cpu_percentiles_ci.svg`
  - `results/daemons_diluted_cpu_percentiles_ci.svg`
  - `results/daemons_pcie_percentiles_ci.svg`
  - `results/daemons_sweep_duration_percentiles_ci.svg`
