# Diretório Oficial de Resultados Experimentais (`official_results/`)

Este diretório centraliza **exclusivamente medições empíricas reais**, scripts de execução de bancada física, datasets brutos (CSV), relatórios técnicos consolidados e figuras vetoriais integradas ao artigo ([`main.tex`](file:///home/joaosoares/Documents/Github/AtesN-DS/main.tex)).

---

## 🎯 Suítes Principais do Artigo

O manuscrito organiza a avaliação experimental em duas grandes baterias complementares (Seções 4.3 e 4.4 de [`main.tex`](file:///home/joaosoares/Documents/Github/AtesN-DS/main.tex)):

### 1. [Evaluation Suite 1: Churn Dinâmico e TTL Variável](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/README.md)
*Diretório:* [`official_results/suite1_variable_ttl/`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/) (alias para [`09_ttl30s_eviction_study/`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/))  
*Seção do Artigo:* Seção 4.3 (*Suite 1: Dynamic TTL and Cache Churn*)  
*Relatório Consolidado:* **[`SUITE1_VARIABLE_TTL_REPORT.md`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/SUITE1_VARIABLE_TTL_REPORT.md)**  
*Objetivo:* Avaliar a resiliência do sistema e o comportamento do barramento PCIe sob **expirações contínuas de TTL e churn dinâmico de cache**.
- **Carga de Trabalho:** 2.000.000 consultas do trace de ISP sob distribuição empírica real de TTL (Tabela 1: 60s dominante para 62,70%, 30s para 22,68%, 10s para 7,69%).
- **Topologia de Barramento:** Slot PCIe Gen 2 ($5.0\,\text{GT/s} \times 8 = 32\,\text{Gbps}$ / $4.0\,\text{GB/s}$) com 4 filas de hardware ativas.
- **Resultados Chave:**
  - `ates_hw_cache` sustenta **3,75 MQPS** com **0,15% de perda** (ou 0,026% na faixa de operação) e atende **50,65% das queries diretamente em silício**.
  - Libera **84,3% dos ciclos de CPU dedicada do Host** (consumo de apenas 22,8% vs 38,5% do driver e 44,9% do Unbound HW).
  - Elimina completamente descartes de DMA no PCIe (`nic_rx_discards` = 0 de 500k a 2.5M QPS, e apenas 1.636 a 4.0 MQPS vs 187 milhões no `unbound_hw_cache`).
  - Reduz $p_{50}$ em 22,9% (3,37 ms), $p_{90}$ em 15,4% (5,23 ms) e $p_{99}$ em 15,2% (5,65 ms).

---

### 2. [Evaluation Suite 2: Capacidade Máxima e TTL Estático](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/06_multicore_xdnsperf_calibrated/README.md)
*Diretório:* [`official_results/suite2_static_ttl/`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/06_multicore_xdnsperf_calibrated/) (alias para [`06_multicore_xdnsperf_calibrated/`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/06_multicore_xdnsperf_calibrated/))  
*Seção do Artigo:* Seção 4.4 (*Suite 2: Upper Bound with Static Capacity*)  
*Relatório Consolidado:* **[`SUITE2_STATIC_TTL_REPORT.md`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/06_multicore_xdnsperf_calibrated/SUITE2_STATIC_TTL_REPORT.md)**  
*Objetivo:* Estabelecer o **limite físico de taxa de linha (10GbE wire-speed)** e latência de piso sob regime estático de retenção ($\text{TTL} = 3.600\,\text{s}$).
- **Carga de Trabalho:** Todas as 32.768 entradas da SmartNIC e 83.659 entradas do host pré-carregadas. Retenção de HW de $\approx 96,34\%$ a $98,07\%$.
- **Resultados Chave:**
  - Saturação de linha a **7,66 MQPS** com **0,17% de perda** (aceleração de **$1,70\times$** sobre o driver em kernel e **$60\times$** sobre o Unbound standalone).
  - Redução de **85,8%** no uso de CPU dedicada (de 98,9% para 14,0%) e de **88,1%** em SoftIRQ (de 49,5% para 5,9%), deixando o host **86% ocioso**.
  - Redução de **52,4%** no $p_{99}$ (2,81 ms vs 5,91 ms) e compressão de **76,7%** na dispersão estocástica ($p_{99.9} - p_{99} = 22,5\,\mu\text{s}$).

---

## 🔬 Suítes Experimentais Complementares

| Diretório | Descrição | Status no Artigo | Datasets Principais |
| :--- | :--- | :---: | :--- |
| **[`01_trace_analysis/`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/01_trace_analysis/ANALYSIS.md)** | Caracterização de wire-format RFC 1035 dos traces de ISP e Campus | Concluído (Seção 4.1) | [`trace_summary_metrics.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/01_trace_analysis/trace_summary_metrics.csv), [`trace_wire_length_cdf.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/01_trace_analysis/trace_wire_length_cdf.csv) |
| **`02_cleaner_daemon/`** | Sobrecarga de CPU e taxa de acesso a mapas do Time Updater e Cleaner Daemon ($n=30$) | Concluído (Seção 4.5, Tabela 4) | [`data/daemons_statistical_30_runs.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/data/daemons_statistical_30_runs.csv) |
| **[`04_overload_fallback_study/`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/04_overload_fallback_study/run_fallback_study.sh)** | Penalidade de latência de fallback sob regime de sobrecarga | Concluído (Seção 4.5) | [`summary_fallback_penalty.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/04_overload_fallback_study/summary_fallback_penalty.csv) |
| **[`07_single_core_max_throughput/`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/07_single_core_max_throughput/run_1core_clean_warmup_10reps.sh)** | Limite de escalabilidade e capacidade máxima em configuração de 1 único núcleo | Concluído | [`summary_1core_clean_warmup_10reps.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/07_single_core_max_throughput/summary_1core_clean_warmup_10reps.csv) |
| **[`08_closed_loop_dnspyre/`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/08_closed_loop_dnspyre/run_closed_loop_dnspyre_10reps.sh)** | Medições em malha fechada via `dnspyre` avaliando latência sem perdas e saturação | Concluído | [`summary_closed_loop_dnspyre_10reps.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/08_closed_loop_dnspyre/summary_closed_loop_dnspyre_10reps.csv) |

---

## 🛠️ Scripts Auxiliares de Bancada

Consulte o diretório [`scripts/`](file:///home/joaosoares/Documents/Github/AtesN-DS/scripts/README.md) para detalhes sobre geradores de jitter, pré-carregadores de cache determinísticos e parsers de telemetria.
