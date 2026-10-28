# Evaluation Suite 1: Churn Dinâmico e TTL Variável (`suite1_variable_ttl`)

Este diretório centraliza os scripts de execução, datasets de medição empírica e relatórios da **Evaluation Suite 1** do artigo ([`main.tex`](file:///home/joaosoares/Documents/Github/AtesN-DS/main.tex), Seção 4.3: *Suite 1: Dynamic TTL and Cache Churn*).

---

## 📄 Relatório Consolidado

- **[SUITE1_VARIABLE_TTL_REPORT.md](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/SUITE1_VARIABLE_TTL_REPORT.md)**: Relatório consolidado com a varredura PCIe Gen 2, tabelas de desempenho por modo e taxa, quebra de atendimento por camada (L1/L2/L3), telemetria de descartes de DMA no PCIe e consumo de CPU.

---

## 🚀 Scripts de Execução

1. **[`run_3levels_5reps.sh`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/run_3levels_5reps.sh)** — **[RUNNER OFICIAL DA VARREDURA PCIE]**
   - Executa a bateria de 4 modos (`ates_hw_cache`, `ates_driver`, `unbound_hw_cache`, `unbound_standalone`) $\times$ 4 taxas ($500\,\text{kQPS}, 1\,\text{MQPS}, 2.5\,\text{MQPS}, 4\,\text{MQPS}$) $\times$ 5 repetições (120s cada) sob a distribuição empírica de TTL variável.
2. **[`run_resume_3levels.sh`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/run_resume_3levels.sh)**
   - Script com retomada automática (continua de onde parou em caso de interrupção).
3. **[`run_second_batch_10reps.sh`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/run_second_batch_10reps.sh)**
   - Lote complementar de 10 repetições para taxas intermediárias.
4. **[`run_ttl30s_7mqps_10reps.sh`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/run_ttl30s_7mqps_10reps.sh)** / **[`run_ttl30s_7mqps_30reps.sh`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/run_ttl30s_7mqps_30reps.sh)**
   - Baterias de estresse máximo a taxa de linha sob TTL reduzido (30s).
5. **[`run_ttl30s_max_throughput_sweep.sh`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/run_ttl30s_max_throughput_sweep.sh)**
   - Varredura de ponto de inflexão de vazão máxima sob evicção ativa.

---

## 📊 Datasets Oficiais

- **[`summary_official_pcie2_sweep.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/summary_official_pcie2_sweep.csv)**: Sumário estatístico agregado com vazão, perda, latência $p_{99}$, uso de CPU e descartes de DMA no PCIe.
- **[`raw_official_pcie2_sweep.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/raw_official_pcie2_sweep.csv)**: Dados brutos das 80 execuções completas da varredura PCIe Gen 2.
- **[`summary_3levels_5reps.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/summary_3levels_5reps.csv)** / **[`raw_3levels_5reps.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/raw_3levels_5reps.csv)**: Dados das 3 taxas nominais.
- **[`summary_ttl30s_10reps.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/summary_ttl30s_10reps.csv)** / **[`raw_ttl30s_10reps.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/raw_ttl30s_10reps.csv)**: Dados de saturação a 7 MQPS com TTL 30s.

---

## 📈 Scripts de Plotagem

- **[`generate_pcie2_sweep_plots.py`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/generate_pcie2_sweep_plots.py)**: Gera as figuras oficiais da Suite 1 (vazão, perda, descarte de DMA, uso de CPU e tier breakdown L1/L2/L3).
- **[`plot_dynamic_eviction_suite.py`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/plot_dynamic_eviction_suite.py)**: Gera gráficos complementares de dinâmica de evicção multi-camada.
- **[`generate_3levels_plots.py`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/generate_3levels_plots.py)**: Visualizações rápidas para 3 níveis de carga.
- **[`generate_all_plots.py`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/generate_all_plots.py)** / **[`plot_suite_10rep_identical.py`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/plot_suite_10rep_identical.py)**: Suítes completas de visualização.
