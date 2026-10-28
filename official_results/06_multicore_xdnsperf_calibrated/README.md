# Evaluation Suite 2: Capacidade Máxima e TTL Estático (`suite2_static_ttl`)

Este diretório contém os scripts de execução, datasets de medição empírica e relatórios da **Evaluation Suite 2** do artigo ([`main.tex`](file:///home/joaosoares/Documents/Github/AtesN-DS/main.tex), Seção 4.4: *Suite 2: Upper Bound with Static Capacity*).

---

## 📄 Relatório Consolidado

- **[SUITE2_STATIC_TTL_REPORT.md](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/06_multicore_xdnsperf_calibrated/SUITE2_STATIC_TTL_REPORT.md)**: Relatório completo com tabelas consolidadas (médias e IC95%), quebra de camadas (L1/L2/L3), utilização de CPU, SoftIRQ e análise comparativa.

---

## 🚀 Scripts de Execução

1. **[`run_2core_clean_warmup_10reps.sh`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/06_multicore_xdnsperf_calibrated/run_2core_clean_warmup_10reps.sh)** — **[RUNNER OFICIAL]**
   - Executa a bateria de saturação oficial de 10 repetições de 120s por nível de taxa ($500\,\text{kQPS}, 1\,\text{MQPS}, 3\,\text{MQPS}, 5\,\text{MQPS}, \text{UNLIMITED}$) em todos os 4 modos operacionais (`ates_hw_cache`, `ates_driver`, `unbound_hw_cache`, `unbound_standalone`).
   - Realiza *clean warmup* antes de cada medição e sincroniza anéis de interface de rede.

---

## 📊 Datasets Oficiais

- **[`summary_2core_clean_warmup_10reps.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/06_multicore_xdnsperf_calibrated/summary_2core_clean_warmup_10reps.csv)**: Resumo estatístico oficial com vazão, perda, latência média, $p_{99}$, $p_{99.9}$, hit rate de HW e consumo de CPU.
- **[`raw_2core_clean_warmup_10reps.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/06_multicore_xdnsperf_calibrated/raw_2core_clean_warmup_10reps.csv)**: Dados brutos de cada repetição individual.
- **[`limits_1core_all_modes.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/06_multicore_xdnsperf_calibrated/limits_1core_all_modes.csv)**: Limites de saturação de 1 core.
- **[`limits_4cores_all_modes.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/06_multicore_xdnsperf_calibrated/limits_4cores_all_modes.csv)**: Limites de saturação de 4 cores.
- **[`client_limits_sweep.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/06_multicore_xdnsperf_calibrated/client_limits_sweep.csv)**: Caracterização de limites de transmissão do gerador de carga.

---

## 📈 Scripts de Plotagem e Exportação para o Artigo

- **[`export_paper_png.py`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/06_multicore_xdnsperf_calibrated/export_paper_png.py)**: Gera todas as figuras oficiais do artigo (barras de vazão, curvas de perda, percentis de cauda, saturação de CPU, SoftIRQ e CCDF).
- **[`plot_2core_calibrated.py`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/06_multicore_xdnsperf_calibrated/plot_2core_calibrated.py)**: Gera gráficos rápidos de calibração.
- **[`plot_comprehensive_calibrated_suite.py`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/06_multicore_xdnsperf_calibrated/plot_comprehensive_calibrated_suite.py)**: Suíte abrangente de visualização multi-métrica.
