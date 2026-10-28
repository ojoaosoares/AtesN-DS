#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAW_CSV="${SCRIPT_DIR}/raw_official_pcie2_sweep.csv"
SUMMARY_CSV="${SCRIPT_DIR}/summary_official_pcie2_sweep.csv"
export RAW_CSV SUMMARY_CSV

echo "=========================================================================="
echo "🚀 INICIANDO SEGUNDA BATERIA PARA COMPLETAR 10 REPETIÇÕES (PCIE GEN 2)"
echo "=========================================================================="

echo "-> [ETAPA 1/3] Finalizando rodadas 4 e 5 de unbound_standalone 500k..."
NUM_CORES=2 SERVER_CORES='0,1' SERVER_TASKSET='0,1' NUM_QUEUES=4 DURATION=120 START_REP=4 REPS=2 \
    "${SCRIPT_DIR}/run_ttl30s_7mqps_10reps.sh" "unbound_standalone" "500000"

echo ""
echo "-> [ETAPA 2/3] Executando rodadas 6 a 10 (4 modos x 4 taxas x 5 reps = 80 testes)..."
NUM_CORES=2 SERVER_CORES='0,1' SERVER_TASKSET='0,1' NUM_QUEUES=4 DURATION=120 START_REP=6 REPS=5 \
    "${SCRIPT_DIR}/run_ttl30s_7mqps_10reps.sh" "ates_hw_cache ates_driver unbound_hw_cache unbound_standalone" "4000000 2500000 1000000 500000"

echo ""
echo "-> [ETAPA 3/3] Regenerando todos os gráficos oficiais de 10 repetições..."
python3 "${SCRIPT_DIR}/generate_all_plots.py"
python3 "${SCRIPT_DIR}/plot_suite_10rep_identical.py"

echo ""
echo "=========================================================================="
echo "🎉 BATERIA DE 10 REPETIÇÕES E TODOS OS GRÁFICOS CONCLUÍDOS COM SUCESSO!"
echo "Dados brutos: ${RAW_CSV}"
echo "Sumário final: ${SUMMARY_CSV}"
echo "Gráficos em: ${SCRIPT_DIR}/plots_pcie2_sweep"
echo "=========================================================================="
