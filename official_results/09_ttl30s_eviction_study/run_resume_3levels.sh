#!/usr/bin/env bash
# ==============================================================================
# run_resume_3levels.sh
# Retomada da Bateria Oficial de 3 Níveis x 4 Modos x 5 Reps (120s)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_BASE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

export NUM_CORES=2
export SERVER_CORES='0,1'
export SERVER_TASKSET='0,1'
export NUM_QUEUES=4
export DURATION=120
export START_REP=1
export REPS=5

export RAW_CSV="${SCRIPT_DIR}/raw_3levels_5reps.csv"
export SUMMARY_CSV="${SCRIPT_DIR}/summary_3levels_5reps.csv"

# Backup e preservação dos 5 runs limpos de ates_hw_cache @ 1MQPS
cp -f "${RAW_CSV}" "${RAW_CSV}.bak"
head -n 6 "${RAW_CSV}.bak" > "${RAW_CSV}"

echo "=========================================================================="
echo "🚀 RETOMANDO BATERIA OFICIAL (120s por repetição)"
echo "1. Completando ates_hw_cache (4 MQPS e Line-Rate)"
echo "2. Executando ates_driver, unbound_hw_cache e unbound_standalone (1M, 4M, Line-Rate)"
echo "Pinning do cliente ativo em taskset -c 0,1,2,3,4,5"
echo "Saída bruta: ${RAW_CSV}"
echo "=========================================================================="

echo ""
echo ">>> FASE 1: ates_hw_cache (4.000.000 QPS e Line-Rate 0) <<<"
"${SCRIPT_DIR}/run_ttl30s_7mqps_10reps.sh" "ates_hw_cache" "4000000 0"

echo ""
echo ">>> FASE 2: ates_driver, unbound_hw_cache, unbound_standalone (1M, 4M, Line-Rate) <<<"
"${SCRIPT_DIR}/run_ttl30s_7mqps_10reps.sh" "ates_driver unbound_hw_cache unbound_standalone" "1000000 4000000 0"

echo ""
echo "=========================================================================="
echo "🎉 TODAS AS 60 RODADAS CONCLUÍDAS COM SUCESSO!"
echo "=========================================================================="
