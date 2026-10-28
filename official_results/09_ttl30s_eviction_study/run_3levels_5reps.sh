#!/usr/bin/env bash
# ==============================================================================
# run_3levels_5reps.sh
#
# Bateria Oficial de Desempenho com 3 Níveis de Concorrência/Carga:
#   1. Baixa (1.000.000 QPS)
#   2. Alta (4.000.000 QPS)
#   3. Line-Rate / Saturação (0 = Ilimitado / ~7.25 MQPS)
#
# Protocolo:
#   - Modos: ates_hw_cache, ates_driver, unbound_hw_cache, unbound_standalone
#   - TTL: Distribuição empírica real (10s a 86400s)
#   - Duração: 120s por rodada
#   - Repetições: 5 independentes por configuração
#   - Total de rodadas: 4 modos x 3 taxas x 5 reps = 60 rodadas
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

MODES="ates_hw_cache ates_driver unbound_hw_cache unbound_standalone"
RATES="1000000 4000000 0"

echo "=========================================================================="
echo "🚀 INICIANDO BATERIA OFICIAL: 3 NÍVEIS DE CARGA x 4 MODOS x 5 REPS (120s)"
echo "Modos: ${MODES}"
echo "Taxas: ${RATES} (1M, 4M, Line-Rate)"
echo "Duração: ${DURATION}s por rodada | Repetições: ${REPS}"
echo "Saída Bruta: ${RAW_CSV}"
echo "Sumário Estatístico: ${SUMMARY_CSV}"
echo "=========================================================================="

"${SCRIPT_DIR}/run_ttl30s_7mqps_10reps.sh" "${MODES}" "${RATES}"

echo ""
echo "=========================================================================="
echo "🎉 BATERIA DE 60 RODADAS CONCLUÍDA COM SUCESSO!"
echo "Dados brutos: ${RAW_CSV}"
echo "Sumário final: ${SUMMARY_CSV}"
echo "=========================================================================="
