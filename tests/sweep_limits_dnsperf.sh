#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROJECT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
cd "${PROJECT_DIR}"
BENCH_SCRIPT="${SCRIPT_DIR}/quick_bench_dnsperf.sh"

MODE="${1:-ates_driver}"
DURATION="${2:-10}"
CONCURRENCY="${3:-512}"
THREADS="${4:-8}"
MAX_OUTSTANDING="${5:-20000}"
NUM_CORES="${6:-2}"
ENABLE_GOVERNOR="${7:-${ENABLE_GOVERNOR:-1}}"

if [ "${NUM_CORES}" -eq 1 ]; then
    RATES=(200000 300000 400000 500000 0)
else
    RATES=(700000 800000 900000 1000000 0)
fi

GOV_SUFFIX="with_gov"
if [ "${ENABLE_GOVERNOR}" = "0" ] || [ "${ENABLE_GOVERNOR}" = "false" ]; then
    GOV_SUFFIX="no_gov"
fi

SWEEP_LOG="${SCRIPT_DIR}/sweep_limits_${MODE}_${NUM_CORES}core_${GOV_SUFFIX}_$(date +%Y-%m-%d_%H-%M-%S).txt"
> "${SWEEP_LOG}"

echo "=========================================================================================="
echo "🚀 INICIANDO SWEEP DE LIMITES OPEN-LOOP (DNSPERF) PARA MODO ${MODE} (${NUM_CORES} CORE)"
echo "Taxas a testar: ${RATES[*]} (0 = Unlimited / Max Line Rate)"
echo "Configuração: Servidor Cores=${NUM_CORES} | Governor=${GOV_SUFFIX} | Concorrência=${CONCURRENCY} | Threads=${THREADS} | Fila=${MAX_OUTSTANDING} | Duração=${DURATION}s"
echo "Log consolidado: ${SWEEP_LOG}"
echo "=========================================================================================="

for RATE in "${RATES[@]}"; do
    LABEL="${RATE}"
    if [ "${RATE}" -eq 0 ]; then
        LABEL="UNLIMITED"
    fi

    echo
    echo "=========================================================================================="
    echo "▶ EXECUTANDO TAXA ALVO: ${LABEL} QPS (${NUM_CORES} CORE, GOVERNOR=${GOV_SUFFIX})"
    echo "=========================================================================================="

    OUTPUT=$("${BENCH_SCRIPT}" "${MODE}" "${RATE}" "${CONCURRENCY}" "${DURATION}" 2 "${THREADS}" "${MAX_OUTSTANDING}" "${NUM_CORES}" "${ENABLE_GOVERNOR}")
    echo "${OUTPUT}"

    # Extrai a última linha de resumo do log gerado pelo quick_bench_dnsperf.sh
    LATEST_DIR=$(ls -td ${SCRIPT_DIR}/../dnsperf_data_* 2>/dev/null | head -n 1 || true)
    if [ -n "${LATEST_DIR}" ] && [ -f "${LATEST_DIR}/client/dnsperf_telemetry_summary.txt" ]; then
        RES_LINE=$(cat "${LATEST_DIR}/client/dnsperf_telemetry_summary.txt" | tail -n 1)
        echo "${LABEL}|${RES_LINE}" >> "${SWEEP_LOG}"
    fi
    sleep 2
done

echo
echo "=================================================================================================================================================="
echo "🎯 RESUMO CONSOLIDADO DO SWEEP DE LIMITES (${MODE} - DNSPERF)"
echo "=================================================================================================================================================="
printf "%-12s | %-9s | %-9s | %-8s | %-9s | %-8s | %-8s | %-12s | %-12s | %-10s | %-10s\n" \
  "ALVO(QPS)" "ENVIADOS" "RESOLVIDOS" "PERDA(%)" "QPS REAL" "MEAN(ms)" "P99(ms)" "DRIVER ANS" "SHED USR" "SRV IDLE" "MAX CORE"
echo "--------------------------------------------------------------------------------------------------------------------------------------------------"

while IFS='|' read -r lbl m_name m_sent m_ans m_lost m_lp m_qps m_mean m_min m_max m_std m_hw m_drv m_usr m_hwdom m_ubdom cl_u cl_s cl_idl cl_max cl_dr srv_u srv_s srv_soft srv_idl srv_max; do
    printf "%-12s | %-9s | %-9s | %-8s | %-9s | %-8s | %-8s | %-12s | %-12s | %-10s | %-10s\n" \
      "${lbl}" "${m_sent}" "${m_ans}" "${m_lp}%" "${m_qps}" "${m_mean}" "${m_max}ms" "${m_drv}" "${m_usr}" "${srv_idl}%" "${srv_max}%"
done < "${SWEEP_LOG}"
echo "=================================================================================================================================================="
