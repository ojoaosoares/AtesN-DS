#!/usr/bin/env bash
# ==============================================================================
# discover_client_limits.sh
# Sweeps target rates from 5M to 10M + UNLIMITED to discover the client's new ceiling
# and measure its exact impact on server CPU, HW offload, and latencies.
# ==============================================================================

set -euo pipefail

DURATION=15
CLIENT_MGMT_IP="150.164.2.81"
CLIENT_USER="soares"
CLIENT_IFACE="enp1s0f0"
CLIENT_XDNSPERF_DIR="/home/soares/Documentos/xdnsperf"
CLIENT_BENCH_TRACE="/home/soares/Documentos/AtesN-DS/tests/isp_queries_2m_dnsperf.txt"
SERVER_IFACE="enp1s0np1"
SERVER_IP="192.168.0.1"

RATES=(5000000 6000000 7000000 8000000 9000000 10000000 0)

OUT_CSV="/home/joaosoares/Documents/Github/AtesN-DS/official_results/06_multicore_xdnsperf_calibrated/client_limits_sweep.csv"
echo "target_qps,achieved_qps,loss_pct,lat_mean_ms,lat_p50_ms,lat_p90_ms,lat_p99_ms,hw_hits_pps,srv_c0_busy,srv_c1_busy,srv_all_busy,client_cpu_busy" > "${OUT_CSV}"

echo "=========================================================================================="
echo "🔍 VARREDURA DE LIMITES DO CLIENTE: 5M -> 10M -> UNLIMITED (${DURATION}s por degrau)"
echo "=========================================================================================="

for RATE in "${RATES[@]}"; do
    if [ "${RATE}" -eq 0 ]; then
        LABEL="UNLIMITED"
    else
        LABEL="${RATE}"
    fi

    echo "▶ Testando Taxa Alvo: ${LABEL}..."

    # Pre-test metrics
    HW_PRE=$(sudo -n ethtool -S "${SERVER_IFACE}" | awk '/bpf_app2_pkts/ {print $2; f=1} END {if(!f) print 0}')
    
    # Start server mpstat
    SRV_LOG=$(mktemp)
    LC_ALL=C mpstat -P 0,1,all 1 "${DURATION}" > "${SRV_LOG}" 2>&1 &
    SRV_PID=$!

    # Run xdnsperf on client
    CLI_RAW=$(ssh -o StrictHostKeyChecking=no "${CLIENT_USER}@${CLIENT_MGMT_IP}" "
        LC_ALL=C mpstat 1 ${DURATION} > /tmp/cli_mpstat_sweep.txt 2>&1 &
        CLI_PID=\$!
        sudo -n ${CLIENT_XDNSPERF_DIR}/bin/xdnsperf \
            -i ${CLIENT_IFACE} \
            -s ${SERVER_IP} \
            -c 6 \
            -d ${DURATION} \
            -r ${RATE} \
            -f ${CLIENT_BENCH_TRACE} \
            --ednsopt=10:11223344556677889900aabb \
            --csv
        wait \${CLI_PID} 2>/dev/null || true
        CLI_CPU=\$(awk '/^Average:/ && \$2 == \"all\" { print 100.0 - \$12 }' /tmp/cli_mpstat_sweep.txt)
        echo \"CLIENT_CPU:\${CLI_CPU}\"
    " 2>&1 || true)

    wait "${SRV_PID}" 2>/dev/null || true

    HW_POST=$(sudo -n ethtool -S "${SERVER_IFACE}" | awk '/bpf_app2_pkts/ {print $2; f=1} END {if(!f) print 0}')
    DELTA_HW=$((HW_POST - HW_PRE))
    HW_PPS=$(awk -v h="${DELTA_HW}" -v d="${DURATION}" 'BEGIN {printf "%.0f", h/d}')

    SRV_C0=$(awk '/^Average:/ && $2 == "0" { print 100.0 - $12 }' "${SRV_LOG}")
    SRV_C1=$(awk '/^Average:/ && $2 == "1" { print 100.0 - $12 }' "${SRV_LOG}")
    SRV_ALL=$(awk '/^Average:/ && $2 == "all" { print 100.0 - $12 }' "${SRV_LOG}")
    rm -f "${SRV_LOG}"

    CLIENT_CPU=$(echo "${CLI_RAW}" | grep "^CLIENT_CPU:" | head -n 1 | cut -d: -f2 | tr -d ' \r')
    [ -z "${CLIENT_CPU}" ] && CLIENT_CPU="0.00"

    CSV_LINE=$(echo "${CLI_RAW}" | grep "^CSV:" | head -n 1 | sed 's/^CSV://')
    if [ -n "${CSV_LINE}" ]; then
        IFS=',' read -r tot_req tot_ans qps lat_mean lat_p50 lat_p75 lat_p90 lat_p95 lat_p99 lat_p99_9 lat_min lat_max lat_std loss_pct loss_cnt trgt <<< "${CSV_LINE}"
        echo "${LABEL},${qps},${loss_pct},${lat_mean},${lat_p50},${lat_p90},${lat_p99},${HW_PPS},${SRV_C0},${SRV_C1},${SRV_ALL},${CLIENT_CPU}" >> "${OUT_CSV}"
        printf "   -> Entregue: %'d QPS | Perda: %s%% | Lat_p99: %sms | SmartNIC HW: %'d PPS | Srv_Cores: %.1f%%/%.1f%% | Cli_CPU: %s%%\n" \
            "${qps}" "${loss_pct}" "${lat_p99}" "${HW_PPS}" "${SRV_C0}" "${SRV_C1}" "${CLIENT_CPU}"
    else
        echo "   [ERRO] xdnsperf falhou nesta taxa. Output:"
        echo "${CLI_RAW}" | tail -n 5
    fi
    sleep 2
done

echo "=========================================================================================="
echo "✅ VARREDURA CONCLUÍDA! Tabela salva em: ${OUT_CSV}"
echo "=========================================================================================="
