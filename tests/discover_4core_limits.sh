#!/usr/bin/env bash
# ==============================================================================
# discover_4core_limits.sh
# Tests and discovers the saturation ceiling of all 4 architectures using 4 CPUs:
#   1. unbound_standalone (4 CPUs)
#   2. unbound_hw_cache   (4 CPUs)
#   3. ates_driver        (4 CPUs)
#   4. ates_hw_cache      (4 CPUs)
# ==============================================================================

set -euo pipefail

DURATION=10
CLIENT_MGMT_IP="150.164.2.81"
CLIENT_USER="soares"
CLIENT_IFACE="enp1s0f0"
CLIENT_XDNSPERF_DIR="/home/soares/Documentos/xdnsperf"
CLIENT_BENCH_TRACE="/home/soares/Documentos/AtesN-DS/tests/isp_queries_2m_dnsperf.txt"
SERVER_BASE_DIR="/home/joaosoares/Documents/Github/AtesN-DS"
SERVER_IFACE="enp1s0np1"
SERVER_IP="192.168.0.1"
CLIENT_IP="192.168.0.2"
CLIENT_MAC="3c:fd:fe:03:02:00"

OUT_CSV="${SERVER_BASE_DIR}/official_results/06_multicore_xdnsperf_calibrated/limits_4cores_all_modes.csv"
echo "mode,target_qps,achieved_qps,loss_pct,lat_mean_ms,lat_p99_ms,hw_pps,srv_c0,srv_c1,srv_c2,srv_c3,srv_all,softirq,cli_cpu" > "${OUT_CSV}"

# Configure 4 hardware IRQs to 4 Cores on server
sudo -n ethtool -L "${SERVER_IFACE}" combined 4 >/dev/null 2>&1 || true
RXTX_IRQS=($(grep "${SERVER_IFACE}-rxtx-" /proc/interrupts | awk -F: '{print $1}' | tr -d ' '))
for q in "${!RXTX_IRQS[@]}"; do
    irq="${RXTX_IRQS[$q]}"
    core=$((q % 4))
    mask=$((1 << core))
    printf "%x" "${mask}" | sudo -n tee "/proc/irq/${irq}/smp_affinity" >/dev/null
done

test_round() {
    local MODE="$1"
    local RATE="$2"
    local LABEL="${RATE}"
    [ "${RATE}" -eq 0 ] && LABEL="UNLIMITED"

    HW_PRE=$(sudo -n ethtool -S "${SERVER_IFACE}" | awk '/bpf_app2_pkts/ {print $2; f=1} END {if(!f) print 0}')
    
    SRV_LOG=$(mktemp)
    LC_ALL=C mpstat -P 0,1,2,3,all 1 "${DURATION}" > "${SRV_LOG}" 2>&1 &
    SRV_PID=$!

    CLI_RAW=$(ssh -o StrictHostKeyChecking=no "${CLIENT_USER}@${CLIENT_MGMT_IP}" "
        LC_ALL=C mpstat 1 ${DURATION} > /tmp/cli_mpstat_4c.txt 2>&1 &
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
        CLI_CPU=\$(awk '/^Average:/ && \$2 == \"all\" { print 100.0 - \$12 }' /tmp/cli_mpstat_4c.txt)
        echo \"CLIENT_CPU:\${CLI_CPU}\"
    " 2>&1 || true)

    wait "${SRV_PID}" 2>/dev/null || true

    HW_POST=$(sudo -n ethtool -S "${SERVER_IFACE}" | awk '/bpf_app2_pkts/ {print $2; f=1} END {if(!f) print 0}')
    DELTA_HW=$((HW_POST - HW_PRE)); [ "${DELTA_HW}" -lt 0 ] && DELTA_HW=0
    HW_PPS=$(awk -v h="${DELTA_HW}" -v d="${DURATION}" 'BEGIN {printf "%.0f", h/d}')

    C0=$(awk '/^Average:/ && $2 == "0" { print 100.0 - $12 }' "${SRV_LOG}")
    C1=$(awk '/^Average:/ && $2 == "1" { print 100.0 - $12 }' "${SRV_LOG}")
    C2=$(awk '/^Average:/ && $2 == "2" { print 100.0 - $12 }' "${SRV_LOG}")
    C3=$(awk '/^Average:/ && $2 == "3" { print 100.0 - $12 }' "${SRV_LOG}")
    ALL=$(awk '/^Average:/ && $2 == "all" { print 100.0 - $12 }' "${SRV_LOG}")
    SOFT=$(awk '/^Average:/ && $2 == "all" { print $8 }' "${SRV_LOG}")
    rm -f "${SRV_LOG}"

    CLI_CPU=$(echo "${CLI_RAW}" | grep "^CLIENT_CPU:" | head -n 1 | cut -d: -f2 | tr -d ' \r')
    [ -z "${CLI_CPU}" ] && CLI_CPU="0.00"

    CSV_LINE=$(echo "${CLI_RAW}" | grep "^CSV:" | head -n 1 | sed 's/^CSV://')
    if [ -n "${CSV_LINE}" ]; then
        IFS=',' read -r tot_req tot_ans qps lat_mean lat_p50 lat_p75 lat_p90 lat_p95 lat_p99 lat_p99_9 lat_min lat_max lat_std loss_pct loss_cnt trgt <<< "${CSV_LINE}"
        echo "${MODE},${LABEL},${qps},${loss_pct},${lat_mean},${lat_p99},${HW_PPS},${C0},${C1},${C2},${C3},${ALL},${SOFT},${CLI_CPU}" >> "${OUT_CSV}"
        printf "   -> Target: %9s | Achieved: %'9d QPS | Loss: %5.2f%% | Lat_p99: %6.3fms | HW_PPS: %'9d | Cores(0-3): %.1f/%.1f/%.1f/%.1f | All: %.1f%%\n" \
            "${LABEL}" "${qps}" "${loss_pct}" "${lat_p99}" "${HW_PPS}" "${C0}" "${C1}" "${C2}" "${C3}" "${ALL}"
    else
        echo "   [ERRO] falha nesta taxa."
    fi
    sleep 1
}

# ==============================================================================
# 1. TEST MODE: unbound_standalone (4 CPUs)
# ==============================================================================
echo "=========================================================================================="
echo "▶ MODO 1/4: unbound_standalone (4 CPUs)"
echo "=========================================================================================="
sudo -n bpftool net detach xdpoffload dev "${SERVER_IFACE}" 2>/dev/null || true
sudo -n ip link set dev "${SERVER_IFACE}" xdp off 2>/dev/null || true
sudo -n pkill -9 -x "atesnds|atesnds_daemon|dns_listener" 2>/dev/null || true
sudo -n systemctl restart unbound
pgrep -x unbound | xargs -r -n1 sudo taskset -acp 0,1,2,3 >/dev/null 2>&1 || true
"${SERVER_BASE_DIR}/scripts/preload_unbound.sh" >/dev/null 2>&1
sleep 1

for R in 100000 200000 400000 600000 800000 1000000; do
    test_round "unbound_standalone" "${R}"
done

# ==============================================================================
# 2. TEST MODE: unbound_hw_cache (4 CPUs)
# ==============================================================================
echo "=========================================================================================="
echo "▶ MODO 2/4: unbound_hw_cache (4 CPUs)"
echo "=========================================================================================="
sudo -n bpftool net attach xdpoffload pinned /sys/fs/bpf/xdp_prog dev "${SERVER_IFACE}" 2>/dev/null || true
sudo -n ip link set dev "${SERVER_IFACE}" xdp off 2>/dev/null || true
sudo -n pkill -9 -x "atesnds|atesnds_daemon|dns_listener" 2>/dev/null || true
nohup sudo -n taskset -c 0,1,2,3 "${SERVER_BASE_DIR}/bin/dns_listener" -i "${SERVER_IFACE}" >/dev/null 2>&1 &
nohup sudo -n taskset -c 0,1,2,3 "${SERVER_BASE_DIR}/bin/atesnds_daemon" >/dev/null 2>&1 &
sudo -n systemctl restart unbound
pgrep -x unbound | xargs -r -n1 sudo taskset -acp 0,1,2,3 >/dev/null 2>&1 || true
"${SERVER_BASE_DIR}/scripts/preload_unbound.sh" >/dev/null 2>&1
"${SERVER_BASE_DIR}/scripts/preload_hw.sh" >/dev/null 2>&1
sleep 2

for R in 3000000 5000000 7000000 0; do
    test_round "unbound_hw_cache" "${R}"
done

# ==============================================================================
# 3. TEST MODE: ates_driver (4 CPUs)
# ==============================================================================
echo "=========================================================================================="
echo "▶ MODO 3/4: ates_driver (4 CPUs)"
echo "=========================================================================================="
sudo -n bpftool net detach xdpoffload dev "${SERVER_IFACE}" 2>/dev/null || true
sudo -n pkill -9 -x "atesnds|atesnds_daemon|dns_listener" 2>/dev/null || true
nohup sudo -n taskset -c 0,1,2,3 "${SERVER_BASE_DIR}/bin/atesnds" -a "${SERVER_IP}" -i "${SERVER_IFACE}" -m "${CLIENT_MAC}" -s "${CLIENT_IP}" >/dev/null 2>&1 &
sleep 2
sudo -n python3 "${SERVER_BASE_DIR}/tests/manage_overload.py" normal >/dev/null 2>&1 || true
sudo -n systemctl restart unbound
pgrep -x unbound | xargs -r -n1 sudo taskset -acp 0,1,2,3 >/dev/null 2>&1 || true
"${SERVER_BASE_DIR}/scripts/preload_unbound.sh" >/dev/null 2>&1
"${SERVER_BASE_DIR}/scripts/preload_driver.sh" >/dev/null 2>&1
sleep 2

for R in 3000000 5000000 6000000 7000000 8000000 0; do
    test_round "ates_driver" "${R}"
done

# ==============================================================================
# 4. TEST MODE: ates_hw_cache (4 CPUs)
# ==============================================================================
echo "=========================================================================================="
echo "▶ MODO 4/4: ates_hw_cache (4 CPUs)"
echo "=========================================================================================="
sudo -n bpftool net attach xdpoffload pinned /sys/fs/bpf/xdp_prog dev "${SERVER_IFACE}" 2>/dev/null || true
sudo -n pkill -9 -x "atesnds|atesnds_daemon|dns_listener" 2>/dev/null || true
nohup sudo -n taskset -c 0,1,2,3 "${SERVER_BASE_DIR}/bin/atesnds" -a "${SERVER_IP}" -i "${SERVER_IFACE}" -m "${CLIENT_MAC}" -s "${CLIENT_IP}" >/dev/null 2>&1 &
nohup sudo -n taskset -c 0,1,2,3 "${SERVER_BASE_DIR}/bin/atesnds_daemon" >/dev/null 2>&1 &
sleep 2
sudo -n python3 "${SERVER_BASE_DIR}/tests/manage_overload.py" normal >/dev/null 2>&1 || true
sudo -n systemctl restart unbound
pgrep -x unbound | xargs -r -n1 sudo taskset -acp 0,1,2,3 >/dev/null 2>&1 || true
"${SERVER_BASE_DIR}/scripts/preload_unbound.sh" >/dev/null 2>&1
"${SERVER_BASE_DIR}/scripts/preload_driver.sh" >/dev/null 2>&1
"${SERVER_BASE_DIR}/scripts/preload_hw.sh" >/dev/null 2>&1
sleep 2

for R in 3000000 5000000 7000000 0; do
    test_round "ates_hw_cache" "${R}"
done

echo "=========================================================================================="
echo "✅ VARREDURA DE TODOS OS 4 MODOS EM 4 CPUS CONCLUÍDA!"
echo "Resultados em: ${OUT_CSV}"
echo "=========================================================================================="
