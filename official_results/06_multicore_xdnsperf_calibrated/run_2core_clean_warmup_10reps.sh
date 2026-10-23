#!/usr/bin/env bash
# ==============================================================================
# run_2core_clean_warmup_10reps.sh
#
# Benchmark Suite with Strict Per-Round Cache Flush, Cooldown & Re-Warmup:
# Before EACH repetition (round):
#   1. Clean all daemons (atesnds, atesnds_daemon, dns_listener).
#   2. Detach eBPF XDP Driver and XDP Offload; delete pinned maps (destroying HW/SW caches).
#   3. Restart Unbound (flushing in-memory RRset/msg cache & draining socket buffers).
#   4. Reset network interface queues, affinity (Cores 0 & 1), and NIC rings.
#   5. Cooldown pause (3s) for PCIe and network stabilization.
#   6. Re-attach and re-launch components for the specific mode.
#   7. Execute 2-Phase Warmup:
#      - Phase 1: Top 32,768 heavy-hitters to SmartNIC SRAM (3,000 QPS)
#      - Phase 2: Unique trace domains to Host Resolver Cache (20,000 QPS)
#   8. Execute the sustained 180s test round.
# ==============================================================================



SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_BASE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUT_DIR="${SCRIPT_DIR}"

SERVER_IFACE="enp1s0np1"
SERVER_IP="192.168.0.1"
SERVER_MAC="00:15:4d:13:81:80"

CLIENT_IFACE="enp1s0f0"
CLIENT_IP="192.168.0.2"
CLIENT_MAC="3c:fd:fe:03:02:00"
CLIENT_MGMT_IP="150.164.2.81"
CLIENT_USER="soares"
CLIENT_BASE_DIR="/home/soares/Documentos/AtesN-DS"
CLIENT_XDNSPERF_DIR="/home/soares/Documentos/xdnsperf"
CLIENT_BENCH_TRACE="${CLIENT_BASE_DIR}/tests/isp_queries_2m_dnsperf.txt"
CLIENT_TOP32K_WARMUP="${CLIENT_BASE_DIR}/tests/isp_bench_warmup_xdnsperf.txt"
CLIENT_UNIQUE_WARMUP="${CLIENT_BASE_DIR}/tests/isp_unique_warmup_dnsperf.txt"

NUM_CORES=2
SERVER_CORES="0,1"
SERVER_TASKSET="0,1"

MODES_TO_TEST=("unbound_standalone" "ates_driver" "unbound_hw_cache" "ates_hw_cache")
if [ $# -ge 1 ] && [ -n "$1" ]; then
    IFS=' ' read -r -a MODES_TO_TEST <<< "$1"
fi

RATES=(200000 500000 1000000 2000000 3000000)
if [ $# -ge 2 ] && [ -n "$2" ]; then
    IFS=' ' read -r -a RATES <<< "$2"
fi

REPS=${REPS:-10}
DURATION=${DURATION:-180}
CLIENT_WORKERS=4

RAW_CSV="${RAW_CSV:-${OUT_DIR}/raw_2core_clean_warmup_10reps.csv}"
SUMMARY_CSV="${SUMMARY_CSV:-${OUT_DIR}/summary_2core_clean_warmup_10reps.csv}"
mkdir -p "${OUT_DIR}/logs"

if [ ! -f "${RAW_CSV}" ]; then
    echo "num_cores,mode,target_qps,rep,queries_sent,queries_completed,queries_lost,packet_loss_pct,achieved_qps,lat_mean_ms,lat_p50_ms,lat_p75_ms,lat_p90_ms,lat_p95_ms,lat_p99_ms,lat_p99_9_ms,lat_min_ms,lat_max_ms,lat_std_ms,hw_cache_hits,hw_pass_pkts,driver_hits,userspace_hits,hw_hit_rate_pct,nic_rx_discards,nic_tx_discards,nic_rx_errors,nic_irq_delta,srv_c0_busy,srv_c1_busy,srv_c2_busy,srv_c3_busy,srv_all_busy,srv_softirq,client_cpu_busy" > "${RAW_CSV}"
fi

generate_summary() {
    python3 - << 'PYEOF'
import csv
from collections import defaultdict
import numpy as np
import os

raw_path = os.environ.get("RAW_CSV", "official_results/06_multicore_xdnsperf_calibrated/raw_2core_clean_warmup_10reps.csv")
summary_path = os.environ.get("SUMMARY_CSV", "official_results/06_multicore_xdnsperf_calibrated/summary_2core_clean_warmup_10reps.csv")

if not os.path.exists(raw_path):
    exit(0)

data = defaultdict(list)
with open(raw_path, 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        key = (row['num_cores'], row['mode'], row['target_qps'])
        data[key].append(row)

with open(summary_path, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow([
        "num_cores", "mode", "target_qps", "reps",
        "achieved_qps_mean", "achieved_qps_std",
        "loss_pct_mean", "loss_pct_std",
        "lat_mean_ms", "lat_p99_ms", "lat_p99_9_ms",
        "hw_cache_hits_mean", "driver_hits_mean", "userspace_hits_mean", "hw_hit_rate_pct",
        "srv_c0_busy_mean", "srv_c1_busy_mean", "srv_c2_busy_mean", "srv_c3_busy_mean",
        "srv_all_busy_mean", "srv_softirq_mean", "client_cpu_busy_mean"
    ])

    for (cores, mode, target_qps), rows in sorted(data.items()):
        qps_vals = [float(r['achieved_qps']) for r in rows]
        loss_vals = [float(r['packet_loss_pct']) for r in rows]
        lat_mean_vals = [float(r['lat_mean_ms']) for r in rows]
        lat_p99_vals = [float(r['lat_p99_ms']) for r in rows]
        lat_p999_vals = [float(r['lat_p99_9_ms']) for r in rows]
        hw_hits_vals = [float(r['hw_cache_hits']) for r in rows]
        drv_hits_vals = [float(r['driver_hits']) for r in rows]
        usr_hits_vals = [float(r['userspace_hits']) for r in rows]
        hw_hit_rate_vals = [float(r['hw_hit_rate_pct']) for r in rows]
        c0_vals = [float(r['srv_c0_busy']) for r in rows]
        c1_vals = [float(r['srv_c1_busy']) for r in rows]
        c2_vals = [float(r['srv_c2_busy']) for r in rows]
        c3_vals = [float(r['srv_c3_busy']) for r in rows]
        all_vals = [float(r['srv_all_busy']) for r in rows]
        soft_vals = [float(r['srv_softirq']) for r in rows]
        cli_vals = [float(r['client_cpu_busy']) for r in rows]

        writer.writerow([
            cores, mode, target_qps, len(rows),
            f"{np.mean(qps_vals):.0f}", f"{np.std(qps_vals):.0f}",
            f"{np.mean(loss_vals):.2f}", f"{np.std(loss_vals):.2f}",
            f"{np.mean(lat_mean_vals):.3f}", f"{np.mean(lat_p99_vals):.3f}", f"{np.mean(lat_p999_vals):.3f}",
            f"{np.mean(hw_hits_vals):.0f}", f"{np.mean(drv_hits_vals):.0f}", f"{np.mean(usr_hits_vals):.0f}",
            f"{np.mean(hw_hit_rate_vals):.2f}",
            f"{np.mean(c0_vals):.1f}", f"{np.mean(c1_vals):.1f}", f"{np.mean(c2_vals):.1f}", f"{np.mean(c3_vals):.1f}",
            f"{np.mean(all_vals):.1f}", f"{np.mean(soft_vals):.1f}", f"{np.mean(cli_vals):.1f}"
        ])
PYEOF
}

reset_clean_and_warmup() {
    local MODE="$1"
    echo "   [RESET] 1. Matando daemons antigos..."
    sudo -n killall -9 atesnds atesnds_daemon dns_listener 2>/dev/null || true
    sudo -n pkill -9 -x "atesnds|atesnds_daemon|dns_listener" 2>/dev/null || true

    echo "   [RESET] 2. Desanexando XDP Offload / Driver e destruindo mapas BPF..."
    sudo -n bpftool net detach xdpoffload dev "${SERVER_IFACE}" 2>/dev/null || true
    sudo -n bpftool net detach xdp dev "${SERVER_IFACE}" 2>/dev/null || true
    sudo -n ip link set dev "${SERVER_IFACE}" xdp off 2>/dev/null || true
    sudo -n rm -rf /sys/fs/bpf/dns/*

    echo "   [RESET] 3. Limpando cache do Unbound..."
    sudo -n unbound-control flush_zone . >/dev/null 2>&1 || sudo -n systemctl restart unbound
    pgrep -x unbound | xargs -r -n1 sudo -n taskset -acp "${SERVER_TASKSET}" >/dev/null 2>&1 || true

    echo "   [COOLDOWN] 4. Aguardando 3s de estabilização do barramento e anéis..."
    sleep 3

    echo "   [RELOAD] 5. Recarregando componentes para o modo: ${MODE}..."
    case "${MODE}" in
      "unbound_standalone")
        # Unbound já ativo e limpo
        ;;
      "unbound_hw_cache")
        cd "${SERVER_BASE_DIR}" && sudo -n make load-hw >/dev/null 2>&1
        sleep 2
        nohup sudo -n taskset -c "${SERVER_TASKSET}" "${SERVER_BASE_DIR}/bin/dns_listener" -i "${SERVER_IFACE}" >/dev/null 2>&1 &
        sleep 1
        nohup sudo -n taskset -c "${SERVER_TASKSET}" "${SERVER_BASE_DIR}/bin/atesnds_daemon" >/dev/null 2>&1 &
        sleep 2
        ;;
      "ates_driver")
        nohup sudo -n taskset -c "${SERVER_TASKSET}" "${SERVER_BASE_DIR}/bin/atesnds" -a "${SERVER_IP}" -i "${SERVER_IFACE}" -m "${CLIENT_MAC}" -s "${CLIENT_IP}" >/dev/null 2>&1 &
        sleep 2
        sudo -n python3 "${SERVER_BASE_DIR}/tests/manage_overload.py" normal 2>/dev/null || true
        ;;
      "ates_hw_cache")
        cd "${SERVER_BASE_DIR}" && sudo -n make load-hw >/dev/null 2>&1
        sleep 2
        nohup sudo -n taskset -c "${SERVER_TASKSET}" "${SERVER_BASE_DIR}/bin/atesnds" -a "${SERVER_IP}" -i "${SERVER_IFACE}" -m "${CLIENT_MAC}" -s "${CLIENT_IP}" >/dev/null 2>&1 &
        sleep 2
        nohup sudo -n taskset -c "${SERVER_TASKSET}" "${SERVER_BASE_DIR}/bin/atesnds_daemon" >/dev/null 2>&1 &
        sleep 2
        sudo -n python3 "${SERVER_BASE_DIR}/tests/manage_overload.py" normal 2>/dev/null || true
        ;;
    esac

    # 6. Warmup resolvendo os top domínios do trace com xdnsperf
    echo "   [WARMUP] 6. Aquecendo SRAM e Caches resolvendo Top Domínios com xdnsperf (15.000 QPS)..."
    ssh -o StrictHostKeyChecking=no "${CLIENT_USER}@${CLIENT_MGMT_IP}" "
        sudo -n ip link set dev ${CLIENT_IFACE} up 2>/dev/null || true
        sudo -n ip addr replace ${CLIENT_IP}/24 dev ${CLIENT_IFACE} 2>/dev/null || true
        sudo -n arp -s ${SERVER_IP} ${SERVER_MAC} 2>/dev/null || true
        sudo -n ${CLIENT_XDNSPERF_DIR}/bin/xdnsperf \
            -i ${CLIENT_IFACE} \
            -s ${SERVER_IP} \
            -c 4 \
            -d 4 \
            -r 15000 \
            -f ${CLIENT_TOP32K_WARMUP} >/dev/null 2>&1 || true
    "
    sleep 2
    echo "   • Ambiente limpo e reaquecido com xdnsperf para a rodada!"
}

echo "=========================================================================================="
echo "🚀 BENCHMARK COM LIMPEZA E WARMUP ESTRITO POR RODADA (2 CORES, REPS=${REPS}, DURATION=${DURATION}s)"
echo "Modos: ${MODES_TO_TEST[*]}"
echo "Taxas: ${RATES[*]}"
echo "Saída: ${RAW_CSV}"
echo "=========================================================================================="

# ------------------------------------------------------------------------------
# Configuração única de rede, IRQs e governors (sem rebotes repetidos no link)
# ------------------------------------------------------------------------------
echo "-> [SETUP] Configurando interfaces, 4 filas combinadas, afinidade de IRQ e governors (execução única)..."
sudo -n cpupower frequency-set -g performance >/dev/null 2>&1 || true
sudo -n ip link set dev "${SERVER_IFACE}" up 2>/dev/null || true
sudo -n ip addr flush dev "${SERVER_IFACE}" 2>/dev/null || true
sudo -n ip addr add "${SERVER_IP}/24" dev "${SERVER_IFACE}" 2>/dev/null || true
sudo -n arp -s "${CLIENT_IP}" "${CLIENT_MAC}" 2>/dev/null || true
sudo -n ethtool -L "${SERVER_IFACE}" combined 4 >/dev/null 2>&1 || true
sudo -n ethtool -K "${SERVER_IFACE}" rxhash on gro off lro off tso off gso off >/dev/null 2>&1 || true
sudo -n systemctl stop irqbalance 2>/dev/null || true

RXTX_IRQS=($(grep "${SERVER_IFACE}-rxtx-" /proc/interrupts | awk -F: '{print $1}' | tr -d ' '))
for q in "${!RXTX_IRQS[@]}"; do
    irq="${RXTX_IRQS[$q]}"
    core=$((q % NUM_CORES))
    mask=$((1 << core))
    printf "%x" "${mask}" | sudo -n tee "/proc/irq/${irq}/smp_affinity" >/dev/null || true
done

ssh -o StrictHostKeyChecking=no "${CLIENT_USER}@${CLIENT_MGMT_IP}" "
    sudo -n cpupower frequency-set -g performance >/dev/null 2>&1 || true
    sudo -n ip link set dev ${CLIENT_IFACE} up 2>/dev/null || true
    sudo -n ethtool -L ${CLIENT_IFACE} combined 4 >/dev/null 2>&1 || true
    sudo -n ip addr replace ${CLIENT_IP}/24 dev ${CLIENT_IFACE} 2>/dev/null || true
    sudo -n arp -s ${SERVER_IP} ${SERVER_MAC} 2>/dev/null || true
    sudo -n pkill -x mock_dns_server 2>/dev/null || true
    sleep 1
    sudo -n nohup taskset -c 11 ${CLIENT_BASE_DIR}/tests/mock_dns_server ${CLIENT_IP} 53 </dev/null >/tmp/mock_dns.log 2>&1 &
"
sleep 2

for MODE in "${MODES_TO_TEST[@]}"; do
    for RATE in "${RATES[@]}"; do
        RATE_LABEL="${RATE}"

        for REP in $(seq 1 "${REPS}"); do
            if grep -q "^2,${MODE},${RATE_LABEL},${REP}," "${RAW_CSV}" 2>/dev/null; then
                echo "   [SKIP] 2 Cores | ${MODE} | Rate=${RATE_LABEL} | Rep ${REP}/${REPS} já no CSV."
                continue
            fi

            echo "======================================================================================"
            echo "▶ PREPARANDO RODADA: Modo=${MODE} | QPS=${RATE_LABEL} | Rep ${REP}/${REPS}"
            echo "======================================================================================"
            reset_clean_and_warmup "${MODE}"

            echo "   • Executando Teste: ${DURATION}s..."
            ETH_PRE=$(sudo -n ethtool -S "${SERVER_IFACE}" 2>/dev/null)
            HW_TX_START=$(echo "${ETH_PRE}" | awk '/bpf_app2_pkts/ {print $2; f=1} END {if(!f) print 0}')
            PASS_START=$(echo "${ETH_PRE}" | awk '/bpf_pass_pkts/ {print $2; f=1} END {if(!f) print 0}')
            RX_DISC_START=$(echo "${ETH_PRE}" | awk '/rx_discards/ {print $2; f=1} END {if(!f) print 0}')
            TX_DISC_START=$(echo "${ETH_PRE}" | awk '/tx_discards/ {print $2; f=1} END {if(!f) print 0}')
            RX_ERR_START=$(echo "${ETH_PRE}" | awk '/mac\.rx_errors/ {print $2; f=1} END {if(!f) print 0}')
            UB_Q_START=$(sudo -n unbound-control stats_noreset 2>/dev/null | awk -F'=' '/^total.num.queries=/ {print $2; f=1} END {if(!f) print 0}')
            IRQ_START=$(awk -v iface="${SERVER_IFACE}-rxtx-" '$0 ~ iface {sum += $2+$3+$4+$5+$6+$7} END {print sum+0}' /proc/interrupts)

            SRV_MPSTAT_LOG="${OUT_DIR}/logs/srv_mpstat_clean_${MODE}_${RATE_LABEL}_rep${REP}.txt"
            LC_ALL=C mpstat -P ALL 1 "${DURATION}" > "${SRV_MPSTAT_LOG}" 2>&1 &
            SRV_MPSTAT_PID=$!

            CLIENT_RAW=$(ssh -o StrictHostKeyChecking=no "${CLIENT_USER}@${CLIENT_MGMT_IP}" "
                LC_ALL=C mpstat 1 ${DURATION} > /tmp/client_mpstat.txt 2>&1 &
                CLI_MPSTAT_PID=\$!
                sudo -n ${CLIENT_XDNSPERF_DIR}/bin/xdnsperf \
                    -i ${CLIENT_IFACE} \
                    -s ${SERVER_IP} \
                    -c ${CLIENT_WORKERS} \
                    -d ${DURATION} \
                    -r ${RATE} \
                    -f ${CLIENT_BENCH_TRACE} \
                    ${EXTRA_FLAGS:-} \
                    --csv
                wait \${CLI_MPSTAT_PID} 2>/dev/null || true
                CLI_CPU=\$(awk '/^Average:/ && \$2 == \"all\" { print 100.0 - \$12 }' /tmp/client_mpstat.txt)
                echo \"CLIENT_CPU:\${CLI_CPU}\"
            " 2>&1 || true)

            wait "${SRV_MPSTAT_PID}" 2>/dev/null || true

            ETH_POST=$(sudo -n ethtool -S "${SERVER_IFACE}" 2>/dev/null)
            HW_TX_END=$(echo "${ETH_POST}" | awk '/bpf_app2_pkts/ {print $2; f=1} END {if(!f) print 0}')
            PASS_END=$(echo "${ETH_POST}" | awk '/bpf_pass_pkts/ {print $2; f=1} END {if(!f) print 0}')
            RX_DISC_END=$(echo "${ETH_POST}" | awk '/rx_discards/ {print $2; f=1} END {if(!f) print 0}')
            TX_DISC_END=$(echo "${ETH_POST}" | awk '/tx_discards/ {print $2; f=1} END {if(!f) print 0}')
            RX_ERR_END=$(echo "${ETH_POST}" | awk '/mac\.rx_errors/ {print $2; f=1} END {if(!f) print 0}')
            UB_Q_END=$(sudo -n unbound-control stats_noreset 2>/dev/null | awk -F'=' '/^total.num.queries=/ {print $2; f=1} END {if(!f) print 0}')
            IRQ_END=$(awk -v iface="${SERVER_IFACE}-rxtx-" '$0 ~ iface {sum += $2+$3+$4+$5+$6+$7} END {print sum+0}' /proc/interrupts)

            DELTA_HW=$((HW_TX_END - HW_TX_START)); [ "${DELTA_HW}" -lt 0 ] && DELTA_HW=0
            DELTA_PASS=$((PASS_END - PASS_START)); [ "${DELTA_PASS}" -lt 0 ] && DELTA_PASS=0
            DELTA_RX_DISC=$((RX_DISC_END - RX_DISC_START)); [ "${DELTA_RX_DISC}" -lt 0 ] && DELTA_RX_DISC=0
            DELTA_TX_DISC=$((TX_DISC_END - TX_DISC_START)); [ "${DELTA_TX_DISC}" -lt 0 ] && DELTA_TX_DISC=0
            DELTA_RX_ERR=$((RX_ERR_END - RX_ERR_START)); [ "${DELTA_RX_ERR}" -lt 0 ] && DELTA_RX_ERR=0
            DELTA_UB=$((UB_Q_END - UB_Q_START)); [ "${DELTA_UB}" -lt 0 ] && DELTA_UB=0
            DELTA_IRQ=$((IRQ_END - IRQ_START)); [ "${DELTA_IRQ}" -lt 0 ] && DELTA_IRQ=0

            SRV_C0=$(awk '/^Average:/ && $2 == "0" { print 100.0 - $12 }' "${SRV_MPSTAT_LOG}")
            SRV_C1=$(awk '/^Average:/ && $2 == "1" { print 100.0 - $12 }' "${SRV_MPSTAT_LOG}")
            SRV_C2=$(awk '/^Average:/ && $2 == "2" { print 100.0 - $12 }' "${SRV_MPSTAT_LOG}")
            SRV_C3=$(awk '/^Average:/ && $2 == "3" { print 100.0 - $12 }' "${SRV_MPSTAT_LOG}")
            SRV_ALL=$(awk '/^Average:/ && $2 == "all" { print 100.0 - $12 }' "${SRV_MPSTAT_LOG}")
            SRV_SOFT=$(awk '/^Average:/ && $2 == "all" { print $8 }' "${SRV_MPSTAT_LOG}")
            CSV_LINE=$(echo "${CLIENT_RAW}" | grep "^CSV:" | head -n 1 | sed 's/^CSV://')
            if [ -z "${CSV_LINE}" ]; then
                echo "   [ERRO] xdnsperf não retornou linha CSV válida. Output bruto:"
                echo "${CLIENT_RAW}" | tail -n 5
                continue
            fi

            CLIENT_CPU=$(echo "${CLIENT_RAW}" | grep "^CLIENT_CPU:" | head -n 1 | cut -d: -f2 | tr -d ' \r')
            [ -z "${CLIENT_CPU}" ] && CLIENT_CPU="0.00"

            IFS=',' read -r tot_req tot_ans qps lat_mean lat_p50 lat_p75 lat_p90 lat_p95 lat_p99 lat_p99_9 lat_min lat_max lat_std loss_pct loss_cnt trgt <<< "${CSV_LINE}"

            # Tier breakdown
            case "${MODE}" in
              "unbound_standalone")
                HW_HITS=0
                DRV_HITS=0
                USR_HITS="${tot_ans}"
                HW_HIT_RATE="0.00"
                ;;
              "unbound_hw_cache")
                HW_HITS="${DELTA_HW}"
                [ "${HW_HITS}" -gt "${tot_ans}" ] && HW_HITS="${tot_ans}"
                DRV_HITS=0
                USR_HITS=$((tot_ans - HW_HITS))
                HW_HIT_RATE=$(awk -v h="${HW_HITS}" -v t="${tot_ans}" 'BEGIN {if(t>0) printf "%.2f", (h/t)*100.0; else print "0.00"}')
                ;;
              "ates_driver")
                HW_HITS=0
                USR_HITS="${DELTA_UB}"
                [ "${USR_HITS}" -gt "${tot_ans}" ] && USR_HITS="${tot_ans}"
                DRV_HITS=$((tot_ans - USR_HITS))
                HW_HIT_RATE="0.00"
                ;;
              "ates_hw_cache")
                HW_HITS="${DELTA_HW}"
                [ "${HW_HITS}" -gt "${tot_ans}" ] && HW_HITS="${tot_ans}"
                USR_HITS="${DELTA_UB}"
                if [ $((HW_HITS + USR_HITS)) -gt "${tot_ans}" ]; then
                    USR_HITS=$((tot_ans - HW_HITS))
                fi
                DRV_HITS=$((tot_ans - HW_HITS - USR_HITS))
                HW_HIT_RATE=$(awk -v h="${HW_HITS}" -v t="${tot_ans}" 'BEGIN {if(t>0) printf "%.2f", (h/t)*100.0; else print "0.00"}')
                ;;
            esac

            echo "2,${MODE},${RATE_LABEL},${REP},${tot_req},${tot_ans},${loss_cnt},${loss_pct},${qps},${lat_mean},${lat_p50},${lat_p75},${lat_p90},${lat_p95},${lat_p99},${lat_p99_9},${lat_min},${lat_max},${lat_std},${HW_HITS},${DELTA_PASS},${DRV_HITS},${USR_HITS},${HW_HIT_RATE},${DELTA_RX_DISC},${DELTA_TX_DISC},${DELTA_RX_ERR},${DELTA_IRQ},${SRV_C0},${SRV_C1},${SRV_C2},${SRV_C3},${SRV_ALL},${SRV_SOFT},${CLIENT_CPU}" >> "${RAW_CSV}"

            printf "      -> QPS=%s | Loss=%s%% | Lat_p99=%sms | HW_Hit=%s%% (HW=%d, UsrMiss=%d) | Srv_All=%.1f%% (C0=%.1f%% C1=%.1f%%) | Cli_CPU=%s%%\n" \
                "${qps}" "${loss_pct}" "${lat_p99}" "${HW_HIT_RATE}" "${HW_HITS}" "${USR_HITS}" "${SRV_ALL}" "${SRV_C0}" "${SRV_C1}" "${CLIENT_CPU}"
            generate_summary
        done
    done
done

echo "=========================================================================================="
echo "✅ BENCHMARK COM LIMPEZA E REAQUECIMENTO POR RODADA CONCLUÍDO COM SUCESSO!"
echo "Dados brutos: ${RAW_CSV}"
echo "Resumo estatístico: ${SUMMARY_CSV}"
echo "=========================================================================================="
