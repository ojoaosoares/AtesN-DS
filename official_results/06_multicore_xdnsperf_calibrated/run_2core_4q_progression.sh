#!/bin/bash
# ==============================================================================
# official_results/06_multicore_xdnsperf_calibrated/run_2core_4q_progression.sh
#
# Calibrated 2-Core Benchmark with Max Queues (4 Combined) & Progressive Rates:
#   - Server Cores: Exactly 2 Dedicated Cores (0 and 1)
#   - NIC Queues: 4 combined queues on Netronome NFP-4000 (Maximum supported)
#   - Queue Affinity: Evenly alternated across Core 0 and Core 1 (q0->c0, q1->c1, q2->c0, q3->c1)
#   - 4 Architectural Modes:
#       1) unbound_standalone (Unbound in User Space on Cores 0,1)
#       2) unbound_hw_cache   (Unbound + Decoupled Listener + SmartNIC HW Cache)
#       3) ates_driver        (AtesN-DS XDP Driver Mode + Unbound Fallback)
#       4) ates_hw_cache      (AtesN-DS Hybrid XDP Driver + SmartNIC HW Cache)
#   - Progressive Rates (without UNLIMITED, Client CPU capped < 90%):
#       200k, 500k, 1M, 2M, 3M, 4M, 5M
#   - Repetitions: 2 independent runs per level (n=2)
#   - Duration: 30 seconds per repetition
#   - Warmup: 32.768 domains Top SRAM at 3.000 QPS
# ==============================================================================

set -euo pipefail
export LC_ALL=C

SERVER_BASE_DIR="/home/joaosoares/Documents/Github/AtesN-DS"
OUT_DIR="${SERVER_BASE_DIR}/official_results/06_multicore_xdnsperf_calibrated"
mkdir -p "${OUT_DIR}/logs"

CLIENT_USER="soares"
CLIENT_MGMT_IP="150.164.2.81"
CLIENT_BASE_DIR="/home/soares/Documentos/AtesN-DS"
CLIENT_XDNSPERF_DIR="/home/soares/Documentos/xdnsperf"
CLIENT_TRACE_FILE="${CLIENT_BASE_DIR}/tests/isp_top32k_hw_warmup_dnsperf.txt"

SERVER_IFACE="enp1s0np1"
SERVER_IP="192.168.0.1"
CLIENT_IFACE="enp1s0f0"
CLIENT_IP="192.168.0.2"
CLIENT_MAC="3c:fd:fe:03:02:00"

NUM_CORES=2
SERVER_TASKSET="0,1"
AFFINITY_MASK="3"

MODES_TO_TEST=("unbound_standalone" "ates_driver" "unbound_hw_cache" "ates_hw_cache")
if [ "$#" -ge 1 ]; then
    MODES_TO_TEST=("$1")
fi

RATES=(200000 500000 1000000 2000000 3000000 4000000 5000000)
REPS=2
DURATION=${DURATION:-30}
CLIENT_WORKERS=4

RAW_CSV="${OUT_DIR}/raw_2core_4q_progression.csv"
SUMMARY_CSV="${OUT_DIR}/summary_2core_4q_progression.csv"

if [ ! -f "${RAW_CSV}" ]; then
    echo "num_cores,mode,target_qps,rep,queries_sent,queries_completed,queries_lost,packet_loss_pct,achieved_qps,lat_mean_ms,lat_p50_ms,lat_p75_ms,lat_p90_ms,lat_p95_ms,lat_p99_ms,lat_p99_9_ms,lat_min_ms,lat_max_ms,lat_std_ms,hw_cache_hits,hw_pass_pkts,driver_hits,userspace_hits,hw_hit_rate_pct,nic_rx_discards,nic_tx_discards,nic_rx_errors,nic_irq_delta,srv_c0_busy,srv_c1_busy,srv_c2_busy,srv_c3_busy,srv_all_busy,srv_softirq,client_cpu_busy" > "${RAW_CSV}"
fi

echo "=========================================================================================="
echo "🚀 INICIANDO BENCHMARK PROGRESSIVO (4 FILAS NIC, 2 CORES SERVIDOR, REPS=${REPS}, DURATION=${DURATION}s)"
echo "Cores de Servidor: 2 (Cores ${SERVER_TASKSET})"
echo "Filas combinadas na SmartNIC: 4 (Máximo de hardware)"
echo "Modos: ${MODES_TO_TEST[*]}"
echo "Níveis de QPS: ${RATES[*]} (Sem UNLIMITED, Cliente CPU < 90%)"
echo "Repetições por nível: ${REPS} | Duração por rep: ${DURATION}s"
echo "Cliente: xdnsperf (${CLIENT_WORKERS} workers AF_XDP em ${CLIENT_IFACE})"
echo "Arquivo de saída: ${RAW_CSV}"
echo "=========================================================================================="

echo "-> Garantindo Mock Authoritative DNS Responder ativo no cliente (${CLIENT_IP}:53)..."
ssh -o StrictHostKeyChecking=no "${CLIENT_USER}@${CLIENT_MGMT_IP}" "
    sudo -n ip link set dev ${CLIENT_IFACE} up 2>/dev/null || true
    sudo -n ip addr replace ${CLIENT_IP}/24 dev ${CLIENT_IFACE} 2>/dev/null || true
    sudo -n pkill -x mock_dns_server 2>/dev/null || true
    sleep 1
    sudo -n nohup taskset -c 11 ${CLIENT_BASE_DIR}/tests/mock_dns_server ${CLIENT_IP} 53 </dev/null >/tmp/mock_dns.log 2>&1 &
    sleep 1
"

# Configura Unbound para 2 cores com cache estendido (24h)
sudo -n bash -c "cat > /etc/unbound/unbound.conf.d/multicore.conf << 'EOF'
server:
    num-threads: 2
    msg-cache-slabs: 2
    rrset-cache-slabs: 2
    infra-cache-slabs: 2
    key-cache-slabs: 2
    so-reuseport: yes
    cache-min-ttl: 86400
    cache-max-ttl: 86400
EOF"

for MODE in "${MODES_TO_TEST[@]}"; do
    echo
    echo "=========================================================================================="
    echo "▶ MODO: ${MODE} (2 CORES: ${SERVER_TASKSET} | 4 FILAS COMBINADAS)"
    echo "=========================================================================================="

    # Limpa processos anteriores
    tmux kill-session -t srv 2>/dev/null || true
    tmux kill-session -t ates 2>/dev/null || true
    tmux kill-session -t hw 2>/dev/null || true
    tmux kill-session -t listener 2>/dev/null || true
    tmux kill-session -t unbound 2>/dev/null || true
    tmux kill-session -t gov 2>/dev/null || true

    sudo -n pkill atesnds 2>/dev/null || true
    sudo -n pkill atesnds_daemon 2>/dev/null || true
    sudo -n pkill dns_listener 2>/dev/null || true
    sudo -n pkill time_updater 2>/dev/null || true
    sudo -n systemctl stop unbound 2>/dev/null || sudo -n pkill -9 unbound 2>/dev/null || true

    cd "${SERVER_BASE_DIR}"
    sudo -n make unload-hw 2>/dev/null || true
    sudo -n tc qdisc del dev "${SERVER_IFACE}" clsact 2>/dev/null || true
    sudo -n bpftool net detach xdp dev "${SERVER_IFACE}" 2>/dev/null || true
    sudo -n rm -f /sys/fs/bpf/dns_misses /sys/fs/bpf/overload_ctrl /sys/fs/bpf/hw_sync_ringbuf /sys/fs/bpf/level_one_cache /sys/fs/bpf/time_map /sys/fs/bpf/xdp_prog

    # Configura estritamente 4 filas combinadas na SmartNIC (máximo)
    sudo -n ip link set dev "${SERVER_IFACE}" down
    sleep 1
    sudo -n ip link set dev "${SERVER_IFACE}" up
    sudo -n ethtool -L "${SERVER_IFACE}" tx 0 rx 0 combined 4 2>/dev/null || sudo -n ethtool -L "${SERVER_IFACE}" combined 4 2>/dev/null || true
    sudo -n ethtool -K "${SERVER_IFACE}" rxhash on gro off lro off tso off gso off 2>/dev/null || true
    sudo -n systemctl stop irqbalance 2>/dev/null || true

    # Distribui as 4 filas alternadamente nos 2 Cores dedicados (Core 0 e Core 1)
    RXTX_IRQS=($(grep "${SERVER_IFACE}-rxtx-" /proc/interrupts | awk -F: '{print $1}' | tr -d ' '))
    for q in "${!RXTX_IRQS[@]}"; do
        irq="${RXTX_IRQS[$q]}"
        core=$((q % NUM_CORES))
        mask=$((1 << core))
        printf "%x" "${mask}" | sudo -n tee "/proc/irq/${irq}/smp_affinity" >/dev/null || true
        echo "   • Fila ${SERVER_IFACE}-rxtx-${q} (IRQ ${irq}) vinculada ao Core ${core} (mask $(printf "%x" ${mask}))"
    done

    sudo -n ip addr flush dev "${SERVER_IFACE}"
    sudo -n ip addr add "${SERVER_IP}/24" dev "${SERVER_IFACE}"
    sleep 2

    for i in {1..10}; do
        if ping -c 1 -W 1 "${CLIENT_IP}" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done

    # Inicia daemons do modo
    case "${MODE}" in
      "unbound_standalone")
        echo "   [Daemon] Unbound Standalone (2 Threads fixadas nos Cores ${SERVER_TASKSET})..."
        sudo -n systemctl restart unbound
        sleep 1
        pgrep -x unbound | xargs -r -n1 sudo -n taskset -acp "${SERVER_TASKSET}" >/dev/null 2>&1 || true
        sleep 2
        ;;

      "unbound_hw_cache")
        echo "   [SmartNIC] Carregando firmware XDP offloaded..."
        sudo -n make load-hw
        sleep 2
        echo "   [Daemon] Decoupled DNS Listener na interface ${SERVER_IFACE}..."
        tmux new-session -d -s listener "cd ${SERVER_BASE_DIR} && sudo -n taskset -c ${SERVER_TASKSET} ./bin/dns_listener -i ${SERVER_IFACE} -v"
        sleep 2
        echo "   [Daemon] AtesN-DS Control-Plane Daemon (Ingestão + Relógio)..."
        tmux new-session -d -s hw "cd ${SERVER_BASE_DIR} && sudo -n taskset -c ${SERVER_TASKSET} ./bin/atesnds_daemon -v"
        sleep 2
        echo "   [Daemon] Unbound (2 Threads nos Cores ${SERVER_TASKSET})..."
        sudo -n systemctl restart unbound
        sleep 1
        pgrep -x unbound | xargs -r -n1 sudo -n taskset -acp "${SERVER_TASKSET}" >/dev/null 2>&1 || true
        sleep 2
        ;;

      "ates_driver")
        echo "   [Daemon] Unbound Fallback (${SERVER_TASKSET})..."
        sudo -n systemctl restart unbound
        sleep 1
        pgrep -x unbound | xargs -r -n1 sudo -n taskset -acp "${SERVER_TASKSET}" >/dev/null 2>&1 || true
        sleep 1
        echo "   [Daemon] AtesN-DS Driver Mode (Cores ${SERVER_TASKSET})..."
        tmux new-session -d -s ates "cd ${SERVER_BASE_DIR} && sudo -n taskset -c ${SERVER_TASKSET} ./bin/atesnds -a ${SERVER_IP} -i ${SERVER_IFACE} -m ${CLIENT_MAC} -s ${CLIENT_IP} -v"
        sleep 3
        sudo -n python3 tests/manage_overload.py normal 2>/dev/null || true
        ;;

      "ates_hw_cache")
        echo "   [SmartNIC] Carregando firmware XDP offloaded..."
        sudo -n make load-hw
        sleep 2
        echo "   [Daemon] AtesN-DS com HW Cache (Cores ${SERVER_TASKSET})..."
        tmux new-session -d -s ates "cd ${SERVER_BASE_DIR} && sudo -n taskset -c ${SERVER_TASKSET} ./bin/atesnds -a ${SERVER_IP} -i ${SERVER_IFACE} -m ${CLIENT_MAC} -s ${CLIENT_IP} -v"
        sleep 3
        echo "   [Daemon] Control-Plane Daemon..."
        tmux new-session -d -s hw "cd ${SERVER_BASE_DIR} && sudo -n taskset -c ${SERVER_TASKSET} ./bin/atesnds_daemon -v"
        sleep 2
        echo "   [Daemon] Unbound Fallback..."
        sudo -n systemctl restart unbound
        sleep 1
        pgrep -x unbound | xargs -r -n1 sudo -n taskset -acp "${SERVER_TASKSET}" >/dev/null 2>&1 || true
        sleep 1
        sudo -n python3 tests/manage_overload.py normal 2>/dev/null || true
        ;;
    esac

    # Warmup calibrado: passagem a 3.000 QPS para povoar 100% da SRAM / Cache sem perda
    echo "-> Executando Warmup calibrado no HW Cache / Unbound (Top 32k domínios a 3.000 QPS)..."
    ssh -o StrictHostKeyChecking=no "${CLIENT_USER}@${CLIENT_MGMT_IP}" "
        dnsperf -s ${SERVER_IP} -d ${CLIENT_TRACE_FILE} -n 1 -c 8 -T 2 -q 200 -Q 3000 >/dev/null 2>&1 || true
    "
    sleep 2
    echo "   • Warmup calibrado concluído!"

    for RATE in "${RATES[@]}"; do
        RATE_LABEL="${RATE}"
        if [ "${RATE}" -eq 0 ]; then
            RATE_LABEL="UNLIMITED"
        fi

        for REP in $(seq 1 "${REPS}"); do
            if grep -q "^2,${MODE},${RATE_LABEL},${REP}," "${RAW_CSV}" 2>/dev/null; then
                echo "   [SKIP] 2 Cores | ${MODE} | Target=${RATE_LABEL} | Rep ${REP}/${REPS} já no CSV."
                continue
            fi

            echo "   --------------------------------------------------------------------------------------"
            echo "   • Executando: 2 Cores | Modo=${MODE} | QPS=${RATE_LABEL} | Rep ${REP}/${REPS} (${DURATION}s)"

            # Snapshot Pré
            ETH_PRE=$(sudo -n ethtool -S "${SERVER_IFACE}" 2>/dev/null)
            HW_TX_START=$(echo "${ETH_PRE}" | awk '/bpf_app2_pkts/ {print $2; f=1} END {if(!f) print 0}')
            PASS_START=$(echo "${ETH_PRE}" | awk '/bpf_pass_pkts/ {print $2; f=1} END {if(!f) print 0}')
            RX_DISC_START=$(echo "${ETH_PRE}" | awk '/rx_discards/ {print $2; f=1} END {if(!f) print 0}')
            TX_DISC_START=$(echo "${ETH_PRE}" | awk '/tx_discards/ {print $2; f=1} END {if(!f) print 0}')
            RX_ERR_START=$(echo "${ETH_POST:-${ETH_PRE}}" | awk '/mac\.rx_errors/ {print $2; f=1} END {if(!f) print 0}')
            UB_Q_START=$(sudo -n unbound-control stats_noreset 2>/dev/null | awk -F'=' '/^total.num.queries=/ {print $2; f=1} END {if(!f) print 0}')
            IRQ_START=$(awk -v iface="${SERVER_IFACE}-rxtx-" '$0 ~ iface {sum += $2+$3+$4+$5+$6+$7} END {print sum+0}' /proc/interrupts)

            SRV_MPSTAT_LOG="${OUT_DIR}/logs/srv_mpstat_2c_prog_${MODE}_${RATE_LABEL}_rep${REP}.txt"
            LC_ALL=C mpstat -P ALL 1 "${DURATION}" > "${SRV_MPSTAT_LOG}" 2>&1 &
            SRV_MPSTAT_PID=$!

            # Dispara xdnsperf + mpstat no cliente
            CLIENT_RAW=$(ssh -o StrictHostKeyChecking=no "${CLIENT_USER}@${CLIENT_MGMT_IP}" "
                LC_ALL=C mpstat 1 ${DURATION} > /tmp/client_mpstat.txt 2>&1 &
                CLI_MPSTAT_PID=\$!
                sudo -n ${CLIENT_XDNSPERF_DIR}/bin/xdnsperf \
                    -i ${CLIENT_IFACE} \
                    -s ${SERVER_IP} \
                    -c ${CLIENT_WORKERS} \
                    -d ${DURATION} \
                    -r ${RATE} \
                    -f ${CLIENT_TRACE_FILE} \
                    --csv
                wait \${CLI_MPSTAT_PID} 2>/dev/null || true
                CLI_CPU=\$(awk '/^Average:/ && \$2 == \"all\" { print 100.0 - \$12 }' /tmp/client_mpstat.txt)
                echo \"CLIENT_CPU:\${CLI_CPU}\"
            " 2>&1 || true)

            wait "${SRV_MPSTAT_PID}" 2>/dev/null || true

            # Snapshot Pós
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

            [ -z "${SRV_C0}" ] && SRV_C0="0.00"
            [ -z "${SRV_C1}" ] && SRV_C1="0.00"
            [ -z "${SRV_C2}" ] && SRV_C2="0.00"
            [ -z "${SRV_C3}" ] && SRV_C3="0.00"
            [ -z "${SRV_ALL}" ] && SRV_ALL="0.00"
            [ -z "${SRV_SOFT}" ] && SRV_SOFT="0.00"

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

            printf "      -> QPS=%s | Loss=%s%% | Lat_p99=%sms | HW_Hit=%s%% | Srv_All=%.1f%% (C0=%.1f%% C1=%.1f%%) | Cli_CPU=%s%%\n" \
                "${qps}" "${loss_pct}" "${lat_p99}" "${HW_HIT_RATE}" "${SRV_ALL}" "${SRV_C0}" "${SRV_C1}" "${CLIENT_CPU}"
            sleep 1
        done
    done
done

echo
echo "-> Gerando resumo estatístico agregado em ${SUMMARY_CSV}..."
python3 - << PYEOF
import csv
from collections import defaultdict
import numpy as np

raw_path = "${RAW_CSV}"
summary_path = "${SUMMARY_CSV}"

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
        "hw_hit_rate_pct",
        "srv_c0_busy_mean", "srv_c1_busy_mean", "srv_c2_busy_mean", "srv_c3_busy_mean",
        "srv_all_busy_mean", "srv_softirq_mean", "client_cpu_busy_mean"
    ])

    for (cores, mode, target_qps), rows in sorted(data.items()):
        qps_vals = [float(r['achieved_qps']) for r in rows]
        loss_vals = [float(r['packet_loss_pct']) for r in rows]
        lat_mean_vals = [float(r['lat_mean_ms']) for r in rows]
        lat_p99_vals = [float(r['lat_p99_ms']) for r in rows]
        lat_p999_vals = [float(r['lat_p99_9_ms']) for r in rows]
        hw_hit_vals = [float(r['hw_hit_rate_pct']) for r in rows]
        c0_vals = [float(r['srv_c0_busy']) for r in rows]
        c1_vals = [float(r['srv_c1_busy']) for r in rows]
        c2_vals = [float(r['srv_c2_busy']) for r in rows]
        c3_vals = [float(r['srv_c3_busy']) for r in rows]
        all_vals = [float(r['srv_all_busy']) for r in rows]
        soft_vals = [float(r.get('srv_softirq', r.get('srv_all_softirq', 0.0))) for r in rows]
        cli_vals = [float(r.get('client_cpu_busy', 0.0)) for r in rows]

        writer.writerow([
            cores, mode, target_qps, len(rows),
            f"{np.mean(qps_vals):.0f}", f"{np.std(qps_vals):.0f}",
            f"{np.mean(loss_vals):.2f}", f"{np.std(loss_vals):.2f}",
            f"{np.mean(lat_mean_vals):.3f}", f"{np.mean(lat_p99_vals):.3f}", f"{np.mean(lat_p999_vals):.3f}",
            f"{np.mean(hw_hit_vals):.2f}",
            f"{np.mean(c0_vals):.1f}", f"{np.mean(c1_vals):.1f}", f"{np.mean(c2_vals):.1f}", f"{np.mean(c3_vals):.1f}",
            f"{np.mean(all_vals):.1f}", f"{np.mean(soft_vals):.1f}", f"{np.mean(cli_vals):.1f}"
        ])

print(f"Resumo gerado com sucesso em: {summary_path}")
PYEOF

echo "-> Gerando gráficos de publicação..."
python3 "${OUT_DIR}/plot_2core_calibrated.py" "${SUMMARY_CSV}"

echo "=========================================================================================="
echo "✅ BENCHMARK PROGRESSIVO (4 FILAS / 2 CORES) CONCLUÍDO!"
echo "Resultados brutos: ${RAW_CSV}"
echo "Resumo agregado:   ${SUMMARY_CSV}"
echo "=========================================================================================="
