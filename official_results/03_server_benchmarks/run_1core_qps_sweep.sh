#!/bin/bash
# ==============================================================================
# official_results/03_server_benchmarks/run_1core_qps_sweep.sh
#
# Official 1-Core QPS Sweep Benchmark across 4 Operational Modes:
#   1) unbound_standalone (Unbound in User Space — 1 Core: Core 0)
#   2) unbound_hw_cache   (Unbound + Decoupled DNS Listener + SmartNIC HW Cache — Core 0)
#   3) ates_driver        (AtesN-DS XDP Driver Mode — 1 Core: Core 0)
#   4) ates_hw_cache      (AtesN-DS Hybrid XDP Driver + SmartNIC HW Cache — Core 0)
#
# Trace: Production ISP DNS Trace (Žiža et al., 2023) - 2,000,000 queries
# Hardware Key: 56 bytes (char[56] + 8B value = 64B cacheline-aligned entry)
# QPS Levels: 50k, 100k, 200k, 350k, 500k, 750k, 1M, UNLIMITED (0)
# Repetitions per QPS Level: 3
# ==============================================================================

set -euo pipefail
export LC_ALL=C

SERVER_BASE_DIR="/home/joaosoares/Documents/Github/AtesN-DS"
OUT_DIR="${SERVER_BASE_DIR}/official_results/03_server_benchmarks"
mkdir -p "${OUT_DIR}/logs"

CLIENT_USER="soares"
CLIENT_MGMT_IP="150.164.2.81"
CLIENT_BASE_DIR="/home/soares/Documentos/AtesN-DS"
CLIENT_BENCH_SCRIPT="${CLIENT_BASE_DIR}/tests/sample_client_dnsperf.py"
CLIENT_ISP_QUERIES="${CLIENT_BASE_DIR}/tests/isp_queries_2m_dnsperf.txt"
CLIENT_ISP_WARMUP="${CLIENT_BASE_DIR}/tests/isp_unique_warmup_dnsperf.txt"

SERVER_IFACE="enp1s0np1"
SERVER_IP="192.168.0.1"
CLIENT_IFACE="enp1s0f0"
CLIENT_IP="192.168.0.2"
CLIENT_MAC="3c:fd:fe:03:02:00"

TARGET_MODES=("${@:-unbound_standalone ates_driver unbound_hw_cache ates_hw_cache}")
if [ "$#" -eq 0 ]; then
    MODES=("unbound_standalone" "ates_driver" "unbound_hw_cache" "ates_hw_cache")
else
    MODES=("$@")
fi

RATES=(50000 100000 200000 350000 500000 750000 1000000 0)
REPS=3
DURATION=60
CONCURRENCY=512
THREADS=8
MAX_OUTSTANDING=20000

RAW_CSV="${OUT_DIR}/raw_1core_qps_sweep_3reps.csv"
SUMMARY_CSV="${OUT_DIR}/summary_1core_qps_sweep.csv"

if [ ! -f "${RAW_CSV}" ]; then
    echo "mode,target_qps,rep,queries_sent,queries_completed,queries_lost,packet_loss_pct,achieved_qps,lat_mean_ms,lat_min_ms,lat_max_ms,lat_std_ms,lat_p50_ms,lat_p75_ms,lat_p90_ms,lat_p95_ms,lat_p99_ms,lat_p99_9_ms,hw_cache_hits,hw_pass_pkts,driver_hits,userspace_hits,hw_hit_rate_pct,nic_rx_discards,nic_tx_discards,nic_rx_errors,nic_irq_delta,srv_core0_user_pct,srv_core0_sys_pct,srv_core0_softirq_pct,srv_core0_idle_pct,srv_core0_busy_pct,client_cpu_busy_pct,client_max_core_pct,client_udp_drops" > "${RAW_CSV}"
fi

echo "=========================================================================================="
echo "🚀 INICIANDO BATERIA OFICIAL DE BENCHMARK (1 CORE = CORE 0, 3 REPS POR NÍVEL DE QPS)"
echo "Modos: ${MODES[*]}"
echo "Níveis de QPS: ${RATES[*]} (0 = UNLIMITED)"
echo "Repetições por nível: ${REPS} | Duração por rep: ${DURATION}s | Trace: ISP 2M (Žiža et al., 2023)"
echo "CSV Bruto: ${RAW_CSV}"
echo "=========================================================================================="

echo "-> Garantindo Mock Authoritative DNS Responder ativo no cliente (${CLIENT_IP}:53)..."
ssh -o StrictHostKeyChecking=no "${CLIENT_USER}@${CLIENT_MGMT_IP}" "
    sudo -n ip link set dev ${CLIENT_IFACE} up 2>/dev/null || true
    sudo -n ip addr replace ${CLIENT_IP}/24 dev ${CLIENT_IFACE} 2>/dev/null || true
    sudo -n sysctl -w net.core.rmem_max=33554432 >/dev/null 2>&1 || true
    sudo -n sysctl -w net.core.wmem_max=33554432 >/dev/null 2>&1 || true
    sudo -n sysctl -w net.core.rmem_default=33554432 >/dev/null 2>&1 || true
    sudo -n sysctl -w net.core.wmem_default=33554432 >/dev/null 2>&1 || true
    sudo -n pkill -x mock_dns_server 2>/dev/null || true
    sleep 1
    sudo -n nohup taskset -c 11 ${CLIENT_BASE_DIR}/tests/mock_dns_server ${CLIENT_IP} 53 </dev/null >/tmp/mock_dns.log 2>&1 &
    sleep 1
"

for MODE in "${MODES[@]}"; do
    echo
    echo "=========================================================================================="
    echo "▶ PREPARANDO MODO: ${MODE} (1 CORE = CORE 0)"
    echo "=========================================================================================="

    # Verifica se o modo já está 100% concluído no CSV
    DONE_COUNT=$(awk -F',' -v m="${MODE}" '$1 == m {count++} END {print count+0}' "${RAW_CSV}")
    TOTAL_EXPECTED=$(( ${#RATES[@]} * REPS ))
    if [ "${DONE_COUNT}" -ge "${TOTAL_EXPECTED}" ]; then
        echo "   [SKIP] Modo ${MODE} já possui todas as ${DONE_COUNT}/${TOTAL_EXPECTED} execuções no CSV. Pulando para o próximo..."
        continue
    fi

    # 1. Limpa processos e estado anterior no servidor (SEM rmmod nfp!)
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
    sudo -n pkill -9 -f '[o]verload_governor.py' 2>/dev/null || true
    sudo -n systemctl stop unbound 2>/dev/null || sudo -n pkill -9 unbound 2>/dev/null || true

    cd "${SERVER_BASE_DIR}"
    sudo -n make unload-hw 2>/dev/null || true
    sudo -n tc qdisc del dev "${SERVER_IFACE}" clsact 2>/dev/null || true
    sudo -n bpftool net detach xdp dev "${SERVER_IFACE}" 2>/dev/null || true
    sudo -n rm -f /sys/fs/bpf/dns_misses /sys/fs/bpf/overload_ctrl /sys/fs/bpf/hw_sync_ringbuf /sys/fs/bpf/level_one_cache /sys/fs/bpf/time_map /sys/fs/bpf/xdp_prog

    # 2. Configura interface com exatamente 1 fila combinada (Core 0)
    sudo -n ip link set dev "${SERVER_IFACE}" down
    sleep 1
    sudo -n ip link set dev "${SERVER_IFACE}" up
    sudo -n ethtool -L "${SERVER_IFACE}" rx 0 tx 0 combined 1 2>/dev/null || sudo -n ethtool -L "${SERVER_IFACE}" combined 1 2>/dev/null || true
    sudo -n ethtool -K "${SERVER_IFACE}" rxhash on gro off lro off tso off gso off 2>/dev/null || true
    sudo -n systemctl stop irqbalance 2>/dev/null || true

    RXTX_IRQ=$(grep "${SERVER_IFACE}-rxtx-" /proc/interrupts | head -n 1 | awk -F: '{print $1}' | tr -d ' ')
    if [ -n "${RXTX_IRQ}" ]; then
        echo 1 | sudo -n tee "/proc/irq/${RXTX_IRQ}/smp_affinity" >/dev/null || true
        echo "   • Fila ${SERVER_IFACE}-rxtx-0 (IRQ ${RXTX_IRQ}) fixada no Core 0 (smp_affinity=1)"
    fi

    sudo -n ip addr flush dev "${SERVER_IFACE}"
    sudo -n ip addr add "${SERVER_IP}/24" dev "${SERVER_IFACE}"
    sleep 2

    # Verifica ping
    for i in {1..10}; do
        if ping -c 1 -W 1 "${CLIENT_IP}" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done

    # 3. Inicia daemons do modo selecionado (todos fixados no Core 0)
    case "${MODE}" in
      "unbound_standalone")
        echo "   [Daemon] Iniciando Unbound Standalone (1 Thread no Core 0)..."
        sudo -n systemctl restart unbound
        sleep 1
        pgrep -x unbound | xargs -r -n1 sudo -n taskset -cp 0 >/dev/null 2>&1 || true
        sleep 2
        ;;

      "unbound_hw_cache")
        echo "   [SmartNIC] Carregando XDP Offload (obj/dns_xdp_hw.o)..."
        sudo -n make load-hw
        sleep 2
        echo "   [Daemon] Iniciando DNS Listener (Core 0)..."
        tmux new-session -d -s listener "sudo -n taskset -c 0 ./bin/dns_listener -i ${SERVER_IFACE} -v"
        sleep 2
        echo "   [Daemon] Iniciando Control-Plane Daemon (Core 0)..."
        tmux new-session -d -s hw "sudo -n taskset -c 0 ./bin/atesnds_daemon -v"
        sleep 2
        echo "   [Daemon] Iniciando Unbound (1 Thread no Core 0)..."
        sudo -n systemctl restart unbound
        sleep 1
        pgrep -x unbound | xargs -r -n1 sudo -n taskset -cp 0 >/dev/null 2>&1 || true
        sleep 2
        ;;

      "ates_driver")
        echo "   [Daemon] Iniciando Unbound Fallback (Core 0)..."
        sudo -n systemctl restart unbound
        sleep 1
        pgrep -x unbound | xargs -r -n1 sudo -n taskset -cp 0 >/dev/null 2>&1 || true
        sleep 1
        echo "   [Daemon] Iniciando AtesN-DS Driver Mode (Core 0)..."
        tmux new-session -d -s ates "sudo -n taskset -c 0 ./bin/atesnds -a ${SERVER_IP} -i ${SERVER_IFACE} -m ${CLIENT_MAC} -s ${CLIENT_IP} -v"
        sleep 3
        sudo -n python3 tests/manage_overload.py normal 2>/dev/null || true
        ;;

      "ates_hw_cache")
        echo "   [SmartNIC] Carregando XDP Offload (obj/dns_xdp_hw.o)..."
        sudo -n make load-hw
        sleep 2
        echo "   [Daemon] Iniciando AtesN-DS com HW Cache (Core 0)..."
        tmux new-session -d -s ates "sudo -n taskset -c 0 ./bin/atesnds -a ${SERVER_IP} -i ${SERVER_IFACE} -m ${CLIENT_MAC} -s ${CLIENT_IP} -v"
        sleep 3
        echo "   [Daemon] Iniciando Control-Plane Daemon (Core 0)..."
        tmux new-session -d -s hw "sudo -n taskset -c 0 ./bin/atesnds_daemon -v"
        sleep 2
        echo "   [Daemon] Iniciando Unbound Fallback (Core 0)..."
        sudo -n systemctl restart unbound
        sleep 1
        pgrep -x unbound | xargs -r -n1 sudo -n taskset -cp 0 >/dev/null 2>&1 || true
        sleep 1
        sudo -n python3 tests/manage_overload.py normal 2>/dev/null || true
        ;;
    esac

    # 4. Warmup completo: primeiro os Top 32.768 domínios <=56B para a SRAM da SmartNIC (a 3k QPS suaves), depois todos os 83.659 para o cache do Host
    echo "-> Executando Warmup completo (Top 32.768 na SRAM da SmartNIC + 83.659 domínios únicos no Host)..."
    ssh -o StrictHostKeyChecking=no "${CLIENT_USER}@${CLIENT_MGMT_IP}" "
        dnsperf -s ${SERVER_IP} -d ${CLIENT_BASE_DIR}/tests/isp_top32k_hw_warmup_dnsperf.txt -n 1 -c 64 -T 4 -q 2000 -Q 3000 -b 16384 -e -E 10:11223344556677889900aabb >/dev/null 2>&1 || true
        dnsperf -s ${SERVER_IP} -d ${CLIENT_ISP_WARMUP} -n 1 -c 256 -T 8 -q 10000 -Q 20000 -b 16384 -e -E 10:11223344556677889900aabb >/dev/null 2>&1 || true
    "
    sleep 3
    echo "   • Warmup concluído! (Sem bpftool map dump para evitar bloqueio do CMSG mailbox da NFP)"

    # 5. Loop pelos níveis de QPS e 3 repetições
    for RATE in "${RATES[@]}"; do
        RATE_LABEL="${RATE}"
        if [ "${RATE}" -eq 0 ]; then
            RATE_LABEL="UNLIMITED"
        fi

        for REP in $(seq 1 "${REPS}"); do
            if grep -q "^${MODE},${RATE_LABEL},${REP}," "${RAW_CSV}" 2>/dev/null; then
                echo "   [SKIP] ${MODE} | Target=${RATE_LABEL} | Rep ${REP}/${REPS} já concluído no CSV."
                continue
            fi

            echo "   [${MODE}] Target=${RATE_LABEL} QPS | Repetição ${REP}/${REPS} (${DURATION}s)..."

            # Snapshot Pré-Execução no Servidor
            ETH_PRE=$(sudo -n ethtool -S "${SERVER_IFACE}" 2>/dev/null)
            HW_TX_START=$(echo "${ETH_PRE}" | awk '/bpf_app2_pkts/ {print $2; f=1} END {if(!f) print 0}')
            PASS_START=$(echo "${ETH_PRE}" | awk '/bpf_pass_pkts/ {print $2; f=1} END {if(!f) print 0}')
            RX_DISC_START=$(echo "${ETH_PRE}" | awk '/rx_discards/ {print $2; f=1} END {if(!f) print 0}')
            TX_DISC_START=$(echo "${ETH_PRE}" | awk '/tx_discards/ {print $2; f=1} END {if(!f) print 0}')
            RX_ERR_START=$(echo "${ETH_PRE}" | awk '/mac\.rx_errors/ {print $2; f=1} END {if(!f) print 0}')
            UB_Q_START=$(sudo -n unbound-control stats_noreset 2>/dev/null | awk -F'=' '/^total.num.queries=/ {print $2; f=1} END {if(!f) print 0}')
            IRQ_START=$(awk -v iface="${SERVER_IFACE}-rxtx-" '$0 ~ iface {sum += $2+$3+$4+$5+$6+$7} END {print sum+0}' /proc/interrupts)

            # Inicia mpstat no Servidor (1s x DURATION)
            SRV_MPSTAT_LOG="${OUT_DIR}/logs/srv_mpstat_${MODE}_${RATE_LABEL}_rep${REP}.txt"
            LC_ALL=C mpstat -P ALL 1 "${DURATION}" > "${SRV_MPSTAT_LOG}" 2>&1 &
            SRV_MPSTAT_PID=$!

            # Executa no Cliente (com mpstat do cliente e contador UDP drops)
            CLIENT_RUN_OUT=$(ssh -o StrictHostKeyChecking=no "${CLIENT_USER}@${CLIENT_MGMT_IP}" "
                UDP_START=\$(awk '/^Udp:/ {vals=\$6} END {print vals+0}' /proc/net/snmp)
                LC_ALL=C mpstat -P ALL 1 ${DURATION} > /tmp/cl_mpstat.txt 2>&1 &
                MP_PID=\$!
                BENCH_CSV=\$(python3 ${CLIENT_BENCH_SCRIPT} \
                    --server ${SERVER_IP} \
                    --duration ${DURATION} \
                    --concurrency ${CONCURRENCY} \
                    --threads ${THREADS} \
                    --rate ${RATE} \
                    --max-outstanding ${MAX_OUTSTANDING} \
                    --queries ${CLIENT_ISP_QUERIES} | tail -n 1)
                wait \$MP_PID 2>/dev/null || true
                UDP_END=\$(awk '/^Udp:/ {vals=\$6} END {print vals+0}' /proc/net/snmp)
                UDP_DROPS=\$((UDP_END - UDP_START))
                if [ \$UDP_DROPS -lt 0 ]; then UDP_DROPS=0; fi
                CL_CPU=\$(awk '/^Average:/ {
                    if (\$2 == \"all\") { busy = 100.0 - \$12 }
                    else if (\$2 ~ /^[0-9]+\$/) { b = 100.0 - \$12; if (b > maxc) maxc = b }
                } END { printf \"%.2f,%.2f\", busy, maxc }' /tmp/cl_mpstat.txt)
                echo \"\${BENCH_CSV},\${CL_CPU},\${UDP_DROPS}\"
            ")

            wait "${SRV_MPSTAT_PID}" 2>/dev/null || true

            # Snapshot Pós-Execução no Servidor
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

            # Extrai CPU do Core 0 no Servidor
            SRV_CORE0_CSV=$(awk '/^Average:/ && $2 == "0" {
                usr=$3; sys=$5; soft=$8; idle=$12; busy=100.0-idle;
                printf "%.2f,%.2f,%.2f,%.2f,%.2f", usr, sys, soft, idle, busy
            }' "${SRV_MPSTAT_LOG}")
            if [ -z "${SRV_CORE0_CSV}" ]; then
                SRV_CORE0_CSV="0.00,0.00,0.00,100.00,0.00"
            fi

            # Parse da linha do cliente:
            # totalRequests,totalSuccessResponses,queriesPerSecond,latency_mean_ms,latency_p50_ms,latency_p75_ms,latency_p90_ms,latency_p95_ms,latency_p99_ms,latency_p99_9_ms,latency_min_ms,latency_max_ms,latency_std_ms,packet_loss_pct,queries_lost,targetRate,cl_busy,cl_maxc,cl_drops
            IFS=',' read -r tot_req tot_ans qps lat_mean lat_p50 lat_p75 lat_p90 lat_p95 lat_p99 lat_p99_9 lat_min lat_max lat_std loss_pct loss_cnt trgt cl_busy cl_maxc cl_drops <<< "${CLIENT_RUN_OUT}"

            case "${MODE}" in
              "unbound_standalone")
                HW_HITS=0
                DRV_HITS=0
                USR_HITS="${tot_ans}"
                HW_HIT_RATE="0.00"
                ;;
              "unbound_hw_cache")
                HW_HITS="${DELTA_HW}"
                if [ "${HW_HITS}" -gt "${tot_ans}" ]; then HW_HITS="${tot_ans}"; fi
                DRV_HITS=0
                USR_HITS=$((tot_ans - HW_HITS))
                HW_HIT_RATE=$(awk -v h="${HW_HITS}" -v t="${tot_ans}" 'BEGIN {if(t>0) printf "%.2f", (h/t)*100.0; else print "0.00"}')
                ;;
              "ates_driver")
                HW_HITS=0
                USR_HITS="${DELTA_UB}"
                if [ "${USR_HITS}" -gt "${tot_ans}" ]; then USR_HITS="${tot_ans}"; fi
                DRV_HITS=$((tot_ans - USR_HITS))
                HW_HIT_RATE="0.00"
                ;;
              "ates_hw_cache")
                HW_HITS="${DELTA_HW}"
                if [ "${HW_HITS}" -gt "${tot_ans}" ]; then HW_HITS="${tot_ans}"; fi
                USR_HITS="${DELTA_UB}"
                if [ $((HW_HITS + USR_HITS)) -gt "${tot_ans}" ]; then
                    USR_HITS=$((tot_ans - HW_HITS))
                fi
                DRV_HITS=$((tot_ans - HW_HITS - USR_HITS))
                HW_HIT_RATE=$(awk -v h="${HW_HITS}" -v t="${tot_ans}" 'BEGIN {if(t>0) printf "%.2f", (h/t)*100.0; else print "0.00"}')
                ;;
            esac

            echo "${MODE},${RATE_LABEL},${REP},${tot_req},${tot_ans},${loss_cnt},${loss_pct},${qps},${lat_mean},${lat_min},${lat_max},${lat_std},${lat_p50},${lat_p75},${lat_p90},${lat_p95},${lat_p99},${lat_p99_9},${HW_HITS},${DELTA_PASS},${DRV_HITS},${USR_HITS},${HW_HIT_RATE},${DELTA_RX_DISC},${DELTA_TX_DISC},${DELTA_RX_ERR},${DELTA_IRQ},${SRV_CORE0_CSV},${cl_busy},${cl_maxc},${cl_drops}" >> "${RAW_CSV}"

            printf "      -> QPS=%s | Loss=%s%% | Mean=%sms (p99=%sms) | HW_Hit=%s%% | Core0_Busy=%s%%\n" \
                "${qps}" "${loss_pct}" "${lat_mean}" "${lat_p99}" "${HW_HIT_RATE}" "$(echo "${SRV_CORE0_CSV}" | awk -F',' '{print $5}')"
            sleep 1
        done
    done
done

echo
echo "-> Gerando tabela agregada (Média ± Desvio Padrão das 3 repetições) em ${SUMMARY_CSV}..."
python3 - << 'PYEOF'
import csv
import numpy as np
from collections import defaultdict

raw_csv = "/home/joaosoares/Documents/Github/AtesN-DS/official_results/03_server_benchmarks/raw_1core_qps_sweep_3reps.csv"
sum_csv = "/home/joaosoares/Documents/Github/AtesN-DS/official_results/03_server_benchmarks/summary_1core_qps_sweep.csv"

groups = defaultdict(list)
with open(raw_csv, "r") as f:
    reader = csv.DictReader(f)
    for row in reader:
        key = (row["mode"], row["target_qps"])
        groups[key].append(row)

num_cols = [
    "queries_sent", "queries_completed", "queries_lost", "packet_loss_pct", "achieved_qps",
    "lat_mean_ms", "lat_min_ms", "lat_max_ms", "lat_std_ms",
    "lat_p50_ms", "lat_p75_ms", "lat_p90_ms", "lat_p95_ms", "lat_p99_ms", "lat_p99_9_ms",
    "hw_cache_hits", "hw_pass_pkts", "driver_hits", "userspace_hits", "hw_hit_rate_pct",
    "nic_rx_discards", "nic_tx_discards", "nic_rx_errors", "nic_irq_delta",
    "srv_core0_user_pct", "srv_core0_sys_pct", "srv_core0_softirq_pct", "srv_core0_idle_pct", "srv_core0_busy_pct",
    "client_cpu_busy_pct", "client_max_core_pct", "client_udp_drops"
]

out_fields = ["mode", "target_qps", "reps"]
for c in num_cols:
    out_fields.extend([f"{c}_mean", f"{c}_std"])

with open(sum_csv, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=out_fields)
    writer.writeheader()
    for (mode, target_qps), rows in groups.items():
        out_row = {"mode": mode, "target_qps": target_qps, "reps": len(rows)}
        for c in num_cols:
            vals = [float(r[c]) for r in rows]
            out_row[f"{c}_mean"] = f"{np.mean(vals):.2f}"
            out_row[f"{c}_std"] = f"{np.std(vals):.2f}"
        writer.writerow(out_row)

print(f"Summary saved to {sum_csv}")
PYEOF

echo "✅ Bateria concluída com sucesso!"
