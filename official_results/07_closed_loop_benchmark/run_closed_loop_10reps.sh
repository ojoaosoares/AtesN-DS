#!/usr/bin/env bash
# ==============================================================================
# run_closed_loop_10reps.sh
#
# Closed-Loop Concurrency Benchmark (2 Dedicated Cores, 4 Queues, n=10 reps):
#   - Server Cores: Exactly 2 Dedicated Cores (0 and 1)
#   - NIC Queues: 4 combined queues on Netronome NFP-4000
#   - 4 Architectural Modes:
#       1) unbound_standalone (Unbound in User Space on Cores 0,1)
#       2) ates_driver        (AtesN-DS XDP Driver Mode + Unbound Fallback)
#       3) unbound_hw_cache   (Unbound + Decoupled Listener + SmartNIC HW Cache)
#       4) ates_hw_cache      (AtesN-DS Hybrid XDP Driver + SmartNIC HW Cache)
#   - Concurrency Windows (In-Flight Queries):
#       W in (16 64 256 512 1024 2048)
#   - Client: xdnsperf in Closed-Loop Mode (-W <window>, 4 AF_XDP workers)
#   - Workload Replay: isp_queries_2m_dnsperf.txt (2M real production ISP trace)
#   - Warmup: isp_bench_warmup_xdnsperf.txt (Pre-populates SmartNIC SRAM & Caches)
#   - Repetitions: 10 independent runs per level (n=10)
#   - Duration: 30s per repetition
# ==============================================================================

set -euo pipefail
export LC_ALL=C

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

NUM_CORES=2
SERVER_CORES="0,1"
SERVER_TASKSET="0,1"
AFFINITY_MASK="3"

MODES_TO_TEST=("unbound_standalone" "ates_driver" "unbound_hw_cache" "ates_hw_cache")
if [ $# -ge 1 ] && [ -n "$1" ] && [ "$1" != "all" ]; then
    IFS=' ' read -r -a MODES_TO_TEST <<< "$1"
fi

WINDOWS=(16 64 256 512 1024 2048 4096 8192 16384 32768 65536)
if [ $# -ge 2 ] && [ -n "$2" ]; then
    IFS=' ' read -r -a WINDOWS <<< "$2"
fi

REPS=${REPS:-10}
DURATION=${DURATION:-30}
CLIENT_WORKERS=4

RAW_CSV="${RAW_CSV:-${OUT_DIR}/raw_closed_loop_10reps.csv}"
SUMMARY_CSV="${SUMMARY_CSV:-${OUT_DIR}/summary_closed_loop_10reps.csv}"
mkdir -p "${OUT_DIR}/logs"

if [ ! -f "${RAW_CSV}" ]; then
    echo "num_cores,mode,window,rep,queries_sent,queries_completed,queries_lost,packet_loss_pct,achieved_qps,lat_mean_ms,lat_p50_ms,lat_p75_ms,lat_p90_ms,lat_p95_ms,lat_p99_ms,lat_p99_9_ms,lat_min_ms,lat_max_ms,lat_std_ms,hw_cache_hits,hw_pass_pkts,driver_hits,userspace_hits,hw_hit_rate_pct,nic_rx_discards,nic_tx_discards,nic_rx_errors,nic_irq_delta,srv_c0_busy,srv_c1_busy,srv_c2_busy,srv_c3_busy,srv_all_busy,srv_softirq,client_cpu_busy" > "${RAW_CSV}"
fi

generate_summary() {
    python3 - << 'PYEOF'
import csv
from collections import defaultdict
import numpy as np
import os

raw_path = os.environ.get("RAW_CSV", "official_results/07_closed_loop_benchmark/raw_closed_loop_10reps.csv")
summary_path = os.environ.get("SUMMARY_CSV", "official_results/07_closed_loop_benchmark/summary_closed_loop_10reps.csv")

if not os.path.exists(raw_path):
    exit(0)

data = defaultdict(list)
with open(raw_path, 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        key = (row['num_cores'], row['mode'], int(row['window']))
        data[key].append(row)

with open(summary_path, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow([
        "num_cores", "mode", "window", "reps",
        "achieved_qps_mean", "achieved_qps_std",
        "loss_pct_mean", "loss_pct_std",
        "lat_mean_ms", "lat_p50_ms", "lat_p90_ms", "lat_p99_ms", "lat_p99_9_ms",
        "hw_cache_hits_mean", "driver_hits_mean", "userspace_hits_mean",
        "true_hw_hit_rate_pct",
        "srv_c0_busy_mean", "srv_c1_busy_mean", "srv_all_busy_mean", "srv_softirq_mean", "client_cpu_busy_mean"
    ])

    for (cores, mode, window), rows in sorted(data.items()):
        qps_vals = [float(r['achieved_qps']) for r in rows]
        loss_vals = [float(r['packet_loss_pct']) for r in rows]
        lat_mean_vals = [float(r['lat_mean_ms']) for r in rows]
        lat_p50_vals = [float(r['lat_p50_ms']) for r in rows]
        lat_p90_vals = [float(r['lat_p90_ms']) for r in rows]
        lat_p99_vals = [float(r['lat_p99_ms']) for r in rows]
        lat_p999_vals = [float(r['lat_p99_9_ms']) for r in rows]
        hw_hits_vals = [float(r['hw_cache_hits']) for r in rows]
        sent_vals = [float(r['queries_sent']) for r in rows]
        drv_hits_vals = [float(r['driver_hits']) for r in rows]
        usr_hits_vals = [float(r['userspace_hits']) for r in rows]
        
        # True Ingress Hit Rate: HW_hits / queries_sent
        true_hits = [(h / s * 100.0) if s > 0 else 0.0 for h, s in zip(hw_hits_vals, sent_vals)]
        
        c0_vals = [float(r['srv_c0_busy']) for r in rows]
        c1_vals = [float(r['srv_c1_busy']) for r in rows]
        all_vals = [float(r['srv_all_busy']) for r in rows]
        soft_vals = [float(r.get('srv_softirq', 0.0)) for r in rows]
        cli_vals = [float(r.get('client_cpu_busy', 0.0)) for r in rows]

        writer.writerow([
            cores, mode, window, len(rows),
            f"{np.mean(qps_vals):.0f}", f"{np.std(qps_vals):.0f}",
            f"{np.mean(loss_vals):.2f}", f"{np.std(loss_vals):.2f}",
            f"{np.mean(lat_mean_vals):.3f}", f"{np.mean(lat_p50_vals):.3f}", f"{np.mean(lat_p90_vals):.3f}",
            f"{np.mean(lat_p99_vals):.3f}", f"{np.mean(lat_p999_vals):.3f}",
            f"{np.mean(hw_hits_vals):.0f}", f"{np.mean(drv_hits_vals):.0f}", f"{np.mean(usr_hits_vals):.0f}",
            f"{np.mean(true_hits):.2f}",
            f"{np.mean(c0_vals):.1f}", f"{np.mean(c1_vals):.1f}",
            f"{np.mean(all_vals):.1f}", f"{np.mean(soft_vals):.1f}", f"{np.mean(cli_vals):.1f}"
        ])
PYEOF
    export SUMMARY_CSV RAW_CSV
    python3 "${OUT_DIR}/plot_closed_loop_ccdf.py" >/dev/null 2>&1 || true
}

reset_clean_and_warmup() {
    local MODE="$1"
    echo "   [RESET] 1. Matando daemons antigos..."
    sudo -n killall -9 atesnds atesnds_daemon dns_listener 2>/dev/null || true
    sudo -n pkill -9 -x "atesnds|atesnds_daemon|dns_listener" 2>/dev/null || true

    echo "   [RESET] 2. Desanexando XDP Offload / Driver e destruindo mapas BPF..."
    sudo -n tc qdisc del dev "${SERVER_IFACE}" clsact 2>/dev/null || true
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
echo "🚀 INICIANDO BENCHMARK CLOSED-LOOP (2 CORES, 4 FILAS NIC, REPS=${REPS}, DURATION=${DURATION}s)"
echo "Cores de Servidor: 2 (Cores ${SERVER_TASKSET})"
echo "Filas SmartNIC: 4 combinadas"
echo "Modos: ${MODES_TO_TEST[*]}"
echo "Janelas de Concorrência (W): ${WINDOWS[*]}"
echo "Warmup: Pre-população com EDNS0 Cookie via xdnsperf"
echo "Trace de Carga: isp_queries_2m_dnsperf.txt (2M queries reais)"
echo "Cliente: xdnsperf Closed-Loop (${CLIENT_WORKERS} workers AF_XDP, -W <window>)"
echo "Arquivo de saída: ${RAW_CSV}"
echo "=========================================================================================="

echo "-> [Client Prep] Garantindo mock_dns_server e interface no cliente..."
ssh -o StrictHostKeyChecking=no "${CLIENT_USER}@${CLIENT_MGMT_IP}" "
    sudo -n ip link set dev ${CLIENT_IFACE} up 2>/dev/null || true
    sudo -n ip addr replace ${CLIENT_IP}/24 dev ${CLIENT_IFACE} 2>/dev/null || true
    sudo -n sysctl -w net.core.rmem_max=67108864 >/dev/null 2>&1 || true
    sudo -n sysctl -w net.core.wmem_max=67108864 >/dev/null 2>&1 || true
    sudo -n pkill -x mock_dns_server 2>/dev/null || true
    sleep 1
    sudo -n nohup taskset -c 11 ${CLIENT_BASE_DIR}/tests/mock_dns_server ${CLIENT_IP} 53 </dev/null >/tmp/mock_dns.log 2>&1 &
    sleep 1
"

# Configuração Unbound 2 Cores
sudo -n tee /etc/unbound/unbound.conf > /dev/null << 'EOF'
server:
    interface: 192.168.0.1
    interface: 127.0.0.1
    port: 53
    outgoing-interface: 192.168.0.1
    access-control: 0.0.0.0/0 allow
    verbosity: 0
    num-threads: 2
    msg-cache-slabs: 2
    rrset-cache-slabs: 2
    infra-cache-slabs: 2
    key-cache-slabs: 2
    msg-cache-size: 512m
    rrset-cache-size: 1g
    outgoing-range: 8192
    num-queries-per-thread: 4096
    infra-cache-numhosts: 100000
    so-rcvbuf: 32m
    so-sndbuf: 32m
    so-reuseport: yes
    cache-min-ttl: 0
    cache-max-ttl: 86400
    module-config: "iterator"

forward-zone:
    name: "."
    forward-addr: 192.168.0.2

remote-control:
    control-enable: yes
EOF

# Configuração NIC: 4 filas e afinidade
sudo -n ip link set dev "${SERVER_IFACE}" down
sleep 1
sudo -n ip link set dev "${SERVER_IFACE}" up
sudo -n ethtool -L "${SERVER_IFACE}" rx 0 tx 0 combined 4 2>/dev/null || sudo -n ethtool -L "${SERVER_IFACE}" combined 4 2>/dev/null || true
sudo -n ethtool -K "${SERVER_IFACE}" rxhash on gro off lro off tso off gso off 2>/dev/null || true
sudo -n systemctl stop irqbalance 2>/dev/null || true

IRQS=($(grep "${SERVER_IFACE}-rxtx-" /proc/interrupts | awk -F: '{print $1}' | tr -d ' '))
if [ "${#IRQS[@]}" -ge 4 ]; then
    echo 1 | sudo -n tee "/proc/irq/${IRQS[0]}/smp_affinity" >/dev/null || true
    echo 2 | sudo -n tee "/proc/irq/${IRQS[1]}/smp_affinity" >/dev/null || true
    echo 1 | sudo -n tee "/proc/irq/${IRQS[2]}/smp_affinity" >/dev/null || true
    echo 2 | sudo -n tee "/proc/irq/${IRQS[3]}/smp_affinity" >/dev/null || true
elif [ "${#IRQS[@]}" -gt 0 ]; then
    for irq in "${IRQS[@]}"; do
        echo "${AFFINITY_MASK}" | sudo -n tee "/proc/irq/${irq}/smp_affinity" >/dev/null || true
    done
fi

sudo -n ip addr flush dev "${SERVER_IFACE}"
sudo -n ip addr add "${SERVER_IP}/24" dev "${SERVER_IFACE}"
sleep 2

ssh -o StrictHostKeyChecking=no "${CLIENT_USER}@${CLIENT_MGMT_IP}" "
    sudo -n ip link set dev ${CLIENT_IFACE} up
    sudo -n ip addr replace ${CLIENT_IP}/24 dev ${CLIENT_IFACE}
    sudo -n arp -s ${SERVER_IP} ${SERVER_MAC} 2>/dev/null || true
"
sudo -n arp -s "${CLIENT_IP}" "${CLIENT_MAC}" 2>/dev/null || true

for i in {1..10}; do
    if ping -c 1 -W 1 "${CLIENT_IP}" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

for MODE in "${MODES_TO_TEST[@]}"; do
    for WIN in "${WINDOWS[@]}"; do
        for REP in $(seq 1 "${REPS}"); do
            if grep -q "^2,${MODE},${WIN},${REP}," "${RAW_CSV}" 2>/dev/null; then
                echo "   [SKIP] 2 Cores | ${MODE} | Window=${WIN} | Rep ${REP}/${REPS} já no CSV."
                continue
            fi

            echo
            echo "======================================================================================"
            echo "▶ PREPARANDO CLOSED-LOOP: Modo=${MODE} | Window=${WIN} | Rep ${REP}/${REPS}"
            echo "======================================================================================"
            reset_clean_and_warmup "${MODE}"

            echo "   • Executando Teste Closed-Loop: ${DURATION}s..."

            ETH_PRE=$(sudo -n ethtool -S "${SERVER_IFACE}" 2>/dev/null)
            HW_TX_START=$(echo "${ETH_PRE}" | awk '/bpf_app2_pkts/ {print $2; f=1} END {if(!f) print 0}')
            PASS_START=$(echo "${ETH_PRE}" | awk '/bpf_pass_pkts/ {print $2; f=1} END {if(!f) print 0}')
            RX_DISC_START=$(echo "${ETH_PRE}" | awk '/rx_discards/ {print $2; f=1} END {if(!f) print 0}')
            TX_DISC_START=$(echo "${ETH_PRE}" | awk '/tx_discards/ {print $2; f=1} END {if(!f) print 0}')
            RX_ERR_START=$(echo "${ETH_PRE}" | awk '/mac\.rx_errors/ {print $2; f=1} END {if(!f) print 0}')
            UB_Q_START=$( (sudo -n unbound-control stats_noreset 2>/dev/null || true) | awk -F'=' '/^total.num.queries=/ {print $2; f=1} END {if(!f) print 0}')
            IRQ_START=$(awk -v iface="${SERVER_IFACE}-rxtx-" '$0 ~ iface {sum += $2+$3+$4+$5+$6+$7} END {print sum+0}' /proc/interrupts)

            SRV_MPSTAT_LOG="${OUT_DIR}/logs/srv_mpstat_closed_loop_${MODE}_w${WIN}_rep${REP}.txt"
            LC_ALL=C mpstat -P ALL 1 "${DURATION}" > "${SRV_MPSTAT_LOG}" 2>&1 &
            SRV_MPSTAT_PID=$!

            # Dispara xdnsperf no modo Closed-Loop (-W ${WIN})
            CLIENT_RAW=$(ssh -o StrictHostKeyChecking=no "${CLIENT_USER}@${CLIENT_MGMT_IP}" "
                LC_ALL=C mpstat 1 ${DURATION} > /tmp/client_mpstat.txt 2>&1 &
                CLI_MPSTAT_PID=\$!
                sudo -n ${CLIENT_XDNSPERF_DIR}/bin/xdnsperf \
                    -i ${CLIENT_IFACE} \
                    -s ${SERVER_IP} \
                    -c ${CLIENT_WORKERS} \
                    -d ${DURATION} \
                    -W ${WIN} \
                    --busy-wait \
                    -f ${CLIENT_BENCH_TRACE} \
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
            UB_Q_END=$( (sudo -n unbound-control stats_noreset 2>/dev/null || true) | awk -F'=' '/^total.num.queries=/ {print $2; f=1} END {if(!f) print 0}')
            IRQ_END=$(awk -v iface="${SERVER_IFACE}-rxtx-" '$0 ~ iface {sum += $2+$3+$4+$5+$6+$7} END {print sum+0}' /proc/interrupts)

            DELTA_HW=$((HW_TX_END - HW_TX_START)); [ "${DELTA_HW}" -lt 0 ] && DELTA_HW=0 || true
            DELTA_PASS=$((PASS_END - PASS_START)); [ "${DELTA_PASS}" -lt 0 ] && DELTA_PASS=0 || true
            DELTA_RX_DISC=$((RX_DISC_END - RX_DISC_START)); [ "${DELTA_RX_DISC}" -lt 0 ] && DELTA_RX_DISC=0 || true
            DELTA_TX_DISC=$((TX_DISC_END - TX_DISC_START)); [ "${DELTA_TX_DISC}" -lt 0 ] && DELTA_TX_DISC=0 || true
            DELTA_RX_ERR=$((RX_ERR_END - RX_ERR_START)); [ "${DELTA_RX_ERR}" -lt 0 ] && DELTA_RX_ERR=0 || true
            DELTA_UB=$((UB_Q_END - UB_Q_START)); [ "${DELTA_UB}" -lt 0 ] && DELTA_UB=0 || true
            DELTA_IRQ=$((IRQ_END - IRQ_START)); [ "${DELTA_IRQ}" -lt 0 ] && DELTA_IRQ=0 || true

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
                HW_HIT_RATE=$(awk -v h="${HW_HITS}" -v t="${tot_req}" 'BEGIN {if(t>0) printf "%.2f", (h/t)*100.0; else print "0.00"}')
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
                HW_HIT_RATE=$(awk -v h="${HW_HITS}" -v t="${tot_req}" 'BEGIN {if(t>0) printf "%.2f", (h/t)*100.0; else print "0.00"}')
                ;;
            esac

            echo "2,${MODE},${WIN},${REP},${tot_req},${tot_ans},${loss_cnt},${loss_pct},${qps},${lat_mean},${lat_p50},${lat_p75},${lat_p90},${lat_p95},${lat_p99},${lat_p99_9},${lat_min},${lat_max},${lat_std},${HW_HITS},${DELTA_PASS},${DRV_HITS},${USR_HITS},${HW_HIT_RATE},${DELTA_RX_DISC},${DELTA_TX_DISC},${DELTA_RX_ERR},${DELTA_IRQ},${SRV_C0},${SRV_C1},${SRV_C2},${SRV_C3},${SRV_ALL},${SRV_SOFT},${CLIENT_CPU}" >> "${RAW_CSV}"

            printf "      -> QPS=%s | Loss=%s%% | Lat_p99=%sms (p50=%sms) | HW_Hit=%s%% | Srv_All=%.1f%% (C0=%.1f%% C1=%.1f%%) | Cli_CPU=%s%%\n" \
                "${qps}" "${loss_pct}" "${lat_p99}" "${lat_p50}" "${HW_HIT_RATE}" "${SRV_ALL}" "${SRV_C0}" "${SRV_C1}" "${CLIENT_CPU}"

            sleep 2
        done
        echo "   -> [Checkpoint] Atualizando resumo estatístico e gráficos após janela W=${WIN}..."
        generate_summary
    done
done

echo
echo "-> Gerando resumo estatístico final agregado em ${SUMMARY_CSV}..."
generate_summary

echo "=========================================================================================="
echo "✅ BENCHMARK CLOSED-LOOP (2 CORES, ${REPS} REPS, ${DURATION}s) CONCLUÍDO COM SUCESSO!"
echo "Resultados brutos: ${RAW_CSV}"
echo "Resumo agregado:   ${SUMMARY_CSV}"
echo "=========================================================================================="
