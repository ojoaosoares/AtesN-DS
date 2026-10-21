#!/bin/bash
# ==============================================================================
# official_results/04_overload_fallback_study/run_fallback_study.sh
#
# Empirical Study: Impact of User-Space Fallback (XDP_PASS) Under Saturation
#
# Investigates what happens when AtesN-DS sheds/cascades queries to userspace:
#   Ratios: 0% (Pure Driver), 10%, 25%, 50%, 75%, 100% (Full Userspace Fallback)
#   Target Load: 250,000 QPS (exceeding userspace capacity of ~118k) and 400,000 QPS
#   Metrics: QPS, Loss%, Latency (Mean, p99), SoftIRQ%, Socket Buffer Drops, SKB allocs
# ==============================================================================

set -euo pipefail
export LC_ALL=C

SERVER_BASE_DIR="/home/joaosoares/Documents/Github/AtesN-DS"
OUT_DIR="${SERVER_BASE_DIR}/official_results/04_overload_fallback_study"
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

TARGET_LOADS=(250000 400000)
FALLBACK_RATIOS=(0 10 25 50 75 100)
REPS=2
DURATION=30
CONCURRENCY=512
THREADS=8
MAX_OUTSTANDING=20000

RAW_CSV="${OUT_DIR}/raw_fallback_penalty.csv"
SUMMARY_CSV="${OUT_DIR}/summary_fallback_penalty.csv"

if [ ! -f "${RAW_CSV}" ]; then
    echo "target_qps,fallback_ratio_pct,rep,queries_sent,queries_completed,queries_lost,packet_loss_pct,achieved_qps,lat_mean_ms,lat_min_ms,lat_max_ms,lat_std_ms,lat_p50_ms,lat_p75_ms,lat_p90_ms,lat_p95_ms,lat_p99_ms,lat_p99_9_ms,srv_core0_user_pct,srv_core0_sys_pct,srv_core0_softirq_pct,srv_core0_idle_pct,srv_core0_busy_pct,udp_rcvbuf_errors_delta,udp_in_errors_delta,skb_head_alloc_delta,client_cpu_busy_pct,client_max_core_pct,client_udp_drops" > "${RAW_CSV}"
fi

echo "=========================================================================================="
echo "🔬 ESTUDO EMPÍRICO: IMPACTO DO FALLBACK PARA USERSPACE (XDP_PASS) SOB ALTA CARGA"
echo "Cargas Alvo: ${TARGET_LOADS[*]} QPS"
echo "Frações de Fallback: ${FALLBACK_RATIOS[*]} %"
echo "Repetições por nível: ${REPS} | Duração por rep: ${DURATION}s"
echo "CSV de Saída: ${RAW_CSV}"
echo "=========================================================================================="

echo "-> Garantindo Mock Authoritative DNS Responder ativo no cliente (${CLIENT_IP}:53)..."
ssh -o StrictHostKeyChecking=no "${CLIENT_USER}@${CLIENT_MGMT_IP}" "
    sudo -n ip link set dev ${CLIENT_IFACE} up 2>/dev/null || true
    sudo -n ip addr replace ${CLIENT_IP}/24 dev ${CLIENT_IFACE} 2>/dev/null || true
    sudo -n sysctl -w net.core.rmem_max=33554432 >/dev/null 2>&1 || true
    sudo -n sysctl -w net.core.wmem_max=33554432 >/dev/null 2>&1 || true
    sudo -n pkill -x mock_dns_server 2>/dev/null || true
    sleep 1
    sudo -n nohup taskset -c 11 ${CLIENT_BASE_DIR}/tests/mock_dns_server ${CLIENT_IP} 53 </dev/null >/tmp/mock_dns.log 2>&1 &
    sleep 1
"

# 1. Limpa estado anterior no servidor
tmux kill-session -t srv 2>/dev/null || true
tmux kill-session -t ates 2>/dev/null || true
tmux kill-session -t hw 2>/dev/null || true
tmux kill-session -t listener 2>/dev/null || true
tmux kill-session -t unbound 2>/dev/null || true

sudo -n pkill atesnds 2>/dev/null || true
sudo -n pkill atesnds_daemon 2>/dev/null || true
sudo -n pkill dns_listener 2>/dev/null || true
sudo -n systemctl stop unbound 2>/dev/null || sudo -n pkill -9 unbound 2>/dev/null || true

cd "${SERVER_BASE_DIR}"
sudo -n make unload-hw 2>/dev/null || true
sudo -n tc qdisc del dev "${SERVER_IFACE}" clsact 2>/dev/null || true
sudo -n bpftool net detach xdp dev "${SERVER_IFACE}" 2>/dev/null || true
sudo -n rm -f /sys/fs/bpf/dns_misses /sys/fs/bpf/overload_ctrl /sys/fs/bpf/hw_sync_ringbuf /sys/fs/bpf/level_one_cache /sys/fs/bpf/time_map /sys/fs/bpf/xdp_prog

# 2. Configura interface com 1 fila (Core 0)
sudo -n ip link set dev "${SERVER_IFACE}" down
sleep 1
sudo -n ip link set dev "${SERVER_IFACE}" up
sudo -n ethtool -L "${SERVER_IFACE}" rx 0 tx 0 combined 1 2>/dev/null || sudo -n ethtool -L "${SERVER_IFACE}" combined 1 2>/dev/null || true
sudo -n ethtool -K "${SERVER_IFACE}" rxhash on gro off lro off tso off gso off 2>/dev/null || true
sudo -n systemctl stop irqbalance 2>/dev/null || true

RXTX_IRQ=$(grep "${SERVER_IFACE}-rxtx-" /proc/interrupts | head -n 1 | awk -F: '{print $1}' | tr -d ' ')
if [ -n "${RXTX_IRQ}" ]; then
    echo 1 | sudo -n tee "/proc/irq/${RXTX_IRQ}/smp_affinity" >/dev/null || true
fi

sudo -n ip addr flush dev "${SERVER_IFACE}"
sudo -n ip addr add "${SERVER_IP}/24" dev "${SERVER_IFACE}"
sleep 2

# 3. Inicia Unbound e AtesN-DS Driver Mode (Core 0)
echo "-> Iniciando Unbound Fallback (Core 0)..."
sudo -n systemctl restart unbound
sleep 1
pgrep -x unbound | xargs -r -n1 sudo -n taskset -cp 0 >/dev/null 2>&1 || true

echo "-> Iniciando AtesN-DS Driver Mode (Core 0)..."
tmux new-session -d -s ates "sudo -n taskset -c 0 ./bin/atesnds -a ${SERVER_IP} -i ${SERVER_IFACE} -m ${CLIENT_MAC} -s ${CLIENT_IP} -v"
sleep 3

# Warmup do cache do driver
echo "-> Aquecendo cache do driver AtesN-DS com domínios do trace..."
ssh -o StrictHostKeyChecking=no "${CLIENT_USER}@${CLIENT_MGMT_IP}" "
    dnsperf -s ${SERVER_IP} -d ${CLIENT_ISP_WARMUP} -n 1 -c 256 -T 8 -q 10000 -Q 25000 -b 16384 -e -E 10:11223344556677889900aabb >/dev/null 2>&1 || true
"
sleep 2

# Função para configurar a política de fallback
configure_fallback() {
    local ratio=$1
    if [ "${ratio}" -eq 0 ]; then
        sudo -n python3 tests/manage_overload.py normal >/dev/null 2>&1
    elif [ "${ratio}" -eq 100 ]; then
        sudo -n python3 tests/manage_overload.py early >/dev/null 2>&1
    else
        sudo -n python3 tests/manage_overload.py prop "${ratio}" >/dev/null 2>&1
    fi
    sleep 1
}

# Loop de testes
for TARGET_QPS in "${TARGET_LOADS[@]}"; do
    echo
    echo "=========================================================================================="
    echo "▶ CARGA ALVO FIXA: ${TARGET_QPS} QPS"
    echo "=========================================================================================="

    for RATIO in "${FALLBACK_RATIOS[@]}"; do
        configure_fallback "${RATIO}"

        for REP in $(seq 1 "${REPS}"); do
            if grep -q "^${TARGET_QPS},${RATIO},${REP}," "${RAW_CSV}" 2>/dev/null; then
                echo "   [SKIP] ${TARGET_QPS} QPS | Fallback=${RATIO}% | Rep ${REP}/${REPS} já no CSV."
                continue
            fi

            echo "   [Fallback ${RATIO}%] Target=${TARGET_QPS} QPS | Rep ${REP}/${REPS} (${DURATION}s)..."

            # Pre-snapshots de sistema
            UDP_RCV_START=$(awk '/^Udp:/ {val=$6} END {print val+0}' /proc/net/snmp)
            UDP_ERR_START=$(awk '/^Udp:/ {val=$4} END {print val+0}' /proc/net/snmp)
            SKB_START=$(awk '/^skbuff_head_cache/ {val=$2} END {print val+0}' /proc/slabinfo 2>/dev/null || echo 0)

            # Inicia monitoramento de CPU do Core 0
            MPSTAT_LOG="${OUT_DIR}/logs/mpstat_${TARGET_QPS}_ratio${RATIO}_rep${REP}.txt"
            LC_ALL=C mpstat -P ALL 1 "${DURATION}" > "${MPSTAT_LOG}" 2>&1 &
            MP_PID=$!

            # Execução no cliente
            CLIENT_RUN_OUT=$(ssh -o StrictHostKeyChecking=no "${CLIENT_USER}@${CLIENT_MGMT_IP}" "
                UDP_START=\$(awk '/^Udp:/ {vals=\$6} END {print vals+0}' /proc/net/snmp)
                LC_ALL=C mpstat -P ALL 1 ${DURATION} > /tmp/cl_mpstat.txt 2>&1 &
                CL_MP=\$!
                BENCH_CSV=\$(python3 ${CLIENT_BENCH_SCRIPT} \
                    --server ${SERVER_IP} \
                    --duration ${DURATION} \
                    --concurrency ${CONCURRENCY} \
                    --threads ${THREADS} \
                    --rate ${TARGET_QPS} \
                    --max-outstanding ${MAX_OUTSTANDING} \
                    --queries ${CLIENT_ISP_QUERIES} | tail -n 1)
                wait \$CL_MP 2>/dev/null || true
                UDP_END=\$(awk '/^Udp:/ {vals=\$6} END {print vals+0}' /proc/net/snmp)
                UDP_DROPS=\$((UDP_END - UDP_START))
                if [ \$UDP_DROPS -lt 0 ]; then UDP_DROPS=0; fi
                CL_CPU=\$(awk '/^Average:/ {
                    if (\$2 == \"all\") { busy = 100.0 - \$12 }
                    else if (\$2 ~ /^[0-9]+\$/) { b = 100.0 - \$12; if (b > maxc) maxc = b }
                } END { printf \"%.2f,%.2f\", busy, maxc }' /tmp/cl_mpstat.txt)
                echo \"\${BENCH_CSV},\${CL_CPU},\${UDP_DROPS}\"
            ")

            wait "${MP_PID}" 2>/dev/null || true

            # Post-snapshots de sistema
            UDP_RCV_END=$(awk '/^Udp:/ {val=$6} END {print val+0}' /proc/net/snmp)
            UDP_ERR_END=$(awk '/^Udp:/ {val=$4} END {print val+0}' /proc/net/snmp)
            SKB_END=$(awk '/^skbuff_head_cache/ {val=$2} END {print val+0}' /proc/slabinfo 2>/dev/null || echo 0)

            DELTA_RCVBUF=$((UDP_RCV_END - UDP_RCV_START)); [ "${DELTA_RCVBUF}" -lt 0 ] && DELTA_RCVBUF=0
            DELTA_INERR=$((UDP_ERR_END - UDP_ERR_START)); [ "${DELTA_INERR}" -lt 0 ] && DELTA_INERR=0
            DELTA_SKB=$((SKB_END - SKB_START)); [ "${DELTA_SKB}" -lt 0 ] && DELTA_SKB=0

            SRV_CORE0_CSV=$(awk '/^Average:/ && $2 == "0" {
                usr=$3; sys=$5; soft=$8; idle=$12; busy=100.0-idle;
                printf "%.2f,%.2f,%.2f,%.2f,%.2f", usr, sys, soft, idle, busy
            }' "${MPSTAT_LOG}")
            if [ -z "${SRV_CORE0_CSV}" ]; then
                SRV_CORE0_CSV="0.00,0.00,0.00,100.00,0.00"
            fi

            IFS=',' read -r tot_req tot_ans qps lat_mean lat_p50 lat_p75 lat_p90 lat_p95 lat_p99 lat_p99_9 lat_min lat_max lat_std loss_pct loss_cnt trgt cl_busy cl_maxc cl_drops <<< "${CLIENT_RUN_OUT}"

            echo "${TARGET_QPS},${RATIO},${REP},${tot_req},${tot_ans},${loss_cnt},${loss_pct},${qps},${lat_mean},${lat_min},${lat_max},${lat_std},${lat_p50},${lat_p75},${lat_p90},${lat_p95},${lat_p99},${lat_p99_9},${SRV_CORE0_CSV},${DELTA_RCVBUF},${DELTA_INERR},${DELTA_SKB},${cl_busy},${cl_maxc},${cl_drops}" >> "${RAW_CSV}"

            printf "      -> Fallback=%3d%% | QPS=%s | Loss=%5s%% | Mean=%6sms | p99=%6sms | SoftIRQ=%5s%% | RcvbufErr=%d\n" \
                "${RATIO}" "${qps}" "${loss_pct}" "${lat_mean}" "${lat_p99}" "$(echo "${SRV_CORE0_CSV}" | awk -F',' '{print $3}')" "${DELTA_RCVBUF}"
            sleep 1
        done
    done
done

# Restaura modo normal
sudo -n python3 tests/manage_overload.py normal >/dev/null 2>&1

echo
echo "-> Gerando resumo consolidado em ${SUMMARY_CSV}..."
python3 - << 'PYEOF'
import csv
import numpy as np
from collections import defaultdict

raw_csv = "/home/joaosoares/Documents/Github/AtesN-DS/official_results/04_overload_fallback_study/raw_fallback_penalty.csv"
sum_csv = "/home/joaosoares/Documents/Github/AtesN-DS/official_results/04_overload_fallback_study/summary_fallback_penalty.csv"

groups = defaultdict(list)
with open(raw_csv, "r") as f:
    reader = csv.DictReader(f)
    for row in reader:
        key = (int(row["target_qps"]), int(row["fallback_ratio_pct"]))
        groups[key].append(row)

num_cols = [
    "queries_sent", "queries_completed", "queries_lost", "packet_loss_pct", "achieved_qps",
    "lat_mean_ms", "lat_min_ms", "lat_max_ms", "lat_std_ms",
    "lat_p50_ms", "lat_p75_ms", "lat_p90_ms", "lat_p95_ms", "lat_p99_ms", "lat_p99_9_ms",
    "srv_core0_user_pct", "srv_core0_sys_pct", "srv_core0_softirq_pct", "srv_core0_idle_pct", "srv_core0_busy_pct",
    "udp_rcvbuf_errors_delta", "udp_in_errors_delta", "skb_head_alloc_delta",
    "client_cpu_busy_pct", "client_max_core_pct", "client_udp_drops"
]

out_fields = ["target_qps", "fallback_ratio_pct", "reps"]
for c in num_cols:
    out_fields.extend([f"{c}_mean", f"{c}_std"])

with open(sum_csv, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=out_fields)
    writer.writeheader()
    for (t_qps, ratio), rows in sorted(groups.items()):
        out_row = {"target_qps": t_qps, "fallback_ratio_pct": ratio, "reps": len(rows)}
        for c in num_cols:
            vals = [float(r[c]) for r in rows]
            out_row[f"{c}_mean"] = f"{np.mean(vals):.2f}"
            out_row[f"{c}_std"] = f"{np.std(vals):.2f}"
        writer.writerow(out_row)

print(f"Summary successfully saved to {sum_csv}")
PYEOF

echo "✅ Experimento de Fallback concluído com sucesso!"
