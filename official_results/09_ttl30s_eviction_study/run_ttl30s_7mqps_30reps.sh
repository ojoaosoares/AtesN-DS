#!/usr/bin/env bash
# ==============================================================================
# run_ttl30s_7mqps_30reps.sh
#
# Benchmark Suite: Dynamic Cache Expiration & Eviction Under 7 MQPS Line-Rate
# Protocol:
#   - TTL: Fixed 30s on all layers (SmartNIC HW, Driver XDP, Unbound, Mock Server)
#   - Duration: 180s (3 minutes = 6 full expiration/eviction cycles)
#   - Rate: UNLIMITED (7.66 MQPS line-rate)
#   - Modes: unbound_hw_cache vs ates_hw_cache
#   - Repetitions: 30 independent runs per mode
# ==============================================================================

set -euo pipefail

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

NUM_CORES=2
SERVER_CORES="0,1"
SERVER_TASKSET="0,1"

MODES_TO_TEST=("unbound_hw_cache" "ates_hw_cache")
if [ $# -ge 1 ] && [ -n "$1" ]; then
    IFS=' ' read -r -a MODES_TO_TEST <<< "$1"
fi

RATES=(0) # 0 = UNLIMITED line rate (7.66 MQPS)
if [ $# -ge 2 ] && [ -n "$2" ]; then
    IFS=' ' read -r -a RATES <<< "$2"
fi

REPS=${REPS:-10}
DURATION=${DURATION:-180}
CLIENT_WORKERS=${CLIENT_WORKERS:-6}
FIXED_TTL=30

RAW_CSV="${RAW_CSV:-${OUT_DIR}/raw_ttl30s_10reps.csv}"
SUMMARY_CSV="${SUMMARY_CSV:-${OUT_DIR}/summary_ttl30s_10reps.csv}"
mkdir -p "${OUT_DIR}/logs"

if [ ! -f "${RAW_CSV}" ]; then
    echo "num_cores,mode,target_qps,rep,queries_sent,queries_completed,queries_lost,packet_loss_pct,achieved_qps,lat_mean_ms,lat_p50_ms,lat_p75_ms,lat_p90_ms,lat_p95_ms,lat_p99_ms,lat_p99_9_ms,lat_min_ms,lat_max_ms,lat_std_ms,hw_cache_hits,hw_pass_pkts,driver_hits,userspace_hits,hw_hit_rate_pct,nic_rx_discards,nic_tx_discards,nic_rx_errors,nic_irq_delta,srv_c0_busy,srv_c1_busy,srv_c2_busy,srv_c3_busy,srv_all_busy,srv_softirq,client_cpu_busy,ttl_evictions" > "${RAW_CSV}"
fi

generate_summary() {
    python3 - << 'PYEOF'
import csv
from collections import defaultdict
import numpy as np
import os

raw_file = os.environ.get("RAW_CSV", "official_results/09_ttl30s_eviction_study/raw_ttl30s_10reps.csv")
summary_file = os.environ.get("SUMMARY_CSV", "official_results/09_ttl30s_eviction_study/summary_ttl30s_10reps.csv")

if not os.path.exists(raw_file):
    exit(0)

groups = defaultdict(list)
with open(raw_file, 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if not row['target_qps']: continue
        key = (row['num_cores'], row['mode'], row['target_qps'])
        groups[key].append(row)

metrics = [
    'queries_sent', 'queries_completed', 'queries_lost', 'packet_loss_pct',
    'achieved_qps', 'lat_mean_ms', 'lat_p50_ms', 'lat_p75_ms', 'lat_p90_ms',
    'lat_p95_ms', 'lat_p99_ms', 'lat_p99_9_ms', 'lat_min_ms', 'lat_max_ms',
    'lat_std_ms', 'hw_cache_hits', 'hw_pass_pkts', 'driver_hits', 'userspace_hits',
    'hw_hit_rate_pct', 'nic_rx_discards', 'nic_tx_discards', 'nic_rx_errors',
    'nic_irq_delta', 'srv_c0_busy', 'srv_c1_busy', 'srv_c2_busy', 'srv_c3_busy',
    'srv_all_busy', 'srv_softirq', 'client_cpu_busy', 'ttl_evictions'
]

fieldnames = ['num_cores', 'mode', 'target_qps', 'reps_count']
for m in metrics:
    fieldnames.extend([f"{m}_mean", f"{m}_std", f"{m}_ci95"])

with open(summary_file, 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for key, rows in sorted(groups.items()):
        n = len(rows)
        out = {
            'num_cores': key[0],
            'mode': key[1],
            'target_qps': key[2],
            'reps_count': n
        }
        for m in metrics:
            vals = []
            for r in rows:
                try:
                    v = float(r[m])
                    if not np.isnan(v):
                        vals.append(v)
                except (ValueError, KeyError):
                    pass
            if vals:
                mean = np.mean(vals)
                std = np.std(vals, ddof=1) if len(vals) > 1 else 0.0
                ci95 = 1.96 * (std / np.sqrt(len(vals))) if len(vals) > 1 else 0.0
                out[f"{m}_mean"] = f"{mean:.4f}"
                out[f"{m}_std"] = f"{std:.4f}"
                out[f"{m}_ci95"] = f"{ci95:.4f}"
            else:
                out[f"{m}_mean"] = "0.0000"
                out[f"{m}_std"] = "0.0000"
                out[f"{m}_ci95"] = "0.0000"
        writer.writerow(out)

print(f"✓ Summary generated: {summary_file}")
PYEOF
}

ensure_hw_offload_state() {
    local target_state=$1
    local current_state=$(ip link show "${SERVER_IFACE}" | grep -q "xdpoffload" && echo 1 || echo 0)
    if [ "${current_state}" -ne "${target_state}" ]; then
        if [ "${target_state}" -eq 1 ]; then
            make -C "${SERVER_BASE_DIR}" load-hw >/dev/null 2>&1
        else
            make -C "${SERVER_BASE_DIR}" unload-hw >/dev/null 2>&1
        fi
        sleep 2
    fi
}

ensure_driver_state() {
    local target_state=$1
    local current_state=$(ip link show "${SERVER_IFACE}" | grep -q "xdpdrv" && echo 1 || echo 0)
    if [ "${current_state}" -ne "${target_state}" ]; then
        if [ "${target_state}" -eq 1 ]; then
            sudo -n ip link set dev "${SERVER_IFACE}" xdpdrv off 2>/dev/null || true
            sudo -n ip link set dev "${SERVER_IFACE}" xdpdrv obj "${SERVER_BASE_DIR}/obj/dns.o" sec xdp 2>/dev/null || true
        else
            sudo -n ip link set dev "${SERVER_IFACE}" xdpdrv off 2>/dev/null || true
        fi
        sleep 2
    fi
}

CURRENT_LOADED_MODE=""

clean_and_prepare_environment() {
    local MODE=$1

    echo "-> [CLEAN] Reiniciando daemons e sincronizando Caches para: ${MODE}..."
    sudo -n killall -9 atesnds atesnds_daemon dns_listener 2>/dev/null || true
    sudo -n pkill -9 -x "atesnds|atesnds_daemon|dns_listener" 2>/dev/null || true
    sleep 1

    echo "   [RESET] Limpando cache do Unbound..."
    sudo -n unbound-control flush_zone . >/dev/null 2>&1 || sudo -n systemctl restart unbound
    pgrep -x unbound | xargs -r -n1 sudo -n taskset -acp "${SERVER_TASKSET}" >/dev/null 2>&1 || true

    # Pre-popular caches L2/L3 com TTL fixo de 30s
    "${SERVER_BASE_DIR}/scripts/preload_unbound.sh" "${SERVER_BASE_DIR}/tests/isp_unique_warmup_dnsperf.txt" "${FIXED_TTL}"

    case "${MODE}" in
      "unbound_hw_cache")
        ensure_driver_state 0
        ensure_hw_offload_state 1
        nohup sudo -n taskset -c "${SERVER_TASKSET}" "${SERVER_BASE_DIR}/bin/dns_listener" -i "${SERVER_IFACE}" >/dev/null 2>&1 &
        sleep 1
        # Inicia daemon semeando simultaneamente a SmartNIC e a Timing Wheel local
        echo "   [SEED] Semeando 32k entradas na Timing Wheel e SmartNIC (TTL=${FIXED_TTL}s)..."
        nohup sudo -n taskset -c "${SERVER_TASKSET}" "${SERVER_BASE_DIR}/bin/atesnds_daemon" \
            -w "${SERVER_BASE_DIR}/tests/isp_top32k_hw_warmup_dnsperf.txt" \
            --ttl "${FIXED_TTL}" >/tmp/daemon.log 2>&1 &
        sleep 4
        ;;
      "ates_hw_cache")
        ensure_hw_offload_state 1
        nohup sudo -n taskset -c "${SERVER_TASKSET}" "${SERVER_BASE_DIR}/bin/atesnds" -a "${SERVER_IP}" -i "${SERVER_IFACE}" -m "${CLIENT_MAC}" -s "${CLIENT_IP}" >/dev/null 2>&1 &
        sleep 2
        "${SERVER_BASE_DIR}/scripts/preload_driver.sh" "${SERVER_BASE_DIR}/tests/isp_unique_warmup_dnsperf.txt" "${FIXED_TTL}"
        echo "   [SEED] Semeando 32k entradas na Timing Wheel e SmartNIC (TTL=${FIXED_TTL}s)..."
        nohup sudo -n taskset -c "${SERVER_TASKSET}" "${SERVER_BASE_DIR}/bin/atesnds_daemon" \
            -w "${SERVER_BASE_DIR}/tests/isp_top32k_hw_warmup_dnsperf.txt" \
            --ttl "${FIXED_TTL}" >/tmp/daemon.log 2>&1 &
        sleep 4
        sudo -n python3 "${SERVER_BASE_DIR}/tests/manage_overload.py" normal 2>/dev/null || true
        ;;
    esac
    sleep 1
    echo "   • Ambiente 100% sincronizado (L1 HW + Timing Wheel) com TTL=${FIXED_TTL}s!"
}

echo "=========================================================================================="
echo "🚀 BENCHMARK TTL=30s EXPIRATION & EVICTION STUDY (2 CORES, REPS=${REPS}, DURATION=${DURATION}s)"
echo "Modos: ${MODES_TO_TEST[*]}"
echo "Taxas: ${RATES[*]} (0 = UNLIMITED / 7 MQPS)"
echo "Saída: ${RAW_CSV}"
echo "=========================================================================================="

# Configurações de rede
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
    sudo -n sysctl -w net.core.rmem_max=67108864 >/dev/null 2>&1 || true
    sudo -n sysctl -w net.core.wmem_max=67108864 >/dev/null 2>&1 || true
    sudo -n sysctl -w net.ipv4.ip_local_port_range='1024 65535' >/dev/null 2>&1 || true
    sudo -n ethtool -L ${CLIENT_IFACE} combined 6 >/dev/null 2>&1 || true
    sudo -n ethtool -G ${CLIENT_IFACE} rx 4096 tx 4096 >/dev/null 2>&1 || true
    sudo -n ip link set dev ${CLIENT_IFACE} xdpgeneric off 2>/dev/null || true
    sudo -n ip link set dev ${CLIENT_IFACE} xdpdrv off 2>/dev/null || true
    sudo -n ip link set dev ${CLIENT_IFACE} xdp off 2>/dev/null || true
    sudo -n ip addr replace ${CLIENT_IP}/24 dev ${CLIENT_IFACE} 2>/dev/null || true
    sudo -n arp -s ${SERVER_IP} ${SERVER_MAC} 2>/dev/null || true

    CLI_IRQS=(\$(grep \"${CLIENT_IFACE}-\" /proc/interrupts | awk -F: '{print \$1}' | tr -d ' '))
    for q in \"\${!CLI_IRQS[@]}\"; do
        irq=\"\${CLI_IRQS[\$q]}\"
        core=\$((q % 6 + 6))
        mask=\$((1 << core))
        printf \"%x\" \"\${mask}\" | sudo -n tee \"/proc/irq/\${irq}/smp_affinity\" >/dev/null || true
    done
    sudo -n pkill -x mock_dns_server 2>/dev/null || true
    sleep 1
    sudo -n nohup taskset -c 11 ${CLIENT_BASE_DIR}/tests/mock_dns_server ${CLIENT_IP} 53 ${FIXED_TTL} </dev/null >/tmp/mock_dns.log 2>&1 &
"

echo "-> [READY] Nó cliente configurado e mock_dns_server ativo com TTL=${FIXED_TTL}s."

# Execução do Benchmark
for RATE in "${RATES[@]}"; do
    for MODE in "${MODES_TO_TEST[@]}"; do
        for ((rep=1; rep<=REPS; rep++)); do
            echo ""
            echo "--------------------------------------------------------------------------------"
            echo ">>> [EXEC] MODO: ${MODE} | TAXA: ${RATE} QPS | RODADA: ${rep}/${REPS} (TTL=${FIXED_TTL}s, DURAÇÃO=${DURATION}s)"
            echo "--------------------------------------------------------------------------------"

            clean_and_prepare_environment "${MODE}"

            # Snapshots de hardware
            RX_DISC_PRE=$(ethtool -S "${SERVER_IFACE}" 2>/dev/null | awk '/rx_discards/{print $2; exit}' || echo 0)
            TX_DISC_PRE=$(ethtool -S "${SERVER_IFACE}" 2>/dev/null | awk '/tx_discards/{print $2; exit}' || echo 0)
            RX_ERR_PRE=$(ethtool -S "${SERVER_IFACE}" 2>/dev/null | awk '/rx_errors/{print $2; exit}' || echo 0)
            IRQ_SUM_PRE=0
            for irq in "${RXTX_IRQS[@]}"; do
                cnt=$(awk -v i="${irq}:" '$1==i {sum=0; for(k=2; k<=NF; k++) sum+=$k; print sum}' /proc/interrupts)
                IRQ_SUM_PRE=$((IRQ_SUM_PRE + cnt))
            done

            STAT_PRE=$(cat /proc/stat)
            CLIENT_STAT_PRE=$(ssh -o StrictHostKeyChecking=no "${CLIENT_USER}@${CLIENT_MGMT_IP}" "cat /proc/stat")

            # Executa teste com xdnsperf
            LOG_FILE="${OUT_DIR}/logs/xdnsperf_${MODE}_rate${RATE}_rep${rep}.log"
            echo "   [LOAD] Disparando xdnsperf (${CLIENT_WORKERS} workers, taxa ${RATE}, duração ${DURATION}s)..."
            ssh -o StrictHostKeyChecking=no "${CLIENT_USER}@${CLIENT_MGMT_IP}" "
                sudo -n ${CLIENT_XDNSPERF_DIR}/bin/xdnsperf \
                    -i ${CLIENT_IFACE} \
                    -c ${CLIENT_WORKERS} \
                    -s ${SERVER_IP} \
                    -f ${CLIENT_BENCH_TRACE} \
                    -r ${RATE} \
                    -d ${DURATION} \
                    --csv
            " > "${LOG_FILE}" 2>&1 || true

            STAT_POST=$(cat /proc/stat)
            CLIENT_STAT_POST=$(ssh -o StrictHostKeyChecking=no "${CLIENT_USER}@${CLIENT_MGMT_IP}" "cat /proc/stat")

            RX_DISC_POST=$(ethtool -S "${SERVER_IFACE}" 2>/dev/null | awk '/rx_discards/{print $2; exit}' || echo 0)
            TX_DISC_POST=$(ethtool -S "${SERVER_IFACE}" 2>/dev/null | awk '/tx_discards/{print $2; exit}' || echo 0)
            RX_ERR_POST=$(ethtool -S "${SERVER_IFACE}" 2>/dev/null | awk '/rx_errors/{print $2; exit}' || echo 0)

            IRQ_SUM_POST=0
            for irq in "${RXTX_IRQS[@]}"; do
                cnt=$(awk -v i="${irq}:" '$1==i {sum=0; for(k=2; k<=NF; k++) sum+=$k; print sum}' /proc/interrupts)
                IRQ_SUM_POST=$((IRQ_SUM_POST + cnt))
            done

            # Parse CPU
            eval $(python3 - << PYEOF
def parse_stat(s_pre, s_post):
    d_pre = {line.split()[0]: [int(x) for x in line.split()[1:]] for line in s_pre.strip().split('\n') if line.startswith('cpu')}
    d_post = {line.split()[0]: [int(x) for x in line.split()[1:]] for line in s_post.strip().split('\n') if line.startswith('cpu')}
    out = {}
    for c in ['cpu', 'cpu0', 'cpu1', 'cpu2', 'cpu3']:
        if c in d_pre and c in d_post:
            v_pre = d_pre[c]
            v_post = d_post[c]
            tot = sum(v_post) - sum(v_pre)
            idle = (v_post[3] + v_post[4]) - (v_pre[3] + v_pre[4])
            sirq = v_post[5] - v_pre[5]
            busy = max(0.0, 100.0 * (1.0 - idle / max(tot, 1)))
            sirq_pct = max(0.0, 100.0 * (sirq / max(tot, 1)))
            out[f"{c}_busy"] = f"{busy:.2f}"
            if c == 'cpu':
                out['srv_softirq'] = f"{sirq_pct:.2f}"
    return out

srv = parse_stat('''${STAT_PRE}''', '''${STAT_POST}''')
cli = parse_stat('''${CLIENT_STAT_PRE}''', '''${CLIENT_STAT_POST}''')
print(f"SRV_C0={srv.get('cpu0_busy', '0.00')}")
print(f"SRV_C1={srv.get('cpu1_busy', '0.00')}")
print(f"SRV_C2={srv.get('cpu2_busy', '0.00')}")
print(f"SRV_C3={srv.get('cpu3_busy', '0.00')}")
print(f"SRV_ALL={srv.get('cpu_busy', '0.00')}")
print(f"SRV_SIRQ={srv.get('srv_softirq', '0.00')}")
print(f"CLI_BUSY={cli.get('cpu_busy', '0.00')}")
PYEOF
)

            # Parse xdnsperf CSV line
            CSV_LINE=$(grep "^CSV:" "${LOG_FILE}" | tail -n 1 | sed 's/^CSV://' || echo "")
            if [ -n "${CSV_LINE}" ]; then
                IFS=',' read -r q_sent q_comp ach_qps lat_mean lat_p50 lat_p75 lat_p90 lat_p95 lat_p99 lat_p99_9 lat_min lat_max lat_std loss_pct q_lost ooo <<< "${CSV_LINE}"
            else
                q_sent=0; q_comp=0; ach_qps=0; lat_mean=0; lat_p50=0; lat_p75=0; lat_p90=0; lat_p95=0; lat_p99=0; lat_p99_9=0; lat_min=0; lat_max=0; lat_std=0; loss_pct=100.0; q_lost=0; ooo=0
            fi

            HW_HITS=0
            HW_PASS=0
            DRV_HITS=0
            USR_HITS=0
            HIT_RATE="0.00"

            if [ "${MODE}" = "unbound_hw_cache" ] || [ "${MODE}" = "ates_hw_cache" ]; then
                HW_HITS=${q_comp} # Linha de frente em hardware
                HIT_RATE=$(awk -v h="${q_comp}" -v s="${q_sent}" 'BEGIN {if(s>0) printf "%.2f", (h/s)*100; else print "0.00"}')
            fi

            NIC_RX_DISC=$((RX_DISC_POST - RX_DISC_PRE))
            NIC_TX_DISC=$((TX_DISC_POST - TX_DISC_PRE))
            NIC_RX_ERR=$((RX_ERR_POST - RX_ERR_PRE))
            NIC_IRQ_DELTA=$((IRQ_SUM_POST - IRQ_SUM_PRE))
            TTL_EVICT=0

            echo "${NUM_CORES},${MODE},${RATE},${rep},${q_sent},${q_comp},${q_lost},${loss_pct},${ach_qps},${lat_mean},${lat_p50},${lat_p75},${lat_p90},${lat_p95},${lat_p99},${lat_p99_9},${lat_min},${lat_max},${lat_std},${HW_HITS},${HW_PASS},${DRV_HITS},${USR_HITS},${HIT_RATE},${NIC_RX_DISC},${NIC_TX_DISC},${NIC_RX_ERR},${NIC_IRQ_DELTA},${SRV_C0},${SRV_C1},${SRV_C2},${SRV_C3},${SRV_ALL},${SRV_SIRQ},${CLI_BUSY},${TTL_EVICT}" >> "${RAW_CSV}"

            echo "   ✓ Concluído: ${ach_qps} QPS | Perda: ${loss_pct}% | p99: ${lat_p99} ms | Servidor CPU: ${SRV_ALL}%"
            generate_summary
        done
    done
done

echo ""
echo "=========================================================================================="
echo "🎉 BENCHMARK TTL=30s CONCLUÍDO COM SUCESSO!"
echo "Dados brutos: ${RAW_CSV}"
echo "Sumário final: ${SUMMARY_CSV}"
echo "=========================================================================================="
