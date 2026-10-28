#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
if [ -f "$SCRIPT_DIR/sample_client.py" ]; then
    PROJECT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
    LOCAL_CLIENT_SCRIPT="$SCRIPT_DIR/sample_client.py"
elif [ -f "$SCRIPT_DIR/tests/sample_client.py" ]; then
    PROJECT_DIR="$SCRIPT_DIR"
    LOCAL_CLIENT_SCRIPT="$SCRIPT_DIR/tests/sample_client.py"
else
    PROJECT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
    LOCAL_CLIENT_SCRIPT="${PROJECT_DIR}/tests/sample_client.py"
fi

#########################
# CONFIGURAÇÃO
#########################

REMOTE_USER="joaosoares"
REMOTE_HOST="150.164.2.93"
REMOTE_BASE_DIR="/home/joaosoares/Documents/Github/AtesN-DS"

TARGET_MODE="${1:-all}"
CONCURRENCY="${2:-512}"
DURATION="${3:-30}"
WARMUP_DURATION="${4:-10}"
WORKERS="${5:-8}"
TARGET_RATE="${6:-0}"

REMOTE_INTERFACE="enp1s0np1"
REMOTE_SERVER_IP="192.168.0.1"
REMOTE_MAC_ADDR="3c:fd:fe:03:02:00"
REMOTE_DNS_SERVER="192.168.0.2"

LOCAL_INTERFACE="enp1s0f0"
LOCAL_CLIENT_IP="192.168.0.2"

DATA_DATE="quick_data_$(date +%Y-%m-%d_%H-%M-%S)"
LOCAL_RESULTS_DIR_CLIENT="${PROJECT_DIR}/${DATA_DATE}/client"
mkdir -p "${LOCAL_RESULTS_DIR_CLIENT}"

if [ "${TARGET_MODE}" = "all" ]; then
    MODES=("unbound_standalone" "unbound_hw_cache" "ates_driver" "ates_hw_cache")
else
    MODES=("${TARGET_MODE}")
fi

SUMMARY_LOG="${LOCAL_RESULTS_DIR_CLIENT}/three_tier_telemetry_summary.txt"
> "${SUMMARY_LOG}"

echo "=========================================================================================="
echo "🚀 INICIANDO BENCHMARK COM TELEMETRIA MULTI-TIER (HW, DRIVER, USERSPACE/UNBOUND)"
echo "Configuração: Concorrência=${CONCURRENCY} | Workers=${WORKERS} | TargetRate=${TARGET_RATE} QPS | Warmup=${WARMUP_DURATION}s | Duração=${DURATION}s"
echo "Modos: ${MODES[*]}"
echo "=========================================================================================="

echo "-> Inicializando Mock Authoritative DNS Responder (${LOCAL_CLIENT_IP}:53 na CPU 11)..."
sudo -n pkill -f mock_dns_server 2>/dev/null || true
taskset -c 11 "${PROJECT_DIR}/tests/mock_dns_server" "${LOCAL_CLIENT_IP}" 53 >/dev/null 2>&1 &
MOCK_PID=$!
sleep 1

cleanup() {
    echo
    echo "-> Encerrando Mock Authoritative DNS Responder..."
    sudo -n kill ${MOCK_PID} 2>/dev/null || true
    sudo -n pkill -f mock_dns_server 2>/dev/null || true
}
trap cleanup EXIT INT TERM

for MODE in "${MODES[@]}"; do
    echo
    echo "=========================================================================================="
    echo "▶ MODO ATUAL: ${MODE}"
    echo "=========================================================================================="

    echo "-> Resetando ambiente no servidor remoto (${REMOTE_HOST})..."
    ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" "
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

      cd '${REMOTE_BASE_DIR}'
      sudo -n make unload-hw

      sudo -n ip link set dev '${REMOTE_INTERFACE}' down
      sleep 1
      sudo -n ip link set dev '${REMOTE_INTERFACE}' up
      sudo -n ethtool -K '${REMOTE_INTERFACE}' rxhash on 2>/dev/null || true
      sudo -n ethtool -L '${REMOTE_INTERFACE}' combined 2 2>/dev/null || true
      sudo -n systemctl stop irqbalance 2>/dev/null || true
      IRQS=(\$(awk -F':' '/${REMOTE_INTERFACE}-rxtx/ {print \$1}' /proc/interrupts | tr -d ' '))
      if [ \${#IRQS[@]} -ge 2 ]; then
        echo 1 | sudo -n tee /proc/irq/\${IRQS[0]}/smp_affinity >/dev/null || true
        echo 2 | sudo -n tee /proc/irq/\${IRQS[1]}/smp_affinity >/dev/null || true
      fi
      sudo -n ip addr flush dev '${REMOTE_INTERFACE}'
      sudo -n ip addr add '${REMOTE_SERVER_IP}/24' dev '${REMOTE_INTERFACE}'
    "

    echo "-> Resetando interface local (${LOCAL_INTERFACE})..."
    sudo -n ip link set dev "${LOCAL_INTERFACE}" down 2>/dev/null || true
    sleep 1
    sudo -n ip link set dev "${LOCAL_INTERFACE}" up 2>/dev/null || true
    sudo -n ethtool -K "${LOCAL_INTERFACE}" rxhash off 2>/dev/null || true
    sudo -n ip addr flush dev "${LOCAL_INTERFACE}" 2>/dev/null || true
    sudo -n ip addr add "${LOCAL_CLIENT_IP}/24" dev "${LOCAL_INTERFACE}" 2>/dev/null || true
    sleep 2

    echo "-> Inicializando ambiente no servidor para modo ${MODE}..."

    case "${MODE}" in
      "unbound_standalone")
        echo "   [Daemon] Unbound Standalone (pinned to Cores 0,1)..."
        ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" "
          sudo -n systemctl restart unbound 2>/dev/null || sudo -n unbound -c /etc/unbound/unbound.conf 2>/dev/null || sudo -n unbound
          sleep 1
          pgrep -x unbound | xargs -r -n1 sudo -n taskset -cp 0,1 2>/dev/null || true
        "
        sleep 2
        ;;

      "unbound_hw_cache")
        echo "   [Daemon] SmartNIC Agilio Offloaded XDP Cache..."
        ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" \
          "cd '${REMOTE_BASE_DIR}' && tmux new-session -d -s hw 'sudo -n make load-and-run-time-updater'"
        sleep 3
        echo "   [Daemon] Decoupled DNS Listener na interface ${REMOTE_INTERFACE}..."
        ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" \
          "cd '${REMOTE_BASE_DIR}' && tmux new-session -d -s listener 'sudo -n ./bin/dns_listener -i ${REMOTE_INTERFACE} -v'"
        sleep 2
        echo "   [Daemon] Unbound Recursive Resolver (pinned to Cores 0,1)..."
        ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" "
          sudo -n systemctl restart unbound 2>/dev/null || sudo -n unbound -c /etc/unbound/unbound.conf 2>/dev/null || sudo -n unbound
          sleep 1
          pgrep -x unbound | xargs -r -n1 sudo -n taskset -cp 0,1 2>/dev/null || true
        "
        sleep 2
        ;;

      "ates_driver"|"no_hw_cache")
        echo "   [Daemon] Unbound Fallback Resolver in Userspace (pinned to Cores 0,1)..."
        ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" "
          sudo -n systemctl restart unbound 2>/dev/null || sudo -n unbound -c /etc/unbound/unbound.conf 2>/dev/null || sudo -n unbound
          sleep 1
          pgrep -x unbound | xargs -r -n1 sudo -n taskset -cp 0,1 2>/dev/null || true
        "
        sleep 2
        echo "   [Daemon] AtesN-DS Driver Mode (pinned to Cores 0,1)..."
        ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" \
          "cd '${REMOTE_BASE_DIR}' && tmux new-session -d -s ates 'sudo -n taskset -c 0,1 ./bin/atesnds -a ${REMOTE_SERVER_IP} -i ${REMOTE_INTERFACE} -m ${REMOTE_MAC_ADDR} -s ${REMOTE_DNS_SERVER} -v'"
        sleep 3
        if ! ssh "${REMOTE_USER}@${REMOTE_HOST}" "pgrep -af atesnds" >/dev/null 2>&1; then
            echo "❌ ERRO: atesnds NÃO está rodando!"
            ssh "${REMOTE_USER}@${REMOTE_HOST}" "tmux capture-pane -t ates -p -S -100" || true
            exit 1
        fi
        echo "   [Daemon] Adaptive Overload Governor (pinned to Cores 0,1)..."
        ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" \
          "cd '${REMOTE_BASE_DIR}' && tmux new-session -d -s gov 'sudo -n taskset -c 0,1 python3 tests/overload_governor.py'"
        sleep 1
        ;;

      "ates_hw_cache"|"hw_cache")
        echo "   [Daemon] SmartNIC Agilio Offloaded XDP Cache..."
        ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" \
          "cd '${REMOTE_BASE_DIR}' && tmux new-session -d -s hw 'sudo -n make load-and-run-time-updater'"
        sleep 3
        echo "   [Daemon] AtesN-DS com HW Cache..."
        ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" \
          "cd '${REMOTE_BASE_DIR}' && tmux new-session -d -s ates 'sudo -n ./bin/atesnds -a ${REMOTE_SERVER_IP} -i ${REMOTE_INTERFACE} -m ${REMOTE_MAC_ADDR} -s ${REMOTE_DNS_SERVER} -v'"
        sleep 3
        if ! ssh "${REMOTE_USER}@${REMOTE_HOST}" "pgrep -af atesnds" >/dev/null 2>&1; then
            echo "❌ ERRO: atesnds NÃO está rodando!"
            ssh "${REMOTE_USER}@${REMOTE_HOST}" "tmux capture-pane -t ates -p -S -100" || true
            exit 1
        fi
        ;;

      *)
        echo "❌ ERRO: Modo desconhecido: ${MODE}"
        exit 1
        ;;
    esac

    echo "-> Executando fase de Warmup (${WARMUP_DURATION}s) para pré-povoar o cache..."
    python3 "${LOCAL_CLIENT_SCRIPT}" \
        --server "${REMOTE_SERVER_IP}" \
        --duration "${WARMUP_DURATION}" \
        --concurrency "${CONCURRENCY}" \
        --workers "${WORKERS}" >/dev/null 2>&1 || true
    sleep 1

    echo "-> Capturando snapshot inicial de telemetria no servidor..."
    SNAP_PRE=$(ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" "
      HW_TX=\$(sudo -n ethtool -S ${REMOTE_INTERFACE} 2>/dev/null | awk '/bpf_app2_pkts/ {print \$2; f=1} END {if(!f) print 0}')
      PASS=\$(sudo -n ethtool -S ${REMOTE_INTERFACE} 2>/dev/null | awk '/bpf_pass_pkts/ {print \$2; f=1} END {if(!f) print 0}')
      UB_Q=\$(sudo -n unbound-control stats_noreset 2>/dev/null | awk -F'=' '/^total.num.queries=/ {print \$2; f=1} END {if(!f) print 0}')
      echo \"\$HW_TX \$PASS \$UB_Q\"
    ")
    SNAP_PRE_LAST=$(echo "${SNAP_PRE}" | tr -d '\r' | tail -n 1)
    HW_TX_START=$(echo "${SNAP_PRE_LAST}" | awk '{print $1}')
    PASS_START=$(echo "${SNAP_PRE_LAST}" | awk '{print $2}')
    UB_Q_START=$(echo "${SNAP_PRE_LAST}" | awk '{print $3}')
    HW_TX_START=${HW_TX_START:-0}
    PASS_START=${PASS_START:-0}
    UB_Q_START=${UB_Q_START:-0}

    echo "-> Iniciando amostragem de telemetria no servidor e no cliente..."
    REMOTE_SERVER_OUTPUT_FILE="/tmp/server_telemetry_${MODE}_${CONCURRENCY}.csv"
    LOCAL_SERVER_OUTPUT_FILE="${LOCAL_RESULTS_DIR_CLIENT}/server_res_${MODE}_${CONCURRENCY}.csv"
    LOCAL_CLIENT_RES_FILE="${LOCAL_RESULTS_DIR_CLIENT}/client_res_${MODE}_${CONCURRENCY}.csv"

    # Inicia monitor no servidor (amostra CPU, SoftIRQ, NIC a cada 0.2s)
    ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" "
      tmux kill-session -t srv 2>/dev/null || true
      tmux new-session -d -s srv 'python3 ${REMOTE_BASE_DIR}/tests/sample_server.py ${REMOTE_SERVER_OUTPUT_FILE} ${DURATION} 0'
    "

    # Inicia monitor no cliente (amostra CPU, Cores, UDP drops a cada 0.2s)
    python3 "${PROJECT_DIR}/tests/sample_client_resources.py" "${LOCAL_CLIENT_RES_FILE}" "${DURATION}" 0 "${LOCAL_INTERFACE}" >/dev/null 2>&1 &
    CLIENT_MON_PID=$!

    if [ "${TARGET_RATE}" -gt 0 ]; then
        echo "-> Executando medição principal (${DURATION}s @ ${CONCURRENCY} conc com ${WORKERS} workers, target rate ${TARGET_RATE} QPS)..."
        CLIENT_OUTPUT_FILE="${LOCAL_RESULTS_DIR_CLIENT}/client_output_${MODE}_${CONCURRENCY}_rate${TARGET_RATE}.csv"
        python3 "${LOCAL_CLIENT_SCRIPT}" \
            --server "${REMOTE_SERVER_IP}" \
            --duration "${DURATION}" \
            --concurrency "${CONCURRENCY}" \
            --workers "${WORKERS}" \
            --rate "${TARGET_RATE}" \
            | tee "${CLIENT_OUTPUT_FILE}"
    else
        echo "-> Executando medição principal (${DURATION}s @ ${CONCURRENCY} conc com ${WORKERS} workers)..."
        CLIENT_OUTPUT_FILE="${LOCAL_RESULTS_DIR_CLIENT}/client_output_${MODE}_${CONCURRENCY}.csv"
        python3 "${LOCAL_CLIENT_SCRIPT}" \
            --server "${REMOTE_SERVER_IP}" \
            --duration "${DURATION}" \
            --concurrency "${CONCURRENCY}" \
            --workers "${WORKERS}" \
            | tee "${CLIENT_OUTPUT_FILE}"
    fi

    # Aguarda conclusão do monitor local
    wait ${CLIENT_MON_PID} 2>/dev/null || true
    sleep 1

    # Recupera telemetria do servidor
    scp -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_SERVER_OUTPUT_FILE}" "${LOCAL_SERVER_OUTPUT_FILE}" 2>/dev/null || true

    echo "-> Capturando snapshot final de telemetria no servidor..."
    SNAP_POST=$(ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" "
      HW_TX=\$(sudo -n ethtool -S ${REMOTE_INTERFACE} 2>/dev/null | awk '/bpf_app2_pkts/ {print \$2; f=1} END {if(!f) print 0}')
      PASS=\$(sudo -n ethtool -S ${REMOTE_INTERFACE} 2>/dev/null | awk '/bpf_pass_pkts/ {print \$2; f=1} END {if(!f) print 0}')
      HW_DOM=\$(sudo -n bpftool map dump name level_one_cache 2>/dev/null | awk '/key:/ {c++} END {print c+0}')
      DRV_DOM=\$(sudo -n bpftool map dump name cache_arecords 2>/dev/null | awk '/key:/ {c++} END {print c+0}')
      UB_Q=\$(sudo -n unbound-control stats_noreset 2>/dev/null | awk -F'=' '/^total.num.queries=/ {print \$2; f=1} END {if(!f) print 0}')
      echo \"\$HW_TX \$PASS \$HW_DOM \$DRV_DOM \$UB_Q\"
    ")
    SNAP_POST_LAST=$(echo "${SNAP_POST}" | tr -d '\r' | tail -n 1)
    HW_TX_END=$(echo "${SNAP_POST_LAST}" | awk '{print $1}')
    PASS_END=$(echo "${SNAP_POST_LAST}" | awk '{print $2}')
    HW_DOMAINS=$(echo "${SNAP_POST_LAST}" | awk '{print $3}')
    DRV_DOMAINS=$(echo "${SNAP_POST_LAST}" | awk '{print $4}')
    UB_Q_END=$(echo "${SNAP_POST_LAST}" | awk '{print $5}')
    HW_TX_END=${HW_TX_END:-0}
    PASS_END=${PASS_END:-0}
    HW_DOMAINS=${HW_DOMAINS:-0}
    DRV_DOMAINS=${DRV_DOMAINS:-0}
    UB_Q_END=${UB_Q_END:-0}

    DELTA_HW_TX=$((HW_TX_END - HW_TX_START))
    if [ "${DELTA_HW_TX}" -lt 0 ]; then DELTA_HW_TX=0; fi

    DELTA_PASS=$((PASS_END - PASS_START))
    if [ "${DELTA_PASS}" -lt 0 ]; then DELTA_PASS=0; fi

    DELTA_UB_Q=$((UB_Q_END - UB_Q_START))
    if [ "${DELTA_UB_Q}" -lt 0 ]; then DELTA_UB_Q=0; fi

    # Extrai métricas do CSV do cliente
    PARSED_METRICS=$(python3 -c "
import csv
try:
    with open('${CLIENT_OUTPUT_FILE}', 'r') as f:
        reader = csv.DictReader(f)
        row = next(reader)
        tot = int(float(row.get('totalSuccessResponses', row.get('totalRequests', 0))))
        qps = float(row.get('queriesPerSecond', 0))
        mean_lat = float(row.get('latency_mean_ms', 0))
        p99_lat = float(row.get('latency_p99_ms', 0))
        p99_9_lat = float(row.get('latency_p99_9_ms', 0))
        print(f'{tot} {qps:.1f} {mean_lat:.2f} {p99_lat:.2f} {p99_9_lat:.2f}')
except Exception:
    print('0 0.0 0.00 0.00 0.00')
")
    TOT_ANS=$(echo "${PARSED_METRICS}" | awk '{print $1}')
    QPS=$(echo "${PARSED_METRICS}" | awk '{print $2}')
    MEAN_LAT=$(echo "${PARSED_METRICS}" | awk '{print $3}')
    P99_LAT=$(echo "${PARSED_METRICS}" | awk '{print $4}')
    P99_9_LAT=$(echo "${PARSED_METRICS}" | awk '{print $5}')

    case "${MODE}" in
      "unbound_standalone")
        HW_ANS=0
        DRV_ANS=0
        USR_ANS=${TOT_ANS}
        HW_DOM_COUNT=0
        UB_DOM_COUNT=512
        ;;
      "unbound_hw_cache")
        HW_ANS=${DELTA_HW_TX}
        if [ "${HW_ANS}" -gt "${TOT_ANS}" ]; then HW_ANS=${TOT_ANS}; fi
        DRV_ANS=0
        USR_ANS=$((TOT_ANS - HW_ANS))
        HW_DOM_COUNT=${HW_DOMAINS}
        UB_DOM_COUNT=$((512 - HW_DOM_COUNT))
        if [ "${UB_DOM_COUNT}" -lt 0 ]; then UB_DOM_COUNT=0; fi
        ;;
      "ates_driver"|"no_hw_cache")
        HW_ANS=0
        if [ "${DELTA_UB_Q}" -gt "${TOT_ANS}" ]; then DELTA_UB_Q=${TOT_ANS}; fi
        USR_ANS=${DELTA_UB_Q}
        DRV_ANS=$((TOT_ANS - USR_ANS))
        HW_DOM_COUNT=0
        UB_DOM_COUNT=${DRV_DOMAINS}
        ;;
      "ates_hw_cache"|"hw_cache")
        HW_ANS=${DELTA_HW_TX}
        if [ "${HW_ANS}" -gt "${TOT_ANS}" ]; then HW_ANS=${TOT_ANS}; fi
        if [ "${DELTA_UB_Q}" -gt "$((TOT_ANS - HW_ANS))" ]; then DELTA_UB_Q=$((TOT_ANS - HW_ANS)); fi
        USR_ANS=${DELTA_UB_Q}
        DRV_ANS=$((TOT_ANS - HW_ANS - USR_ANS))
        HW_DOM_COUNT=${HW_DOMAINS}
        UB_DOM_COUNT=0
        ;;
    esac

    # Extrai telemetria de CPU/Rede do Servidor
    SRV_CPU_USER="0.0"
    SRV_CPU_SYS="0.0"
    SRV_CPU_SOFT="0.0"
    SRV_CPU_IDLE="0.0"
    SRV_MAX_CORE="0.0"
    if [ -f "${LOCAL_SERVER_OUTPUT_FILE}" ]; then
        SRV_METRICS=$(python3 -c "
import csv
metrics = {}
try:
    with open('${LOCAL_SERVER_OUTPUT_FILE}', 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2 and row[0].strip() != 'metric':
                try:
                    metrics[row[0].strip()] = float(row[1].strip())
                except ValueError:
                    pass
    u = metrics.get('cpu_user_mean', 0.0)
    s = metrics.get('cpu_system_mean', 0.0)
    soft = metrics.get('cpu_softirq_mean', 0.0)
    idle = max(0.0, 100.0 - (u + s + soft))
    maxc = metrics.get('max_core_usage_p99', 0.0)
    print(f'{u:.1f} {s:.1f} {soft:.1f} {idle:.1f} {maxc:.1f}')
except Exception:
    print('0.0 0.0 0.0 0.0 0.0')
")
        SRV_CPU_USER=$(echo "${SRV_METRICS}" | awk '{print $1}')
        SRV_CPU_SYS=$(echo "${SRV_METRICS}" | awk '{print $2}')
        SRV_CPU_SOFT=$(echo "${SRV_METRICS}" | awk '{print $3}')
        SRV_CPU_IDLE=$(echo "${SRV_METRICS}" | awk '{print $4}')
        SRV_MAX_CORE=$(echo "${SRV_METRICS}" | awk '{print $5}')
    fi

    # Extrai telemetria de CPU/Rede do Cliente
    CL_CPU_USER="0.0"
    CL_CPU_SYS="0.0"
    CL_CPU_IDLE="0.0"
    CL_MAX_CORE="0.0"
    CL_UDP_DROPS="0"
    if [ -f "${LOCAL_CLIENT_RES_FILE}" ]; then
        CL_METRICS=$(python3 -c "
metrics = {}
try:
    with open('${LOCAL_CLIENT_RES_FILE}', 'r') as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) >= 2:
                metrics[parts[0].strip()] = float(parts[1].strip())
    u = metrics.get('client_cpu_user_mean', 0.0)
    s = metrics.get('client_cpu_system_mean', 0.0)
    idle = metrics.get('client_cpu_idle_mean', 0.0)
    maxc = metrics.get('client_max_core_max', 0.0)
    drops = int(metrics.get('client_udp_rcvbuf_drops', 0))
    print(f'{u:.1f} {s:.1f} {idle:.1f} {maxc:.1f} {drops}')
except Exception:
    print('0.0 0.0 0.0 0.0 0')
")
        CL_CPU_USER=$(echo "${CL_METRICS}" | awk '{print $1}')
        CL_CPU_SYS=$(echo "${CL_METRICS}" | awk '{print $2}')
        CL_CPU_IDLE=$(echo "${CL_METRICS}" | awk '{print $3}')
        CL_MAX_CORE=$(echo "${CL_METRICS}" | awk '{print $4}')
        CL_UDP_DROPS=$(echo "${CL_METRICS}" | awk '{print $5}')
    fi

    # Salva na tabela consolidada
    echo "${MODE}|${TOT_ANS}|${QPS}|${MEAN_LAT}|${P99_LAT}|${P99_9_LAT}|${HW_ANS}|${DRV_ANS}|${USR_ANS}|${HW_DOM_COUNT}|${UB_DOM_COUNT}|${CL_CPU_USER}|${CL_CPU_SYS}|${CL_CPU_IDLE}|${CL_MAX_CORE}|${CL_UDP_DROPS}|${SRV_CPU_USER}|${SRV_CPU_SYS}|${SRV_CPU_SOFT}|${SRV_CPU_IDLE}|${SRV_MAX_CORE}" >> "${SUMMARY_LOG}"

    echo
    echo "📊 Telemetria Multi-Tier (${MODE}):"
    echo "   - Respostas no HW Cache:      ${HW_ANS} ($([ "${TOT_ANS}" -gt 0 ] && awk "BEGIN {printf \"%.1f\", (${HW_ANS}/${TOT_ANS})*100}" || echo 0)%)"
    echo "   - Respostas no Driver Cache:  ${DRV_ANS} ($([ "${TOT_ANS}" -gt 0 ] && awk "BEGIN {printf \"%.1f\", (${DRV_ANS}/${TOT_ANS})*100}" || echo 0)%)"
    echo "   - Respostas em Userspace:     ${USR_ANS} ($([ "${TOT_ANS}" -gt 0 ] && awk "BEGIN {printf \"%.1f\", (${USR_ANS}/${TOT_ANS})*100}" || echo 0)%)"
    echo "   - Domínios no HW Cache:       ${HW_DOM_COUNT}"
    echo "   - Domínios no Unbound:        ${UB_DOM_COUNT}"
    echo "   🖥️ Carga no Cliente (12 CPUs): User=${CL_CPU_USER}% | Sys=${CL_CPU_SYS}% | Idle=${CL_CPU_IDLE}% | MaxCore=${CL_MAX_CORE}% | UDP Drops=${CL_UDP_DROPS}"
    echo "   🖥️ Carga no Servidor (4 CPUs): User=${SRV_CPU_USER}% | Sys=${SRV_CPU_SYS}% | SoftIRQ=${SRV_CPU_SOFT}% | Idle=${SRV_CPU_IDLE}% | MaxCore=${SRV_MAX_CORE}%"

    echo
    echo "-> Encerrando processos remotos..."
    ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" "
      sudo -n pkill atesnds 2>/dev/null || true
      sudo -n pkill atesnds_daemon 2>/dev/null || true
      sudo -n pkill dns_listener 2>/dev/null || true
      sudo -n pkill time_updater 2>/dev/null || true
      sudo -n pkill -9 -f '[o]verload_governor.py' 2>/dev/null || true
      sudo -n systemctl stop unbound 2>/dev/null || sudo -n pkill -9 unbound 2>/dev/null || true

      tmux kill-session -t ates 2>/dev/null || true
      tmux kill-session -t hw 2>/dev/null || true
      tmux kill-session -t listener 2>/dev/null || true
      tmux kill-session -t unbound 2>/dev/null || true
      tmux kill-session -t srv 2>/dev/null || true
      tmux kill-session -t gov 2>/dev/null || true
    "
done

echo
echo "=================================================================================================================================="
echo "🎯 RESUMO FINAL MULTI-TIER: RESOLUÇÃO POR CAMADA (HW vs DRIVER vs USERSPACE)"
echo "=================================================================================================================================="
printf "%-20s | %-9s | %-8s | %-9s | %-8s | %-8s | %-12s | %-12s | %-13s | %-10s | %-10s\n" \
  "MODO" "TOTAL REQ" "QPS" "MEAN(ms)" "P99(ms)" "P99.9(ms)" "HW ANSWERS" "DRIVER ANS" "USERSPACE ANS" "HW DOMAINS" "UB DOMAINS"
echo "----------------------------------------------------------------------------------------------------------------------------------"

while IFS='|' read -r m_name m_tot m_qps m_mean m_p99 m_p99_9 m_hw m_drv m_usr m_hwdom m_ubdom cl_u cl_s cl_idl cl_max cl_dr srv_u srv_s srv_soft srv_idl srv_max; do
    printf "%-20s | %-9s | %-8s | %-9s | %-8s | %-8s | %-12s | %-12s | %-13s | %-10s | %-10s\n" \
      "${m_name}" "${m_tot}" "${m_qps}" "${m_mean}" "${m_p99}" "${m_p99_9}" "${m_hw}" "${m_drv}" "${m_usr}" "${m_hwdom}" "${m_ubdom}"
done < "${SUMMARY_LOG}"
echo "=================================================================================================================================="

echo
echo "=================================================================================================================================="
echo "🖥️ CONFIRMAÇÃO DE SOBRECARGA: CLIENTE (12 CORES) vs SERVIDOR (4 CORES)"
echo "=================================================================================================================================="
printf "%-20s | %-15s | %-15s | %-16s | %-16s | %-16s\n" \
  "MODO" "CLIENT CPU IDLE" "CLIENT MAX CORE" "CLIENT UDP DROPS" "SERVER CPU IDLE" "SERVER SOFTIRQ"
echo "----------------------------------------------------------------------------------------------------------------------------------"

while IFS='|' read -r m_name m_tot m_qps m_mean m_p99 m_p99_9 m_hw m_drv m_usr m_hwdom m_ubdom cl_u cl_s cl_idl cl_max cl_dr srv_u srv_s srv_soft srv_idl srv_max; do
    printf "%-20s | %-15s | %-15s | %-16s | %-16s | %-16s\n" \
      "${m_name}" "${cl_idl}%" "${cl_max}%" "${cl_dr}" "${srv_idl}%" "${srv_soft}% (Max: ${srv_max}%)"
done < "${SUMMARY_LOG}"
echo "=================================================================================================================================="

