#!/bin/bash
# ==============================================================================
# tests/bench_all_cores.sh
# 
# Comprehensive Multi-Core Physical Benchmark Suite for AtesN-DS and Unbound
# Supports:
#   - Dynamic core scaling: NUM_CORES (1, 2, or 4 cores)
#   - Symmetrical NIC queue allocation: Queue 0 -> Core 0, Queue 1 -> Core 1, ...
#   - 4 Architectural Modes:
#       1) unbound_standalone
#       2) unbound_hw_cache (SmartNIC HW Cache + Decoupled Listener + Unbound)
#       3) ates_driver (Pure XDP Driver Mode + Unbound)
#       4) ates_hw_cache (SmartNIC HW Cache + AtesN-DS Driver + Unbound)
#   - Full CPU telemetry (mpstat) on Server and Client
#   - Multi-tier resolution breakdown: HW Cache vs Driver XDP vs Userspace
#   - Line-rate open-loop testing via dnsperf
# ==============================================================================

set -euo pipefail
export LC_ALL=C
ulimit -n 65535 2>/dev/null || true

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
if [ -f "$SCRIPT_DIR/sample_client_dnsperf.py" ]; then
    PROJECT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
    LOCAL_CLIENT_SCRIPT="$SCRIPT_DIR/sample_client_dnsperf.py"
elif [ -f "$SCRIPT_DIR/tests/sample_client_dnsperf.py" ]; then
    PROJECT_DIR="$SCRIPT_DIR"
    LOCAL_CLIENT_SCRIPT="$SCRIPT_DIR/tests/sample_client_dnsperf.py"
else
    PROJECT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
    LOCAL_CLIENT_SCRIPT="${PROJECT_DIR}/tests/sample_client_dnsperf.py"
fi
cd "${PROJECT_DIR}"

#########################
# CONFIGURAÇÃO
#########################

REMOTE_USER="joaosoares"
REMOTE_HOST="150.164.2.93"
REMOTE_BASE_DIR="/home/joaosoares/Documents/Github/AtesN-DS"

NUM_CORES="${1:-1}"               # 1, 2 ou 4 cores
TARGET_MODE="${2:-all}"           # 'all', 'unbound_standalone', 'unbound_hw_cache', 'ates_driver', 'ates_hw_cache'
TARGET_RATE="${3:-0}"             # 0 = UNLIMITED (Max Line Rate)
DURATION="${4:-10}"               # Duration in seconds
WARMUP_DURATION="${5:-4}"         # Warmup in seconds
CONCURRENCY="${6:-512}"           # Concurrent in-flight connections
THREADS="${7:-8}"                 # Client worker threads
MAX_OUTSTANDING="${8:-20000}"     # Maximum outstanding in-flight queue window
ENABLE_GOVERNOR="${9:-0}"         # 0 = Disabled (Raw Driver Limit), 1 = Enabled
QUERIES_FILE="${10:-${PROJECT_DIR}/dominios_5k_dnsperf.txt}"

if [ "${NUM_CORES}" -eq 1 ]; then
    SERVER_CORES="0"
elif [ "${NUM_CORES}" -eq 2 ]; then
    SERVER_CORES="0,1"
else
    SERVER_CORES="0,1,2,3"
fi

REMOTE_INTERFACE="enp1s0np1"
REMOTE_SERVER_IP="192.168.0.1"
REMOTE_MAC_ADDR="3c:fd:fe:03:02:00"
REMOTE_DNS_SERVER="192.168.0.2"

LOCAL_INTERFACE="enp1s0f0"
LOCAL_CLIENT_IP="192.168.0.2"

DATA_DATE="bench_${NUM_CORES}cores_$(date +%Y-%m-%d_%H-%M-%S)"
RESULTS_DIR="${PROJECT_DIR}/${DATA_DATE}"
mkdir -p "${RESULTS_DIR}"

if [ "${TARGET_MODE}" = "all" ]; then
    MODES=("unbound_standalone" "unbound_hw_cache" "ates_driver" "ates_hw_cache")
else
    MODES=("${TARGET_MODE}")
fi

echo "=========================================================================================="
echo "🚀 INICIANDO BENCHMARK MULTI-TIER (${NUM_CORES} CORES DO SERVIDOR)"
echo "Configuração: Modo=${TARGET_MODE} | Taxa Alvo=$([ "${TARGET_RATE}" -eq 0 ] && echo 'UNLIMITED (Linha Máxima)' || echo "${TARGET_RATE} QPS")"
echo "              Duração=${DURATION}s | Concorrência=${CONCURRENCY} | Threads Cliente=${THREADS} | Fila=${MAX_OUTSTANDING}"
echo "              Servidor: ${NUM_CORES} Cores (${SERVER_CORES}) com ${NUM_CORES} Filas de Hardware Sincronizadas"
echo "              Modos a testar: ${MODES[*]}"
echo "Diretório de resultados: ${RESULTS_DIR}"
echo "=========================================================================================="

echo "-> Inicializando Mock Authoritative DNS Responder (${LOCAL_CLIENT_IP}:53 na CPU 11)..."
sudo -n pkill -f mock_dns_server 2>/dev/null || true
sudo -n taskset -c 11 "${PROJECT_DIR}/tests/mock_dns_server" "${LOCAL_CLIENT_IP}" 53 >/tmp/mock_dns.log 2>&1 &
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
    echo "▶ EXECUTANDO MODO: ${MODE} (${NUM_CORES} CORES NO SERVIDOR: ${SERVER_CORES})"
    echo "=========================================================================================="

    echo "-> Resetando ambiente e configurando ${NUM_CORES} filas na NIC do servidor (${REMOTE_HOST})..."
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
      sudo -n make unload-hw 2>/dev/null || true
      sudo -n tc qdisc del dev '${REMOTE_INTERFACE}' clsact 2>/dev/null || true
      sudo -n bpftool net detach xdp dev '${REMOTE_INTERFACE}' 2>/dev/null || true
      sudo -n rm -f /sys/fs/bpf/dns_misses /sys/fs/bpf/overload_ctrl /sys/fs/bpf/hw_sync_ringbuf /sys/fs/bpf/level_one_cache /sys/fs/bpf/time_map /sys/fs/bpf/xdp_prog

      # Se o modo for com aceleração de HW, reseta o módulo NFP para garantir firmware limpo
      if [ '${MODE}' = 'unbound_hw_cache' ] || [ '${MODE}' = 'ates_hw_cache' ]; then
        sudo -n ip link set enp1s0np0 down 2>/dev/null || true
        sudo -n ip link set enp1s0np1 down 2>/dev/null || true
        sudo -n rmmod nfp 2>/dev/null || true
        sudo -n modprobe nfp 2>/dev/null || true
        sleep 3
      fi

      sudo -n ip link set dev '${REMOTE_INTERFACE}' down 2>/dev/null || true
      sleep 1
      sudo -n ip link set dev '${REMOTE_INTERFACE}' up
      
      # Aloca exatamente NUM_CORES filas combinadas
      sudo -n ethtool -L '${REMOTE_INTERFACE}' rx 0 tx 0 combined ${NUM_CORES} 2>/dev/null || sudo -n ethtool -L '${REMOTE_INTERFACE}' combined ${NUM_CORES} 2>/dev/null || true
      sudo -n ethtool -K '${REMOTE_INTERFACE}' rxhash on 2>/dev/null || true
      sudo -n ethtool -N '${REMOTE_INTERFACE}' rx-flow-hash udp4 sdfn 2>/dev/null || true
      sudo -n ethtool -K '${REMOTE_INTERFACE}' gro off lro off tso off gso off 2>/dev/null || true

      # Para irqbalance e distribui cada fila exatamente em um core
      sudo -n systemctl stop irqbalance 2>/dev/null || true
      
      RXTX_IRQS=(\$(grep 'enp1s0np1-rxtx-' /proc/interrupts | awk -F: '{print \$1}' | tr -d ' '))
      if [ '${NUM_CORES}' -eq 1 ]; then
        if [ \${#RXTX_IRQS[@]} -ge 1 ]; then
          echo 1 | sudo -n tee /proc/irq/\${RXTX_IRQS[0]}/smp_affinity >/dev/null # Core 0 (0x1)
        fi
      elif [ '${NUM_CORES}' -eq 2 ]; then
        if [ \${#RXTX_IRQS[@]} -ge 2 ]; then
          echo 1 | sudo -n tee /proc/irq/\${RXTX_IRQS[0]}/smp_affinity >/dev/null # Core 0 (0x1)
          echo 2 | sudo -n tee /proc/irq/\${RXTX_IRQS[1]}/smp_affinity >/dev/null # Core 1 (0x2)
        fi
      elif [ '${NUM_CORES}' -ge 4 ]; then
        if [ \${#RXTX_IRQS[@]} -ge 4 ]; then
          echo 1 | sudo -n tee /proc/irq/\${RXTX_IRQS[0]}/smp_affinity >/dev/null # Core 0 (0x1)
          echo 2 | sudo -n tee /proc/irq/\${RXTX_IRQS[1]}/smp_affinity >/dev/null # Core 1 (0x2)
          echo 4 | sudo -n tee /proc/irq/\${RXTX_IRQS[2]}/smp_affinity >/dev/null # Core 2 (0x4)
          echo 8 | sudo -n tee /proc/irq/\${RXTX_IRQS[3]}/smp_affinity >/dev/null # Core 3 (0x8)
        fi
      fi

      sudo -n ip addr flush dev '${REMOTE_INTERFACE}'
      sudo -n ip addr add '${REMOTE_SERVER_IP}/24' dev '${REMOTE_INTERFACE}'
    "

    echo "-> Verificando distribuição de IRQs das filas no servidor:"
    ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" "
      grep 'enp1s0np1-rxtx-' /proc/interrupts | head -n ${NUM_CORES} | while read -r line; do
        irq=\$(echo \"\$line\" | awk -F: '{print \$1}' | tr -d ' ')
        qname=\$(echo \"\$line\" | awk '{print \$NF}')
        aff=\$(cat /proc/irq/\$irq/smp_affinity 2>/dev/null || echo '?')
        printf '   • %-18s (IRQ %2s) -> smp_affinity = %s\n' \"\$qname\" \"\$irq\" \"\$aff\"
      done
    "

    echo "-> Resetando interface do cliente local (${LOCAL_INTERFACE})..."
    sudo -n ip link set dev "${LOCAL_INTERFACE}" down 2>/dev/null || true
    sleep 1
    sudo -n ip link set dev "${LOCAL_INTERFACE}" up 2>/dev/null || true
    sudo -n ip addr flush dev "${LOCAL_INTERFACE}" 2>/dev/null || true
    sudo -n ip addr add "${LOCAL_CLIENT_IP}/24" dev "${LOCAL_INTERFACE}" 2>/dev/null || true
    sudo -n sysctl -w net.core.rmem_max=33554432 >/dev/null 2>&1 || true
    sudo -n sysctl -w net.core.wmem_max=33554432 >/dev/null 2>&1 || true
    sudo -n sysctl -w net.core.rmem_default=33554432 >/dev/null 2>&1 || true
    sudo -n sysctl -w net.core.wmem_default=33554432 >/dev/null 2>&1 || true
    sleep 2

    echo "-> Verificando conectividade 10GbE entre cliente e servidor..."
    for i in {1..10}; do
        if ping -c 1 -W 1 "${REMOTE_SERVER_IP}" >/dev/null 2>&1; then
            echo "   Conexão 10GbE UP!"
            break
        fi
        sleep 1
    done

    echo "-> Inicializando ambiente no servidor para modo ${MODE}..."
    case "${MODE}" in
      "unbound_standalone")
        echo "   [Daemon] Unbound Standalone nos Cores ${SERVER_CORES}..."
        ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" "
          sudo -n systemctl restart unbound 2>/dev/null || sudo -n unbound -c /etc/unbound/unbound.conf 2>/dev/null || sudo -n unbound
          sleep 1
          pgrep -x unbound | xargs -r -n1 sudo -n taskset -cp ${SERVER_CORES} 2>/dev/null || true
        "
        sleep 2
        ;;

      "unbound_hw_cache")
        echo "   [SmartNIC] Carregando firmware offloaded XDP..."
        ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" \
          "cd '${REMOTE_BASE_DIR}' && sudo -n make load-hw"
        sleep 2
        echo "   [Daemon] Decoupled DNS Listener na interface ${REMOTE_INTERFACE}..."
        ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" \
          "cd '${REMOTE_BASE_DIR}' && tmux new-session -d -s listener 'sudo -n ./bin/dns_listener -i ${REMOTE_INTERFACE} -v'"
        sleep 2
        echo "   [Daemon] AtesN-DS Control-Plane Daemon (Ingestão + Relógio 1Hz)..."
        ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" \
          "cd '${REMOTE_BASE_DIR}' && tmux new-session -d -s hw 'sudo -n ./bin/atesnds_daemon -v'"
        sleep 2
        echo "   [Daemon] Unbound nos Cores ${SERVER_CORES}..."
        ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" "
          sudo -n systemctl restart unbound 2>/dev/null || sudo -n unbound -c /etc/unbound/unbound.conf 2>/dev/null || sudo -n unbound
          sleep 1
          pgrep -x unbound | xargs -r -n1 sudo -n taskset -cp ${SERVER_CORES} 2>/dev/null || true
        "
        sleep 2
        ;;

      "ates_driver")
        echo "   [Daemon] Unbound Fallback nos Cores ${SERVER_CORES}..."
        ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" "
          sudo -n systemctl restart unbound 2>/dev/null || sudo -n unbound -c /etc/unbound/unbound.conf 2>/dev/null || sudo -n unbound
          sleep 1
          pgrep -x unbound | xargs -r -n1 sudo -n taskset -cp ${SERVER_CORES} 2>/dev/null || true
        "
        sleep 1
        echo "   [Daemon] AtesN-DS Driver Mode nos Cores ${SERVER_CORES}..."
        ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" \
          "cd '${REMOTE_BASE_DIR}' && tmux new-session -d -s ates 'sudo -n taskset -c ${SERVER_CORES} ./bin/atesnds -a ${REMOTE_SERVER_IP} -i ${REMOTE_INTERFACE} -m ${REMOTE_MAC_ADDR} -s ${REMOTE_DNS_SERVER} -v'"
        sleep 3
        if ! ssh "${REMOTE_USER}@${REMOTE_HOST}" "pgrep -af atesnds" >/dev/null 2>&1; then
            echo "❌ ERRO: atesnds NÃO está rodando!"
            ssh "${REMOTE_USER}@${REMOTE_HOST}" "tmux capture-pane -t ates -p -S -100" || true
            exit 1
        fi
        if [ "${ENABLE_GOVERNOR}" = "1" ]; then
            echo "   [Daemon] Adaptive Overload Governor ativo nos Cores ${SERVER_CORES}..."
            ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" \
              "cd '${REMOTE_BASE_DIR}' && tmux new-session -d -s gov 'sudo -n taskset -c ${SERVER_CORES} python3 tests/overload_governor.py --cores ${SERVER_CORES}'"
            sleep 1
        else
            echo "   [Governor] DESATIVADO (Modo puro XDP sem shedding)..."
            ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" \
              "cd '${REMOTE_BASE_DIR}' && sudo -n python3 tests/manage_overload.py normal 2>/dev/null || true"
        fi
        ;;

      "ates_hw_cache")
        echo "   [SmartNIC] Carregando firmware offloaded XDP..."
        ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" \
          "cd '${REMOTE_BASE_DIR}' && sudo -n make load-hw"
        sleep 2
        echo "   [Daemon] AtesN-DS com HW Cache nos Cores ${SERVER_CORES}..."
        ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" \
          "cd '${REMOTE_BASE_DIR}' && tmux new-session -d -s ates 'sudo -n taskset -c ${SERVER_CORES} ./bin/atesnds -a ${REMOTE_SERVER_IP} -i ${REMOTE_INTERFACE} -m ${REMOTE_MAC_ADDR} -s ${REMOTE_DNS_SERVER} -v'"
        sleep 3
        if ! ssh "${REMOTE_USER}@${REMOTE_HOST}" "pgrep -af atesnds" >/dev/null 2>&1; then
            echo "❌ ERRO: atesnds NÃO está rodando!"
            ssh "${REMOTE_USER}@${REMOTE_HOST}" "tmux capture-pane -t ates -p -S -100" || true
            exit 1
        fi
        echo "   [Daemon] AtesN-DS Control-Plane Daemon (Ingestão + Relógio 1Hz)..."
        ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" \
          "cd '${REMOTE_BASE_DIR}' && tmux new-session -d -s hw 'sudo -n ./bin/atesnds_daemon -v'"
        sleep 2
        echo "   [Daemon] Unbound Fallback nos Cores ${SERVER_CORES}..."
        ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" "
          sudo -n systemctl restart unbound 2>/dev/null || sudo -n unbound -c /etc/unbound/unbound.conf 2>/dev/null || sudo -n unbound
          sleep 1
          pgrep -x unbound | xargs -r -n1 sudo -n taskset -cp ${SERVER_CORES} 2>/dev/null || true
        "
        sleep 2
        ;;
    esac

    sleep 2

    echo "-> Executando Warmup (${WARMUP_DURATION}s)..."
    python3 "${LOCAL_CLIENT_SCRIPT}" \
        --server "${REMOTE_SERVER_IP}" \
        --duration "${WARMUP_DURATION}" \
        --concurrency "${CONCURRENCY}" \
        --threads "${THREADS}" \
        --rate "${TARGET_RATE}" \
        --max-outstanding "${MAX_OUTSTANDING}" \
        --queries "${QUERIES_FILE}" \
        --warmup >/dev/null 2>&1 || true
    sleep 2

    echo "-> Verificando status dos caches após Warmup no servidor..."
    ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" "
      HW_ENTRIES=\$(sudo -n bpftool map dump name level_one_cache 2>/dev/null | grep -c 'key:' || echo 0)
      SW_ENTRIES=\$(sudo -n bpftool map dump name cache_arecords 2>/dev/null | grep -c 'key:' || echo 0)
      printf '   • SmartNIC level_one_cache: %s entradas\n' \"\$HW_ENTRIES\"
      printf '   • AtesN-DS cache_arecords:   %s entradas\n' \"\$SW_ENTRIES\"
    "
    sleep 1

    echo "-> Capturando snapshot pré-teste de hardware e telemetria no servidor..."
    PRE_IRQS=$(ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" "
      awk '/enp1s0np1-rxtx-/ {q=\$NF; sum=\$2+\$3+\$4+\$5; print q, sum}' /proc/interrupts | head -n ${NUM_CORES}
    ")
    
    PRE_STATS=$(ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" "
      HW_TX=\$(sudo -n ethtool -S ${REMOTE_INTERFACE} 2>/dev/null | awk '/bpf_app2_pkts/ {print \$2; f=1} END {if(!f) print 0}')
      PASS=\$(sudo -n ethtool -S ${REMOTE_INTERFACE} 2>/dev/null | awk '/bpf_pass_pkts/ {print \$2; f=1} END {if(!f) print 0}')
      UB_Q=\$(sudo -n unbound-control stats_noreset 2>/dev/null | awk -F'=' '/^total.num.queries=/ {print \$2; f=1} END {if(!f) print 0}')
      echo \"\$HW_TX \$PASS \$UB_Q\"
    ")
    HW_TX_START=$(echo "${PRE_STATS}" | awk '{print $1}')
    PASS_START=$(echo "${PRE_STATS}" | awk '{print $2}')
    UB_Q_START=$(echo "${PRE_STATS}" | awk '{print $3}')
    HW_TX_START=${HW_TX_START:-0}
    PASS_START=${PASS_START:-0}
    UB_Q_START=${UB_Q_START:-0}

    CLIENT_UDP_START=$(grep "^Udp:" /proc/net/snmp | awk 'NR==2 {print $6}')
    CLIENT_UDP_START=${CLIENT_UDP_START:-0}

    echo "-> Iniciando monitores de CPU (mpstat) no Servidor e no Cliente por ${DURATION} segundos..."
    SERVER_MPSTAT_FILE="/tmp/server_mpstat_${MODE}.txt"
    CLIENT_MPSTAT_FILE="${RESULTS_DIR}/client_mpstat_${MODE}.txt"

    ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" "
      LC_ALL=C mpstat -P ALL 1 ${DURATION} > ${SERVER_MPSTAT_FILE} 2>&1 &
    "

    LC_ALL=C mpstat -P ALL 1 "${DURATION}" > "${CLIENT_MPSTAT_FILE}" 2>&1 &
    CLIENT_MPSTAT_PID=$!

    echo "-> DISPARANDO CARGA MÁXIMA COM DNSPERF (${DURATION}s)..."
    RATE_LABEL="$([ "${TARGET_RATE}" -eq 0 ] && echo 'UNLIMITED (Linha Máxima)' || echo "${TARGET_RATE} QPS")"
    echo "   Taxa Alvo: ${RATE_LABEL} | Threads Cliente: ${THREADS} | Concorrência: ${CONCURRENCY} | Fila: ${MAX_OUTSTANDING}"

    BENCH_OUT=$(python3 "${LOCAL_CLIENT_SCRIPT}" \
        --server "${REMOTE_SERVER_IP}" \
        --duration "${DURATION}" \
        --concurrency "${CONCURRENCY}" \
        --threads "${THREADS}" \
        --rate "${TARGET_RATE}" \
        --queries "${QUERIES_FILE}" \
        --max-outstanding "${MAX_OUTSTANDING}")

    echo "   Aguardando finalização dos monitores de telemetria..."
    wait ${CLIENT_MPSTAT_PID} 2>/dev/null || true
    sleep 2

    # Snapshot pós-teste
    POST_IRQS=$(ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" "
      awk '/enp1s0np1-rxtx-/ {q=\$NF; sum=\$2+\$3+\$4+\$5; print q, sum}' /proc/interrupts | head -n ${NUM_CORES}
    ")

    POST_STATS=$(ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" "
      HW_TX=\$(sudo -n ethtool -S ${REMOTE_INTERFACE} 2>/dev/null | awk '/bpf_app2_pkts/ {print \$2; f=1} END {if(!f) print 0}')
      PASS=\$(sudo -n ethtool -S ${REMOTE_INTERFACE} 2>/dev/null | awk '/bpf_pass_pkts/ {print \$2; f=1} END {if(!f) print 0}')
      UB_Q=\$(sudo -n unbound-control stats_noreset 2>/dev/null | awk -F'=' '/^total.num.queries=/ {print \$2; f=1} END {if(!f) print 0}')
      echo \"\$HW_TX \$PASS \$UB_Q\"
    ")
    HW_TX_END=$(echo "${POST_STATS}" | awk '{print $1}')
    PASS_END=$(echo "${POST_STATS}" | awk '{print $2}')
    UB_Q_END=$(echo "${POST_STATS}" | awk '{print $3}')
    HW_TX_END=${HW_TX_END:-0}
    PASS_END=${PASS_END:-0}
    UB_Q_END=${UB_Q_END:-0}

    CLIENT_UDP_END=$(grep "^Udp:" /proc/net/snmp | awk 'NR==2 {print $6}')
    CLIENT_UDP_END=${CLIENT_UDP_END:-0}
    CLIENT_UDP_DROPS=$(( CLIENT_UDP_END - CLIENT_UDP_START ))

    # Puxa o mpstat do servidor
    SERVER_MPSTAT_LOCAL="${RESULTS_DIR}/server_mpstat_${MODE}.txt"
    scp -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}:${SERVER_MPSTAT_FILE}" "${SERVER_MPSTAT_LOCAL}" >/dev/null 2>&1 || true

    # Parse do dnsperf
    CSV_LINE=$(echo "${BENCH_OUT}" | tail -n 1)
    IFS=',' read -r tot_req tot_ans qps lat_mean lat_p50 lat_p75 lat_p90 lat_p95 lat_p99 lat_p99_9 lat_min lat_max lat_std loss_pct loss_cnt trgt <<< "${CSV_LINE}"

    # Multi-tier breakdown
    DELTA_HW=$(( HW_TX_END - HW_TX_START ))
    if [ "${DELTA_HW}" -lt 0 ]; then DELTA_HW=0; fi

    DELTA_PASS=$(( PASS_END - PASS_START ))
    if [ "${DELTA_PASS}" -lt 0 ]; then DELTA_PASS=0; fi

    DELTA_UB=$(( UB_Q_END - UB_Q_START ))
    if [ "${DELTA_UB}" -lt 0 ]; then DELTA_UB=0; fi

    case "${MODE}" in
      "unbound_standalone")
        HW_ANS=0
        DRIVER_ANS=0
        USERS_ANS="${tot_ans}"
        ;;
      "unbound_hw_cache")
        HW_ANS="${DELTA_HW}"
        if [ "${HW_ANS}" -gt "${tot_ans}" ]; then HW_ANS="${tot_ans}"; fi
        DRIVER_ANS=0
        USERS_ANS=$(( tot_ans - HW_ANS ))
        ;;
      "ates_driver")
        HW_ANS=0
        USERS_ANS="${DELTA_UB}"
        if [ "${USERS_ANS}" -gt "${tot_ans}" ]; then USERS_ANS="${tot_ans}"; fi
        DRIVER_ANS=$(( tot_ans - USERS_ANS ))
        ;;
      "ates_hw_cache")
        HW_ANS="${DELTA_HW}"
        if [ "${HW_ANS}" -gt "${tot_ans}" ]; then HW_ANS="${tot_ans}"; fi
        USERS_ANS="${DELTA_UB}"
        if [ $(( HW_ANS + USERS_ANS )) -gt "${tot_ans}" ]; then
            USERS_ANS=$(( tot_ans - HW_ANS ))
        fi
        DRIVER_ANS=$(( tot_ans - HW_ANS - USERS_ANS ))
        ;;
    esac

    echo
    echo "=========================================================================================="
    echo "📊 RESULTADOS DE PERFORMANCE: ${MODE} (${NUM_CORES} CORES)"
    echo "=========================================================================================="
    printf " • Pacotes Enviados:       %s\n" "${tot_req}"
    printf " • Respostas Concluídas:   %s\n" "${tot_ans}"
    printf " • Pacotes Perdidos:       %s (%s%%)\n" "${loss_cnt}" "${loss_pct}"
    printf " • Vazão Real Sustentada:  %s QPS\n" "${qps}"
    printf " • Latência Média:         %s ms\n" "${lat_mean}"
    printf " • Latência Mín / Máx:     %s ms / %s ms\n" "${lat_min}" "${lat_max}"
    printf " • Latência StdDev:        %s ms\n" "${lat_std}"
    printf " • Percentis Latência:     p50=%s ms | p90=%s ms | p99=%s ms | p99.9=%s ms\n" \
           "${lat_p50}" "${lat_p90}" "${lat_p99}" "${lat_p99_9}"
    printf " • Respostas no HW Cache:  %s\n" "${HW_ANS}"
    printf " • Respostas no Driver:    %s\n" "${DRIVER_ANS}"
    printf " • Respostas em Userspace: %s\n" "${USERS_ANS}"

    echo
    echo "------------------------------------------------------------------------------------------"
    echo "⚖️ DISTRIBUIÇÃO DAS FILAS DE REDE (PROVA DE BALANCEAMENTO ENTRE OS ${NUM_CORES} CORES)"
    echo "------------------------------------------------------------------------------------------"
    printf "%-18s | %-15s | %-15s | %-15s\n" "FILA DA NIC" "INTERRUPÇÕES PRÉ" "INTERRUPÇÕES PÓS" "PACOTES PROCESSADOS (%)"
    echo "------------------------------------------------------------------------------------------"
    
    TOTAL_IRQ_DELTA=0
    declare -A IRQ_DELTAS
    while read -r qname count; do
        if [ -n "${qname}" ]; then
            post_count=$(echo "${POST_IRQS}" | awk -v q="${qname}" '$1==q {print $2}')
            post_count=${post_count:-$count}
            delta=$(( post_count - count ))
            if [ "${delta}" -lt 0 ]; then delta=0; fi
            IRQ_DELTAS["${qname}"]=${delta}
            TOTAL_IRQ_DELTA=$(( TOTAL_IRQ_DELTA + delta ))
        fi
    done <<< "${PRE_IRQS}"

    for qname in $(echo "${!IRQ_DELTAS[@]}" | tr ' ' '\n' | sort); do
        pre_cnt=$(echo "${PRE_IRQS}" | awk -v q="${qname}" '$1==q {print $2}')
        post_cnt=$(echo "${POST_IRQS}" | awk -v q="${qname}" '$1==q {print $2}')
        delta=${IRQ_DELTAS["${qname}"]}
        pct=0.0
        if [ "${TOTAL_IRQ_DELTA}" -gt 0 ]; then
            pct=$(awk -v d="${delta}" -v t="${TOTAL_IRQ_DELTA}" 'BEGIN {printf "%.2f", (d/t)*100}')
        fi
        printf "%-18s | %-15s | %-15s | %s (%s%%)\n" "${qname}" "${pre_cnt}" "${post_cnt}" "${delta}" "${pct}"
    done
    echo "------------------------------------------------------------------------------------------"

    echo
    echo "------------------------------------------------------------------------------------------"
    echo "🖥️ TELEMETRIA DE CPU DO SERVIDOR: TODOS OS NÚCLEOS (mpstat)"
    echo "------------------------------------------------------------------------------------------"
    printf "%-8s | %-10s | %-10s | %-10s | %-10s | %-10s\n" "CPU" "USER%" "SYS%" "SOFTIRQ%" "IDLE%" "STATUS"
    echo "------------------------------------------------------------------------------------------"
    awk '/^Average:/ {
        cpu=$2; usr=$3; sys=$5; soft=$8; idle=$12;
        status = "OK";
        if (idle + 0.0 < 5.0) status = "🔥 SATURADO";
        else if (idle + 0.0 < 25.0) status = "⚠️ ELEVADO";
        else status = "🟢 FOLGA";
        printf "%-8s | %9s%% | %9s%% | %9s%% | %9s%% | %s\n", cpu, usr, sys, soft, idle, status;
    }' "${SERVER_MPSTAT_LOCAL}"
    echo "------------------------------------------------------------------------------------------"

    echo
    echo "------------------------------------------------------------------------------------------"
    echo "💻 TELEMETRIA DE CPU DO CLIENTE: 12 NÚCLEOS E SOCKET DROPS"
    echo "------------------------------------------------------------------------------------------"
    printf " • Client UDP Drops: %s\n" "${CLIENT_UDP_DROPS}"
    printf "%-8s | %-10s | %-10s | %-10s | %-10s\n" "CPU" "USER%" "SYS%" "SOFTIRQ%" "IDLE%"
    echo "------------------------------------------------------------------------------------------"
    awk '/^Average:/ {
        cpu=$2; usr=$3; sys=$5; soft=$8; idle=$12;
        if (cpu == "all" || cpu == "0" || cpu == "1" || cpu == "2" || cpu == "3" || cpu == "4" || cpu == "5" || cpu == "10") {
            printf "%-8s | %9s%% | %9s%% | %9s%% | %9s%%\n", cpu, usr, sys, soft, idle;
        }
    }' "${CLIENT_MPSTAT_FILE}"
    echo "------------------------------------------------------------------------------------------"

    echo "${MODE}|${tot_req}|${tot_ans}|${loss_pct}|${qps}|${lat_mean}|${lat_p99}|${HW_ANS}|${DRIVER_ANS}|${USERS_ANS}|${CLIENT_UDP_DROPS}" >> "${RESULTS_DIR}/summary.csv"
done

echo
echo "=================================================================================================================================="
echo "🎯 RESUMO COMPARATIVO FINAL EM ${NUM_CORES} CORES (${SERVER_CORES})"
echo "=================================================================================================================================="
printf "%-20s | %-10s | %-10s | %-8s | %-12s | %-9s | %-9s | %-10s | %-10s | %-10s\n" \
  "MODO (${NUM_CORES} CORES)" "ENVIADOS" "RESOLVIDOS" "PERDA(%)" "QPS REAL" "MEAN(ms)" "P99(ms)" "HW ANS" "DRIVER ANS" "USERS ANS"
echo "----------------------------------------------------------------------------------------------------------------------------------"
while IFS='|' read -r m req ans l_pct q_val l_m l_99 hw_ans d_ans u_ans u_drp; do
    printf "%-20s | %-10s | %-10s | %-7s%% | %-12s | %-8sms | %-8sms | %-10s | %-10s | %-10s\n" \
      "${m}" "${req}" "${ans}" "${l_pct}" "${q_val}" "${l_m}" "${l_99}" "${hw_ans}" "${d_ans}" "${u_ans}"
done < "${RESULTS_DIR}/summary.csv"
echo "=================================================================================================================================="
echo "Resultados completos e logs salvos em: ${RESULTS_DIR}"
