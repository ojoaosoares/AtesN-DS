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

REMOTE_USER="soares"
REMOTE_HOST="150.164.2.81"
REMOTE_BASE_DIR="/home/soares/Documentos/AtesN-DS"

# Parâmetros para benchmark rápido
NUM_RUNS=1
DURATION=10

REMOTE_INTERFACE="enp1s0np1"
REMOTE_SERVER_IP="192.168.0.1"
REMOTE_MAC_ADDR="3c:fd:fe:03:02:00"
REMOTE_DNS_SERVER="199.7.83.42"

LOCAL_INTERFACE="enp1s0f0np0"
LOCAL_CLIENT_IP="192.168.0.2"

REMOTE_PYTHON="python3"
REMOTE_SERVER_SCRIPT="${REMOTE_BASE_DIR}/tests/sample_server.py"
LOCAL_CLIENT_SCRIPT="${PROJECT_DIR}/tests/sample_client.py"

DATA_DATE="quick_data_$(date +%Y-%m-%d_%H-%M-%S)"
LOCAL_RESULTS_DIR_CLIENT="${PROJECT_DIR}/${DATA_DATE}/client"
mkdir -p "${LOCAL_RESULTS_DIR_CLIENT}"

CONCURRENCY_LEVELS=(512)
MODES=("hw_cache")

echo "=========================================================="
echo "🚀 INICIANDO BENCHMARK RÁPIDO (1 run x 10s @ 512 conc)"
echo "=========================================================="

for MODE in "${MODES[@]}"; do
  for CONCURRENCY in "${CONCURRENCY_LEVELS[@]}"; do
    echo "-> Resetando ambiente no servidor remoto (${REMOTE_HOST})..."

    ssh -tt "${REMOTE_USER}@${REMOTE_HOST}" "
      tmux kill-session -t srv 2>/dev/null || true
      tmux kill-session -t ates 2>/dev/null || true
      tmux kill-session -t hw 2>/dev/null || true

      sudo -n pkill atesnds 2>/dev/null || true
      sudo -n pkill atesnds_daemon 2>/dev/null || true
      sudo -n pkill time_updater 2>/dev/null || true
      sudo -n pkill sample_server.py 2>/dev/null || true

      cd '${REMOTE_BASE_DIR}'
      sudo -n make unload-hw

      sudo -n ip link set dev '${REMOTE_INTERFACE}' down
      sleep 1
      sudo -n ip link set dev '${REMOTE_INTERFACE}' up
      sudo -n ethtool -N '${REMOTE_INTERFACE}' rx-flow-hash udp4 sdfn
      sudo -n ip addr flush dev '${REMOTE_INTERFACE}'
      sudo -n ip addr add '${REMOTE_SERVER_IP}/24' dev '${REMOTE_INTERFACE}'
    "

    echo "-> Resetando interface local (${LOCAL_INTERFACE})..."
    sudo -n ip link set dev "${LOCAL_INTERFACE}" down
    sleep 1
    sudo -n ip link set dev "${LOCAL_INTERFACE}" up
    sudo -n ip addr flush dev "${LOCAL_INTERFACE}"
    sudo -n ip addr add "${LOCAL_CLIENT_IP}/24" dev "${LOCAL_INTERFACE}"
    sleep 2

    echo "-> Carregando XDP no hardware e iniciando time_updater..."
    ssh -tt "${REMOTE_USER}@${REMOTE_HOST}" \
      "cd '${REMOTE_BASE_DIR}' && tmux new-session -d -s hw 'sudo -n make load-and-run-time-updater'"

    sleep 3

    echo "-> Iniciando atesnds no servidor..."
    ssh -tt "${REMOTE_USER}@${REMOTE_HOST}" \
      "cd '${REMOTE_BASE_DIR}' && tmux new-session -d -s ates 'sudo -n ./bin/atesnds -a ${REMOTE_SERVER_IP} -i ${REMOTE_INTERFACE} -m ${REMOTE_MAC_ADDR} -s ${REMOTE_DNS_SERVER}'"

    sleep 3

    echo "-> Executando dnspyre client (warmup + medição de 10s)..."
    CLIENT_OUTPUT_FILE="${LOCAL_RESULTS_DIR_CLIENT}/client_output_${MODE}_${CONCURRENCY}.csv"

    python3 "${LOCAL_CLIENT_SCRIPT}" \
        --server "${REMOTE_SERVER_IP}" \
        --duration "${DURATION}" \
        --concurrency "${CONCURRENCY}" \
        --warmup \
        | tee "${CLIENT_OUTPUT_FILE}"

    echo
    echo "-> Encerrando processos remotos..."
    ssh -tt "${REMOTE_USER}@${REMOTE_HOST}" "
      sudo -n pkill atesnds 2>/dev/null || true
      sudo -n pkill atesnds_daemon 2>/dev/null || true
      sudo -n pkill time_updater 2>/dev/null || true
      tmux kill-session -t ates 2>/dev/null || true
      tmux kill-session -t hw 2>/dev/null || true
    "
  done
done

echo
echo "=========================================================="
echo "✅ Benchmark concluído! Verifique o resultado acima."
echo "=========================================================="
