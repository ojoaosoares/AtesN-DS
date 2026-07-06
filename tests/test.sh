#!/bin/bash

set -e

# --- Script Portability ---
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROJECT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

#########################
# CONFIGURAÇÃO
#########################

# Conexão Remota
REMOTE_USER="soares"
REMOTE_HOST="150.164.2.81"
REMOTE_BASE_DIR="/home/soares/Documentos/AtesN-DS"

# Parâmetros do Benchmark
NUM_RUNS=30
DURATION=60
# Warmup é obrigatório nos testes

# Configuração de Rede
REMOTE_INTERFACE="enp1s0np1"
REMOTE_SERVER_IP="192.168.0.1"
REMOTE_MAC_ADDR="3c:fd:fe:03:02:00"
REMOTE_DNS_SERVER="199.7.83.42"

LOCAL_INTERFACE="enp1s0f0np0"
LOCAL_CLIENT_IP="192.168.0.2"

# Scripts e Diretórios
REMOTE_PYTHON="python3"
REMOTE_SERVER_SCRIPT="${REMOTE_BASE_DIR}/tests/sample_server.py"
LOCAL_CLIENT_SCRIPT="${PROJECT_DIR}/tests/sample_client.py"
CONSOLIDATE_SCRIPT="${PROJECT_DIR}/graphs/consolidate.py"

# Diretórios de Resultados
REMOTE_RESULTS_DIR_SERVER="${REMOTE_BASE_DIR}/data/server"
LOCAL_RESULTS_DIR_CLIENT="${PROJECT_DIR}/data/client"
LOCAL_RESULTS_DIR_SERVER="${PROJECT_DIR}/data/server"
LOCAL_FINAL_RESULTS_DIR="${PROJECT_DIR}/data"

# Níveis de Concorrência e Modos
#CONCURRENCY_LEVELS=(512 896 1280 1792 2560 3584 5120 7168 10240 16384)
CONCURRENCY_LEVELS=(16384)
MODES=("no_hw_cache" "hw_cache")

#########################
# PREPARAÇÃO
#########################

echo "-> Preparando diretórios..."
mkdir -p "${LOCAL_RESULTS_DIR_CLIENT}"
mkdir -p "${LOCAL_RESULTS_DIR_SERVER}"
ssh -tt ${REMOTE_USER}@${REMOTE_HOST} "mkdir -p ${REMOTE_RESULTS_DIR_SERVER}"

#########################
# LOOP PRINCIPAL
#########################

for MODE in "${MODES[@]}"; do
  echo "==============================================="
  echo "Modo atual: ${MODE}"
  echo "==============================================="

  for CONCURRENCY in "${CONCURRENCY_LEVELS[@]}"; do
    echo
    echo "========== Iniciando concorrência ${CONCURRENCY} =========="

    # NOVO LOOP DE RUN: A lógica de reset/init/exec/kill acontece aqui dentro
    for run in $(seq 1 $NUM_RUNS); do
        echo
        echo "--> RUN ${run} / ${NUM_RUNS}"

        CLIENT_OUTPUT_FILE="${LOCAL_RESULTS_DIR_CLIENT}/client_output_${MODE}_${CONCURRENCY}_run${run}.csv"
        REMOTE_SERVER_OUTPUT_FILE="${REMOTE_RESULTS_DIR_SERVER}/server_output_${MODE}_${CONCURRENCY}_run${run}.csv"

        # 1. LIMPEZA E RESET
        echo "-> Limpando e resetando ambiente..."
        ssh -tt ${REMOTE_USER}@${REMOTE_HOST} "
          tmux kill-session -t srv 2>/dev/null || true
          tmux kill-session -t ates 2>/dev/null || true
          tmux kill-session -t hw 2>/dev/null || true
          sudo -n pkill atesnds 2>/dev/null || true
          sudo -n pkill time_updater 2>/dev/null || true
          sudo -n pkill sample_server.py 2>/dev/null || true
          (cd ${REMOTE_BASE_DIR} && sudo -n make unload-hw) 2>/dev/null || true
          sudo -n ip link set dev ${REMOTE_INTERFACE} down 2>/dev/null || true
          sleep 1
          sudo -n ip link set dev ${REMOTE_INTERFACE} up 2>/dev/null || true
          sudo -n ip addr flush dev ${REMOTE_INTERFACE} 2>/dev/null || true
          sudo -n ip addr add ${REMOTE_SERVER_IP}/24 dev ${REMOTE_INTERFACE} 2>/dev/null || true
        "
        sudo -n ip link set dev ${LOCAL_INTERFACE} down 2>/dev/null || true
        sleep 1
        sudo -n ip link set dev ${LOCAL_INTERFACE} up 2>/dev/null || true
        sudo -n ip addr flush dev ${LOCAL_INTERFACE} 2>/dev/null || true
        sudo -n ip addr add ${LOCAL_CLIENT_IP}/24 dev ${LOCAL_INTERFACE} 2>/dev/null || true
        sleep 2

        # 2. INICIALIZAÇÃO
        echo "-> Inicializando ambiente no servidor remoto..."
        if [ "${MODE}" = "hw_cache" ]; then
          ssh -tt ${REMOTE_USER}@${REMOTE_HOST} "cd ${REMOTE_BASE_DIR} && tmux new-session -d -s hw 'make load-and-run-time-updater'"
          sleep 3
        fi

        ssh -tt ${REMOTE_USER}@${REMOTE_HOST} "cd ${REMOTE_BASE_DIR} && tmux new-session -d -s ates 'sudo -n ./bin/atesnds -a ${REMOTE_SERVER_IP} -i ${REMOTE_INTERFACE} -m ${REMOTE_MAC_ADDR} -s ${REMOTE_DNS_SERVER}'"
        sleep 3

        # Warmup duration is always equal to DURATION since warmup is mandatory
        WARMUP_DURATION="${DURATION}"

        ssh -tt ${REMOTE_USER}@${REMOTE_HOST} "nohup ${REMOTE_PYTHON} ${REMOTE_SERVER_SCRIPT} ${REMOTE_SERVER_OUTPUT_FILE} ${DURATION} ${WARMUP_DURATION} > /dev/null 2>&1 &"
        sleep 2

        # 3. EXECUÇÃO DO CLIENTE (UMA MEDIÇÃO)
        echo "-> Executando cliente (run ${run})..."
        python3 "${LOCAL_CLIENT_SCRIPT}" \
            --server "${REMOTE_SERVER_IP}" \
            --duration "${DURATION}" \
            --concurrency "${CONCURRENCY}" \
            --warmup > "${CLIENT_OUTPUT_FILE}"

        # 4. ENCERRAMENTO
        echo "-> Encerrando processos remotos para esta execução..."
        ssh -tt ${REMOTE_USER}@${REMOTE_HOST} "
            sudo -n pkill sample_server.py 2>/dev/null || true
            sudo -n pkill atesnds 2>/dev/null || true
            sudo -n pkill time_updater 2>/dev/null || true
            tmux kill-session -t srv 2>/dev/null || true
            tmux kill-session -t ates 2>/dev/null || true
            tmux kill-session -t hw 2>/dev/null || true
        "
        echo "--> Fim da RUN ${run}"
    done

    # 5. CONSOLIDAÇÃO (após todos os runs da concorrência)
    echo
    echo "========== Fim da concorrência ${CONCURRENCY} =========="
    echo "-> Baixando arquivos de resultado do servidor..."
    scp "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_RESULTS_DIR_SERVER}/server_output_${MODE}_${CONCURRENCY}_run*.csv" "${LOCAL_RESULTS_DIR_SERVER}/" || echo "Nenhum arquivo de servidor para baixar, continuando."

    echo "-> Consolidando resultados..."
    python3 "${CONSOLIDATE_SCRIPT}" \
        --mode "${MODE}" \
        --concurrency "${CONCURRENCY}" \
        --client-dir "${LOCAL_RESULTS_DIR_CLIENT}" \
        --server-dir "${LOCAL_RESULTS_DIR_SERVER}" \
        --output-dir "${LOCAL_FINAL_RESULTS_DIR}"
  done
done

echo "✅ Todos os testes foram concluídos!"
