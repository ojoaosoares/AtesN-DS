#!/bin/bash

#########################
# CONFIGURAÇÃO
#########################

REMOTE_USER="lecom"
REMOTE_HOST="192.168.0.1"
REMOTE_PYTHON="python3"
REMOTE_SERVER_SCRIPT="/home/lecom/AtesN-DS/sample/sample_server.py"
REMOTE_RESULTS_DIR="/home/lecom/AtesN-DS/results"

LOCAL_CLIENT_SCRIPT="./sample/sample_client.py"
LOCAL_RESULTS_DIR="./results"

NUM_RUNS=2
DURATION=60
SERVER_IP="192.168.0.1"    # ou DNS ou IP real do servidor
TMUX_SESSION="testsession"

CONCURRENCY_LEVELS=(1 2 4 8 16 32 64 128 256)

#########################
# CRIA PASTA LOCAL
#########################

# mkdir -p "$LOCAL_RESULTS_DIR"

# Garante pasta remota de resultados
# ssh ${REMOTE_USER}@${REMOTE_HOST} "mkdir -p ${REMOTE_RESULTS_DIR}"

#########################
# LOOP PARA CADA NÍVEL
#########################

for CONCURRENCY in "${CONCURRENCY_LEVELS[@]}"; do
  echo "========== Iniciando teste para concorrência $CONCURRENCY =========="

  # Nome de saída com sufixo
  OUTPUT_SUFFIX="_${CONCURRENCY}.csv"

  # Caminhos de saída
  REMOTE_OUTPUT="${REMOTE_RESULTS_DIR}/server_output${OUTPUT_SUFFIX}"
  LOCAL_OUTPUT="${LOCAL_RESULTS_DIR}/client_output${OUTPUT_SUFFIX}"

  # Inicia servidor remoto no tmux
  echo "-> Iniciando servidor remoto via tmux"
  ssh ${REMOTE_USER}@${REMOTE_HOST} "
    tmux new-session -d -s ${TMUX_SESSION} || true
    tmux send-keys -t ${TMUX_SESSION} \
      '${REMOTE_PYTHON} ${REMOTE_SERVER_SCRIPT} ${REMOTE_OUTPUT} ${DURATION} ${NUM_RUNS}' C-m
  "

  echo "-> Aguardando servidor iniciar..."
  sleep 1

  # Roda cliente local
  echo "-> Executando cliente local"
  python3 ${LOCAL_CLIENT_SCRIPT} \
    "${LOCAL_OUTPUT}" \
    ${NUM_RUNS} ${SERVER_IP} ${DURATION}s ${CONCURRENCY}

  # Aguarda servidor terminar
  echo "-> Aguardando servidor encerrar..."
  sleep $((DURATION + 5))

  # Mata a sessão tmux
  echo "-> Limpando sessão tmux no servidor"
  ssh ${REMOTE_USER}@${REMOTE_HOST} "tmux kill-session -t ${TMUX_SESSION} || true"

  echo "========== Fim do teste para concorrência $CONCURRENCY =========="
  echo
done

echo "✅ Todos os testes foram concluídos com sucesso!"
