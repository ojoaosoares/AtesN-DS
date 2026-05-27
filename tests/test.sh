#!/bin/bash

#########################
# CONFIGURAÇÃO
#########################

REMOTE_USER="soares"
REMOTE_HOST="150.164.2.81"
REMOTE_BASE_DIR="/home/soares/Documentos/AtesN-DS"

REMOTE_PYTHON="python3"
REMOTE_SERVER_SCRIPT="${REMOTE_BASE_DIR}/tests/sample_server.py"
REMOTE_RESULTS_DIR="${REMOTE_BASE_DIR}/results"

LOCAL_CLIENT_SCRIPT="./tests/sample_client.py"
LOCAL_RESULTS_DIR="./results"

NUM_RUNS=2
DURATION=60
SERVER_IP="192.168.0.1"

TMUX_SESSION_SERVER="server_session"
TMUX_SESSION_ATES="ates_session"
TMUX_SESSION_HW="hw_session"

INTERFACE="enp1s0np1"
MAC_ADDR="3c:fd:fe:03:02:00"
DNS_SERVER="199.7.83.42"

CONCURRENCY_LEVELS=(1 2 4 8 16 32 64 128 256)

#########################
# MODOS DE EXECUÇÃO
#########################

MODES=("no_hw_cache" "hw_cache")

#########################
# LOOP PRINCIPAL
#########################

for MODE in "${MODES[@]}"; do

  echo "==============================================="
  echo "Modo atual: ${MODE}"
  echo "==============================================="

  for CONCURRENCY in "${CONCURRENCY_LEVELS[@]}"; do

    echo
    echo "========== Concorrência ${CONCURRENCY} =========="

    OUTPUT_SUFFIX="_${MODE}_${CONCURRENCY}.csv"

    REMOTE_OUTPUT="${REMOTE_RESULTS_DIR}/server_output${OUTPUT_SUFFIX}"
    LOCAL_OUTPUT="${LOCAL_RESULTS_DIR}/client_output${OUTPUT_SUFFIX}"

    #########################################
    # LIMPEZA PRÉVIA
    #########################################

    ssh ${REMOTE_USER}@${REMOTE_HOST} "
      tmux kill-session -t ${TMUX_SESSION_SERVER} 2>/dev/null || true
      tmux kill-session -t ${TMUX_SESSION_ATES} 2>/dev/null || true
      tmux kill-session -t ${TMUX_SESSION_HW} 2>/dev/null || true

      pkill -f atesnds || true
      pkill -f time_updater || true
    "

    #########################################
    # MODO HW CACHE
    #########################################

    if [ "${MODE}" = "hw_cache" ]; then

      echo "-> Iniciando time_updater (HW cache)"

      ssh ${REMOTE_USER}@${REMOTE_HOST} "
        cd ${REMOTE_BASE_DIR}

        tmux new-session -d -s ${TMUX_SESSION_HW}

        tmux send-keys -t ${TMUX_SESSION_HW} \
          'make load-and-run-time-updater' C-m
      "

      echo "-> Aguardando inicialização do HW updater..."
      sleep 5
    fi

    #########################################
    # INICIA ATESNDS
    #########################################

    echo "-> Iniciando atesnds"

    ssh ${REMOTE_USER}@${REMOTE_HOST} "
      cd ${REMOTE_BASE_DIR}

      tmux new-session -d -s ${TMUX_SESSION_ATES}

      tmux send-keys -t ${TMUX_SESSION_ATES} \
        'sudo ./bin/atesnds -a ${SERVER_IP} -i ${INTERFACE} -m ${MAC_ADDR} -s ${DNS_SERVER}' C-m
    "

    echo "-> Aguardando atesnds inicializar..."
    sleep 3

    #########################################
    # INICIA SERVIDOR PYTHON
    #########################################

    echo "-> Iniciando servidor Python"

    ssh ${REMOTE_USER}@${REMOTE_HOST} "
      tmux new-session -d -s ${TMUX_SESSION_SERVER}

      tmux send-keys -t ${TMUX_SESSION_SERVER} \
        '${REMOTE_PYTHON} ${REMOTE_SERVER_SCRIPT} ${REMOTE_OUTPUT} ${DURATION} ${NUM_RUNS}' C-m
    "

    echo "-> Aguardando servidor iniciar..."
    sleep 2

    #########################################
    # EXECUTA CLIENTE
    #########################################

    echo "-> Executando cliente"

    python3 ${LOCAL_CLIENT_SCRIPT} \
      "${LOCAL_OUTPUT}" \
      ${NUM_RUNS} ${SERVER_IP} ${DURATION}s ${CONCURRENCY}

    #########################################
    # AGUARDA FINALIZAÇÃO
    #########################################

    echo "-> Aguardando finalização..."
    sleep $((DURATION + 5))

    #########################################
    # ENCERRAMENTO
    #########################################

    echo "-> Encerrando processos"

    ssh ${REMOTE_USER}@${REMOTE_HOST} "

      tmux kill-session -t ${TMUX_SESSION_SERVER} 2>/dev/null || true
      tmux kill-session -t ${TMUX_SESSION_ATES} 2>/dev/null || true

      pkill -f atesnds || true

      if [ '${MODE}' = 'hw_cache' ]; then

        tmux kill-session -t ${TMUX_SESSION_HW} 2>/dev/null || true

        pkill -f time_updater || true

        cd ${REMOTE_BASE_DIR}

        make unload-hw
      fi
    "

    echo "========== Fim concorrência ${CONCURRENCY} =========="
    echo

  done

done

echo "✅ Todos os testes foram concluídos!"