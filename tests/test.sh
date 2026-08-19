#!/bin/bash

set -euo pipefail

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
DATA_DATE="data_$(date +%Y-%m-%d)"
REMOTE_RESULTS_DIR_SERVER="${REMOTE_BASE_DIR}/${DATA_DATE}/server"
LOCAL_RESULTS_DIR_CLIENT="${PROJECT_DIR}/${DATA_DATE}/client"
LOCAL_RESULTS_DIR_SERVER="${PROJECT_DIR}/${DATA_DATE}/server"
LOCAL_FINAL_RESULTS_DIR="${PROJECT_DIR}/${DATA_DATE}"

# Níveis de Concorrência e Modos
CONCURRENCY_LEVELS=(512 896 1280 1792 2560 3584 5120 7168 10240 16384)
# CONCURRENCY_LEVELS=(754)

MODES=("hw_cache")
# MODES=("hw_cache")

#########################
# TRATAMENTO DE ERROS
#########################

CURRENT_MODE=""
CURRENT_CONCURRENCY=""
CURRENT_RUN=""

error_handler() {
    local exit_code=$?
    echo
    echo "=================================================="
    echo "❌ ERRO!"
    echo "Modo:         ${CURRENT_MODE}"
    echo "Concorrência: ${CURRENT_CONCURRENCY}"
    echo "RUN:          ${CURRENT_RUN}"
    echo "Comando:      ${BASH_COMMAND}"
    echo "Exit code:    ${exit_code}"
    echo "=================================================="
    exit "${exit_code}"
}

trap error_handler ERR

#########################
# PREPARAÇÃO
#########################

echo "-> Preparando diretórios..."

mkdir -p "${LOCAL_RESULTS_DIR_CLIENT}"
mkdir -p "${LOCAL_RESULTS_DIR_SERVER}"

ssh -tt "${REMOTE_USER}@${REMOTE_HOST}" \
  "mkdir -p '${REMOTE_RESULTS_DIR_SERVER}'"

#########################
# LOOP PRINCIPAL
#########################

for MODE in "${MODES[@]}"; do

  CURRENT_MODE="${MODE}"

  echo "==============================================="
  echo "Modo atual: ${MODE}"
  echo "==============================================="

  for CONCURRENCY in "${CONCURRENCY_LEVELS[@]}"; do

    CURRENT_CONCURRENCY="${CONCURRENCY}"

    echo
    echo "========== Iniciando concorrência ${CONCURRENCY} =========="

    for run in $(seq 1 "$NUM_RUNS"); do

        CURRENT_RUN="${run}"

        echo
        echo "--> RUN ${run} / ${NUM_RUNS}"

        CLIENT_OUTPUT_FILE="${LOCAL_RESULTS_DIR_CLIENT}/client_output_${MODE}_${CONCURRENCY}_run${run}.csv"
        REMOTE_SERVER_OUTPUT_FILE="${REMOTE_RESULTS_DIR_SERVER}/server_output_${MODE}_${CONCURRENCY}_run${run}.csv"

        #########################
        # 1. LIMPEZA E RESET
        #########################

        echo "-> Limpando e resetando ambiente..."

        ssh -tt "${REMOTE_USER}@${REMOTE_HOST}" "
          echo '[REMOTE] Matando sessões tmux...'

          tmux kill-session -t srv 2>/dev/null || true
          tmux kill-session -t ates 2>/dev/null || true
          tmux kill-session -t hw 2>/dev/null || true

          echo '[REMOTE] Matando processos...'

          sudo -n pkill atesnds 2>/dev/null || true
          sudo -n pkill time_updater 2>/dev/null || true
          sudo -n pkill sample_server.py 2>/dev/null || true

          echo '[REMOTE] Executando unload-hw...'

          cd '${REMOTE_BASE_DIR}'
          sudo -n make unload-hw

          echo '[REMOTE] Resetando interface...'

          sudo -n ip link set dev '${REMOTE_INTERFACE}' down
          sleep 1
          sudo -n ip link set dev '${REMOTE_INTERFACE}' up

          echo '[REMOTE] Configurando RSS...'

          sudo -n ethtool -N '${REMOTE_INTERFACE}' rx-flow-hash udp4 sdfn

          echo '[REMOTE] Configurando IP...'

          sudo -n ip addr flush dev '${REMOTE_INTERFACE}'
          sudo -n ip addr add '${REMOTE_SERVER_IP}/24' dev '${REMOTE_INTERFACE}'

          echo '[REMOTE] Cleanup concluído.'
        "

        echo "-> Resetando interface local..."

        sudo -n ip link set dev "${LOCAL_INTERFACE}" down
        sleep 1
        sudo -n ip link set dev "${LOCAL_INTERFACE}" up
        sudo -n ip addr flush dev "${LOCAL_INTERFACE}"
        sudo -n ip addr add "${LOCAL_CLIENT_IP}/24" dev "${LOCAL_INTERFACE}"

        sleep 2

        #########################
        # 2. INICIALIZAÇÃO
        #########################

        echo "-> Inicializando ambiente no servidor remoto..."

        if [ "${MODE}" = "hw_cache" ]; then

          echo "-> Iniciando load-and-run-time-updater..."

          ssh -tt "${REMOTE_USER}@${REMOTE_HOST}" \
            "cd '${REMOTE_BASE_DIR}' && \
             tmux new-session -d -s hw 'sudo -n make load-and-run-time-updater'"

          sleep 3

          echo "-> Verificando sessão tmux 'hw'..."

          ssh "${REMOTE_USER}@${REMOTE_HOST}" \
            "tmux has-session -t hw"

          echo "-> Saída do tmux 'hw':"

          ssh "${REMOTE_USER}@${REMOTE_HOST}" \
            "tmux capture-pane -t hw -p -S -100"

          echo "-> Verificando time_updater..."

          if ! ssh "${REMOTE_USER}@${REMOTE_HOST}" \
              "pgrep -af time_updater"; then

              echo
              echo "❌ ERRO: time_updater NÃO está rodando!"
              echo
              echo "===== SAÍDA DO TMUX hw ====="

              ssh "${REMOTE_USER}@${REMOTE_HOST}" \
                "tmux capture-pane -t hw -p -S -200"

              exit 1
          fi

          echo "-> time_updater está rodando."

        fi

        #########################
        # ATES
        #########################

        echo "-> Iniciando atesnds..."

        ssh -tt "${REMOTE_USER}@${REMOTE_HOST}" \
          "cd '${REMOTE_BASE_DIR}' && \
           tmux new-session -d -s ates \
           'sudo -n ./bin/atesnds \
            -a ${REMOTE_SERVER_IP} \
            -i ${REMOTE_INTERFACE} \
            -m ${REMOTE_MAC_ADDR} \
            -s ${REMOTE_DNS_SERVER}'"

        sleep 3

        echo "-> Verificando atesnds..."

        if ! ssh "${REMOTE_USER}@${REMOTE_HOST}" \
            "pgrep -af atesnds"; then

            echo "❌ ERRO: atesnds NÃO está rodando!"

            ssh "${REMOTE_USER}@${REMOTE_HOST}" \
              "tmux capture-pane -t ates -p -S -100"

            exit 1
        fi

        #########################
        # SAMPLE SERVER
        #########################

        WARMUP_DURATION="${DURATION}"

        echo "-> Iniciando sample_server.py..."

        ssh -tt "${REMOTE_USER}@${REMOTE_HOST}" \
          "mkdir -p \"$(dirname "${REMOTE_SERVER_OUTPUT_FILE}")\" && \
           tmux kill-session -t srv 2>/dev/null || true && \
           tmux new-session -d -s srv \
           '${REMOTE_PYTHON} ${REMOTE_SERVER_SCRIPT} \
            ${REMOTE_SERVER_OUTPUT_FILE} \
            ${DURATION} \
            ${WARMUP_DURATION}'"

        sleep 2

        echo "-> Verificando sample_server.py..."

        if ! ssh "${REMOTE_USER}@${REMOTE_HOST}" \
            "pgrep -af sample_server.py"; then

            echo "❌ ERRO: sample_server.py NÃO está rodando!"

            ssh "${REMOTE_USER}@${REMOTE_HOST}" \
              "tmux capture-pane -t srv -p -S -100"

            exit 1
        fi

        #########################
        # 3. EXECUÇÃO DO CLIENTE
        #########################

        echo "-> Executando cliente..."

        python3 "${LOCAL_CLIENT_SCRIPT}" \
            --server "${REMOTE_SERVER_IP}" \
            --duration "${DURATION}" \
            --concurrency "${CONCURRENCY}" \
            --warmup \
            > "${CLIENT_OUTPUT_FILE}"

        #########################
        # 3.5. AGUARDAR MONITOR
        #########################

        echo "-> Aguardando sample_server.py concluir..."

        for i in {1..30}; do

          if ! ssh "${REMOTE_USER}@${REMOTE_HOST}" \
              "pgrep -f 'python.*sample_server.py'" \
              >/dev/null 2>&1; then

            echo "-> sample_server.py finalizou."
            break
          fi

          sleep 2

        done

        #########################
        # 4. ENCERRAMENTO
        #########################

        echo "-> Encerrando processos remotos..."

        ssh -tt "${REMOTE_USER}@${REMOTE_HOST}" "
            sudo -n pkill sample_server.py 2>/dev/null || true
            sudo -n pkill atesnds 2>/dev/null || true
            sudo -n pkill time_updater 2>/dev/null || true

            tmux kill-session -t srv 2>/dev/null || true
            tmux kill-session -t ates 2>/dev/null || true
            tmux kill-session -t hw 2>/dev/null || true
        "

        echo "--> Fim da RUN ${run}"

    done

    #########################
    # 5. CONSOLIDAÇÃO
    #########################

    echo
    echo "========== Fim da concorrência ${CONCURRENCY} =========="

    echo "-> Baixando arquivos de resultado do servidor..."

    scp \
      "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_RESULTS_DIR_SERVER}/server_output_${MODE}_${CONCURRENCY}_run*.csv" \
      "${LOCAL_RESULTS_DIR_SERVER}/"

    echo "-> Consolidando resultados..."

    python3 "${CONSOLIDATE_SCRIPT}" \
        --mode "${MODE}" \
        --concurrency "${CONCURRENCY}" \
        --client-dir "${LOCAL_RESULTS_DIR_CLIENT}" \
        --server-dir "${LOCAL_RESULTS_DIR_SERVER}" \
        --output-dir "${LOCAL_FINAL_RESULTS_DIR}"

  done

done

echo
echo "==============================================="
echo "✅ Todos os testes foram concluídos!"
echo "==============================================="