#!/bin/bash

set -e

# ============================================================
# SCRIPT PORTABILITY
# ============================================================

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROJECT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

# ============================================================
# CONFIGURAÇÃO
# ============================================================

# Conexão Remota
REMOTE_USER="soares"
REMOTE_HOST="150.164.2.81"
REMOTE_BASE_DIR="/home/soares/Documentos/AtesN-DS"

# Parâmetros do Benchmark
NUM_RUNS=10
DURATION=60

# Configuração de Rede
REMOTE_INTERFACE="enp1s0np1"
REMOTE_SERVER_IP="192.168.0.1"
REMOTE_MAC_ADDR="3c:fd:fe:03:02:00"
REMOTE_DNS_SERVER="199.7.83.42"

LOCAL_INTERFACE="enp1s0f0np0"
LOCAL_CLIENT_IP="192.168.0.2"

# ============================================================
# SCRIPTS E DIRETÓRIOS
# ============================================================

REMOTE_PYTHON="python3"
REMOTE_SERVER_SCRIPT="${REMOTE_BASE_DIR}/tests/sample_server.py"
LOCAL_CLIENT_SCRIPT="${PROJECT_DIR}/tests/sample_client.py"
CONSOLIDATE_SCRIPT="${PROJECT_DIR}/graphs/consolidate.py"

REMOTE_RESULTS_DIR_SERVER="${REMOTE_BASE_DIR}/data/server"
LOCAL_RESULTS_DIR_CLIENT="${PROJECT_DIR}/data/client"
LOCAL_RESULTS_DIR_SERVER="${PROJECT_DIR}/data/server"
LOCAL_FINAL_RESULTS_DIR="${PROJECT_DIR}/data"

# ============================================================
# BPF
# ============================================================

BPF_MISS_MAP="/sys/fs/bpf/dns_misses"

# ============================================================
# NÍVEIS DE CONCORRÊNCIA E MODOS
# ============================================================

# CONCURRENCY_LEVELS=(512 896 1280 1792 2560 3584 5120 7168 10240 16384)
#CONCURRENCY_LEVELS=(896 2560 7168 12288 17408 20224)
CONCURRENCY_LEVELS=(754)

MODES=("hw_cache")

# ============================================================
# FUNÇÃO: ZERAR DNS MISSES
# ============================================================

reset_cache_misses()
{
    echo "-> Zerando dns_misses..."

    ssh "${REMOTE_USER}@${REMOTE_HOST}" \
        "sudo -n bpftool map update pinned ${BPF_MISS_MAP} \
        key hex 00 00 00 00 \
        value hex 00 00 00 00 00 00 00 00"

    echo "-> dns_misses zerado."
}

# ============================================================
# FUNÇÃO: COLETAR DNS MISSES
# ============================================================

get_cache_misses()
{
    ssh "${REMOTE_USER}@${REMOTE_HOST}" \
        "sudo -n bpftool map dump pinned ${BPF_MISS_MAP}" |
    python3 -c '
import sys
import re

total = 0

for line in sys.stdin:

    # Exemplo:
    #
    # value (CPU 04): 54 66 00 00 00 00 00 00

    m = re.search(
        r"value \(CPU \d+\): ((?:[0-9a-fA-F]{2} ?){8})",
        line
    )

    if m:
        raw = bytes.fromhex(m.group(1))
        value = int.from_bytes(raw, byteorder="little")
        total += value

print(total)
'
}

# ============================================================
# FUNÇÃO: PEGAR TOTAL REQUESTS DO CLIENT OUTPUT
# ============================================================

get_total_requests()
{
    local client_file="$1"

    python3 - "${client_file}" <<'PY'
import sys
import csv

filename = sys.argv[1]

try:
    with open(filename, newline="") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        print(
            f"ERRO: CSV do cliente vazio: {filename}",
            file=sys.stderr
        )
        sys.exit(1)

    if "totalRequests" not in rows[0]:
        print(
            f"ERRO: coluna totalRequests não encontrada em {filename}",
            file=sys.stderr
        )
        print(
            f"Colunas encontradas: {list(rows[0].keys())}",
            file=sys.stderr
        )
        sys.exit(1)

    print(rows[0]["totalRequests"])

except Exception as e:
    print(
        f"ERRO lendo {filename}: {e}",
        file=sys.stderr
    )
    sys.exit(1)
PY
}

# ============================================================
# FUNÇÃO: CALCULAR HIT RATE
# ============================================================

calculate_cache_metrics()
{
    local total_requests="$1"
    local cache_misses="$2"

    python3 - "${total_requests}" "${cache_misses}" <<'PY'
import sys

total = float(sys.argv[1])
misses = float(sys.argv[2])

if total <= 0:
    print("0,0,0")
    sys.exit(0)

hits = total - misses

if hits < 0:
    hits = 0

hit_rate = (hits / total) * 100.0

print(f"{hits},{hit_rate},{misses}")
PY
}

# ============================================================
# PREPARAÇÃO
# ============================================================

echo "-> Preparando diretórios..."

mkdir -p "${LOCAL_RESULTS_DIR_CLIENT}"
mkdir -p "${LOCAL_RESULTS_DIR_SERVER}"

ssh "${REMOTE_USER}@${REMOTE_HOST}" \
    "mkdir -p ${REMOTE_RESULTS_DIR_SERVER}"

# ============================================================
# LOOP PRINCIPAL
# ============================================================

for MODE in "${MODES[@]}"; do

    echo "==============================================="
    echo "Modo atual: ${MODE}"
    echo "==============================================="

    for CONCURRENCY in "${CONCURRENCY_LEVELS[@]}"; do

        echo
        echo "========== Iniciando concorrência ${CONCURRENCY} =========="

        # ====================================================
        # RUNS
        # ====================================================

        for run in $(seq 1 $NUM_RUNS); do

            echo
            echo "--> RUN ${run} / ${NUM_RUNS}"

            CLIENT_OUTPUT_FILE="${LOCAL_RESULTS_DIR_CLIENT}/client_output_${MODE}_${CONCURRENCY}_run${run}.csv"

            REMOTE_SERVER_OUTPUT_FILE="${REMOTE_RESULTS_DIR_SERVER}/server_output_${MODE}_${CONCURRENCY}_run${run}.csv"

            # =================================================
            # 1. LIMPEZA E RESET
            # =================================================

            echo "-> Limpando e resetando ambiente..."

            ssh -tt "${REMOTE_USER}@${REMOTE_HOST}" "
                tmux kill-session -t srv 2>/dev/null || true
                tmux kill-session -t ates 2>/dev/null || true
                tmux kill-session -t hw 2>/dev/null || true

                sudo -n pkill atesnds 2>/dev/null || true
                sudo -n pkill time_updater 2>/dev/null || true
                sudo -n pkill sample_server.py 2>/dev/null || true

                (cd ${REMOTE_BASE_DIR} && make unload-hw) 2>/dev/null || true

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

            # =================================================
            # 2. INICIALIZAÇÃO DO HW CACHE
            # =================================================

            if [ "${MODE}" = "hw_cache" ]; then

                echo "-> Inicializando HW cache..."

                ssh -tt "${REMOTE_USER}@${REMOTE_HOST}" \
                    "cd ${REMOTE_BASE_DIR} && \
                     tmux new-session -d -s hw \
                     'make load-and-run-time-updater'"

                sleep 3
            fi

            # =================================================
            # 3. INICIALIZAÇÃO DO ATESNDS
            # =================================================

            echo "-> Inicializando atesnds..."

            ssh -tt "${REMOTE_USER}@${REMOTE_HOST}" \
                "cd ${REMOTE_BASE_DIR} && \
                 tmux new-session -d -s ates \
                 'sudo -n ./bin/atesnds \
                    -a ${REMOTE_SERVER_IP} \
                    -i ${REMOTE_INTERFACE} \
                    -m ${REMOTE_MAC_ADDR} \
                    -s ${REMOTE_DNS_SERVER}'"

            sleep 3

            # =================================================
            # 4. ZERAR MAPA ANTES DO WARMUP
            # =================================================

            if [ "${MODE}" = "hw_cache" ]; then
                reset_cache_misses
            fi

            # =================================================
            # 5. SERVER
            # =================================================

            WARMUP_DURATION="${DURATION}"

            echo "-> Iniciando sample_server.py..."

            ssh "${REMOTE_USER}@${REMOTE_HOST}" \
                "nohup ${REMOTE_PYTHON} \
                ${REMOTE_SERVER_SCRIPT} \
                ${REMOTE_SERVER_OUTPUT_FILE} \
                ${DURATION} \
                ${WARMUP_DURATION} \
                > ${REMOTE_SERVER_OUTPUT_FILE}.log 2>&1 &"

            sleep 2

            echo "-> Verificando sample_server.py..."

            ssh "${REMOTE_USER}@${REMOTE_HOST}" \
                "pgrep -a -f 'python.*sample_server.py'" \
                || echo "-> ALERTA: sample_server.py NÃO está rodando!"

            # =================================================
            # 6. EXECUÇÃO DO CLIENTE
            # =================================================

            echo "-> Executando cliente (run ${run})..."

            # IMPORTANTE:
            # Este arquivo é criado LOCALMENTE.
            #
            # ${CLIENT_OUTPUT_FILE}
            #
            # não é um arquivo remoto.

            python3 "${LOCAL_CLIENT_SCRIPT}" \
                --server "${REMOTE_SERVER_IP}" \
                --duration "${DURATION}" \
                --concurrency "${CONCURRENCY}" \
                --warmup \
                > "${CLIENT_OUTPUT_FILE}"

            # =================================================
            # 7. DEBUG DO CLIENT OUTPUT
            # =================================================

            echo "-> Client output gerado em:"
            echo "   ${CLIENT_OUTPUT_FILE}"

            if [ ! -s "${CLIENT_OUTPUT_FILE}" ]; then
                echo "ERRO: client output está vazio!"
                exit 1
            fi

            # =================================================
            # 8. COLETAR TOTAL REQUESTS DO CLIENTE
            # =================================================

            echo "-> Coletando Total Requests do cliente..."

            TOTAL_REQUESTS=$(get_total_requests "${CLIENT_OUTPUT_FILE}")

            echo "-> Total requests: ${TOTAL_REQUESTS}"

            # =================================================
            # 9. COLETAR CACHE MISSES
            # =================================================

            CACHE_MISSES=0

            if [ "${MODE}" = "hw_cache" ]; then

                echo "-> Coletando dns_misses..."

                CACHE_MISSES=$(get_cache_misses)

                echo "-> Cache misses: ${CACHE_MISSES}"

            fi

            # =================================================
            # 10. CALCULAR CACHE HITS / HIT RATE
            # =================================================

            if [ "${MODE}" = "hw_cache" ]; then

                CACHE_METRICS=$(calculate_cache_metrics \
                    "${TOTAL_REQUESTS}" \
                    "${CACHE_MISSES}")

                IFS=',' read -r CACHE_HITS CACHE_HIT_RATE _ <<< "${CACHE_METRICS}"

            else

                CACHE_HITS=0
                CACHE_HIT_RATE=0

            fi

            echo "-> Cache hits: ${CACHE_HITS}"
            echo "-> Cache hit rate: ${CACHE_HIT_RATE}%"

            # =================================================
            # 11. SALVAR RESULTADO NO SERVER OUTPUT
            # =================================================

            echo "-> Salvando métricas no server output..."

            ssh "${REMOTE_USER}@${REMOTE_HOST}" \
                "cat > '${REMOTE_SERVER_OUTPUT_FILE}' <<EOF
metric,value
totalRequests,${TOTAL_REQUESTS}
cacheMisses,${CACHE_MISSES}
cacheHits,${CACHE_HITS}
cacheHitRate,${CACHE_HIT_RATE}
EOF"

            # =================================================
            # 12. ENCERRAMENTO
            # =================================================

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

        # ====================================================
        # 13. FIM DA CONCORRÊNCIA
        # ====================================================

        echo
        echo "========== Fim da concorrência ${CONCURRENCY} =========="

        # ====================================================
        # 14. BAIXAR SERVER OUTPUT
        # ====================================================

        echo "-> Baixando arquivos de resultado do servidor..."

        scp \
            "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_RESULTS_DIR_SERVER}/server_output_${MODE}_${CONCURRENCY}_run*.csv" \
            "${LOCAL_RESULTS_DIR_SERVER}/" \
            || echo "Nenhum arquivo de servidor para baixar, continuando."

        # ====================================================
        # 15. CONSOLIDAÇÃO
        # ====================================================

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
echo "Todos os testes foram concluídos!"
echo "==============================================="
