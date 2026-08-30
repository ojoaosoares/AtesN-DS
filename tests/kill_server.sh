#!/bin/bash

set -uo pipefail

REMOTE_USER="soares"
REMOTE_HOST="150.164.2.81"
REMOTE_INTERFACE="enp1s0np1"
REMOTE_SERVER_IP="192.168.0.1"
REMOTE_BASE_DIR="/home/soares/Documentos/AtesN-DS"

cleanup_local_server() {
    echo "============================================="
    echo "-> Limpando processos e recursos no servidor..."
    echo "============================================="

    # 1. Matar processos
    echo "1. Encerrando processos (atesnds, time_updater, sample_server.py)..."
    sudo -n pkill -9 atesnds 2>/dev/null || true
    sudo -n pkill -9 time_updater 2>/dev/null || true
    sudo -n pkill -9 -f sample_server.py 2>/dev/null || true
    sudo -n pkill -9 -f dnspyre 2>/dev/null || true

    # 2. Encerrar sessões tmux
    echo "2. Encerrando sessões tmux (ates, hw, srv)..."
    tmux kill-session -t ates 2>/dev/null || true
    tmux kill-session -t hw 2>/dev/null || true
    tmux kill-session -t srv 2>/dev/null || true

    # 3. Descarregar XDP e desanexar BPF
    echo "3. Descarregando XDP e limpando pins BPF..."
    sudo -n bpftool map update name dns_misses key hex 00 00 00 00 value hex 00 00 00 00 00 00 00 00 2>/dev/null || true
    sudo -n bpftool map update pinned /sys/fs/bpf/dns_misses key hex 00 00 00 00 value hex 00 00 00 00 00 00 00 00 2>/dev/null || true
    sudo -n bpftool net detach xdpoffload dev "${REMOTE_INTERFACE}" 2>/dev/null || true
    sudo -n bpftool net detach xdp dev "${REMOTE_INTERFACE}" 2>/dev/null || true
    sudo -n ip link set dev "${REMOTE_INTERFACE}" xdp off 2>/dev/null || true
    sudo -n rm -f /sys/fs/bpf/xdp_prog 2>/dev/null || true
    sudo -n rm -f /sys/fs/bpf/time_map 2>/dev/null || true
    sudo -n rm -f /sys/fs/bpf/level_one_cache 2>/dev/null || true
    sudo -n rm -f /sys/fs/bpf/dns_misses 2>/dev/null || true

    # 4. Resetar interface de rede
    echo "4. Resetando interface de rede ${REMOTE_INTERFACE}..."
    sudo -n ip link set dev "${REMOTE_INTERFACE}" down 2>/dev/null || true
    sleep 1
    sudo -n ip link set dev "${REMOTE_INTERFACE}" up 2>/dev/null || true
    sudo -n ip addr flush dev "${REMOTE_INTERFACE}" 2>/dev/null || true
    sudo -n ip addr add "${REMOTE_SERVER_IP}/24" dev "${REMOTE_INTERFACE}" 2>/dev/null || true

    echo "✅ Servidor limpo com sucesso!"
}

if [ "${1:-}" = "--remote" ] || [ "${1:-}" = "-r" ]; then
    echo "-> Executando limpeza remota em ${REMOTE_USER}@${REMOTE_HOST}..."
    ssh -tt "${REMOTE_USER}@${REMOTE_HOST}" "
        sudo -n pkill -9 atesnds 2>/dev/null || true
        sudo -n pkill -9 time_updater 2>/dev/null || true
        sudo -n pkill -9 -f sample_server.py 2>/dev/null || true
        sudo -n pkill -9 -f dnspyre 2>/dev/null || true
        tmux kill-session -t ates 2>/dev/null || true
        tmux kill-session -t hw 2>/dev/null || true
        tmux kill-session -t srv 2>/dev/null || true
        sudo -n bpftool map update name dns_misses key hex 00 00 00 00 value hex 00 00 00 00 00 00 00 00 2>/dev/null || true
        sudo -n bpftool map update pinned /sys/fs/bpf/dns_misses key hex 00 00 00 00 value hex 00 00 00 00 00 00 00 00 2>/dev/null || true
        sudo -n bpftool net detach xdpoffload dev ${REMOTE_INTERFACE} 2>/dev/null || true
        sudo -n bpftool net detach xdp dev ${REMOTE_INTERFACE} 2>/dev/null || true
        sudo -n ip link set dev ${REMOTE_INTERFACE} xdp off 2>/dev/null || true
        sudo -n rm -f /sys/fs/bpf/xdp_prog /sys/fs/bpf/time_map /sys/fs/bpf/level_one_cache /sys/fs/bpf/dns_misses 2>/dev/null || true
        (cd ${REMOTE_BASE_DIR} && sudo -n make unload-hw) 2>/dev/null || true
        sudo -n ip link set dev ${REMOTE_INTERFACE} down 2>/dev/null || true
        sleep 1
        sudo -n ip link set dev ${REMOTE_INTERFACE} up 2>/dev/null || true
        sudo -n ip addr flush dev ${REMOTE_INTERFACE} 2>/dev/null || true
        sudo -n ip addr add ${REMOTE_SERVER_IP}/24 dev ${REMOTE_INTERFACE} 2>/dev/null || true
        echo '✅ Limpeza remota concluída!'
    "
else
    cleanup_local_server
fi
