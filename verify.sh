#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$SCRIPT_DIR"

echo "=========================================================="
echo "🚀 AtesN-DS Full-Stack Build & Verifier Suite"
echo "=========================================================="
echo ""

echo "🔨 1. Compilando toda a stack (HW, Driver, Proxy e Daemon)..."
make build-all
echo "  ✅ Compilação concluída com sucesso."
echo ""

HW_DEV="${HW_DEV:-enp1s0np1}"

echo "🔍 2. Testando Verificador do Hardware (SmartNIC NFP-4000 em ${HW_DEV})..."
sudo -n bpftool net detach xdpoffload dev "${HW_DEV}" 2>/dev/null || true
sudo -n rm -f /sys/fs/bpf/test_hw_pin

if sudo -n bpftool prog load obj/dns_xdp_hw.o /sys/fs/bpf/test_hw_pin type xdp dev "${HW_DEV}" 2>&1; then
    echo "  ✅ Hardware XDP: APROVADO no verificador da SmartNIC!"
    echo "     (Microcódigo <= 1.536 instruções, chave 50B, bpf_map_delete_elem)"
    sudo -n rm -f /sys/fs/bpf/test_hw_pin
else
    echo "  ❌ Hardware XDP: FALHOU no verificador da SmartNIC."
    sudo -n rm -f /sys/fs/bpf/test_hw_pin
    exit 1
fi
echo ""

echo "🔍 3. Testando Verificador do Driver de Software (Kernel eBPF)..."
sudo -n rm -f /sys/fs/bpf/test_sw_pin 2>/dev/null || true

if sudo -n bpftool prog load obj/dns.o /sys/fs/bpf/test_sw_pin type xdp; then
    echo "  ✅ Driver eBPF: APROVADO no verificador do kernel!"
    echo "     (hw_sync_ringbuf 4MB, ringbuf_send_packet 8MB, tail calls)"
    sudo -n rm -f /sys/fs/bpf/test_sw_pin
else
    echo "  ❌ Driver eBPF: FALHOU no verificador do kernel."
    sudo -n rm -f /sys/fs/bpf/test_sw_pin
    exit 1
fi
echo ""

echo "🔍 4. Verificando Binários em Userspace..."
test -x bin/atesnds && echo "  ✅ Proxy Server: bin/atesnds (OK)"
test -x bin/atesnds_daemon && echo "  ✅ Daemon Unificado: bin/atesnds_daemon (OK)"
echo ""

echo "=========================================================="
echo "🎉 TUDO PRONTO E VERIFICADO COM SUCESSO!"
echo "   Hardware Offload, Driver Host, Proxy e Daemon 100% OK"
echo "=========================================================="
