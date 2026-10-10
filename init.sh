#!/bin/bash
# Este script deve ser executado com privilégios de superusuário (sudo)

set -e

if [ "$EUID" -ne 0 ]; then
    echo "[ERRO] Este script deve ser executado como root (ex: sudo ./init.sh)"
    exit 1
fi

echo "======================================================================"
echo "  Instalação de Dependências e Firmware do AtesN-DS"
echo "======================================================================"

echo "[1/5] Removendo compilações manuais legadas da libbpf em /usr/local..."
# Remove versões compiladas manualmente que causam conflitos de ABI e segfaults
rm -rf /usr/local/libbpf
rm -f /usr/local/lib/libbpf.so* /usr/local/lib/libbpf.a
rm -rf /usr/local/include/bpf
ldconfig

echo "[2/5] Atualizando lista de pacotes do sistema..."
apt-get update

echo "[3/5] Instalando dependências e libbpf oficial dos repositórios..."
apt-get install -y \
    make \
    llvm \
    git \
    pkg-config \
    vim \
    clang \
    clang-15 \
    net-tools \
    curl \
    gcc-multilib \
    bpfcc-tools \
    linux-headers-$(uname -r) \
    libelf-dev \
    zlib1g-dev \
    libevent-dev \
    build-essential \
    bison \
    linux-tools-$(uname -r) \
    linux-tools-common \
    linux-tools-generic \
    libbpf-dev

echo "[4/5] Atualizando serviços e cache de bibliotecas compartilhadas..."
systemctl daemon-reload
ldconfig

echo "[5/5] Configurando Firmware da SmartNIC Netronome (Agilio BPF)..."
FIRMWARE_DEB=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Procura o arquivo .deb do firmware (priorizando a versão dev/wip que habilita eBPF)
for cand in \
    "$SCRIPT_DIR/firmware/agilio-bpf-firmware-26.05-dev_66997b63e_all.deb" \
    "$SCRIPT_DIR/firmware/"*dev*.deb \
    "$SCRIPT_DIR/firmware/"*wip*.deb \
    "$SCRIPT_DIR/"*dev*.deb \
    "$SCRIPT_DIR/"*wip*.deb \
    "${HOME}/Downloads/"*dev*.deb \
    "${HOME}/Downloads/"*wip*.deb \
    /home/*/Downloads/*dev*.deb \
    /home/*/Downloads/*wip*.deb \
    "$SCRIPT_DIR/firmware/agilio-bpf-firmware"*.deb; do
    if [ -f "$cand" ]; then
        FIRMWARE_DEB="$cand"
        break
    fi
done

if [ -n "$FIRMWARE_DEB" ] && [ -f "$FIRMWARE_DEB" ]; then
    echo "  -> Instalando pacote de firmware: $FIRMWARE_DEB"
    dpkg -i "$FIRMWARE_DEB"

    # Atualiza links simbólicos em /lib/firmware/netronome
    mkdir -p /lib/firmware/netronome
    if [ -d "/opt/netronome/agilio-bpf-firmware" ]; then
        echo "  -> Atualizando links simbólicos em /lib/firmware/netronome..."
        cd /lib/firmware/netronome
        ln -sf /opt/netronome/agilio-bpf-firmware/*.nffw .
        cd "$SCRIPT_DIR"
    elif [ -d "/lib/firmware/netronome/agilio-bpf" ]; then
        cd /lib/firmware/netronome
        ln -sf agilio-bpf/* .
        cd "$SCRIPT_DIR"
    fi

    # Recarrega o driver NFP se a placa SmartNIC estiver presente
    if lspci -d 19ee: >/dev/null 2>&1; then
        echo "  -> SmartNIC Netronome detectada. Recarregando driver nfp..."
        modprobe -r nfp 2>/dev/null || true
        modprobe nfp
        sleep 2

        # Ativa todas as interfaces Netronome encontradas
        for iface in $(ip -o link show | grep -oP 'enp\w+np\d+'); do
            ip link set dev "$iface" up 2>/dev/null || true
            echo "  -> Interface $iface ativada."
            FW_VER=$(ethtool -i "$iface" 2>/dev/null | grep firmware-version || true)
            echo "  -> [$iface] $FW_VER"
        done
    fi
    echo "  -> Firmware Agilio eBPF configurado com sucesso!"
else
    echo "  [AVISO] Pacote do firmware Agilio não encontrado. Pulando etapa de firmware."
fi

echo "======================================================================"
echo "  Instalação concluída com sucesso!"
echo "  Dependências e firmware SmartNIC configurados."
echo "======================================================================"
