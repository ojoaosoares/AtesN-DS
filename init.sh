#!/bin/bash
# Este script deve ser executado com privilégios de superusuário (sudo)

set -e

if [ "$EUID" -ne 0 ]; then
    echo "[ERRO] Este script deve ser executado como root (ex: sudo ./init.sh)"
    exit 1
fi

echo "======================================================================"
echo "  Instalação de Dependências do AtesN-DS"
echo "======================================================================"

echo "[1/4] Removendo compilações manuais legadas da libbpf em /usr/local..."
# Remove versões compiladas manualmente que causam conflitos de ABI e segfaults
rm -rf /usr/local/libbpf
rm -f /usr/local/lib/libbpf.so* /usr/local/lib/libbpf.a
rm -rf /usr/local/include/bpf
ldconfig

echo "[2/4] Atualizando lista de pacotes do sistema..."
apt-get update

echo "[3/4] Instalando dependências e libbpf oficial dos repositórios..."
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
    linux-tools-generic \
    libbpf-dev \
    bpftool

echo "[4/4] Atualizando serviços e cache de bibliotecas compartilhadas..."
systemctl daemon-reload
ldconfig

echo "======================================================================"
echo "  Instalação concluída com sucesso!"
echo "  libbpf-dev oficial instalado e configurado via sistema de pacotes."
echo "======================================================================"
