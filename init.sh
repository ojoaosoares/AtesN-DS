#!/bin/bash
# Este script deve ser executado com privilégios de superusuário

sudo systemctl daemon-reload -y

# Atualize a lista de pacotes
apt-get update

# Instale as dependências
apt-get install -y \
    make \
    llvm \
    git \
    pkg-config \
    libelf-dev \
    vim \
    clang \
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
    linux-tools-generic

# Instale e configure a libbpf
LIBBPF_REPO="https://github.com/libbpf/libbpf.git"
LIBBPF_DIR="/usr/local/libbpf"
INCLUDE_DIR="/usr/local/include/bpf"
LIB_DIR="/usr/local/lib"

# Clone o repositório do libbpf
git clone $LIBBPF_REPO $LIBBPF_DIR

# Compile e instale o libbpf
cd $LIBBPF_DIR/src
make

# Crie os diretórios para os cabeçalhos e biblioteca
mkdir -p $INCLUDE_DIR
mkdir -p $LIB_DIR

# Copie os arquivos de cabeçalho e a biblioteca
cp *.h $INCLUDE_DIR
cp ../LICENSE $INCLUDE_DIR
cp libbpf.a $LIB_DIR
cp libbpf.so $LIB_DIR

# Atualize o cache de bibliotecas compartilhadas
ldconfig

echo "Instalação e configuração do libbpf concluídas com sucesso."

# Volte para o diretório inicial ou o diretório do seu projeto
cd -

# Mensagem de conclusão
echo "Instalação de todas as dependências concluída com sucesso."
