#!/bin/bash
#exec privileged 
apt-get update
apt-get install make
apt-get install llvm -y
apt-get install git -y
apt-get install vim -y
apt-get install clang -y
apt-get install net-tools -y
apt-get install curl -y
apt-get install gcc-multilib -y
apt-get install pkg-config -y
apt-get install bpfcc-tools linux-headers-$(uname -r) -y
apt-get install libelf-dev -y
apt-get install zlib1g-dev 
apt-get install libevent-dev -y
apt-get install build-essential -y
apt-get install libevent -y
apt-get install bison -y

#bpf lib
cd /usr/include/linux
mkdir bpf