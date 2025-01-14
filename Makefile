# cc and flags
CC = clang
CXXFLAGS = -g -target bpf -O2
#CXXFLAGS = -std=c++11 -O3 -Wall

# LIBBPF = /usr/lib64/libbpf.so

# folders
INCLUDE_FOLDER = ./include/
BIN_FOLDER = ./bin/
OBJ_FOLDER = ./obj/
SRC_FOLDER = ./src/
DATA_FOLDER = ./data/

INSTALL = ./init.sh

# eBPF
DEV = $(shell ip route | awk '/default/ {print $$5}' | head -n 1)

MAC = $(shell arp -n | grep $$(ip route | grep default | awk '{print $$3}' | head -n 1) | awk '{print $$3}')

IP = $(shell ip -4 addr show $(shell ip route | awk '/default/ {print $$5}' | head -n 1) | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

# all sources, objs, and header files
MAIN = ${SRC_FOLDER}dns_userspace.c
SKELETON = ${INCLUDE_FOLDER}dns.skel.h
TARGET = ${BIN_FOLDER}atesnds

SRC = $(wildcard $(SRC_FOLDER)*.c)
OBJ = $(patsubst $(SRC_FOLDER)%.c, $(OBJ_FOLDER)%.o, $(SRC))

PROG_MOUNT_PATH=/sys/fs/bpf

$(shell mkdir -p $(OBJ_FOLDER))

$(shell mkdir -p $(BIN_FOLDER))

$(shell mkdir -p $(DATA_FOLDER))

all: ${TARGET}

run: ${TARGET}
	sudo ${TARGET} -a ${IP} -i ${DEV} -m ${MAC}

${TARGET} : ${MAIN} ${SKELETON}
	${CC} $< -o $@ -I ${INCLUDE_FOLDER} -lbpf

${SKELETON} : ${OBJ_FOLDER}dns.o
	bpftool gen skeleton $< name dns | tee $@

${OBJ_FOLDER}dns.o: ${SRC_FOLDER}dns.c
	$(CC) $(CXXFLAGS) -c $< -o $@ -I $(INCLUDE_FOLDER)

install:
	sudo chmod +x ${INSTALL} && sudo ${INSTALL}

load:
	sudo ip -force link set ${DEV} xdp obj ${OBJ_FOLDER}dns.o sec xdp

reload:
	make stop && make && make load 

stop:
	sudo ip link set dev ${DEV} xdp off

debug:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

skeleton:
	bpftool gen skeleton ${OBJ_FOLDER}dns.o name dns | tee ${SKELETON}

clean:
	@rm -rf $(OBJ_FOLDER)* $(BIN_FOLDER)*