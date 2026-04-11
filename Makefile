# cc and flags
CC = clang-15
CXXFLAGS = -g -target bpf -O2
# LIBBPF = /usr/lib64/libbpf.so

# folders
INCLUDE_FOLDER = ./include/
BIN_FOLDER     = ./bin/
OBJ_FOLDER     = ./obj/
SRC_FOLDER     = ./src/
DATA_FOLDER    = ./data/
INSTALL        = ./init.sh

# eBPF
# DEV = $(shell ip route | awk '/default/ {print $$5}' | head -n 1)
DEV=enp1s0np1
IP  = $(shell ip -4 addr show $(shell ip route | awk '/default/ {print $$5}' | head -n 1) | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
MAC = $(shell ip addr show ${DEV} | grep -oP 'link/ether \K([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}')

# offload
HW_DEV         = enp1s0np1
HW_OBJ         = $(OBJ_FOLDER)dns_xdp_hw.o
HW_SRC         = $(SRC_FOLDER)dns_filter.c
PROG_PIN       = $(PROG_MOUNT_PATH)/xdp_prog

# all sources, objs, and header files
MAIN      = ${SRC_FOLDER}dns_userspace.c
SKELETON  = ${INCLUDE_FOLDER}dns.skel.h
TARGET    = ${BIN_FOLDER}atesnds
SRC       = $(wildcard $(SRC_FOLDER)*.c)
OBJ       = $(patsubst $(SRC_FOLDER)%.c, $(OBJ_FOLDER)%.o, $(SRC))
PROG_MOUNT_PATH = /sys/fs/bpf

$(shell mkdir -p $(OBJ_FOLDER))
$(shell mkdir -p $(BIN_FOLDER))
$(shell mkdir -p $(DATA_FOLDER))

all: ${TARGET}

run: ${TARGET}
	sudo ${TARGET} -a ${IP} -i ${DEV} -m ${MAC}

${TARGET}: ${MAIN} ${SKELETON}
	${CC} $< -o $@ -I ${INCLUDE_FOLDER} -lbpf

${SKELETON}: ${OBJ_FOLDER}dns.o
	bpftool gen skeleton $< name dns | tee $@

${OBJ_FOLDER}dns.o: ${SRC_FOLDER}dns.c
	$(CC) $(CXXFLAGS) -c $< -o $@ -I $(INCLUDE_FOLDER)

# ------------------------------------------------
# Offload (NFP hardware)
# ------------------------------------------------

build-hw: $(HW_OBJ)

$(HW_OBJ): $(HW_SRC)
	$(CC) -O2 -target bpf -c $< -o $@ -g \
		-I $(INCLUDE_FOLDER) \
		-D __TARGET_ARCH_x86 \
		-D HW_MODE

load-hw: $(HW_OBJ)
	sudo bpftool prog load $(HW_OBJ) $(PROG_PIN) \
		type xdp \
		dev $(HW_DEV)
	sudo bpftool net attach xdpoffload \
		pinned $(PROG_PIN) \
		dev $(HW_DEV)

unload-hw:
	sudo bpftool net detach xdpoffload dev $(HW_DEV) 2>/dev/null || true
	sudo rm -f $(PROG_PIN)

reload-hw: unload-hw build-hw load-hw

# ------------------------------------------------

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