# cc and flags
CC = clang
CXXFLAGS = -target bpf -O2
#CXXFLAGS = -std=c++11 -O3 -Wall

# folders
INCLUDE_FOLDER = ./include/
BIN_FOLDER = ./bin/
OBJ_FOLDER = ./obj/
SRC_FOLDER = ./src/

# eBPF
DEV = enp2s0

# all sources, objs, and header files
MAIN = Main
TARGET = a.out
SRC = $(wildcard $(SRC_FOLDER)*.c)
OBJ = $(patsubst $(SRC_FOLDER)%.c, $(OBJ_FOLDER)%.o, $(SRC))

$(OBJ_FOLDER)%.o: $(SRC_FOLDER)%.c
	$(CC) $(CXXFLAGS) -c $< -o $@ -I$(INCLUDE_FOLDER)

all: $(OBJ)

load:
	sudo ip -force link set ${DEV} xdp obj ${OBJ} sec dns_filter

reload:
	make stop && make && make load 

stop:
	sudo ip link set dev ${DEV} xdp off


debug:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	@rm -rf $(OBJ_FOLDER)* $(BIN_FOLDER)*