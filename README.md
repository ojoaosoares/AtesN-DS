# AtesN-DS

## Introduction

AtesN-DS is a recursive DNS server built on eBPF that runs directly in the Linux kernel, specifically within the XDP hook, without any interaction with userspace. Essentially, AtesN-DS processes DNS queries at the network interface level, generating requests to root servers, TLD servers, and authoritative servers, while caching their responses in eBPF maps. If a query arrives and its response is already cached, AtesN-DS directly returns the response to the client. All packets handled by AtesN-DS bypass the network stack and avoid context switches, significantly reducing latency.

## Features

- **Recursion**: Efficiently resolves queries with recursion, leveraging cache maps for records and servers that can fulfill the request.
- **Caching**: AtesN-DS caches DNS records, TLDs and authoritative servers to improve perfomance.
- **Context Switch Avoidance**: AtesN-DS operates directly in the kernel, specifically within the XDP hook. Since DNS packets never reach the network stack, context switches are significantly reduced.

## Prerequisites

### Dependencies
**Installation Script** Run install.sh to install dependencies automatically

#### 1. Grant Execution Permission
Before running `install.sh`, ensure it has the correct permissions:

```bash
chmod +x install.sh
```

#### 2. Execute the Script

Run the script using:

```bash
sudo ./install.sh
```

Alternatively, you can execute it with bash:

```bash
sudo bash install.sh
```

## How to Compile and Run

### Using Makefile

The project includes a `Makefile` to simplify the compilation process. Below are the available commands:

1. **Compile the Program**:  
To compile the program, run:
```bash
make
```

This will generate the executable in the ./bin/ folder.

2. **Clean Build Files**:
To remove all compiled object files and the executable, run:

```bash
make clean
```

### Execution

After compiling, run the program using:
```bash
./bin/atesn_ds [-h] [-a your_ip] [-i bind_interface] [-s root_server_ip] [-m proxy_mac]
```

where

- **-m [your_ip]**: The ip address the server will run
- **-i [bind_interface]**: The interface where the program will be attached in the XDP hook
- **-s [root_server_ip]**: The ip address of a root dns server
- **-m [proxy_mac]**: The mac address of the proxy
- **-h**: Outputs usage
