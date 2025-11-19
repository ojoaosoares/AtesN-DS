# AtesN-DS

AtesN-DS is a high-performance, recursive DNS resolver built on eBPF that runs directly in the Linux kernel. By attaching to the XDP (eXpress Data Path) hook, it processes DNS queries at the network interface level, bypassing the kernel's network stack entirely. This approach avoids context switches and significantly reduces latency.

The server handles the full recursion process, sending requests to root, TLD, and authoritative servers, while caching their responses in efficient eBPF maps. When a cached response is available, it's returned directly to the client at line rate.

***

## Key Features

-   **High-Performance Recursion**: Efficiently resolves DNS queries by performing the full recursive lookup process in-kernel.
-   **Kernel-Level Caching**: Uses eBPF maps for lightning-fast caching of DNS records, TLDs, and authoritative server information, dramatically improving performance for repeated queries.
-   **Zero Context Switch Overhead**: Operates entirely at the XDP hook, meaning handled DNS packets never touch the traditional network stack, eliminating performance penalties.

***

## Another Features

- **Proactive Cache Renewal**: Frequently accessed or critical entries are refreshed before their TTL expires. This avoids disruptive cache misses and ensures stable latency, especially during peak traffic.
- **Fault-Resilient Query Strategy**: To avoid delays caused by unreachable or slow upstream servers, the resolver can issue redundant parallel queries. The first valid response is accepted, improving resilience against timeouts and partial network failures.
- **Authoritative Server Intelligence**: In addition to caching responses, the resolver stores the most frequently and fastest DNS server the resolver interacts with. This allows dynamic upstream selection, prioritizing the fastest and most stable servers over time.

## Prerequisites

### System Requirements

AtesN-DS was developed and tested on the following environment. This is the recommended setup for optimal performance and compatibility.

-   **Operating System:** Ubuntu 22.04.1 (64-bit)
-   **Linux Kernel:** `6.8.0-60-generic` or newer
-   **Compiler:** Clang `18.1.8` or newer

### Dependencies

The project includes an installation script (`install.sh`) to automatically set up all required dependencies.

1.  **Grant Execution Permission**
    First, make the installation script executable:
    ```bash
    chmod +x install.sh
    ```

2.  **Execute the Script**
    Run the script with `sudo` to install the dependencies:
    ```bash
    sudo ./install.sh
    ```

***

## How to Compile and Run

### Compilation

The project includes a `Makefile` to simplify the build process.

-   **Compile the program**:
    ```bash
    make
    ```
    This will create the `atesn_ds` executable in the `./bin/` directory.

-   **Clean build files**:
    ```bash
    make clean
    ```
    This removes all compiled object files and the executable.

### Execution

You need superuser privileges to run AtesN-DS because it must attach the eBPF program to a network interface.

-   **General Usage**:
    ```bash
    sudo ./bin/atesn_ds -a <your_ip> -i <interface> -s <root_server_ip> -m <gateway_mac>
    ```

-   **Example**:
    ```bash
    sudo ./bin/atesn_ds -a 192.168.1.100 -i eth0 -s 198.41.0.4 -m 00:1A:2B:3C:4D:5E
    ```

#### Command-Line Options

| Flag | Argument | Description |
| :--- | :--- | :--- |
| `-h` | | Display the help and usage information. |
| `-a` | `[your_ip]` | The IP address the server will bind to. |
| `-i` | `[interface]` | The network interface to attach the XDP hook to. |
| `-s` | `[root_server_ip]` | The IP address of a root DNS server to start recursion. |
| `-m` | `[gateway_mac]` | The MAC address of the network gateway or proxy. |
