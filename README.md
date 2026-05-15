# AtesN-DS
AtesN-DS is a high-performance, recursive DNS resolver built on eBPF that runs directly in the Linux kernel. By attaching to the XDP (eXpress Data Path) hook, it processes DNS queries at the network interface level, bypassing the kernel's network stack entirely. This approach avoids context switches and significantly reduces latency.

This work was presetented at [SBESC 2025](https://sol.sbc.org.br/index.php/sbesc_estendido/article/view/39485) in Campinas, Brazil.

The project is split into two main programs:

- **Kernel Resolver** — a full recursive DNS resolver that runs in XDP generic or native mode. It performs the complete recursion process, querying root, TLD, and authoritative servers, and caches responses in eBPF maps.
- **Hardware Cache** (`dns_filter`) — an XDP program designed for NIC hardware offload. It serves cached DNS responses directly from eBPF maps at line rate, without touching the CPU.

***

When a cached response is available, it is returned directly to the client. On a cache miss, the query is forwarded to the kernel resolver for full recursion.

---

## Key Features

- **Kernel-Level Caching** — DNS records are stored in eBPF maps, enabling near-zero-latency responses for repeated queries.
- **Zero Context Switch Overhead** — Packets handled by the XDP hook never enter the traditional network stack.
- **Full Recursive Resolution** — The kernel resolver performs the complete DNS recursion cycle autonomously.
- **Proactive Cache Renewal** — Frequently accessed entries are refreshed before their TTL expires, avoiding disruptive cache misses during peak traffic.
- **Fault-Resilient Query Strategy** — Redundant parallel queries are issued to upstream servers; the first valid response wins, improving resilience against timeouts and partial failures.
- **Authoritative Server Intelligence** — The resolver tracks response times and availability of upstream servers, dynamically prioritizing the fastest and most stable ones.

---

## Prerequisites

### System Requirements

AtesN-DS was developed and tested on the following environment:

- **Operating System:** Ubuntu 24.04.3 LTS (64-bit)
- **Linux Kernel:** `6.17.0-23-generic`
- **Compiler:** Clang `18.1.3` or newer

### Hardware Offload

The hardware cache (`dns_filter`) requires a NIC with XDP offload support. AtesN-DS was developed and tested with a **Netronome Agilio CX 4000** SmartNIC.

Other Netronome cards may work but have not been tested. Non-Netronome NICs are unlikely to support XDP hardware offload.

### Dependencies

The project includes an installation script to automatically set up all required dependencies.

```bash
chmod +x install.sh
sudo ./install.sh
```

---

## Compilation

```bash
make        # compiles the kernel resolver → ./bin/atesnds
make clean  # removes all build artifacts
```

To compile the hardware offload cache:

```bash
make build-hw  # compiles dns_filter → ./obj/dns_xdp_hw.o
```

---

## Running the Kernel Resolver

The kernel resolver runs in XDP generic or native mode and handles full DNS recursion.

```bash
sudo ./bin/atesnds -a <ip> -i <interface> -m <gateway_mac> -s <dns_server>
```

**Example:**

```bash
sudo ./bin/atesnds -a 192.168.0.1 -i enp1s0np1 -m 3c:fd:fe:03:02:00 -s 199.7.83.42
```

### Command-Line Options

| Flag | Argument | Description |
| :--- | :--- | :--- |
| `-h` | | Display help and usage information. |
| `-a` | `[ip]` | IP address associated with the interface receiving XDP packets. |
| `-i` | `[interface]` | Network interface to attach the XDP hook to. |
| `-m` | `[gateway_mac]` | MAC address of the network gateway or upstream proxy. |
| `-s` | `[dns_server]` | IP address of a DNS server to forward queries to (root server or recursive resolver). |

---

## Running the Hardware Cache

The hardware cache offloads DNS response serving directly to the NIC firmware. It requires an NFP-compatible network card.

### Step 1 — Load the program onto the NIC

```bash
make load-hw
```

This compiles, loads, and attaches `dns_filter` to the NIC in XDP offload mode.

### Step 2 — Find the time_map ID

After loading, find the ID of the `time_map` BPF map:

```bash
sudo bpftool map show
```

Look for the entry named `time_map`:

```
243: array  name time_map  flags 0x0  offloaded_to enp1s0np1
```

### Step 3 — Start the time updater

The hardware offload program cannot call `bpf_ktime_get_ns()`, so a userspace daemon keeps the time map updated:

```bash
make run-time-updater TIME_MAP_ID=243
```

This pins the map to `/sys/fs/bpf/time_map` and starts the daemon, which writes the current Unix timestamp to the map every second. This is used for TTL expiration of cached DNS entries.

### Unloading

```bash
make unload-hw
```

This detaches the XDP program, removes all BPF pins, and stops the time updater.

---

## XDP Offload Reference

This section documents hardware offload constraints and usage details for the `dns_filter` program on NFP hardware.

### Loading Manually

```bash
# compile
clang -O2 -target bpf -c src/dns_filter.c -o obj/dns_xdp_hw.o -g -I include/ -DHW_MODE

# load and pin
sudo bpftool prog load obj/dns_xdp_hw.o /sys/fs/bpf/xdp_prog type xdp dev <interface>

# attach in offload mode
sudo bpftool net attach xdpoffload pinned /sys/fs/bpf/xdp_prog dev <interface>

# verify
sudo bpftool net show dev <interface>

# detach
sudo bpftool net detach xdpoffload dev <interface>
```

### NFP Hardware Limitations

#### No `.rodata` or `.data` sections

Static global variables and `bpf_printk` calls generate `.data` or `.rodata` sections that the NIC firmware cannot load. Avoid them entirely in offload mode.

```c
// forbidden
static const __u32 my_var = 0;
bpf_printk("debug message"); // generates .rodata

// use maps instead
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} my_config SEC(".maps");
```

#### Map entry size limit

The NFP firmware enforces a maximum of **64 bytes per map entry** (key + value combined).

```c
// forbidden — 256 + 16 = 272 bytes
struct { __uint(key_size, 256); __uint(value_size, 16); } big_map SEC(".maps");

// ok — 8 + 16 = 24 bytes
struct { __uint(key_size, 8); __uint(value_size, 16); } small_map SEC(".maps");
```

#### Stack pointer alignment

Pointers passed to BPF helpers must be 8-byte aligned:

```c
__u8 key[8] __attribute__((aligned(8)));
```

#### Supported map types

| Type | Supported |
|---|---|
| `BPF_MAP_TYPE_ARRAY` | ✅ |
| `BPF_MAP_TYPE_HASH` | ✅ (entry ≤ 64 bytes) |
| `BPF_MAP_TYPE_LRU_HASH` | ❌ |
| `BPF_MAP_TYPE_PERCPU_HASH` | ❌ |
| `BPF_MAP_TYPE_LPM_TRIE` | ❌ |

#### Supported BPF helpers

| Helper | Supported |
|---|---|
| `bpf_map_lookup_elem` | ✅ |
| `bpf_map_update_elem` | ✅ |
| `bpf_map_delete_elem` | ✅ |
| `bpf_xdp_adjust_head` | ✅ |
| `bpf_redirect` | ✅ |
| `bpf_ktime_get_ns` | ❌ |
| `bpf_trace_printk` | ❌ |
| `bpf_perf_event_output` | ❌ |