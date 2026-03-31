# XDP Offload with bpftool

This guide explains how to compile and attach AtesN-DS using XDP hardware offload. The same steps can be applied to other eBPF/XDP programs.

---

## 1 - Compilation

Compile the XDP program using `clang`:

```bash
clang -O2 -target bpf -c src/dns_filter.c -o dns_xdp.o -g -I include/ -DHW_MODE
```

### Notes
- `-target bpf` → Compiles the program for the eBPF virtual machine  
- `-g` → Generates BTF debug information (required by bpftool)  
- `-DHW_MODE` → Enables hardware offload support (if implemented in the program)

## 2 - Load the Program

Load the compiled XDP program into the kernel and pin it to bpffs:

```bash
sudo bpftool prog load dns_xdp.o /sys/fs/bpf/dns_xdp type xdp dev <interface>
```

This makes the program available for attachment.


## 3 - Attach to Interface

Attach the program to a network interface.

### Hardware Offload (XDP Offload)

```bash
sudo bpftool net attach xdpoffload pinned /sys/fs/bpf/xdp_prog dev <interface>
```

## 4 - Verify Attachment

Check if the program is attached:

```bash
sudo bpftool net show dev <interface>	
```

## 5 - Detach the Program

If only one program is attached:

```bash
sudo bpftool net detach xdpoffload dev <interface>
```
## Tips

### XDP Offload Limitations (NFP Hardware)

#### No `.data` section allowed
Programs running in hardware offload mode cannot access static global variables.
These generate a `.data` section that the NIC firmware cannot access.
```c
// Forbidden — generates .data section
__u32 my_var = 0;
volatile unsigned char my_array[6] = {0};
__u32 x SEC(".data") = 0;

// Use ARRAY maps instead
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
// Forbidden — key(256) + value(16) = 272 bytes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, 256);
    __uint(value_size, 16);
} big_map SEC(".maps");

// key(8) + value(16) = 24 bytes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, 8);
    __uint(value_size, 16);
} small_map SEC(".maps");
```

#### Stack pointer alignment
All pointers passed to BPF helpers must be **8-byte aligned** on the stack.
```c
// May be unaligned depending on surrounding variables
__u8 key[8];

// Explicitly aligned
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