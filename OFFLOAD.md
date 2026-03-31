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
sudo bpftool net detach xdpoffload <interface>
```
