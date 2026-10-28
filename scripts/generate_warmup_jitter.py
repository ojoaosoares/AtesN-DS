#!/usr/bin/env python3
import sys

def hash_domain(domain):
    h = 2166136261
    for c in domain.lower():
        h ^= ord(c)
        h = (h * 16777619) & 0xFFFFFFFF
    return h

def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "tests/isp_top32k_hw_warmup_dnsperf.txt"
    dst = sys.argv[2] if len(sys.argv) > 2 else "tests/isp_top32k_hw_warmup_jitter.txt"
    ttl = int(sys.argv[3]) if len(sys.argv) > 3 else 30

    with open(src, "r") as f_in, open(dst, "w") as f_out:
        for line in f_in:
            parts = line.strip().split()
            if not parts:
                continue
            dom = parts[0]
            h = hash_domain(dom)
            entry_ttl = 30 + (h % 31)  # Range [30, 60]
            f_out.write(f"{dom} {entry_ttl}\n")

if __name__ == "__main__":
    main()
