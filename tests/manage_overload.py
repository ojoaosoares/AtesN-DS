#!/usr/bin/env python3
import sys
import subprocess
import json

MAP_PIN = "/sys/fs/bpf/overload_ctrl"

SHED_MODES = {
    "disabled": 0,
    "misses": 1,
    "early": 2,
    "proportional": 3
}
SHED_MODES_INV = {v: k for k, v in SHED_MODES.items()}

def get_status():
    cmd = ["sudo", "bpftool", "-j", "map", "dump", "pinned", MAP_PIN]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        # Fallback to name lookup if not pinned
        cmd = ["sudo", "bpftool", "-j", "map", "dump", "name", "overload_ctrl"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            return None

    try:
        data = json.loads(res.stdout)
        if isinstance(data, list) and len(data) > 0:
            item = data[0]
            val = item.get("formatted", {}).get("value", item.get("value", {}))
            if isinstance(val, dict):
                is_ovl = int(val.get("is_overloaded", 0))
                mode = int(val.get("shed_mode", 0))
                ratio = int(val.get("shed_ratio", 0))
                return {
                    "is_overloaded": bool(is_ovl),
                    "shed_mode": SHED_MODES_INV.get(mode, f"unknown({mode})"),
                    "shed_mode_raw": mode,
                    "shed_ratio": ratio
                }
    except Exception as e:
        pass
    return None

def set_overload(is_ovl, mode_str, ratio=0):
    mode = SHED_MODES.get(mode_str, 0)
    # 4 ints little-endian: is_ovl (4B), mode (4B), ratio (4B), pad (4B)
    import struct
    val_bytes = struct.pack("<IIII", 1 if is_ovl else 0, mode, ratio, 0)

    target = ["pinned", MAP_PIN]
    cmd = [
        "sudo", "bpftool", "map", "update", target[0], target[1],
        "key", "hex", "00", "00", "00", "00",
        "value", "hex"
    ] + [f"{b:02x}" for b in val_bytes]

    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        # Fallback to name
        target = ["name", "overload_ctrl"]
        cmd[4] = target[0]
        cmd[5] = target[1]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            print(f"Error updating map: {res.stderr.strip()}", file=sys.stderr)
            return False
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == "status":
        st = get_status()
        if st:
            print("Current Overload Control State:")
            print(f"  • is_overloaded: {st['is_overloaded']}")
            print(f"  • shed_mode:     {st['shed_mode']} (mode {st['shed_mode_raw']})")
            print(f"  • shed_ratio:    {st['shed_ratio']}%")
        else:
            print("Failed to get status (is AtesN-DS running?)")
    elif sys.argv[1] == "normal":
        if set_overload(False, "disabled", 0):
            print("✅ Overload shedding DISABLED (Normal Full Driver Processing).")
    elif sys.argv[1] == "early":
        if set_overload(True, "early", 100):
            print("⚡ Early Pre-Lookup Shedding ENABLED (100% of queries pass to userspace BEFORE testing hit).")
    elif sys.argv[1] == "misses":
        if set_overload(True, "misses", 0):
            print("⚡ Miss Shedding ENABLED (Hits answered in driver, misses pass to userspace).")
    elif sys.argv[1] == "prop":
        ratio = int(sys.argv[2]) if len(sys.argv) > 2 else 50
        if set_overload(True, "proportional", ratio):
            print(f"⚡ Proportional Early Shedding ENABLED ({ratio}% pass to userspace before hit).")
    else:
        print(f"Unknown command. Usage: {sys.argv[0]} [status|normal|early|misses|prop <ratio>]")
