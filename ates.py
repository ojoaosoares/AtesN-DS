#!/usr/bin/env python3
"""
AtesN-DS Management CLI (ates)
Unified command-line interface to build, configure, run, monitor, and verify AtesN-DS.
"""

import os
import sys
import time
import signal
import socket
import struct
import argparse
import subprocess
from pathlib import Path

# Paths
ROOT_DIR = Path(__file__).resolve().parent
BIN_DIR = ROOT_DIR / "bin"
OBJ_DIR = ROOT_DIR / "obj"
PID_PROXY = Path("/tmp/ates_proxy.pid")
PID_DAEMON = Path("/tmp/ates_daemon.pid")
LOG_PROXY = Path("/tmp/ates_proxy.log")
LOG_DAEMON = Path("/tmp/ates_daemon.log")

BPF_FS = Path("/sys/fs/bpf")
PIN_LEVEL_ONE = BPF_FS / "level_one_cache"
PIN_TIME_MAP = BPF_FS / "time_map"
PIN_HW_SYNC = BPF_FS / "hw_sync_ringbuf"
PIN_RESOLVER = BPF_FS / "ringbuf_send_packet"
PIN_XDP_PROG = BPF_FS / "xdp_prog"


# ==============================================================================
# Terminal Helpers
# ==============================================================================
class Color:
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def info(msg):
    print(f"{Color.CYAN}ℹ{Color.RESET} {msg}")


def success(msg):
    print(f"{Color.GREEN}✔{Color.RESET} {msg}")


def warn(msg):
    print(f"{Color.YELLOW}⚠{Color.RESET} {msg}")


def error(msg):
    print(f"{Color.RED}✖{Color.RESET} {msg}", file=sys.stderr)


def check_root(cmd_name="this command"):
    if os.geteuid() != 0:
        error(f"Root privileges required for {cmd_name}. Please re-run with: sudo ./ates {cmd_name}")
        sys.exit(1)


# ==============================================================================
# Hardware & Network Auto-Detection
# ==============================================================================
def detect_interface():
    # Prefer Netronome SmartNIC default interface if available
    smartnic_if = "enp1s0np1"
    if Path(f"/sys/class/net/{smartnic_if}").exists():
        return smartnic_if

    # Otherwise fallback to default route interface
    try:
        res = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, check=True
        )
        for part in res.stdout.split():
            if part.startswith("en") or part.startswith("eth"):
                return part
    except Exception:
        pass
    return "enp1s0np1"


def detect_ip(interface):
    try:
        res = subprocess.run(
            ["ip", "-4", "addr", "show", interface],
            capture_output=True, text=True, check=True
        )
        for line in res.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except Exception:
        pass
    return "192.168.0.1"


def detect_mac(interface):
    try:
        addr_file = Path(f"/sys/class/net/{interface}/address")
        if addr_file.exists():
            mac = addr_file.read_text().strip()
            if mac and len(mac) == 17:
                return mac
    except Exception:
        pass
    return "3c:fd:fe:03:02:00"


# ==============================================================================
# Build & Compilation
# ==============================================================================
def build_stack(hw=True):
    info("Checking and building AtesN-DS binaries...")
    cmd = ["make", "build-all"] if hw else ["make", "all", "daemon"]
    res = subprocess.run(cmd, cwd=ROOT_DIR)
    if res.returncode != 0:
        error("Build failed. Run 'make check' to inspect compilation errors.")
        sys.exit(1)
    success("All binaries built successfully.")


# ==============================================================================
# Hardware Offload Load / Unload
# ==============================================================================
def load_hardware_offload(interface):
    hw_obj = OBJ_DIR / "dns_xdp_hw.o"
    if not hw_obj.exists():
        build_stack(hw=True)

    info(f"Loading XDP offload microcode into SmartNIC ({interface})...")
    # Clean previous attachments
    subprocess.run(["bpftool", "net", "detach", "xdpoffload", "dev", interface], capture_output=True)
    subprocess.run(["bpftool", "net", "detach", "xdp", "dev", interface], capture_output=True)
    subprocess.run(["ip", "link", "set", "dev", interface, "xdp", "off"], capture_output=True)

    # Clean pins
    PIN_XDP_PROG.unlink(missing_ok=True)
    PIN_TIME_MAP.unlink(missing_ok=True)
    PIN_LEVEL_ONE.unlink(missing_ok=True)

    # Load program
    cmd_load = ["bpftool", "prog", "load", str(hw_obj), str(PIN_XDP_PROG), "type", "xdp", "dev", interface]
    res = subprocess.run(cmd_load, capture_output=True, text=True)
    if res.returncode != 0:
        error(f"Failed to load hardware XDP on {interface}:\n{res.stderr}")
        sys.exit(1)

    # Attach program
    cmd_attach = ["bpftool", "net", "attach", "xdpoffload", "pinned", str(PIN_XDP_PROG), "dev", interface]
    res = subprocess.run(cmd_attach, capture_output=True, text=True)
    if res.returncode != 0:
        error(f"Failed to attach XDP offload on {interface}:\n{res.stderr}")
        sys.exit(1)

    # Pin maps
    time.sleep(0.5)
    maps_out = subprocess.run(["bpftool", "map", "show"], capture_output=True, text=True).stdout
    for line in maps_out.splitlines():
        if "name level_one_cache" in line:
            mid = line.split(":")[0].strip()
            PIN_LEVEL_ONE.unlink(missing_ok=True)
            subprocess.run(["bpftool", "map", "pin", "id", mid, str(PIN_LEVEL_ONE)], capture_output=True)
        elif "name time_map" in line:
            mid = line.split(":")[0].strip()
            PIN_TIME_MAP.unlink(missing_ok=True)
            subprocess.run(["bpftool", "map", "pin", "id", mid, str(PIN_TIME_MAP)], capture_output=True)

    success(f"SmartNIC hardware offload active on {interface} with pinned maps.")


def unload_hardware_offload(interface):
    subprocess.run(["bpftool", "net", "detach", "xdpoffload", "dev", interface], capture_output=True)
    subprocess.run(["bpftool", "net", "detach", "xdp", "dev", interface], capture_output=True)
    subprocess.run(["ip", "link", "set", "dev", interface, "xdp", "off"], capture_output=True)
    PIN_XDP_PROG.unlink(missing_ok=True)
    PIN_TIME_MAP.unlink(missing_ok=True)
    PIN_LEVEL_ONE.unlink(missing_ok=True)


# ==============================================================================
# Service Lifecycle (Start, Stop, Run)
# ==============================================================================
def start_services(args, foreground=False):
    check_root("start")

    # Clean existing runs
    stop_services(args.interface, quiet=True)

    if args.build:
        build_stack(hw=args.hw)

    # 1. Hardware Offload setup
    if args.hw:
        load_hardware_offload(args.interface)
    else:
        warn(f"Hardware cache offload disabled. Running purely on host driver (software XDP).")

    # 2. Launch Control-Plane Daemon (atesnds_daemon)
    daemon_bin = BIN_DIR / "atesnds_daemon"
    daemon_cmd = [
        str(daemon_bin),
        "-c", str(PIN_LEVEL_ONE),
        "-t", str(PIN_TIME_MAP),
        "-r", str(PIN_HW_SYNC),
        "-n", str(args.capacity),
        "-H", str(args.high_watermark),
        "-L", str(args.low_watermark),
    ]
    if args.verbose:
        daemon_cmd.append("-v")

    info(f"Starting unified control-plane daemon (capacity={args.capacity}, high_wm={args.high_watermark}%, low_wm={args.low_watermark}%)...")
    log_d = open(LOG_DAEMON, "w")
    daemon_proc = subprocess.Popen(daemon_cmd, stdout=log_d, stderr=subprocess.STDOUT)
    PID_DAEMON.write_text(str(daemon_proc.pid))
    success(f"Control-plane daemon started [PID {daemon_proc.pid}].")

    time.sleep(1)

    # 3. Launch AtesN-DS Proxy Server (atesnds)
    proxy_bin = BIN_DIR / "atesnds"
    proxy_cmd = [
        str(proxy_bin),
        "-a", args.server_ip,
        "-i", args.interface,
        "-m", args.mac,
        "-s", args.resolver,
        "-C", str(args.sw_cache_size),
        "-N", str(args.ns_cache_size),
        "-Q", str(args.queries_size),
    ]
    if args.verbose:
        proxy_cmd.append("-v")
    else:
        proxy_cmd.append("-q")

    info(f"Starting AtesN-DS proxy (IP={args.server_ip}, Interface={args.interface}, Gateway MAC={args.mac}, Resolver={args.resolver})...")
    log_p = open(LOG_PROXY, "w")
    proxy_proc = subprocess.Popen(proxy_cmd, stdout=log_p, stderr=subprocess.STDOUT)
    PID_PROXY.write_text(str(proxy_proc.pid))
    success(f"AtesN-DS proxy server started [PID {proxy_proc.pid}].")

    print("\n" + "=" * 65)
    print(f" {Color.BOLD}🚀 AtesN-DS is running!{Color.RESET}")
    print("=" * 65)
    print(f"  Mode:            {'Hardware SmartNIC Offload (50B key)' if args.hw else 'Host Software Only'}")
    print(f"  Interface:       {args.interface}")
    print(f"  Server IP:       {args.server_ip}")
    print(f"  Gateway MAC:     {args.mac}")
    print(f"  Upstream DNS:    {args.resolver}")
    print(f"  HW Capacity:     {args.capacity} entries (High={args.high_watermark}%, Low={args.low_watermark}%)")
    print(f"  SW Cache (A):    {args.sw_cache_size} entries")
    print(f"  SW Cache (NS):   {args.ns_cache_size} entries")
    print(f"  In-Flight Table: {args.queries_size} entries")
    print(f"  Prints/Logging:  {'Verbose' if args.verbose else 'Deactivated (Quiet Mode - Zero Datapath I/O)'}")
    print(f"  Daemon Log:      {LOG_DAEMON}")
    print(f"  Proxy Log:       {LOG_PROXY}")
    print("=" * 65)

    if foreground:
        print(f"\n{Color.YELLOW}Streaming logs in foreground. Press Ctrl+C to terminate...{Color.RESET}\n")
        try:
            # Simple log streamer
            tail_proc = subprocess.Popen(["tail", "-f", "-n", "20", str(LOG_DAEMON), str(LOG_PROXY)])
            while daemon_proc.poll() is None and proxy_proc.poll() is None:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down gracefully...")
        finally:
            tail_proc.kill()
            stop_services(args.interface)
    else:
        print(f"\nTip: Use '{Color.CYAN}./ates status{Color.RESET}' to check health, or '{Color.CYAN}sudo ./ates stop{Color.RESET}' to shut down.")


def stop_services(interface=None, quiet=False):
    check_root("stop")
    if not quiet:
        info("Stopping AtesN-DS services and cleaning up BPF resources...")

    # Kill processes
    subprocess.run(["pkill", "-9", "atesnds"], capture_output=True)
    subprocess.run(["pkill", "-9", "atesnds_daemon"], capture_output=True)
    subprocess.run(["pkill", "-9", "time_updater"], capture_output=True)

    PID_PROXY.unlink(missing_ok=True)
    PID_DAEMON.unlink(missing_ok=True)

    # Detach and unpin
    iface = interface or detect_interface()
    unload_hardware_offload(iface)

    PIN_HW_SYNC.unlink(missing_ok=True)
    PIN_RESOLVER.unlink(missing_ok=True)

    if not quiet:
        success("AtesN-DS stopped and network interfaces/BPF maps cleaned cleanly.")


# ==============================================================================
# Status and Monitoring
# ==============================================================================
def show_status(interface):
    print("=" * 65)
    print(f" {Color.BOLD}📊 AtesN-DS System Status{Color.RESET}")
    print("=" * 65)

    # Check processes
    def get_pid(name):
        try:
            res = subprocess.run(["pgrep", "-f", name], capture_output=True, text=True)
            pids = res.stdout.strip().split()
            return pids[0] if pids else None
        except Exception:
            return None

    pid_proxy = get_pid("bin/atesnds")
    pid_daemon = get_pid("bin/atesnds_daemon")

    status_proxy = f"{Color.GREEN}RUNNING (PID {pid_proxy}){Color.RESET}" if pid_proxy else f"{Color.RED}STOPPED{Color.RESET}"
    status_daemon = f"{Color.GREEN}RUNNING (PID {pid_daemon}){Color.RESET}" if pid_daemon else f"{Color.RED}STOPPED{Color.RESET}"

    print(f"  Proxy Server (atesnds):        {status_proxy}")
    print(f"  Control Daemon (atesnds_daemon): {status_daemon}")

    # Check XDP attachment
    iface = interface or detect_interface()
    xdp_status = f"{Color.RED}None{Color.RESET}"
    try:
        link_out = subprocess.run(["ip", "link", "show", iface], capture_output=True, text=True).stdout
        if "xdpoffload" in link_out:
            xdp_status = f"{Color.GREEN}SmartNIC Hardware Offload (xdpoffload){Color.RESET}"
        elif "xdp" in link_out:
            xdp_status = f"{Color.BLUE}Host Driver Mode (xdpdrv){Color.RESET}"
    except Exception:
        pass
    print(f"  Interface ({iface}) Mode:         {xdp_status}")

    # Check BPF maps
    print("\n  Pinned BPF Maps:")
    for name, path in [
        ("SmartNIC level_one_cache", PIN_LEVEL_ONE),
        ("SmartNIC time_map", PIN_TIME_MAP),
        ("Host hw_sync_ringbuf", PIN_HW_SYNC),
        ("Host ringbuf_send_packet", PIN_RESOLVER),
    ]:
        exists = path.exists()
        badge = f"{Color.GREEN}Pinned{Color.RESET}" if exists else f"{Color.YELLOW}Unpinned{Color.RESET}"
        print(f"    - {name:25s}: {badge} ({path})")

    # Check recent daemon metrics if log exists
    if LOG_DAEMON.exists():
        print("\n  Recent Daemon Telemetry:")
        try:
            tail = subprocess.run(["tail", "-n", "3", str(LOG_DAEMON)], capture_output=True, text=True).stdout
            for line in tail.strip().splitlines():
                print(f"    {line}")
        except Exception:
            pass
    print("=" * 65)


# ==============================================================================
# CLI Entrypoint
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="AtesN-DS Management CLI: Start, configure, monitor, and test AtesN-DS DNS Cache.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: start
    p_start = subparsers.add_parser("start", help="Start AtesN-DS in the background")
    # Command: run
    p_run = subparsers.add_parser("run", help="Run AtesN-DS in the foreground with live log streaming")

    default_iface = detect_interface()
    default_ip = detect_ip(default_iface)
    default_mac = detect_mac(default_iface)

    for p in [p_start, p_run]:
        p.add_argument("--hw", dest="hw", action="store_true", default=True, help="Enable SmartNIC hardware offload cache (default: enabled)")
        p.add_argument("--no-hw", dest="hw", action="store_false", help="Disable SmartNIC hardware offload (run host software mode only)")
        p.add_argument("-i", "--interface", default=default_iface, help=f"Network interface (default: {default_iface})")
        p.add_argument("-a", "--server-ip", default=default_ip, help=f"DNS Server IPv4 (default: {default_ip})")
        p.add_argument("-m", "--mac", default=default_mac, help=f"Target/Gateway MAC address (default: {default_mac})")
        p.add_argument("-s", "--resolver", default="8.8.8.8", help="Upstream recursive DNS resolver IP (default: 8.8.8.8)")
        p.add_argument("-n", "--capacity", "--hw-capacity", type=int, default=2000000, help="SmartNIC hardware cache capacity (default: 2000000 entries)")
        p.add_argument("-H", "--high-watermark", type=int, default=90, help="High watermark %% for proactive eviction (default: 90)")
        p.add_argument("-L", "--low-watermark", type=int, default=80, help="Low watermark %% target (default: 80)")
        p.add_argument("-C", "--sw-cache-size", type=int, default=4000000, help="Software A-record cache capacity (default: 4000000 entries)")
        p.add_argument("-N", "--ns-cache-size", type=int, default=8000000, help="Software NS-record cache capacity (default: 8000000 entries)")
        p.add_argument("-Q", "--queries-size", type=int, default=4587576, help="Software in-flight queries table capacity (default: 4587576 entries)")
        p.add_argument("--no-build", dest="build", action="store_false", default=True, help="Skip automatic compilation")
        p.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (default: quiet, prints deactivated)")

    # Command: stop
    p_stop = subparsers.add_parser("stop", help="Stop all AtesN-DS processes and cleanup BPF maps")
    p_stop.add_argument("-i", "--interface", default=default_iface, help=f"Interface to detach XDP from (default: {default_iface})")

    # Command: restart
    p_restart = subparsers.add_parser("restart", help="Restart AtesN-DS services")

    # Command: status
    p_status = subparsers.add_parser("status", help="Show current operational status and BPF maps")
    p_status.add_argument("-i", "--interface", default=default_iface, help="Interface to inspect")

    # Command: logs
    p_logs = subparsers.add_parser("logs", help="View or follow runtime logs")
    p_logs.add_argument("-f", "--follow", action="store_true", help="Follow log output (like tail -f)")
    p_logs.add_argument("-d", "--daemon", action="store_true", help="Show only daemon logs")
    p_logs.add_argument("-p", "--proxy", action="store_true", help="Show only proxy logs")

    # Command: verify
    subparsers.add_parser("verify", help="Run the full hardware & driver BPF verifier suite (make check)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "start":
        start_services(args, foreground=False)
    elif args.command == "run":
        start_services(args, foreground=True)
    elif args.command == "stop":
        stop_services(args.interface)
    elif args.command == "restart":
        stop_services(default_iface)
        time.sleep(1)
        # re-run default start
        args.hw = True
        args.interface = default_iface
        args.server_ip = default_ip
        args.mac = default_mac
        args.resolver = "8.8.8.8"
        args.capacity = 2000000
        args.high_watermark = 90
        args.low_watermark = 80
        args.sw_cache_size = 4000000
        args.ns_cache_size = 8000000
        args.queries_size = 4587576
        args.build = True
        args.verbose = False
        start_services(args, foreground=False)
    elif args.command == "status":
        show_status(args.interface)
    elif args.command == "logs":
        files = []
        if args.daemon:
            files = [str(LOG_DAEMON)]
        elif args.proxy:
            files = [str(LOG_PROXY)]
        else:
            files = [str(LOG_DAEMON), str(LOG_PROXY)]
        cmd = ["tail"]
        if args.follow:
            cmd.append("-f")
        cmd.extend(["-n", "30"])
        cmd.extend(files)
        subprocess.run(cmd)
    elif args.command == "verify":
        subprocess.run(["./verify.sh"], cwd=ROOT_DIR)


if __name__ == "__main__":
    main()
