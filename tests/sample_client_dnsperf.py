#!/usr/bin/env python3
import argparse
import csv
import io
import os
import re
import subprocess
import sys


def prepare_dnsperf_datafile(source_file):
    """
    Ensures the query file is in dnsperf format (<domain> <TYPE>).
    If the file already has query types on each line, uses it directly.
    Otherwise, generates a cached *_dnsperf.txt file.
    """
    if not source_file:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_dir = os.path.abspath(os.path.join(script_dir, ".."))
        candidates = [
            "dominios3_dnsperf.txt",
            "dominios3.txt",
            os.path.join(project_dir, "dominios3_dnsperf.txt"),
            os.path.join(project_dir, "dominios3.txt"),
            os.path.join(script_dir, "dominios3_dnsperf.txt"),
            os.path.join(script_dir, "dominios3.txt"),
            "tests/dominios.txt",
            "unique.txt"
        ]
        for candidate in candidates:
            if os.path.exists(candidate):
                source_file = candidate
                break
        if not source_file:
            source_file = os.path.join(project_dir, "dominios3_dnsperf.txt")

    # If it's already a _dnsperf.txt file and exists, return directly
    if source_file.endswith("_dnsperf.txt") and os.path.exists(source_file):
        return source_file

    target_file = f"{os.path.splitext(source_file)[0]}_dnsperf.txt"
    if os.path.exists(target_file) and os.path.getsize(target_file) > 0:
        return target_file

    if not os.path.exists(source_file):
        # Fallback if neither exists
        return source_file

    print(f"Preparing dnsperf datafile: {target_file} from {source_file}...", file=sys.stderr)
    with open(source_file, "r") as src, open(target_file, "w") as dst:
        for line in src:
            parts = line.strip().split()
            if not parts:
                continue
            if len(parts) == 1:
                dst.write(f"{parts[0]} A\n")
            else:
                dst.write(f"{parts[0]} {parts[1]}\n")

    return target_file


def run_dnsperf(server, duration, concurrency=512, threads=8, rate=0, max_outstanding=0,
                queries_file=None, dnssec=False, edns0=0):
    datafile = prepare_dnsperf_datafile(queries_file)

    if max_outstanding <= 0:
        max_outstanding = max(1000, concurrency * 2)

    cmd = [
        "dnsperf",
        "-s", server,
        "-d", datafile,
        "-l", str(duration),
        "-c", str(concurrency),
        "-T", str(threads),
        "-q", str(max_outstanding),
        "-b", "16384",  # 16 MB socket buffers
    ]

    if rate > 0:
        cmd.extend(["-Q", str(rate)])
    if dnssec:
        cmd.append("-D")
    if edns0 > 0:
        cmd.append("-e")
    else:
        # Standard EDNS0 Option 10 (DNS Cookie) matching dnspyre behavior for SmartNIC offload
        cmd.extend(["-e", "-E", "10:11223344556677889900aabb"])

    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return p.returncode, p.stdout, p.stderr


def parse_dnsperf_output(stdout, stderr, target_rate=0):
    text = stdout

    def get_match(pattern, default=0.0):
        m = re.search(pattern, text)
        if m:
            return float(m.group(1))
        return default

    def get_int(pattern, default=0):
        m = re.search(pattern, text)
        if m:
            return int(m.group(1))
        return default

    queries_sent = get_int(r"Queries sent:\s+(\d+)")
    queries_completed = get_int(r"Queries completed:\s+(\d+)")
    queries_lost = get_int(r"Queries lost:\s+(\d+)")

    qps = get_match(r"Queries per second:\s+([\d.]+)")

    # Latency: Average Latency (s):  0.033918 (min 0.009445, max 0.644702)
    lat_match = re.search(r"Average Latency \(s\):\s+([\d.]+)\s+\(min\s+([\d.]+),\s+max\s+([\d.]+)\)", text)
    if lat_match:
        mean_s = float(lat_match.group(1))
        min_s = float(lat_match.group(2))
        max_s = float(lat_match.group(3))
        mean_ms = round(mean_s * 1000.0, 3)
        min_ms = round(min_s * 1000.0, 3)
        max_ms = round(max_s * 1000.0, 3)
    else:
        mean_ms = 0.0
        min_ms = 0.0
        max_ms = 0.0

    stddev_s = get_match(r"Latency StdDev \(s\):\s+([\d.]+)")
    stddev_ms = round(stddev_s * 1000.0, 3)

    loss_pct = round((queries_lost / queries_sent * 100.0), 4) if queries_sent > 0 else 0.0

    return {
        "totalRequests": queries_sent,
        "totalSuccessResponses": queries_completed,
        "queriesPerSecond": round(qps, 2),
        "latency_mean_ms": mean_ms,
        "latency_p50_ms": mean_ms,  # dnsperf provides mean and stddev
        "latency_p75_ms": round(mean_ms + 0.67 * stddev_ms, 3),
        "latency_p90_ms": round(mean_ms + 1.28 * stddev_ms, 3),
        "latency_p95_ms": round(mean_ms + 1.64 * stddev_ms, 3),
        "latency_p99_ms": round(mean_ms + 2.33 * stddev_ms, 3),
        "latency_p99_9_ms": round(mean_ms + 3.09 * stddev_ms, 3),
        "latency_min_ms": min_ms,
        "latency_max_ms": max_ms,
        "latency_std_ms": stddev_ms,
        "packet_loss_pct": loss_pct,
        "queries_lost": queries_lost,
        "targetRate": target_rate,
    }


def main():
    parser = argparse.ArgumentParser(description="Run DNS benchmark using open-loop dnsperf tool.")
    parser.add_argument("--server", type=str, required=True, help="DNS server IP/host")
    parser.add_argument("--duration", type=int, required=True, help="Measurement duration in seconds")
    parser.add_argument("--concurrency", type=int, default=512, help="Number of concurrent clients (-c)")
    parser.add_argument("--rate", type=int, default=0, help="Target queries per second (-Q)")
    parser.add_argument("--threads", type=int, default=8, help="Number of worker threads (-T)")
    parser.add_argument("--max-outstanding", type=int, default=0, help="Max outstanding queries (-q)")
    parser.add_argument("--warmup", action="store_true", help="Execute warmup run")
    parser.add_argument("--queries", dest="queries_file", type=str, default=None, help="Queries data file")
    parser.add_argument("--dnssec", action="store_true", help="Set DNSSEC DO bit (-D)")
    parser.add_argument("--edns0", type=int, default=0, help="Enable EDNS0 (-e)")

    args = parser.parse_args()

    if args.warmup:
        print("  Warmup run (dnsperf)...", file=sys.stderr)
        run_dnsperf(
            server=args.server,
            duration=args.duration,
            concurrency=args.concurrency,
            threads=args.threads,
            rate=args.rate,
            max_outstanding=args.max_outstanding,
            queries_file=args.queries_file,
            dnssec=args.dnssec,
            edns0=args.edns0
        )
        return

    print("  Measured run (dnsperf)...", file=sys.stderr)
    retcode, stdout, stderr = run_dnsperf(
        server=args.server,
        duration=args.duration,
        concurrency=args.concurrency,
        threads=args.threads,
        rate=args.rate,
        max_outstanding=args.max_outstanding,
        queries_file=args.queries_file,
        dnssec=args.dnssec,
        edns0=args.edns0
    )

    if retcode != 0 and not stdout.strip():
        print(f"Error: dnsperf exited with code {retcode}:\n{stderr}", file=sys.stderr)

    extracted_data = parse_dnsperf_output(stdout, stderr, target_rate=args.rate)

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=extracted_data.keys())
    writer.writeheader()
    writer.writerow(extracted_data)

    print(output.getvalue(), end="")


if __name__ == "__main__":
    main()
