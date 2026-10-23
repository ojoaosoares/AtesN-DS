#!/usr/bin/env python3

import sys
import subprocess
import json
import csv
import statistics
import re
import argparse
import io
import os
import math


def get_warmup_file(specified=None):
    if specified:
        return specified if specified.startswith("@") else f"@{specified}"
    for candidate in ["isp_unique_warmup.txt", "tests/isp_unique_warmup.txt", "unicos.txt", "unique.txt", "tests/unique.txt", "tests/dnsperf_warmup.txt"]:
        if os.path.exists(candidate):
            return f"@{candidate}"
    return "@unique.txt"


def get_benchmark_file(specified=None):
    if specified:
        return specified if specified.startswith("@") else f"@{specified}"
    for candidate in ["isp_queries_2m.txt", "tests/isp_queries_2m.txt", "dominios3.txt", "dominios.txt", "tests/dominos2.txt", "tests/dominios.txt"]:
        if os.path.exists(candidate):
            return f"@{candidate}"
    return "@dominios3.txt"


def run_warmup(server, duration, concurrency, workers=8, dns_type="A", warmup_file=None, edns0=0):
    workers = max(1, workers)
    worker_concurrency = max(1, concurrency // workers)
    warmup_target = get_warmup_file(warmup_file)
    num_cpus = os.cpu_count() or 12

    procs = []
    for i in range(workers):
        core = i % num_cpus
        cmd = [
            "taskset", "-c", str(core),
            "dnspyre",
            "--duration", f"{duration}s",
            "--concurrency", str(worker_concurrency),
            "--server", server,
            "--type", dns_type,
        ]
        if edns0 > 0:
            cmd.append(f"--edns0={edns0}")
        else:
            cmd.append("--ednsopt=10:11223344556677889900aabb")
        cmd.append("--request=1s")

        cmd.append(warmup_target)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        procs.append(p)

    for p in procs:
        p.wait()


def run_dnspyre(server, duration, concurrency, workers=8, dns_type="A", queries_file=None, dnssec=False, tcp=False, edns0=0, rate=0):
    workers = max(1, workers)
    worker_concurrency = max(1, concurrency // workers)
    query_target = get_benchmark_file(queries_file)
    num_cpus = os.cpu_count() or 12

    rate_per_conn = 0
    if rate > 0 and concurrency > 0:
        rate_per_conn = max(1, int(round(rate / concurrency)))

    procs = []
    for i in range(workers):
        core = i % num_cpus
        cmd = [
            "taskset", "-c", str(core),
            "dnspyre",
            "--duration", f"{duration}s",
            "--concurrency", str(worker_concurrency),
            "--server", server,
            "--type", dns_type,
            "--json",
        ]
        if rate_per_conn > 0:
            cmd.append(f"--rate-limit-worker={rate_per_conn}")
        if dnssec:
            cmd.append("--dnssec")
        if tcp:
            cmd.append("--tcp")
        if edns0 > 0:
            cmd.append(f"--edns0={edns0}")
        else:
            cmd.append("--ednsopt=10:11223344556677889900aabb")
        cmd.append("--request=1s")

        cmd.append(query_target)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        procs.append(p)

    raw_outputs = []
    for p in procs:
        stdout, stderr = p.communicate()
        raw_outputs.append((p.returncode, stdout, stderr))

    return raw_outputs


def calculate_percentile_from_dist(distribution, percentile=99.9):
    """
    Computes precise percentile from dnspyre's histogram buckets in latencyDistribution.
    """
    if not distribution:
        return 0.0

    valid_buckets = []
    for bucket in distribution:
        cnt = bucket.get("count", 0)
        lat = bucket.get("latencyMs", 0)
        if cnt > 0:
            valid_buckets.append((float(lat), int(cnt)))

    if not valid_buckets:
        return 0.0

    valid_buckets.sort(key=lambda x: x[0])
    total_samples = sum(c for _, c in valid_buckets)
    if total_samples == 0:
        return 0.0

    target_count = (percentile / 100.0) * total_samples
    cumulative = 0
    for latency, count in valid_buckets:
        cumulative += count
        if cumulative >= target_count:
            return latency

    return valid_buckets[-1][0]


def parse_duration_to_ms(value, unit):
    unit = unit.strip()
    value = float(value)
    if unit == "µs":
        return value / 1000
    elif unit == "ms":
        return value
    elif unit == "s":
        return value * 1000
    return value


def strip_ansi(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


def extract_single_worker_fields(raw_output):
    # 1. Structured JSON parsing (preferred mode from dnspyre --json)
    json_match = re.search(r'\{.*\}', raw_output, re.DOTALL)
    if json_match:
        try:
            data = json.loads(json_match.group(0))
            lat_stats = data.get("latencyStats", {})
            dist = data.get("latencyDistribution", [])

            total_req = float(data.get("totalRequests", 0))
            success_req = float(data.get("totalSuccessResponses", 0))
            io_err = float(data.get("totalIOErrors", 0))
            neg_req = float(data.get("totalNegativeResponses", 0))
            err_req = float(data.get("totalErrorResponses", 0))
            trunc_req = float(data.get("totalTruncatedResponses", 0))
            id_mismatch = float(data.get("totalIDmismatch", 0))
            qps = float(data.get("queriesPerSecond", 0.0))

            mean_ms = float(lat_stats.get("meanMs", 0.0))
            p50_ms = float(lat_stats.get("p50Ms", 0.0))
            p75_ms = float(lat_stats.get("p75Ms", 0.0))
            p90_ms = float(lat_stats.get("p90Ms", 0.0))
            p95_ms = float(lat_stats.get("p95Ms", 0.0))
            p99_ms = float(lat_stats.get("p99Ms", 0.0))
            p99_9_ms = calculate_percentile_from_dist(dist, 99.9) if dist else p99_ms
            min_ms = float(lat_stats.get("minMs", 0.0))
            max_ms = float(lat_stats.get("maxMs", 0.0))
            std_ms = float(lat_stats.get("stdMs", 0.0))

            packet_loss_pct = ((total_req - success_req) / total_req * 100.0) if total_req > 0 else 0.0

            return {
                "totalRequests": total_req,
                "queriesPerSecond": qps,
                "latency_mean_ms": mean_ms,
                "latency_p50_ms": p50_ms,
                "latency_p75_ms": p75_ms,
                "latency_p90_ms": p90_ms,
                "latency_p95_ms": p95_ms,
                "latency_p99_ms": p99_ms,
                "latency_p99_9_ms": p99_9_ms,
                "latency_min_ms": min_ms,
                "latency_max_ms": max_ms,
                "latency_std_ms": std_ms,
                "totalSuccessResponses": success_req,
                "totalNegativeResponses": neg_req,
                "totalErrorResponses": err_req,
                "totalIOErrors": io_err,
                "totalTruncatedResponses": trunc_req,
                "totalIDmismatch": id_mismatch,
                "packet_loss_pct": round(packet_loss_pct, 4),
                "raw_dist": dist,
            }
        except Exception:
            pass

    # 2. Fallback regex text parsing
    text = strip_ansi(raw_output)

    def get_float(pattern):
        m = re.search(pattern, text)
        return float(m.group(1)) if m else 0.0

    def get_latency(label):
        m = re.search(rf"{label}:\s+([\d.]+)(µs|ms|s)", text)
        if m:
            return parse_duration_to_ms(m.group(1), m.group(2))
        return 0.0

    total_req = get_float(r"Total requests:\s+([\d.]+)")
    success_req = get_float(r"Total success responses:\s+([\d.]+)")
    qps = get_float(r"Questions per second:\s+([\d.]+)")
    p99 = get_latency("p99")
    loss_pct = ((total_req - success_req) / total_req * 100.0) if total_req > 0 else 0.0

    return {
        "totalRequests": total_req,
        "queriesPerSecond": qps,
        "latency_mean_ms": get_latency("mean"),
        "latency_p50_ms": get_latency("p50"),
        "latency_p75_ms": get_latency("p75"),
        "latency_p90_ms": get_latency("p90"),
        "latency_p95_ms": get_latency("p95"),
        "latency_p99_ms": p99,
        "latency_p99_9_ms": p99,
        "latency_min_ms": get_latency("min"),
        "latency_max_ms": get_latency("max"),
        "latency_std_ms": get_latency("std"),
        "totalSuccessResponses": success_req,
        "totalNegativeResponses": get_float(r"Total negative responses:\s+([\d.]+)"),
        "totalErrorResponses": get_float(r"Total error responses:\s+([\d.]+)"),
        "totalIOErrors": get_float(r"Total IO errors:\s+([\d.]+)"),
        "totalTruncatedResponses": get_float(r"Total truncated responses:\s+([\d.]+)"),
        "totalIDmismatch": get_float(r"Total ID mismatch:\s+([\d.]+)"),
        "packet_loss_pct": round(loss_pct, 4),
        "raw_dist": [],
    }


def extract_principal_fields(raw_output):
    """Backwards compatible alias for single output."""
    res = extract_single_worker_fields(raw_output)
    res.pop("raw_dist", None)
    return res


def aggregate_worker_results(worker_data_list):
    if not worker_data_list:
        return {}
    if len(worker_data_list) == 1:
        res = dict(worker_data_list[0])
        res.pop("raw_dist", None)
        return res

    total_req = sum(w.get("totalRequests", 0) for w in worker_data_list)
    success_req = sum(w.get("totalSuccessResponses", 0) for w in worker_data_list)
    neg_req = sum(w.get("totalNegativeResponses", 0) for w in worker_data_list)
    err_req = sum(w.get("totalErrorResponses", 0) for w in worker_data_list)
    io_err = sum(w.get("totalIOErrors", 0) for w in worker_data_list)
    trunc_req = sum(w.get("totalTruncatedResponses", 0) for w in worker_data_list)
    id_mismatch = sum(w.get("totalIDmismatch", 0) for w in worker_data_list)
    qps = sum(w.get("queriesPerSecond", 0.0) for w in worker_data_list)
    packet_loss_pct = ((total_req - success_req) / total_req * 100.0) if total_req > 0 else 0.0

    # Combine latency distributions across all workers
    combined_dist_dict = {}
    for w in worker_data_list:
        for b in w.get("raw_dist", []):
            lat = float(b.get("latencyMs", 0))
            cnt = int(b.get("count", 0))
            if cnt > 0:
                combined_dist_dict[lat] = combined_dist_dict.get(lat, 0) + cnt

    if combined_dist_dict:
        combined_dist = [{"latencyMs": lat, "count": cnt} for lat, cnt in sorted(combined_dist_dict.items())]
        total_samples = sum(combined_dist_dict.values())
        mean_ms = sum(lat * cnt for lat, cnt in combined_dist_dict.items()) / total_samples
        variance = sum(cnt * ((lat - mean_ms) ** 2) for lat, cnt in combined_dist_dict.items()) / total_samples
        std_ms = math.sqrt(variance)
        min_ms = min(combined_dist_dict.keys())
        max_ms = max(combined_dist_dict.keys())
        p50_ms = calculate_percentile_from_dist(combined_dist, 50.0)
        p75_ms = calculate_percentile_from_dist(combined_dist, 75.0)
        p90_ms = calculate_percentile_from_dist(combined_dist, 90.0)
        p95_ms = calculate_percentile_from_dist(combined_dist, 95.0)
        p99_ms = calculate_percentile_from_dist(combined_dist, 99.0)
        p99_9_ms = calculate_percentile_from_dist(combined_dist, 99.9)
    else:
        # Fallback weighted average
        sum_success = max(1.0, success_req)
        mean_ms = sum(w["latency_mean_ms"] * w["totalSuccessResponses"] for w in worker_data_list) / sum_success
        p50_ms = max(w["latency_p50_ms"] for w in worker_data_list)
        p75_ms = max(w["latency_p75_ms"] for w in worker_data_list)
        p90_ms = max(w["latency_p90_ms"] for w in worker_data_list)
        p95_ms = max(w["latency_p95_ms"] for w in worker_data_list)
        p99_ms = max(w["latency_p99_ms"] for w in worker_data_list)
        p99_9_ms = max(w["latency_p99_9_ms"] for w in worker_data_list)
        min_candidates = [w["latency_min_ms"] for w in worker_data_list if w["latency_min_ms"] > 0]
        min_ms = min(min_candidates) if min_candidates else 0.0
        max_ms = max((w["latency_max_ms"] for w in worker_data_list), default=0.0)
        std_ms = max((w["latency_std_ms"] for w in worker_data_list), default=0.0)

    return {
        "totalRequests": total_req,
        "queriesPerSecond": round(qps, 2),
        "latency_mean_ms": round(mean_ms, 3),
        "latency_p50_ms": round(p50_ms, 3),
        "latency_p75_ms": round(p75_ms, 3),
        "latency_p90_ms": round(p90_ms, 3),
        "latency_p95_ms": round(p95_ms, 3),
        "latency_p99_ms": round(p99_ms, 3),
        "latency_p99_9_ms": round(p99_9_ms, 3),
        "latency_min_ms": round(min_ms, 3),
        "latency_max_ms": round(max_ms, 3),
        "latency_std_ms": round(std_ms, 3),
        "totalSuccessResponses": success_req,
        "totalNegativeResponses": neg_req,
        "totalErrorResponses": err_req,
        "totalIOErrors": io_err,
        "totalTruncatedResponses": trunc_req,
        "totalIDmismatch": id_mismatch,
        "packet_loss_pct": round(packet_loss_pct, 4),
    }


def execute_measured_run(server, duration, concurrency, warmup, workers=8, dns_type="A",
                         queries_file=None, warmup_file=None, dnssec=False, tcp=False, edns0=0, rate=0):
    if warmup:
        print("  Warmup run...", file=sys.stderr)
        run_warmup(
            server=server,
            duration=duration,
            concurrency=concurrency,
            workers=workers,
            dns_type=dns_type,
            warmup_file=warmup_file,
            edns0=edns0
        )

    print("  Measured run...", file=sys.stderr)
    raw_outputs = run_dnspyre(
        server=server,
        duration=duration,
        concurrency=concurrency,
        workers=workers,
        dns_type=dns_type,
        queries_file=queries_file,
        dnssec=dnssec,
        tcp=tcp,
        edns0=edns0,
        rate=rate
    )

    worker_data_list = []
    for retcode, stdout, stderr in raw_outputs:
        if retcode != 0 and not stdout.strip():
            print(f"Warning: dnspyre worker failed with code {retcode}: {stderr.strip()}", file=sys.stderr)
        w_data = extract_single_worker_fields(stdout)
        worker_data_list.append(w_data)

    res = aggregate_worker_results(worker_data_list)
    if rate > 0:
        res["targetRate"] = rate
    return res


def main():
    parser = argparse.ArgumentParser(description='Run DNS benchmark using parallel taskset dnspyre workers and export detailed metrics CSV.')
    parser.add_argument('--server', type=str, required=True, help='DNS server IP/host')
    parser.add_argument('--duration', type=int, required=True, help='Measurement duration in seconds')
    parser.add_argument('--concurrency', type=int, required=True, help='Concurrency level')
    parser.add_argument('--rate', type=int, default=0, help='Target queries per second across all workers (rate-driven mode)')
    parser.add_argument('--workers', type=int, default=8, help='Number of parallel worker processes pinned to CPU cores via taskset')
    parser.add_argument('--warmup', action='store_true', help='Execute warmup phase before measured run')
    parser.add_argument('--type', dest='dns_type', type=str, default='A', help='DNS query type (A, AAAA, CNAME, etc.)')
    parser.add_argument('--queries', dest='queries_file', type=str, default=None, help='Queries file path')
    parser.add_argument('--warmup-queries', dest='warmup_file', type=str, default=None, help='Warmup queries file path')
    parser.add_argument('--dnssec', action='store_true', help='Set DNSSEC DO bit')
    parser.add_argument('--tcp', action='store_true', help='Fallback to TCP')
    parser.add_argument('--edns0', type=int, default=0, help='EDNS0 buffer size')

    args = parser.parse_args()

    extracted_data = execute_measured_run(
        server=args.server,
        duration=args.duration,
        concurrency=args.concurrency,
        warmup=args.warmup,
        workers=args.workers,
        dns_type=args.dns_type,
        queries_file=args.queries_file,
        warmup_file=args.warmup_file,
        dnssec=args.dnssec,
        tcp=args.tcp,
        edns0=args.edns0,
        rate=args.rate
    )

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=extracted_data.keys())
    writer.writeheader()
    writer.writerow(extracted_data)

    print(output.getvalue(), end='')


if __name__ == "__main__":
    main()
