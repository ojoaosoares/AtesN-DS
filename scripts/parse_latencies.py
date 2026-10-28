import csv

summary_file = 'official_results/09_ttl30s_eviction_study/summary_official_pcie2_sweep.csv'
with open(summary_file, 'r') as f:
    rows = list(csv.DictReader(f))

print(f"{'Mode':<18} | {'Target':<7} | {'Mean (ms)':<9} | {'p50 (ms)':<9} | {'p75 (ms)':<9} | {'p90 (ms)':<9} | {'p95 (ms)':<9} | {'p99 (ms)':<9} | {'p99.9':<7} | {'Max (ms)':<9} | {'Std (ms)':<8}")
print("-" * 125)
for r in sorted(rows, key=lambda x: (x['mode'], -int(x['target_qps']))):
    m = r['mode']
    t = r['target_qps']
    mean = float(r['lat_mean_ms_mean'])
    p50 = float(r['lat_p50_ms_mean'])
    p75 = float(r['lat_p75_ms_mean'])
    p90 = float(r['lat_p90_ms_mean'])
    p95 = float(r['lat_p95_ms_mean'])
    p99 = float(r['lat_p99_ms_mean'])
    p999 = float(r['lat_p99_9_ms_mean'])
    max_lat = float(r['lat_max_ms_mean'])
    std_lat = float(r['lat_std_ms_mean'])
    print(f"{m:<18} | {t:<7} | {mean:9.3f} | {p50:9.3f} | {p75:9.3f} | {p90:9.3f} | {p95:9.3f} | {p99:9.3f} | {p999:7.3f} | {max_lat:9.3f} | {std_lat:8.3f}")
