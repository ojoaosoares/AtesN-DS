import csv

summary_file = 'official_results/09_ttl30s_eviction_study/summary_official_pcie2_sweep.csv'
with open(summary_file, 'r') as f:
    rows = list(csv.DictReader(f))

print(f"{'Mode':<18} | {'Target':<7} | {'Achieved QPS':<14} | {'Loss %':<8} | {'p99 (ms)':<9} | {'HW Hits %':<10} | {'Discards':<10} | {'CPU %':<7}")
print("-" * 95)
for r in sorted(rows, key=lambda x: (x['mode'], -int(x['target_qps']))):
    ach_qps = float(r['achieved_qps_mean'])
    loss = float(r['packet_loss_pct_mean'])
    p99 = float(r['lat_p99_ms_mean'])
    hw_hr = float(r['hw_hit_rate_pct_mean'])
    disc = int(float(r['nic_rx_discards_mean']))
    cpu = float(r['srv_all_busy_mean'])
    print(f"{r['mode']:<18} | {r['target_qps']:<7} | {ach_qps:14,.0f} | {loss:7.2f}% | {p99:8.2f}  | {hw_hr:8.2f}%  | {disc:10,d} | {cpu:6.2f}%")
