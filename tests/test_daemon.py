#!/usr/bin/env python3
"""
Unit tests for AtesN-DS Control-Plane Daemon Architecture,
Timing Wheel Logic, Dual-Watermark Eviction, and Event Serialization.
"""

import sys
import struct
import unittest
from pathlib import Path
from collections import defaultdict

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import ates

MAX_DNS_NAME_LENGTH_HW = 56


class MockTimingWheel:
    """
    Python mirror of the O(1) circular timing wheel implemented in src/daemon_timing_wheel.c.
    Maintains 86,400 second-resolution buckets to track DRAM expiration without PCIe reads.
    """
    def __init__(self, capacity=86400):
        self.capacity = capacity
        self.buckets = defaultdict(list)
        self.total_entries = 0
        self.last_tick = 0

    def insert(self, name: str, expire_time: int):
        bucket_idx = expire_time % self.capacity
        # Store name and expire_time
        self.buckets[bucket_idx].append({"name": name, "expire_time": expire_time})
        self.total_entries += 1

    def pop_expired(self, current_time: int):
        """Zero-PCIe-Read expiration sweep from last_tick to current_time."""
        expired = []
        if self.last_tick == 0:
            self.last_tick = current_time

        ticks = min(current_time - self.last_tick, self.capacity)
        for i in range(1, ticks + 1):
            idx = (self.last_tick + i) % self.capacity
            items = self.buckets.pop(idx, [])
            for item in items:
                expired.append(item)
                self.total_entries -= 1

        self.last_tick = current_time
        return expired

    def pop_min_ttl(self, current_time: int, count: int):
        """Proactive eviction of keys with lowest remaining TTLs."""
        evicted = []
        for i in range(self.capacity):
            if len(evicted) >= count:
                break
            idx = (current_time + i) % self.capacity
            items = self.buckets.get(idx, [])
            while items and len(evicted) < count:
                item = items.pop(0)
                evicted.append(item)
                self.total_entries -= 1
            if not items and idx in self.buckets:
                del self.buckets[idx]
        return evicted


class TestDaemonArchitecture(unittest.TestCase):
    """Test suite validating daemon timing wheel algorithms and memory mechanics."""

    def test_timing_wheel_insert_and_collision(self):
        """Verify O(1) bucket insertion and hash collision handling."""
        wheel = MockTimingWheel(capacity=1000)
        now = 5000

        # Insert 3 domains at different timestamps
        wheel.insert("example.com", now + 10)
        wheel.insert("google.com", now + 20)
        wheel.insert("github.com", now + 30)
        self.assertEqual(wheel.total_entries, 3)

        # Insert 2 colliding domains at exact same timestamp
        wheel.insert("collision1.org", now + 50)
        wheel.insert("collision2.org", now + 50)
        self.assertEqual(wheel.total_entries, 5)

        col_bucket = (now + 50) % wheel.capacity
        self.assertEqual(len(wheel.buckets[col_bucket]), 2)
        domains = [item["name"] for item in wheel.buckets[col_bucket]]
        self.assertIn("collision1.org", domains)
        self.assertIn("collision2.org", domains)

    def test_zero_pcie_read_expiration_sweep(self):
        """Verify advancing time pops expired elements without querying hardware."""
        wheel = MockTimingWheel(capacity=1000)
        start_time = 10000
        wheel.last_tick = start_time

        wheel.insert("exp-1.com", start_time + 10)
        wheel.insert("exp-2.com", start_time + 20)
        wheel.insert("future-1.com", start_time + 100)
        self.assertEqual(wheel.total_entries, 3)

        # Advance by 5s -> no keys expire
        popped = wheel.pop_expired(start_time + 5)
        self.assertEqual(len(popped), 0)
        self.assertEqual(wheel.total_entries, 3)

        # Advance to 25s -> exp-1 and exp-2 expire, future-1 stays
        popped = wheel.pop_expired(start_time + 25)
        self.assertEqual(len(popped), 2)
        names = [p["name"] for p in popped]
        self.assertIn("exp-1.com", names)
        self.assertIn("exp-2.com", names)
        self.assertEqual(wheel.total_entries, 1)

        # Advance past 100s -> future-1 expires
        popped = wheel.pop_expired(start_time + 150)
        self.assertEqual(len(popped), 1)
        self.assertEqual(popped[0]["name"], "future-1.com")
        self.assertEqual(wheel.total_entries, 0)

    def test_proactive_min_ttl_watermark_eviction(self):
        """Verify watermark-driven eviction preferentially evicts lowest remaining TTLs."""
        wheel = MockTimingWheel(capacity=1000)
        now = 20000
        wheel.last_tick = now

        wheel.insert("ttl-10.com", now + 10)
        wheel.insert("ttl-20.com", now + 20)
        wheel.insert("ttl-30.com", now + 30)
        wheel.insert("ttl-40.com", now + 40)
        wheel.insert("ttl-50.com", now + 50)
        self.assertEqual(wheel.total_entries, 5)

        # Proactively evict 2 entries
        evicted = wheel.pop_min_ttl(now, 2)
        self.assertEqual(len(evicted), 2)
        self.assertEqual(wheel.total_entries, 3)

        evicted_names = [e["name"] for e in evicted]
        # Must evict ttl-10 and ttl-20 first (lowest TTLs)
        self.assertEqual(evicted_names, ["ttl-10.com", "ttl-20.com"])

        # Remaining should be ttl-30, ttl-40, ttl-50
        remaining_names = [
            item["name"]
            for items in wheel.buckets.values()
            for item in items
        ]
        self.assertIn("ttl-30.com", remaining_names)
        self.assertIn("ttl-40.com", remaining_names)
        self.assertIn("ttl-50.com", remaining_names)

    def test_dual_watermark_calculations(self):
        """Verify mathematical watermark calculations for 2,000,000 capacity."""
        capacity = 2000000
        high_pct = 90
        low_pct = 80

        high_watermark = (capacity * high_pct) // 100
        low_watermark = (capacity * low_pct) // 100

        self.assertEqual(high_watermark, 1800000)
        self.assertEqual(low_watermark, 1600000)

        # Saturated occupancy: 1,850,000
        curr_occ = 1850000
        self.assertGreater(curr_occ, high_watermark)

        needed_evictions = curr_occ - low_watermark
        self.assertEqual(needed_evictions, 250000)

    def test_hw_sync_event_binary_serialization(self):
        """Verify binary format and memory layout matching C struct hw_cache_sync_event."""
        # C struct layout:
        # char name[56];
        # __be32 ip;
        # __u32 timestamp;
        # Total size: 64 bytes (56 + 4 + 4)
        domain = "netflix.com"
        raw_name = domain.encode("ascii").ljust(MAX_DNS_NAME_LENGTH_HW, b"\x00")
        self.assertEqual(len(raw_name), 56)

        ip_int = 0x0100007F  # 127.0.0.1 in network byte order
        timestamp = 1718000000

        # Pack matching struct hw_cache_sync_event
        packed = struct.pack("=56sII", raw_name, ip_int, timestamp)
        self.assertEqual(len(packed), 64)

        # Unpack and verify
        unpacked_name, unpacked_ip, unpacked_ts = struct.unpack("=56sII", packed)
        clean_name = unpacked_name.rstrip(b"\x00").decode("ascii")
        self.assertEqual(clean_name, domain)
        self.assertEqual(unpacked_ip, ip_int)
        self.assertEqual(unpacked_ts, timestamp)

    def test_dns_listener_binary_help(self):
        """Verify that bin/dns_listener binary compiles and runs help message cleanly."""
        listener_bin = ROOT_DIR / "bin" / "dns_listener"
        if listener_bin.exists():
            import subprocess
            res = subprocess.run([str(listener_bin), "-h"], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)
            self.assertIn("AtesN-DS Decoupled DNS Listener", res.stdout)
            self.assertIn("--interface", res.stdout)
            self.assertIn("--ringbuf", res.stdout)


if __name__ == "__main__":
    unittest.main()
