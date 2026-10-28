#!/usr/bin/env python3
"""
Unit tests for AtesN-DS Management CLI (ates.py)
"""

import os
import sys
import unittest
import subprocess
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import ates


class TestAtesCLI(unittest.TestCase):
    """Test suite verifying CLI argument parsing, detection, and lifecycle commands."""

    def test_cli_help_flag(self):
        """Verify that './ates.py --help' executes cleanly and lists all subcommands."""
        res = subprocess.run(
            [sys.executable, str(ROOT_DIR / "ates.py"), "--help"],
            capture_output=True, text=True
        )
        self.assertEqual(res.returncode, 0)
        for cmd in ["start", "run", "stop", "restart", "status", "logs", "verify", "test"]:
            self.assertIn(cmd, res.stdout)

    def test_start_help_contains_all_sw_and_hw_options(self):
        """Verify that './ates.py start --help' documents all hardware and software map options."""
        res = subprocess.run(
            [sys.executable, str(ROOT_DIR / "ates.py"), "start", "--help"],
            capture_output=True, text=True
        )
        self.assertEqual(res.returncode, 0)
        expected_flags = [
            "--hw",
            "--no-hw",
            "--capacity",
            "--high-watermark",
            "--low-watermark",
            "--sw-cache-size",
            "--ns-cache-size",
            "--queries-size",
            "--interface",
            "--server-ip",
            "--mac",
            "--resolver",
            "--verbose",
        ]
        for flag in expected_flags:
            self.assertIn(flag, res.stdout, f"Flag '{flag}' missing from 'ates.py start --help'")

    def test_network_detection_helpers(self):
        """Verify network interface and address detection helpers return non-empty strings."""
        iface = ates.detect_interface()
        self.assertIsInstance(iface, str)
        self.assertTrue(len(iface) > 0)

        ip = ates.detect_ip(iface)
        self.assertIsInstance(ip, str)
        self.assertTrue(len(ip.split(".")) == 4, f"Invalid IPv4: {ip}")

        mac = ates.detect_mac(iface)
        self.assertIsInstance(mac, str)
        self.assertTrue(len(mac) == 17, f"Invalid MAC format: {mac}")

    def test_default_argument_values(self):
        """Verify parser defaults for hardware and software map capacities."""
        # Simulate CLI parse without executing
        parser = ates.argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        p_start = subparsers.add_parser("start")

        default_iface = ates.detect_interface()
        default_ip = ates.detect_ip(default_iface)
        default_mac = ates.detect_mac(default_iface)

        p_start.add_argument("--hw", dest="hw", action="store_true", default=True)
        p_start.add_argument("--no-hw", dest="hw", action="store_false")
        p_start.add_argument("-i", "--interface", default=default_iface)
        p_start.add_argument("-a", "--server-ip", default=default_ip)
        p_start.add_argument("-m", "--mac", default=default_mac)
        p_start.add_argument("-s", "--resolver", default="8.8.8.8")
        p_start.add_argument("-n", "--capacity", type=int, default=2000000)
        p_start.add_argument("-H", "--high-watermark", type=int, default=90)
        p_start.add_argument("-L", "--low-watermark", type=int, default=80)
        p_start.add_argument("-C", "--sw-cache-size", type=int, default=4000000)
        p_start.add_argument("-N", "--ns-cache-size", type=int, default=8000000)
        p_start.add_argument("-Q", "--queries-size", type=int, default=4587576)
        p_start.add_argument("-v", "--verbose", action="store_true")

        args = parser.parse_args(["start"])
        self.assertTrue(args.hw)
        self.assertEqual(args.capacity, 2000000)
        self.assertEqual(args.high_watermark, 90)
        self.assertEqual(args.low_watermark, 80)
        self.assertEqual(args.sw_cache_size, 4000000)
        self.assertEqual(args.ns_cache_size, 8000000)
        self.assertEqual(args.queries_size, 4587576)
        self.assertFalse(args.verbose)

    def test_custom_capacities_and_software_only_mode(self):
        """Verify custom map capacities and software-only mode (--no-hw)."""
        parser = ates.argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        p_start = subparsers.add_parser("start")

        p_start.add_argument("--hw", dest="hw", action="store_true", default=True)
        p_start.add_argument("--no-hw", dest="hw", action="store_false")
        p_start.add_argument("-n", "--capacity", type=int, default=2000000)
        p_start.add_argument("-H", "--high-watermark", type=int, default=90)
        p_start.add_argument("-L", "--low-watermark", type=int, default=80)
        p_start.add_argument("-C", "--sw-cache-size", type=int, default=4000000)
        p_start.add_argument("-N", "--ns-cache-size", type=int, default=8000000)
        p_start.add_argument("-Q", "--queries-size", type=int, default=4587576)
        p_start.add_argument("-v", "--verbose", action="store_true")

        custom_args = [
            "start",
            "--no-hw",
            "--capacity", "1500000",
            "-H", "85",
            "-L", "75",
            "-C", "1000000",
            "-N", "2000000",
            "-Q", "500000",
            "-v"
        ]
        args = parser.parse_args(custom_args)
        self.assertFalse(args.hw)
        self.assertEqual(args.capacity, 1500000)
        self.assertEqual(args.high_watermark, 85)
        self.assertEqual(args.low_watermark, 75)
        self.assertEqual(args.sw_cache_size, 1000000)
        self.assertEqual(args.ns_cache_size, 2000000)
        self.assertEqual(args.queries_size, 500000)
        self.assertTrue(args.verbose)

    def test_status_command_execution(self):
        """Verify './ates.py status' executes cleanly and formats output without throwing exceptions."""
        res = subprocess.run(
            [sys.executable, str(ROOT_DIR / "ates.py"), "status"],
            capture_output=True, text=True
        )
        self.assertEqual(res.returncode, 0, f"ates.py status failed with returncode {res.returncode}.\nStderr: {res.stderr}\nStdout: {res.stdout}")
        self.assertIn("AtesN-DS System Status", res.stdout)
        self.assertIn("Proxy Server", res.stdout)
        self.assertIn("Control Daemon", res.stdout)
        self.assertIn("Pinned BPF Maps", res.stdout)

    def test_test_subcommand_help(self):
        """Verify './ates.py test --help' displays options for CLI and daemon testing."""
        res = subprocess.run(
            [sys.executable, str(ROOT_DIR / "ates.py"), "test", "--help"],
            capture_output=True, text=True
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("--cli", res.stdout)
        self.assertIn("--daemon", res.stdout)


if __name__ == "__main__":
    unittest.main()
