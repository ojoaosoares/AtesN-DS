#!/usr/bin/env bash
# ==============================================================================
# scripts/preload_30s_ttl.sh
#
# Pre-populates Unbound, Host Driver, and SmartNIC HW caches with a fixed 30s TTL
# to evaluate dynamic cache expiration, timing wheel sweeps, and evict-on-write.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

HOST_TRACE="${1:-${BASE_DIR}/tests/isp_unique_warmup_dnsperf.txt}"
HW_TRACE="${2:-${BASE_DIR}/tests/isp_top32k_hw_warmup_dnsperf.txt}"
TTL=30

echo "=== PRE-POPULATING CACHES WITH FIXED TTL = ${TTL}s ==="
"${SCRIPT_DIR}/preload_unbound.sh" "${HOST_TRACE}" "${TTL}"
"${SCRIPT_DIR}/preload_driver.sh" "${HOST_TRACE}" "${TTL}"
"${SCRIPT_DIR}/preload_hw.sh" "${HW_TRACE}" "${TTL}"
echo "✓ All caches pre-populated with TTL = ${TTL}s"
