#!/usr/bin/env bash
# ==============================================================================
# run_ttl30s_max_throughput_sweep.sh
#
# Sweep to discover maximum sustainable throughput under dynamic TTL=30s eviction.
# Tests rates: 500k, 1M, 2M, 3M, 4M, 5M, 6M, 7M, UNLIMITED (0)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export RAW_CSV="${RAW_CSV:-${SCRIPT_DIR}/raw_ttl30s_max_throughput_sweep.csv}"
export SUMMARY_CSV="${SUMMARY_CSV:-${SCRIPT_DIR}/summary_ttl30s_max_throughput_sweep.csv}"
export REPS=${REPS:-1}
export DURATION=${DURATION:-60}

# Range of rates to test low loads and saturation point
export RATES="${RATES:-50000 100000 200000}"

chmod +x "${SCRIPT_DIR}/run_ttl30s_7mqps_10reps.sh"
"${SCRIPT_DIR}/run_ttl30s_7mqps_10reps.sh" "ates_hw_cache unbound_hw_cache" "${RATES}"
