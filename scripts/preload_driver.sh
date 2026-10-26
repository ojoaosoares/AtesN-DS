#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

TRACE="${1:-${BASE_DIR}/tests/isp_unique_warmup_dnsperf.txt}"
TTL="${2:-3600}"

if [ ! -f "${BASE_DIR}/bin/preload_cache" ]; then
    echo "[BUILD] Compiling bin/preload_cache..."
    make -C "${BASE_DIR}" preload >/dev/null 2>&1 || clang-15 "${BASE_DIR}/src/preload_cache.c" -o "${BASE_DIR}/bin/preload_cache" -I "${BASE_DIR}/include" -lbpf
fi

sudo -n "${BASE_DIR}/bin/preload_cache" --driver "${TRACE}" "${TTL}"
