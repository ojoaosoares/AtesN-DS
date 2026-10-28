#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "=== PRE-POPULATING ALL DNS CACHES (Unbound + Driver + HW) ==="
"${SCRIPT_DIR}/preload_unbound.sh" "$@"
"${SCRIPT_DIR}/preload_driver.sh" "$@"
"${SCRIPT_DIR}/preload_hw.sh" "$@"
echo "=== ALL CACHES PRE-POPULATED SUCCESSFULLY ==="
