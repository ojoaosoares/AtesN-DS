#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROJECT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

cd "$PROJECT_DIR"

CAPACITY=${1:-2000000}
RUNS=${2:-30}
NOVEL=${3:-50000}
EXPIRED=${4:-100000}

echo "=========================================================================="
echo "🚀 AtesN-DS Evaluation: PASSIVE EVICT-ON-WRITE vs. ACTIVE CLEANER SWEEPS"
echo "=========================================================================="
echo "  Scale:       ${CAPACITY} entries (100% full saturation)"
echo "  Runs:        ${RUNS} independent cycles"
echo "  Novel Adds:  ${NOVEL} novel records inserted"
echo "  Expired:     ${EXPIRED} initial expired records per cycle"
echo "=========================================================================="
echo ""

echo "-> [Step 1/3] Compilando binário nativo bench_passive_eviction..."
make bench-passive

echo ""
echo "-> [Step 2/3] Executando benchmark estatístico com lookups concorrentes..."
./bin/bench_passive_eviction -n "$CAPACITY" -r "$RUNS" -m "$NOVEL" -e "$EXPIRED"

echo ""
echo "-> [Step 3/3] Gerando gráficos comparativos de publicação..."
python3 graphs/plot_passive_eviction.py

echo ""
echo "=========================================================================="
echo "🎉 Avaliação concluída com sucesso!"
echo "   Dados CSV: data/passive_eviction_benchmark.csv"
echo "   Figuras:   results/passive_vs_active_pcie_and_occupancy.png (.svg)"
echo "              results/passive_vs_active_lookups_and_latency.png (.svg)"
echo "=========================================================================="
