# Relatório Oficial: Evaluation Suite 2 (TTL Estático / Capacidade Máxima)

**Artigo de Referência:** Seção 4.4 (*Suite 2: Upper Bound with Static Capacity*) em `main.tex`  
**Data da Campanha:** Outubro de 2026  
**Topologia de Hardware:** 
- Servidor: Netronome Agilio-CX NFP-3800, 2 Cores dedicados ao tráfego (`0, 1`), 4 Filas de Hardware ativas (`Combined: 4`), Cores `2, 3` alocados para o SO e Daemons de Controle.
- Cliente: Gerador de tráfego `xdnsperf` (AF_XDP multi-thread) saturando link físico de 10GbE.
**Regime de Cache:** Estático ($\text{TTL} = 3.600\,\text{s}$). Todas as $32.768$ entradas da SmartNIC e $83.659$ entradas do host pré-carregadas antes do início do tráfego.  
**Protocolo:** 4 Modos $\times$ 5 Taxas ($500\,\text{kQPS}$ a $\text{UNLIMITED}$) $\times$ 10 Repetições $\times$ 120 segundos ($N = 200$ execuções completas com *clean warmup* e validação de consistência de anéis).

---

## 1. Tabela Consolidada de Desempenho (Médias das 10 Repetições, IC 95%)

| Modo | Taxa Alvo (QPS) | Vazão Efetiva (QPS) | Perda de Pacotes (%) | Latência Média (ms) | Latência $p_{99}$ (ms) | Latência $p_{99.9}$ (ms) | CPU Dedicada (%) | SoftIRQ (%) | HW Hit Rate (%) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`ates_hw_cache`** | **UNLIMITED** | **7.660.888** $\pm$ 58.891 | **0,17%** $\pm$ 0,02% | **2,05 ms** | **2,81 ms** | **2,84 ms** | **14,0%** | **5,9%** | **96,34%** |
| `ates_hw_cache` | 5.000.000 | 4.683.695 $\pm$ 1.274 | 0,17% $\pm$ 0,01% | 2,93 ms | 4,44 ms | 4,45 ms | 7,5% | 3,0% | 96,34% |
| `ates_hw_cache` | 3.000.000 | 2.815.907 $\pm$ 254 | 0,09% $\pm$ 0,00% | 4,56 ms | 7,30 ms | 7,31 ms | 4,1% | 1,6% | 96,27% |
| `ates_hw_cache` | 1.000.000 | 940.199 $\pm$ 81 | 0,01% $\pm$ 0,00% | 13,37 ms | 21,71 ms | 21,75 ms | 1,1% | 0,3% | 96,18% |
| `ates_hw_cache` | 500.000 | 470.424 $\pm$ 25 | 0,02% $\pm$ 0,00% | 26,27 ms | 43,60 ms | 43,91 ms | 0,7% | 0,1% | 96,18% |
| **`ates_driver`** | **UNLIMITED** | **4.518.047** $\pm$ 2.792 | **49,57%** $\pm$ 0,04% | **3,59 ms** | **5,91 ms** | **6,00 ms** | **98,9%** | **49,5%** | **0,00%** |
| `ates_driver` | 5.000.000 | 4.521.089 $\pm$ 8.730 | 3,58% $\pm$ 0,18% | 5,85 ms | 7,62 ms | 7,68 ms | 98,7% | 49,4% | 0,00% |
| `ates_driver` | 3.000.000 | 2.814.577 $\pm$ 306 | 0,11% $\pm$ 0,01% | 5,27 ms | 8,31 ms | 8,38 ms | 48,5% | 24,2% | 0,00% |
| `ates_driver` | 1.000.000 | 940.274 $\pm$ 66 | 0,01% $\pm$ 0,00% | 13,97 ms | 23,65 ms | 24,47 ms | 12,3% | 6,0% | 0,00% |
| `ates_driver` | 500.000 | 470.475 $\pm$ 23 | 0,02% $\pm$ 0,00% | 27,71 ms | 49,19 ms | 49,45 ms | 7,9% | 3,8% | 0,00% |
| **`unbound_hw_cache`** | **UNLIMITED** | **7.596.658** $\pm$ 32.018 | **1,93%** $\pm$ 0,02% | **2,07 ms** | **2,82 ms** | **2,84 ms** | **98,9%** | **24,1%** | **98,07%** |
| `unbound_hw_cache` | 5.000.000 | 4.683.454 $\pm$ 1.315 | 0,16% $\pm$ 0,01% | 3,01 ms | 4,54 ms | 4,59 ms | 88,9% | 16,7% | 96,34% |
| `unbound_hw_cache` | 3.000.000 | 2.815.896 $\pm$ 348 | 0,09% $\pm$ 0,00% | 4,61 ms | 7,35 ms | 7,38 ms | 55,7% | 10,4% | 96,26% |
| `unbound_hw_cache` | 1.000.000 | 940.298 $\pm$ 61 | 0,01% $\pm$ 0,00% | 13,44 ms | 21,81 ms | 22,12 ms | 18,1% | 3,2% | 96,18% |
| `unbound_hw_cache` | 500.000 | 470.447 $\pm$ 32 | 0,01% $\pm$ 0,00% | 26,44 ms | 44,19 ms | 44,54 ms | 9,2% | 1,7% | 96,18% |
| **`unbound_standalone`**| **UNLIMITED** | **32** $\pm$ 4 | **100,00%** $\pm$ 0,00% | **2,64 ms** | **5,22 ms** | **5,59 ms** | **98,9%** | **49,5%** | **0,00%** |
| `unbound_standalone` | 5.000.000 | 33 $\pm$ 4 | 100,00% $\pm$ 0,00% | 5,20 ms | 10,34 ms | 10,44 ms | 98,9% | 49,5% | 0,00% |
| `unbound_standalone` | 3.000.000 | 34 $\pm$ 3 | 100,00% $\pm$ 0,00% | 8,76 ms | 17,24 ms | 17,40 ms | 98,9% | 49,5% | 0,00% |
| `unbound_standalone` | 1.000.000 | 762 $\pm$ 386 | 99,92% $\pm$ 0,04% | 33,02 ms | 50,49 ms | 50,77 ms | 98,9% | 49,4% | 0,00% |
| `unbound_standalone` | 500.000 | 125.507 $\pm$ 1.575 | 73,32% $\pm$ 0,33% | 72,71 ms | 98,30 ms | 101,58 ms | 97,6% | 31,7% | 0,00% |

---

## 2. Decomposição de Atendimento por Camada (Total de Consultas em 120s a Line Rate)

Sob taxa máxima de linha (`UNLIMITED`):
- **`ates_hw_cache`:**
  - **L1 SmartNIC SRAM:** $1.328.565.930$ consultas atendidas diretamente em silício ($96,34\%$).
  - **L2 Host DRAM (Driver XDP):** $50.392.425$ consultas resolvidas em DRAM no kernel ($3,66\%$).
  - **L3 Userspace:** Apenas $2.055$ consultas repassadas ($<0,001\%$).
- **`unbound_hw_cache`:**
  - **L1 SmartNIC SRAM:** $1.341.036.125$ consultas atendidas em silício ($98,07\%$).
  - **L3 Userspace (Unbound):** $26.362.906$ consultas resolvidas pelo daemon Unbound ($1,93\%$).
- **`ates_driver`:**
  - **L2 Host DRAM:** $813.247.462$ consultas atendidas. Zero aceleração por hardware.
- **`unbound_standalone`:**
  - Colapso arquitetural completo: apenas $5.828$ consultas processadas pelo daemon em 120 segundos sob $100\%$ de perda de pacotes.

---

## 3. Principais Conclusões de Desempenho

1. **Vazão Máxima de Silício (Line-Rate 10GbE):**
   - O `ates_hw_cache` atinge saturação física do enlace a **7,66 MQPS** com **0,17% de perda**, representando aceleração de **$1,70\times$** sobre o driver em kernel ($4,52\,\text{MQPS}$) e **$60\times$** sobre o Unbound standalone a 500 kQPS.
2. **Economia Massiva de Recursos de CPU:**
   - O hardware offload reduz o consumo de CPU dedicada de **98,9% para 14,0%** (economia de **$85,8\%$** de ciclos de CPU) e reduz a sobrecarga de SoftIRQ de **49,5% para 5,9%** (redução de **$88,1\%$**), deixando o servidor hospedeiro **86% ocioso**.
3. **Latência Ultrabaixa e Determinística:**
   - Reduz a latência de cauda $p_{99}$ em **$52,4\%$** (de $5,91\,\text{ms}$ para $2,81\,\text{ms}$) e $p_{99.9}$ em **$52,7\%$** (de $6,00\,\text{ms}$ para $2,84\,\text{ms}$).
   - Comprime a dispersão estocástica de cauda ($p_{99.9} - p_{99}$) em **$76,7\%$**, reduzindo-a para **$22,5\,\mu\text{s}$**.

---

## 4. Scripts e Datasets Oficiais Desta Suíte

- **Runner Oficial:** [`run_2core_clean_warmup_10reps.sh`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/06_multicore_xdnsperf_calibrated/run_2core_clean_warmup_10reps.sh)
- **Dataset Agregado:** [`summary_2core_clean_warmup_10reps.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/06_multicore_xdnsperf_calibrated/summary_2core_clean_warmup_10reps.csv)
- **Dataset Bruto:** [`raw_2core_clean_warmup_10reps.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/06_multicore_xdnsperf_calibrated/raw_2core_clean_warmup_10reps.csv)
- **Gerador de Gráficos do Artigo:** [`export_paper_png.py`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/06_multicore_xdnsperf_calibrated/export_paper_png.py)
