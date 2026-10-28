# Relatório Final: Varredura Oficial de Desempenho no PCIe Gen 2

**Data:** 27 de Outubro de 2026  
**Topologia de Hardware:** Netronome Agilio-CX NFP-3800 no slot PCIe Gen 2 ($5.0\,\text{GT/s} \times 8 = 32\,\text{Gbps} / 4.0\,\text{GB/s}$)  
**Topologia de Software:** 2 Cores dedicados ao tráfego (`0,1`) com 4 Filas de Hardware ativas (`Combined: 4`), Cores `2,3` dedicados ao Sistema e Daemon.  
**Distribuição de TTL:** Empírica real (60s dominante para 62,70% do tráfego, 30s para 22,68%, 10s para 7,69%, 300s/1800s/86400s na cauda).  
**Protocolo:** 4 Modos $\times$ 4 Taxas $\times$ 5 Repetições $\times$ 120 segundos ($N = 80$ testes executados).

---

## 1. Tabela Consolidada de Desempenho (Médias das 5 Repetições)

| Modo | Taxa Alvo (QPS) | Vazão Efetiva (QPS) | Perda de Pacotes (%) | Latência $p_{99}$ (ms) | CPU Servidor (%) | HW Hit Rate (%) | Descartes NIC RX (DMA) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`ates_hw_cache`** | **4.000.000** | **3.748.286** | **0,15%** | **5,89 ms** | **22,80%** | **50,65%** | **1.636** |
| `ates_hw_cache` | 2.500.000 | 2.347.609 | 0,06% | 9,34 ms | 18,71% | 48,86% | 0 |
| `ates_hw_cache` | 1.000.000 | 940.178 | 0,01% | 23,26 ms | 8,51% | 49,07% | 0 |
| `ates_hw_cache` | 500.000 | 470.373 | 0,03% | 46,34 ms | 3,52% | 48,16% | 0 |
| **`ates_driver`** | **4.000.000** | **3.745.293** | **0,21%** | **6,67 ms** | **38,46%** | **0,00%** | **115.532** |
| `ates_driver` | 2.500.000 | 2.347.352 | 0,06% | 10,03 ms | 21,23% | 0,00% | 0 |
| `ates_driver` | 1.000.000 | 940.233 | 0,01% | 23,82 ms | 8,29% | 0,00% | 0 |
| `ates_driver` | 500.000 | 470.404 | 0,03% | 49,42 ms | 5,18% | 0,00% | 4 |
| **`unbound_hw_cache`** | **4.000.000** | **1.580.575** | **57,93%** | **5,88 ms** | **44,92%** | **41,49%** | **187.935.034** |
| `unbound_hw_cache` | 2.500.000 | 1.201.423 | 48,84% | 9,36 ms | 38,75% | 49,33% | 84.535.621 |
| `unbound_hw_cache` | 1.000.000 | 519.690 | 44,75% | 23,20 ms | 32,41% | 52,33% | 3.699.038 |
| `unbound_hw_cache` | 500.000 | 302.350 | 35,74% | 53,40 ms | 21,29% | 55,20% | 0 |
| **`unbound_standalone`**| **4.000.000** | **17** | **100,00%** | **12,92 ms** | **50,64%** | **0,00%** | **352.320.361** |
| `unbound_standalone` | 2.500.000 | 18 | 100,00% | 20,72 ms | 49,20% | 0,00% | 182.555.602 |
| `unbound_standalone` | 1.000.000 | 559 | 99,94% | 50,53 ms | 49,33% | 0,00% | 14.084.949 |
| `unbound_standalone` | 500.000 | 63.007 | 86,61% | 100,37 ms | 38,31% | 0,00% | 1.489.288 |

---

## 2. Decomposição de Atendimento por Camada (Tier Breakdown em 120s)

| Modo | Taxa Alvo (QPS) | L1 SRAM SmartNIC | L2 DRAM Host (XDP) | L3 Userspace (Unbound) | Queries Perdidas | Eficiência de Cache |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`ates_hw_cache`** | 4.000.000 | **228.235.044** (50,7%) | **221.514.858** (49,2%) | 44.674 (0,01%) | **697.840** (0,15%) | **99,85%** |
| `ates_hw_cache` | 2.500.000 | 137.792.071 (48,9%) | 143.883.139 (51,0%) | 37.997 (0,01%) | 186.416 (0,06%) | 99,94% |
| `ates_hw_cache` | 1.000.000 | 55.419.258 (49,1%) | 57.369.320 (50,8%) | 32.860 (0,03%) | 17.474 (0,01%) | 99,99% |
| `ates_hw_cache` | 500.000 | 27.241.918 (48,2%) | 29.175.785 (51,7%) | 27.099 (0,05%) | 17.790 (0,03%) | 99,97% |
| **`ates_driver`** | 4.000.000 | 0 (0,0%) | **449.361.402** (99,8%) | 74.046 (0,02%) | **934.549** (0,21%) | **99,79%** |
| `ates_driver` | 2.500.000 | 0 (0,0%) | 281.605.038 (99,9%) | 77.363 (0,03%) | 172.985 (0,06%) | 99,94% |
| `ates_driver` | 1.000.000 | 0 (0,0%) | 112.748.704 (99,9%) | 79.295 (0,07%) | 16.391 (0,01%) | 99,99% |
| `ates_driver` | 500.000 | 0 (0,0%) | 56.382.998 (99,8%) | 65.481 (0,12%) | 19.539 (0,03%) | 99,97% |
| **`unbound_hw_cache`**| 4.000.000 | 187.027.064 (41,5%) | 0 (0,0%) | 2.642.012 (0,6%) | **261.120.659** (57,9%)| **42,07%** |
| `unbound_hw_cache` | 2.500.000 | 139.010.792 (49,3%) | 0 (0,0%) | 5.160.084 (1,8%) | 137.633.309 (48,8%)| 51,16% |
| `unbound_hw_cache` | 1.000.000 | 59.075.643 (52,3%) | 0 (0,0%) | 3.287.257 (2,9%) | 50.506.015 (44,8%) | 55,25% |
| `unbound_hw_cache` | 500.000 | 31.195.173 (55,2%) | 0 (0,0%) | 5.086.778 (9,0%) | 20.181.000 (35,7%) | 64,26% |
| **`unbound_standalone`**| 4.000.000 | 0 (0,0%) | 0 (0,0%) | 2.084 (0,0%) | **451.701.161** (100,0%)| **0,00%** |
| `unbound_standalone` | 2.500.000 | 0 (0,0%) | 0 (0,0%) | 2.196 (0,0%) | 282.190.700 (100,0%)| 0,00% |
| `unbound_standalone` | 1.000.000 | 0 (0,0%) | 0 (0,0%) | 67.040 (0,1%) | 112.863.930 (99,9%) | 0,06% |
| `unbound_standalone` | 500.000 | 0 (0,0%) | 0 (0,0%) | 7.560.852 (13,4%) | 48.900.358 (86,6%) | 13,39% |

---

## 3. Principais Descobertas Científicas

### 1. Eliminação do Gargalo de DMA no PCIe Gen 2
- Com o slot operando a **5.0 GT/s x8 (32 Gbps)** e **4 filas de hardware ativas** mapeadas nos 2 cores do servidor, o descarte de anel DMA da SmartNIC (`nic_rx_discards`) caiu de centenas de milhões para **ZERO** nas taxas de 500k, 1M e 2.5M QPS.
- A 4M QPS, o descarte no `ates_hw_cache` foi de apenas **1.636 pacotes** em 450 milhões (descarte nulo na prática), comparado a **187 milhões de descartes** no `unbound_hw_cache`.

### 2. Eficiência de CPU: O Papel Vital da SmartNIC
- Tanto o `ates_hw_cache` quanto o `ates_driver` sustentam **3,75 Milhões de QPS** quase sem perdas ($0,15\%$ vs $0,21\%$).
- No entanto, a SmartNIC absorve **50,65% das queries diretamente em silício** ($\approx 228$ milhões de pacotes), aliviando o host.
- **Resultado na CPU:** O `ates_hw_cache` consome apenas **22,80% de CPU**, enquanto o `ates_driver` atinge **38,46% de CPU**. O offload em hardware proporciona uma **economia direta de 40,7% de ciclos de processador no Host**.

### 3. Por que o `unbound_hw_cache` Colapsa sob Expiração de TTL
- Sem a camada L2 em DRAM (Driver XDP), todas as expirações dinâmicas de TTL (que atingem $\sim 50\%$ do tráfego) desabam diretamente no socket UDP do Unbound.
- O socket do Unbound em user-space processa no máximo $\approx 60.000$ a $80.000$ QPS.
- O excesso transborda o buffer de recepção da placa de rede, gerando **187 milhões de descartes** e provocando **57,93% de perda de pacotes** a 4M QPS.

---

## 4. Gráficos Oficiais Gerados

Os gráficos vetoriais em alta resolução (300 DPI) foram gerados automaticamente a partir dos dados do sumário:
1. **Vazão e Perda de Pacotes:** [`fig_pcie2_throughput_loss.png`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/fig_pcie2_throughput_loss.png)
2. **Decomposição em Camadas (L1 vs L2 vs L3 vs Lost):** [`fig_pcie2_tier_breakdown.png`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/fig_pcie2_tier_breakdown.png)
3. **Descartes de DMA no PCIe e Uso de CPU:** [`fig_pcie2_pcie_discards_cpu.png`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/fig_pcie2_pcie_discards_cpu.png)

---

## 5. Arquivos de Dados

- **Dados Brutos (80 Execuções):** [`raw_official_pcie2_sweep.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/raw_official_pcie2_sweep.csv)
- **Sumário Agregado (Médias, Desvio Padrão e IC95):** [`summary_official_pcie2_sweep.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/summary_official_pcie2_sweep.csv)
- **Script de Plotagem:** [`generate_pcie2_sweep_plots.py`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/09_ttl30s_eviction_study/generate_pcie2_sweep_plots.py)
