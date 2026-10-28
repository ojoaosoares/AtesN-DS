# Scripts de Suporte e Automação de Bancada (`scripts/`)

Este diretório contém os scripts utilitários de pré-carga de cache, geradores de tráfego com jitter e parsers estatísticos utilizados pelas suítes experimentais do artigo ([`main.tex`](file:///home/joaosoares/Documents/Github/AtesN-DS/main.tex)).

---

## 🔀 Mapeamento por Suíte Experimental

### Suíte 1: Churn Dinâmico e TTL Variável (`suite1_variable_ttl`)

1. **[`preload_30s_ttl.sh`](file:///home/joaosoares/Documents/Github/AtesN-DS/scripts/preload_30s_ttl.sh)**
   - Pré-carrega o cache de hardware e driver com TTLs dinâmicos baseados no mapa empírico de TTL da Tabela 1 do artigo.
   - Utilizado pelos runners da Suite 1 para inicializar o estado de churn contínuo.
2. **[`generate_warmup_jitter.py`](file:///home/joaosoares/Documents/Github/AtesN-DS/scripts/generate_warmup_jitter.py)**
   - Gera trace de warm-up aplicando jitter estocástico de TTLs para evitar sincronização artificial de expirações de cache (*thundering herd*).
3. **[`parse_latencies.py`](file:///home/joaosoares/Documents/Github/AtesN-DS/scripts/parse_latencies.py)**
   - Extrai e formata percentis de latência ($p_{50}, p_{90}, p_{99}, p_{99.9}$) a partir dos logs de execução da varredura PCIe Gen 2.
4. **[`parse_summary_pcie2.py`](file:///home/joaosoares/Documents/Github/AtesN-DS/scripts/parse_summary_pcie2.py)**
   - Processa saídas de telemetria da NIC (`ethtool -S`) e gera métricas consolidadas de descartes de DMA no PCIe (`nic_rx_discards`).

---

### Suíte 2: Capacidade Máxima e TTL Estático (`suite2_static_ttl`)

1. **[`preload_all.sh`](file:///home/joaosoares/Documents/Github/AtesN-DS/scripts/preload_all.sh)**
   - Script orquestrador que dispara a pré-carga de todas as camadas com TTL estático de $3.600\,\text{s}$ (SmartNIC e Host).
2. **[`preload_hw.sh`](file:///home/joaosoares/Documents/Github/AtesN-DS/scripts/preload_hw.sh)**
   - Injeta as $32.768$ entradas mais frequentes do trace diretamente no mapa de SRAM/DRAM da SmartNIC via `bin/preload_cache`.
3. **[`preload_driver.sh`](file:///home/joaosoares/Documents/Github/AtesN-DS/scripts/preload_driver.sh)**
   - Popula a tabela BPF `cache_arecords` do driver XDP no host com as $83.659$ entradas do trace.
4. **[`preload_unbound.sh`](file:///home/joaosoares/Documents/Github/AtesN-DS/scripts/preload_unbound.sh)**
   - Carrega o cache local do Unbound em user-space via `unbound-control load_cache`.
