# Diretório Oficial de Resultados e Análises (`official_results/`)

Este diretório centraliza **exclusivamente resultados empíricos reais**, scripts de extração, CSVs brutos e gráficos oficiais que serão inseridos em [`main.tex`](file:///home/joaosoares/Documents/Github/AtesN-DS/main.tex). Nenhum dado simulado ou não executado consta no artigo.

---

## Estrutura do Diretório

1. **[`01_trace_analysis/`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/01_trace_analysis/ANALYSIS.md)** — **[CONCLUÍDO / OFICIAL]**
   - Caracterização completa em formato de fio (RFC 1035 wire format) dos traces de ISP ($2.000.000$ consultas, $83.659$ domínios únicos) e Campus ($734.161$ consultas, $39.919$ domínios únicos).
   - CSVs: [`trace_summary_metrics.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/01_trace_analysis/trace_summary_metrics.csv), [`trace_wire_length_cdf.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/01_trace_analysis/trace_wire_length_cdf.csv).
   - Gráfico CDF: [`qname_length_cdf.png`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/01_trace_analysis/qname_length_cdf.png) e [`qname_length_cdf.pdf`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/01_trace_analysis/qname_length_cdf.pdf).

2. **`02_cleaner_daemon/`** — **[CONCLUÍDO / OFICIAL]**
   - Avaliação empírica do *Passive Evict-on-Write Daemon* e *Time Updater Daemon* ($n=30$, IC 95%), já presente na Seção 4.5 (`tab:control_plane_overhead`) de [`main.tex`](file:///home/joaosoares/Documents/Github/AtesN-DS/main.tex).

3. **`03_server_benchmarks/`** — **[PENDENTE — EXECUÇÃO CONJUNTA NO SERVIDOR]**
   - Armazenará os CSVs brutos e consolidados da campanha de testes físicos no servidor (`joaosoares@150.164.2.93`) e cliente (`soares@150.164.2.81`) comparando os 4 modos em 1 core ($n=30$ repetições por faixa de QPS até saturação unbounded).

---

## Matriz de Verificação de Métricas Solicitadas pelos Revisores

| Revisor & Comentário | Métrica Requisitada | Status Atual | Onde Está / Como Será Coletada |
| :--- | :--- | :---: | :--- |
| **R1 — Comment 2** | Máximo de Queries/s e Packets/s até saturação do host/NIC; utilização por núcleo (per-core CPU) da máquina cliente | **Pendente (Bateria no Servidor)** | Coletado via `dnsperf` + `mpstat -P ALL` no cliente e `ethtool -S` no servidor (`03_server_benchmarks/`) |
| **R1 — Comment 4** | Hit rate do cache do driver; contagem de misses e falhas; avaliação com RTT de upstream realista | **Pendente (Bateria no Servidor)** | Contadores de mapa/driver + `mock_dns_server` com RTT configurável (`03_server_benchmarks/`) |
| **R1 — Comment 5** | CDF do tamanho dos nomes em wire format; mix QTYPE; fração rejeitada em 24B vs 56B; latência SRAM vs DRAM; quebra dos misses (nome longo, cold miss, expiração TTL, tipo não suportado) | **CDF e Quebra Estrutural Concluídos** (`01_trace_analysis/`); **Misses Dinâmicos no Servidor Pendentes** | [`ANALYSIS.md`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/01_trace_analysis/ANALYSIS.md) + contadores em tempo de execução no servidor |
| **R1 — Comment 6** | Percentis de latência de cauda ($p_{50}, p_{75}, p_{90}, p_{99}, p_{99.9}$) e gráficos CDF de latência; drop counters da NIC/driver; separação de latência entre hit na NIC vs consulta no host | **Pendente (Bateria no Servidor)** | `dnsperf` / `sample_client_dnsperf.py` + `ethtool -S enp1s0np1` (`03_server_benchmarks/`) |
| **R1 — Comment 7** | Custo de CPU e taxa de acesso à memória (map-access rate / PCIe load) do Time Daemon e Cleaner Daemon | **Oficial e Concluído** | Seção 4.5 (`tab:control_plane_overhead`) em [`main.tex`](file:///home/joaosoares/Documents/Github/AtesN-DS/main.tex) |
| **R6 — Comment 4** | Distribuição de tamanho dos QNAMEs e porcentagem exata de queries que cabem na chave de hardware | **Oficial e Concluído** | [`01_trace_analysis/ANALYSIS.md`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/01_trace_analysis/ANALYSIS.md) ($97,90\%$ ISP $\le 56\text{ B}$; $98,90\%$ Campus $\le 56\text{ B}$) |
| **R6 — Comment 5** | Contagem direta de hits e misses extraída de dentro do programa offloaded na NIC | **Instrumentado / Pendente Execução** | Registradores de hardware `bpf_app2_pkts` (`XDP_TX` hits) e `bpf_pass_pkts` (`XDP_PASS` misses) via `ethtool -S` |
| **R6 — Comment 7 & 8** | Saúde do gerador de carga no cliente: erros, timeouts, códigos de resposta (RCODEs), requisições falhas e percentis | **Instrumentado / Pendente Execução** | Telemetria de cliente (`RcvbufErrors`, `SndbufErrors`, timeouts, RCODEs) em `03_server_benchmarks/` |
| **R3 — Comment 4** | Tail latency, packet loss, uso de recursos da NIC (instruções NFP, memória SRAM/DRAM), tráfego PCIe e contagem de interrupções (`/proc/interrupts`, SoftIRQ) | **Recursos da NIC e PCIe do Daemon Concluídos**; **Tail Latency, Loss e IRQs sob Carga Pendentes** | Seção 4.5 + coleta de `/proc/interrupts` e `mpstat -I SUM,SCPU` em `03_server_benchmarks/` |
