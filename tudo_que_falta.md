# Checklist Oficial: Tudo Que Falta para o Artigo e Rebuttal

---

## 1. Modificações no Artigo (`main.tex`)

- [x] **Descrição da Recursão no Testbed Isolado (Seção 4, Linha 418):**
  - Explicado detalhadamente o papel do `mock_dns_server` (`192.168.0.2:53`) rodando na CPU 11 do cliente como autoritativo upstream.
  - Documentado o caminho do miss (`XDP_PASS` $\rightarrow$ Unbound $\rightarrow$ recursão upstream em 10GbE $\rightarrow$ `dns_listener` $\rightarrow$ PCIe DMA na SmartNIC).
  - Incluída a menção à emulação de RTT de WAN via `tc netem delay`.
- [x] **Descrição do Protocolo de Teste de 3 Minutos / 180 Segundos (Seção 4, Linhas 471 e 528):**
  - Documentada a geração de carga de malha aberta via `xdnsperf` com AF_XDP em 4 filas RSS.
  - Janela de teste de 3 minutos (180 segundos) por patamar de taxa para permitir múltiplos ciclos de expiração de TTL (18 ciclos para 10s e 3 ciclos para 60s).
  - Protocolo em 2 fases: (1) Warmup calibrado no Top 32k domínios SRAM, seguido de (2) replay sustentado do trace de 2M queries com transição dinâmica e misses reais.
- [x] **Caracterização do Trace ISP e Chave de 56 Bytes (Seção 4.1, Linhas 424–463):**
  - Trace ISP Mendeley 2M queries, 83.659 nomes únicos, 100% Type A.
  - CDF em wire format (Tabela 1 e Figura 3).
  - Comparação 24B (38.48% rejeitado) vs 56B (2.10% rejeitado, 97.90% elegível).
  - Decomposição dos misses: long-names (2.10%), cold misses (1.2%–2.1%), TTL expiries (0.5%–1.1%), unsupported (0.0%).
  - Alocação SRAM (32k entradas, 2.35 MB, 40 ns) vs DRAM (2M entradas, 128 MB, 250 ns).
- [x] **Racional e Comparação com hyDNS (Seção 2, Linha 277):**
  - Corrigido: hyDNS suporta recursão em kernel/eBPF, mas perde em funcionalidade (sem aprendizado natural de zonas `ns_cache`, sem prefetch de domínios prestes a expirar, sem tolerância a perda UDP com fanout multi-servidor e sem offload em SmartNIC).
- [x] **Categorização de Baselines e Paradigmas (Seção 4, Linhas 458–466):**
  - Mapeadas explicitamente as 4 classes de baselines exigidas pelo Revisor 1: (1) Resolvers Userspace Mainstream (Unbound / Knot / BIND), (2) In-Kernel / XDP (AtesN-DS Driver / hyDNS), (3) Kernel-Bypass / DPDK (Namestorm / ANS / FDNS), e (4) Caches In-Network / In-NIC de Alta Performance (NetCache / P4DNS / Emu DNS / BMC / Santa via Tabela 1).
- [x] **Tabela com Decomposição de Hits, Misses e Perdas (Seção 4.3, Linha 478):**
  - Inserida a Tabela 2 (`tab:realtrace_benchmark_results`) com os dados oficiais do trace real de 2M em 4 filas RSS (2 núcleos):
    * **Taxas Avaliadas:** 200k, 500k, 1M, 2M, 3M, 4M, 5M QPS.
    * **Vazão Atingida:** Médias e desvios para os 4 modos (Unbound Standalone, Ates Driver, Unbound HW Cache, Ates HW Cache).
    * **Hits/Misses:** HW Hit Rate de até 99.25% no trace real; isolamento de misses upstream.
    * **Perda e Latência de Cauda:** Percentis P99 e P99.9 milissegundo a milissegundo.
    * **CPU:** Queda de 29x na CPU do host (de 72.6% para 2.5% em 1M QPS).
- [x] **Métricas Multidimensionais e Casos Realistas de DNS (Seção 4, Linhas 465–472 e Seção 3.4):**
  - Adicionado parágrafo formal cobrindo:
    * Percentis de cauda ($p_{50}, p_{90}, p_{99}, p_{99.9}$) e $40\,\text{ns}$ RTT em silício.
    * Perda de pacotes e contadores de descarte de hardware (`nic_rx_discards = 0`, `nic_tx_discards = 0`).
    * Utilização de recursos da SmartNIC (589 instruções nativas / 38.3% do budget; 32.768 entradas / ~2.35 MB SRAM CLS/IMEM; zero register spills).
    * Desafogamento de barramento PCIe e interrupções do host (queda de 29x em SoftIRQ: de 72.6% para 2.5%; sync de relógio a 24 B/s).
    * Cobertura sistemática dos 9 casos realistas de DNS (nomes longos $>56\,\text{B}$, AAAA, CNAME, DNSSEC, EDNS0 $>512\,\text{B}$, TCP fallback, respostas grandes, negative caching e proteção 3-tuple contra envenenamento).
- [x] **Figuras de Publicação Atualizadas (Seção 4.3):**
  - Inseridas as figuras de alta resolução copiadas para `results/`:
    * `results/realtrace_2core_throughput_bars.png` (Vazão)
    * `results/realtrace_2core_tail_latency.png` (Latência P99/P99.9)
    * `results/realtrace_2core_cpu_saturation.png` (Curva de CPU por Core)

---

## 2. Infraestrutura e Código de Teste

- [x] **Correção do `xdnsperf`:**
  - Adicionado suporte a Cookie EDNS0 Opção 10 (`10:11223344556677889900aabb`), eliminando a restrição de expansão de buffer no NFP-4000.
- [x] **Instalação dos TTLs no `mock_dns_server`:**
  - Implementada distribuição determinística por hash FNV-1a (10% 10s, 20% 60s, 45% 300s, 15% 1800s, 10% 86400s).
  - Compilado no cliente e ativo na porta 53 (`192.168.0.2:53`).
- [x] **Aumento das Filas na SmartNIC:**
  - Configuradas 4 filas combinadas na placa Netronome, balanceadas entre os 2 núcleos do servidor (`q0/q2 -> c0`, `q1/q3 -> c1`).
- [x] **Separação de Warmup e Trace Real no Script de Teste:**
  - `WARMUP_TRACE`: `tests/isp_top32k_hw_warmup_dnsperf.txt` (Phase 1: Top 32k domínios na SRAM a 3k QPS; Phase 2: 83k únicos no Host).
  - `BENCH_TRACE`: `tests/isp_queries_2m_dnsperf.txt` (trace real de 2M com 73k misses reais).
  - Duração: 180 segundos (3 minutos) por repetição implementado em `run_2core_realtrace_2reps.sh` e `tests/test.sh`.
- [x] **Bateria Rápida Preliminar ($n=2$):**
  - Executada com sucesso em `official_results/06_multicore_xdnsperf_calibrated/run_2core_realtrace_2reps.sh`.
  - Dados consolidados em `summary_2core_realtrace_2reps.csv` e gráficos gerados.
- [ ] **Bateria Oficial Estatística ($n=30$):**
  - Opcional/futuro: Executar a bateria final de 30 repetições para intervalos de confiança de 95% mais estreitos caso necessário.

---

## 3. Carta de Resposta aos Revisores (`REVIEWER_RESPONSE.md`)

- [x] **Resposta ao Major Comment (2) — Baselines Ampliados (Seção 5):**
  - Mapeadas formalmente as 4 classes: Mainstream Userspace (Unbound standalone & acelerado), In-Kernel/XDP (AtesN-DS driver & justificativa do hyDNS), DPDK/Bypass (trade-offs arquiteturais: PMD 100% busy-poll, DMA PCIe, corte de kernel stack vs offload in-silicon com fallback `XDP_PASS`), e Caches de Alta Performance In-Network/In-NIC (Tabela 1).
- [x] Justificativa da exclusão de re-teste do hyDNS corrigida (Seção 5.2): hyDNS tem recursão, mas perde em funcionalidade (sem `ns_cache`, sem prefetch, sem redundância contra perda UDP e sem offload em SmartNIC).
- [x] Justificativa da escolha do Unbound sobre BIND/Knot/PowerDNS (já escrita na Seção 5.1).
- [x] **Resposta ao Major Comment (4) — Métricas Abrangentes e Semântica de Protocolo DNS Realista (Seção 6):**
  - Resposta formal estruturada em:
    * **Parte I (Métricas além de Médias):** Latência de cauda ($p_{50}, p_{90}, p_{99}, p_{99.9}$ e 40 ns RTT em silício), perdas e descartes de NIC (`nic_rx_discards = 0`), recursos de SmartNIC (589 instruções / 38.3% budget, 32.768 entradas / ~2.35 MB SRAM), economia PCIe / interrupções (SoftIRQ de 72.6% para 2.5%, clock sync 24 B/s).
    * **Parte II (9 Casos Realistas de DNS):** Nomes longos $>56$B, AAAA, CNAME, DNSSEC, EDNS0 $>512$B, TCP fallback, respostas grandes, negative caching, e proteção anti-envenenamento por validação 3-tuple (TXID, porta efêmera, QNAME) no `dns_listener`.
- [x] Resposta ao Comentário (5): Caracterização do trace ISP, 56B vs 24B, decomposição de misses, SRAM vs DRAM (Seção 7.1).
- [x] Resposta ao Comentário de Testbed e Caminho de Miss do Revisor 2 (Seção 7.2).
- [x] Resposta ao Comentário 3 do Revisor 3: Traces longos, janelas múltiplas, corridas de 3 minutos (180s) sustentadas e conclusões gerais (Seção 7.3).
- [x] Resposta ao Comentário (6): Percentis de latência ($p_{50}, p_{90}, p_{99}, p_{99.9}$), contadores de descarte, análise da inversão de concorrência e latência desagregada HW vs Host (Seção 7.4).
- [x] Resposta ao Comentário (7): Generalidade e portabilidade (BlueField, hXDP, P4), custo do plano de controle (0.053% CPU), eliminação de cleaner scans via Timing Wheel e saturação de cache (Seção 7.5 e Seção 3.5 no artigo).
- [x] Resposta ao Comentário de Tamanho de Nomes, CDN e Sensibilidade da Chave ($24\,\text{B} \to 56\,\text{B}$): Análise empírica do trace ISP real com rejeições exatas e impacto direto no hit rate (Seção 7.6).
- [x] Resposta ao Comentário de Platô em 101.8k QPS, CPU Baixa (3.2%) e Gargalo do Gerador Go: Diagnóstico experimental comprovando gargalo no cliente e transição para open-loop com `xdnsperf` AF_XDP (Seção 7.7).
- [x] **Resposta ao Comentário de Consistência com Repositório Público (Seção 7.8):** Verificação completa e reconciliação de tamanhos de mapas (32k SRAM, 2M DRAM, 56B key, ring buffers 8MB/4MB), intervalos de daemons (1 Hz clock, eviction sob demanda), presença de todos os componentes (`mock_dns_server`, `dns_listener`, `timing_wheel`) e passagem de 100% dos testes unitários (`make test`).
- [x] Tabela final de métricas dissecadas e sweep completo de open-loop 200k a 5M QPS em 2 núcleos (Seção 8.24).
- [x] **Polimento de Escrita, Apresentação e Rigor Editorial (Seção 9 em `REVIEWER_RESPONSE.md` e Revisão Global em `main.tex`):**
  - Eliminação de números de micro-benchmark redundantes no Abstract, Intro e Conclusão.
  - Moderação de afirmações enfáticas/hiperbólicas ("catastrophic collapse", "complete non-interference", "fundamentally supersedes", "physically impossible", etc.).
  - Correção de bugs de baixo nível: remoção de menções redundantes ao "Figure 2", eliminação do erro gramatical ("with an 2,000,000-entry"), correção de frases incompletas e notas de desenvolvimento (`%%%`, `TODO`).
  - Padronização de formatação `\texttt{...}` para mapas e daemons.
  - Correção de referências RFC no `cas-refs.bib` (RFC 1034, RFC 1035, RFC 6891 com autores) e substituição de todas as citações em parênteses duplos `~(\cite{...})` por `~\citep{...}` e `\citet{...}` via natbib.

