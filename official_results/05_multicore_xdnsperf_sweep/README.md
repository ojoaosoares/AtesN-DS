# 05 — Multi-Core Server Saturation Benchmark (xdnsperf)

Este experimento avalia a escalabilidade multi-core e a saturação real de CPU do servidor DNS sob taxas extremas de injeção geradas pelo **xdnsperf** (eBPF + AF_XDP).

## Motivação

Nos testes anteriores com `dnsperf`, o cliente atingia 100% de saturação de CPU em ~960k QPS, impedindo observar a verdadeira capacidade máxima do servidor nos modos de alta performance (`ates_hw_cache` deixava a CPU do servidor em apenas ~30% de uso).

Com o **xdnsperf**, o cliente atinge **2.43M+ QPS** em line-rate com menos de 7% de CPU cliente. Isso possibilita:
1. Saturar a capacidade real de 1, 2 e 4 cores do servidor.
2. Medir o ganho de vazão ao escalar as filas de hardware e threads do Unbound/AtesN-DS.
3. Provar empiricamente até onde o hardware SmartNIC desonera a CPU do host sob cargas de múltiplos milhões de QPS.

## Matriz Experimental

* **Cores de Servidor**: 1 Core (`Core 0`), 2 Cores (`Cores 0, 1`), 4 Cores (`Cores 0, 1, 2, 3`)
* **Filas de Hardware (Netronome NFP-4000)**: Sincronizadas simetricamente (1 fila/core com afinidade IRQ 1:1)
* **Modos Arquiteturais**:
  1. `unbound_standalone`: Unbound multi-thread no espaço de usuário
  2. `ates_driver`: Driver XDP AtesN-DS com fallback para Unbound
  3. `unbound_hw_cache`: SmartNIC HW Cache + Decoupled DNS Listener + Unbound
  4. `ates_hw_cache`: SmartNIC HW Cache + AtesN-DS Driver + Unbound
* **Taxas Alvo (QPS)**: 200k, 500k, 1M, 1.5M, 2M, UNLIMITED (Linha máxima de 10GbE)
* **Repetições**: 3 por nível de QPS (30s cada)
* **Trace**: Produção ISP DNS Trace (Žiža et al., 2023) com Top 32.768 domínios pré-aquecidos na SRAM da SmartNIC

## Como Executar

```bash
# Executar a bateria completa (1, 2 e 4 cores, todos os 4 modos)
./official_results/05_multicore_xdnsperf_sweep/run_multicore_xdnsperf_sweep.sh

# Executar apenas para 2 cores
./official_results/05_multicore_xdnsperf_sweep/run_multicore_xdnsperf_sweep.sh 2

# Executar apenas para 4 cores no modo ates_hw_cache
./official_results/05_multicore_xdnsperf_sweep/run_multicore_xdnsperf_sweep.sh 4 ates_hw_cache
```

## Geração dos Gráficos

```bash
python3 official_results/05_multicore_xdnsperf_sweep/plot_multicore_xdnsperf.py
```
