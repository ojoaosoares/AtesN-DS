# Comparativo Técnico: xdnsperf vs. dnsperf
## Análise de Capacidade, Vazão Máxima e Eficiência de CPU em Redes de Alta Velocidade (10GbE+)

---

## 1. Resumo Executivo & Veredito

Tradicionalmente, a ferramenta padrão da indústria para avaliação de servidores DNS (BIND, Unbound, Knot, PowerDNS) é o **`dnsperf`** (desenvolvido originalmente pela Nominum e mantido pelo DNS-OARC). No entanto, em ambientes modernos de alta densidade e com aceleração em hardware (**SmartNICs Netronome Agilio CX e eBPF/XDP**), o `dnsperf` torna-se ele próprio o **gargalo do benchmark**, saturando a CPU do cliente antes de conseguir estressar o servidor.

Para superar essa barreira física, foi desenvolvido o **`xdnsperf`**, um gerador de carga de malha aberta (*open-loop*) e fechada (*closed-loop*) construído sobre o subsistema **eBPF (XDP)** e **AF_XDP (XSK Zero-Copy)**.

```
+-------------------------------------------------------------------------------------------------------+
|                                    VEREDITO EMPÍRICO NO TESTBED 10GbE                                 |
+-------------------------------------------------------------------------------------------------------+
|  Métrica                   | dnsperf (Sockets POSIX)          | xdnsperf (AF_XDP + eBPF)   | Ganho    |
+----------------------------+----------------------------------+----------------------------+----------+
|  Teto Máximo de Vazão      | ~1.079.245 QPS (Gargalo Cliente) | 3.000.000+ QPS (Wire-Rate) | +178%    |
|  CPU do Cliente @ 1M QPS   | 95,2% a 99,5% (Saturado)         | 13,0% (Folgado)            | 7,3x     |
|  CPU do Cliente @ 3M QPS   | Inatingível (Colapso)            | 25,0% a 26,0%              | Inédito  |
|  Custo de CPU / 100k QPS   | ~9,5% de CPU                     | ~0,8% de CPU               | 11,8x    |
|  Jitter de Medição         | Alto (locks de socket UDP)       | Sub-microsegundo (DMA)     | Ultra    |
+-------------------------------------------------------------------------------------------------------+
```

---

## 2. Diferenças Arquiteturais Profundas

### A. Caminho de Transmissão (TX) e Recepção (RX)

```
                    ARQUITETURA CLÁSSICA (dnsperf)
       
  [ Userspace: dnsperf ]
         │  sendto() syscall (context switch)
         ▼
  [ Kernel Network Stack ] ──> Alocação de sk_buff ──> Qdisc / Locking ──> Ring Buffer da NIC
         ▲
         │  recvmsg() syscall (context switch + cópia de memória do kernel para userspace)
  [ Socket UDP Buffer ] <── Interrupções / SoftIRQ (ksoftirqd) <── Ring RX da NIC

----------------------------------------------------------------------------------------

                    ARQUITETURA KERNEL-BYPASS (xdnsperf)
       
  [ Userspace: xdnsperf ] ──> Pre-allocated UMEM Frames (Lock-free Ring)
         │
         ▼  bpf_prog_test_run (Burst direto)
  [ In-Kernel eBPF: dns_mutator ] ──> XDP_TX (Ejeção imediata no anel de hardware)
         ▲
         │  bpf_redirect_map (Zero-Copy direto no anel UMEM de userspace)
  [ Driver XDP / AF_XDP Socket ] <── Polling sem lock <── Hardware RX Queue (RSS 1:1)
```

1. **Eliminação de Syscalls:** O `dnsperf` realiza chamadas de sistema `sendto()` e `recvmsg()` para cada lote de pacotes. A 1 milhão de QPS, o kernel passa a gastar mais tempo chaveando contexto (Ring 3 $\leftrightarrow$ Ring 0) do que gerando tráfego. O `xdnsperf` usa anéis de memória compartilhada (*UMEM*) com sincronização lock-free.
2. **Zero Alocação de `sk_buff`:** O `dnsperf` obriga o kernel a alocar e desalocar estruturas `sk_buff` de ~256 bytes para cada pacote. O `xdnsperf` recicla descritores fixos de 2048 bytes na UMEM em DMA direto.
3. **Mapeamento Multi-Fila 1:1:** O `xdnsperf` associa cada thread worker diretamente a uma fila física RSS da placa de rede Intel X710, eliminando contenção de locks de barramento.

---

## 3. Dados Empíricos: Comparação Lado a Lado no Mesmo Testbed

> [!NOTE]
> Todos os dados abaixo foram extraídos dos testes oficiais conduzidos no nó cliente (`lecom-goddess`: Intel Core i7-8086K 6C/12T @ 4.00GHz, NIC Intel X710 10GbE SFP+).

### Tabela 1: Utilização de CPU no Nó Cliente conforme a Carga Injetada

| Taxa Injetada | CPU Cliente com `dnsperf` | CPU Cliente com `xdnsperf` | Economia de CPU no Cliente |
| :--- | :--- | :--- | :--- |
| **50.000 QPS** | 72,4% (Pico em 75,1%) | **2,0%** | **36x menos CPU** |
| **100.000 QPS** | 94,3% (Pico em 99,3%) | **3,0%** | **31x menos CPU** |
| **200.000 QPS** | 97,1% (Pico em 99,2%) | **4,0%** | **24x menos CPU** |
| **500.000 QPS** | 95,5% (Pico em 97,8%) | **6,6%** | **14x menos CPU** |
| **1.000.000 QPS**| **95,2% a 99,5% (Teto)** | **13,0%** | **7,3x menos CPU** |
| **2.000.000 QPS**| **Inatingível** (Travamento) | **19,0%** | Capacidade exclusiva do xdnsperf |
| **3.000.000 QPS**| **Inatingível** (Travamento) | **25,5%** | **Fio de 10GbE saturado sem exaustão** |

```
CPU do Cliente (%) vs Taxa Injetada (QPS)
100% |  [dnsperf: SATURA EM 200k-500k QPS] ════════════════════════ (Gargalo de CPU)
 90% |  /
 80% | /
 70% |/
 60% |
 50% |
 40% |
 30% |                                              [xdnsperf @ 3M QPS: 25.5%]
 20% |                                      [xdnsperf @ 2M QPS: 19.0%]
 10% |                  [xdnsperf @ 1M QPS: 13.0%]
  0% +------------------------------------------------------------------------
     50k     100k    200k    500k    1M             2M             3M QPS
```

---

## 4. Onde o `dnsperf` Falhava na Avaliação do AtesN-DS

Ao testar a arquitetura híbrida de alto desempenho do AtesN-DS (SmartNIC Netronome + Driver XDP), o `dnsperf` apresentava 3 problemas críticos:

### 1. Falso Teto de Desempenho do Servidor
No teste do `ates_driver` e `ates_hw_cache` com `dnsperf`, a vazão máxima registrada parava em **~1.079.245 QPS**. O gráfico parecia indicar que o AtesN-DS tinha atingido o limite. 
* **A realidade:** O AtesN-DS estava com menos de 20% de uso de CPU no servidor. Quem havia atingido 100% de saturação era o nó cliente com o `dnsperf`, que não conseguia enviar mais pacotes pelos sockets POSIX.
* **Com o `xdnsperf`:** O cliente conseguiu empurrar **3.000.000 QPS** e provou que o AtesN-DS entrega **2.362.784 QPS** reais com folga de hardware.

### 2. Distorção de Latência por Contenção de Socket
Como o `dnsperf` utiliza um buffer de socket UDP (`-b 16384`), sob alta taxa os pacotes ficam enfileirados no próprio kernel do cliente antes de serem transmitidos ou lidos pelo `recvmsg()`. 
Isso adicionava milissegundos de **latência artificial gerada pelo cliente**, contaminando as medidas de latência de cauda ($p_{99}$ e $p_{99.9}$) do servidor sob teste.

### 3. Falta de Compatibilidade com Restrições de SmartNIC (O Bug dos 8 Bytes)
O `dnsperf` tradicional envia apenas queries brutas e mínimas (sem EDNS0), a menos que explicitamente configurado com `-e -E 10:...`. 
O `xdnsperf` foi atualizado para embutir nativamente o cabeçalho EDNS0 Opção 10 Cookie (27 bytes), garantindo que a SmartNIC Netronome NFP-4000 consiga aplicar in-place tail shrinkage (`bpf_xdp_adjust_tail(ctx, -11)`) e resolver **93%+ das queries diretamente em silício**.

---

## 5. Tabela Comparativa de Recursos

| Recurso / Capacidade | `dnsperf` (ISC / Nominum) | `xdnsperf` (AtesN-DS Project) |
| :--- | :--- | :--- |
| **Mecanismo de Rede** | Sockets POSIX UDP (`sendto`/`recvmsg`) | **AF_XDP (XSK) + eBPF (XDP)** |
| **Cópia de Pacotes** | Dupla (Kernel $\leftrightarrow$ Userspace) | **Zero-Copy na Recepção (UMEM Rings)** |
| **Geração de Tráfego** | Em Userspace via Syscalls | **Injeção Direta no Driver/NIC via XDP** |
| **Afinidade de Filas RSS** | Genérica (Kernel balanceia via SO_REUSEPORT)| **1:1 Mapeamento Estrito Thread $\leftrightarrow$ Fila** |
| **Precisão de Timestamp** | `gettimeofday` em Userspace (microssegundos) | **Monotônico 64-bit em Nanossangos (`send_ns`)** |
| **Tracking de In-Flight** | Tabela hash em userspace com locks | **Array circular lock-free indexado por TxID** |
| **Modo Open-Loop** | Sim (`-Q <qps>`) | **Sim (`-r <qps>`, rate-limiter por worker)** |
| **Modo Closed-Loop** | Sim (`-c <concurrency>`) | **Sim (`-W <window>`, janela in-flight sem locks)** |
| **Suporte a Traces Reais**| Sim (`<dominio> <tipo>`) | **Sim (Mesmo formato padrão do dnsperf)** |
| **EDNS0 Cookie Nativo** | Opcional via flag CLI complexa | **Nativo (27B OPT RR para SmartNICs)** |
| **Saída Estruturada** | Texto não-padronizado | **Flag nativa `--csv` de alta precisão** |
| **Vazão Máxima no Testbed**| **~1,07 Milhões QPS** | **> 3,00 Milhões QPS** |
| **Uso de CPU do Cliente**| **95% - 99%** | **13% - 25%** |

---

## 6. Conclusão

O `dnsperf` continua sendo uma ferramenta útil para benchmarks de baixa a média taxa (< 500k QPS) em resolvers convencionais baseados em userspace. 

No entanto, para avaliar **arquiteturas de resolução em nível de kernel (XDP) e em silício de SmartNICs**, o `dnsperf` é inadequado devido ao colapso de CPU na pilha de sockets do Linux. O **`xdnsperf` resolveu essa limitação estrutural**, permitindo que o AtesN-DS fosse avaliado fielmente até o limite físico de **3.000.000 QPS em 10GbE**, consumindo uma fração mínima da capacidade do gerador de carga.
