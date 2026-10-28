# 01 — Workload & Trace Characterization (Production ISP Trace)

## 1. Dataset Overview
- **Production ISP DNS Trace** ([`tests/isp_queries_2m.txt`](file:///home/joaosoares/Documents/Github/AtesN-DS/tests/isp_queries_2m.txt)):
  - **Source**: Žiža, K., Tadić, P., & Vuletić, P. (2023), *"DNS Exfiltration Dataset"*, Mendeley Data, V3, DOI: `10.17632/c4n7fckkz3.3` (`\cite{11314363}`).
  - **Collection Environment**: Recorded directly on an active production ISP DNS server in a realistic network environment (over 50M raw DNS queries, anonymized via injective IP mapping).
  - **Replayed Window**: $N = 2{,}000{,}000$ continuous queries spanning $U = 83{,}659$ unique domain names (`100%` IPv4 `A`/`IN` queries in benchmark replay).

---

## 2. RFC 1035 Wire-Format Length Distribution & 56-Byte Hardware Key Coverage
In RFC 1035 wire format, a domain name (`QNAME`) consists of length-prefixed labels terminated by a null root byte (`0x00`), meaning $\text{Wire Length} = \text{len}(\text{FQDN}) + 2\text{ bytes}$.

| Metric (RFC 1035 Wire Format) | All Replayed Queries ($N = 2{,}000{,}000$) | Unique Domain Names ($U = 83{,}659$) |
| :--- | :---: | :---: |
| **Dataset / Scope** | Full Chronological Stream | Deduplicated Working Set |
| **Replayed QTYPE / QCLASS Mix** | $100\%$ `A` / `IN` | $100\%$ `A` / `IN` |
| **Min / Max Wire Length** | $9\text{ B}$ / $219\text{ B}$ | $9\text{ B}$ / $219\text{ B}$ |
| **Mean $\pm$ SD Wire Length** | $24.81 \pm 11.42\text{ B}$ | $39.07 \pm 16.97\text{ B}$ |
| **$p_{10}$ / $p_{25}$ / $p_{50}$ (Median)** | $16.0\text{ B}$ / $19.0\text{ B}$ / $21.0\text{ B}$ | $21.0\text{ B}$ / $27.0\text{ B}$ / $32.0\text{ B}$ |
| **$p_{75}$ / $p_{90}$ / $p_{95}$** | $29.0\text{ B}$ / $35.0\text{ B}$ / $41.0\text{ B}$ | $56.0\text{ B}$ / $66.0\text{ B}$ / $66.0\text{ B}$ |
| **$p_{99}$ / $p_{99.9}$** | $66.0\text{ B}$ / $74.0\text{ B}$ | $74.0\text{ B}$ / $84.0\text{ B}$ |
| **Hardware Key Coverage ($\le 56\text{ B}$)** | **$1{,}958{,}022$ ($97.90\%$)** | **$63{,}747$ ($76.20\%$)** |
| **Long-Name Host Fallback ($> 56\text{ B}$)** | **$41{,}978$ ($2.10\%$)** | **$19{,}912$ ($23.80\%$)** |
| *Legacy 24B Key Coverage ($\le 24\text{ B}$, for Reviewer Response only)* | *$1{,}230{,}398$ ($61.52\%$)* | *$11{,}915$ ($14.24\%$)* |
| *Legacy 24B Key Rejected ($> 24\text{ B}$, for Reviewer Response only)* | *$769{,}602$ ($38.48\%$)* | *$71{,}744$ ($85.76\%$)* |

> [!IMPORTANT]
> **Key Takeaway**: Expanding the SmartNIC hardware key to **56 bytes (`char[56]`)** (paired with an 8-byte value to form a single cacheline-aligned 64-byte entry) captures **$97.90\%$ of all production ISP queries**, leaving only **$2.10\%$** to fall back to the host due to name length.

---

## 3. Zipfian Popularity Skew & On-Chip SRAM Capacity ($32{,}768$ Entries)
| Top-$K$ Most Frequent Domains | Query Volume ($N = 2{,}000{,}000$) | Share of Total ISP Traffic | Share of Working Set ($U = 83{,}659$) |
| :--- | :---: | :---: | :---: |
| **Top 10 Domains** | $547{,}184$ | $27.36\%$ | $0.01\%$ |
| **Top 100 Domains** | $956{,}857$ | $47.84\%$ | $0.12\%$ |
| **Top 1,000 Domains** | $1{,}502{,}578$ | $75.13\%$ | $1.20\%$ |
| **Top 5,000 Domains** | $1{,}788{,}849$ | $89.44\%$ | $5.98\%$ |
| **Top 10,000 Domains** | $1{,}863{,}957$ | $93.20\%$ | $11.95\%$ |
| **Top 32,768 Domains (L1 On-Chip SRAM)** | **$1{,}945{,}796$** | **$97.29\%$** | **$39.17\%$** |

---

## 4. Generated Artifacts in This Directory
- [`analyze_trace.py`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/01_trace_analysis/analyze_trace.py): Reproducible analysis and plotting script.
- [`trace_summary_metrics.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/01_trace_analysis/trace_summary_metrics.csv): Summary table of all statistical metrics.
- [`trace_wire_length_cdf.csv`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/01_trace_analysis/trace_wire_length_cdf.csv): Byte-by-byte empirical CDF from $1\text{ B}$ to $219\text{ B}$.
- [`qname_length_cdf.png`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/01_trace_analysis/qname_length_cdf.png) & [`qname_length_cdf.pdf`](file:///home/joaosoares/Documents/Github/AtesN-DS/official_results/01_trace_analysis/qname_length_cdf.pdf): Publication-ready CDF figure (also synced to [`results/qname_length_cdf.png`](file:///home/joaosoares/Documents/Github/AtesN-DS/results/qname_length_cdf.png)).
