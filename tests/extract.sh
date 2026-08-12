#!/usr/bin/env bash
#
# extract.sh (extract_dns_domains.sh)
#
# Extrai nomes de domínio de consultas DNS do tipo A (dns.qry.type == 1)
# e classe IN (dns.qry.class == 1) de arquivos .pcap/.pcapng.
#
# Limpa e sanitiza os domínios (removendo http://, https://, caminhos /,
# parâmetros ?, portas, etc.) e gera automaticamente:
#   1. Arquivo original/completo (com repetições na ordem original das queries)
#   2. Arquivo deduplicado único (para a etapa de warmup)
#
# Requisitos:
#   - tshark (Wireshark)
#
# Uso:
#   ./extract.sh -i /caminho/pcaps -o dominios.txt -u unique.txt
#   ./extract.sh -o dominios.txt arquivo1.pcap arquivo2.pcap
#
# Opções:
#   -i DIR      Diretório contendo os arquivos .pcap/.pcapng (busca recursiva).
#   -o FILE     Arquivo de saída para a sequência completa (padrão: dominios.txt).
#   -u FILE     Arquivo de saída para os domínios únicos deduplicados (padrão: unique.txt).
#   -h          Mostra esta ajuda.

set -euo pipefail

INPUT_DIRS=()
INPUT_FILES=()
OUTPUT_FILE="dominios.txt"
UNIQUE_FILE="unique.txt"

usage() {
    grep '^#' "$0" | sed -e 's/^#//' -e 's/^ //'
    exit 1
}

while getopts ":i:o:u:h" opt; do
    case "$opt" in
        i) INPUT_DIRS+=("$OPTARG") ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        u) UNIQUE_FILE="$OPTARG" ;;
        h) usage ;;
        \?) echo "Opção inválida: -$OPTARG" >&2; usage ;;
        :) echo "A opção -$OPTARG requer um argumento." >&2; usage ;;
    esac
done
shift $((OPTIND - 1))

# Arquivos passados diretamente como argumentos posicionais
INPUT_FILES+=("$@")

if ! command -v tshark >/dev/null 2>&1; then
    echo "Erro: tshark não encontrado. Instale o Wireshark/tshark antes de continuar." >&2
    echo "  Ubuntu/Debian: sudo apt-get install tshark" >&2
    echo "  macOS (brew):  brew install wireshark" >&2
    exit 1
fi

# Monta a lista final de arquivos pcap a processar
ALL_PCAPS=()

for dir in "${INPUT_DIRS[@]:-}"; do
    [[ -z "$dir" ]] && continue
    if [[ ! -d "$dir" ]]; then
        echo "Aviso: diretório não encontrado, ignorando: $dir" >&2
        continue
    fi
    while IFS= read -r -d '' f; do
        ALL_PCAPS+=("$f")
    done < <(find "$dir" -type f \( -iname "*.pcap" -o -iname "*.pcapng" \) -print0)
done

for f in "${INPUT_FILES[@]:-}"; do
    [[ -z "$f" ]] && continue
    if [[ ! -f "$f" ]]; then
        echo "Aviso: arquivo não encontrado, ignorando: $f" >&2
        continue
    fi
    ALL_PCAPS+=("$f")
done

if [[ ${#ALL_PCAPS[@]} -eq 0 ]]; then
    echo "Erro: nenhum arquivo .pcap/.pcapng encontrado para processar." >&2
    exit 1
fi

echo "Encontrados ${#ALL_PCAPS[@]} arquivo(s) pcap para processar." >&2

# Arquivo temporário para acumular os domínios antes da limpeza final
TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT

COUNT=0
for pcap in "${ALL_PCAPS[@]}"; do
    COUNT=$((COUNT + 1))
    echo "[$COUNT/${#ALL_PCAPS[@]}] Extraindo e limpando: $pcap" >&2

    # Filtro e Sanitização:
    # 1. Extrai apenas queries DNS (tipo A, classe IN)
    # 2. Remove protocolos (http://, https://, etc)
    # 3. Remove caminhos (/...), query params (?...) e fragments (#...)
    # 4. Remove portas (:8080, :53, etc)
    # 5. Remove pontos no início e fim
    # 6. Converte para minúsculas
    # 7. Garante apenas caracteres válidos de hostname e remove linhas vazias
    tshark -r "$pcap" \
        -Y "dns.flags.response == 0 && dns.qry.type == 1 && dns.qry.class == 1" \
        -T fields -e dns.qry.name 2>/dev/null \
        | sed -E '
            s~^[a-zA-Z0-9+.-]+://~~;
            s~/.*~~;
            s~\?.*~~;
            s~#.*~~;
            s~:[0-9]+$~~;
            s~^\.+~~;
            s~\.+$~~;
            /^[a-zA-Z0-9_.-]+$/!d;
            /^\s*$/d
        ' \
        | tr '[:upper:]' '[:lower:]' \
        >> "$TMP_FILE" || echo "  Aviso: erro ao processar $pcap, pulando." >&2
done

# 1. Salva o arquivo original com a sequência completa de consultas (com repetições)
cp "$TMP_FILE" "$OUTPUT_FILE"

# 2. Salva o arquivo único deduplicado (para o warmup)
sort -u "$TMP_FILE" > "$UNIQUE_FILE"

TOTAL_ORIGINAL=$(wc -l < "$OUTPUT_FILE" | tr -d ' ')
TOTAL_UNIQUE=$(wc -l < "$UNIQUE_FILE" | tr -d ' ')

echo "==============================================" >&2
echo "✅ Extração e parsing concluídos com sucesso!" >&2
echo "  -> Arquivo completo (medição): $OUTPUT_FILE ($TOTAL_ORIGINAL queries)" >&2
echo "  -> Arquivo único (warmup):     $UNIQUE_FILE ($TOTAL_UNIQUE domínios únicos)" >&2
echo "==============================================" >&2
