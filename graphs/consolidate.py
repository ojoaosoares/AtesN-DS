#!/usr/bin/env python3
import argparse
import pandas as pd
import glob
import os
import sys
import re


def enrich_server_files_with_hit_rate(client_dir, server_dir, mode, concurrency):
    """
    Reads pairs of client and server output CSVs for each run,
    calculates cache_hits and cache_hit_rate using totalRequests from client
    and cache_misses from server, and appends these metrics to the server CSVs.
    """
    server_pattern = os.path.join(server_dir, f"server_output_{mode}_{concurrency}_run*.csv")
    server_files = glob.glob(server_pattern)

    for s_file in server_files:
        m = re.search(r"_run(\d+)\.csv$", s_file)
        if not m:
            continue
        run_num = m.group(1)

        c_file = os.path.join(client_dir, f"client_output_{mode}_{concurrency}_run{run_num}.csv")
        if not os.path.exists(c_file) or os.path.getsize(c_file) == 0:
            continue

        try:
            c_df = pd.read_csv(c_file)
            s_df = pd.read_csv(s_file)

            if "totalRequests" not in c_df.columns:
                continue

            total_req = float(c_df["totalRequests"].iloc[0])

            miss_row = s_df[s_df["metric"] == "cache_misses"]
            if miss_row.empty:
                cache_misses = 0.0
            else:
                cache_misses = float(miss_row["value"].iloc[0])

            hits = max(0.0, total_req - cache_misses)
            hit_rate = (hits / total_req * 100.0) if total_req > 0 else 0.0

            new_rows = []
            if "cache_hits" not in s_df["metric"].values:
                new_rows.append({"metric": "cache_hits", "value": round(hits, 2)})
            if "cache_hit_rate" not in s_df["metric"].values:
                new_rows.append({"metric": "cache_hit_rate", "value": round(hit_rate, 4)})

            if new_rows:
                s_df = pd.concat([s_df, pd.DataFrame(new_rows)], ignore_index=True)
                s_df.to_csv(s_file, index=False)

        except Exception as e:
            print(f"Aviso: Erro ao calcular hit rate para a run {run_num}: {e}", file=sys.stderr)


def consolidate_files(input_dir, file_pattern, output_file, is_server_data=False):
    """
    Finds all CSV files matching a pattern, calculates mean and std dev for each metric,
    and saves to a consolidated CSV file.
    """
    try:
        file_paths = glob.glob(os.path.join(input_dir, file_pattern))

        if not file_paths:
            print(f"Aviso: Nenhum arquivo encontrado para o padrão '{file_pattern}' em '{input_dir}'. Pulando.", file=sys.stderr)
            return

        df_list = []
        for f in file_paths:
            try:
                if os.path.getsize(f) > 0:
                    df_list.append(pd.read_csv(f))
                else:
                    print(f"Aviso: Pulando arquivo vazio '{f}'", file=sys.stderr)
            except pd.errors.EmptyDataError:
                print(f"Aviso: Pulando arquivo vazio ou malformado '{f}'", file=sys.stderr)
                continue

        if not df_list:
            print(f"Aviso: Nenhum dado válido encontrado para o padrão '{file_pattern}'. Pulando.", file=sys.stderr)
            return

        combined_df = pd.concat(df_list, ignore_index=True)

        if is_server_data:
            # Server data is in long format: metric, value
            combined_df['value'] = pd.to_numeric(combined_df['value'], errors='coerce')
            summary = combined_df.groupby('metric')['value'].agg(['mean', 'std']).reset_index()
            summary.columns = ['metric', 'mean', 'std']
            summary_df = summary
        else:
            # Client data is in wide format, one column per metric.
            numeric_cols = combined_df.select_dtypes(include='number').columns
            summary_mean = combined_df[numeric_cols].mean()
            summary_std = combined_df[numeric_cols].std()

            rows = []
            for col in numeric_cols:
                rows.append({
                    "metric": col,
                    "mean": summary_mean[col],
                    "std": summary_std[col]
                })
            summary_df = pd.DataFrame(rows)

        summary_df.to_csv(output_file, index=False)
        print(f"Sucesso: {len(df_list)} arquivos consolidados em '{output_file}'")

    except Exception as e:
        print(f"Erro durante a consolidação para o padrão '{file_pattern}': {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='Consolida os resultados do benchmark.')
    parser.add_argument('--mode', type=str, required=True)
    parser.add_argument('--concurrency', type=int, required=True)
    parser.add_argument('--client-dir', type=str, required=True)
    parser.add_argument('--server-dir', type=str, required=True)
    parser.add_argument('--output-dir', type=str, required=True)

    args = parser.parse_args()

    # 1. Enriquecer arquivos do servidor com cache_hits e cache_hit_rate calculados a partir dos totalRequests do cliente
    enrich_server_files_with_hit_rate(args.client_dir, args.server_dir, args.mode, args.concurrency)

    # 2. Consolida dados do cliente
    client_pattern = f"client_output_{args.mode}_{args.concurrency}_run*.csv"
    client_output_file = os.path.join(args.output_dir, f"client_results_{args.mode}_{args.concurrency}.csv")
    consolidate_files(args.client_dir, client_pattern, client_output_file, is_server_data=False)

    # 3. Consolida dados do servidor
    server_pattern = f"server_output_{args.mode}_{args.concurrency}_run*.csv"
    server_output_file = os.path.join(args.output_dir, f"server_results_{args.mode}_{args.concurrency}.csv")
    consolidate_files(args.server_dir, server_pattern, server_output_file, is_server_data=True)


if __name__ == '__main__':
    main()
