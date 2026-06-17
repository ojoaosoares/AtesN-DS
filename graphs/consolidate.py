#!/usr/bin/env python3
import argparse
import pandas as pd
import glob
import os
import sys

def consolidate_files(input_dir, file_pattern, output_file):
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

        # Calcula a média e o desvio padrão para todas as colunas numéricas
        summary_mean = combined_df.mean().add_suffix('_mean')
        summary_std = combined_df.std().add_suffix('_std')

        # Combina as duas séries em um único DataFrame
        summary_df = pd.concat([summary_mean, summary_std]).to_frame().T

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

    # Consolida dados do cliente
    client_pattern = f"client_output_{args.mode}_{args.concurrency}_run*.csv"
    client_output_file = os.path.join(args.output_dir, f"client_results_{args.mode}_{args.concurrency}.csv")
    consolidate_files(args.client_dir, client_pattern, client_output_file)

    # Consolida dados do servidor
    server_pattern = f"server_output_{args.mode}_{args.concurrency}_run*.csv"
    server_output_file = os.path.join(args.output_dir, f"server_results_{args.mode}_{args.concurrency}.csv")
    consolidate_files(args.server_dir, server_pattern, server_output_file)


if __name__ == '__main__':
    main()
