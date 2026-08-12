#!/usr/bin/env python3

import argparse
import pandas as pd
import glob
import os
import sys


def consolidate_files(
    input_dir,
    file_pattern,
    output_file,
    is_server_data=False
):

    try:

        file_paths = glob.glob(
            os.path.join(input_dir, file_pattern)
        )

        if not file_paths:

            print(
                f"Aviso: Nenhum arquivo encontrado para "
                f"'{file_pattern}' em '{input_dir}'.",
                file=sys.stderr
            )

            return

        df_list = []

        for f in file_paths:

            try:

                if os.path.getsize(f) > 0:

                    df_list.append(
                        pd.read_csv(f)
                    )

                else:

                    print(
                        f"Aviso: arquivo vazio '{f}'",
                        file=sys.stderr
                    )

            except pd.errors.EmptyDataError:

                print(
                    f"Aviso: arquivo inválido '{f}'",
                    file=sys.stderr
                )


        if not df_list:

            return


        combined_df = pd.concat(
            df_list,
            ignore_index=True
        )


        # ========================================================
        # SERVER
        # ========================================================

        if is_server_data:

            combined_df["value"] = pd.to_numeric(
                combined_df["value"],
                errors="coerce"
            )

            summary = (
                combined_df
                .groupby("metric")["value"]
                .agg(["mean", "std"])
                .reset_index()
            )

            summary.columns = [
                "metric",
                "mean",
                "std"
            ]

            summary_df = summary


        # ========================================================
        # CLIENT
        # ========================================================

        else:

            numeric_cols = (
                combined_df
                .select_dtypes(include="number")
                .columns
            )

            summary_mean = (
                combined_df[numeric_cols]
                .mean()
            )

            summary_std = (
                combined_df[numeric_cols]
                .std()
            )

            rows = []

            for col in numeric_cols:

                rows.append({
                    "metric": col,
                    "mean": summary_mean[col],
                    "std": summary_std[col]
                })

            summary_df = pd.DataFrame(rows)


        # ========================================================
        # SALVAR
        # ========================================================

        summary_df.to_csv(
            output_file,
            index=False
        )

        print(
            f"Sucesso: {len(df_list)} arquivos "
            f"consolidados em '{output_file}'"
        )


    except Exception as e:

        print(
            f"Erro durante consolidação: {e}",
            file=sys.stderr
        )

        sys.exit(1)


def main():

    parser = argparse.ArgumentParser(
        description="Consolida os resultados do benchmark."
    )

    parser.add_argument(
        "--mode",
        required=True
    )

    parser.add_argument(
        "--concurrency",
        type=int,
        required=True
    )

    parser.add_argument(
        "--client-dir",
        required=True
    )

    parser.add_argument(
        "--server-dir",
        required=True
    )

    parser.add_argument(
        "--output-dir",
        required=True
    )

    args = parser.parse_args()


    # =========================================================
    # CLIENT
    # =========================================================

    client_pattern = (
        f"client_output_"
        f"{args.mode}_"
        f"{args.concurrency}_"
        f"run*.csv"
    )

    client_output = os.path.join(
        args.output_dir,
        f"client_results_"
        f"{args.mode}_"
        f"{args.concurrency}.csv"
    )

    consolidate_files(
        args.client_dir,
        client_pattern,
        client_output,
        False
    )


    # =========================================================
    # SERVER
    # =========================================================

    server_pattern = (
        f"server_output_"
        f"{args.mode}_"
        f"{args.concurrency}_"
        f"run*.csv"
    )

    server_output = os.path.join(
        args.output_dir,
        f"server_results_"
        f"{args.mode}_"
        f"{args.concurrency}.csv"
    )

    consolidate_files(
        args.server_dir,
        server_pattern,
        server_output,
        True
    )


if __name__ == "__main__":
    main()
