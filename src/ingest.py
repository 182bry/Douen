import os
import pandas as pd
import numpy as np

from src.config.settings import (
    CICIDS_PATH,
    CICIDS_OUTPUT,
)


def clean_data(df):
    rows_before = len(df)

    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    rows_after = len(df)
    print(f"  Cleaned: removed {rows_before - rows_after} rows ({rows_before - rows_after:,} NaN/inf)")

    return df


def load_cicids(path):
    files = sorted([f for f in os.listdir(path) if f.endswith(".csv")])

    if not files:
        raise FileNotFoundError(
            f"No CSV files found in: {path}\n"
            "Download CICIDS2017 from https://www.unb.ca/cic/datasets/ids-2017.html "
            "and place the 8 CSV files in data/raw/cicids2017/"
        )

    dataframes = []

    for file in files:
        file_path = os.path.join(path, file)
        print(f"Loading: {file}...")

        df = pd.read_csv(file_path, low_memory=False)
        df = clean_data(df)

        df["dataset"]     = "cicids2017"
        df["source_file"] = file

        print(f"  Shape after clean: {df.shape}")
        dataframes.append(df)

    combined_df = pd.concat(dataframes, ignore_index=True)

    print("\nCICIDS2017 combined shape:", combined_df.shape)
    print("Label distribution:")
    print(combined_df["Label"].value_counts())

    return combined_df


def main():
    print("=" * 50)
    print("CICIDS2017 Ingestion")
    print("=" * 50)

    cicids_df = load_cicids(CICIDS_PATH)
    cicids_df.to_parquet(CICIDS_OUTPUT, index=False)

    print(f"\nSaved to: {CICIDS_OUTPUT}")
    print(f"Total rows: {len(cicids_df):,}")


if __name__ == "__main__":
    main()