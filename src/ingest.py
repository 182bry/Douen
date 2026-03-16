import os
import pandas as pd
import numpy as np

from config.settings import (
    CICIDS_PATH,
    UNSW_PATH,
    CTU13_PATH,
    CICIDS_OUTPUT,
    UNSW_OUTPUT,
    CTU13_OUTPUT
)


def clean_data(df):
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    return df


def load_cicids(path):
    files = [f for f in os.listdir(path) if f.endswith(".csv")]
    dataframes = []

    for file in files:
        file_path = os.path.join(path, file)
        print(f"Loading CICIDS file: {file}...")

        df = pd.read_csv(file_path)
        df = clean_data(df)

        df["dataset"] = "cicids2017"
        df["source_file"] = file

        dataframes.append(df)

    combined_df = pd.concat(dataframes, ignore_index=True)
    return combined_df


def load_unsw(path):
    train_file = os.path.join(path, "UNSW_NB15_training-set.csv")
    test_file = os.path.join(path, "UNSW_NB15_testing-set.csv")

    print("Loading UNSW training set...")
    train_df = pd.read_csv(train_file)
    train_df = clean_data(train_df)
    train_df["dataset"] = "unsw_nb15"
    train_df["source_split"] = "train"

    print("Loading UNSW testing set...")
    test_df = pd.read_csv(test_file)
    test_df = clean_data(test_df)
    test_df["dataset"] = "unsw_nb15"
    test_df["source_split"] = "test"

    combined_df = pd.concat([train_df, test_df], ignore_index=True)
    return combined_df


def load_ctu13(path):
    files = [f for f in os.listdir(path) if f.endswith(".parquet")]
    dataframes = []

    for file in files:
        file_path = os.path.join(path, file)
        print(f"Loading CTU-13 file: {file}...")

        df = pd.read_parquet(file_path)
        df = clean_data(df)

        df["dataset"] = "ctu13"
        df["source_file"] = file

        dataframes.append(df)

    combined_df = pd.concat(dataframes, ignore_index=True)
    return combined_df


def main():
    print("Processing CICIDS2017...")
    cicids_df = load_cicids(CICIDS_PATH)
    cicids_df.to_parquet(CICIDS_OUTPUT, index=False)
    print("Saved CICIDS2017:", cicids_df.shape)

    print("\nProcessing UNSW-NB15...")
    unsw_df = load_unsw(UNSW_PATH)
    unsw_df.to_parquet(UNSW_OUTPUT, index=False)
    print("Saved UNSW-NB15:", unsw_df.shape)

    print("\nProcessing CTU-13...")
    ctu13_df = load_ctu13(CTU13_PATH)
    ctu13_df.to_parquet(CTU13_OUTPUT, index=False)
    print("Saved CTU-13:", ctu13_df.shape)

    print("\nAll datasets processed successfully.")


if __name__ == "__main__":
    main()