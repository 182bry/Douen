import pandas as pd
import numpy as np

from src.config.settings import (
    CICIDS_OUTPUT,
    CICIDS_TRAIN,
    CICIDS_VALID,
    CICIDS_TEST,
)


def print_section(title):
    print(f"\n{'=' * 55}")
    print(f"  {title}")
    print(f"{'=' * 55}")


def summarise_df(df, name):
    print_section(f"{name} — Overview")

    print(f"Shape         : {df.shape[0]:,} rows × {df.shape[1]} columns")
    print(f"Memory usage  : {df.memory_usage(deep=True).sum() / 1e6:.1f} MB")

    print("\nLabel distribution:")
    vc = df["Label"].value_counts()
    pct = df["Label"].value_counts(normalize=True) * 100
    summary = pd.DataFrame({"Count": vc, "Pct %": pct.round(2)})
    print(summary.to_string())

    numeric = df.select_dtypes(include=[np.number])
    print(f"\nNumeric features : {numeric.shape[1]}")

    missing = df.isnull().sum()
    missing = missing[missing > 0]
    if len(missing):
        print(f"\nColumns with missing values ({len(missing)}):")
        print(missing)
    else:
        print("\nNo missing values.")

    inf_cols = [c for c in numeric.columns if np.isinf(numeric[c]).any()]
    if inf_cols:
        print(f"\nColumns with inf values: {inf_cols}")
    else:
        print("No inf values.")


def summarise_split(train, valid, test):
    print_section("Temporal Split Summary")

    total = len(train) + len(valid) + len(test)
    for name, df in [("Train", train), ("Valid", valid), ("Test", test)]:
        pct = len(df) / total * 100
        attacks = (df["Label"] != "BENIGN").sum()
        attack_pct = attacks / len(df) * 100
        print(f"{name:6s}: {len(df):>9,} rows ({pct:.1f}%)  |  "
              f"Attack rows: {attacks:>7,} ({attack_pct:.1f}%)")


def feature_stats(df):
    print_section("Top 10 Features — Descriptive Stats")
    numeric = df.select_dtypes(include=[np.number]).drop(
        columns=["dataset", "source_file"], errors="ignore"
    )
    # Show stats for 10 most-variance features
    top10 = numeric.var().nlargest(10).index
    print(numeric[top10].describe().T[["mean", "std", "min", "max"]].round(3).to_string())


def attack_feature_contrast(df):
    print_section("Mean Feature Values — BENIGN vs ATTACK (top 10 by difference)")

    numeric = df.select_dtypes(include=[np.number])
    benign_mean  = numeric[df["Label"] == "BENIGN"].mean()
    attack_mean  = numeric[df["Label"] != "BENIGN"].mean()
    diff = (attack_mean - benign_mean).abs().nlargest(10)

    contrast = pd.DataFrame({
        "BENIGN mean" : benign_mean[diff.index].round(4),
        "ATTACK mean" : attack_mean[diff.index].round(4),
        "|diff|"      : diff.round(4),
    })
    print(contrast.to_string())


def main():
    print_section("CICIDS2017 Dataset Summary")

    print("Loading combined dataset...")
    df = pd.read_parquet(CICIDS_OUTPUT)
    summarise_df(df, "CICIDS2017 (combined)")
    feature_stats(df)
    attack_feature_contrast(df)

    print_section("Split Datasets")
    try:
        train = pd.read_parquet(CICIDS_TRAIN)
        valid = pd.read_parquet(CICIDS_VALID)
        test  = pd.read_parquet(CICIDS_TEST)
        summarise_split(train, valid, test)
    except FileNotFoundError:
        print("Split files not found — run preprocess.py first.")


if __name__ == "__main__":
    main()