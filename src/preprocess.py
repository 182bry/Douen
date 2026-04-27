import pandas as pd
import numpy as np
 
from src.config.settings import (
    CICIDS_OUTPUT,
    CICIDS_TRAIN,
    CICIDS_VALID,
    CICIDS_TEST,
    X_TRAIN,
    Y_TRAIN,
    X_VALID,
    Y_VALID,
    X_TEST,
    Y_TEST,
)
 
# File assignments
 
TRAIN_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
]
 
VALID_FILES = [
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
]
 
TEST_FILES = [
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]
 
# Fraction of each Thursday *attack* class seeded into training
# (BENIGN rows from Thursday are left in validation unchanged)
THURSDAY_SEED_FRACTION = 0.15
RANDOM_SEED            = 42
 
 
def clean_labels(df: pd.DataFrame) -> pd.DataFrame:
    df["Label"] = df["Label"].str.strip()
    df["Label"] = df["Label"].replace({
        "Web Attack \u2013 Brute Force" : "WebAttack_BruteForce",
        "Web Attack - Brute Force"      : "WebAttack_BruteForce",
        "Web Attack \ufffd Brute Force" : "WebAttack_BruteForce",
 
        "Web Attack \u2013 XSS"         : "WebAttack_XSS",
        "Web Attack - XSS"              : "WebAttack_XSS",
        "Web Attack \ufffd XSS"         : "WebAttack_XSS",
 
        "Web Attack \u2013 Sql Injection" : "WebAttack_SQLInjection",
        "Web Attack - Sql Injection"      : "WebAttack_SQLInjection",
        "Web Attack \ufffd Sql Injection" : "WebAttack_SQLInjection",
    })
    return df
 
 
def split_features_labels(df: pd.DataFrame):
    y = df["Label"]
    X = df.drop(columns=["Label", "dataset", "source_file"], errors="ignore")
    return X, y
 
 
def seed_thursday_attacks_into_train(
    train_df: pd.DataFrame,
    valid_df: pd.DataFrame,
    seed_fraction: float = THURSDAY_SEED_FRACTION,
    random_state: int    = RANDOM_SEED,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Take a stratified sample of Thursday *attack* rows and move them from
    valid_df into train_df. BENIGN rows stay in validation.
 
    Returns (new_train_df, new_valid_df).
    """
    rng         = np.random.default_rng(random_state)
    seed_rows   = []
    keep_valid  = []
 
    attack_mask = valid_df["Label"] != "BENIGN"
    benign_df   = valid_df[~attack_mask].copy()
    attack_df   = valid_df[attack_mask].copy()
 
    classes_seeded = {}
    for label, group in attack_df.groupby("Label"):
        n_seed = max(1, int(len(group) * seed_fraction))
        idx    = rng.choice(len(group), size=n_seed, replace=False)
        mask   = np.zeros(len(group), dtype=bool)
        mask[idx] = True
 
        seed_rows.append(group.iloc[mask])
        keep_valid.append(group.iloc[~mask])
        classes_seeded[label] = n_seed
 
    seed_df      = pd.concat(seed_rows, ignore_index=True)
    new_valid_df = pd.concat([benign_df] + keep_valid, ignore_index=True)
    new_train_df = pd.concat([train_df, seed_df], ignore_index=True)
 
    print("\nThursday attack seed summary:")
    for label, n in classes_seeded.items():
        remaining = (new_valid_df["Label"] == label).sum()
        print(f"  {label:<35}  seeded {n:>5}  |  remaining in valid {remaining:>5}")
 
    return new_train_df, new_valid_df
 
 
def main():
    print("Loading CICIDS2017 dataset...")
    df = pd.read_parquet(CICIDS_OUTPUT)
 
    print("Cleaning labels...")
    df = clean_labels(df)
 
    print("Applying temporal split by source file...")
    train_df = df[df["source_file"].isin(TRAIN_FILES)].copy()
    valid_df = df[df["source_file"].isin(VALID_FILES)].copy()
    test_df  = df[df["source_file"].isin(TEST_FILES)].copy()
 
    print(f"\nBefore Thursday seed:")
    print(f"  Train : {len(train_df):>9,}   Valid : {len(valid_df):>9,}   Test : {len(test_df):>9,}")
 
    #Seed Thursday attack classes into training
    train_df, valid_df = seed_thursday_attacks_into_train(train_df, valid_df)
 
    print(f"\nAfter Thursday seed:")
    print(f"  Train : {len(train_df):>9,}   Valid : {len(valid_df):>9,}   Test : {len(test_df):>9,}")
 
    print("\nSaving temporal split datasets...")
    train_df.to_parquet(CICIDS_TRAIN, index=False)
    valid_df.to_parquet(CICIDS_VALID, index=False)
    test_df.to_parquet(CICIDS_TEST, index=False)
 
    print("\nTrain labels:")
    print(train_df["Label"].value_counts())
    print("\nValidation labels:")
    print(valid_df["Label"].value_counts())
    print("\nTest labels:")
    print(test_df["Label"].value_counts())
 
    print("\nPreparing modelling datasets...")
    X_train, y_train = split_features_labels(train_df)
    X_valid, y_valid = split_features_labels(valid_df)
    X_test,  y_test  = split_features_labels(test_df)
 
    print("Saving feature datasets...")
    X_train.to_parquet(X_TRAIN)
    y_train.to_frame().to_parquet(Y_TRAIN)
 
    X_valid.to_parquet(X_VALID)
    y_valid.to_frame().to_parquet(Y_VALID)
 
    X_test.to_parquet(X_TEST)
    y_test.to_frame().to_parquet(Y_TEST)
 
    print("Done saving modelling datasets!")
    print(f"  X_train : {X_train.shape}")
    print(f"  X_valid : {X_valid.shape}")
    print(f"  X_test  : {X_test.shape}")
 
 
if __name__ == "__main__":
    main()