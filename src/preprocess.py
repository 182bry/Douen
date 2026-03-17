import pandas as pd

from config.settings import (
    CICIDS_OUTPUT,
    CICIDS_TRAIN,
    CICIDS_VALID,
    CICIDS_TEST,
    X_TRAIN,
    Y_TRAIN,
    X_VALID,
    Y_VALID,
    X_TEST,
    Y_TEST
)

TRAIN_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv"
]

VALID_FILES = [
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"
]

TEST_FILES = [
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
]


def clean_labels(df):

    df["Label"] = df["Label"].str.strip()

    df["Label"] = df["Label"].replace({
        "Web Attack – Brute Force": "WebAttack_BruteForce",
        "Web Attack - Brute Force": "WebAttack_BruteForce",
        "Web Attack � Brute Force": "WebAttack_BruteForce",

        "Web Attack – XSS": "WebAttack_XSS",
        "Web Attack - XSS": "WebAttack_XSS",
        "Web Attack � XSS": "WebAttack_XSS",

        "Web Attack – Sql Injection": "WebAttack_SQLInjection",
        "Web Attack - Sql Injection": "WebAttack_SQLInjection",
        "Web Attack � Sql Injection": "WebAttack_SQLInjection"
    })

    return df

def split_features_labels(df):

    y = df["Label"]

    X = df.drop(
        columns=[
            "Label",
            "dataset",
            "source_file"
        ],
        errors="ignore"
    )

    return X, y


def main():
    print("Loading CICIDS2017 dataset...")
    df = pd.read_parquet(CICIDS_OUTPUT)

    print("Cleaning labels...")
    df = clean_labels(df)

    print("Applying temporal split by source file...")
    train_df = df[df["source_file"].isin(TRAIN_FILES)].copy()
    valid_df = df[df["source_file"].isin(VALID_FILES)].copy()
    test_df = df[df["source_file"].isin(TEST_FILES)].copy()

    print("Saving temporal split datasets...")
    train_df.to_parquet(CICIDS_TRAIN, index=False)
    valid_df.to_parquet(CICIDS_VALID, index=False)
    test_df.to_parquet(CICIDS_TEST, index=False)

    print("Done!")
    print("Train shape:", train_df.shape)
    print("Validation shape:", valid_df.shape)
    print("Test shape:", test_df.shape)

    print("\nTrain labels:")
    print(train_df["Label"].value_counts())

    print("\nValidation labels:")
    print(valid_df["Label"].value_counts())

    print("\nTest labels:")
    print(test_df["Label"].value_counts())

    print("Preparing modeling datasets...")

    X_train, y_train = split_features_labels(train_df)
    X_valid, y_valid = split_features_labels(valid_df)
    X_test, y_test = split_features_labels(test_df)

    print("Saving feature datasets...")

    X_train.to_parquet(X_TRAIN)
    y_train.to_frame().to_parquet(Y_TRAIN)

    X_valid.to_parquet(X_VALID)
    y_valid.to_frame().to_parquet(Y_VALID)

    X_test.to_parquet(X_TEST)
    y_test.to_frame().to_parquet(Y_TEST)

    print("Done saving modeling datasets!")
    print("X_train shape:", X_train.shape)
    print("X_valid shape:", X_valid.shape)
    print("X_test shape:", X_test.shape)

if __name__ == "__main__":
    main()