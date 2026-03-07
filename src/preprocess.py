import pandas as pd
from sklearn.model_selection import train_test_split

INPUT_PATH = "data/processed/cicids_combined.parquet"

X_TRAIN_PATH = "data/processed/X_train.parquet"
X_TEST_PATH = "data/processed/X_test.parquet"
Y_TRAIN_PATH = "data/processed/y_train.parquet"
Y_TEST_PATH = "data/processed/y_test.parquet"


def clean_labels(df):

    df["Label"] = df["Label"].str.strip()

    df["Label"] = df["Label"].replace({
        "Web Attack – Brute Force": "WebAttack_BruteForce",
        "Web Attack – XSS": "WebAttack_XSS",
        "Web Attack – Sql Injection": "WebAttack_SQLInjection"
    })

    return df


def main():

    print("Loading dataset...")
    df = pd.read_parquet(INPUT_PATH)

    print("Cleaning labels...")
    df = clean_labels(df)

    print("Separating features and labels...")
    X = df.drop("Label", axis=1)
    y = df["Label"]

    print("Splitting train/test...")
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    print("Saving processed splits...")

    X_train.to_parquet(X_TRAIN_PATH)
    X_test.to_parquet(X_TEST_PATH)

    y_train.to_frame().to_parquet(Y_TRAIN_PATH)
    y_test.to_frame().to_parquet(Y_TEST_PATH)

    print("Done!")

    print("Train shape:", X_train.shape)
    print("Test shape:", X_test.shape)


if __name__ == "__main__":
    main()