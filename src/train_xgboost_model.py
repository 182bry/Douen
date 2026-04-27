import argparse
import os
import joblib
import pandas as pd

from xgboost import XGBClassifier

from src.config.settings import (
    X_TRAIN,
    Y_TRAIN,
    X_VALID,
    Y_VALID
)


BINARY_MODEL_PATH = "models/xgboost_binary.pkl"
MULTICLASS_MODEL_PATH = "models/xgboost_multiclass.pkl"


def convert_to_binary(y_series):
    return y_series.apply(lambda x: 0 if x == "BENIGN" else 1)


def train_binary():
    print("Loading training and validation datasets...")

    X_train = pd.read_parquet(X_TRAIN)
    y_train = pd.read_parquet(Y_TRAIN)["Label"]

    X_valid = pd.read_parquet(X_VALID)
    y_valid = pd.read_parquet(Y_VALID)["Label"]

    print("Converting labels to binary classification...")
    y_train_binary = convert_to_binary(y_train)
    y_valid_binary = convert_to_binary(y_valid)

    print("Creating balanced training sample...")
    train_df = X_train.copy()
    train_df["Label"] = y_train_binary

    benign = train_df[train_df["Label"] == 0]
    attack = train_df[train_df["Label"] == 1]

    benign_sample = benign.sample(n=min(len(benign), 50000), random_state=42)
    attack_sample = attack.sample(n=min(len(attack), 50000), random_state=42)

    balanced = pd.concat([benign_sample, attack_sample], ignore_index=True)

    X_train_sample = balanced.drop("Label", axis=1)
    y_train_sample = balanced["Label"]

    print("Balanced training shape:", X_train_sample.shape)
    print("Validation shape:", X_valid.shape)
    print("\nTraining label distribution:")
    print(y_train_sample.value_counts())

    print("\nTraining XGBoost binary classifier...")
    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        n_jobs=-1,
        eval_metric="logloss"
    )

    model.fit(X_train_sample, y_train_sample)

    os.makedirs("models", exist_ok=True)
    joblib.dump(model, BINARY_MODEL_PATH)

    print(f"Saved binary XGBoost model to: {BINARY_MODEL_PATH}")
    print("Training complete.")


def train_multiclass():
    print("Loading training and validation datasets...")

    X_train = pd.read_parquet(X_TRAIN)
    y_train = pd.read_parquet(Y_TRAIN)["Label"]

    X_valid = pd.read_parquet(X_VALID)
    y_valid = pd.read_parquet(Y_VALID)["Label"]

    print("Training label distribution:")
    print(y_train.value_counts())

    print("\nSampling training data for faster multiclass baseline...")
    train_df = X_train.copy()
    train_df["Label"] = y_train

    sampled_parts = []
    label_to_id = {}
    id_to_label = {}

    for idx, label in enumerate(sorted(train_df["Label"].unique())):
        label_to_id[label] = idx
        id_to_label[idx] = label

    for label, group in train_df.groupby("Label"):
        sample_size = min(len(group), 20000)
        sampled_parts.append(group.sample(n=sample_size, random_state=42))

    sampled_train = pd.concat(sampled_parts, ignore_index=True)

    X_train_sample = sampled_train.drop("Label", axis=1)
    y_train_sample = sampled_train["Label"].map(label_to_id)

    print("Sampled training shape:", X_train_sample.shape)
    print("\nSampled training label distribution:")
    print(sampled_train["Label"].value_counts())

    print("\nTraining XGBoost multiclass classifier...")
    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        n_jobs=-1,
        objective="multi:softmax",
        num_class=len(label_to_id),
        eval_metric="mlogloss"
    )

    model.fit(X_train_sample, y_train_sample)

    os.makedirs("models", exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "label_to_id": label_to_id,
            "id_to_label": id_to_label
        },
        MULTICLASS_MODEL_PATH
    )

    print(f"Saved multiclass XGBoost model to: {MULTICLASS_MODEL_PATH}")
    print("Training complete.")


def main():
    parser = argparse.ArgumentParser(description="Train XGBoost intrusion detection models.")
    parser.add_argument(
        "--mode",
        type=str,
        required=True,
        choices=["binary", "multiclass"],
        help="Training mode: binary or multiclass"
    )

    args = parser.parse_args()

    if args.mode == "binary":
        train_binary()
    elif args.mode == "multiclass":
        train_multiclass()


if __name__ == "__main__":
    main()