import os
import gc
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest

from src.config.settings import (
    CICIDS_TRAIN,
    CICIDS_VALID
)

MODEL_PATH = "models/isolation_forest.pkl"
RESULTS_PATH = "data/processed/anomaly_validation_results.csv"

TRAIN_BENIGN_SAMPLE_SIZE = 150000

def prepare_features(df):
    columns_to_drop = [
        col for col in ["Label", "dataset", "source_file"]
        if col in df.columns
    ]

    X = df.drop(columns=columns_to_drop, errors="ignore")

    non_numeric = X.select_dtypes(exclude=[np.number]).columns.tolist()
    if non_numeric:
        X = X.drop(columns=non_numeric)

    return X


def main():
    print("Loading temporal training and validation datasets...")

    train_df = pd.read_parquet(CICIDS_TRAIN)
    valid_df = pd.read_parquet(CICIDS_VALID)

    print("\nTraining split label distribution:")
    print(train_df["Label"].value_counts())

    print("\nValidation split label distribution:")
    print(valid_df["Label"].value_counts())

    print("\nSelecting BENIGN-only traffic from temporal training split...")
    benign_train_df = train_df[train_df["Label"] == "BENIGN"].copy()

    print(f"Available benign training rows: {len(benign_train_df):,}")

    benign_train_df = benign_train_df.sample(
        n=min(TRAIN_BENIGN_SAMPLE_SIZE, len(benign_train_df)),
        random_state=42
    )

    X_train = prepare_features(benign_train_df)

    print(f"Training feature shape: {X_train.shape}")

    print("\nTraining Isolation Forest model...")
    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
        n_jobs=-1
    )
    iso_forest.fit(X_train)

    os.makedirs("models", exist_ok=True)
    joblib.dump(iso_forest, MODEL_PATH)
    print(f"Saved model to: {MODEL_PATH}")

    print("\nPreparing temporal validation features...")
    X_valid = prepare_features(valid_df)
    y_valid = valid_df["Label"]

    print(f"Validation feature shape: {X_valid.shape}")

    print("\nRunning anomaly predictions on temporal validation split...")
    predictions = iso_forest.predict(X_valid)

    # IsolationForest returns:
    #  1  = normal
    # -1  = anomaly
    predicted_anomaly = (predictions == -1).astype(int)

    results_df = pd.DataFrame({
        "true_label": y_valid.values,
        "predicted_anomaly": predicted_anomaly
    })

    os.makedirs("data/processed", exist_ok=True)
    results_df.to_csv(RESULTS_PATH, index=False)
    print(f"Saved validation results to: {RESULTS_PATH}")

    print("\nOverall Results")
    print("---------------")
    print(f"Total rows tested: {len(results_df):,}")
    print(f"Flagged as anomalous: {predicted_anomaly.sum():,}")
    print(f"Anomaly rate: {predicted_anomaly.mean() * 100:.2f}%")

    benign_results = results_df[results_df["true_label"] == "BENIGN"]
    attack_results = results_df[results_df["true_label"] != "BENIGN"]

    fp_rate = benign_results["predicted_anomaly"].mean() * 100
    attack_detection_rate = attack_results["predicted_anomaly"].mean() * 100

    print("\nBenign False Positive Analysis")
    print("------------------------------")
    print(f"Benign flows tested: {len(benign_results):,}")
    print(f"False positive rate: {fp_rate:.2f}%")

    print("\nAttack Detection Analysis")
    print("-------------------------")
    print(f"Attack flows tested: {len(attack_results):,}")
    print(f"Attack detection rate: {attack_detection_rate:.2f}%")

    print("\nDetection Rate by Attack Type")
    print("-----------------------------")
    detection_summary = results_df.groupby("true_label")["predicted_anomaly"].agg(
        Total="count",
        Flagged="sum"
    )
    detection_summary["Detection_Rate_%"] = (
        detection_summary["Flagged"] / detection_summary["Total"] * 100
    ).round(2)

    print(detection_summary.sort_values("Detection_Rate_%", ascending=False))

    del train_df, valid_df, benign_train_df, X_train, X_valid, results_df
    gc.collect()

    print("\nTemporal anomaly detection pipeline complete.")


if __name__ == "__main__":
    main()