import argparse
from flask_admin import model
import pandas as pd
import joblib

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

from config.settings import (
    X_VALID,
    Y_VALID
)


def convert_to_binary(y_series):
    return y_series.apply(lambda x: 0 if x == "BENIGN" else 1)


def evaluate_binary(model, X_valid, y_valid):
    print("Running binary evaluation...")

    y_valid_binary = convert_to_binary(y_valid)
    y_pred = model.predict(X_valid)

    print("\nValidation Metrics")
    print("------------------")
    print("Accuracy :", accuracy_score(y_valid_binary, y_pred))
    print("Precision:", precision_score(y_valid_binary, y_pred, zero_division=0))
    print("Recall   :", recall_score(y_valid_binary, y_pred, zero_division=0))
    print("F1 Score :", f1_score(y_valid_binary, y_pred, zero_division=0))

    print("\nConfusion Matrix")
    print("----------------")
    print(confusion_matrix(y_valid_binary, y_pred))

    print("\nClassification Report")
    print("---------------------")
    print(classification_report(
        y_valid_binary,
        y_pred,
        target_names=["BENIGN", "ATTACK"],
        zero_division=0
    ))

    benign_mask = y_valid_binary == 0
    attack_mask = y_valid_binary == 1

    false_positive_rate = (y_pred[benign_mask] == 1).mean() * 100
    attack_detection_rate = (y_pred[attack_mask] == 1).mean() * 100

    print("\nAdditional Security Metrics")
    print("---------------------------")
    print(f"False Positive Rate (BENIGN flagged as ATTACK): {false_positive_rate:.2f}%")
    print(f"Attack Detection Rate: {attack_detection_rate:.2f}%")


def evaluate_multiclass(model, X_valid, y_valid):
    print("Running multiclass evaluation...")

    y_pred = model.predict(X_valid)

    print("\nValidation Metrics")
    print("------------------")
    print("Accuracy :", accuracy_score(y_valid, y_pred))
    print("Precision:", precision_score(y_valid, y_pred, average="weighted", zero_division=0))
    print("Recall   :", recall_score(y_valid, y_pred, average="weighted", zero_division=0))
    print("F1 Score :", f1_score(y_valid, y_pred, average="weighted", zero_division=0))

    print("\nConfusion Matrix")
    print("----------------")
    print(confusion_matrix(y_valid, y_pred))

    print("\nClassification Report")
    print("---------------------")
    print(classification_report(y_valid, y_pred, zero_division=0))


def main():
    parser = argparse.ArgumentParser(description="Evaluate a saved intrusion detection model.")
    parser.add_argument(
        "--model-path",
        type=str,
        required=True,
        help="Path to the saved model file"
    )
    parser.add_argument(
        "--mode",
        type=str,
        required=True,
        choices=["binary", "multiclass"],
        help="Evaluation mode: binary or multiclass"
    )

    args = parser.parse_args()

    print("Loading validation dataset...")
    X_valid = pd.read_parquet(X_VALID)
    y_valid = pd.read_parquet(Y_VALID)["Label"]

    print(f"Loading model from {args.model_path}...")
    loaded_obj = joblib.load(args.model_path)

    print(f"Validation shape: {X_valid.shape}")
    print("\nValidation label distribution:")
    print(y_valid.value_counts())

    if args.mode == "binary":
        model = loaded_obj
        evaluate_binary(model, X_valid, y_valid)

    elif args.mode == "multiclass":
        if isinstance(loaded_obj, dict):
            model = loaded_obj["model"]
            id_to_label = loaded_obj["id_to_label"]

            y_pred_ids = model.predict(X_valid)
            y_pred = pd.Series(y_pred_ids).map(id_to_label)

            print("Running multiclass evaluation...")

            print("\nValidation Metrics")
            print("------------------")
            print("Accuracy :", accuracy_score(y_valid, y_pred))
            print("Precision:", precision_score(y_valid, y_pred, average="weighted", zero_division=0))
            print("Recall   :", recall_score(y_valid, y_pred, average="weighted", zero_division=0))
            print("F1 Score :", f1_score(y_valid, y_pred, average="weighted", zero_division=0))

            print("\nConfusion Matrix")
            print("----------------")
            print(confusion_matrix(y_valid, y_pred))

            print("\nClassification Report")
            print("---------------------")
            print(classification_report(y_valid, y_pred, zero_division=0))
        else:
            model = loaded_obj
            evaluate_multiclass(model, X_valid, y_valid)


if __name__ == "__main__":
    main()