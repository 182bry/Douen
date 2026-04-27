import argparse
import pandas as pd
import joblib
import numpy as np

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

from src.config.settings import (
    X_VALID,
    Y_VALID
)


# Helpers

def convert_to_binary(y_series):
    return y_series.apply(lambda x: 0 if x == "BENIGN" else 1)


def load_model_predict(loaded_obj, X_valid, mode):
    """Return string predictions regardless of model packaging format."""
    if mode == "binary":
        if isinstance(loaded_obj, dict):
            return loaded_obj["model"].predict(X_valid)
        return loaded_obj.predict(X_valid)

    # multiclass
    if isinstance(loaded_obj, dict):
        model       = loaded_obj["model"]
        id_to_label = loaded_obj["id_to_label"]
        raw         = model.predict(X_valid)
        return pd.Series(raw).map(id_to_label).values
    return loaded_obj.predict(X_valid)


# Binary evaluation

def evaluate_binary(model, X_valid, y_valid):
    print("Running binary evaluation...")

    y_valid_binary = convert_to_binary(y_valid)
    y_pred         = model.predict(X_valid) if not isinstance(model, dict) \
                     else model["model"].predict(X_valid)

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
        y_valid_binary, y_pred,
        target_names=["BENIGN", "ATTACK"],
        zero_division=0
    ))

    benign_mask = y_valid_binary == 0
    attack_mask = y_valid_binary == 1

    false_positive_rate  = (y_pred[benign_mask] == 1).mean() * 100
    attack_detection_rate = (y_pred[attack_mask] == 1).mean() * 100

    print("\nAdditional Security Metrics")
    print("---------------------------")
    print(f"False Positive Rate (BENIGN flagged as ATTACK): {false_positive_rate:.2f}%")
    print(f"Attack Detection Rate                         : {attack_detection_rate:.2f}%")


# Multiclass evaluation

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


# Per-class isolated evaluation
# (extract each attack type and test the model on just those rows)

def per_class_isolated_evaluation(y_valid: pd.Series, y_pred_series: pd.Series) -> None:
    """
    For every attack type in the validation set:
      1. Extract only rows where the true label = that attack type
      2. Measure how well the model does on that subset alone
      3. Print a ranked summary from best to worst

    This answers: "how does the model perform specifically on DDoS attacks?
    And how does that compare to how it handles PortScans?"
    """
    print("\n" + "=" * 70)
    print("  PER-CLASS ISOLATED EVALUATION")
    print("  (each attack type tested independently — your teacher's approach)")
    print("=" * 70)

    y_true = y_valid.reset_index(drop=True)
    y_pred = y_pred_series.reset_index(drop=True)

    classes = sorted(y_true.unique())

    results = []
    for cls in classes:
        mask = y_true == cls
        n    = mask.sum()
        if n == 0:
            continue

        y_true_sub = y_true[mask]
        y_pred_sub = y_pred[mask]

        correct = (y_pred_sub == cls).sum()
        recall  = correct / n                     # = recall for this class
        # Precision: of all the times the model predicted this class, how often was it right?
        pred_as_cls = (y_pred == cls).sum()
        precision   = correct / pred_as_cls if pred_as_cls > 0 else 0.0
        f1          = (2 * precision * recall / (precision + recall)
                       if (precision + recall) > 0 else 0.0)

        # Top misclassification targets
        wrong       = y_pred_sub[y_pred_sub != cls]
        top_wrong   = wrong.value_counts().head(3).to_dict()
        top_wrong_str = ", ".join(f"{k}×{v}" for k, v in top_wrong.items()) or "—"

        results.append({
            "attack_type"   : cls,
            "support"       : int(n),
            "correct"       : int(correct),
            "detection_rate": round(recall * 100, 2),
            "precision"     : round(precision, 4),
            "f1_score"      : round(f1, 4),
            "top_confusions": top_wrong_str,
        })

    results_df = pd.DataFrame(results).sort_values("f1_score", ascending=True)

    print(f"\n  {'Attack Type':<35} {'Support':>8} {'Detect%':>9} {'Precision':>10} {'F1':>8}")
    print("  " + "-" * 75)
    for _, row in results_df.iterrows():
        flag = "  ← WEAK" if row["f1_score"] < 0.70 else ""
        print(
            f"  {row['attack_type']:<35} {row['support']:>8,} "
            f"{row['detection_rate']:>8.1f}% {row['precision']:>10.4f} "
            f"{row['f1_score']:>8.4f}{flag}"
        )
        if row["top_confusions"] != "—":
            print(f"    └─ confused with: {row['top_confusions']}")

    weak_count   = (results_df["f1_score"] < 0.70).sum()
    strong_count = (results_df["f1_score"] >= 0.70).sum()
    print(f"\n  Strong classes (F1 ≥ 0.70): {strong_count}")
    print(f"  Weak classes   (F1 < 0.70): {weak_count}")
    print(f"\n  → Run per_class_evaluation.py for deeper analysis and to")
    print(f"    generate the weak_classes.txt used by the specialist trainer.")


# Main

def main():
    parser = argparse.ArgumentParser(description="Evaluate a saved intrusion detection model.")
    parser.add_argument("--model-path", type=str, required=True,
                        help="Path to the saved model file")
    parser.add_argument("--mode", type=str, required=True,
                        choices=["binary", "multiclass"],
                        help="Evaluation mode: binary or multiclass")
    parser.add_argument("--per-class", action="store_true",
                        help="Run per-class isolated evaluation (multiclass only).")

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
            model       = loaded_obj["model"]
            id_to_label = loaded_obj["id_to_label"]

            y_pred_ids  = model.predict(X_valid)
            y_pred      = pd.Series(y_pred_ids).map(id_to_label)

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
            model  = loaded_obj
            y_pred = pd.Series(model.predict(X_valid))
            evaluate_multiclass(model, X_valid, y_valid)

        # Per-class isolated evaluation
        if args.per_class:
            per_class_isolated_evaluation(y_valid, y_pred)


if __name__ == "__main__":
    main()
