import argparse
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from src.config.settings import X_VALID, Y_VALID, PROCESSED_DIR

# Outputs
PER_CLASS_REPORT_PATH  = os.path.join(PROCESSED_DIR, "per_class_report.csv")
WEAK_CLASSES_PATH      = os.path.join(PROCESSED_DIR, "weak_classes.txt")

# A class is "weak" if its F1 score is below this threshold
WEAK_CLASS_F1_THRESHOLD = 0.70


# Helpers

def load_model_and_predict(model_path: str, X_valid: pd.DataFrame, y_valid: pd.Series):
    """Load any supported model format and return (y_pred, label_list)."""
    obj = joblib.load(model_path)

    if isinstance(obj, dict):
        # XGBoost multiclass packed as {model, label_to_id, id_to_label}
        model      = obj["model"]
        id_to_label = obj["id_to_label"]
        y_pred_ids = model.predict(X_valid)
        y_pred     = pd.Series(y_pred_ids).map(id_to_label).values
    else:
        y_pred = obj.predict(X_valid)

    return y_pred


def per_class_breakdown(y_true: pd.Series, y_pred, threshold: float) -> pd.DataFrame:
    """
    Build a full per-class metrics DataFrame and tag each class as
    STRONG / WEAK based on the F1 threshold.
    """
    report_dict = classification_report(
        y_true, y_pred, zero_division=0, output_dict=True
    )

    rows = []
    for label, metrics in report_dict.items():
        if label in ("accuracy", "macro avg", "weighted avg"):
            continue
        if not isinstance(metrics, dict):
            continue

        support   = int(metrics.get("support", 0))
        if support == 0:
            continue

        f1        = metrics.get("f1-score", 0.0)
        precision = metrics.get("precision", 0.0)
        recall    = metrics.get("recall", 0.0)

        rows.append({
            "attack_type"  : label,
            "precision"    : round(precision, 4),
            "recall"       : round(recall,    4),
            "f1_score"     : round(f1,        4),
            "support"      : support,
            "status"       : "WEAK" if f1 < threshold else "STRONG",
        })

    df = pd.DataFrame(rows).sort_values("f1_score", ascending=True).reset_index(drop=True)
    return df


def print_class_report(report_df: pd.DataFrame, threshold: float) -> None:
    print("\n" + "=" * 65)
    print("  PER-CLASS EVALUATION REPORT")
    print("=" * 65)
    print(f"  Weak class threshold: F1 < {threshold}\n")

    print(f"{'Attack Type':<35} {'Precision':>10} {'Recall':>8} {'F1':>8} {'Support':>9} {'Status':>8}")
    print("-" * 80)
    for _, row in report_df.iterrows():
        marker = "  ← NEEDS SPECIALIST" if row["status"] == "WEAK" else ""
        print(
            f"  {row['attack_type']:<33} "
            f"{row['precision']:>10.4f} "
            f"{row['recall']:>8.4f} "
            f"{row['f1_score']:>8.4f} "
            f"{row['support']:>9,} "
            f"  {row['status']}{marker}"
        )

    weak   = report_df[report_df["status"] == "WEAK"]
    strong = report_df[report_df["status"] == "STRONG"]
    print(f"\n  Strong classes : {len(strong)}")
    print(f"  Weak classes   : {len(weak)}")

    if len(weak):
        print(f"\n  Weak classes targeted for specialist model:")
        for _, row in weak.iterrows():
            print(f"    • {row['attack_type']}  (F1={row['f1_score']:.4f}, n={row['support']:,})")


def extract_class_subset(
    X_valid: pd.DataFrame,
    y_valid: pd.Series,
    attack_type: str,
    model_path: str,
) -> None:
    obj       = joblib.load(model_path)
    if isinstance(obj, dict):
        model       = obj["model"]
        id_to_label = obj["id_to_label"]
        y_pred_ids  = model.predict(X_valid)
        y_pred      = pd.Series(y_pred_ids).map(id_to_label).reset_index(drop=True)
    else:
        y_pred = pd.Series(obj.predict(X_valid))

    y_true_reset = y_valid.reset_index(drop=True)

    # Subset to rows that are truly this attack type
    mask         = y_true_reset == attack_type
    y_true_sub   = y_true_reset[mask]
    y_pred_sub   = y_pred[mask]

    if len(y_true_sub) == 0:
        print(f"  No samples found for '{attack_type}' in validation set.")
        return

    correct   = (y_pred_sub == y_true_reset[mask]).sum()
    total     = len(y_true_sub)
    precision = precision_score(y_true_sub, y_pred_sub, average="weighted",
                                zero_division=0, labels=[attack_type])
    recall    = recall_score(y_true_sub, y_pred_sub, average="weighted",
                             zero_division=0, labels=[attack_type])
    f1        = f1_score(y_true_sub, y_pred_sub, average="weighted",
                         zero_division=0, labels=[attack_type])

    print(f"\n  Isolated class analysis: '{attack_type}'")
    print(f"  {'Samples':>20} : {total:,}")
    print(f"  {'Correctly classified':>20} : {correct:,} ({correct/total*100:.1f}%)")
    print(f"  {'Precision':>20} : {precision:.4f}")
    print(f"  {'Recall':>20} : {recall:.4f}")
    print(f"  {'F1':>20} : {f1:.4f}")

    
    wrong_mask   = y_pred_sub != attack_type
    wrong_preds  = y_pred_sub[wrong_mask].value_counts()
    if len(wrong_preds):
        print(f"\n  Misclassified as:")
        for wrong_label, n in wrong_preds.head(5).items():
            print(f"    → {wrong_label:<35} {n:>5}×")


def isolated_class_report(
    X_valid: pd.DataFrame,
    y_valid: pd.Series,
    model_path: str,
    report_df: pd.DataFrame,
) -> None:
    """
    Run isolated-class analysis for every attack type so you can see
    exactly how the model handles each attack in isolation.
    """
    print("\n" + "=" * 65)
    print("  ISOLATED CLASS ANALYSIS  (one attack type at a time)")
    print("=" * 65)

    for attack_type in sorted(report_df["attack_type"].unique()):
        if attack_type == "BENIGN":
            continue
        extract_class_subset(X_valid, y_valid, attack_type, model_path)


# Main

def main():
    parser = argparse.ArgumentParser(
        description="Per-class evaluation to identify strong and weak attack types."
    )
    parser.add_argument(
        "--model-path", type=str, required=True,
        help="Path to a saved multiclass model file."
    )
    parser.add_argument(
        "--threshold", type=float, default=WEAK_CLASS_F1_THRESHOLD,
        help=f"F1 threshold below which a class is flagged as weak (default: {WEAK_CLASS_F1_THRESHOLD})"
    )
    parser.add_argument(
        "--isolated", action="store_true",
        help="Also run isolated per-class analysis (extract each attack type and test independently)."
    )
    args = parser.parse_args()

    print("Loading validation data...")
    X_valid = pd.read_parquet(X_VALID)
    y_valid = pd.read_parquet(Y_VALID)["Label"]

    print(f"Loading model from: {args.model_path}")
    y_pred = load_model_and_predict(args.model_path, X_valid, y_valid)

    # Overall headline metrics
    print(f"\nOverall accuracy  : {accuracy_score(y_valid, y_pred):.4f}")
    print(f"Weighted F1       : {f1_score(y_valid, y_pred, average='weighted', zero_division=0):.4f}")

    # Per-class breakdown
    report_df = per_class_breakdown(y_valid, y_pred, args.threshold)
    print_class_report(report_df, args.threshold)

    # Save outputs
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    report_df.to_csv(PER_CLASS_REPORT_PATH, index=False)
    print(f"\nPer-class report saved → {PER_CLASS_REPORT_PATH}")

    weak_classes = report_df[report_df["status"] == "WEAK"]["attack_type"].tolist()
    with open(WEAK_CLASSES_PATH, "w") as f:
        f.write("\n".join(weak_classes))
    print(f"Weak class list saved  → {WEAK_CLASSES_PATH}")
    print(f"  ({len(weak_classes)} weak class(es): {', '.join(weak_classes) or 'none'})")

    # Optional isolated analysis
    if args.isolated:
        isolated_class_report(X_valid, y_valid, args.model_path, report_df)


if __name__ == "__main__":
    main()
