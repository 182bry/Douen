import argparse
import os
 
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from xgboost import XGBClassifier
 
from src.config.settings import (
    X_TRAIN, Y_TRAIN,
    X_VALID, Y_VALID,
    PROCESSED_DIR,
)
 
# Paths
SPECIALIST_MODEL_PATH  = "models/specialist_model.pkl"
SPECIALIST_REPORT_PATH = os.path.join(PROCESSED_DIR, "specialist_report.csv")
WEAK_CLASSES_PATH      = os.path.join(PROCESSED_DIR, "weak_classes.txt")
CTGAN_AUGMENTED_PATH   = os.path.join(PROCESSED_DIR, "ctgan_augmented_train.parquet")
PER_CLASS_REPORT_PATH  = os.path.join(PROCESSED_DIR, "per_class_report.csv")
GENERAL_MODEL_PATH     = "models/xgboost_multiclass.pkl"
 
# The full web-attack family -- the specialist's complete scope
WEB_ATTACK_FAMILY = [
    "WebAttack_BruteForce",
    "WebAttack_XSS",
    "WebAttack_SQLInjection",
    "Infiltration",
]
 
BENIGN_SAMPLE_SIZE = 30_000
REAL_SAMPLE_CAP    = 10_000
 
 
def load_weak_classes_from_file():
    if os.path.exists(WEAK_CLASSES_PATH):
        with open(WEAK_CLASSES_PATH) as f:
            return [line.strip() for line in f if line.strip()]
    return []
 
 
def predict_with_model(model_path, X):
    obj = joblib.load(model_path)
    if isinstance(obj, dict):
        raw = obj["model"].predict(X)
        return np.array([obj["id_to_label"][i] for i in raw])
    return obj.predict(X)
 
 
def build_training_data(specialist_classes, use_ctgan):
    """
    Build training data containing BENIGN + all specialist_classes.
    Uses CTGAN-augmented data if available and requested.
    """
    print("\nBuilding specialist training data...")
 
    if use_ctgan and os.path.exists(CTGAN_AUGMENTED_PATH):
        print(f"  Using CTGAN-augmented data from: {CTGAN_AUGMENTED_PATH}")
        aug_df = pd.read_parquet(CTGAN_AUGMENTED_PATH)
        X_src  = aug_df.drop(columns=["Label"])
        y_src  = aug_df["Label"]
    else:
        if use_ctgan:
            print("  [WARN] CTGAN file not found -- using real training data.")
        X_src = pd.read_parquet(X_TRAIN)
        y_src = pd.read_parquet(Y_TRAIN)["Label"]
 
    parts = []
    rng   = np.random.RandomState(42)
 
    # BENIGN
    benign_idx = y_src[y_src == "BENIGN"].index
    b_sample   = rng.choice(benign_idx, size=min(BENIGN_SAMPLE_SIZE, len(benign_idx)), replace=False)
    parts.append(pd.concat([X_src.loc[b_sample], y_src.loc[b_sample].rename("Label")], axis=1))
    print(f"  BENIGN samples           : {len(b_sample):,}")
 
    # Each specialist class
    for cls in specialist_classes:
        cls_idx = y_src[y_src == cls].index
        if len(cls_idx) == 0:
            print(f"  [WARN] '{cls}' not found in training data -- skipping.")
            continue
        s_idx = rng.choice(cls_idx, size=min(REAL_SAMPLE_CAP, len(cls_idx)), replace=False)
        parts.append(pd.concat([X_src.loc[s_idx], y_src.loc[s_idx].rename("Label")], axis=1))
        print(f"  '{cls}' samples  : {len(s_idx):,}")
 
    combined = pd.concat(parts, ignore_index=True)
    X_out    = combined.drop(columns=["Label"])
    y_out    = combined["Label"]
 
    print(f"\n  Total specialist training rows : {len(combined):,}")
    print(f"  Classes in training            : {sorted(y_out.unique())}")
    return X_out, y_out
 
 
def build_label_maps(y):
    labels      = sorted(y.unique())
    label_to_id = {l: i for i, l in enumerate(labels)}
    id_to_label = {i: l for l, i in label_to_id.items()}
    return label_to_id, id_to_label
 
 
def train_specialist(X_train, y_train, label_to_id):
    print("\nTraining specialist XGBoost model...")
    y_encoded = y_train.map(label_to_id)
 
    # Per-sample weights: upweight minority classes so XSS/SQLInjection
    # are not drowned out by BruteForce even within the specialist set
    class_counts = y_train.value_counts()
    max_count    = class_counts.max()
    weights      = y_train.map(lambda l: max_count / class_counts[l])
 
    model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=2,
        gamma=0.1,
        random_state=42,
        n_jobs=-1,
        objective="multi:softmax",
        num_class=len(label_to_id),
        eval_metric="mlogloss",
    )
    model.fit(X_train, y_encoded, sample_weight=weights)
    print("  Specialist model trained")
    return model
 
 
def evaluate_comparison(X_valid, y_valid, specialist, label_to_id, id_to_label, specialist_classes):
    """Side-by-side: general vs specialist on all specialist classes."""
    y_enc_pred   = specialist.predict(X_valid)
    y_spec_pred  = pd.Series([id_to_label.get(i, "BENIGN") for i in y_enc_pred])
    y_valid_reset = y_valid.reset_index(drop=True)
 
    if os.path.exists(GENERAL_MODEL_PATH):
        y_gen_pred = pd.Series(predict_with_model(GENERAL_MODEL_PATH, X_valid))
    else:
        print(f"  [WARN] General model not found at {GENERAL_MODEL_PATH}.")
        y_gen_pred = None
 
    rows = []
    for cls in sorted(set(specialist_classes + ["BENIGN"])):
        mask = y_valid_reset == cls
        if mask.sum() == 0:
            continue
 
        y_true_sub = y_valid_reset[mask]
        y_spec_sub = y_spec_pred[mask]
 
        spec_f1  = f1_score(y_true_sub, y_spec_sub, average="weighted", zero_division=0, labels=[cls])
        spec_rec = recall_score(y_true_sub, y_spec_sub, average="weighted", zero_division=0, labels=[cls])
        spec_pre = precision_score(y_true_sub, y_spec_sub, average="weighted", zero_division=0, labels=[cls])
 
        row = {
            "attack_type"         : cls,
            "support"             : int(mask.sum()),
            "specialist_precision": round(spec_pre, 4),
            "specialist_recall"   : round(spec_rec, 4),
            "specialist_f1"       : round(spec_f1,  4),
        }
 
        if y_gen_pred is not None:
            y_gen_sub = y_gen_pred[mask]
            gen_f1    = f1_score(y_true_sub, y_gen_sub, average="weighted", zero_division=0, labels=[cls])
            gen_rec   = recall_score(y_true_sub, y_gen_sub, average="weighted", zero_division=0, labels=[cls])
            gen_pre   = precision_score(y_true_sub, y_gen_sub, average="weighted", zero_division=0, labels=[cls])
            row.update({
                "general_precision": round(gen_pre, 4),
                "general_recall"   : round(gen_rec, 4),
                "general_f1"       : round(gen_f1,  4),
                "f1_improvement"   : round(spec_f1 - gen_f1, 4),
            })
 
        rows.append(row)
 
    return pd.DataFrame(rows), y_spec_pred, y_valid_reset
 
 
def print_comparison_report(report_df, specialist_classes):
    print("\n" + "=" * 75)
    print("  SPECIALIST vs GENERAL — FULL WEB-ATTACK FAMILY")
    print("=" * 75)
 
    has_gen = "general_f1" in report_df.columns
 
    display = report_df[report_df["attack_type"] != "BENIGN"]
 
    if has_gen:
        print(f"  {'Attack Type':<35} {'Support':>8} {'Gen F1':>8} {'Spec F1':>9} {'Delta':>8}")
        print("-" * 75)
        for _, row in display.iterrows():
            delta = row.get("f1_improvement", 0)
            arrow = "+" if delta > 0 else ("-" if delta < 0 else "=")
            print(
                f"  {row['attack_type']:<35} {row['support']:>8,} "
                f"{row.get('general_f1', 0):>8.4f} {row['specialist_f1']:>9.4f} "
                f"  {arrow} {abs(delta):.4f}"
            )
        avg_imp = display["f1_improvement"].mean()
        target  = display[display["attack_type"].isin(specialist_classes)]
        print(f"\n  Avg F1 delta -- all web-attack family : {avg_imp:+.4f}")
        if len(target):
            print(f"  Avg F1 delta -- original weak targets : {target['f1_improvement'].mean():+.4f}")
    else:
        for _, row in display.iterrows():
            print(f"  {row['attack_type']:<35} {row['support']:>8,} {row['specialist_f1']:>9.4f}")
 
 
def main():
    parser = argparse.ArgumentParser(
        description="Train specialist model for web-attack family classification."
    )
    parser.add_argument("--use-ctgan", action="store_true",
                        help="Use CTGAN-augmented training data if available.")
    parser.add_argument(
        "--specialist-scope", type=str, default="full-web-family",
        choices=["full-web-family", "weak-only"],
        help=(
            "full-web-family (default): train on all 4 web-attack classes so the "
            "ensemble can safely route the whole family. "
            "weak-only: train only on classes in weak_classes.txt (original behaviour)."
        )
    )
    parser.add_argument("--weak-classes", type=str, default=None,
                        help="Comma-separated override. Ignores --specialist-scope.")
    args = parser.parse_args()
 
    # Resolve which classes the specialist will cover
    if args.weak_classes:
        specialist_classes = [c.strip() for c in args.weak_classes.split(",") if c.strip()]
        print(f"Using manually specified classes: {specialist_classes}")
 
    elif args.specialist_scope == "full-web-family":
        specialist_classes = WEB_ATTACK_FAMILY
        print(f"Scope: full web-attack family: {specialist_classes}")
        print(
            "  Rationale: the ensemble routes the whole family to the specialist.\n"
            "  The specialist must therefore know ALL four classes, not just the weak two.\n"
            "  This prevents the BruteForce/Infiltration F1 collapse seen in earlier runs."
        )
 
    else:  # weak-only
        specialist_classes = load_weak_classes_from_file()
        if not specialist_classes:
            if os.path.exists(PER_CLASS_REPORT_PATH):
                df = pd.read_csv(PER_CLASS_REPORT_PATH)
                specialist_classes = df[df["f1_score"] < 0.70]["attack_type"].tolist()
            if not specialist_classes:
                print("[ERROR] No weak classes found. Run per_class_evaluation.py first.")
                raise SystemExit(1)
        print(f"Scope: weak classes only: {specialist_classes}")
 
    if not specialist_classes:
        print("No classes to train on.")
        raise SystemExit(0)
 
    # Build training data
    X_train, y_train = build_training_data(specialist_classes, args.use_ctgan)
 
    label_to_id, id_to_label = build_label_maps(y_train)
 
    # Train
    specialist = train_specialist(X_train, y_train, label_to_id)
 
    # Save — store specialist_classes (the full scope, including "strong" web-attack
    # classes) so the ensemble knows what to route
    os.makedirs("models", exist_ok=True)
    joblib.dump(
        {
            "model"             : specialist,
            "label_to_id"       : label_to_id,
            "id_to_label"       : id_to_label,
            "weak_classes"      : specialist_classes,   # used by EnsemblePredictor
            "specialist_scope"  : args.specialist_scope,
        },
        SPECIALIST_MODEL_PATH,
    )
    print(f"\nSpecialist model saved -> {SPECIALIST_MODEL_PATH}")
 
    # Evaluate
    print("\nLoading validation data for comparison...")
    X_valid = pd.read_parquet(X_VALID)
    y_valid = pd.read_parquet(Y_VALID)["Label"]
 
    report_df, y_spec_pred, y_valid_reset = evaluate_comparison(
        X_valid, y_valid, specialist, label_to_id, id_to_label, specialist_classes
    )
 
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    report_df.to_csv(SPECIALIST_REPORT_PATH, index=False)
 
    print_comparison_report(report_df, specialist_classes)
 
    print("\nOverall specialist metrics (full validation set):")
    print(f"  Accuracy   : {accuracy_score(y_valid_reset, y_spec_pred):.4f}")
    print(f"  Weighted F1: {f1_score(y_valid_reset, y_spec_pred, average='weighted', zero_division=0):.4f}")
 
 
if __name__ == "__main__":
    main()
