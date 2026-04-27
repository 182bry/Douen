import argparse
import os
import warnings
warnings.filterwarnings("ignore")
 
import numpy as np
import pandas as pd
 
from src.config.settings import (
    X_TRAIN,
    Y_TRAIN,
    PROCESSED_DIR,
)
 
CTGAN_AUGMENTED_PATH = os.path.join(PROCESSED_DIR, "ctgan_augmented_train.parquet")
CTGAN_REPORT_PATH    = os.path.join(PROCESSED_DIR, "ctgan_generation_report.csv")
 
DEFAULT_MIN_SAMPLES = 1000
DEFAULT_TARGET      = 1500
DEFAULT_EPOCHS      = 100
 
 
def _check_ctgan():
    try:
        from ctgan import CTGAN  # noqa: F401
        return True
    except ImportError:
        print(
            "\n[ERROR] ctgan is not installed.\n"
            "  Install it with:  pip install ctgan\n"
            "  Then re-run this script.\n"
        )
        return False
 
 
def identify_weak_classes(y_train: pd.Series, min_samples: int) -> dict:
    counts = y_train.value_counts()
    weak   = counts[counts < min_samples].to_dict()
 
    print(f"\nClass counts in training set:")
    for label, n in counts.items():
        flag = "  <- WEAK (will synthesise)" if label in weak else ""
        print(f"  {label:<40} {n:>8,}{flag}")
 
    print(f"\nFound {len(weak)} weak class(es) with < {min_samples} samples.")
    return weak
 
 
def synthesise_class(X_class, label, n_generate, epochs):
    from ctgan import CTGAN
 
    n_real = len(X_class)
    print(f"\n  Synthesising '{label}' ({n_real} real rows -> +{n_generate} synthetic)...")
 
    if n_real < 5:
        print(f"  [WARN] Only {n_real} real samples - CTGAN quality may be poor.")
 
    # For very small classes, repeat rows so CTGAN has enough to fit
    if n_real < 50:
        repeats = max(2, 50 // n_real)
        X_fit   = pd.concat([X_class] * repeats, ignore_index=True)
        print(f"  [INFO] Repeated real data {repeats}x to give CTGAN enough rows.")
    else:
        X_fit = X_class
 
    discrete_cols = [
        col for col in X_fit.columns
        if pd.api.types.is_integer_dtype(X_fit[col]) and X_fit[col].nunique() < 50
    ]
 
    model = CTGAN(epochs=epochs, verbose=False)
    model.fit(X_fit, discrete_columns=discrete_cols)
 
    synthetic = model.sample(n_generate)
    synthetic = synthetic.reindex(columns=X_class.columns)
 
    for col in X_class.select_dtypes(include=[np.number]).columns:
        synthetic[col] = synthetic[col].clip(X_class[col].min(), X_class[col].max())
 
    print(f"  Generated {len(synthetic)} synthetic rows for '{label}'")
    return synthetic
 
 
def run_ctgan_augmentation(min_samples, target, epochs):
    if not _check_ctgan():
        raise SystemExit(1)
 
    print("Loading training data...")
    X_train = pd.read_parquet(X_TRAIN)
    y_train = pd.read_parquet(Y_TRAIN)["Label"]
 
    print(f"Training set: {X_train.shape[0]:,} rows x {X_train.shape[1]} features")
 
    weak_classes = identify_weak_classes(y_train, min_samples)
 
    if not weak_classes:
        print("\nNo weak classes found - no CTGAN augmentation needed.")
        aug_df = X_train.copy()
        aug_df["Label"] = y_train.values
        aug_df.to_parquet(CTGAN_AUGMENTED_PATH, index=False)
        print(f"Saved original training set -> {CTGAN_AUGMENTED_PATH}")
        return aug_df
 
    report_rows   = []
    synthetic_dfs = []
 
    for label, real_count in weak_classes.items():
        n_to_generate = max(0, target - real_count)
        if n_to_generate <= 0:
            continue
 
        mask    = y_train == label
        X_class = X_train[mask].copy()
 
        try:
            synth          = synthesise_class(X_class, label, n_to_generate, epochs)
            synth["Label"] = label
            synthetic_dfs.append(synth)
            report_rows.append({
                "label"       : label,
                "real_count"  : real_count,
                "synth_count" : len(synth),
                "total_count" : real_count + len(synth),
                "status"      : "success",
            })
        except Exception as exc:
            print(f"  [WARN] Failed to synthesise '{label}': {exc}")
            report_rows.append({
                "label"       : label,
                "real_count"  : real_count,
                "synth_count" : 0,
                "total_count" : real_count,
                "status"      : f"failed: {exc}",
            })
 
    real_df          = X_train.copy()
    real_df["Label"] = y_train.values
 
    if synthetic_dfs:
        all_synthetic = pd.concat(synthetic_dfs, ignore_index=True)
        augmented_df  = pd.concat([real_df, all_synthetic], ignore_index=True)
        print(f"\nAugmented dataset: {len(augmented_df):,} rows (+{len(all_synthetic):,} synthetic)")
    else:
        augmented_df = real_df
        print("\nNo synthetic rows added.")
 
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    augmented_df.to_parquet(CTGAN_AUGMENTED_PATH, index=False)
    print(f"Saved augmented training set -> {CTGAN_AUGMENTED_PATH}")
 
    report_df = pd.DataFrame(report_rows)
    report_df.to_csv(CTGAN_REPORT_PATH, index=False)
    print(f"Saved generation report     -> {CTGAN_REPORT_PATH}")
 
    print("\n" + "=" * 55)
    print("  CTGAN Augmentation Report")
    print("=" * 55)
    print(report_df.to_string(index=False))
 
    return augmented_df
 
 
def main():
    parser = argparse.ArgumentParser(
        description="CTGAN synthetic data augmentation for minority attack classes."
    )
    parser.add_argument("--min-samples", type=int, default=DEFAULT_MIN_SAMPLES)
    parser.add_argument("--target",      type=int, default=DEFAULT_TARGET)
    parser.add_argument("--epochs",      type=int, default=DEFAULT_EPOCHS)
    args = parser.parse_args()
 
    run_ctgan_augmentation(
        min_samples=args.min_samples,
        target=args.target,
        epochs=args.epochs,
    )
 
 
if __name__ == "__main__":
    main()
