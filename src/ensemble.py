from __future__ import annotations
 
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
 
from src.config.settings import X_VALID, Y_VALID, PROCESSED_DIR
 
GENERAL_MODEL_PATH    = "models/xgboost_multiclass.pkl"
SPECIALIST_MODEL_PATH = "models/specialist_model.pkl"
ENSEMBLE_REPORT_PATH  = os.path.join(PROCESSED_DIR, "ensemble_report.csv")
 
# Confidence threshold for the targeted trigger.
# Only applies to flows the general model predicts as an adjacent class.
DEFAULT_CONFIDENCE_THRESHOLD = 0.80
 
# Classes the confusion matrix showed absorbing misclassified XSS/SQL flows.
# If the general model predicts one of these with low confidence, route to specialist.
ADJACENT_CLASSES = [
    "DoS slowloris",
    "DoS GoldenEye",
    "DoS Hulk",
    "DoS Slowhttptest",
    "BENIGN",
    "FTP-Patator",
]
 
 
class EnsemblePredictor:
    """
    Two-stage ensemble: general model -> specialist for web-attack family.
 
    Routing triggers (either fires -> specialist is used):
      Trigger 1 (label):      general predicts any web-attack family class
      Trigger 2 (targeted):   general predicts an adjacent class AND
                               confidence < confidence_threshold
    """
 
    WEB_ATTACK_FAMILY = [
        "WebAttack_BruteForce",
        "WebAttack_XSS",
        "WebAttack_SQLInjection",
        "Infiltration",
    ]
 
    def __init__(
        self,
        general_path:         str   = GENERAL_MODEL_PATH,
        specialist_path:      str   = SPECIALIST_MODEL_PATH,
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    ):
        if not os.path.exists(general_path):
            raise FileNotFoundError(f"General model not found: {general_path}")
        if not os.path.exists(specialist_path):
            raise FileNotFoundError(f"Specialist model not found: {specialist_path}")
 
        print(f"Loading general model    : {general_path}")
        gen_obj               = joblib.load(general_path)
        self._gen_model       = gen_obj["model"]
        self._gen_id_to_label = gen_obj["id_to_label"]
 
        print(f"Loading specialist model : {specialist_path}")
        spec_obj               = joblib.load(specialist_path)
        self._spec_model       = spec_obj["model"]
        self._spec_id_to_label = spec_obj["id_to_label"]
 
        # Classes the specialist was trained to handle (from saved metadata)
        self.specialist_classes = [
            c for c in spec_obj.get("weak_classes", [])
            if c != "BENIGN"
        ]
        if not self.specialist_classes:
            self.specialist_classes = [
                c for c in self._spec_id_to_label.values()
                if c != "BENIGN"
            ]
 
        # Trigger 1: route these labels directly
        self.routing_classes = sorted(
            set(self.specialist_classes) | set(self.WEB_ATTACK_FAMILY)
        )
 
        # Trigger 2: route adjacent-class predictions when confidence is low
        self.adjacent_classes       = ADJACENT_CLASSES
        self.confidence_threshold   = confidence_threshold
 
        print(f"Specialist targets       : {self.specialist_classes}")
        print(f"Label routing trigger    : {self.routing_classes}")
        print(f"Adjacent classes trigger : confidence < {self.confidence_threshold} "
              f"when general predicts {self.adjacent_classes}")
 
    # Internal helpers
    def _build_route_mask(self, gen_labels, gen_proba):
        """
        Returns (route_mask, label_trigger, targeted_conf_trigger).
 
        label_trigger         : general predicted a web-attack family class
        targeted_conf_trigger : general predicted an adjacent class
                                AND max probability < threshold
        """
        # Trigger 1 — label
        label_trigger = np.isin(gen_labels, self.routing_classes)
 
        # Trigger 2 — targeted confidence
        max_proba             = gen_proba.max(axis=1)
        predicted_adjacent    = np.isin(gen_labels, self.adjacent_classes)
        targeted_conf_trigger = predicted_adjacent & (max_proba < self.confidence_threshold)
 
        route_mask = label_trigger | targeted_conf_trigger
        return route_mask, label_trigger, targeted_conf_trigger
 
    def _spec_predict(self, X_sub):
        raw = self._spec_model.predict(X_sub)
        return np.array([self._spec_id_to_label[i] for i in raw])
 
    # Public API
 
    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """Return final string label predictions using ensemble routing."""
        gen_raw    = self._gen_model.predict(X)
        gen_labels = np.array([self._gen_id_to_label[i] for i in gen_raw])
        gen_proba  = self._gen_model.predict_proba(X)
 
        route_mask, _, _ = self._build_route_mask(gen_labels, gen_proba)
        final_labels = gen_labels.copy()
 
        if route_mask.sum() > 0:
            X_routed = X.iloc[route_mask] if hasattr(X, "iloc") else X[route_mask]
            final_labels[route_mask] = self._spec_predict(X_routed)
 
        return final_labels
 
    def predict_with_routing_info(self, X: pd.DataFrame):
        """
        Returns (final_labels, gen_labels, route_mask, label_trigger, conf_trigger).
        """
        gen_raw    = self._gen_model.predict(X)
        gen_labels = np.array([self._gen_id_to_label[i] for i in gen_raw])
        gen_proba  = self._gen_model.predict_proba(X)
 
        route_mask, label_trig, conf_trig = self._build_route_mask(gen_labels, gen_proba)
        final_labels = gen_labels.copy()
 
        if route_mask.sum() > 0:
            X_routed = X.iloc[route_mask] if hasattr(X, "iloc") else X[route_mask]
            final_labels[route_mask] = self._spec_predict(X_routed)
 
        return final_labels, gen_labels, route_mask, label_trig, conf_trig
 
 
# Evaluation
 
def _per_class_f1(y_true, y_pred):
    report = classification_report(y_true, y_pred, zero_division=0, output_dict=True)
    return {
        k: v["f1-score"]
        for k, v in report.items()
        if isinstance(v, dict) and k not in ("macro avg", "weighted avg", "accuracy")
    }
 
 
def evaluate_ensemble(predictor, X_valid, y_valid, show_routing=False):
 
    print("\n" + "=" * 65)
    print("  ENSEMBLE EVALUATION  (v4 — targeted confidence trigger)")
    print("=" * 65)
 
    final_pred, gen_pred, route_mask, label_trig, conf_trig = \
        predictor.predict_with_routing_info(X_valid)
 
    final_pred = pd.Series(final_pred, index=y_valid.index)
    gen_pred   = pd.Series(gen_pred,   index=y_valid.index)
 
    n_total      = len(y_valid)
    n_routed     = int(route_mask.sum())
    n_label      = int(label_trig.sum())
    n_conf       = int(conf_trig.sum())
    n_both       = int((label_trig & conf_trig).sum())
 
    print(f"\nRows evaluated                 : {n_total:,}")
    print(f"Routed to specialist           : {n_routed:,}  ({n_routed/n_total*100:.2f}%)")
    print(f"  via label trigger            : {n_label:,}  "
          f"(general predicted web-attack family)")
    print(f"  via targeted conf trigger    : {n_conf:,}  "
          f"(adjacent class + confidence < {predictor.confidence_threshold})")
    print(f"  both triggers fired          : {n_both:,}")
 
    # Overall metrics
    print("\n── Overall metrics ─────────────────────────────────────────")
    for name, pred in [("General model", gen_pred), ("Ensemble      ", final_pred)]:
        acc  = accuracy_score(y_valid, pred)
        f1w  = f1_score(y_valid, pred, average="weighted", zero_division=0)
        prec = precision_score(y_valid, pred, average="weighted", zero_division=0)
        rec  = recall_score(y_valid, pred, average="weighted", zero_division=0)
        print(f"\n  {name}")
        print(f"    Accuracy          : {acc:.4f}")
        print(f"    Weighted Precision: {prec:.4f}")
        print(f"    Weighted Recall   : {rec:.4f}")
        print(f"    Weighted F1       : {f1w:.4f}")
 
    # Per-class comparison
    print("\n── Per-class F1 comparison ──────────────────────────────────")
    gen_f1s = _per_class_f1(y_valid, gen_pred)
    ens_f1s = _per_class_f1(y_valid, final_pred)
 
    rows = []
    for cls in sorted(y_valid.unique()):
        gen_f1  = gen_f1s.get(cls, 0.0)
        ens_f1  = ens_f1s.get(cls, 0.0)
        delta   = ens_f1 - gen_f1
        routed  = cls in predictor.routing_classes
        support = int((y_valid == cls).sum())
        rows.append({
            "attack_type"   : cls,
            "support"       : support,
            "general_f1"    : round(gen_f1, 4),
            "ensemble_f1"   : round(ens_f1, 4),
            "f1_delta"      : round(delta,  4),
            "routed_to_spec": routed,
        })
 
    comparison_df = pd.DataFrame(rows)
 
    header = f"  {'Class':<35} {'Support':>8} {'Gen F1':>8} {'Ens F1':>9} {'Delta':>8}  Routed?"
    print(header)
    print("  " + "-" * 80)
    for _, row in comparison_df.iterrows():
        arrow  = "+" if row["f1_delta"] > 0.001 else ("-" if row["f1_delta"] < -0.001 else "=")
        routed = "YES" if row["routed_to_spec"] else "   "
        print(
            f"  {row['attack_type']:<35} {row['support']:>8,} "
            f"{row['general_f1']:>8.4f} {row['ensemble_f1']:>9.4f} "
            f"  {arrow} {abs(row['f1_delta']):.4f}  {routed}"
        )
 
    routed_rows = comparison_df[comparison_df["routed_to_spec"]]
    spec_rows   = comparison_df[
        comparison_df["attack_type"].isin(predictor.specialist_classes)
    ]
    print(f"\n  Avg delta F1 -- routed classes         : {routed_rows['f1_delta'].mean():+.4f}")
    print(f"  Avg delta F1 -- specialist target (XSS/SQL): "
          f"{spec_rows['f1_delta'].mean():+.4f}")
 
    # Routing breakdown
    if show_routing and n_routed > 0:
        print("\n── Routing breakdown ────────────────────────────────────────")
        y_true_r = y_valid.reset_index(drop=True)
        y_fin_r  = final_pred.reset_index(drop=True)
        y_gen_r  = gen_pred.reset_index(drop=True)
 
        print("\n  True labels among ALL routed rows:")
        for lbl, n in y_true_r[route_mask].value_counts().items():
            print(f"    {lbl:<35} {n:>6,}")
 
        # Breakdown: what did the targeted confidence trigger catch?
        if n_conf > 0:
            only_conf = conf_trig & ~label_trig   # caught by conf but NOT label
            print(f"\n  True labels caught ONLY by confidence trigger ({only_conf.sum():,} rows):")
            for lbl, n in y_true_r[only_conf].value_counts().items():
                print(f"    {lbl:<35} {n:>6,}")
            print(f"\n  General predicted (for confidence-trigger rows):")
            for lbl, n in y_gen_r[only_conf].value_counts().items():
                print(f"    {lbl:<35} {n:>6,}")
 
        correct_after  = (y_fin_r[route_mask] == y_true_r[route_mask]).sum()
        correct_before = (y_gen_r[route_mask] == y_true_r[route_mask]).sum()
        print(f"\n  Correct after routing  : {correct_after:,} / {n_routed:,} "
              f"({correct_after/n_routed*100:.1f}%)")
        print(f"  Correct before routing : {correct_before:,} / {n_routed:,} "
              f"({correct_before/n_routed*100:.1f}%)")
        print(f"  Net gain in routed rows: {correct_after - correct_before:+,}")
 
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    comparison_df.to_csv(ENSEMBLE_REPORT_PATH, index=False)
    print(f"\nEnsemble report saved -> {ENSEMBLE_REPORT_PATH}")
 
    return comparison_df
 
 
# Main
 
def main():
    parser = argparse.ArgumentParser(
        description="Evaluate the ensemble (general + specialist) predictor."
    )
    parser.add_argument("--evaluate",     action="store_true")
    parser.add_argument("--show-routing", action="store_true")
    parser.add_argument(
        "--confidence-threshold", type=float,
        default=DEFAULT_CONFIDENCE_THRESHOLD,
        help=f"Route adjacent-class predictions to specialist when general "
             f"confidence < this (default: {DEFAULT_CONFIDENCE_THRESHOLD})"
    )
    parser.add_argument("--general-path",    type=str, default=GENERAL_MODEL_PATH)
    parser.add_argument("--specialist-path", type=str, default=SPECIALIST_MODEL_PATH)
    args = parser.parse_args()
 
    predictor = EnsemblePredictor(
        general_path=args.general_path,
        specialist_path=args.specialist_path,
        confidence_threshold=args.confidence_threshold,
    )
 
    if args.evaluate:
        print("\nLoading validation data...")
        X_valid = pd.read_parquet(X_VALID)
        y_valid = pd.read_parquet(Y_VALID)["Label"]
        evaluate_ensemble(predictor, X_valid, y_valid, show_routing=args.show_routing)
    else:
        print("Ensemble loaded.")
        print(f"Specialist target classes : {predictor.specialist_classes}")
        print(f"Routing trigger classes   : {predictor.routing_classes}")
        print(f"Confidence threshold      : {predictor.confidence_threshold}")
 
 
if __name__ == "__main__":
    main()