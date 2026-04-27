
import argparse
import os
import subprocess
import sys
import time
from datetime import datetime
 
from src.config.settings import (
    CICIDS_OUTPUT,
    CICIDS_TRAIN, CICIDS_VALID, CICIDS_TEST,
    X_TRAIN, Y_TRAIN, X_VALID, Y_VALID, X_TEST, Y_TEST,
    MODEL_PATH, MULTICLASS_MODEL_PATH,
    XGBOOST_BINARY_PATH, XGBOOST_MULTICLASS_PATH,
    ANOMALY_MODEL_PATH,
    ALERTS_CORRELATED,
    PROCESSED_DIR,
)
 
# Paths
SRC_DIR      = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SRC_DIR)
PYTHON_EXEC  = sys.executable
 
# New model/data paths for specialist pipeline
CTGAN_AUGMENTED_PATH   = os.path.join(PROCESSED_DIR, "ctgan_augmented_train.parquet")
PER_CLASS_REPORT_PATH  = os.path.join(PROCESSED_DIR, "per_class_report.csv")
WEAK_CLASSES_PATH      = os.path.join(PROCESSED_DIR, "weak_classes.txt")
SPECIALIST_MODEL_PATH  = "models/specialist_model.pkl"
SPECIALIST_REPORT_PATH = os.path.join(PROCESSED_DIR, "specialist_report.csv")
ENSEMBLE_REPORT_PATH   = os.path.join(PROCESSED_DIR, "ensemble_report.csv")
 
 

# Stage definitions 
STAGES = [
    #Data pipeline 
    {
        "name": "ingest",
        "description": "Load CICIDS2017 CSVs → clean → save combined parquet",
        "cmd": [PYTHON_EXEC, "-m", "src.ingest"],
        "outputs": [CICIDS_OUTPUT],
    },
    {
        "name": "dataset_summary",
        "description": "Print dataset statistics (informational, always runs)",
        "cmd": [PYTHON_EXEC, "-m", "src.dataset_summary"],
        "outputs": [],
    },
    {
        "name": "preprocess",
        "description": "Temporal train/valid/test split + feature/label separation",
        "cmd": [PYTHON_EXEC, "-m", "src.preprocess"],
        "outputs": [
            CICIDS_TRAIN, CICIDS_VALID, CICIDS_TEST,
            X_TRAIN, Y_TRAIN, X_VALID, Y_VALID, X_TEST, Y_TEST,
        ],
    },
 
    #Standard model training
    {
        "name": "train_binary_rf",
        "description": "Train Random Forest binary classifier (BENIGN vs ATTACK)",
        "cmd": [PYTHON_EXEC, "-m", "src.train_model"],
        "outputs": [MODEL_PATH],
    },
    {
        "name": "train_multiclass_rf",
        "description": "Train Random Forest multiclass classifier (per attack type)",
        "cmd": [PYTHON_EXEC, "-m", "src.train_multiclass_model"],
        "outputs": [MULTICLASS_MODEL_PATH],
    },
    {
        "name": "train_xgboost_binary",
        "description": "Train XGBoost binary classifier",
        "cmd": [PYTHON_EXEC, "-m", "src.train_xgboost_model", "--mode", "binary"],
        "outputs": [XGBOOST_BINARY_PATH],
    },
    {
        "name": "train_xgboost_multiclass",
        "description": "Train XGBoost multiclass classifier",
        "cmd": [PYTHON_EXEC, "-m", "src.train_xgboost_model", "--mode", "multiclass"],
        "outputs": [XGBOOST_MULTICLASS_PATH],
    },
    {
        "name": "train_anomaly",
        "description": "Train Isolation Forest for zero-day / unknown threat detection",
        "cmd": [PYTHON_EXEC, "-m", "src.train_anomaly_model"],
        "outputs": [ANOMALY_MODEL_PATH],
    },
 
    #Standard evaluation 
    {
        "name": "evaluate_binary_rf",
        "description": "Evaluate RF binary model on validation set",
        "cmd": [
            PYTHON_EXEC, "-m", "src.evaluate_model",
            "--model-path", MODEL_PATH, "--mode", "binary",
        ],
        "outputs": [],
    },
    {
        "name": "evaluate_multiclass_rf",
        "description": "Evaluate RF multiclass model on validation set",
        "cmd": [
            PYTHON_EXEC, "-m", "src.evaluate_model",
            "--model-path", MULTICLASS_MODEL_PATH, "--mode", "multiclass",
        ],
        "outputs": [],
    },
    {
        "name": "evaluate_xgboost_binary",
        "description": "Evaluate XGBoost binary model on validation set",
        "cmd": [
            PYTHON_EXEC, "-m", "src.evaluate_model",
            "--model-path", XGBOOST_BINARY_PATH, "--mode", "binary",
        ],
        "outputs": [],
    },
    {
        "name": "evaluate_xgboost_multiclass",
        "description": "Evaluate XGBoost multiclass model + per-class isolated analysis",
        "cmd": [
            PYTHON_EXEC, "-m", "src.evaluate_model",
            "--model-path", XGBOOST_MULTICLASS_PATH,
            "--mode", "multiclass",
            "--per-class",            
        ],
        "outputs": [],
    },
 
    #Per-class analysis + specialist pipeline
    {
        "name": "per_class_evaluation",
        "description": "Identify strong/weak classes; save weak_classes.txt for specialist",
        "cmd": [
            PYTHON_EXEC, "-m", "src.per_class_evaluation",
            "--model-path", XGBOOST_MULTICLASS_PATH,
            "--isolated",               # run isolated class analysis too
        ],
        "outputs": [PER_CLASS_REPORT_PATH, WEAK_CLASSES_PATH],
    },
    {
        "name": "ctgan_augmentation",
        "description": "Generate synthetic minority-class samples with CTGAN",
        "cmd": [PYTHON_EXEC, "-m", "src.train_ctgan"],
        "outputs": [CTGAN_AUGMENTED_PATH],
    },
    {
        "name": "train_specialist",
        "description": "Train specialist model on weak classes using CTGAN-augmented data",
        "cmd": [
            PYTHON_EXEC, "-m", "src.train_specialist_model",
            "--use-ctgan",                      # use CTGAN-augmented data
            "--specialist-scope", "full-web-family",  # train on all 4 web-attack classes
        ],
        "outputs": [SPECIALIST_MODEL_PATH],
    },
    {
        "name": "evaluate_specialist",
        "description": "Compare specialist vs general model on weak attack classes",
        "cmd": [
            PYTHON_EXEC, "-m", "src.evaluate_model",
            "--model-path", SPECIALIST_MODEL_PATH,
            "--mode", "multiclass",
            "--per-class",
        ],
        "outputs": [SPECIALIST_REPORT_PATH],
    },
 
    #Ensemble evaluation
    {
        "name": "evaluate_ensemble",
        "description": "Evaluate general + specialist ensemble; show routing & per-class improvement",
        "cmd": [
            PYTHON_EXEC, "-m", "src.ensemble",
            "--evaluate",
            "--show-routing",   # prints routing breakdown per class
        ],
        "outputs": [ENSEMBLE_REPORT_PATH],
    },
 
    #Alert correlation + dashboard
    {
        "name": "alert_correlation",
        "description": "Run alert correlation engine (demo mode)",
        "cmd": [PYTHON_EXEC, "-m", "src.alert_correlation", "--generate-demo"],
        "outputs": [ALERTS_CORRELATED],
    },
    {
        "name": "dashboard",
        "description": "Launch Streamlit dashboard",
        "cmd": [
            PYTHON_EXEC, "-m", "streamlit", "run",
            os.path.join(SRC_DIR, "dashboard.py"),
        ],
        "outputs": [],
        "interactive": True,
    },
]
 
 

# Helpers
def all_outputs_exist(stage):
    return len(stage["outputs"]) > 0 and all(
        os.path.exists(p) for p in stage["outputs"]
    )
 
 
def print_stage_header(stage):
    print(f"\n{'─' * 60}")
    print(f"[RUN]   {stage['name']}")
    print(f"        {stage['description']}")
    print(f"        CMD: {' '.join(stage['cmd'])}")
    print(f"{'─' * 60}")
 
 
def run_stage(stage, force=False):
    name = stage["name"]
 
    if stage.get("interactive"):
        print(f"\n[SKIP]  {name} — launch manually with:")
        print(f"        python -m streamlit run src/dashboard.py")
        return True
 
    if not force and all_outputs_exist(stage):
        print(f"\n[SKIP]  {name} — outputs already exist")
        return True
 
    print_stage_header(stage)
 
    start  = time.time()
    result = subprocess.run(stage["cmd"], cwd=PROJECT_ROOT)
    elapsed = time.time() - start
 
    if result.returncode != 0:
        print(f"\n[FAIL]  {name} exited with code {result.returncode}")
        return False
 
    print(f"\n[OK]    {name} completed in {elapsed:.1f}s")
    return True
 
 
def get_selected_stages(args):
    if args.only_stage:
        matching = [s for s in STAGES if s["name"] == args.only_stage]
        if not matching:
            print(f"Unknown stage: {args.only_stage}")
            print("Use --list to see available stages.")
            sys.exit(1)
        return matching
 
    if args.from_stage:
        stage_names = [s["name"] for s in STAGES]
        if args.from_stage not in stage_names:
            print(f"Unknown stage: {args.from_stage}")
            print("Use --list to see available stages.")
            sys.exit(1)
        return STAGES[stage_names.index(args.from_stage):]
 
    return STAGES
 
 
def list_stages():
    print("\nAvailable pipeline stages:")
    print(f"  {'Name':<35} Description")
    print("  " + "-" * 70)
    for stage in STAGES:
        marker = "  [interactive]" if stage.get("interactive") else ""
        print(f"  {stage['name']:<35} {stage['description']}{marker}")
 
 
# Main
 
def main():
    parser = argparse.ArgumentParser(
        description="Run the full AI-Powered SOC pipeline."
    )
    parser.add_argument(
        "--from", dest="from_stage", type=str, default=None,
        help="Start from this stage name (skip everything before it)",
    )
    parser.add_argument(
        "--only", dest="only_stage", type=str, default=None,
        help="Run only this single stage",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Re-run all stages even if outputs already exist",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List all available stage names and exit",
    )
    args = parser.parse_args()
 
    if args.list:
        list_stages()
        return
 
    stages_to_run = get_selected_stages(args)
 
    print("=" * 60)
    print("  AI-Powered SOC — Pipeline Runner")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print(f"Stages to run: {len(stages_to_run)}")
 
    for stage in stages_to_run:
        success = run_stage(stage, force=args.force)
        if not success:
            print(f"\nPipeline stopped at: {stage['name']}")
            print("Fix the error above and re-run with:")
            print(f"  python -m src.run_pipeline --from {stage['name']}")
            sys.exit(1)
 
    print("\n" + "=" * 60)
    print("  Pipeline complete!")
    print(f"  Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print("\nNext step → launch the dashboard manually with:")
    print("  python -m streamlit run src/dashboard.py")
 
 
if __name__ == "__main__":
    main()