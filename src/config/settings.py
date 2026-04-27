# Raw dataset paths
CICIDS_PATH = "data/raw/cicids2017"
UNSW_PATH = "data/raw/unsw_nb15"
CTU13_PATH = "data/raw/ctu13"

# Processed dataset folder
import os
 
# ─────────────────────────────────────────────
# Base directories
# ─────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR       = os.path.join(BASE_DIR, "data")
RAW_DIR        = os.path.join(DATA_DIR, "raw")
PROCESSED_DIR  = os.path.join(DATA_DIR, "processed")
MODELS_DIR     = os.path.join(BASE_DIR, "models")
 
# ─────────────────────────────────────────────
# Raw data paths
# ─────────────────────────────────────────────
CICIDS_PATH = os.path.join(RAW_DIR, "cicids2017")   # folder containing the 8 CSVs
 
# ─────────────────────────────────────────────
# Processed / ingested parquet
# ─────────────────────────────────────────────
CICIDS_OUTPUT = os.path.join(PROCESSED_DIR, "cicids2017.parquet")
 
# ─────────────────────────────────────────────
# Temporal split parquets (full rows + labels)
# ─────────────────────────────────────────────
CICIDS_TRAIN = os.path.join(PROCESSED_DIR, "cicids_train.parquet")
CICIDS_VALID = os.path.join(PROCESSED_DIR, "cicids_valid.parquet")
CICIDS_TEST  = os.path.join(PROCESSED_DIR, "cicids_test.parquet")
 
# ─────────────────────────────────────────────
# Feature / label parquets (model-ready)
# ─────────────────────────────────────────────
X_TRAIN = os.path.join(PROCESSED_DIR, "X_train.parquet")
Y_TRAIN = os.path.join(PROCESSED_DIR, "y_train.parquet")
 
X_VALID = os.path.join(PROCESSED_DIR, "X_valid.parquet")
Y_VALID = os.path.join(PROCESSED_DIR, "y_valid.parquet")
 
X_TEST  = os.path.join(PROCESSED_DIR, "X_test.parquet")
Y_TEST  = os.path.join(PROCESSED_DIR, "y_test.parquet")
 
# ─────────────────────────────────────────────
# Model paths
# ─────────────────────────────────────────────
MODEL_PATH                = os.path.join(MODELS_DIR, "random_forest_binary.pkl")
MULTICLASS_MODEL_PATH     = os.path.join(MODELS_DIR, "random_forest_multiclass.pkl")
XGBOOST_BINARY_PATH       = os.path.join(MODELS_DIR, "xgboost_binary.pkl")
XGBOOST_MULTICLASS_PATH   = os.path.join(MODELS_DIR, "xgboost_multiclass.pkl")
ANOMALY_MODEL_PATH        = os.path.join(MODELS_DIR, "isolation_forest.pkl")
 
# ─────────────────────────────────────────────
# Alert correlation output
# ─────────────────────────────────────────────
ALERTS_RAW        = os.path.join(PROCESSED_DIR, "alerts_raw.csv")
ALERTS_CORRELATED = os.path.join(PROCESSED_DIR, "alerts_correlated.csv")
 
# ─────────────────────────────────────────────
# Ensure output directories exist at import time
# ─────────────────────────────────────────────
for _dir in [PROCESSED_DIR, MODELS_DIR]:
    os.makedirs(_dir, exist_ok=True)