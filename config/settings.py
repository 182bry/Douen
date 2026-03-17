# Raw dataset paths
CICIDS_PATH = "data/raw/cicids2017"
UNSW_PATH = "data/raw/unsw_nb15"
CTU13_PATH = "data/raw/ctu13"

# Processed dataset folder
PROCESSED_DATA_PATH = "data/processed"

# Ingested full datasets
CICIDS_OUTPUT = f"{PROCESSED_DATA_PATH}/cicids2017.parquet"
UNSW_OUTPUT = f"{PROCESSED_DATA_PATH}/unsw_nb15.parquet"
CTU13_OUTPUT = f"{PROCESSED_DATA_PATH}/ctu13.parquet"

# CICIDS temporal split outputs
CICIDS_TRAIN = f"{PROCESSED_DATA_PATH}/cicids_train.parquet"
CICIDS_VALID = f"{PROCESSED_DATA_PATH}/cicids_valid.parquet"
CICIDS_TEST = f"{PROCESSED_DATA_PATH}/cicids_test.parquet"

# Modeling datasets

X_TRAIN = "data/processed/X_train.parquet"
Y_TRAIN = "data/processed/y_train.parquet"

X_VALID = "data/processed/X_valid.parquet"
Y_VALID = "data/processed/y_valid.parquet"

X_TEST = "data/processed/X_test.parquet"
Y_TEST = "data/processed/y_test.parquet"

# Model output
MODEL_PATH = "models/random_forest_binary.pkl"