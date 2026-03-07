# Data paths
RAW_DATA_PATH = "data/raw"
PROCESSED_DATA_PATH = "data/processed"

# Processed dataset
COMBINED_DATASET = f"{PROCESSED_DATA_PATH}/cicids_combined.parquet"

# Train/test datasets
X_TRAIN = f"{PROCESSED_DATA_PATH}/X_train.parquet"
X_TEST = f"{PROCESSED_DATA_PATH}/X_test.parquet"
Y_TRAIN = f"{PROCESSED_DATA_PATH}/y_train.parquet"
Y_TEST = f"{PROCESSED_DATA_PATH}/y_test.parquet"

# Model output
MODEL_PATH = "models/random_forest.pkl"