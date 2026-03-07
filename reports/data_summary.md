# DOUEN Data Summary

## Dataset
- Source: CICIDS2017 MachineLearningCSV
- Combined rows: 2,827,876
- Columns: 79
- Features used after split: 78
- Label column: `Label`

## Data Engineering Steps Completed
- Loaded and merged all 8 CICIDS2017 CSV files
- Stripped whitespace from column names
- Replaced infinite values with NaN
- Dropped rows with missing values
- Saved combined dataset to Parquet
- Normalized selected label names
- Split dataset into train/test sets using stratified sampling
- Saved processed train/test datasets to Parquet

## Current Processed Files
- `data/processed/cicids_combined.parquet`
- `data/processed/X_train.parquet`
- `data/processed/X_test.parquet`
- `data/processed/y_train.parquet`
- `data/processed/y_test.parquet`

## Train/Test Split
- Train shape: 2,262,300 × 78
- Test shape: 565,576 × 78

## Notes
- Dataset is highly imbalanced
- Rare classes include Heartbleed, Infiltration, and WebAttack_SQLInjection
- Further feature scaling, feature selection, and class balancing may be added during model development
