# DOUEN Data Summary

## Datasets

The project currently ingests and processes three cybersecurity datasets.

### CICIDS2017 MachineLearningCSV
- **Rows:** 2,827,876  
- **Columns:** 81  
- **Format:** CSV  
- **Label Column:** `Label`

### UNSW-NB15
- **Rows:** 257,673  
- **Columns:** 47  
- **Format:** CSV  
- **Label Columns:** `attack_cat`, `label`

### CTU-13
- **Rows:** 9,614,377  
- **Columns:** 13  
- **Format:** Parquet  
- **Label Column:** `label`

---

## Total Data Scale

**Total rows processed across all datasets:** **12,699,926**

This exceeds the project **minimum requirement of 5 million records** and also exceeds the **10 million+ stretch target**.

---

## Data Engineering Steps Completed

- Organized the raw data into separate dataset-specific folders
- Built a reproducible ingestion pipeline for:
  - CICIDS2017
  - UNSW-NB15
  - CTU-13
- Loaded multiple file formats:
  - CSV
  - Parquet
- Stripped whitespace from column names where needed
- Replaced infinite values with `NaN`
- Dropped rows with missing values
- Added dataset/source metadata columns where appropriate
- Saved each cleaned dataset as a processed **Parquet file**

---

## Current Processed Files

- `data/processed/cicids2017.parquet`
- `data/processed/unsw_nb15.parquet`
- `data/processed/ctu13.parquet`

---

## Key Observations

- The three datasets have **different schemas**, so they are currently processed separately rather than merged into one unified table.
- **CICIDS2017** contains rich flow-based intrusion detection features and many attack categories.
- **UNSW-NB15** already provides a built-in training/testing split.
- **CTU-13** is the **largest dataset** and has a much smaller, more compact feature set.
- The datasets use **different labeling styles**, so schema harmonization will need to be handled carefully before any cross-dataset modeling.

---

## Notes

- The project already satisfies the **data scale**, **multiple sources**, and **automated pipeline** minimum requirements.
- A **temporal or source-aware split** will be applied during preprocessing or model preparation rather than during ingestion.
- The primary candidate for the first full modeling pipeline is **CICIDS2017**, since it is the most complete and consistent dataset for **classification and anomaly detection**.
