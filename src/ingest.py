import pandas as pd
import numpy as np
import os

from config.settings import RAW_DATA_PATH, COMBINED_DATASET

OUTPUT_PATH = COMBINED_DATASET


def load_csv_files(path):
    files = [f for f in os.listdir(path) if f.endswith(".csv")]
    
    dataframes = []
    
    for file in files:
        file_path = os.path.join(path, file)
        print(f"Loading {file}...")
        
        df = pd.read_csv(file_path)
        
        # clean column names
        df.columns = df.columns.str.strip()
        
        dataframes.append(df)
    
    return pd.concat(dataframes, ignore_index=True)


def clean_data(df):
    
    # replace infinity values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # drop rows with missing values
    df.dropna(inplace=True)
    
    return df


def main():
    
    print("Loading datasets...")
    df = load_csv_files(RAW_DATA_PATH)
    
    print("Cleaning data...")
    df = clean_data(df)
    
    print("Saving processed dataset...")
    df.to_parquet(OUTPUT_PATH, index=False)
    
    print("Done!")
    print(df.shape)


if __name__ == "__main__":
    main()