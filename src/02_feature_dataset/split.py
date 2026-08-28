import argparse
import logging
from pathlib import Path
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def time_aware_split(df: pd.DataFrame) -> tuple:
    """Splits data chronologically to prevent data leakage."""
    logging.info("Sorting data chronologically for leakage-safe split...")
    
    # CIC-IDS2017 uses 'Timestamp' with a capital T. Check for both cases.
    time_col = None
    if "timestamp" in df.columns:
        time_col = "timestamp"
    elif "Timestamp" in df.columns:
        time_col = "Timestamp"

    if time_col:
        # Sort chronologically so the AI doesn't "see into the future" during training
        df[time_col] = pd.to_datetime(df[time_col], errors='coerce')
        df = df.sort_values(time_col).reset_index(drop=True)
    else:
        logging.warning("No timestamp column found! Falling back to raw row split.")

    # Chronological Split (70% Train, 15% Validation, 15% Test)
    total_rows = len(df)
    train_idx = int(total_rows * 0.70)
    val_idx = int(total_rows * 0.85)

    train_df = df.iloc[:train_idx]
    val_df = df.iloc[train_idx:val_idx]
    test_df = df.iloc[val_idx:]

    logging.info(f"Time-aware split complete:")
    logging.info(f" - Train rows: {len(train_df)}")
    logging.info(f" - Validation rows: {len(val_df)}")
    logging.info(f" - Test rows: {len(test_df)}")
    
    return train_df, val_df, test_df

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    # Default to the output of our new clean.py
    parser.add_argument("--input", default="data/interim/cic_ids2017_clean.csv")
    args = parser.parse_args()

    input_path = Path(args.input)
    
    # Define output paths
    train_path = Path("data/processed/train/train.csv")
    val_path = Path("data/processed/val/val.csv")
    test_path = Path("data/processed/test/test.csv")
    
    if input_path.exists():
        logging.info(f"Loading data from {input_path}...")
        # low_memory=False prevents pandas from crashing on massive CSV files
        df = pd.read_csv(input_path, low_memory=False)
        
        # Execute the safe split
        train_df, val_df, test_df = time_aware_split(df)
        
        # Ensure directories exist and save
        train_path.parent.mkdir(parents=True, exist_ok=True)
        val_path.parent.mkdir(parents=True, exist_ok=True)
        test_path.parent.mkdir(parents=True, exist_ok=True)
        
        logging.info("Saving split datasets (this may take a minute)...")
        train_df.to_csv(train_path, index=False)
        val_df.to_csv(val_path, index=False)
        test_df.to_csv(test_path, index=False)
        
        logging.info("Successfully saved train, val, and test datasets.")
    else:
        logging.error(f"Missing input file: {input_path}")
