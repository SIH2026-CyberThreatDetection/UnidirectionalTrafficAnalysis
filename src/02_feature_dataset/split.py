import logging
from pathlib import Path
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def time_aware_split(df: pd.DataFrame) -> tuple:
    """Splits data chronologically to prevent data leakage."""
    logging.info("Sorting data chronologically for leakage-safe split...")
    
    # 1. Ensure timestamp is treated as a real date/time and sort it
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values("timestamp").reset_index(drop=True)
    else:
        logging.warning("No timestamp found! Falling back to raw row split.")

    # 2. Chronological Split (70% Train, 15% Validation, 15% Test)
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
    input_path = Path("data/processed/final_feature_matrix.csv")
    
    # Define output paths
    train_path = Path("data/processed/train/train.csv")
    val_path = Path("data/processed/val/val.csv")
    test_path = Path("data/processed/test/test.csv")
    
    if input_path.exists():
        df = pd.read_csv(input_path)
        
        # Execute the safe split
        train_df, val_df, test_df = time_aware_split(df)
        
        # Ensure directories exist and save
        train_path.parent.mkdir(parents=True, exist_ok=True)
        val_path.parent.mkdir(parents=True, exist_ok=True)
        test_path.parent.mkdir(parents=True, exist_ok=True)
        
        train_df.to_csv(train_path, index=False)
        val_df.to_csv(val_path, index=False)
        test_df.to_csv(test_path, index=False)
        
        logging.info("Successfully saved train, val, and test datasets.")
    else:
        logging.error(f"Missing input file: {input_path}")
