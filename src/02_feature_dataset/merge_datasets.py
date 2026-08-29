import pandas as pd
import numpy as np
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def merge_synthetic_data():
    print("--- Fusing Historical and Synthetic Datasets (Pre-Split) ---")
    
    # Target the pre-scaled matrix, not the post-scaled train.csv
    historical_path = Path("data/processed/final_feature_matrix.csv")
    synthetic_path = Path("data/interim/synthetic_dns_tunnels.csv")
    
    if not historical_path.exists() or not synthetic_path.exists():
        logging.error("Missing required datasets! Ensure tls_features and generate_dns_tunnels have run.")
        return

    print("Loading Historical Feature Matrix...")
    df_hist = pd.read_csv(historical_path, low_memory=False)
    
    print("Loading Synthetic DNS Tunnels...")
    df_sync = pd.read_csv(synthetic_path)
    
    # 1. Align the Timeline (Crucial for split.py)
    # We must give synthetic data valid timestamps so split.py naturally distributes it 
    # across train, val, and test sets when it sorts chronologically.
    if 'timestamp' in df_hist.columns:
        df_hist['timestamp'] = pd.to_datetime(df_hist['timestamp'], errors='coerce')
        start_time = df_hist['timestamp'].min()
        end_time = df_hist['timestamp'].max()
        
        # Scatter the synthetic attacks randomly throughout the historical timeline
        time_deltas = (end_time - start_time).total_seconds() * np.random.rand(len(df_sync))
        df_sync['timestamp'] = start_time + pd.to_timedelta(time_deltas, unit='s')
        
    print("Concatenating datasets...")
    df_master = pd.concat([df_hist, df_sync], ignore_index=True)
    
    # 2. Save OVER the final_feature_matrix so split.py processes the whole dataset
    df_master.to_csv(historical_path, index=False)
    
    print(f"\nSuccess! Fused dataset saved back to {historical_path}")
    print(f"Total Master Rows: {len(df_master)}")
    print("\nCRITICAL NEXT STEP: You MUST re-run split.py now so the Scaler can learn the synthetic data!")

if __name__ == "__main__":
    merge_synthetic_data()
