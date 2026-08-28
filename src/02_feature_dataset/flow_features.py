import pandas as pd
import logging
from pathlib import Path
import numpy as np

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Calculates behavioral network features required by NTRO."""
    logging.info("Engineering base flow features...")
    
    # 1. Directional Asymmetry (Step 23)
    # Adding 1 prevents mathematical division by zero errors
    df["total_bytes"] = df["bytes_out"] + df["bytes_in"]
    df["total_packets"] = df["packets_out"] + df["packets_in"]
    df["byte_ratio"] = (df["bytes_out"] + 1) / (df["bytes_in"] + 1)
    df["packet_ratio"] = (df["packets_out"] + 1) / (df["packets_in"] + 1)
    
    # 2. Rate Features (Step 24)
    # Replace exactly 0 duration with a tiny number (1 microsecond) to avoid dividing by zero
    safe_duration = df["duration"].clip(lower=1e-6)
    df["bytes_per_second"] = df["total_bytes"] / safe_duration
    df["packets_per_second"] = df["total_packets"] / safe_duration

    # Round to 4 decimal places for cleaner matrices
    cols_to_round = ["byte_ratio", "packet_ratio", "bytes_per_second", "packets_per_second"]
    df[cols_to_round] = df[cols_to_round].round(4)

    logging.info("Engineered rate and asymmetry features successfully.")
    return df

if __name__ == "__main__":
    input_path = Path("data/interim/clean_telemetry.csv")
    output_path = Path("data/processed/flow_features.csv") 
    
    if input_path.exists():
        # Read the cleaned data
        df = pd.read_csv(input_path)
        
        # Calculate features
        df_features = engineer_features(df)
        
        # Save to processed folder
        output_path.parent.mkdir(parents=True, exist_ok=True)
        df_features.to_csv(output_path, index=False)
        logging.info(f"Saved engineered features to {output_path}")
    else:
        logging.error(f"Could not find clean dataset at {input_path}")
