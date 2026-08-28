import json
import logging
from pathlib import Path
import pandas as pd

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def load_telemetry(file_path: Path) -> pd.DataFrame:
    """Loads JSONL telemetry into a Pandas DataFrame."""
    logging.info(f"Loading M1 telemetry from {file_path}")
    data = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if line_str:
                data.append(json.loads(line_str))
    return pd.DataFrame(data)

def validate_and_clean(df: pd.DataFrame) -> pd.DataFrame:
    """Applies M2 cleaning and validation rules."""
    initial_rows = len(df)
    
    # 1. Enforce numeric types for core fields
    numeric_cols = [
        "src_port", "dst_port", "duration", 
        "bytes_out", "bytes_in", "packets_out", "packets_in"
    ]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    # 2. Validate Port Ranges (0-65535)
    valid_ports = (
        df["src_port"].between(0, 65535, inclusive="both") & 
        df["dst_port"].between(0, 65535, inclusive="both")
    )
    df = df[valid_ports].copy()
    
    # 3. Validate logical bounds (non-negative duration and byte counts)
    valid_bounds = (df["duration"] >= 0) & (df["bytes_out"] >= 0) & (df["bytes_in"] >= 0)
    df = df[valid_bounds].copy()
    
    # 4. Handle Missing Values
    core_metrics = ["bytes_out", "bytes_in", "packets_out", "packets_in"]
    for col in core_metrics:
        if col in df.columns:
            df[col] = df[col].fillna(0)
    
    # 5. Check Duplicate Signatures
    if "flow_id" in df.columns and "timestamp" in df.columns:
        duplicates = df.duplicated(subset=["flow_id", "timestamp"]).sum()
        logging.info(f"Suspicious flow duplicates found: {duplicates}")

    final_rows = len(df)
    logging.info(f"Cleaning complete. Kept {final_rows}/{initial_rows} valid rows.")
    return df

if __name__ == "__main__":
    input_path = Path("data/telemetry/normalized/sample_telemetry.jsonl")
    output_path = Path("data/interim/clean_telemetry.csv")
    
    if input_path.exists():
        df_raw = load_telemetry(input_path)
        df_clean = validate_and_clean(df_raw)
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        df_clean.to_csv(output_path, index=False)
        logging.info(f"Saved clean interim dataset to {output_path}")
    else:
        logging.error(f"Input file not found: {input_path}")
