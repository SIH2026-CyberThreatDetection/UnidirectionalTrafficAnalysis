import pandas as pd
import numpy as np
import logging
import json
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def clean_csv_training_data(raw_dir: Path, output_file: Path):
    all_csvs = list(raw_dir.glob("*.csv"))
    logging.info(f"Training Mode: Merging {len(all_csvs)} CSV files...")
    df_list = [pd.read_csv(f, encoding="utf-8", low_memory=False) for f in all_csvs]
    df = pd.concat(df_list, ignore_index=True)
    
    # 1. Strip spaces and destroy illegal bidirectional columns (CASE-INSENSITIVE)
    df.columns = df.columns.str.strip()
    bwd_cols = [c for c in df.columns if 'bwd' in c.lower() or 'backward' in c.lower()]
    df.drop(columns=bwd_cols, inplace=True)
    df.columns = [c.replace('Fwd ', '').replace('Forward ', '') for c in df.columns]
    
    # 2. Defuse the Infinity and Missing Values Bomb
    logging.info("Scrubbing infinities and NaN values...")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)
    
    # 3. Fix the Negative Time Bug
    if 'Flow Duration' in df.columns:
        logging.info("Removing impossible negative flow durations...")
        df = df[df['Flow Duration'] >= 0]
    
    output_file.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_file, index=False)
    logging.info(f"Saved compliant unidirectional dataset to {output_file}")

def clean_live_telemetry(telemetry_file: Path, output_file: Path):
    logging.info(f"Live Mode: Validating JSONL telemetry from {telemetry_file}...")
    data = []
    with open(telemetry_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip(): data.append(json.loads(line.strip()))
    df = pd.DataFrame(data)
    
    # Enforce numeric logic and valid port ranges
    numeric_cols = ["src_port", "dst_port", "duration", "bytes_out", "bytes_in", "packets_out", "packets_in"]
    for col in numeric_cols:
        if col in df.columns: df[col] = pd.to_numeric(df[col], errors="coerce")
        
    if "src_port" in df.columns and "dst_port" in df.columns:
        valid_ports = df["src_port"].between(0, 65535) & df["dst_port"].between(0, 65535)
        df = df[valid_ports].copy()
        
    for col in ["bytes_out", "bytes_in", "packets_out", "packets_in"]:
        if col in df.columns: df[col] = df[col].fillna(0)
        
    output_file.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_file, index=False)
    logging.info(f"Saved cleaned live telemetry to {output_file}")

if __name__ == "__main__":
    raw_csv_dir = Path("data/raw")
    live_jsonl_file = Path("data/telemetry/normalized/sample_telemetry.jsonl")
    
    # Auto-detect Environment
    if list(raw_csv_dir.glob("*.csv")):
        clean_csv_training_data(raw_csv_dir, Path("data/interim/cic_ids2017_clean.csv"))
    elif live_jsonl_file.exists():
        clean_live_telemetry(live_jsonl_file, Path("data/interim/clean_telemetry.csv"))
    else:
        logging.error("No valid training CSVs or live JSONL telemetry found.")

