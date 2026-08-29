import pandas as pd
import numpy as np
import logging
import json
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def clean_telemetry(telemetry_file: Path, output_file: Path):
    logging.info(f"Phase 5.1: Loading and cleaning telemetry from {telemetry_file}...")
    
    if not telemetry_file.exists():
        logging.error(f"CRITICAL: Cannot find {telemetry_file}. Did M1 finish running?")
        return

    # 1. Load the unified M1 JSONL output
    data = []
    with open(telemetry_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip(): 
                data.append(json.loads(line.strip()))
    df = pd.DataFrame(data)
    
    # 2. Enforce Numeric Logic
    numeric_cols = ["src_port", "dst_port", "duration", "bytes_out", "bytes_in", "packets_out", "packets_in", "suricata_alert_count"]
    for col in numeric_cols:
        if col in df.columns: 
            df[col] = pd.to_numeric(df[col], errors="coerce")
            # Domain specific imputation: Missing packets/bytes/alerts inherently equal 0
            df[col] = df[col].fillna(0)
            
    # 3. Defuse Infinities
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
            
    # 4. Scrub Impossible Values (Valid Ports and Positive Time)
    if "src_port" in df.columns and "dst_port" in df.columns:
        valid_ports = df["src_port"].between(0, 65535) & df["dst_port"].between(0, 65535)
        df = df[valid_ports].copy()
        
    if "duration" in df.columns:
        logging.info("Removing impossible negative flow durations...")
        df = df[df["duration"] >= 0]
        
    # 5. Enforce SIH 26145 Unidirectional Constraint (Safety Check)
    bwd_cols = [c for c in df.columns if 'bwd' in c.lower() or 'backward' in c.lower() or 'resp_' in c.lower()]
    if bwd_cols:
        logging.info(f"Stripping forbidden bidirectional columns: {bwd_cols}")
        df.drop(columns=bwd_cols, inplace=True)

    # Output the clean interim file for flow_features.py
    output_file.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_file, index=False)
    logging.info(f"Saved compliant, unified dataset to {output_file}")

if __name__ == "__main__":
    # ONLY ONE ENTRY POINT: The master telemetry file from M1
    master_jsonl = Path("data/telemetry/normalized/master_telemetry.jsonl")
    clean_output = Path("data/interim/clean_telemetry.csv")
    
    clean_telemetry(master_jsonl, clean_output)
