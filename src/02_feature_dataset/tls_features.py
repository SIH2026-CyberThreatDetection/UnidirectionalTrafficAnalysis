import logging
from pathlib import Path
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def extract_tls_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extracts TLS/QUIC metadata indicators for encrypted malware detection."""
    logging.info("Extracting TLS/QUIC metadata features...")
    
    # Check if TLS column exists from M1
    if "tls" in df.columns:
        # Safely handle nulls and string conversions
        df["tls_raw"] = df["tls"].fillna("").astype(str).replace("nan", "")
        
        # Binary indicator: Does this flow use encryption?
        df["is_encrypted"] = (df["tls_raw"] != "").astype(int)
        
        # In a massive dataset, you would parse the exact TLS version (e.g., TLSv1.2).
        # For this M2 baseline, knowing if it's encrypted vs plaintext is the critical first feature.
    else:
        df["is_encrypted"] = 0

    logging.info("TLS features extracted successfully.")
    return df

if __name__ == "__main__":
    # Take the output from the DNS script
    input_path = Path("data/processed/flow_features_with_dns.csv")
    
    # Save as the absolute final M2 feature matrix
    output_path = Path("data/processed/final_feature_matrix.csv")
    
    if input_path.exists():
        df = pd.read_csv(input_path)
        df_updated = extract_tls_features(df)
        df_updated.to_csv(output_path, index=False)
        logging.info(f"Saved FINAL feature matrix to {output_path}")
    else:
        logging.error(f"Missing input file: {input_path}")
