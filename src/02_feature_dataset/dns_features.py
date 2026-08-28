import logging
import math
from pathlib import Path
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def calculate_shannon_entropy(domain_str: str) -> float:
    """Calculates Shannon entropy to detect DGA/tunneling strings."""
    if not isinstance(domain_str, str) or not domain_str or domain_str == "nan":
        return 0.0
    entropy = 0.0
    length = len(domain_str)
    for char in set(domain_str):
        prob = domain_str.count(char) / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 4)

def extract_dns_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extracts query length, subdomain depth, and entropy."""
    logging.info("Extracting DNS and entropy features...")
    
    if "dns" in df.columns:
        # Safely force all nulls/floats to empty strings
        df["dns_query"] = df["dns"].fillna("").astype(str)
        
        # Catch literal "nan" strings created by CSV conversion
        df["dns_query"] = df["dns_query"].replace("nan", "")
        
        # Vectorized string length calculation (immune to float errors)
        df["dns_query_length"] = df["dns_query"].str.len().fillna(0).astype(int)
        df["dns_entropy"] = df["dns_query"].apply(calculate_shannon_entropy)
    else:
        df["dns_query_length"] = 0
        df["dns_entropy"] = 0.0

    logging.info("DNS features extracted successfully.")
    return df

if __name__ == "__main__":
    input_path = Path("data/processed/flow_features.csv")
    output_path = Path("data/processed/flow_features_with_dns.csv")
    
    if input_path.exists():
        df = pd.read_csv(input_path)
        df_updated = extract_dns_features(df)
        df_updated.to_csv(output_path, index=False)
        logging.info(f"Saved dataset with DNS features to {output_path}")
    else:
        logging.error(f"Missing input file: {input_path}")
