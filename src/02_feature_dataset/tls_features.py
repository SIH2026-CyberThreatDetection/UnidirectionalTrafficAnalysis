import logging
import math
from pathlib import Path
import pandas as pd
import ast

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def calculate_sni_entropy(sni: str) -> float:
    """Calculates Shannon entropy of the SNI to detect DGA."""
    if pd.isna(sni) or not sni or sni == '-' or sni.lower() == 'nan':
        return 0.0
    entropy = 0.0
    length = len(sni)
    for x in set(sni):
        p_x = float(sni.count(x)) / length
        entropy -= p_x * math.log(p_x, 2)
    return round(float(entropy), 4)

def parse_tls_dict(tls_val):
    """Safely extracts the TLS version and SNI from a stringified dictionary."""
    if pd.isna(tls_val) or str(tls_val).strip().lower() in ['nan', 'none', '']:
        return pd.Series(["None", ""])
    
    version, sni = "None", ""
    if isinstance(tls_val, str):
        try:
            tls_dict = ast.literal_eval(tls_val)
            if isinstance(tls_dict, dict):
                version = str(tls_dict.get('version') or "None")
                sni = str(tls_dict.get('server_name') or "")
        except (ValueError, SyntaxError):
            pass
    elif isinstance(tls_val, dict):
        version = str(tls_val.get('version') or "None")
        sni = str(tls_val.get('server_name') or "")
        
    return pd.Series([version, sni])

def extract_tls_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extracts TLS metadata and SNI entropy for encrypted malware detection."""
    logging.info("Extracting advanced TLS metadata and SNI entropy...")
    
    if "tls" in df.columns:
        # Extract version and SNI simultaneously
        df[["tls_version", "sni"]] = df["tls"].apply(parse_tls_dict)
        
        # Binary indicator
        df["is_encrypted"] = (df["tls_version"] != "None").astype(int)
        
        # SNI Entropy (Your logic)
        df["sni_entropy"] = df["sni"].apply(calculate_sni_entropy)
        
        # Deprecated crypto flags
        df["uses_deprecated_crypto"] = df["tls_version"].apply(
            lambda x: 1 if x in ["SSLv2", "SSLv3", "TLSv10", "TLSv11"] else 0
        )
        
        # Drop temporary parsing columns
        df.drop(columns=["tls", "sni"], inplace=True)
    else:
        df["is_encrypted"] = 0
        df["sni_entropy"] = 0.0
        df["uses_deprecated_crypto"] = 0

    if "dns" in df.columns:
        df = df.drop(columns=["dns"])

    logging.info("Advanced TLS features extracted successfully.")
    return df

if __name__ == "__main__":
    input_path = Path("data/processed/flow_features_with_dns.csv")
    output_path = Path("data/processed/final_feature_matrix.csv")
    
    if input_path.exists():
        df = pd.read_csv(input_path)
        df_updated = extract_tls_features(df)
        df_updated.to_csv(output_path, index=False)
        logging.info(f"Saved FINAL feature matrix to {output_path}")
    else:
        logging.error(f"Missing input file: {input_path}")
