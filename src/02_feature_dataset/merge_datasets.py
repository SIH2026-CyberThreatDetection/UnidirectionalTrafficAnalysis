import pandas as pd
from pathlib import Path

def main():
    print("--- Fusing Historical and Synthetic Datasets ---")
    train_path = Path("data/processed/train/train.csv")
    dns_path = Path("data/interim/synthetic_dns_tunnels.csv")
    out_path = Path("data/processed/train/master_train.csv")
    
    print("Loading 1.98M row CIC-IDS2017 training matrix (This takes a moment)...")
    df_cic = pd.read_csv(train_path, low_memory=False)
    
    print("Loading Synthetic DNS Tunneling data...")
    df_dns = pd.read_csv(dns_path)
    
    # Backfill the new DNS features into historical data as zeros
    df_cic['dns_query_length'] = 0.0
    df_cic['dns_entropy'] = 0.0
    
    print("Concatenating datasets...")
    df_master = pd.concat([df_cic, df_dns], ignore_index=True)
    
    # Shuffle the dataset so the DNS attacks aren't stacked at the very end
    print("Shuffling master training matrix...")
    df_master = df_master.sample(frac=1, random_state=42).reset_index(drop=True)
    
    df_master.to_csv(out_path, index=False)
    print(f"\nSuccess! Master training file saved to {out_path}")
    print(f"Total Master Rows: {len(df_master)}")

if __name__ == "__main__":
    main()
