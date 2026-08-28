import joblib
import pandas as pd
from pathlib import Path
from data_loader import load_dataset
from anomaly_detector import build_anomaly_detector

# Point to the newly fused master dataset
TRAIN_PATH = Path("data/processed/train/master_train.csv")
MODEL_OUT = Path("models/isolation_forest.pkl")

def main():
    print("ML training pipeline initialized.")
    print(f"Expected data: {TRAIN_PATH}")
    
    df = load_dataset(TRAIN_PATH)
    
    # The 10 core volumetric features + 2 new synthetic DNS features
    features = [
        'Destination Port', 'Flow Duration', 'Total Packets', 
        'Total Length of Packets', 'Flow Bytes/s', 'Flow Packets/s', 
        'Packet Length Max', 'Packet Length Mean', 'Average Packet Size', 
        'Down/Up Ratio', 'dns_query_length', 'dns_entropy'
    ]
    
    X_train = df[features].fillna(0)
    
    print("Building Multi-Vector Anomaly Detector...")
    model = build_anomaly_detector()
    
    print(f"Training model on {len(X_train)} combined rows (This might take a minute)...")
    model.fit(X_train)
    
    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_OUT)
    print(f"Upgraded model successfully trained and saved to {MODEL_OUT}")

if __name__ == "__main__":
    main()
