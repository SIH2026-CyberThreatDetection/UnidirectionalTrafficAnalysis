from pathlib import Path
import joblib
from data_loader import load_dataset
from anomaly_detector import build_anomaly_detector

# Point to the strictly split M2 data
TRAIN_PATH = Path("data/processed/train/train.csv")
MODEL_OUT = Path("models/isolation_forest.pkl")

def main():
    print("ML training pipeline initialized.")
    print(f"Expected data: {TRAIN_PATH}")
    
    # 1. Load data using your custom module
    df = load_dataset(TRAIN_PATH)
    
    # 2. Select the M2 engineered features
    features = [
        'total_bytes', 'total_packets', 'byte_ratio', 'packet_ratio', 
        'bytes_per_second', 'packets_per_second', 'dns_query_length', 
        'dns_entropy', 'is_encrypted'
    ]
    X_train = df[features].fillna(0)
    
    # 3. Build model using your custom anomaly module
    print("Building Baseline Anomaly Detector...")
    model = build_anomaly_detector()
    
    print("Training model...")
    model.fit(X_train)
    
    # 4. Save the compiled model
    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_OUT)
    print(f"Model successfully trained and saved to {MODEL_OUT}")

if __name__ == "__main__":
    main()
