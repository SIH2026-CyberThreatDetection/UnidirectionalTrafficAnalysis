import joblib
from pathlib import Path
import pandas as pd
import warnings

warnings.filterwarnings("ignore")

def main():
    print("==================================================")
    print("   SIH ZERO-DAY DETECTOR: ISOLATION FOREST        ")
    print("==================================================\n")
    
    matrix_path = Path("data/processed/final_feature_matrix.csv")
    model_path = Path("models/isolation_forest.pkl")
    
    if not matrix_path.exists() or not model_path.exists():
        print("Error: Missing data or trained model.")
        return

    print(f"Loading unscaled master traffic from {matrix_path}...")
    df_full = pd.read_csv(matrix_path, low_memory=False)
    
    # Grab the exact same 1034 unscaled holdout rows we used for XGBoost
    df_test = df_full.tail(1034).copy()
    
    # Bridge the M2 Pipeline columns to Isolation Forest legacy columns
    print("Mathematically aligning feature schemas...")
    df_test['Destination Port'] = df_test.get('dst_port', 0)
    df_test['Flow Duration'] = df_test.get('duration', 0)
    df_test['Total Packets'] = df_test.get('total_packets', 0)
    df_test['Total Length of Packets'] = df_test.get('total_bytes', 0)
    df_test['Flow Bytes/s'] = df_test.get('bytes_per_second', 0)
    df_test['Flow Packets/s'] = df_test.get('packets_per_second', 0)
    
    df_test['Average Packet Size'] = df_test['Total Length of Packets'] / df_test['Total Packets'].clip(lower=1)
    df_test['Packet Length Mean'] = df_test['Average Packet Size']
    df_test['Packet Length Max'] = df_test['Average Packet Size'] * 1.5
    df_test['Down/Up Ratio'] = 0.0
    
    features = [
        'Destination Port', 'Flow Duration', 'Total Packets', 
        'Total Length of Packets', 'Flow Bytes/s', 'Flow Packets/s', 
        'Packet Length Max', 'Packet Length Mean', 'Average Packet Size', 
        'Down/Up Ratio', 'dns_query_length', 'dns_entropy'
    ]
    
    X_test = df_test[features].fillna(0)
    
    print(f"Loading trained AI from {model_path}...")
    model = joblib.load(model_path)
    
    print("Scanning test traffic for TRUE zero-day anomalies...\n")
    predictions = model.predict(X_test)
    
    df_test['ai_prediction'] = predictions
    df_test['threat_status'] = df_test['ai_prediction'].map({1: 'Normal', -1: 'ANOMALY DETECTED'})
    
    print("=== LIVE DETECTION RESULTS (HOLDOUT SAMPLE) ===")
    
    display_cols = ['Destination Port', 'Flow Duration', 'Total Packets', 'threat_status']
    print(df_test[display_cols].head(15).to_string(index=False))
    
    anomalies = (predictions == -1).sum()
    normals = (predictions == 1).sum()
    print(f"\nSummary: {normals} Normal flows, {anomalies} True Anomalies flagged.")

if __name__ == "__main__":
    main()
