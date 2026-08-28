import joblib
from pathlib import Path
from data_loader import load_dataset

def main():
    print("--- ML Evaluation Pipeline ---")
    
    test_path = Path("data/processed/test/test.csv")
    model_path = Path("models/isolation_forest.pkl")
    
    if not test_path.exists() or not model_path.exists():
        print("Error: Missing test data or trained model.")
        return

    # 1. Load unseen future traffic
    df_test = load_dataset(test_path)
    
    # 2. Extract the exact same features used in training
    features = [
        'total_bytes', 'total_packets', 'byte_ratio', 'packet_ratio', 
        'bytes_per_second', 'packets_per_second', 'dns_query_length', 
        'dns_entropy', 'is_encrypted'
    ]
    X_test = df_test[features].fillna(0)
    
    # 3. Wake up the trained AI
    print(f"Loading trained AI from {model_path}...")
    model = joblib.load(model_path)
    
    # 4. Make predictions (Isolation Forest outputs 1 for Normal, -1 for Anomaly)
    print("Scanning test traffic for zero-day threats...\n")
    predictions = model.predict(X_test)
    
    # 5. Format and display the results
    df_test['ai_prediction'] = predictions
    df_test['threat_status'] = df_test['ai_prediction'].map({1: 'Normal', -1: 'THREAT DETECTED'})
    
    print("=== LIVE DETECTION RESULTS (TEST SET) ===")
    
    # Handle missing columns gracefully just in case
    display_cols = ['timestamp', 'src_ip', 'dst_ip']
    existing_cols = [col for col in display_cols if col in df_test.columns]
    existing_cols.append('threat_status')
    
    print(df_test[existing_cols].to_string(index=False))
    
    # Print Summary
    anomalies = (predictions == -1).sum()
    normals = (predictions == 1).sum()
    print(f"\nSummary: {normals} Normal flows, {anomalies} Anomalies flagged.")

if __name__ == "__main__":
    main()
