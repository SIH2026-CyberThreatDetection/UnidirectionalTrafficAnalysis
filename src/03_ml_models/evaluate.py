import joblib
from pathlib import Path
import pandas as pd
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
    
    # 2. Extract the EXACT same features used in training
    features = [
        'Destination Port', 'Flow Duration', 'Total Packets', 
        'Total Length of Packets', 'Flow Bytes/s', 'Flow Packets/s', 
        'Packet Length Max', 'Packet Length Mean', 'Average Packet Size', 
        'Down/Up Ratio'
    ]
    X_test = df_test[features].fillna(0)
    
    # 3. Wake up the trained AI
    print(f"Loading trained AI from {model_path}...")
    model = joblib.load(model_path)
    
    # 4. Make predictions
    print("Scanning test traffic for zero-day threats...\n")
    predictions = model.predict(X_test)
    
    # 5. Format and display the results
    df_test['ai_prediction'] = predictions
    df_test['threat_status'] = df_test['ai_prediction'].map({1: 'Normal', -1: 'THREAT DETECTED'})
    
    print("=== LIVE DETECTION RESULTS (TEST SET SAMPLE) ===")
    
    # Display relevant historical columns alongside the prediction
    display_cols = ['Destination Port', 'Flow Duration', 'Total Packets']
    existing_cols = [col for col in display_cols if col in df_test.columns]
    existing_cols.append('threat_status')
    
    # Print the first 15 rows so it doesn't flood your terminal
    print(df_test[existing_cols].head(15).to_string(index=False))
    
    # Print Summary
    anomalies = (predictions == -1).sum()
    normals = (predictions == 1).sum()
    print(f"\nSummary: {normals} Normal flows, {anomalies} Anomalies flagged.")

if __name__ == "__main__":
    main()

