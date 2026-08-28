import pandas as pd
import joblib
import warnings
import json
import numpy as np
from datetime import datetime
from pathlib import Path

# Suppress sklearn warnings for clean terminal output
warnings.filterwarnings("ignore")

def run_m4_json_terminal():
    print("===================================================")
    print("   NTRO 26145: M4 JSON PREDICTION STREAM ACTIVE    ")
    print("===================================================\n")
    
    iso_forest = joblib.load("models/isolation_forest.pkl")
    xgboost_model = joblib.load("models/xgboost_classifier.pkl")
    
    # Map the AI's integer output back to the SIH text strings
    target_names = {
        0: "benign",
        1: "ddos",
        2: "botnet_c2",
        3: "dns_tunneling",
        4: "encrypted_malware",
        5: "reconnaissance",
        6: "data_exfiltration"
    }
    
    features = [
        'Destination Port', 'Flow Duration', 'Total Packets', 
        'Total Length of Packets', 'Flow Bytes/s', 'Flow Packets/s', 
        'Packet Length Max', 'Packet Length Mean', 'Average Packet Size', 
        'Down/Up Ratio', 'dns_query_length', 'dns_entropy'
    ]
    
    live_traffic = pd.DataFrame([
        [443, 50000, 10, 5000, 100000.0, 200.0, 1200, 500.0, 550.0, 1.0, 0, 0.0],          # Normal
        [80, 1000, 5000, 250000, 250000000.0, 5000000.0, 50, 50.0, 50.0, 0.0, 0, 0.0],       # DDoS
        [22, 200000, 50, 4000, 20000.0, 250.0, 80, 80.0, 80.0, 0.5, 0, 0.0],                 # Brute Force (Encrypted Malware)
        [53, 15000, 4, 600, 40000.0, 266.6, 300, 150.0, 175.0, 1.0, 185, 4.2],               # DNS Tunneling
        [4444, 800000, 15, 950000, 1187500.0, 18.7, 65000, 63000.0, 64000.0, 0.1, 0, 0.0]    # Unknown Zero-Day
    ], columns=features)
    
    for i, (index, row) in enumerate(live_traffic.iterrows()):
        flow_data = pd.DataFrame([row])
        port = int(row['Destination Port'])
        
        # Engine 1: Anomaly Detection
        is_anomaly = iso_forest.predict(flow_data)[0] == -1
        
        # Engine 2: Multiclass Classification & Confidence Scoring
        xgboost_probs = xgboost_model.predict_proba(flow_data)[0]
        xgboost_pred_idx = int(np.argmax(xgboost_probs))
        confidence = float(xgboost_probs[xgboost_pred_idx])
        
        threat_class = target_names[xgboost_pred_idx]
        
        # Dual-Engine Logic: If XGBoost misses it but IsoForest catches it
        if is_anomaly and xgboost_pred_idx == 0:
            threat_class = "zero_day_anomaly"
            confidence = 0.8500 # Baseline confidence for mathematical anomalies
            
        # Only output alerts for malicious traffic (M4 doesn't need to see normal traffic)
        if threat_class != "benign":
            contract = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "flow_id": f"192.168.1.100:{port}",
                "threat_class": threat_class,
                "confidence": round(confidence, 4),
                "model_version": "M3-DualEngine-v1.0",
                "feature_version": "M2-v1.0",
                "evidence": [
                    {"feature": "Destination Port", "value": port},
                    {"feature": "Flow Bytes/s", "value": float(row['Flow Bytes/s'])},
                    {"feature": "dns_entropy", "value": float(row['dns_entropy'])}
                ]
            }
            
            # Print the machine-readable JSON object
            print(json.dumps(contract, indent=2))

if __name__ == "__main__":
    run_m4_json_terminal()
