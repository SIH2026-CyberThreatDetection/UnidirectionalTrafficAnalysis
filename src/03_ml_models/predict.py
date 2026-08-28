import joblib
import pandas as pd
from pathlib import Path

def run_live_scan(flow_data: dict):
    """Simulates live SOC prediction for a single incoming network flow."""
    print(f"\n[!] INCOMING FLOW: {flow_data.get('src_ip')} -> {flow_data.get('dst_ip')}")
    
    model_path = Path("models/isolation_forest.pkl")
    if not model_path.exists():
        print("Error: AI Model offline.")
        return
    
    # Load the trained brain
    model = joblib.load(model_path)
    
    features = [
        'total_bytes', 'total_packets', 'byte_ratio', 'packet_ratio', 
        'bytes_per_second', 'packets_per_second', 'dns_query_length', 
        'dns_entropy', 'is_encrypted'
    ]
    
    # Convert the live dictionary to a dataframe
    df = pd.DataFrame([flow_data])
    
    # Ensure all required math features exist (fill missing with 0)
    for col in features:
        if col not in df.columns:
            df[col] = 0.0
            
    X = df[features]
    
    # AI predicts the traffic
    prediction = model.predict(X)[0]
    
    if prediction == -1:
        print(">>> [ALERT] ZERO-DAY THREAT DETECTED! Mathematical anomaly found.")
    else:
        print(">>> [OK] Traffic profile is normal.")

if __name__ == "__main__":
    print("--- NTRO LIVE THREAT DETECTION SYSTEM ---")
    
    # 1. Simulate Normal Web Browsing (Small downloads)
    normal_flow = {
        'src_ip': '192.168.1.100',
        'dst_ip': '104.18.32.7',
        'total_bytes': 3500,
        'total_packets': 20,
        'byte_ratio': 0.1,  # Mostly downloading
        'packet_ratio': 0.3,
        'bytes_per_second': 1200.0,
        'packets_per_second': 15.0,
        'is_encrypted': 1
    }
    
    # 2. Simulate Data Exfiltration Attack (Massive outbound upload)
    attack_flow = {
        'src_ip': '192.168.1.100',
        'dst_ip': '45.33.12.9',
        'total_bytes': 9500000,
        'total_packets': 8500,
        'byte_ratio': 8500.0, # Huge asymmetry (Sending WAY more than receiving)
        'packet_ratio': 4000.0,
        'bytes_per_second': 950000.0, # Super high throughput
        'packets_per_second': 2000.0,
        'is_encrypted': 1
    }

    # Run the live scanner
    run_live_scan(normal_flow)
    run_live_scan(attack_flow)
