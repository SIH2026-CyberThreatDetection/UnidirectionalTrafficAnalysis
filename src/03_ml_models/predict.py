import joblib
import pandas as pd
from pathlib import Path

def run_live_scan(flow_data: dict, model_path: Path):
    """Simulates live SOC prediction for a single incoming network flow."""
    print(f"\n[!] INCOMING FLOW: {flow_data.get('src_ip')} -> {flow_data.get('dst_ip')}")
    
    if not model_path.exists():
        print("Error: AI Model offline.")
        return
    
    model = joblib.load(model_path)
    
    # The 12-Feature Golden Schema
    features = [
        'Destination Port', 'Flow Duration', 'Total Packets', 
        'Total Length of Packets', 'Flow Bytes/s', 'Flow Packets/s', 
        'Packet Length Max', 'Packet Length Mean', 'Average Packet Size', 
        'Down/Up Ratio', 'dns_query_length', 'dns_entropy'
    ]
    
    df = pd.DataFrame([flow_data])
    X = df[features].fillna(0)
    
    prediction = model.predict(X)[0]
    
    if prediction == -1:
        print(">>> [ALERT] ZERO-DAY THREAT DETECTED! Mathematical anomaly found.")
    else:
        print(">>> [OK] Traffic profile is normal.")

if __name__ == "__main__":
    print("--- NTRO LIVE THREAT DETECTION SYSTEM ---")
    model_file = Path("models/isolation_forest.pkl")
    
    # 1. Normal Web Browsing
    normal_flow = {
        'src_ip': '192.168.1.100', 'dst_ip': '104.18.32.7',
        'Destination Port': 443, 'Flow Duration': 1500000,
        'Total Packets': 15, 'Total Length of Packets': 3500,
        'Flow Bytes/s': 2333.33, 'Flow Packets/s': 10.0,
        'Packet Length Max': 500, 'Packet Length Mean': 233.33,
        'Average Packet Size': 233.33, 'Down/Up Ratio': 0,
        'dns_query_length': 0, 'dns_entropy': 0.0
    }
    
    # 2. Volumetric Data Exfiltration (e.g., Reverse Shell to C2)
    attack_flow = {
        'src_ip': '192.168.1.100', 'dst_ip': '45.33.12.9',
        'Destination Port': 4444, 'Flow Duration': 50000,
        'Total Packets': 8500, 'Total Length of Packets': 9500000,
        'Flow Bytes/s': 190000.0, 'Flow Packets/s': 170.0,
        'Packet Length Max': 1460, 'Packet Length Mean': 1117.6,
        'Average Packet Size': 1117.6, 'Down/Up Ratio': 0,
        'dns_query_length': 0, 'dns_entropy': 0.0
    }

    # 3. Stealthy DNS Tunneling (e.g., Cobalt Strike Beaconing)
    dns_tunnel_flow = {
        'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8',
        'Destination Port': 53, 'Flow Duration': 4500,
        'Total Packets': 45, 'Total Length of Packets': 5800,
        'Flow Bytes/s': 1288.8, 'Flow Packets/s': 10.0,
        'Packet Length Max': 250, 'Packet Length Mean': 128.8,
        'Average Packet Size': 128.8, 'Down/Up Ratio': 0,
        'dns_query_length': 185, 'dns_entropy': 4.92 # High entropy payload
    }

    run_live_scan(normal_flow, model_file)
    run_live_scan(attack_flow, model_file)
    run_live_scan(dns_tunnel_flow, model_file)
