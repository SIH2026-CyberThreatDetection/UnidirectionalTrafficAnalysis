import pandas as pd
import numpy as np
import math
import random
from pathlib import Path

def shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string to detect encoded malware payloads."""
    if not data: return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log(p_x, 2)
    return round(entropy, 4)

def generate_dns_tunneling_traffic(num_samples=10000):
    print(f"Generating {num_samples} synthetic unidirectional DNS flows...")
    
    # Base realistic domains for normal traffic
    normal_domains = ['google.com', 'microsoft.com', 'aws.amazon.com', 'github.com', 'ntro.gov.in']
    
    data = []
    for _ in range(num_samples):
        is_malicious = random.choice([0, 1])
        
        if is_malicious:
            # Synthetic covert channel: Base32/Hex encoded payloads
            payload_length = random.randint(50, 220)
            chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
            subdomain = ''.join(random.choice(chars) for _ in range(payload_length))
            domain = f"{subdomain}.evil-c2.net"
            
            # Unidirectional attack profile (Outbound beaconing)
            duration = random.uniform(0.01, 2.0)
            bytes_out = random.randint(1500, 8000)
            packets_out = random.randint(10, 100)
            
        else:
            # Normal DNS resolution
            domain = random.choice(normal_domains)
            duration = random.uniform(0.05, 5.0)
            bytes_out = random.randint(40, 250)
            packets_out = random.randint(1, 4)
            
        # Build the flow using the EXACT schema from our M2 pipeline
        flow = {
            'dst_port': 53,
            'duration': duration,
            'bytes_out': bytes_out,
            'bytes_in': 0,  # Unidirectional constraint
            'packets_out': packets_out,
            'packets_in': 0,
            
            # Engineered ratios from flow_features.py
            'total_bytes': bytes_out,
            'total_packets': packets_out,
            'byte_ratio': round((bytes_out + 1) / 1.0, 4), 
            'packet_ratio': round((packets_out + 1) / 1.0, 4),
            'bytes_per_second': round(bytes_out / max(duration, 1e-6), 4),
            'packets_per_second': round(packets_out / max(duration, 1e-6), 4),
            
            # DNS and TLS specific features
            'dns_query_length': len(domain),
            'dns_entropy': shannon_entropy(domain),
            'is_encrypted': 0, # DNS over UDP is plaintext
            'uses_deprecated_crypto': 0,
            
            # The Target Label for XGBoost
            'is_attack': is_malicious
        }
        
        data.append(flow)
        
    df = pd.DataFrame(data)
    out_path = Path("data/interim/synthetic_dns_tunnels.csv")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)
    
    print(f"Saved synthetic DNS telemetry to {out_path}")
    print(f"Malicious flows generated: {df['is_attack'].sum()}")
    return df

if __name__ == "__main__":
    generate_dns_tunneling_traffic()
