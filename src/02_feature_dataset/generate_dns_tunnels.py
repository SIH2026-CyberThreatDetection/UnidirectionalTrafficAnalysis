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
    return entropy

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
            
            # Malicious unidirectional flow characteristics (high volume, high entropy)
            flow = {
                'Destination Port': 53,
                'Flow Duration': random.randint(10, 5000), # Very fast beaconing
                'Total Packets': random.randint(10, 100),
                'Total Length of Packets': random.randint(1500, 8000), # Heavy TXT records
                'Flow Bytes/s': random.uniform(10000, 50000),
                'Flow Packets/s': random.uniform(100, 500),
                'Packet Length Max': random.randint(300, 512),
                'Packet Length Mean': random.uniform(200, 400),
                'Average Packet Size': random.uniform(200, 400),
                'Down/Up Ratio': 0, # Strictly unidirectional requirement
                'dns_query_length': len(domain),
                'dns_entropy': shannon_entropy(domain),
                'is_attack': 1
            }
        else:
            # Normal DNS resolution
            domain = random.choice(normal_domains)
            flow = {
                'Destination Port': 53,
                'Flow Duration': random.randint(5000, 200000),
                'Total Packets': random.randint(1, 4),
                'Total Length of Packets': random.randint(40, 250),
                'Flow Bytes/s': random.uniform(10, 500),
                'Flow Packets/s': random.uniform(1, 10),
                'Packet Length Max': random.randint(50, 120),
                'Packet Length Mean': random.uniform(30, 80),
                'Average Packet Size': random.uniform(30, 80),
                'Down/Up Ratio': 0,
                'dns_query_length': len(domain),
                'dns_entropy': shannon_entropy(domain),
                'is_attack': 0
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
