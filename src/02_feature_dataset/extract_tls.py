import hashlib
import math
import pandas as pd
from typing import Dict

def calculate_sni_entropy(sni: str) -> float:
    """Calculates Shannon entropy of the Server Name Indication (SNI).
       High entropy indicates potential Domain Generation Algorithms (DGA) in encrypted C2."""
    if not sni or sni == '-':
        return 0.0
    entropy = 0.0
    for x in set(sni):
        p_x = float(sni.count(x)) / len(sni)
        entropy += - p_x * math.log(p_x, 2)
    return float(entropy)

def encode_ja3_hash(ja3_string: str) -> int:
    """Converts a string-based JA3 hash into a bounded integer for the ML model."""
    if not ja3_string or ja3_string == '-':
        return 0
    # Use MD5 to encode the string, then convert the first 8 hex characters to an integer
    md5_hash = hashlib.md5(ja3_string.encode('utf-8')).hexdigest()
    return int(md5_hash[:8], 16)

def extract_encrypted_features(zeek_ssl_log: list) -> pd.DataFrame:
    """
    Simulates parsing Zeek's ssl.log to extract unidirectional encrypted session features.
    """
    extracted_data = []
    
    for session in zeek_ssl_log:
        sni = session.get('server_name', '')
        ja3 = session.get('ja3', '')
        
        features = {
            'src_ip': session.get('id.orig_h'),
            'dst_ip': session.get('id.resp_h'),
            'Destination Port': session.get('id.resp_p'),
            'sni_entropy': calculate_sni_entropy(sni),
            'ja3_numeric': encode_ja3_hash(ja3),
            'tls_version_num': 1 if session.get('version') == 'TLSv12' else (2 if session.get('version') == 'TLSv13' else 0)
        }
        extracted_data.append(features)
        
    return pd.DataFrame(extracted_data)

if __name__ == "__main__":
    print("--- Testing Encrypted Session (TLS) Feature Extraction ---")
    
    # Simulating raw output from your teammate's Kali VM Zeek sensor
    mock_zeek_ssl_log = [
        {
            "id.orig_h": "192.168.1.100", "id.resp_h": "104.18.32.7", "id.resp_p": 443,
            "version": "TLSv13", "server_name": "github.com", 
            "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0" # Standard Browser
        },
        {
            "id.orig_h": "192.168.1.100", "id.resp_h": "45.33.12.9", "id.resp_p": 443,
            "version": "TLSv12", "server_name": "x8f9q2mzk1.evil-c2.net", # High entropy DGA
            "ja3": "771,49192-49191-49172-49171-53,0-10-11,23-24-25,0" # Known Metasploit/Cobalt Strike signature
        }
    ]
    
    df_tls = extract_encrypted_features(mock_zeek_ssl_log)
    
    print("\nExtracted Unidirectional ML Features:")
    print(df_tls.to_string(index=False))
