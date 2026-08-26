import json
from collections import defaultdict

def validate_telemetry(file_path):
    stats = {
        "total_records": 0,
        "valid_records": 0,
        "invalid_records": 0,
        "missing_fields": 0,
        "duplicate_ids": 0,
        "protocols": defaultdict(int),
        "sensors": defaultdict(int),
        "dns_count": 0,
        "tls_count": 0,
        "quic_count": 0
    }
    
    seen_ids = set()
    timestamps = []
    # Core fields your schema demands
    required_fields = ["timestamp", "flow_id", "src_ip", "dst_ip", "protocol"]

    print(f"Analyzing telemetry file: {file_path}...\n")
    
    try:
        with open(file_path, 'r') as f:
            for line in f:
                if not line.strip(): continue
                stats["total_records"] += 1
                
                try:
                    record = json.loads(line)
                    
                    # 1. Check for missing required fields
                    missing = [field for field in required_fields if field not in record or record[field] is None]
                    if missing:
                        stats["missing_fields"] += 1
                        stats["invalid_records"] += 1
                        continue 
                        
                    # 2. Check for duplicate IDs
                    flow_id = record.get("flow_id")
                    if flow_id in seen_ids:
                        stats["duplicate_ids"] += 1
                    else:
                        seen_ids.add(flow_id)
                        
                    # 3. Track Timestamps
                    timestamps.append(record.get("timestamp"))
                    
                    # 4. Count Protocols
                    protocol = str(record.get("protocol", "unknown")).upper()
                    stats["protocols"][protocol] += 1
                    
                    # 5. Count Sensors
                    sensor = record.get("sensor", "unknown")
                    stats["sensors"][sensor] += 1
                    
                    # 6. Specific Service Counts (DNS, TLS, QUIC)
                    dst_port = record.get("dst_port", 0)
                    src_port = record.get("src_port", 0)
                    suricata_events = record.get("suricata_events", [])
                    
                    if dst_port == 53 or src_port == 53 or "dns" in suricata_events:
                        stats["dns_count"] += 1
                    if dst_port == 443 or src_port == 443 or "tls" in suricata_events:
                        stats["tls_count"] += 1
                    if protocol == "UDP" and (dst_port == 443 or src_port == 443):
                        stats["quic_count"] += 1
                        
                    stats["valid_records"] += 1
                    
                except json.JSONDecodeError:
                    stats["invalid_records"] += 1
                    
    except FileNotFoundError:
        print(f"CRITICAL ERROR: Could not find {file_path}")
        return

    # Print the exact report requested by Phase 4, Step 28
    print("="*45)
    print("      TELEMETRY VALIDATION REPORT")
    print("="*45)
    print(f"Total records:           {stats['total_records']}")
    print(f"Valid records:           {stats['valid_records']}")
    print(f"Invalid records:         {stats['invalid_records']}")
    print(f"Missing required fields: {stats['missing_fields']}")
    print(f"Duplicate IDs:           {stats['duplicate_ids']}")
    
    if timestamps:
        timestamps.sort()
        print(f"Timestamp range:         {timestamps[0]}\n                         {timestamps[-1]}")
    else:
        print("Timestamp range:         N/A")
        
    print("-" * 45)
    print("PROTOCOL COUNTS:")
    for p, count in stats["protocols"].items():
        print(f"  - {p:<6}: {count}")
        
    print("-" * 45)
    print("SERVICE COUNTS:")
    print(f"  - DNS:  {stats['dns_count']}")
    print(f"  - TLS:  {stats['tls_count']}")
    print(f"  - QUIC: {stats['quic_count']}")
    
    print("-" * 45)
    print("SENSOR COUNTS:")
    for s, count in stats["sensors"].items():
        print(f"  - {s}: {count}")
    print("="*45)

if __name__ == "__main__":
    master_file = "data/telemetry/normalized/master_telemetry.jsonl"
    validate_telemetry(master_file)
