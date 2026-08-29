import json
import os

def generate_key(record):
    """
    Forces strings and lowercase protocol.
    Extracts a coarse timestamp (YYYY-MM-DDTHH:MM) to prevent 5-tuple collisions
    when source ports are reused later in the day.
    """
    src = str(record.get('src_ip', ''))
    dst = str(record.get('dst_ip', ''))
    s_port = str(record.get('src_port', '0'))
    d_port = str(record.get('dst_port', '0'))
    proto = str(record.get('protocol', '')).lower()
    
    # Extract the timestamp down to the minute to isolate the flow in time
    # e.g., "2017-07-07T12:01:58..." becomes "2017-07-07T12:01"
    raw_ts = str(record.get('timestamp', '1970-01-01T00:00'))
    time_boundary = raw_ts[:16] 
    
    return f"{src}-{dst}-{s_port}-{d_port}-{proto}-{time_boundary}"

def merge_telemetry(zeek_file, suricata_file, output_file):
    merged_data = {}
    
    print("Reading Zeek baseline...")
    with open(zeek_file, 'r') as f:
        for line in f:
            if not line.strip(): continue
            record = json.loads(line)
            key = generate_key(record)
            
            # Initialize ML-safe numeric features for Suricata intelligence
            record['suricata_alert_count'] = 0
            record['has_suricata_alert'] = 0
            
            merged_data[key] = record

    print("Enriching with Suricata intelligence...")
    suricata_count = 0
    with open(suricata_file, 'r') as f:
        for line in f:
            if not line.strip(): continue
            record = json.loads(line)
            key = generate_key(record)
            
            if key in merged_data:
                # Increment the alert count for XGBoost to use as a numeric feature
                merged_data[key]['suricata_alert_count'] += 1
                merged_data[key]['has_suricata_alert'] = 1
                suricata_count += 1
                
                # Optional: If you strictly need the event types for M4 (not for ML),
                # combine them as a single comma-separated string, not a list.
                event = str(record.get('event_type', ''))
                if event:
                    existing_events = merged_data[key].get('suricata_event_types', '')
                    if event not in existing_events:
                        if existing_events:
                            merged_data[key]['suricata_event_types'] += f",{event}"
                        else:
                            merged_data[key]['suricata_event_types'] = event

    print(f"Writing unified dataset to {output_file}...")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w') as f:
        for record in merged_data.values():
            f.write(json.dumps(record) + "\n")
            
    print("-" * 40)
    print(f"SUCCESS: Created {len(merged_data)} unified Super Records!")
    print(f"SUCCESS: Enriched {suricata_count} flows with deep packet inspection.")

if __name__ == "__main__":
    zeek_path = "data/telemetry/normalized/normalized_telemetry.jsonl"
    suricata_path = "data/telemetry/normalized/suricata_normalized.jsonl"
    master_path = "data/telemetry/normalized/master_telemetry.jsonl"
    
    merge_telemetry(zeek_path, suricata_path, master_path)
