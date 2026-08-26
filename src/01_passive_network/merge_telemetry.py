import json
import os

def generate_key(record):
    # Force strings and lowercase protocol to ensure perfect matching across different sensors
    src = str(record.get('src_ip', ''))
    dst = str(record.get('dst_ip', ''))
    s_port = str(record.get('src_port', '0'))
    d_port = str(record.get('dst_port', '0'))
    proto = str(record.get('protocol', '')).lower()
    
    return f"{src}-{dst}-{s_port}-{d_port}-{proto}"

def merge_telemetry(zeek_file, suricata_file, output_file):
    merged_data = {}
    
    print("Reading Zeek baseline...")
    with open(zeek_file, 'r') as f:
        for line in f:
            if not line.strip(): continue
            record = json.loads(line)
            key = generate_key(record)
            merged_data[key] = record
            merged_data[key]['suricata_events'] = []
    
    print("Enriching with Suricata intelligence...")
    suricata_count = 0
    with open(suricata_file, 'r') as f:
        for line in f:
            if not line.strip(): continue
            record = json.loads(line)
            key = generate_key(record)
            
            if key in merged_data:
                # Avoid appending the exact same event multiple times per flow
                event = record.get('event_type')
                if event not in merged_data[key]['suricata_events']:
                    merged_data[key]['suricata_events'].append(event)
                suricata_count += 1
    
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

