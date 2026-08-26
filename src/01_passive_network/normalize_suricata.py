import json
import os

def normalize_suricata(raw_file, output_file):
    count = 0
    
    # Ensure the output directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(raw_file, 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            if not line.strip():
                continue
            try:
                raw_event = json.loads(line)
                
                # We only care about network events with IPs (skip internal engine logs)
                if "src_ip" not in raw_event or "dest_ip" not in raw_event:
                    continue
                    
                # Build the normalized record matching your AI schema
                normalized_record = {
                    "timestamp": raw_event.get("timestamp"),
                    "flow_id": str(raw_event.get("flow_id", "")),
                    "src_ip": raw_event.get("src_ip"),
                    "src_port": raw_event.get("src_port", 0),
                    "dst_ip": raw_event.get("dest_ip"),  # Suricata uses dest_ip, we map to dst_ip
                    "dst_port": raw_event.get("dest_port", 0),
                    "protocol": raw_event.get("proto", "UNKNOWN"),
                    "event_type": raw_event.get("event_type", "unknown"),
                    "sensor": "suricata",
                    "sensor_version": "suricata-8.0.6"
                }
                
                outfile.write(json.dumps(normalized_record) + "\n")
                count += 1
            except Exception as e:
                print(f"Error parsing line: {e}")
                continue
                
    print(f"Successfully normalized {count} Suricata events to {output_file}")

if __name__ == "__main__":
    raw_path = "data/telemetry/raw/suricata/sample/eve.json"
    out_path = "data/telemetry/normalized/suricata_normalized.jsonl"
    normalize_suricata(raw_path, out_path)

