import datetime
import json
import os
import sys

def parse_zeek_tsv(filepath):
    """Parses Zeek tab-separated log files into dictionaries."""
    if not os.path.exists(filepath):
        return []
    
    records = []
    fields = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif not line.startswith("#") and fields:
                values = line.split("\t")
                record = {}
                for field, val in zip(fields, values):
                    record[field] = None if val == "-" else val
                records.append(record)
    return records

def safe_int(val):
    try:
        return int(val) if val is not None else None
    except ValueError:
        return None

def safe_float(val):
    try:
        return float(val) if val is not None else None
    except ValueError:
        return None

def normalize(raw_dir, output_file):
    conn_records = parse_zeek_tsv(os.path.join(raw_dir, "conn.log"))
    dns_records = parse_zeek_tsv(os.path.join(raw_dir, "dns.log"))
    ssl_records = parse_zeek_tsv(os.path.join(raw_dir, "ssl.log"))

    # Index auxiliary logs by flow UID
    dns_map = {d["uid"]: d for d in dns_records if "uid" in d and d["uid"]}
    ssl_map = {s["uid"]: s for s in ssl_records if "uid" in s and s["uid"]}

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    count = 0

    with open(output_file, "w", encoding="utf-8") as out:
        for conn in conn_records:
            uid = conn.get("uid")
            if not uid:
                continue

            # Convert epoch to ISO-8601 UTC
            ts_raw = safe_float(conn.get("ts"))
            if ts_raw:
                ts_iso = datetime.datetime.fromtimestamp(ts_raw, datetime.timezone.utc).isoformat()
            else:
                ts_iso = None

            # Join DNS / TLS metadata if present
            dns_info = None
            if uid in dns_map:
                dns_entry = dns_map[uid]
                dns_info = {
                    "query": dns_entry.get("query"),
                    "qtype_name": dns_entry.get("qtype_name"),
                    "rcode_name": dns_entry.get("rcode_name")
                }

            tls_info = None
            if uid in ssl_map:
                ssl_entry = ssl_map[uid]
                tls_info = {
                    "version": ssl_entry.get("version"),
                    "cipher": ssl_entry.get("cipher"),
                    "server_name": ssl_entry.get("server_name")
                }

            normalized_record = {
                "timestamp": ts_iso,
                "flow_id": uid,
                "src_ip": conn.get("id.orig_h"),
                "dst_ip": conn.get("id.resp_h"),
                "src_port": safe_int(conn.get("id.orig_p")),
                "dst_port": safe_int(conn.get("id.resp_p")),
                "protocol": conn.get("proto"),
                "duration": safe_float(conn.get("duration")),
                "bytes_out": safe_int(conn.get("orig_bytes")),
                "bytes_in": safe_int(conn.get("resp_bytes")),
                "packets_out": safe_int(conn.get("orig_pkts")),
                "packets_in": safe_int(conn.get("resp_pkts")),
                "dns": dns_info,
                "tls": tls_info,
                "quic": None,
                "sensor": "zeek",
                "sensor_version": "zeek-native"
            }

            out.write(json.dumps(normalized_record) + "\n")
            count += 1

    print(f"Successfully normalized {count} flows to {output_file}")

if __name__ == "__main__":
    raw_path = "data/raw/zeek/sample"
    out_path = "telemetry/normalized/normalized_telemetry.jsonl"
    normalize(raw_path, out_path)

