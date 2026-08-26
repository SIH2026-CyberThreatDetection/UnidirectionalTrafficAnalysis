# Pipeline Reproduction & Engineering Handoff

## 1. Raw & Normalized Paths
* **Raw PCAP:** `data/pcaps/test/sample.pcap` (Kept out of version control due to size limits)
* **Raw Zeek Logs:** Generated via isolated Kali Linux sensor environment
* **Raw Suricata Logs:** Generated via isolated Kali Linux sensor environment
* **Normalized Master JSONL:** `data/telemetry/normalized/master_telemetry.jsonl`
* **Sample JSONL (50 records):** `data/telemetry/normalized/sample_telemetry.jsonl`
* **Sensors:** Zeek Native + Suricata 8.0.6

## 2. Core Fields Explained
The Data Engineering pipeline guarantees these fields are mathematically accurate baselines. The Machine Learning (ML) engineers will use these to build rates, ratios, and behavioral features:
* `src_ip` / `dst_ip`: The unidirectional flow endpoints.
* `src_port` / `dst_port`: Used to identify the service (e.g., 53=DNS, 443=TLS).
* `protocol`: Layer 4 protocol (TCP, UDP, ICMP).
* `timestamp`: ISO 8601 UTC timestamp of the flow start.
* `suricata_events`: List of deep-packet inspection alerts fused to the flow.

## 3. Handoff Walkthrough
`PCAP packet` -> `Zeek/Suricata event` -> `source field` -> `normalized field` -> `future engineered feature (ML Team)` -> `future model input (ML Team)`.

If the ML Team cannot trace a value back to its source, the handoff is considered incomplete.

## 4. Handoff Checklist
- [x] PCAP source documented
- [x] provenance/license documented
- [x] Zeek version recorded
- [x] Suricata version recorded
- [x] commands/config recorded
- [x] raw logs reproducible
- [x] normalized schema finalized
- [x] field mapping finalized
- [x] timestamp semantics documented
- [x] direction semantics documented
- [x] missingness documented
- [x] duplicates documented
- [x] capture loss documented
- [x] throughput measured
- [x] sample telemetry provided
- [x] ML Engineering Team can regenerate the data
