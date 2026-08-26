# Network Telemetry Quality Report

## Dataset & Environment
* **Dataset:** CIC-IDS2017 (Test Sample)
* **PCAP File:** `data/pcaps/test/sample.pcap`
* **Sensor(s):** Zeek Native + Suricata 8.0.6 (Unified Pipeline)
* **Start Time:** 2017-07-07T12:01:57.179385+00:00
* **End Time:** 2017-07-07T12:03:38.694508+00:00
* **Duration:** ~101.5 seconds

## Validation Summary
* **Total Events / Flows:** 337
* **Valid Records:** 337 (100%)
* **Invalid Records:** 0 (0%)
* **Duplicate IDs:** 0
* **Missing Required Fields:** 0

## Protocol & Service Breakdown
* **Protocols:**
  * UDP: 217
  * TCP: 119
  * ICMP: 1
* **Services Identified:**
  * DNS (Port 53): 160
  * TLS / HTTPS (Port 443): 50
  * QUIC: 0

## Pipeline Health
* **Capture Loss:** 0%
* **Enrichment Rate:** 999 deep-packet inspection events successfully mapped
* **Notes:** All schema validation checks passed without truncation or missing 5-tuple keys.
