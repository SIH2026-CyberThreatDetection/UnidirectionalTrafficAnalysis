# Passive Network Final Report

**1. Environment**
* Sensors: Kali Linux (VMware)
* Analytics/Processing: Windows Host
* Network Capture: Offline PCAP ingestion (Unidirectional)

**2. Sensor versions**
* Zeek: Native (Latest)
* Suricata: Version 8.0.6

**3. PCAP sources**
* Primary: CIC-IDS2017 (Test Sample)
* Secondary/Future: CTU-13 / CSE-CIC-IDS2018

**4. One-way/read-only architecture**
* Verified (Step 50 compliance). The pipeline ingests passive PCAPs only. Scripts do not initiate network connections to observed endpoints, and the analytics environment has no route back to the capture source. No active probing is performed.

**5. Zeek outputs**
* Foundational network baselines (Conn logs) establishing the definitive 5-Tuple flow truth.

**6. Suricata outputs**
* Deep Packet Inspection (DPI) metadata and alerts mapped via `eve.json`.

**7. Normalized schema**
* Unified `.jsonl` schema mapping source IP, destination IP, ports, and protocols into a standardized dictionary.

**8. Field mapping**
* Suricata alerts and events successfully fused to Zeek baselines using standardized lowercase 5-tuple keys to prevent schema mismatch.

**9. Data-quality results**
* Valid Records: 100% (337/337)
* Invalid/Malformed: 0
* Missing Required Fields: 0
* Duplicate IDs: 0

**10. Capture-loss results**
* 0% Capture Loss. All packets accounted for during the normalization phase.

**11. Throughput benchmark**
* Processing Speed: ~245,908 flows/sec
* Throughput: ~0.56 Mbps (Small PCAP workload)
* System Impact: Nominal CPU/RAM footprint.

**12. Limitations & Constraints**
* Encrypted Traffic Constraint (Step 49): TLS/QUIC analysis relies strictly on unencrypted metadata (e.g., SNI, ports). No decryption, key extraction, or payload reconstruction is performed. 

**13. Machine Learning Team Handoff**
* Completed. Core semantics documented. `sample_telemetry.jsonl` (50 records) generated for M2 feature engineering.

**14. Reproduction commands**
* Execution logic and commands are permanently documented in `docs/reproduction.md`.
