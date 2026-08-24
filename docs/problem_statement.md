# Problem Statement: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

**SIH Problem Statement ID:** 26145  
**Organization:** National Technical Research Organisation (NTRO)  
**Event:** Smart India Hackathon 2026

## 📌 Background

Critical-infrastructure operators may monitor gateway and peering links using passive traffic mirroring or hardware data diodes. These systems allow traffic to be copied into an isolated monitoring environment in one direction only.

The monitoring environment can observe network traffic, but it has no physical or protocol-level path back into the production network.

This improves isolation and reduces the risk of a compromised monitoring system being used to attack the production network. However, it also means that the security-monitoring system must detect threats using only what it can passively observe.

## 🎯 Objective

Design and build an AI/ML pipeline that:

- Ingests one-directional IP traffic or exported flow/metadata
- Extracts relevant features
- Detects and classifies cyber threats
- Assigns confidence/severity scores
- Generates alerts with supporting evidence
- Processes traffic incrementally / near real time
- Displays detections through a dashboard

## 🛡️ Threats to Detect

The system should address:

1. **Volumetric / Protocol DDoS**
   - SYN floods
   - UDP reflection/amplification
   - Spoofed-source floods

2. **Botnet C2 Beaconing**
   - Periodic connections
   - Repeated communication with a small set of destinations

3. **DGA Domains & DNS Tunneling**
   - High-entropy domains
   - Unusual query lengths
   - Abnormal DNS behavior

4. **Malware in Encrypted Sessions**
   - TLS/QUIC metadata
   - JA3/JA4 or similar fingerprints
   - Packet-size and timing patterns
   - Without decrypting payloads

5. **Reconnaissance & Port Scanning**
   - High destination-port diversity
   - High destination-host fan-out
   - Unusual connection patterns

6. **Data Exfiltration**
   - Abnormal outbound traffic
   - Unusual outbound/inbound byte ratios
   - Large or unusual transfers

## 🔒 Architectural Constraints

The solution must be:

### Read-only
The system must not send traffic back into the monitored network.

### Passive
Detection must rely only on observed traffic, flows, and metadata.

### No Payload Decryption
TLS/QUIC traffic must be analyzed using metadata rather than decrypted content.

### Streaming
The system must process traffic incrementally and generate alerts with bounded latency.

### Defined Throughput
The prototype must state and demonstrate the traffic rate at which it was tested.

### Standardized Alerts
Alerts should contain information such as:

- Timestamp
- Flow identifier
- Threat class
- Confidence score
- Severity
- Supporting evidence/features

## 📌 Expected Deliverable

A working prototype containing:

```text
Traffic Ingest
      ↓
Feature Extraction
      ↓
Model Inference / Detection
      ↓
Threat Classification
      ↓
Alert Generation
      ↓
Dashboard
```