# AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

## 📌 Problem Statement

**SIH Problem Statement ID:** 26145  
**Title:** AI-Based Detection of Cyber Threats in Unidirectional IP Traffic  
**Organization:** National Technical Research Organisation (NTRO)  
**Event:** Smart India Hackathon 2026

---

## 🎯 Objective

Build a prototype AI/ML pipeline that passively analyzes one-directional IP traffic and detects, classifies, and scores cyber-security threats in near real time.

The system should follow:

**Traffic Ingest → Feature Extraction → Threat Detection → Classification → Confidence Scoring → Alert → Dashboard**

The prototype should detect:

- Volumetric / Protocol DDoS
- Botnet C2 Beaconing
- DGA Domains / DNS Tunneling
- Malware in Encrypted Sessions using TLS/QUIC metadata
- Reconnaissance / Port Scanning
- Data Exfiltration

---

## 👥 Team

We are a student team working on SIH 2026 Problem Statement 26145.

| Member | GitHub | Role |
|---|---|---|
| Priyanko Majumder | [@Priyanko2006](https://github.com/Priyanko2006) | To be decided |
| Sayan Chakraborty | [@username](https://github.com/username) | To be decided |
| Sudhriti Dey | [@username](https://github.com/username) | To be decided |
| Priyangshu Howladar | [@username](https://github.com/username) | To be decided |
| Sougata Bhunia | [@username](https://github.com/username) | To be decided |

> Roles will be finalized after the research and initial understanding phase.

---

## 🔒 Important System Constraints

The solution must operate as a **passive, read-only monitoring system**.

### ✅ Our system can:

- Observe incoming traffic
- Analyze packets, flows, and metadata
- Extract statistical and behavioral features
- Run AI/ML inference
- Generate alerts
- Display evidence and confidence scores

### ❌ Our system cannot:

- Send traffic back to the source
- Perform active probing
- Complete its own network handshakes
- Issue mitigation/blocking commands
- Depend on decrypted TLS/QUIC payloads

---

## 📊 Required Alert Information

Each alert should contain at least:

- Timestamp
- Flow ID
- Threat class
- Confidence score
- Severity
- Supporting evidence/features

Example:

```text
Threat: DNS Tunneling
Severity: HIGH
Confidence: 93%

Evidence:
- High DNS query entropy
- Unusually long query names
- Abnormal query frequency
```

--- 

## 🛠️ Planned Tech Stack

- **Language:** Python
- **Data / ML:** pandas, NumPy, scikit-learn
- **Network Analysis:** Wireshark, Zeek, Scapy
- **Dashboard:** Streamlit
- **Version Control:** Git & GitHub

> The final technology stack will be decided after research and experimentation.

---

## 📌 Note

This repository documents our ongoing research and development for SIH 2026 Problem Statement 26145.