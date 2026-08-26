# Passive Network Observation Architecture

**Input:**
Authorized one-directional PCAP / mirrored telemetry

**Allowed:**
- read packets
- parse flow metadata
- parse DNS metadata
- parse TLS/QUIC metadata when available
- derive statistical metadata

**Not allowed:**
- active probes
- packet injection
- completing handshakes as a probe
- payload decryption
- inline blocking
- mitigation commands
- return traffic from the monitoring enclave

**Output:**
Normalized read-only telemetry for downstream feature engineering.
