# Dataset & Feature Profile Report

## 1. Dataset Overview (Step 49)
- **Total Rows:** 2830628
- **Total Columns:** 57
- **Missing Values:** 0

## 2. Split Report (Step 52)
- **Train Rows:** 1981439
- **Validation Rows:** 424594
- **Test Rows:** 424595
- **Leakage Audit:** PASS (Strict Time-Aware Split Applied)

## 3. Feature Profile Summary (Step 50)
| Feature | Type | Missing | Min | Max |
|---------|------|---------|-----|-----|
| Destination Port | int64 | 0 | 0 | 65535 |
| Flow Duration | int64 | 0 | 0 | 119999998 |
| Total Packets | int64 | 0 | 1 | 219759 |
| Total Length of Packets | int64 | 0 | 0 | 12900000 |
| Packet Length Max | int64 | 0 | 0 | 24820 |
| Packet Length Min | int64 | 0 | 0 | 2325 |
| Packet Length Mean | float64 | 0 | 0.0 | 5940.8571 |
| Packet Length Std | float64 | 0 | 0.0 | 7125.5968 |
| Flow Bytes/s | float64 | 0 | 0.0 | 2071000000.0 |
| Flow Packets/s | float64 | 0 | 0.0 | 4000000.0 |
| Flow IAT Mean | float64 | 0 | 0.0 | 120000000.0 |
| Flow IAT Std | float64 | 0 | 0.0 | 84800261.5664 |
| Flow IAT Max | int64 | 0 | 0 | 120000000 |
| Flow IAT Min | int64 | 0 | -14 | 120000000 |
| IAT Total | int64 | 0 | 0 | 120000000 |
| IAT Mean | float64 | 0 | 0.0 | 120000000.0 |
| IAT Std | float64 | 0 | 0.0 | 84602929.277 |
| IAT Max | int64 | 0 | 0 | 120000000 |
| IAT Min | int64 | 0 | -12 | 120000000 |
| PSH Flags | int64 | 0 | 0 | 1 |
| URG Flags | int64 | 0 | 0 | 1 |
| Header Length | int64 | 0 | -32212234632 | 4644908 |
| Packets/s | float64 | 0 | 0.0 | 3000000.0 |
| Min Packet Length | int64 | 0 | 0 | 1448 |
| Max Packet Length | int64 | 0 | 0 | 24820 |
| Packet Length Mean.1 | float64 | 0 | 0.0 | 3337.1429 |
| Packet Length Std.1 | float64 | 0 | 0.0 | 4731.5224 |
| Packet Length Variance | float64 | 0 | 0.0 | 22400000.0 |
| FIN Flag Count | int64 | 0 | 0 | 1 |
| SYN Flag Count | int64 | 0 | 0 | 1 |
| RST Flag Count | int64 | 0 | 0 | 1 |
| PSH Flag Count | int64 | 0 | 0 | 1 |
| ACK Flag Count | int64 | 0 | 0 | 1 |
| URG Flag Count | int64 | 0 | 0 | 1 |
| CWE Flag Count | int64 | 0 | 0 | 1 |
| ECE Flag Count | int64 | 0 | 0 | 1 |
| Down/Up Ratio | int64 | 0 | 0 | 156 |
| Average Packet Size | float64 | 0 | 0.0 | 3893.3333 |
| Avg Segment Size | float64 | 0 | 0.0 | 5940.8571 |
| Header Length.1 | int64 | 0 | -32212234632 | 4644908 |
| Avg Bytes/Bulk | int64 | 0 | 0 | 0 |
| Avg Packets/Bulk | int64 | 0 | 0 | 0 |
| Avg Bulk Rate | int64 | 0 | 0 | 0 |
| Subflow Packets | int64 | 0 | 1 | 219759 |
| Subflow Bytes | int64 | 0 | 0 | 12870338 |
| Init_Win_bytes_forward | int64 | 0 | -1 | 65535 |
| act_data_pkt_fwd | int64 | 0 | 0 | 213557 |
| min_seg_size_forward | int64 | 0 | -536870661 | 138 |
| Active Mean | float64 | 0 | 0.0 | 110000000.0 |
| Active Std | float64 | 0 | 0.0 | 74200000.0 |
| Active Max | int64 | 0 | 0 | 110000000 |
| Active Min | int64 | 0 | 0 | 110000000 |
| Idle Mean | float64 | 0 | 0.0 | 120000000.0 |
| Idle Std | float64 | 0 | 0.0 | 76900000.0 |
| Idle Max | int64 | 0 | 0 | 120000000 |
| Idle Min | int64 | 0 | 0 | 120000000 |
