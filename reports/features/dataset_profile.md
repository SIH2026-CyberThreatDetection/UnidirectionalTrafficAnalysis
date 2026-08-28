# Dataset & Feature Profile Report

## 1. Dataset Overview (Step 49)
- **Total Rows:** 50
- **Total Columns:** 29
- **Missing Values (Post-Imputation):** 196

## 2. Split Report (Step 52)
- **Train Rows:** 35
- **Validation Rows:** 7
- **Test Rows:** 8
- **Leakage Audit:** PASS (Strict Time-Aware Split Applied)

## 3. Feature Profile Summary (Step 50)
| Feature | Type | Missing | Min | Max |
|---------|------|---------|-----|-----|
| src_port | int64 | 0 | 137 | 63088 |
| dst_port | int64 | 0 | 21 | 49666 |
| duration | float64 | 0 | 0.0 | 7.6824 |
| bytes_out | int64 | 0 | 0 | 25345 |
| bytes_in | int64 | 0 | 0 | 50534 |
| packets_out | int64 | 0 | 1 | 42 |
| packets_in | int64 | 0 | 0 | 46 |
| quic | float64 | 50 | nan | nan |
| total_bytes | int64 | 0 | 0 | 75879 |
| total_packets | int64 | 0 | 2 | 88 |
| byte_ratio | float64 | 0 | 0.0643 | 10258.0 |
| packet_ratio | float64 | 0 | 0.7857 | 25.0 |
| bytes_per_second | float64 | 0 | 0.0 | 31764705.8824 |
| packets_per_second | float64 | 0 | 4.5954 | 750000.0 |
| dns_query_length | int64 | 0 | 0 | 122 |
| dns_entropy | float64 | 0 | 0.0 | 4.7344 |
| is_encrypted | int64 | 0 | 0 | 1 |
