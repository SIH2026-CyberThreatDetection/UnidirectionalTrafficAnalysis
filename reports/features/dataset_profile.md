# Dataset & Feature Profile Report

## 1. Dataset Overview (Step 49)
- **Total Rows:** 10337
- **Total Columns:** 30
- **Missing Values:** 121137

## 2. Split Report (Step 52)
- **Train Rows:** 8269
- **Validation Rows:** 1034
- **Test Rows:** 1034
- **Leakage Audit:** PASS (Strict Time-Aware Split Applied)

## 3. Feature Profile Summary (Step 50)
| Feature | Type | Missing | Min | Max |
|---------|------|---------|-----|-----|
| src_port | float64 | 10000 | 123.0 | 65369.0 |
| dst_port | int64 | 0 | 0 | 49671 |
| duration | float64 | 0 | 0.0 | 97.3855 |
| bytes_out | int64 | 0 | 0 | 182510 |
| bytes_in | int64 | 0 | 0 | 3195427 |
| packets_out | int64 | 0 | 1 | 1158 |
| packets_in | int64 | 0 | 0 | 1799 |
| quic | float64 | 10337 | nan | nan |
| total_bytes | int64 | 0 | 0 | 3246794 |
| total_packets | int64 | 0 | 1 | 2957 |
| byte_ratio | float64 | 0 | 0.0008 | 23401.0 |
| packet_ratio | float64 | 0 | 0.5147 | 469.0 |
| bytes_per_second | float64 | 0 | 0.0 | 165882352.9412 |
| packets_per_second | float64 | 0 | 0.1656 | 750000.0 |
| dns_query_length | int64 | 0 | 0 | 232 |
| dns_entropy | float64 | 0 | 0.0 | 5.1718 |
| is_encrypted | int64 | 0 | 0 | 1 |
| sni_entropy | float64 | 10000 | 0.0 | 4.0518 |
| uses_deprecated_crypto | int64 | 0 | 0 | 1 |
| is_attack | float64 | 337 | 0.0 | 1.0 |
