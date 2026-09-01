# Dataset & Feature Profile Report

## 1. Dataset Overview

- **Total Rows:** 10337
- **Total Columns:** 42
- **Missing Values:** 51516

## 2. Split Report

- **Train Rows:** 8269
- **Validation Rows:** 1034
- **Test Rows:** 1034
- **Split Strategy:** Strict chronological 80/10/10
- **Scaler Strategy:** Scaler fitted on training data only
- **Leakage Audit:** PASS

## 3. Feature Profile Summary

| Feature | Type | Missing | Min | Max |
|---|---|---:|---:|---:|
| alert_severity | float64 | 337 | 0.0 | 0.0 |
| byte_ratio | float64 | 0 | 0.0008 | 23401.0 |
| bytes_in | int64 | 0 | 0.0 | 3195427.0 |
| bytes_out | int64 | 0 | 0.0 | 182510.0 |
| bytes_per_packet | float64 | 0 | 0.0 | 1499.0 |
| bytes_per_second | float64 | 0 | 0.0 | 165882352.9412 |
| dns_digit_fraction | float64 | 0 | 0.0 | 0.3973 |
| dns_entropy | float64 | 0 | 0.0 | 5.1719 |
| dns_query_length | int64 | 0 | 0.0 | 232.0 |
| dns_subdomain_depth | int64 | 0 | 0.0 | 7.0 |
| dst_port | int64 | 0 | 0.0 | 49671.0 |
| duration | float64 | 0 | 0.0 | 97.3855 |
| has_suricata_alert | float64 | 337 | 0.0 | 0.0 |
| is_attack | int64 | 0 | 0.0 | 1.0 |
| is_encrypted | int64 | 0 | 0.0 | 1.0 |
| ja3_numeric | int64 | 0 | 0.0 | 0.0 |
| mean_packet_size_in | float64 | 0 | 0.0 | 2165.9636 |
| mean_packet_size_out | float64 | 0 | 0.0 | 3443.5849 |
| outbound_fraction | float64 | 0 | 0.0 | 1.0 |
| packet_ratio | float64 | 0 | 0.5147 | 469.0 |
| packets_in | int64 | 0 | 0.0 | 1799.0 |
| packets_out | int64 | 0 | 1.0 | 1158.0 |
| packets_per_second | float64 | 0 | 0.1656 | 750000.0 |
| quic | float64 | 10337 | N/A | N/A |
| sni_entropy | float64 | 0 | 0.0 | 4.0518 |
| src_port | int64 | 0 | 123.0 | 65369.0 |
| suricata_alert_count | float64 | 337 | 0.0 | 0.0 |
| total_bytes | int64 | 0 | 0.0 | 3246794.0 |
| total_packets | int64 | 0 | 1.0 | 2957.0 |
| uses_deprecated_crypto | int64 | 0 | 0.0 | 1.0 |
