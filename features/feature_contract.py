FEATURE_VERSION = "M2-v2.0"

FEATURE_ORDER = [
    "duration",
    "bytes_out",
    "bytes_in",
    "packets_out",
    "packets_in",
    "total_bytes",
    "total_packets",
    "byte_ratio",
    "packet_ratio",
    "outbound_fraction",
    "bytes_per_second",
    "packets_per_second",
    "bytes_per_packet",
    "mean_packet_size_out",
    "mean_packet_size_in",
    "dns_query_length",
    "dns_entropy",
    "dns_digit_fraction",
    "dns_subdomain_depth",
    "is_encrypted",
    "uses_deprecated_crypto",
    "ja3_numeric",
    "suricata_alert_count",
    "has_suricata_alert",
    "alert_severity"
]


BINARY_FEATURES = [
    "is_encrypted",
    "uses_deprecated_crypto",
    "has_suricata_alert"
]


TARGET_NAMES = {
    0: "benign",
    1: "ddos",
    2: "botnet_c2",
    3: "dns_tunneling",
    4: "encrypted_malware",
    5: "reconnaissance",
    6: "data_exfiltration"
}