import math
import random
from pathlib import Path

import pandas as pd


SEED = 42


def shannon_entropy(value):

    if not value:
        return 0.0

    counts = {}

    for char in value:
        counts[char] = (
            counts.get(char, 0) + 1
        )

    length = len(value)

    entropy = 0.0

    for count in counts.values():

        p = count / length

        entropy -= (
            p * math.log2(p)
        )

    return round(
        entropy,
        4
    )


def generate_dns_tunneling_traffic(
    num_samples=10000
):

    random.seed(SEED)

    normal_domains = [
        "google.com",
        "microsoft.com",
        "aws.amazon.com",
        "github.com",
        "ntro.gov.in"
    ]

    records = []

    base_timestamp = pd.Timestamp(
        "2017-07-07T00:00:00Z"
    )

    for index in range(
        num_samples
    ):

        # deterministic 50/50 distribution
        is_attack = (
            index % 2
        )

        if is_attack:

            payload_length = random.randint(
                50,
                220
            )

            alphabet = (
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789"
            )

            subdomain = "".join(
                random.choice(alphabet)
                for _ in range(
                    payload_length
                )
            )

            domain = (
                f"{subdomain}.evil-c2.net"
            )

            duration = random.uniform(
                0.01,
                2.0
            )

            bytes_out = random.randint(
                1500,
                8000
            )

            packets_out = random.randint(
                10,
                100
            )

            label = "DNS_TUNNELING"

        else:

            domain = random.choice(
                normal_domains
            )

            duration = random.uniform(
                0.05,
                5.0
            )

            bytes_out = random.randint(
                40,
                250
            )

            packets_out = random.randint(
                1,
                4
            )

            label = "BENIGN"

        timestamp = (
            base_timestamp
            + pd.to_timedelta(
                index,
                unit="s"
            )
        )

        total_bytes = bytes_out
        total_packets = packets_out

        safe_duration = max(
            duration,
            1e-6
        )

        record = {

            "timestamp":
                timestamp.isoformat(),

            "flow_id":
                f"synthetic-dns-{index}",

            "src_ip":
                "10.255.0.1",

            "dst_ip":
                "8.8.8.8",

            "src_port":
                40000 + (
                    index % 1000
                ),

            "dst_port":
                53,

            "protocol":
                "UDP",

            "duration":
                duration,

            "bytes_out":
                bytes_out,

            "bytes_in":
                0,

            "packets_out":
                packets_out,

            "packets_in":
                0,

            "total_bytes":
                total_bytes,

            "total_packets":
                total_packets,

            "byte_ratio":
                bytes_out + 1.0,

            "packet_ratio":
                packets_out + 1.0,

            "outbound_fraction":
                1.0,

            "bytes_per_second":
                bytes_out / safe_duration,

            "packets_per_second":
                packets_out / safe_duration,

            "bytes_per_packet":
                bytes_out /
                max(packets_out, 1),

            "mean_packet_size_out":
                bytes_out /
                max(packets_out, 1),

            "mean_packet_size_in":
                0.0,

            "dns_query_length":
                len(domain),

            "dns_entropy":
                shannon_entropy(domain),

            "dns_digit_fraction":
                sum(
                    c.isdigit()
                    for c in domain
                ) / max(
                    len(domain),
                    1
                ),

            "dns_subdomain_depth":
                domain.count("."),

            "is_encrypted":
                0,

            "uses_deprecated_crypto":
                0,

            "ja3_numeric":
                0,

            "suricata_alert_count":
                0,

            "has_suricata_alert":
                0,

            "alert_severity":
                0,

            "is_attack":
                is_attack,

            "Label":
                label,

            "source_dataset":
                "synthetic_dns",

            "scenario":
                "dns_tunneling"
                if is_attack
                else "benign_dns"
        }

        records.append(record)

    df = pd.DataFrame(
        records
    )

    output = Path(
        "data/interim/"
        "synthetic_dns_tunnels.csv"
    )

    output.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    df.to_csv(
        output,
        index=False
    )

    print(
        f"Generated {len(df)} records."
    )

    print(
        df["Label"].value_counts()
    )

    print(
        f"Saved: {output}"
    )


if __name__ == "__main__":
    generate_dns_tunneling_traffic()