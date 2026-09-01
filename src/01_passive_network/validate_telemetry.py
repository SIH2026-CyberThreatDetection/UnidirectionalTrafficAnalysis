import argparse
import json
from collections import Counter


REQUIRED_FIELDS = [
    "timestamp",
    "flow_id",
    "src_ip",
    "dst_ip",
    "protocol"
]


def validate_telemetry(file_path):

    stats = {
        "total": 0,
        "valid": 0,
        "invalid": 0,
        "missing_fields": 0,
        "duplicate_ids": 0,
        "dns": 0,
        "tls": 0,
        "alerts": 0
    }

    protocols = Counter()
    sensors = Counter()
    seen_ids = set()

    try:

        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            for line in file:

                if not line.strip():
                    continue

                stats["total"] += 1

                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    stats["invalid"] += 1
                    continue

                missing = [
                    field
                    for field in REQUIRED_FIELDS
                    if (
                        field not in record
                        or record[field] is None
                        or str(record[field]).strip() == ""
                    )
                ]

                if missing:
                    stats["missing_fields"] += 1
                    stats["invalid"] += 1
                    continue

                flow_id = str(
                    record["flow_id"]
                )

                if flow_id in seen_ids:
                    stats["duplicate_ids"] += 1
                else:
                    seen_ids.add(flow_id)

                protocol = str(
                    record.get(
                        "protocol",
                        "UNKNOWN"
                    )
                ).upper()

                protocols[protocol] += 1

                sensor = str(
                    record.get(
                        "sensor",
                        "UNKNOWN"
                    )
                )

                sensors[sensor] += 1

                if record.get("dns"):
                    stats["dns"] += 1

                if record.get("tls"):
                    stats["tls"] += 1

                if int(
                    record.get(
                        "has_suricata_alert",
                        0
                    ) or 0
                ) == 1:
                    stats["alerts"] += 1

                stats["valid"] += 1

    except FileNotFoundError:
        print(
            f"ERROR: File not found: {file_path}"
        )
        return False

    print()
    print("=" * 60)
    print("TELEMETRY VALIDATION REPORT")
    print("=" * 60)

    for key, value in stats.items():
        print(
            f"{key:<20}: {value}"
        )

    print()
    print("PROTOCOLS")

    for key, value in sorted(
        protocols.items()
    ):
        print(
            f"  {key:<10} {value}"
        )

    print()
    print("SENSORS")

    for key, value in sorted(
        sensors.items()
    ):
        print(
            f"  {key:<10} {value}"
        )

    print("=" * 60)

    return (
        stats["valid"] > 0
        and stats["missing_fields"] == 0
    )


if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input",
        default=(
            "data/telemetry/normalized/"
            "master_telemetry.jsonl"
        )
    )

    args = parser.parse_args()

    validate_telemetry(
        args.input
    )