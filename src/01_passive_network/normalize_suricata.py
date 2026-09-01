import json
import logging
import os


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)


def normalize_suricata(raw_file, output_file):

    logging.info("=" * 60)
    logging.info("SURICATA TELEMETRY NORMALIZATION")
    logging.info("=" * 60)

    if not os.path.exists(raw_file):
        logging.error(
            "Suricata file not found: %s",
            raw_file
        )
        return False

    output_parent = os.path.dirname(output_file)

    if output_parent:
        os.makedirs(
            output_parent,
            exist_ok=True
        )

    count = 0
    skipped = 0

    with open(
        raw_file,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as infile, open(
        output_file,
        "w",
        encoding="utf-8"
    ) as outfile:

        for line_number, line in enumerate(
            infile,
            start=1
        ):

            if not line.strip():
                continue

            try:
                raw = json.loads(line)

            except json.JSONDecodeError:
                skipped += 1
                continue

            src_ip = raw.get("src_ip")
            dst_ip = raw.get("dest_ip")

            if not src_ip or not dst_ip:
                skipped += 1
                continue

            alert = raw.get("alert")

            if not isinstance(alert, dict):
                alert = {}

            normalized = {
                "timestamp": raw.get("timestamp"),

                "flow_id": str(
                    raw.get("flow_id", "")
                ),

                "src_ip": src_ip,
                "src_port": raw.get(
                    "src_port",
                    0
                ),

                "dst_ip": dst_ip,
                "dst_port": raw.get(
                    "dest_port",
                    0
                ),

                "protocol": str(
                    raw.get(
                        "proto",
                        "UNKNOWN"
                    )
                ).upper(),

                "event_type": raw.get(
                    "event_type",
                    "unknown"
                ),

                "sensor": "suricata",
                "sensor_version": "suricata-8.0.6",

                "alert_signature": alert.get(
                    "signature"
                ),

                "alert_category": alert.get(
                    "category"
                ),

                "alert_severity": alert.get(
                    "severity"
                )
            }

            outfile.write(
                json.dumps(
                    normalized,
                    separators=(",", ":")
                ) + "\n"
            )

            count += 1

    logging.info(
        "Normalized events: %d",
        count
    )

    logging.info(
        "Skipped events: %d",
        skipped
    )

    return True


if __name__ == "__main__":

    normalize_suricata(
        "data/telemetry/raw/suricata/sample/eve.json",
        "data/telemetry/normalized/suricata_normalized.jsonl"
    )