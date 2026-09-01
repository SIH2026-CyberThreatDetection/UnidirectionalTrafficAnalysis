import json
import logging
import os
from datetime import datetime


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)


def parse_time(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(
            str(value).replace(
                "Z",
                "+00:00"
            )
        )
    except ValueError:
        return None


def flow_key(record):
    """
    Stable directional flow key.

    flow_id is preferred because it is unique inside
    the originating sensor.
    """

    flow_id = record.get("flow_id")

    if flow_id:
        return (
            str(record.get("sensor", "")),
            str(flow_id)
        )

    return (
        str(record.get("src_ip", "")),
        str(record.get("dst_ip", "")),
        str(record.get("src_port", "")),
        str(record.get("dst_port", "")),
        str(record.get("protocol", "")).upper(),
        str(record.get("timestamp", ""))
    )


def initialize_suricata_fields(record):

    record["suricata_alert_count"] = 0
    record["has_suricata_alert"] = 0
    record["suricata_event_types"] = ""
    record["alert_severity"] = 0

    return record


def merge_telemetry(
    zeek_file,
    suricata_file,
    output_file
):

    logging.info("=" * 60)
    logging.info("MERGING ZEEK + SURICATA TELEMETRY")
    logging.info("=" * 60)

    if not os.path.exists(zeek_file):
        logging.error(
            "Zeek file not found: %s",
            zeek_file
        )
        return False

    if not os.path.exists(suricata_file):
        logging.error(
            "Suricata file not found: %s",
            suricata_file
        )
        return False

    merged = {}

    with open(
        zeek_file,
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            record = initialize_suricata_fields(
                record
            )

            key = flow_key(record)

            # Never silently overwrite a flow.
            if key in merged:
                logging.warning(
                    "Duplicate Zeek key encountered: %s",
                    key
                )
                continue

            merged[key] = record

    logging.info(
        "Zeek flows loaded: %d",
        len(merged)
    )

    matches = 0

    with open(
        suricata_file,
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Suricata flow_id is not necessarily equal
            # to Zeek UID, therefore use directional metadata.
            candidate_keys = [
                key
                for key, value in merged.items()
                if (
                    value.get("src_ip") == record.get("src_ip")
                    and
                    value.get("dst_ip") == record.get("dst_ip")
                    and
                    int(value.get("src_port") or 0)
                    == int(record.get("src_port") or 0)
                    and
                    int(value.get("dst_port") or 0)
                    == int(record.get("dst_port") or 0)
                    and
                    str(value.get("protocol", "")).upper()
                    ==
                    str(record.get("protocol", "")).upper()
                )
            ]

            if not candidate_keys:
                continue

            # Match the closest timestamp when available.
            suri_time = parse_time(
                record.get("timestamp")
            )

            best_key = candidate_keys[0]
            best_delta = None

            if suri_time:

                for key in candidate_keys:

                    zeek_time = parse_time(
                        merged[key].get("timestamp")
                    )

                    if not zeek_time:
                        continue

                    delta = abs(
                        (
                            zeek_time - suri_time
                        ).total_seconds()
                    )

                    if (
                        best_delta is None
                        or delta < best_delta
                    ):
                        best_delta = delta
                        best_key = key

            # Avoid matching completely unrelated traffic.
            if (
                best_delta is not None
                and best_delta > 5
            ):
                continue

            target = merged[best_key]

            target[
                "suricata_alert_count"
            ] += 1

            target[
                "has_suricata_alert"
            ] = 1

            event_type = str(
                record.get(
                    "event_type",
                    ""
                )
            ).strip()

            existing = [
                x
                for x in str(
                    target.get(
                        "suricata_event_types",
                        ""
                    )
                ).split(",")
                if x
            ]

            if (
                event_type
                and event_type not in existing
            ):
                existing.append(
                    event_type
                )

            target[
                "suricata_event_types"
            ] = ",".join(existing)

            severity = record.get(
                "alert_severity"
            )

            try:
                severity = int(severity)
            except (ValueError, TypeError):
                severity = 0

            target[
                "alert_severity"
            ] = max(
                target.get(
                    "alert_severity",
                    0
                ),
                severity
            )

            matches += 1

    output_parent = os.path.dirname(
        output_file
    )

    if output_parent:
        os.makedirs(
            output_parent,
            exist_ok=True
        )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        for record in merged.values():

            file.write(
                json.dumps(
                    record,
                    separators=(",", ":")
                ) + "\n"
            )

    logging.info(
        "Unified records: %d",
        len(merged)
    )

    logging.info(
        "Suricata matched flows: %d",
        matches
    )

    logging.info(
        "Output: %s",
        output_file
    )

    return True


if __name__ == "__main__":

    merge_telemetry(
        "data/telemetry/normalized/normalized_telemetry.jsonl",
        "data/telemetry/normalized/suricata_normalized.jsonl",
        "data/telemetry/normalized/master_telemetry.jsonl"
    )