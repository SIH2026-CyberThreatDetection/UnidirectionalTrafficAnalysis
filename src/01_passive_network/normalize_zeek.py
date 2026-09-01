import datetime
import json
import logging
import os


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)


def parse_zeek_tsv(filepath):
    """Parse a Zeek TSV log into dictionaries."""

    if not os.path.exists(filepath):
        logging.warning(
            "Zeek log not found: %s",
            filepath
        )
        return []

    records = []
    fields = []

    with open(
        filepath,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as file:

        for line in file:
            line = line.rstrip("\n")

            if not line:
                continue

            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue

            if line.startswith("#"):
                continue

            if not fields:
                continue

            values = line.split("\t")

            record = {}

            for field, value in zip(fields, values):
                record[field] = (
                    None
                    if value == "-"
                    else value
                )

            records.append(record)

    return records


def safe_int(value):
    try:
        return int(value) if value is not None else None
    except (ValueError, TypeError):
        return None


def safe_float(value):
    try:
        return float(value) if value is not None else None
    except (ValueError, TypeError):
        return None


def convert_timestamp(value):
    """Convert Zeek epoch timestamp to UTC ISO-8601."""

    timestamp = safe_float(value)

    if timestamp is None:
        return None

    try:
        return datetime.datetime.fromtimestamp(
            timestamp,
            datetime.timezone.utc
        ).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


def normalize(raw_dir, output_file):

    logging.info("=" * 60)
    logging.info("ZEEK TELEMETRY NORMALIZATION")
    logging.info("=" * 60)

    conn_file = os.path.join(
        raw_dir,
        "conn.log"
    )

    dns_file = os.path.join(
        raw_dir,
        "dns.log"
    )

    ssl_file = os.path.join(
        raw_dir,
        "ssl.log"
    )

    conn_records = parse_zeek_tsv(conn_file)
    dns_records = parse_zeek_tsv(dns_file)
    ssl_records = parse_zeek_tsv(ssl_file)

    logging.info(
        "Connection records: %d",
        len(conn_records)
    )

    logging.info(
        "DNS records: %d",
        len(dns_records)
    )

    logging.info(
        "TLS records: %d",
        len(ssl_records)
    )

    dns_map = {
        record.get("uid"): record
        for record in dns_records
        if record.get("uid")
    }

    ssl_map = {
        record.get("uid"): record
        for record in ssl_records
        if record.get("uid")
    }

    output_parent = os.path.dirname(output_file)

    if output_parent:
        os.makedirs(
            output_parent,
            exist_ok=True
        )

    count = 0

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as output:

        for conn in conn_records:

            uid = conn.get("uid")

            if not uid:
                continue

            dns_info = None

            dns_entry = dns_map.get(uid)

            if dns_entry:

                dns_info = {
                    "query": dns_entry.get("query"),
                    "qtype_name": dns_entry.get("qtype_name"),
                    "rcode_name": dns_entry.get("rcode_name")
                }

            tls_info = None

            ssl_entry = ssl_map.get(uid)

            if ssl_entry:

                tls_info = {
                    "version": ssl_entry.get("version"),
                    "cipher": ssl_entry.get("cipher"),
                    "server_name": ssl_entry.get("server_name"),
                    "ja3": ssl_entry.get("ja3"),
                    "ja3s": ssl_entry.get("ja3s")
                }

            record = {
                "timestamp": convert_timestamp(
                    conn.get("ts")
                ),

                "flow_id": str(uid),

                "src_ip": conn.get("id.orig_h"),
                "dst_ip": conn.get("id.resp_h"),

                "src_port": safe_int(
                    conn.get("id.orig_p")
                ),

                "dst_port": safe_int(
                    conn.get("id.resp_p")
                ),

                "protocol": str(
                    conn.get("proto", "UNKNOWN")
                ).upper(),

                "duration": safe_float(
                    conn.get("duration")
                ),

                "bytes_out": safe_int(
                    conn.get("orig_bytes")
                ),

                "bytes_in": safe_int(
                    conn.get("resp_bytes")
                ),

                "packets_out": safe_int(
                    conn.get("orig_pkts")
                ),

                "packets_in": safe_int(
                    conn.get("resp_pkts")
                ),

                "conn_state": conn.get("conn_state"),
                "history": conn.get("history"),

                "dns": dns_info,
                "tls": tls_info,
                "quic": None,

                "sensor": "zeek",
                "sensor_version": "zeek-native"
            }

            output.write(
                json.dumps(
                    record,
                    separators=(",", ":")
                ) + "\n"
            )

            count += 1

    logging.info(
        "SUCCESS: Normalized %d Zeek flows.",
        count
    )

    logging.info(
        "Output: %s",
        output_file
    )

    return True


if __name__ == "__main__":

    normalize(
        "data/telemetry/raw/zeek/sample",
        "data/telemetry/normalized/normalized_telemetry.jsonl"
    )