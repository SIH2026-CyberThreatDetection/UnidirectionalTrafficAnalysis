import json
import logging
import os
from bisect import bisect_left
from datetime import datetime, timezone


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)


# ============================================================
# CONFIGURATION
# ============================================================

TIMESTAMP_TOLERANCE_SECONDS = 5.0

PROGRESS_INTERVAL = 100_000


# ============================================================
# TIME HELPERS
# ============================================================

def parse_time(value):
    """
    Convert an ISO-8601 timestamp into a timezone-aware datetime.

    Returns:
        datetime | None
    """

    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(
            str(value).replace(
                "Z",
                "+00:00"
            )
        )

        # Make naive timestamps UTC-aware so they can safely
        # participate in timestamp comparisons.
        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed

    except (
        ValueError,
        TypeError
    ):
        return None


def timestamp_seconds(value):
    """
    Convert an ISO-8601 timestamp into Unix seconds.

    Returns:
        float | None
    """

    parsed = parse_time(
        value
    )

    if parsed is None:
        return None

    return parsed.timestamp()


# ============================================================
# FLOW KEY
# ============================================================

def flow_key(record):
    """
    Stable directional flow key.

    flow_id is preferred because it is unique inside the
    originating sensor.

    This function is retained for compatibility and for
    identifying Zeek records internally.

    Returns:
        tuple
    """

    flow_id = record.get(
        "flow_id"
    )

    if flow_id:
        return (
            str(
                record.get(
                    "sensor",
                    ""
                )
            ),
            str(
                flow_id
            )
        )

    return (
        str(
            record.get(
                "src_ip",
                ""
            )
        ),
        str(
            record.get(
                "dst_ip",
                ""
            )
        ),
        str(
            record.get(
                "src_port",
                ""
            )
        ),
        str(
            record.get(
                "dst_port",
                ""
            )
        ),
        str(
            record.get(
                "protocol",
                ""
            )
        ).upper(),
        str(
            record.get(
                "timestamp",
                ""
            )
        )
    )


# ============================================================
# DIRECTIONAL MATCH KEY
# ============================================================

def telemetry_match_key(record):
    """
    Build the directional 5-tuple used to associate Suricata
    events with Zeek flows.

    The original implementation compared:

        src_ip
        dst_ip
        src_port
        dst_port
        protocol

    Therefore this function preserves that behavior.

    Ports are normalized to integers where possible.
    Protocol is normalized to uppercase.
    """

    src_ip = str(
        record.get(
            "src_ip",
            ""
        )
    )

    dst_ip = str(
        record.get(
            "dst_ip",
            ""
        )
    )

    src_port = normalize_port(
        record.get(
            "src_port"
        )
    )

    dst_port = normalize_port(
        record.get(
            "dst_port"
        )
    )

    protocol = str(
        record.get(
            "protocol",
            ""
        )
    ).upper()

    return (
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol
    )


def normalize_port(value):
    """
    Normalize a port value in the same spirit as the old
    implementation.

    Invalid/missing ports become 0.
    """

    try:
        return int(
            value or 0
        )

    except (
        ValueError,
        TypeError
    ):
        return 0


# ============================================================
# SURICATA FIELD INITIALIZATION
# ============================================================

def initialize_suricata_fields(record):
    """
    Initialize the Suricata-derived fields expected by the
    downstream telemetry schema.
    """

    record[
        "suricata_alert_count"
    ] = 0

    record[
        "has_suricata_alert"
    ] = 0

    record[
        "suricata_event_types"
    ] = ""

    record[
        "alert_severity"
    ] = 0

    return record


# ============================================================
# INDEX ENTRY
# ============================================================

def create_index_entry():
    """
    Create an index bucket.

    Structure:

        {
            "timed": [
                (timestamp_seconds, zeek_key),
                ...
            ],
            "untimed": [
                zeek_key,
                ...
            ]
        }

    Timed records are sorted by timestamp after the Zeek
    loading phase.

    Untimed records are retained to preserve the old behavior
    when no usable Zeek timestamp exists.
    """

    return {
        "timed": [],
        "untimed": []
    }


# ============================================================
# ADD ZEEK RECORD TO INDEX
# ============================================================

def add_to_index(
    index,
    match_key,
    timestamp_value,
    record_key
):
    """
    Add one Zeek record to the directional lookup index.
    """

    bucket = index.get(
        match_key
    )

    if bucket is None:

        bucket = create_index_entry()

        index[
            match_key
        ] = bucket

    timestamp = timestamp_seconds(
        timestamp_value
    )

    if timestamp is None:

        bucket[
            "untimed"
        ].append(
            record_key
        )

    else:

        bucket[
            "timed"
        ].append(
            (
                timestamp,
                record_key
            )
        )


# ============================================================
# FINALIZE INDEX
# ============================================================

def finalize_index(index):
    """
    Sort all timestamped Zeek candidates.

    This allows binary-search lookup using bisect instead of
    scanning every Zeek flow for every Suricata event.
    """

    logging.info(
        "Finalizing Zeek timestamp index..."
    )

    bucket_count = 0
    timed_records = 0
    untimed_records = 0

    for bucket in index.values():

        timed = bucket[
            "timed"
        ]

        if timed:

            timed.sort(
                key=lambda item: item[0]
            )

            timed_records += len(
                timed
            )

        untimed_records += len(
            bucket[
                "untimed"
            ]
        )

        bucket_count += 1

    logging.info(
        "Indexed directional keys: %d",
        bucket_count
    )

    logging.info(
        "Indexed timestamped Zeek flows: %d",
        timed_records
    )

    logging.info(
        "Indexed Zeek flows without usable timestamps: %d",
        untimed_records
    )


# ============================================================
# FIND BEST ZEEK MATCH
# ============================================================

def find_best_zeek_match(
    index,
    match_key,
    suricata_timestamp
):
    """
    Find the best Zeek flow for a Suricata event.

    Matching behavior:

    1. Match the same directional 5-tuple.
    2. If the Suricata event has no timestamp:
       use the first candidate.
    3. If the Suricata event has a timestamp and Zeek has
       timestamped candidates:
       find the closest timestamp using binary search.
    4. Reject the match if the closest timestamp is more
       than TIMESTAMP_TOLERANCE_SECONDS away.
    5. If no Zeek candidate has a usable timestamp, preserve
       the original behavior and use the first candidate.
    """

    bucket = index.get(
        match_key
    )

    if bucket is None:
        return None

    timed = bucket[
        "timed"
    ]

    untimed = bucket[
        "untimed"
    ]

    # --------------------------------------------------------
    # No Suricata timestamp
    # --------------------------------------------------------

    if suricata_timestamp is None:

        if timed:

            return timed[0][1]

        if untimed:

            return untimed[0]

        return None

    # --------------------------------------------------------
    # We have timestamped Zeek candidates.
    # --------------------------------------------------------

    if timed:

        timestamps = [
            item[0]
            for item in timed
        ]

        position = bisect_left(
            timestamps,
            suricata_timestamp
        )

        candidates = []

        if position < len(timed):

            candidates.append(
                timed[position]
            )

        if position > 0:

            candidates.append(
                timed[position - 1]
            )

        if not candidates:

            return None

        best_timestamp, best_key = min(
            candidates,
            key=lambda item: abs(
                item[0]
                -
                suricata_timestamp
            )
        )

        delta = abs(
            best_timestamp
            -
            suricata_timestamp
        )

        if delta > TIMESTAMP_TOLERANCE_SECONDS:

            return None

        return best_key

    # --------------------------------------------------------
    # No Zeek timestamps.
    #
    # This preserves the old behavior where the first
    # candidate was accepted if no Zeek timestamp could be
    # parsed.
    # --------------------------------------------------------

    if untimed:

        return untimed[0]

    return None


# ============================================================
# UPDATE SURICATA FIELDS
# ============================================================

def update_suricata_fields(
    target,
    record
):
    """
    Merge one Suricata event into its matched Zeek flow.
    """

    target[
        "suricata_alert_count"
    ] += 1

    target[
        "has_suricata_alert"
    ] = 1

    # --------------------------------------------------------
    # Event type
    # --------------------------------------------------------

    event_type = str(
        record.get(
            "event_type",
            ""
        )
    ).strip()

    if event_type:

        existing_string = str(
            target.get(
                "suricata_event_types",
                ""
            )
        )

        existing = [
            value.strip()
            for value in existing_string.split(
                ","
            )
            if value.strip()
        ]

        if event_type not in existing:

            existing.append(
                event_type
            )

        target[
            "suricata_event_types"
        ] = ",".join(
            existing
        )

    # --------------------------------------------------------
    # Severity
    # --------------------------------------------------------

    severity = record.get(
        "alert_severity"
    )

    try:

        severity = int(
            severity
        )

    except (
        ValueError,
        TypeError
    ):

        severity = 0

    current_severity = target.get(
        "alert_severity",
        0
    )

    try:

        current_severity = int(
            current_severity
        )

    except (
        ValueError,
        TypeError
    ):

        current_severity = 0

    target[
        "alert_severity"
    ] = max(
        current_severity,
        severity
    )


# ============================================================
# LOAD ZEEK TELEMETRY
# ============================================================

def load_zeek_telemetry(
    zeek_file
):
    """
    Load normalized Zeek telemetry and build a directional
    lookup index.

    Returns:

        merged_records
        lookup_index
    """

    merged = {}

    lookup_index = {}

    malformed_lines = 0
    duplicate_keys = 0

    logging.info(
        "Loading Zeek telemetry..."
    )

    with open(
        zeek_file,
        "r",
        encoding="utf-8"
    ) as file:

        for line_number, line in enumerate(
            file,
            start=1
        ):

            if not line.strip():
                continue

            try:

                record = json.loads(
                    line
                )

            except json.JSONDecodeError:

                malformed_lines += 1

                continue

            record = initialize_suricata_fields(
                record
            )

            key = flow_key(
                record
            )

            if key in merged:

                duplicate_keys += 1

                continue

            merged[
                key
            ] = record

            match_key = telemetry_match_key(
                record
            )

            add_to_index(
                lookup_index,
                match_key,
                record.get(
                    "timestamp"
                ),
                key
            )

            if (
                len(merged)
                % PROGRESS_INTERVAL
                == 0
            ):

                logging.info(
                    "Zeek flows indexed: %d",
                    len(merged)
                )

    logging.info(
        "Zeek flows loaded: %d",
        len(merged)
    )

    if duplicate_keys:

        logging.warning(
            "Duplicate Zeek keys skipped: %d",
            duplicate_keys
        )

    if malformed_lines:

        logging.warning(
            "Malformed Zeek JSON lines skipped: %d",
            malformed_lines
        )

    finalize_index(
        lookup_index
    )

    return (
        merged,
        lookup_index
    )


# ============================================================
# PROCESS SURICATA TELEMETRY
# ============================================================

def process_suricata_telemetry(
    suricata_file,
    merged,
    lookup_index
):
    """
    Process Suricata telemetry using the indexed Zeek
    directional keys.

    This replaces the original O(N*M) implementation with
    approximately O(N log K) timestamp lookup behavior.
    """

    processed = 0
    matched = 0
    unmatched = 0
    malformed_lines = 0

    logging.info(
        "Processing Suricata telemetry..."
    )

    with open(
        suricata_file,
        "r",
        encoding="utf-8"
    ) as file:

        for line_number, line in enumerate(
            file,
            start=1
        ):

            if not line.strip():
                continue

            try:

                record = json.loads(
                    line
                )

            except json.JSONDecodeError:

                malformed_lines += 1

                continue

            processed += 1

            match_key = telemetry_match_key(
                record
            )

            suricata_timestamp = timestamp_seconds(
                record.get(
                    "timestamp"
                )
            )

            best_key = find_best_zeek_match(
                lookup_index,
                match_key,
                suricata_timestamp
            )

            if best_key is None:

                unmatched += 1

            else:

                target = merged.get(
                    best_key
                )

                if target is not None:

                    update_suricata_fields(
                        target,
                        record
                    )

                    matched += 1

                else:

                    unmatched += 1

            if (
                processed
                % PROGRESS_INTERVAL
                == 0
            ):

                logging.info(
                    "Suricata events processed: %d | "
                    "matched: %d | "
                    "unmatched: %d",
                    processed,
                    matched,
                    unmatched
                )

    logging.info(
        "Suricata events processed: %d",
        processed
    )

    logging.info(
        "Suricata matched flows: %d",
        matched
    )

    logging.info(
        "Suricata unmatched events: %d",
        unmatched
    )

    if malformed_lines:

        logging.warning(
            "Malformed Suricata JSON lines skipped: %d",
            malformed_lines
        )

    return (
        processed,
        matched,
        unmatched
    )


# ============================================================
# WRITE MERGED TELEMETRY
# ============================================================

def write_merged_telemetry(
    merged,
    output_file
):
    """
    Write merged telemetry as JSONL.

    The output is first written to a temporary file and then
    atomically replaced into the final destination.
    """

    output_parent = os.path.dirname(
        output_file
    )

    if output_parent:

        os.makedirs(
            output_parent,
            exist_ok=True
        )

    temporary_file = (
        output_file
        +
        ".tmp"
    )

    logging.info(
        "Writing merged telemetry..."
    )

    with open(
        temporary_file,
        "w",
        encoding="utf-8"
    ) as file:

        for record in merged.values():

            file.write(
                json.dumps(
                    record,
                    separators=(
                        ",",
                        ":"
                    ),
                    ensure_ascii=False
                )
                +
                "\n"
            )

    os.replace(
        temporary_file,
        output_file
    )

    logging.info(
        "Output written successfully: %s",
        output_file
    )


# ============================================================
# MAIN MERGE FUNCTION
# ============================================================

def merge_telemetry(
    zeek_file,
    suricata_file,
    output_file
):
    """
    Merge normalized Zeek and Suricata telemetry.

    Efficient design:

        Zeek
          |
          v
        Build directional index
          |
          v
        Sort timestamps
          |
          v
        Process Suricata events
          |
          v
        Binary-search nearest Zeek timestamp
          |
          v
        Write unified telemetry

    This avoids scanning all Zeek flows for every Suricata
    event.
    """

    logging.info("=" * 60)
    logging.info(
        "MERGING ZEEK + SURICATA TELEMETRY"
    )
    logging.info("=" * 60)

    # --------------------------------------------------------
    # Validate input files
    # --------------------------------------------------------

    if not os.path.exists(
        zeek_file
    ):

        logging.error(
            "Zeek file not found: %s",
            zeek_file
        )

        return False

    if not os.path.exists(
        suricata_file
    ):

        logging.error(
            "Suricata file not found: %s",
            suricata_file
        )

        return False

    logging.info(
        "Zeek input: %s",
        zeek_file
    )

    logging.info(
        "Suricata input: %s",
        suricata_file
    )

    logging.info(
        "Timestamp tolerance: %.1f seconds",
        TIMESTAMP_TOLERANCE_SECONDS
    )

    # --------------------------------------------------------
    # Load Zeek and build index
    # --------------------------------------------------------

    (
        merged,
        lookup_index
    ) = load_zeek_telemetry(
        zeek_file
    )

    # --------------------------------------------------------
    # Process Suricata using index
    # --------------------------------------------------------

    (
        processed,
        matched,
        unmatched
    ) = process_suricata_telemetry(
        suricata_file,
        merged,
        lookup_index
    )

    # --------------------------------------------------------
    # Write final telemetry
    # --------------------------------------------------------

    write_merged_telemetry(
        merged,
        output_file
    )

    # --------------------------------------------------------
    # Final statistics
    # --------------------------------------------------------

    logging.info("=" * 60)
    logging.info(
        "MERGE COMPLETE"
    )
    logging.info("=" * 60)

    logging.info(
        "Unified records: %d",
        len(merged)
    )

    logging.info(
        "Suricata events processed: %d",
        processed
    )

    logging.info(
        "Suricata matched events: %d",
        matched
    )

    logging.info(
        "Suricata unmatched events: %d",
        unmatched
    )

    if processed:

        match_rate = (
            matched
            /
            processed
            *
            100.0
        )

        logging.info(
            "Suricata match rate: %.2f%%",
            match_rate
        )

    logging.info(
        "Output: %s",
        output_file
    )

    return True


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    success = merge_telemetry(
        "data/telemetry/normalized/normalized_telemetry.jsonl",
        "data/telemetry/normalized/suricata_normalized.jsonl",
        "data/telemetry/normalized/master_telemetry.jsonl"
    )

    if not success:

        raise SystemExit(1)