import json
import logging
from pathlib import Path

import numpy as np
import pandas as pd


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)


# ============================================================
# HELPERS
# ============================================================

def make_duplicate_safe(value):
    """
    Convert unhashable Python objects into deterministic strings
    for duplicate detection.

    IMPORTANT:
    This function is used ONLY for duplicate checking.
    The original dataframe values are not modified.

    Examples:
        dict -> JSON string
        list -> JSON string
        tuple -> JSON string
        set -> sorted JSON string
    """

    if isinstance(value, dict):
        return json.dumps(
            value,
            sort_keys=True,
            default=str
        )

    if isinstance(value, (list, tuple)):
        return json.dumps(
            list(value),
            sort_keys=True,
            default=str
        )

    if isinstance(value, set):
        return json.dumps(
            sorted(
                list(value),
                key=lambda item: str(item)
            ),
            default=str
        )

    return value


def remove_duplicates_safely(df: pd.DataFrame) -> pd.DataFrame:
    """
    Remove duplicate rows even when dataframe cells contain
    dictionaries, lists, tuples, or sets.

    The original dataframe is preserved. A temporary
    duplicate-safe dataframe is created only for comparison.
    """

    logging.info("Checking for duplicate telemetry records...")

    if df.empty:
        return df

    duplicate_check_df = df.copy()

    # Convert only object/string-like columns to hashable values
    # in the temporary dataframe.
    for column in duplicate_check_df.columns:

        if (
            duplicate_check_df[column].dtype == "object"
            or pd.api.types.is_string_dtype(
                duplicate_check_df[column].dtype
            )
        ):

            duplicate_check_df[column] = (
                duplicate_check_df[column]
                .map(make_duplicate_safe)
            )

    duplicate_mask = duplicate_check_df.duplicated(
        keep="first"
    )

    duplicate_count = int(
        duplicate_mask.sum()
    )

    if duplicate_count > 0:

        logging.warning(
            f"Removing {duplicate_count} duplicate telemetry "
            f"records."
        )

        df = df.loc[
            ~duplicate_mask
        ].copy()

    else:

        logging.info(
            "No duplicate telemetry records found."
        )

    return df.reset_index(
        drop=True
    )


# ============================================================
# MAIN CLEANING FUNCTION
# ============================================================

def clean_telemetry(
    telemetry_file: Path,
    output_file: Path
):
    """
    Clean normalized telemetry for feature engineering.

    Processing performed:

    1. Load JSONL telemetry.
    2. Ignore empty lines.
    3. Skip invalid JSON records.
    4. Convert records into a dataframe.
    5. Safely remove duplicate records, including rows
       containing dictionaries/lists.
    6. Convert expected numeric fields to numeric values.
    7. Fill missing counters with zero.
    8. Replace infinite values with NaN.
    9. Validate network ports.
    10. Validate flow duration.
    11. Parse and sort timestamps.
    12. Remove forbidden backward-direction features.
    13. Ensure binary attack target exists.
    14. Preserve the original Label for M3.
    15. Save cleaned CSV.

    The cleaning stage does NOT perform ML scaling.
    Scaling is handled later by split.py.
    """

    logging.info(
        f"Loading telemetry from {telemetry_file}"
    )

    # ========================================================
    # 1. CHECK INPUT
    # ========================================================

    if not telemetry_file.exists():

        logging.error(
            f"Telemetry file not found: "
            f"{telemetry_file}"
        )

        return False

    # ========================================================
    # 2. LOAD JSONL
    # ========================================================

    records = []

    invalid_json_count = 0

    try:

        with open(
            telemetry_file,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            for line_number, line in enumerate(
                file,
                start=1
            ):

                # Ignore blank lines
                if not line.strip():
                    continue

                try:

                    record = json.loads(
                        line
                    )

                except json.JSONDecodeError as error:

                    invalid_json_count += 1

                    logging.warning(
                        f"Skipping invalid JSON on "
                        f"line {line_number}: {error}"
                    )

                    continue

                # Make sure every JSON record is an object.
                if not isinstance(record, dict):

                    logging.warning(
                        f"Skipping non-object JSON record "
                        f"on line {line_number}."
                    )

                    continue

                records.append(
                    record
                )

    except OSError as error:

        logging.error(
            f"Could not read telemetry file: {error}"
        )

        return False

    # ========================================================
    # 3. BASIC VALIDATION
    # ========================================================

    if invalid_json_count > 0:

        logging.warning(
            f"Skipped {invalid_json_count} invalid JSON records."
        )

    if not records:

        logging.error(
            "No valid telemetry records found."
        )

        return False

    df = pd.DataFrame(
        records
    )

    logging.info(
        f"Loaded {len(df)} rows and "
        f"{len(df.columns)} columns."
    )

    # ========================================================
    # 4. SAFE DUPLICATE REMOVAL
    # ========================================================
    #
    # FIX FOR YOUR CURRENT ERROR:
    #
    # TypeError: unhashable type: 'dict'
    #
    # We do NOT modify the original dictionary values.
    # We create a temporary hashable representation only
    # for duplicate detection.
    #
    # ========================================================

    df = remove_duplicates_safely(
        df
    )

    logging.info(
        f"Rows after duplicate removal: {len(df)}"
    )

    # ========================================================
    # 5. NUMERIC COLUMN CONVERSION
    # ========================================================

    numeric_columns = [
        "src_port",
        "dst_port",
        "duration",
        "bytes_out",
        "bytes_in",
        "packets_out",
        "packets_in",
        "suricata_alert_count",
        "has_suricata_alert",
        "alert_severity"
    ]

    logging.info(
        "Converting numeric telemetry fields..."
    )

    for column in numeric_columns:

        if column in df.columns:

            df[column] = pd.to_numeric(
                df[column],
                errors="coerce"
            )

    # ========================================================
    # 6. FILL MISSING COUNTER VALUES
    # ========================================================

    counter_columns = [
        "src_port",
        "dst_port",
        "bytes_out",
        "bytes_in",
        "packets_out",
        "packets_in",
        "suricata_alert_count",
        "has_suricata_alert"
    ]

    for column in counter_columns:

        if column in df.columns:

            df[column] = (
                df[column]
                .fillna(0)
            )

    # Duration gets zero when missing.
    if "duration" in df.columns:

        df["duration"] = (
            df["duration"]
            .fillna(0)
        )

    # ========================================================
    # 7. REPLACE INFINITE VALUES
    # ========================================================

    df.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True
    )

    # ========================================================
    # 8. VALIDATE PORT VALUES
    # ========================================================

    if (
        "src_port" in df.columns
        and "dst_port" in df.columns
    ):

        valid_ports = (
            df["src_port"].between(
                0,
                65535
            )
            &
            df["dst_port"].between(
                0,
                65535
            )
        )

        invalid_ports = int(
            (~valid_ports).sum()
        )

        if invalid_ports:

            logging.warning(
                f"Removing {invalid_ports} rows with "
                f"invalid network ports."
            )

            df = df.loc[
                valid_ports
            ].copy()

    # ========================================================
    # 9. VALIDATE DURATION
    # ========================================================

    if "duration" in df.columns:

        valid_duration = (
            df["duration"] >= 0
        )

        invalid_duration = int(
            (~valid_duration).sum()
        )

        if invalid_duration:

            logging.warning(
                f"Removing {invalid_duration} rows with "
                f"negative duration."
            )

            df = df.loc[
                valid_duration
            ].copy()

    # ========================================================
    # 10. TIMESTAMP PROCESSING
    # ========================================================

    if "timestamp" in df.columns:

        logging.info(
            "Parsing telemetry timestamps..."
        )

        df["timestamp"] = pd.to_datetime(
            df["timestamp"],
            errors="coerce",
            utc=True
        )

        invalid_timestamps = int(
            df["timestamp"]
            .isna()
            .sum()
        )

        if invalid_timestamps:

            logging.warning(
                f"Removing {invalid_timestamps} rows with "
                f"invalid timestamps."
            )

            df = df.dropna(
                subset=[
                    "timestamp"
                ]
            ).copy()

        # Chronological ordering is important because
        # split.py later performs a strict time-aware split.
        df = (
            df
            .sort_values(
                "timestamp"
            )
            .reset_index(
                drop=True
            )
        )

        logging.info(
            "Telemetry sorted chronologically."
        )

    else:

        logging.warning(
            "No timestamp column found."
        )

        logging.warning(
            "Chronological ordering cannot be guaranteed."
        )

    # ========================================================
    # 11. REMOVE FORBIDDEN BACKWARD-DIRECTION FEATURES
    # ========================================================
    #
    # Your project is specifically based on
    # unidirectional traffic.
    #
    # Therefore features representing the backward/
    # responder direction should not enter the feature matrix.
    #
    # ========================================================

    forbidden_columns = []

    forbidden_patterns = [
        "bwd",
        "backward",
        "resp_"
    ]

    for column in df.columns:

        column_lower = str(
            column
        ).lower()

        if any(
            pattern in column_lower
            for pattern in forbidden_patterns
        ):

            forbidden_columns.append(
                column
            )

    if forbidden_columns:

        logging.info(
            f"Removing forbidden backward-direction "
            f"columns: {forbidden_columns}"
        )

        df.drop(
            columns=forbidden_columns,
            inplace=True,
            errors="ignore"
        )

    # ========================================================
    # 12. LABEL VALIDATION
    # ========================================================

    if "Label" not in df.columns:

        logging.warning(
            "'Label' column not found."
        )

        logging.warning(
            "M3 multiclass training may require the "
            "original attack label."
        )

    else:

        # Clean whitespace while preserving the actual label.
        df["Label"] = (
            df["Label"]
            .astype(str)
            .str.strip()
        )

    # ========================================================
    # 13. CREATE BINARY is_attack TARGET
    # ========================================================

    if "is_attack" not in df.columns:

        logging.info(
            "'is_attack' column not found."
        )

        if "Label" in df.columns:

            logging.info(
                "Creating binary is_attack target from Label."
            )

            df["is_attack"] = (
                df["Label"]
                .astype(str)
                .str.strip()
                .str.lower()
                .apply(
                    lambda value:
                    0
                    if value in (
                        "benign",
                        "normal"
                    )
                    else 1
                )
            )

        else:

            logging.warning(
                "No Label available."
            )

            logging.warning(
                "Creating fallback is_attack=0."
            )

            df["is_attack"] = 0

    else:

        logging.info(
            "'is_attack' column already exists."
        )

        df["is_attack"] = pd.to_numeric(
            df["is_attack"],
            errors="coerce"
        )

        invalid_attack_values = int(
            df["is_attack"]
            .isna()
            .sum()
        )

        if invalid_attack_values:

            logging.warning(
                f"Found {invalid_attack_values} invalid "
                f"is_attack values. Converting them to 0."
            )

            df["is_attack"] = (
                df["is_attack"]
                .fillna(0)
            )

        df["is_attack"] = (
            df["is_attack"] > 0
        ).astype(int)

    # ========================================================
    # 14. FINAL EMPTY DATASET CHECK
    # ========================================================

    if len(df) == 0:

        logging.error(
            "Dataset became empty after cleaning."
        )

        return False

    # ========================================================
    # 15. FINAL DUPLICATE CHECK
    # ========================================================
    #
    # Some rows can become equivalent after cleaning.
    # Perform one final safe check.
    #
    # ========================================================

    df = remove_duplicates_safely(
        df
    )

    if len(df) == 0:

        logging.error(
            "Dataset became empty after final duplicate removal."
        )

        return False

    # ========================================================
    # 16. OUTPUT DIRECTORY
    # ========================================================

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # ========================================================
    # 17. SAVE CLEAN DATASET
    # ========================================================

    try:

        df.to_csv(
            output_file,
            index=False
        )

    except Exception as error:

        logging.error(
            f"Could not save cleaned dataset: {error}"
        )

        return False

    # ========================================================
    # 18. FINAL REPORT
    # ========================================================

    logging.info(
        f"Clean dataset saved to {output_file}"
    )

    logging.info(
        f"Final dataset: "
        f"{len(df)} rows × "
        f"{len(df.columns)} columns"
    )

    if "is_attack" in df.columns:

        attack_distribution = (
            df["is_attack"]
            .value_counts()
            .sort_index()
        )

        logging.info(
            "Binary target distribution:"
        )

        for value, count in attack_distribution.items():

            logging.info(
                f"  is_attack={value}: {count}"
            )

    if "Label" in df.columns:

        logging.info(
            "Label distribution:"
        )

        label_distribution = (
            df["Label"]
            .value_counts()
        )

        for label, count in label_distribution.items():

            logging.info(
                f"  {label}: {count}"
            )

    logging.info(
        "Phase 2.1 cleaning completed successfully."
    )

    return True


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    input_file = Path(
        "data/telemetry/normalized/"
        "master_telemetry.jsonl"
    )

    output_file = Path(
        "data/interim/"
        "clean_telemetry.csv"
    )

    success = clean_telemetry(
        input_file,
        output_file
    )

    if success:

        logging.info(
            "CLEAN.PY COMPLETED SUCCESSFULLY."
        )

    else:

        logging.error(
            "CLEAN.PY FAILED."
        )

        raise SystemExit(1)