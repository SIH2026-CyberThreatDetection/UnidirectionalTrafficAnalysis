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
# PATHS
# ============================================================

HISTORICAL_PATH = Path(
    "data/processed/final_feature_matrix.csv"
)

SYNTHETIC_PATH = Path(
    "data/interim/synthetic_dns_tunnels.csv"
)

HISTORICAL_BACKUP_PATH = Path(
    "data/interim/historical_feature_matrix.csv"
)

MASTER_OUTPUT_PATH = Path(
    "data/processed/final_feature_matrix.csv"
)


# ============================================================
# M3 MODEL FEATURE CONTRACT
# ============================================================
#
# These are the features expected by the three-model layer:
#
#   - Isolation Forest
#   - Random Forest
#   - XGBoost
#
# The models must eventually receive the same feature schema.
#
# ============================================================

MODEL_FEATURES = [
    "duration",
    "bytes_out",
    "packets_out",
    "total_bytes",
    "total_packets",
    "byte_ratio",
    "packet_ratio",
    "bytes_per_second",
    "packets_per_second",
    "dns_query_length",
    "dns_entropy",
    "is_encrypted",
    "uses_deprecated_crypto",
    "sni_entropy"
]


# ============================================================
# FEATURES THAT CAN SAFELY DEFAULT TO ZERO
# ============================================================
#
# These features represent optional protocol observations.
#
# For example:
#
#   DNS-only traffic -> no TLS SNI -> sni_entropy = 0
#
# This is NOT the same as inventing a random value.
#
# ============================================================

ZERO_DEFAULT_FEATURES = {
    "bytes_out": 0.0,
    "packets_out": 0.0,
    "byte_ratio": 0.0,
    "packet_ratio": 0.0,
    "dns_query_length": 0.0,
    "dns_entropy": 0.0,
    "is_encrypted": 0.0,
    "uses_deprecated_crypto": 0.0,
    "sni_entropy": 0.0,
}


# ============================================================
# LABEL NORMALIZATION
# ============================================================

def normalize_label(value):
    """
    Normalize a dataset label.

    BENIGN and NORMAL become BENIGN.

    Other labels remain explicit attack labels.
    """

    if pd.isna(value):
        return "BENIGN"

    label = str(value).strip().upper()

    if label in {
        "BENIGN",
        "NORMAL"
    }:
        return "BENIGN"

    return label


# ============================================================
# LABEL VALIDATION
# ============================================================

def ensure_labels(
    df,
    dataset_name
):
    """
    Ensure both Label and is_attack exist.

    Label is treated as the primary multiclass ground truth.

    is_attack is derived from Label when necessary.
    """

    df = df.copy()

    logging.info(
        "Validating labels for %s dataset...",
        dataset_name
    )

    # --------------------------------------------------------
    # CASE 1:
    # Label exists
    # --------------------------------------------------------

    if "Label" in df.columns:

        df["Label"] = (
            df["Label"]
            .apply(normalize_label)
        )

        label_attack = (
            ~df["Label"].isin(
                [
                    "BENIGN",
                    "NORMAL"
                ]
            )
        ).astype(int)

        # ----------------------------------------------------
        # If is_attack does not exist, create it.
        # ----------------------------------------------------

        if "is_attack" not in df.columns:

            logging.info(
                "%s: creating is_attack from Label.",
                dataset_name
            )

            df["is_attack"] = label_attack

        else:

            numeric_attack = pd.to_numeric(
                df["is_attack"],
                errors="coerce"
            )

            invalid_count = (
                numeric_attack.isna().sum()
            )

            if invalid_count > 0:

                logging.warning(
                    "%s: %d invalid is_attack values. "
                    "Rebuilding from Label.",
                    dataset_name,
                    invalid_count
                )

                df["is_attack"] = label_attack

            else:

                numeric_attack = (
                    numeric_attack
                    .astype(int)
                )

                if not numeric_attack.isin(
                    [0, 1]
                ).all():

                    logging.warning(
                        "%s: invalid binary target detected. "
                        "Rebuilding from Label.",
                        dataset_name
                    )

                    df["is_attack"] = label_attack

                else:

                    disagreement = (
                        numeric_attack
                        != label_attack
                    ).sum()

                    if disagreement > 0:

                        logging.warning(
                            "%s: %d Label/is_attack "
                            "disagreements detected. "
                            "Label is used as ground truth.",
                            dataset_name,
                            disagreement
                        )

                        df["is_attack"] = label_attack

                    else:

                        df["is_attack"] = (
                            numeric_attack
                        )

    # --------------------------------------------------------
    # CASE 2:
    # Label does not exist
    # --------------------------------------------------------

    else:

        logging.warning(
            "%s has no Label column.",
            dataset_name
        )

        if "is_attack" not in df.columns:

            raise ValueError(
                f"{dataset_name} contains neither "
                "'Label' nor 'is_attack'. "
                "Cannot determine ground truth."
            )

        numeric_attack = pd.to_numeric(
            df["is_attack"],
            errors="coerce"
        )

        if numeric_attack.isna().any():

            raise ValueError(
                f"{dataset_name} contains invalid "
                "is_attack values."
            )

        numeric_attack = (
            numeric_attack
            .astype(int)
        )

        if not numeric_attack.isin(
            [0, 1]
        ).all():

            raise ValueError(
                f"{dataset_name} contains values other "
                "than 0 or 1 in is_attack."
            )

        df["is_attack"] = numeric_attack

        # ----------------------------------------------------
        # IMPORTANT:
        #
        # We do not pretend to know the exact attack type.
        #
        # ----------------------------------------------------

        df["Label"] = np.where(
            df["is_attack"] == 1,
            "UNKNOWN_ATTACK",
            "BENIGN"
        )

        logging.warning(
            "%s: Label reconstructed as BENIGN/"
            "UNKNOWN_ATTACK because original Label "
            "was unavailable.",
            dataset_name
        )

    return df


# ============================================================
# TIMESTAMP VALIDATION
# ============================================================

def validate_timestamp(
    df,
    dataset_name
):
    """
    Convert timestamps to UTC and remove invalid rows.
    """

    df = df.copy()

    if "timestamp" not in df.columns:

        raise ValueError(
            f"{dataset_name} has no timestamp column."
        )

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce",
        utc=True
    )

    invalid = df["timestamp"].isna().sum()

    if invalid > 0:

        logging.warning(
            "%s: removing %d rows with invalid timestamps.",
            dataset_name,
            invalid
        )

        df = (
            df
            .dropna(
                subset=["timestamp"]
            )
            .copy()
        )

    if df.empty:

        raise ValueError(
            f"{dataset_name} has no valid timestamped rows."
        )

    return df


# ============================================================
# NUMERIC FEATURE NORMALIZATION
# ============================================================

def normalize_numeric_features(
    df,
    dataset_name
):
    """
    Convert model features to numeric values.

    Missing optional protocol features are assigned zero.
    """

    df = df.copy()

    for feature in MODEL_FEATURES:

        if feature not in df.columns:

            if feature in ZERO_DEFAULT_FEATURES:

                df[feature] = (
                    ZERO_DEFAULT_FEATURES[
                        feature
                    ]
                )

                logging.info(
                    "%s: missing '%s' -> defaulting to 0.",
                    dataset_name,
                    feature
                )

            else:

                raise ValueError(
                    f"{dataset_name} is missing required "
                    f"model feature '{feature}'."
                )

        df[feature] = pd.to_numeric(
            df[feature],
            errors="coerce"
        )

    # --------------------------------------------------------
    # Replace invalid numeric values.
    # --------------------------------------------------------

    for feature in MODEL_FEATURES:

        invalid = (
            df[feature]
            .isna()
            .sum()
        )

        if invalid > 0:

            logging.warning(
                "%s: %d invalid values in '%s'. "
                "Replacing with 0.",
                dataset_name,
                invalid,
                feature
            )

            df[feature] = (
                df[feature]
                .fillna(0.0)
            )

    return df


# ============================================================
# SYNTHETIC TIMESTAMP GENERATION
# ============================================================

def assign_synthetic_timestamps(
    historical,
    synthetic
):
    """
    Place synthetic DNS traffic after the historical
    observation period.

    Synthetic rows are interleaved by label so that the
    synthetic period is not:

        BENIGN x 5000
        DNS_TUNNELING x 5000

    Instead:

        BENIGN
        DNS_TUNNELING
        BENIGN
        DNS_TUNNELING
        ...

    This makes chronological evaluation less degenerate.
    """

    synthetic = synthetic.copy()

    if synthetic.empty:

        raise ValueError(
            "Synthetic dataset is empty."
        )

    historical_end = (
        historical["timestamp"].max()
    )

    synthetic["_merge_order"] = np.arange(
        len(synthetic)
    )

    benign = (
        synthetic[
            synthetic["Label"] == "BENIGN"
        ]
        .sort_values("_merge_order")
        .copy()
    )

    attacks = (
        synthetic[
            synthetic["Label"] != "BENIGN"
        ]
        .sort_values("_merge_order")
        .copy()
    )

    ordered_parts = []

    max_length = max(
        len(benign),
        len(attacks)
    )

    for index in range(max_length):

        if index < len(benign):

            ordered_parts.append(
                benign.iloc[[index]]
            )

        if index < len(attacks):

            ordered_parts.append(
                attacks.iloc[[index]]
            )

    if not ordered_parts:

        raise ValueError(
            "Could not construct synthetic timeline."
        )

    synthetic = pd.concat(
        ordered_parts,
        ignore_index=True
    )

    synthetic.drop(
        columns=["_merge_order"],
        inplace=True,
        errors="ignore"
    )

    # --------------------------------------------------------
    # Give each record a deterministic timestamp.
    # --------------------------------------------------------

    synthetic["timestamp"] = (
        historical_end
        + pd.to_timedelta(
            np.arange(
                1,
                len(synthetic) + 1
            ),
            unit="s"
        )
    )

    return synthetic


# ============================================================
# SCHEMA ALIGNMENT
# ============================================================

def align_schemas(
    historical,
    synthetic
):
    """
    Make both datasets share exactly the same columns.
    """

    all_columns = sorted(
        set(historical.columns)
        | set(synthetic.columns)
    )

    for column in all_columns:

        if column not in historical.columns:

            historical[column] = np.nan

        if column not in synthetic.columns:

            synthetic[column] = np.nan

    historical = historical[
        all_columns
    ]

    synthetic = synthetic[
        all_columns
    ]

    return historical, synthetic


# ============================================================
# DATASET QUALITY CHECK
# ============================================================

def validate_final_dataset(
    df
):
    """
    Final sanity checks before saving the master dataset.
    """

    required_columns = [
        "timestamp",
        "Label",
        "is_attack"
    ]

    missing = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing:

        raise ValueError(
            f"Final dataset missing required columns: "
            f"{missing}"
        )

    # --------------------------------------------------------
    # Binary target
    # --------------------------------------------------------

    if not df["is_attack"].isin(
        [0, 1]
    ).all():

        raise ValueError(
            "Final dataset contains invalid is_attack values."
        )

    # --------------------------------------------------------
    # Label
    # --------------------------------------------------------

    if df["Label"].isna().any():

        raise ValueError(
            "Final dataset contains missing labels."
        )

    # --------------------------------------------------------
    # Timestamp ordering
    # --------------------------------------------------------

    if not df[
        "timestamp"
    ].is_monotonic_increasing:

        raise ValueError(
            "Final dataset is not chronologically sorted."
        )

    # --------------------------------------------------------
    # Model feature presence
    # --------------------------------------------------------

    missing_features = [
        feature
        for feature in MODEL_FEATURES
        if feature not in df.columns
    ]

    if missing_features:

        raise ValueError(
            "Final dataset missing model features: "
            f"{missing_features}"
        )


# ============================================================
# LOAD HISTORICAL DATA
# ============================================================

def load_historical_dataset():
    """
    Load the original historical feature matrix.

    A protected backup prevents repeated executions of this
    script from merging synthetic data repeatedly.
    """

    HISTORICAL_BACKUP_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Existing protected copy
    # --------------------------------------------------------

    if HISTORICAL_BACKUP_PATH.exists():

        logging.info(
            "Loading protected historical dataset:"
        )

        logging.info(
            "  %s",
            HISTORICAL_BACKUP_PATH
        )

        return pd.read_csv(
            HISTORICAL_BACKUP_PATH,
            low_memory=False
        )

    # --------------------------------------------------------
    # No backup -> use current matrix.
    # --------------------------------------------------------

    if not HISTORICAL_PATH.exists():

        raise FileNotFoundError(
            f"Historical feature matrix not found:\n"
            f"{HISTORICAL_PATH}\n\n"
            "Run tls_features.py first."
        )

    logging.info(
        "No historical backup exists."
    )

    logging.info(
        "Loading current feature matrix:"
    )

    logging.info(
        "  %s",
        HISTORICAL_PATH
    )

    historical = pd.read_csv(
        HISTORICAL_PATH,
        low_memory=False
    )

    # --------------------------------------------------------
    # Protect against accidentally backing up an already
    # merged dataset.
    # --------------------------------------------------------

    if "source_dataset" in historical.columns:

        source_values = (
            historical["source_dataset"]
            .astype(str)
            .str.lower()
        )

        if source_values.str.contains(
            "synthetic"
        ).any():

            raise RuntimeError(
                "\nThe current final_feature_matrix.csv "
                "already contains synthetic data.\n\n"
                "Regenerate the historical feature matrix "
                "first using:\n\n"
                "python src/02_feature_dataset/tls_features.py\n\n"
                "Then run:\n\n"
                "python src/02_feature_dataset/merge_datasets.py"
            )

    # --------------------------------------------------------
    # Save protected historical dataset.
    # --------------------------------------------------------

    historical.to_csv(
        HISTORICAL_BACKUP_PATH,
        index=False
    )

    logging.info(
        "Protected historical dataset created:"
    )

    logging.info(
        "  %s",
        HISTORICAL_BACKUP_PATH
    )

    return historical


# ============================================================
# MAIN MERGE
# ============================================================

def merge_datasets():

    print()
    print("=" * 70)
    print("             M2 DATASET MERGE")
    print("        HISTORICAL + SYNTHETIC DNS")
    print("=" * 70)
    print()

    # --------------------------------------------------------
    # Check synthetic dataset
    # --------------------------------------------------------

    if not SYNTHETIC_PATH.exists():

        raise FileNotFoundError(
            f"Synthetic DNS dataset not found:\n"
            f"{SYNTHETIC_PATH}\n\n"
            "Run generate_dns_tunnels.py first."
        )

    # --------------------------------------------------------
    # Load datasets
    # --------------------------------------------------------

    historical = load_historical_dataset()

    synthetic = pd.read_csv(
        SYNTHETIC_PATH,
        low_memory=False
    )

    logging.info(
        "Historical rows loaded: %d",
        len(historical)
    )

    logging.info(
        "Synthetic rows loaded: %d",
        len(synthetic)
    )

    # --------------------------------------------------------
    # Labels
    # --------------------------------------------------------

    historical = ensure_labels(
        historical,
        "historical"
    )

    synthetic = ensure_labels(
        synthetic,
        "synthetic"
    )

    # --------------------------------------------------------
    # Timestamps
    # --------------------------------------------------------

    historical = validate_timestamp(
        historical,
        "historical"
    )

    synthetic = validate_timestamp(
        synthetic,
        "synthetic"
    )

    # --------------------------------------------------------
    # Source metadata
    # --------------------------------------------------------

    historical["source_dataset"] = (
        "historical_telemetry"
    )

    synthetic["source_dataset"] = (
        "synthetic_dns"
    )

    # --------------------------------------------------------
    # Scenario metadata
    # --------------------------------------------------------

    if "scenario" not in historical.columns:

        historical["scenario"] = (
            "historical"
        )

    historical["scenario"] = (
        historical["scenario"]
        .fillna("historical")
        .astype(str)
    )

    synthetic["scenario"] = (
        "dns_tunneling"
    )

    # --------------------------------------------------------
    # Normalize required model features.
    #
    # THIS is where sni_entropy gets safely added.
    # --------------------------------------------------------

    logging.info(
        "Aligning M3 model feature contract..."
    )

    historical = normalize_numeric_features(
        historical,
        "historical"
    )

    synthetic = normalize_numeric_features(
        synthetic,
        "synthetic"
    )

    # --------------------------------------------------------
    # Create synthetic timeline.
    # --------------------------------------------------------

    logging.info(
        "Creating synthetic DNS timeline..."
    )

    synthetic = assign_synthetic_timestamps(
        historical,
        synthetic
    )

    # --------------------------------------------------------
    # Align complete schemas.
    # --------------------------------------------------------

    logging.info(
        "Aligning dataset schemas..."
    )

    historical, synthetic = align_schemas(
        historical,
        synthetic
    )

    # --------------------------------------------------------
    # Combine.
    # --------------------------------------------------------

    master = pd.concat(
        [
            historical,
            synthetic
        ],
        ignore_index=True
    )

    # --------------------------------------------------------
    # Chronological ordering.
    # --------------------------------------------------------

    master = (
        master
        .sort_values(
            "timestamp"
        )
        .reset_index(
            drop=True
        )
    )

    # --------------------------------------------------------
    # Remove exact duplicates.
    # --------------------------------------------------------

    duplicate_count = (
        master
        .duplicated()
        .sum()
    )

    if duplicate_count > 0:

        logging.warning(
            "Removing %d exact duplicate rows.",
            duplicate_count
        )

        master = (
            master
            .drop_duplicates(
                keep="first"
            )
            .reset_index(
                drop=True
            )
        )

    # --------------------------------------------------------
    # Final validation.
    # --------------------------------------------------------

    validate_final_dataset(
        master
    )

    # --------------------------------------------------------
    # Save.
    # --------------------------------------------------------

    MASTER_OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    master.to_csv(
        MASTER_OUTPUT_PATH,
        index=False
    )

    # ========================================================
    # REPORT
    # ========================================================

    print()
    print("=" * 70)
    print("                 MERGE COMPLETE")
    print("=" * 70)

    logging.info(
        "Historical rows: %d",
        len(historical)
    )

    logging.info(
        "Synthetic rows: %d",
        len(synthetic)
    )

    logging.info(
        "Master rows: %d",
        len(master)
    )

    logging.info(
        "Master columns: %d",
        len(master.columns)
    )

    print()
    print("Binary target distribution:")

    print(
        master["is_attack"]
        .value_counts()
        .sort_index()
        .to_string()
    )

    print()
    print("Multiclass label distribution:")

    print(
        master["Label"]
        .value_counts()
        .to_string()
    )

    print()

    logging.info(
        "Timestamp range:"
    )

    logging.info(
        "  First: %s",
        master["timestamp"].min()
    )

    logging.info(
        "  Last:  %s",
        master["timestamp"].max()
    )

    logging.info(
        "Final model feature count: %d",
        len(MODEL_FEATURES)
    )

    logging.info(
        "Saved master dataset:"
    )

    logging.info(
        "  %s",
        MASTER_OUTPUT_PATH
    )

    logging.info(
        "Protected historical dataset:"
    )

    logging.info(
        "  %s",
        HISTORICAL_BACKUP_PATH
    )

    print()
    print("=" * 70)
    print("              M2 MERGE SUCCESSFUL")
    print("=" * 70)
    print()

    return True


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        merge_datasets()

    except Exception as exc:

        logging.error(
            "M2 MERGE FAILED: %s",
            exc
        )

        raise SystemExit(1)