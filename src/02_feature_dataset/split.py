import json
import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler


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

INPUT_FILE = Path(
    "data/processed/final_feature_matrix.csv"
)

OUTPUT_BASE = Path(
    "data/processed"
)

TRAIN_DIR = OUTPUT_BASE / "train"
VAL_DIR = OUTPUT_BASE / "val"
TEST_DIR = OUTPUT_BASE / "test"

MODEL_PREPROCESSING_DIR = Path(
    "models/preprocessing"
)

FEATURE_ORDER_FILE = Path(
    "features/feature_order.json"
)

FEATURE_CONTRACT_FILE = Path(
    "features/feature_contract.json"
)

SPLIT_REPORT_FILE = Path(
    "reports/split_report.json"
)


# ============================================================
# VERSION
# ============================================================

SPLIT_VERSION = "M2-SPLIT-v3.1"


# ============================================================
# CURRENT M2 FEATURE CONTRACT
#
# Your current M2 dataset contains 14 model features.
#
# This list is only a fallback.
# If feature_order.json exists, it takes priority.
# ============================================================

FALLBACK_FEATURES = [
    "duration",
    "total_bytes",
    "total_packets",
    "bytes_per_second",
    "packets_per_second",
    "bytes_per_packet",
    "byte_ratio",
    "packet_ratio",
    "outbound_fraction",
    "dns_query_length",
    "dns_entropy",
    "dns_digit_fraction",
    "dns_subdomain_depth",
    "sni_entropy"
]


# ============================================================
# BINARY FEATURES
# ============================================================

BINARY_FEATURES = {
    "is_encrypted",
    "uses_deprecated_crypto",
    "has_suricata_alert"
}


# ============================================================
# LEAKAGE / METADATA COLUMNS
# ============================================================

LEAKAGE_COLUMNS = {
    "label",
    "Label",
    "attack_type",
    "project_class",
    "binary_label",
    "is_attack",
    "day",
    "source_file",
    "scenario_id",
    "dataset",
    "source_dataset",
    "scenario"
}


# ============================================================
# LOAD FEATURE ORDER
# ============================================================

def load_feature_order():

    # --------------------------------------------------------
    # Preferred source:
    # features/feature_order.json
    # --------------------------------------------------------

    if FEATURE_ORDER_FILE.exists():

        logging.info(
            "Loading M2 feature order from %s",
            FEATURE_ORDER_FILE
        )

        with open(
            FEATURE_ORDER_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            features = json.load(file)

        if not isinstance(features, list):

            raise ValueError(
                "features/feature_order.json "
                "must contain a JSON list."
            )

        features = [
            str(feature).strip()
            for feature in features
            if str(feature).strip()
        ]

        if not features:

            raise ValueError(
                "features/feature_order.json is empty."
            )

        logging.info(
            "M2 feature count: %d",
            len(features)
        )

        return features

    # --------------------------------------------------------
    # Secondary source:
    # feature_contract.json
    # --------------------------------------------------------

    if FEATURE_CONTRACT_FILE.exists():

        logging.info(
            "feature_order.json not found."
        )

        logging.info(
            "Trying feature contract: %s",
            FEATURE_CONTRACT_FILE
        )

        with open(
            FEATURE_CONTRACT_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            contract = json.load(file)

        features = None

        if isinstance(contract, dict):

            for key in [
                "feature_order",
                "features",
                "model_features"
            ]:

                value = contract.get(key)

                if isinstance(value, list):

                    features = value
                    break

        if features:

            features = [
                str(feature).strip()
                for feature in features
                if str(feature).strip()
            ]

            logging.info(
                "M2 feature count: %d",
                len(features)
            )

            return features

    # --------------------------------------------------------
    # Explicit fallback
    # --------------------------------------------------------

    logging.warning(
        "No M2 feature-order artifact found."
    )

    logging.warning(
        "Using explicit 14-feature fallback contract."
    )

    logging.info(
        "Fallback M2 feature count: %d",
        len(FALLBACK_FEATURES)
    )

    return FALLBACK_FEATURES.copy()


# ============================================================
# LABEL NORMALIZATION
# ============================================================

def normalize_labels(df):

    # --------------------------------------------------------
    # Preserve original Label
    # --------------------------------------------------------

    if "Label" not in df.columns:

        if "label" in df.columns:

            df["Label"] = df["label"]

        else:

            raise ValueError(
                "No Label column exists in the M2 feature matrix."
            )

    # --------------------------------------------------------
    # Normalize label strings
    # --------------------------------------------------------

    df["Label"] = (
        df["Label"]
        .fillna("UNKNOWN")
        .astype(str)
        .str.strip()
        .str.upper()
    )

    # --------------------------------------------------------
    # Binary target
    # --------------------------------------------------------

    if "is_attack" not in df.columns:

        logging.info(
            "Creating is_attack from Label."
        )

        df["is_attack"] = (
            ~df["Label"].isin(
                [
                    "BENIGN",
                    "NORMAL"
                ]
            )
        ).astype(int)

    else:

        df["is_attack"] = (
            pd.to_numeric(
                df["is_attack"],
                errors="coerce"
            )
            .fillna(0)
            .clip(0, 1)
            .astype(int)
        )

    return df


# ============================================================
# PREPARE NUMERIC FEATURES
# ============================================================

def prepare_numeric_features(
    train,
    val,
    test,
    features
):

    # --------------------------------------------------------
    # Convert all model features to numeric.
    # --------------------------------------------------------

    train_X = (
        train[features]
        .apply(
            pd.to_numeric,
            errors="coerce"
        )
    )

    val_X = (
        val[features]
        .apply(
            pd.to_numeric,
            errors="coerce"
        )
    )

    test_X = (
        test[features]
        .apply(
            pd.to_numeric,
            errors="coerce"
        )
    )

    # --------------------------------------------------------
    # Replace infinities with NaN.
    # --------------------------------------------------------

    train_X = train_X.replace(
        [np.inf, -np.inf],
        np.nan
    )

    val_X = val_X.replace(
        [np.inf, -np.inf],
        np.nan
    )

    test_X = test_X.replace(
        [np.inf, -np.inf],
        np.nan
    )

    # --------------------------------------------------------
    # IMPORTANT:
    # Learn medians from TRAIN ONLY.
    # --------------------------------------------------------

    train_medians = (
        train_X
        .median()
        .fillna(0.0)
        .astype(float)
    )

    # --------------------------------------------------------
    # Apply TRAIN medians to all splits.
    # --------------------------------------------------------

    train_X = train_X.fillna(
        train_medians
    )

    val_X = val_X.fillna(
        train_medians
    )

    test_X = test_X.fillna(
        train_medians
    )

    # --------------------------------------------------------
    # Force numeric float representation.
    #
    # This is the important fix for the previous error.
    # StandardScaler outputs floating-point values.
    # --------------------------------------------------------

    train_X = train_X.astype(float)
    val_X = val_X.astype(float)
    test_X = test_X.astype(float)

    return (
        train_X,
        val_X,
        test_X,
        train_medians
    )


# ============================================================
# FIT PREPROCESSING
# ============================================================

def fit_preprocessing(
    train_X,
    val_X,
    test_X,
    features
):

    # --------------------------------------------------------
    # Identify continuous and binary features.
    # --------------------------------------------------------

    continuous_features = [
        feature
        for feature in features
        if feature not in BINARY_FEATURES
    ]

    binary_features = [
        feature
        for feature in features
        if feature in BINARY_FEATURES
    ]

    # --------------------------------------------------------
    # Create scaler.
    # --------------------------------------------------------

    scaler = StandardScaler()

    # --------------------------------------------------------
    # Fit ONLY on TRAIN.
    # --------------------------------------------------------

    if continuous_features:

        scaler.fit(
            train_X[
                continuous_features
            ]
        )

        # ----------------------------------------------------
        # Transform and explicitly create float DataFrames.
        #
        # Do NOT assign an ndarray into an int64 dataframe
        # column block.
        # ----------------------------------------------------

        train_scaled = pd.DataFrame(
            scaler.transform(
                train_X[
                    continuous_features
                ]
            ),
            columns=continuous_features,
            index=train_X.index
        )

        val_scaled = pd.DataFrame(
            scaler.transform(
                val_X[
                    continuous_features
                ]
            ),
            columns=continuous_features,
            index=val_X.index
        )

        test_scaled = pd.DataFrame(
            scaler.transform(
                test_X[
                    continuous_features
                ]
            ),
            columns=continuous_features,
            index=test_X.index
        )

        # Explicit float dtype.
        train_scaled = train_scaled.astype(float)
        val_scaled = val_scaled.astype(float)
        test_scaled = test_scaled.astype(float)

        # Replace original continuous columns.
        train_X = train_X.copy()
        val_X = val_X.copy()
        test_X = test_X.copy()

        train_X[continuous_features] = train_scaled
        val_X[continuous_features] = val_scaled
        test_X[continuous_features] = test_scaled

    # --------------------------------------------------------
    # Binary features remain 0/1.
    # --------------------------------------------------------

    for feature in binary_features:

        train_X[feature] = (
            pd.to_numeric(
                train_X[feature],
                errors="coerce"
            )
            .fillna(0)
            .clip(0, 1)
            .astype(int)
        )

        val_X[feature] = (
            pd.to_numeric(
                val_X[feature],
                errors="coerce"
            )
            .fillna(0)
            .clip(0, 1)
            .astype(int)
        )

        test_X[feature] = (
            pd.to_numeric(
                test_X[feature],
                errors="coerce"
            )
            .fillna(0)
            .clip(0, 1)
            .astype(int)
        )

    # --------------------------------------------------------
    # Ensure feature order remains deterministic.
    # --------------------------------------------------------

    train_X = train_X[features]
    val_X = val_X[features]
    test_X = test_X[features]

    return (
        train_X,
        val_X,
        test_X,
        scaler,
        continuous_features,
        binary_features
    )


# ============================================================
# DISTRIBUTION REPORT
# ============================================================

def distribution(df):

    result = {
        "binary": {},
        "multiclass": {}
    }

    if "is_attack" in df.columns:

        result["binary"] = {
            str(key): int(value)
            for key, value in (
                df["is_attack"]
                .value_counts()
                .sort_index()
                .items()
            )
        }

    if "Label" in df.columns:

        result["multiclass"] = {
            str(key): int(value)
            for key, value in (
                df["Label"]
                .value_counts()
                .items()
            )
        }

    return result


# ============================================================
# TIME RANGE
# ============================================================

def time_range(df):

    if len(df) == 0:

        return {
            "start": None,
            "end": None
        }

    return {
        "start": str(
            df["timestamp"].min()
        ),
        "end": str(
            df["timestamp"].max()
        )
    }


# ============================================================
# CHRONOLOGICAL SPLIT
# ============================================================

def chronological_split(df):

    n = len(df)

    if n < 10:

        raise ValueError(
            "Dataset is too small for "
            "train/validation/test split."
        )

    # --------------------------------------------------------
    # 80 / 10 / 10 chronological split.
    # --------------------------------------------------------

    train_end = int(
        n * 0.80
    )

    val_end = int(
        n * 0.90
    )

    train = df.iloc[
        :train_end
    ].copy()

    val = df.iloc[
        train_end:val_end
    ].copy()

    test = df.iloc[
        val_end:
    ].copy()

    return (
        train,
        val,
        test
    )


# ============================================================
# LEAKAGE AUDIT
# ============================================================

def leakage_audit(
    df,
    features
):

    audit = {
        "feature_count": len(features),
        "features": features,
        "leakage_columns_present_in_features": [],
        "metadata_columns_excluded": [],
        "passed": True
    }

    for feature in features:

        if feature in LEAKAGE_COLUMNS:

            audit[
                "leakage_columns_present_in_features"
            ].append(feature)

    audit[
        "metadata_columns_excluded"
    ] = sorted(
        [
            column
            for column in df.columns
            if column in LEAKAGE_COLUMNS
        ]
    )

    if audit[
        "leakage_columns_present_in_features"
    ]:

        audit["passed"] = False

    return audit


# ============================================================
# MAIN
# ============================================================

def split_dataset():

    print(
        "\n"
        + "=" * 65
    )

    print(
        "              M2 DATASET SPLIT"
    )

    print(
        "        LEAKAGE-SAFE TRAIN / VAL / TEST"
    )

    print(
        "=" * 65
        + "\n"
    )

    # --------------------------------------------------------
    # Input validation
    # --------------------------------------------------------

    if not INPUT_FILE.exists():

        raise FileNotFoundError(
            f"Could not find M2 feature matrix:\n"
            f"{INPUT_FILE}"
        )

    logging.info(
        "Loading M2 feature matrix:"
    )

    logging.info(
        "  %s",
        INPUT_FILE
    )

    df = pd.read_csv(
        INPUT_FILE,
        low_memory=False
    )

    logging.info(
        "Loaded rows: %d",
        len(df)
    )

    logging.info(
        "Loaded columns: %d",
        len(df.columns)
    )

    # --------------------------------------------------------
    # Timestamp validation
    # --------------------------------------------------------

    if "timestamp" not in df.columns:

        raise ValueError(
            "timestamp column is required."
        )

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce",
        utc=True
    )

    invalid_timestamps = int(
        df["timestamp"].isna().sum()
    )

    if invalid_timestamps:

        logging.warning(
            "Dropping %d rows with invalid timestamps.",
            invalid_timestamps
        )

        df = df.dropna(
            subset=["timestamp"]
        )

    # --------------------------------------------------------
    # Sort chronologically
    # --------------------------------------------------------

    df = (
        df
        .sort_values(
            "timestamp",
            kind="mergesort"
        )
        .reset_index(drop=True)
    )

    # --------------------------------------------------------
    # Normalize labels
    # --------------------------------------------------------

    df = normalize_labels(
        df
    )

    # --------------------------------------------------------
    # Load feature contract
    # --------------------------------------------------------

    features = load_feature_order()

    # --------------------------------------------------------
    # Verify features
    # --------------------------------------------------------

    missing_features = [
        feature
        for feature in features
        if feature not in df.columns
    ]

    if missing_features:

        raise ValueError(
            "\n"
            "M2 FEATURE CONTRACT MISMATCH\n"
            "====================================\n"
            f"Missing features: {missing_features}\n\n"
            "The dataset and feature-order artifact "
            "do not agree.\n"
            "Do NOT continue to M3 until this is fixed."
        )

    # --------------------------------------------------------
    # Leakage audit
    # --------------------------------------------------------

    audit = leakage_audit(
        df,
        features
    )

    if not audit["passed"]:

        raise ValueError(
            "LEAKAGE AUDIT FAILED.\n"
            "Prohibited model features:\n"
            f"{audit['leakage_columns_present_in_features']}"
        )

    logging.info(
        "Leakage audit: PASSED"
    )

    # --------------------------------------------------------
    # Dataset overview
    # --------------------------------------------------------

    logging.info(
        "Final dataset rows: %d",
        len(df)
    )

    logging.info(
        "Model feature count: %d",
        len(features)
    )

    logging.info(
        "Model features:"
    )

    for index, feature in enumerate(
        features,
        start=1
    ):

        logging.info(
            "  %02d. %s",
            index,
            feature
        )

    # --------------------------------------------------------
    # Label distribution
    # --------------------------------------------------------

    logging.info(
        "Overall label distribution:"
    )

    logging.info(
        "\n%s",
        df["Label"].value_counts()
    )

    logging.info(
        "Overall binary distribution:"
    )

    logging.info(
        "\n%s",
        df["is_attack"].value_counts()
    )

    # --------------------------------------------------------
    # Chronological split
    # --------------------------------------------------------

    (
        train,
        val,
        test
    ) = chronological_split(
        df
    )

    logging.info(
        "Chronological split created."
    )

    logging.info(
        "Train rows: %d",
        len(train)
    )

    logging.info(
        "Validation rows: %d",
        len(val)
    )

    logging.info(
        "Test rows: %d",
        len(test)
    )

    # --------------------------------------------------------
    # Temporal leakage check
    # --------------------------------------------------------

    if not (
        train["timestamp"].max()
        <=
        val["timestamp"].min()
    ):

        raise ValueError(
            "Temporal overlap detected between "
            "TRAIN and VALIDATION."
        )

    if not (
        val["timestamp"].max()
        <=
        test["timestamp"].min()
    ):

        raise ValueError(
            "Temporal overlap detected between "
            "VALIDATION and TEST."
        )

    logging.info(
        "Temporal leakage check: PASSED"
    )

    # --------------------------------------------------------
    # Split label distributions
    # --------------------------------------------------------

    logging.info(
        "\nTRAIN labels:\n%s",
        train["Label"].value_counts()
    )

    logging.info(
        "\nVALIDATION labels:\n%s",
        val["Label"].value_counts()
    )

    logging.info(
        "\nTEST labels:\n%s",
        test["Label"].value_counts()
    )

    # --------------------------------------------------------
    # Prepare numeric features
    # --------------------------------------------------------

    (
        train_X,
        val_X,
        test_X,
        train_medians
    ) = prepare_numeric_features(
        train,
        val,
        test,
        features
    )

    # --------------------------------------------------------
    # Train-only preprocessing
    # --------------------------------------------------------

    (
        train_X,
        val_X,
        test_X,
        scaler,
        continuous_features,
        binary_features
    ) = fit_preprocessing(
        train_X,
        val_X,
        test_X,
        features
    )

    logging.info(
        "Preprocessing fitted on TRAIN only."
    )

    logging.info(
        "Continuous features scaled: %d",
        len(continuous_features)
    )

    logging.info(
        "Binary features preserved: %d",
        len(binary_features)
    )

    # --------------------------------------------------------
    # Reattach labels
    # --------------------------------------------------------

    train_out = train_X.copy()
    val_out = val_X.copy()
    test_out = test_X.copy()

    train_out["is_attack"] = (
        train["is_attack"]
        .astype(int)
        .values
    )

    val_out["is_attack"] = (
        val["is_attack"]
        .astype(int)
        .values
    )

    test_out["is_attack"] = (
        test["is_attack"]
        .astype(int)
        .values
    )

    train_out["Label"] = (
        train["Label"]
        .values
    )

    val_out["Label"] = (
        val["Label"]
        .values
    )

    test_out["Label"] = (
        test["Label"]
        .values
    )

    # --------------------------------------------------------
    # Preserve timestamp for evaluation/auditing.
    #
    # Timestamp is NOT a model feature.
    # --------------------------------------------------------

    train_out["timestamp"] = (
        train["timestamp"]
        .astype(str)
        .values
    )

    val_out["timestamp"] = (
        val["timestamp"]
        .astype(str)
        .values
    )

    test_out["timestamp"] = (
        test["timestamp"]
        .astype(str)
        .values
    )

    # --------------------------------------------------------
    # Freeze output column order.
    # --------------------------------------------------------

    output_columns = (
        features
        + [
            "is_attack",
            "Label",
            "timestamp"
        ]
    )

    train_out = train_out[
        output_columns
    ]

    val_out = val_out[
        output_columns
    ]

    test_out = test_out[
        output_columns
    ]

    # --------------------------------------------------------
    # Create directories.
    # --------------------------------------------------------

    for directory in [
        TRAIN_DIR,
        VAL_DIR,
        TEST_DIR,
        MODEL_PREPROCESSING_DIR,
        Path("reports"),
        Path("features")
    ]:

        directory.mkdir(
            parents=True,
            exist_ok=True
        )

    # --------------------------------------------------------
    # Save datasets.
    # --------------------------------------------------------

    train_path = (
        TRAIN_DIR
        / "train.csv"
    )

    val_path = (
        VAL_DIR
        / "val.csv"
    )

    test_path = (
        TEST_DIR
        / "test.csv"
    )

    train_out.to_csv(
        train_path,
        index=False
    )

    val_out.to_csv(
        val_path,
        index=False
    )

    test_out.to_csv(
        test_path,
        index=False
    )

    logging.info(
        "Saved TRAIN: %s",
        train_path
    )

    logging.info(
        "Saved VALIDATION: %s",
        val_path
    )

    logging.info(
        "Saved TEST: %s",
        test_path
    )

    # --------------------------------------------------------
    # Save scaler.
    # --------------------------------------------------------

    scaler_path = (
        MODEL_PREPROCESSING_DIR
        / "standard_scaler.pkl"
    )

    joblib.dump(
        scaler,
        scaler_path
    )

    # --------------------------------------------------------
    # Save preprocessing contract.
    # --------------------------------------------------------

    preprocessing_contract = {

        "version":
            SPLIT_VERSION,

        "feature_order":
            features,

        "feature_count":
            len(features),

        "continuous_features":
            continuous_features,

        "binary_features":
            binary_features,

        "training_medians":
            {
                str(key): float(value)
                for key, value
                in train_medians.items()
            },

        "scaler_path":
            str(scaler_path),

        "input_dataset":
            str(INPUT_FILE),

        "preprocessing_fit":
            "training_only"
    }

    preprocessing_contract_path = (
        MODEL_PREPROCESSING_DIR
        / "preprocessing_contract.pkl"
    )

    joblib.dump(
        preprocessing_contract,
        preprocessing_contract_path
    )

    # --------------------------------------------------------
    # Save exact feature order.
    # --------------------------------------------------------

    with open(
        FEATURE_ORDER_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            features,
            file,
            indent=2
        )

    # --------------------------------------------------------
    # Save split report.
    # --------------------------------------------------------

    report = {

        "version":
            SPLIT_VERSION,

        "input_dataset":
            str(INPUT_FILE),

        "rows": {

            "total":
                len(df),

            "train":
                len(train),

            "validation":
                len(val),

            "test":
                len(test)
        },

        "features": {

            "count":
                len(features),

            "order":
                features,

            "continuous":
                continuous_features,

            "binary":
                binary_features
        },

        "time": {

            "train":
                time_range(train),

            "validation":
                time_range(val),

            "test":
                time_range(test)
        },

        "labels": {

            "overall":
                distribution(df),

            "train":
                distribution(train),

            "validation":
                distribution(val),

            "test":
                distribution(test)
        },

        "leakage_audit":
            audit,

        "preprocessing": {

            "fit_on":
                "train_only",

            "scaler":
                str(scaler_path),

            "median_imputation":
                "train_only",

            "feature_order":
                str(FEATURE_ORDER_FILE)
        },

        "outputs": {

            "train":
                str(train_path),

            "validation":
                str(val_path),

            "test":
                str(test_path)
        },

        "notes": [

            "Chronological 80/10/10 split used.",

            "No random row splitting used.",

            "Median imputation fitted on training data only.",

            "StandardScaler fitted on training data only.",

            "Binary features were preserved as 0/1.",

            "Labels were excluded from model features.",

            "Metadata and provenance columns were excluded from model features.",

            "No artificial attack classes were created.",

            "Current dataset contains the labels actually present in M2."
        ]
    }

    with open(
        SPLIT_REPORT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=2,
            default=str
        )

    # --------------------------------------------------------
    # Final validation of saved matrices.
    # --------------------------------------------------------

    if list(train_out[features].columns) != features:
        raise ValueError(
            "TRAIN feature order validation failed."
        )

    if list(val_out[features].columns) != features:
        raise ValueError(
            "VALIDATION feature order validation failed."
        )

    if list(test_out[features].columns) != features:
        raise ValueError(
            "TEST feature order validation failed."
        )

    # --------------------------------------------------------
    # Final summary.
    # --------------------------------------------------------

    print(
        "\n"
        + "=" * 65
    )

    print(
        "                 SPLIT COMPLETE"
    )

    print(
        "=" * 65
    )

    print(
        f"Total rows       : {len(df)}"
    )

    print(
        f"Training rows    : {len(train)}"
    )

    print(
        f"Validation rows  : {len(val)}"
    )

    print(
        f"Test rows        : {len(test)}"
    )

    print(
        f"Model features   : {len(features)}"
    )

    print(
        f"Train labels     : {train['Label'].nunique()}"
    )

    print(
        f"Validation labels: {val['Label'].nunique()}"
    )

    print(
        f"Test labels      : {test['Label'].nunique()}"
    )

    print(
        "\nPreprocessing:"
    )

    print(
        "  [OK] Median imputation fitted on TRAIN only"
    )

    print(
        "  [OK] StandardScaler fitted on TRAIN only"
    )

    print(
        "  [OK] Continuous features stored as float"
    )

    print(
        "  [OK] Binary features preserved"
    )

    print(
        "  [OK] Feature order frozen"
    )

    print(
        "  [OK] Temporal leakage check passed"
    )

    print(
        "  [OK] Feature leakage check passed"
    )

    print(
        "\nSaved:"
    )

    print(
        f"  {train_path}"
    )

    print(
        f"  {val_path}"
    )

    print(
        f"  {test_path}"
    )

    print(
        f"  {scaler_path}"
    )

    print(
        f"  {preprocessing_contract_path}"
    )

    print(
        f"  {FEATURE_ORDER_FILE}"
    )

    print(
        f"  {SPLIT_REPORT_FILE}"
    )

    print(
        "\nM2 SPLIT READY FOR M3."
    )

    print(
        "=" * 65
        + "\n"
    )

    return True


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    split_dataset()