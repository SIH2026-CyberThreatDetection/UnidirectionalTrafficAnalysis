"""
M3 Explainability Module

Generates explainability reports for the trained XGBoost
multiclass threat classifier.

Compatible with the current M3 XGBoost artifact produced by:

    src/03_ml_models/train_xgboost.py

Current artifact contract:

    model
    feature_order
    class_to_encoded
    encoded_to_class
    target_names
    train_classes
    num_classes
    validation_accuracy
    validation_macro_f1
    test_accuracy
    test_macro_f1
    model_version
    feature_version

Outputs:

    reports/xgboost_confusion_matrix.png
    reports/xgboost_feature_importance.png
    reports/xgboost_feature_importance.csv
    reports/xgboost_permutation_importance.png
    reports/xgboost_permutation_importance.csv

IMPORTANT:

    This module uses the same M2 preprocessing pipeline used
    during XGBoost training.

    It does NOT recreate a legacy CIC-IDS feature schema.

    The module is designed to work with 2, 3, ... up to all
    7 SIH threat classes, provided those classes exist in
    the trained model artifact.
"""

from pathlib import Path
import logging
import warnings

import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.inspection import permutation_importance

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
    f1_score,
)


# -------------------------------------------------------------------------
# Existing project preprocessing
# -------------------------------------------------------------------------

from preprocessing import transform_features


# -------------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)

warnings.filterwarnings(
    "ignore"
)


# =========================================================================
# PATHS
# =========================================================================

MODEL_PATH = Path(
    "models/xgboost_classifier.pkl"
)

TEST_PATH = Path(
    "data/processed/test/test.csv"
)

REPORT_DIR = Path(
    "reports"
)


# =========================================================================
# SIH THREAT TAXONOMY
# =========================================================================

TARGET_NAMES = {
    0: "benign",
    1: "ddos",
    2: "botnet_c2",
    3: "dns_tunneling",
    4: "encrypted_malware",
    5: "reconnaissance",
    6: "data_exfiltration"
}


# =========================================================================
# XGBOOST PREDICTION NORMALIZATION
# =========================================================================

def normalize_predictions(
    predictions,
    num_classes
):
    """
    Convert XGBoost predictions into a clean 1-D integer
    class-ID array.

    Depending on the installed XGBoost version/configuration,
    model.predict() may return:

        [0, 1, 0, 1, ...]

    or:

        [[0.90, 0.10],
         [0.05, 0.95],
         ...]

    or, for multiclass:

        [[0.90, 0.05, 0.05],
         [0.01, 0.95, 0.04],
         ...]

    sklearn classification metrics require a 1-D class
    representation.

    Therefore:

        1-D -> directly converted to integer IDs
        2-D -> argmax across classes
    """

    values = np.asarray(
        predictions
    )

    # ------------------------------------------------------------------
    # Normal 1-D class IDs
    # ------------------------------------------------------------------

    if values.ndim == 1:

        return values.astype(
            int
        )

    # ------------------------------------------------------------------
    # 2-D probability / indicator representation
    # ------------------------------------------------------------------

    if values.ndim == 2:

        if values.shape[1] != num_classes:

            raise ValueError(
                "Unexpected XGBoost prediction shape: "
                f"{values.shape}. "
                f"Expected shape[1] == num_classes "
                f"({num_classes})."
            )

        return np.argmax(
            values,
            axis=1
        ).astype(
            int
        )

    raise ValueError(
        "Unexpected XGBoost prediction dimensions: "
        f"shape={values.shape}"
    )


# =========================================================================
# LOAD MODEL ARTIFACT
# =========================================================================

def load_model_artifact():
    """
    Load the current M3 XGBoost artifact.

    Expected structure:

        {
            "model": ...,
            "feature_order": [...],
            "class_to_encoded": {...},
            "encoded_to_class": {...},
            "target_names": {...},
            "train_classes": [...],
            "num_classes": ...,
            ...
        }
    """

    if not MODEL_PATH.exists():

        raise FileNotFoundError(
            f"XGBoost model not found: {MODEL_PATH}"
        )

    logging.info(
        "Loading XGBoost model artifact..."
    )

    artifact = joblib.load(
        MODEL_PATH
    )

    if not isinstance(
        artifact,
        dict
    ):

        raise ValueError(
            "Invalid XGBoost artifact. "
            "Expected a dictionary."
        )

    required_keys = [
        "model",
        "feature_order",
        "class_to_encoded",
        "encoded_to_class",
        "target_names",
        "train_classes",
        "num_classes",
    ]

    missing_keys = [
        key
        for key in required_keys
        if key not in artifact
    ]

    if missing_keys:

        raise ValueError(
            "XGBoost model artifact is missing required keys: "
            f"{missing_keys}"
        )

    return artifact


# =========================================================================
# LOAD TEST DATASET
# =========================================================================

def load_test_dataset():

    if not TEST_PATH.exists():

        raise FileNotFoundError(
            f"Test dataset not found: {TEST_PATH}"
        )

    logging.info(
        "Loading test dataset..."
    )

    df = pd.read_csv(
        TEST_PATH,
        low_memory=False
    )

    logging.info(
        "Test rows: %d",
        len(df)
    )

    logging.info(
        "Test columns: %d",
        len(df.columns)
    )

    if "Label" not in df.columns:

        raise ValueError(
            "Test dataset does not contain 'Label'."
        )

    return df


# =========================================================================
# PREPARE FEATURES
# =========================================================================

def prepare_features(
    df,
    feature_order
):
    """
    Use the exact M2 preprocessing pipeline.

    The important point here is that we do NOT manually recreate
    scaling, imputation, or feature preparation.

    transform_features() is the project's preprocessing contract.

    After transformation, the feature order is explicitly
    checked against the order stored in the XGBoost artifact.
    """

    logging.info(
        "Transforming test features using M2 preprocessing..."
    )

    X = transform_features(
        df
    )

    if not isinstance(
        X,
        pd.DataFrame
    ):

        X = pd.DataFrame(
            X,
            columns=feature_order
        )

    # ------------------------------------------------------------------
    # Verify feature count
    # ------------------------------------------------------------------

    if X.shape[1] != len(feature_order):

        raise ValueError(
            "Feature count mismatch after preprocessing. "
            f"Expected {len(feature_order)}, "
            f"received {X.shape[1]}."
        )

    # ------------------------------------------------------------------
    # Verify feature names/order
    # ------------------------------------------------------------------

    actual_order = list(
        X.columns
    )

    if actual_order != list(
        feature_order
    ):

        raise ValueError(
            "Feature order mismatch between M2 preprocessing "
            "and the XGBoost model contract.\n"
            f"Expected: {feature_order}\n"
            f"Received: {actual_order}"
        )

    logging.info(
        "Feature count: %d",
        X.shape[1]
    )

    logging.info(
        "Feature order validated."
    )

    return X


# =========================================================================
# PREPARE TARGET
# =========================================================================

def prepare_target(
    df,
    class_to_encoded
):
    """
    Convert raw Label values into SIH threat IDs and then into
    the contiguous encoded IDs used by XGBoost.

    The same map_threat_class() implementation from
    train_xgboost.py is reused.
    """

    if "Label" not in df.columns:

        raise ValueError(
            "'Label' column is required."
        )

    # ------------------------------------------------------------------
    # Import exact label mapping used during training.
    # ------------------------------------------------------------------

    from train_xgboost import map_threat_class

    logging.info(
        "Converting test labels into SIH threat IDs..."
    )

    sih_ids = (
        df["Label"]
        .apply(map_threat_class)
        .astype(int)
        .to_numpy()
    )

    # ------------------------------------------------------------------
    # Verify all test classes were present during training.
    # ------------------------------------------------------------------

    unknown_classes = sorted(
        set(sih_ids)
        - set(
            int(key)
            for key in class_to_encoded.keys()
        )
    )

    if unknown_classes:

        raise ValueError(
            "Test contains SIH threat classes that were not "
            "present during XGBoost training: "
            f"{unknown_classes}"
        )

    # ------------------------------------------------------------------
    # Convert SIH IDs to XGBoost encoded IDs.
    # ------------------------------------------------------------------

    encoded = np.asarray(
        [
            class_to_encoded[
                int(class_id)
            ]
            for class_id in sih_ids
        ],
        dtype=int
    )

    return encoded, sih_ids


# =========================================================================
# PRINT MODEL CONTRACT
# =========================================================================

def print_model_contract(
    artifact
):
    """
    Display the actual contract stored by train_xgboost.py.
    """

    feature_order = artifact[
        "feature_order"
    ]

    class_to_encoded = artifact[
        "class_to_encoded"
    ]

    encoded_to_class = artifact[
        "encoded_to_class"
    ]

    train_classes = [
        int(value)
        for value in artifact[
            "train_classes"
        ]
    ]

    num_classes = int(
        artifact[
            "num_classes"
        ]
    )

    print()
    print("=" * 60)
    print("XGBOOST MODEL CONTRACT")
    print("=" * 60)

    print(
        f"Model classes : {num_classes}"
    )

    print(
        f"Feature count : {len(feature_order)}"
    )

    print()
    print(
        "Training SIH classes:"
    )

    for class_id in train_classes:

        print(
            f"  SIH {class_id} "
            f"-> {TARGET_NAMES.get(class_id, 'unknown')}"
        )

    print()
    print(
        "Class encoding:"
    )

    for encoded_id in sorted(
        int(key)
        for key in encoded_to_class.keys()
    ):

        sih_id = int(
            encoded_to_class[
                encoded_id
            ]
        )

        name = TARGET_NAMES.get(
            sih_id,
            f"class_{sih_id}"
        )

        print(
            f"  XGBoost {encoded_id} "
            f"-> SIH {sih_id} "
            f"-> {name}"
        )

    print()
    print(
        "Feature order:"
    )

    for index, feature in enumerate(
        feature_order,
        start=1
    ):

        print(
            f"  {index:02d}. {feature}"
        )


# =========================================================================
# NATIVE FEATURE IMPORTANCE
# =========================================================================

def generate_native_importance(
    model,
    feature_order
):
    """
    Generate native XGBoost feature importance.
    """

    print()
    print(
        "Generating native XGBoost feature importance..."
    )

    importances = np.asarray(
        model.feature_importances_,
        dtype=float
    )

    if len(importances) != len(
        feature_order
    ):

        raise ValueError(
            "Feature importance count does not match "
            "the stored feature contract. "
            f"Importance count={len(importances)}, "
            f"feature count={len(feature_order)}."
        )

    importance_df = pd.DataFrame(
        {
            "feature": feature_order,
            "importance": importances,
        }
    )

    importance_df = (
        importance_df
        .sort_values(
            "importance",
            ascending=False
        )
        .reset_index(drop=True)
    )

    # ------------------------------------------------------------------
    # Save CSV
    # ------------------------------------------------------------------

    output_csv = (
        REPORT_DIR
        / "xgboost_feature_importance.csv"
    )

    importance_df.to_csv(
        output_csv,
        index=False
    )

    logging.info(
        "Saved native feature importance: %s",
        output_csv
    )

    # ------------------------------------------------------------------
    # Generate chart
    # ------------------------------------------------------------------

    plt.figure(
        figsize=(11, 7)
    )

    plt.barh(
        importance_df["feature"],
        importance_df["importance"]
    )

    plt.gca().invert_yaxis()

    plt.title(
        "XGBoost Global Feature Importance"
    )

    plt.xlabel(
        "Feature Importance"
    )

    plt.ylabel(
        "Feature"
    )

    plt.tight_layout()

    output_png = (
        REPORT_DIR
        / "xgboost_feature_importance.png"
    )

    plt.savefig(
        output_png,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    logging.info(
        "Saved native importance chart: %s",
        output_png
    )

    print()
    print(
        "Top XGBoost features:"
    )

    for _, row in (
        importance_df
        .head(10)
        .iterrows()
    ):

        print(
            f"  {row['feature']:<30}"
            f"{row['importance']:.6f}"
        )

    return importance_df


# =========================================================================
# PERMUTATION SCORER
# =========================================================================

def xgboost_macro_f1_scorer(
    estimator,
    X,
    y
):
    """
    Custom permutation-importance scorer.

    This is intentionally used instead of the standard string
    'f1_macro' because the installed XGBoost version may return
    a 2-D prediction matrix from model.predict().

    We normalize the prediction first and then calculate
    macro-F1.

    This makes permutation importance compatible with the
    current XGBoost behavior.
    """

    raw_predictions = estimator.predict(
        X
    )

    normalized_predictions = (
        normalize_predictions(
            raw_predictions,
            len(
                np.unique(y)
            )
        )
    )

    return f1_score(
        y,
        normalized_predictions,
        average="macro",
        zero_division=0
    )


# =========================================================================
# PERMUTATION IMPORTANCE
# =========================================================================

def generate_permutation_importance(
    model,
    X,
    y_encoded,
    feature_order,
    num_classes
):
    """
    Generate permutation importance using Macro-F1.

    Macro-F1 is used because it gives each threat class equal
    importance instead of allowing the majority class to dominate.
    """

    print()
    print(
        "Generating permutation importance..."
    )

    # ------------------------------------------------------------------
    # Limit computation for practicality.
    # ------------------------------------------------------------------

    max_samples = 5000

    if len(X) > max_samples:

        rng = np.random.RandomState(
            42
        )

        selected_indices = rng.choice(
            len(X),
            size=max_samples,
            replace=False
        )

        X_eval = X.iloc[
            selected_indices
        ].copy()

        y_eval = y_encoded[
            selected_indices
        ]

        logging.info(
            "Using %d samples for permutation importance.",
            max_samples
        )

    else:

        X_eval = X.copy()

        y_eval = y_encoded

        logging.info(
            "Using all %d test samples.",
            len(X_eval)
        )

    # ------------------------------------------------------------------
    # Run permutation importance.
    # ------------------------------------------------------------------

    result = permutation_importance(
        model,
        X_eval,
        y_eval,
        n_repeats=5,
        random_state=42,
        scoring=xgboost_macro_f1_scorer,
        n_jobs=-1
    )

    permutation_means = np.asarray(
        result["importances_mean"],
        dtype=float
    )

    permutation_std = np.asarray(
        result["importances_std"],
        dtype=float
    )

    if len(permutation_means) != len(
        feature_order
    ):

        raise ValueError(
            "Permutation importance count does not match "
            "feature count."
        )

    permutation_df = pd.DataFrame(
        {
            "feature": feature_order,
            "importance_mean": permutation_means,
            "importance_std": permutation_std,
        }
    )

    permutation_df = (
        permutation_df
        .sort_values(
            "importance_mean",
            ascending=False
        )
        .reset_index(drop=True)
    )

    # ------------------------------------------------------------------
    # Save CSV
    # ------------------------------------------------------------------

    output_csv = (
        REPORT_DIR
        / "xgboost_permutation_importance.csv"
    )

    permutation_df.to_csv(
        output_csv,
        index=False
    )

    logging.info(
        "Saved permutation importance: %s",
        output_csv
    )

    # ------------------------------------------------------------------
    # Generate chart
    # ------------------------------------------------------------------

    plt.figure(
        figsize=(11, 7)
    )

    plt.barh(
        permutation_df["feature"],
        permutation_df["importance_mean"],
        xerr=permutation_df["importance_std"]
    )

    plt.gca().invert_yaxis()

    plt.title(
        "XGBoost Permutation Importance "
        "(Macro-F1)"
    )

    plt.xlabel(
        "Mean decrease in Macro-F1"
    )

    plt.ylabel(
        "Feature"
    )

    plt.tight_layout()

    output_png = (
        REPORT_DIR
        / "xgboost_permutation_importance.png"
    )

    plt.savefig(
        output_png,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    logging.info(
        "Saved permutation importance chart: %s",
        output_png
    )

    print()
    print(
        "Top permutation-important features:"
    )

    for _, row in (
        permutation_df
        .head(10)
        .iterrows()
    ):

        print(
            f"  {row['feature']:<30}"
            f"{row['importance_mean']:.6f}"
        )

    return permutation_df


# =========================================================================
# CONFUSION MATRIX
# =========================================================================

def generate_confusion_matrix(
    y_true,
    predictions,
    artifact
):
    """
    Generate a confusion matrix using every class that belongs
    to the trained model.

    This means that when the model eventually contains all 7
    SIH classes, the confusion matrix will automatically become
    a 7 x 7 matrix.
    """

    print()
    print(
        "Generating multiclass confusion matrix..."
    )

    encoded_to_class = {
        int(key): int(value)
        for key, value
        in artifact[
            "encoded_to_class"
        ].items()
    }

    num_classes = int(
        artifact[
            "num_classes"
        ]
    )

    encoded_labels = list(
        range(
            num_classes
        )
    )

    display_labels = []

    for encoded_id in encoded_labels:

        sih_id = encoded_to_class[
            encoded_id
        ]

        display_labels.append(
            TARGET_NAMES.get(
                sih_id,
                f"class_{sih_id}"
            )
        )

    cm = confusion_matrix(
        y_true,
        predictions,
        labels=encoded_labels
    )

    fig, ax = plt.subplots(
        figsize=(11, 9)
    )

    display = ConfusionMatrixDisplay(
        confusion_matrix=cm,
        display_labels=display_labels
    )

    display.plot(
        ax=ax,
        xticks_rotation=45,
        values_format="d",
        colorbar=False
    )

    ax.set_title(
        "SIH 26145 - XGBoost Threat Classification"
    )

    ax.set_xlabel(
        "Predicted Threat Class"
    )

    ax.set_ylabel(
        "Actual Threat Class"
    )

    plt.tight_layout()

    output_png = (
        REPORT_DIR
        / "xgboost_confusion_matrix.png"
    )

    plt.savefig(
        output_png,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    logging.info(
        "Saved confusion matrix: %s",
        output_png
    )

    return cm


# =========================================================================
# CLASSIFICATION REPORT
# =========================================================================

def generate_classification_report(
    y_true,
    predictions,
    artifact
):
    """
    Print classification performance for every class in the
    trained model.
    """

    encoded_to_class = {
        int(key): int(value)
        for key, value
        in artifact[
            "encoded_to_class"
        ].items()
    }

    num_classes = int(
        artifact[
            "num_classes"
        ]
    )

    labels = list(
        range(
            num_classes
        )
    )

    target_names = []

    for encoded_id in labels:

        sih_id = encoded_to_class[
            encoded_id
        ]

        target_names.append(
            TARGET_NAMES.get(
                sih_id,
                f"class_{sih_id}"
            )
        )

    print()
    print(
        "Classification Report:"
    )

    report = classification_report(
        y_true,
        predictions,
        labels=labels,
        target_names=target_names,
        zero_division=0
    )

    print(
        report
    )

    return report


# =========================================================================
# MAIN
# =========================================================================

def main():

    print("=" * 60)
    print(
        "PHASE 6: XGBOOST EXPLAINABILITY"
    )
    print("=" * 60)

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # ------------------------------------------------------------------
    # 1. Load model artifact
    # ------------------------------------------------------------------

    artifact = load_model_artifact()

    model = artifact[
        "model"
    ]

    feature_order = artifact[
        "feature_order"
    ]

    class_to_encoded = {
        int(key): int(value)
        for key, value
        in artifact[
            "class_to_encoded"
        ].items()
    }

    num_classes = int(
        artifact[
            "num_classes"
        ]
    )

    # ------------------------------------------------------------------
    # 2. Print model contract
    # ------------------------------------------------------------------

    print_model_contract(
        artifact
    )

    # ------------------------------------------------------------------
    # 3. Load test dataset
    # ------------------------------------------------------------------

    df_test = load_test_dataset()

    # ------------------------------------------------------------------
    # 4. Transform test features using M2
    # ------------------------------------------------------------------

    X_test = prepare_features(
        df_test,
        feature_order
    )

    # ------------------------------------------------------------------
    # 5. Prepare labels
    # ------------------------------------------------------------------

    y_test_encoded, y_test_sih = (
        prepare_target(
            df_test,
            class_to_encoded
        )
    )

    # ------------------------------------------------------------------
    # 6. Generate raw predictions
    # ------------------------------------------------------------------

    logging.info(
        "Generating XGBoost predictions..."
    )

    raw_predictions = model.predict(
        X_test
    )

    logging.info(
        "Raw prediction shape: %s",
        np.asarray(
            raw_predictions
        ).shape
    )

    # ------------------------------------------------------------------
    # 7. Normalize predictions
    # ------------------------------------------------------------------

    predictions = normalize_predictions(
        raw_predictions,
        num_classes
    )

    logging.info(
        "Normalized prediction shape: %s",
        predictions.shape
    )

    # ------------------------------------------------------------------
    # 8. Validate prediction shape
    # ------------------------------------------------------------------

    if y_test_encoded.shape != predictions.shape:

        raise ValueError(
            "Target/prediction shape mismatch.\n"
            f"Target shape: {y_test_encoded.shape}\n"
            f"Prediction shape: {predictions.shape}"
        )

    # ------------------------------------------------------------------
    # 9. Validate prediction class IDs
    # ------------------------------------------------------------------

    invalid_predictions = sorted(
        set(
            int(value)
            for value in predictions
        )
        -
        set(
            range(
                num_classes
            )
        )
    )

    if invalid_predictions:

        raise ValueError(
            "XGBoost generated invalid encoded class IDs: "
            f"{invalid_predictions}"
        )

    # ------------------------------------------------------------------
    # 10. Calculate metrics
    # ------------------------------------------------------------------

    accuracy = accuracy_score(
        y_test_encoded,
        predictions
    )

    macro_f1 = f1_score(
        y_test_encoded,
        predictions,
        average="macro",
        zero_division=0
    )

    weighted_f1 = f1_score(
        y_test_encoded,
        predictions,
        average="weighted",
        zero_division=0
    )

    # ------------------------------------------------------------------
    # 11. Print performance
    # ------------------------------------------------------------------

    print()
    print("=" * 60)
    print(
        "XGBOOST TEST PERFORMANCE"
    )
    print("=" * 60)

    print(
        f"Model classes : {num_classes}"
    )

    print(
        f"Accuracy      : {accuracy:.4f}"
    )

    print(
        f"Macro F1      : {macro_f1:.4f}"
    )

    print(
        f"Weighted F1   : {weighted_f1:.4f}"
    )

    # ------------------------------------------------------------------
    # 12. Classification report
    # ------------------------------------------------------------------

    generate_classification_report(
        y_test_encoded,
        predictions,
        artifact
    )

    # ------------------------------------------------------------------
    # 13. Confusion matrix
    # ------------------------------------------------------------------

    generate_confusion_matrix(
        y_test_encoded,
        predictions,
        artifact
    )

    # ------------------------------------------------------------------
    # 14. Native XGBoost importance
    # ------------------------------------------------------------------

    generate_native_importance(
        model,
        feature_order
    )

    # ------------------------------------------------------------------
    # 15. Permutation importance
    # ------------------------------------------------------------------

    generate_permutation_importance(
        model,
        X_test,
        y_test_encoded,
        feature_order,
        num_classes
    )

    # ------------------------------------------------------------------
    # 16. Final output
    # ------------------------------------------------------------------

    print()
    print("=" * 60)
    print(
        "EXPLAINABILITY COMPLETE"
    )
    print("=" * 60)

    print()
    print(
        "Generated reports:"
    )

    print(
        "  -> reports/xgboost_confusion_matrix.png"
    )

    print(
        "  -> reports/xgboost_feature_importance.png"
    )

    print(
        "  -> reports/xgboost_feature_importance.csv"
    )

    print(
        "  -> reports/xgboost_permutation_importance.png"
    )

    print(
        "  -> reports/xgboost_permutation_importance.csv"
    )

    print()
    print(
        f"Model currently contains {num_classes} "
        "trained threat classes."
    )

    print(
        "Explainability uses the current M2 feature contract."
    )

    print(
        "No legacy CIC-IDS feature bridge is used."
    )

    print("=" * 60)


# =========================================================================
# ENTRY POINT
# =========================================================================

if __name__ == "__main__":
    main()