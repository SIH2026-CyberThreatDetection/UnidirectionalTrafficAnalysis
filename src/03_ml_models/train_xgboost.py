import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from xgboost import XGBClassifier

from sklearn.metrics import (
    accuracy_score,
    f1_score
)

from preprocessing import transform_features


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)


# -------------------------------------------------------------------------
# Original project threat taxonomy
# -------------------------------------------------------------------------

TARGET_NAMES = {
    0: "benign",
    1: "ddos",
    2: "botnet_c2",
    3: "dns_tunneling",
    4: "encrypted_malware",
    5: "reconnaissance",
    6: "data_exfiltration"
}


# -------------------------------------------------------------------------
# Label mapping
# -------------------------------------------------------------------------

def map_threat_class(label):

    if pd.isna(label):
        raise ValueError(
            "Missing Label."
        )

    value = (
        str(label)
        .strip()
        .upper()
    )

    if value in [
        "BENIGN",
        "NORMAL"
    ]:
        return 0

    if (
        "DDOS" in value
        or "DOS " in value
        or value.startswith("DOS")
        or "HEARTBLEED" in value
    ):
        return 1

    if "BOT" in value:
        return 2

    if (
        "DNS_TUNNEL" in value
        or "DNS-TUNNEL" in value
        or "DNS TUNNEL" in value
    ):
        return 3

    if (
        "ENCRYPTED_MALWARE" in value
        or "ENCRYPTED MALWARE" in value
        or "MALWARE_C2" in value
    ):
        return 4

    if (
        "PORTSCAN" in value
        or "PORT SCAN" in value
        or "RECON" in value
    ):
        return 5

    if (
        "EXFIL" in value
        or "INFILTRATION" in value
        or "DATA EXFIL" in value
    ):
        return 6

    raise ValueError(
        f"Unmapped Label: {value}"
    )


# -------------------------------------------------------------------------
# Dataset loading
# -------------------------------------------------------------------------

def load_split(path):

    file = Path(path)

    if not file.exists():
        raise FileNotFoundError(
            file
        )

    return pd.read_csv(
        file,
        low_memory=False
    )


# -------------------------------------------------------------------------
# XGBoost prediction normalization
# -------------------------------------------------------------------------

def normalize_predictions(
    predictions,
    num_classes
):
    """
    Convert XGBoost predictions into a 1-D array
    of class IDs.

    Depending on the XGBoost version/configuration,
    model.predict() may return:

        [0, 1, 0, 1, ...]

    or:

        [[1, 0],
         [0, 1],
         [1, 0],
         ...]

    sklearn classification metrics require the
    final representation to be 1-D class IDs.
    """

    predictions = np.asarray(
        predictions
    )

    # ---------------------------------------------------------
    # Standard 1-D class prediction.
    # ---------------------------------------------------------

    if predictions.ndim == 1:

        return predictions.astype(
            int
        )

    # ---------------------------------------------------------
    # Multiclass / multilabel-style prediction.
    #
    # Example:
    #
    # [[0.90, 0.10],
    #  [0.05, 0.95]]
    #
    # Convert to:
    #
    # [0, 1]
    # ---------------------------------------------------------

    if predictions.ndim == 2:

        if predictions.shape[1] != num_classes:

            raise ValueError(
                "Unexpected XGBoost prediction shape: "
                f"{predictions.shape}. "
                f"Expected second dimension to equal "
                f"num_classes={num_classes}."
            )

        return np.argmax(
            predictions,
            axis=1
        ).astype(int)

    raise ValueError(
        "Unexpected XGBoost prediction dimensions: "
        f"shape={predictions.shape}"
    )


# -------------------------------------------------------------------------
# Target normalization
# -------------------------------------------------------------------------

def normalize_targets(
    targets,
    name
):
    """
    Ensure target labels are a clean 1-D integer array.
    """

    values = np.asarray(
        targets
    )

    if values.ndim != 1:

        raise ValueError(
            f"{name} target must be 1-D. "
            f"Received shape={values.shape}."
        )

    if pd.isna(values).any():

        raise ValueError(
            f"{name} target contains missing values."
        )

    return values.astype(
        int
    )


# -------------------------------------------------------------------------
# Main training procedure
# -------------------------------------------------------------------------

def main():

    # ---------------------------------------------------------
    # Load splits
    # ---------------------------------------------------------

    train = load_split(
        "data/processed/train/train.csv"
    )

    val = load_split(
        "data/processed/val/val.csv"
    )

    test = load_split(
        "data/processed/test/test.csv"
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

    # ---------------------------------------------------------
    # Validate labels
    # ---------------------------------------------------------

    for name, df in [
        ("train", train),
        ("validation", val),
        ("test", test)
    ]:

        if "Label" not in df.columns:

            raise ValueError(
                f"{name} missing Label."
            )

    # ---------------------------------------------------------
    # Convert project labels into threat-class IDs
    # ---------------------------------------------------------

    train["threat_class_id"] = (
        train["Label"]
        .apply(map_threat_class)
    )

    val["threat_class_id"] = (
        val["Label"]
        .apply(map_threat_class)
    )

    test["threat_class_id"] = (
        test["Label"]
        .apply(map_threat_class)
    )

    # ---------------------------------------------------------
    # Determine classes available in training
    # ---------------------------------------------------------

    train_classes = sorted(
        train[
            "threat_class_id"
        ].unique()
    )

    val_classes = set(
        val[
            "threat_class_id"
        ].unique()
    )

    test_classes = set(
        test[
            "threat_class_id"
        ].unique()
    )

    logging.info(
        "Training threat classes: %s",
        train_classes
    )

    logging.info(
        "Validation threat classes: %s",
        sorted(val_classes)
    )

    logging.info(
        "Test threat classes: %s",
        sorted(test_classes)
    )

    # ---------------------------------------------------------
    # Ensure validation/test contain no unseen classes.
    # ---------------------------------------------------------

    unknown_val = (
        val_classes
        - set(train_classes)
    )

    unknown_test = (
        test_classes
        - set(train_classes)
    )

    if unknown_val:

        raise ValueError(
            "Validation contains classes "
            f"absent from training: {unknown_val}"
        )

    if unknown_test:

        raise ValueError(
            "Test contains classes "
            f"absent from training: {unknown_test}"
        )

    # ---------------------------------------------------------
    # Map project threat IDs to contiguous XGBoost IDs.
    #
    # Example:
    #
    # project ID 0 -> XGBoost ID 0
    # project ID 3 -> XGBoost ID 1
    #
    # This is necessary because XGBoost multiclass labels
    # must be contiguous: 0 ... N-1.
    # ---------------------------------------------------------

    class_to_encoded = {
        class_id: index
        for index, class_id
        in enumerate(train_classes)
    }

    encoded_to_class = {
        index: class_id
        for class_id, index
        in class_to_encoded.items()
    }

    logging.info(
        "Class encoding: %s",
        class_to_encoded
    )

    # ---------------------------------------------------------
    # Create encoded targets.
    # ---------------------------------------------------------

    y_train = (
        train[
            "threat_class_id"
        ]
        .map(class_to_encoded)
    )

    y_val = (
        val[
            "threat_class_id"
        ]
        .map(class_to_encoded)
    )

    y_test = (
        test[
            "threat_class_id"
        ]
        .map(class_to_encoded)
    )

    y_train = normalize_targets(
        y_train,
        "Training"
    )

    y_val = normalize_targets(
        y_val,
        "Validation"
    )

    y_test = normalize_targets(
        y_test,
        "Test"
    )

    # ---------------------------------------------------------
    # Transform features using the existing M2 preprocessing
    # contract.
    # ---------------------------------------------------------

    logging.info(
        "Transforming training features..."
    )

    X_train = transform_features(
        train
    )

    logging.info(
        "Transforming validation features..."
    )

    X_val = transform_features(
        val
    )

    logging.info(
        "Transforming test features..."
    )

    X_test = transform_features(
        test
    )

    # ---------------------------------------------------------
    # Validate feature consistency.
    # ---------------------------------------------------------

    if list(X_train.columns) != list(
        X_val.columns
    ):

        raise ValueError(
            "Training and validation feature "
            "orders do not match."
        )

    if list(X_train.columns) != list(
        X_test.columns
    ):

        raise ValueError(
            "Training and test feature "
            "orders do not match."
        )

    logging.info(
        "Feature count: %d",
        X_train.shape[1]
    )

    logging.info(
        "Feature order validated."
    )

    # ---------------------------------------------------------
    # Number of classes
    # ---------------------------------------------------------

    num_classes = len(
        train_classes
    )

    if num_classes < 2:

        raise ValueError(
            "XGBoost classification requires at "
            "least two training classes."
        )

    logging.info(
        "Training XGBoost with %d classes.",
        num_classes
    )

    # ---------------------------------------------------------
    # XGBoost classifier
    # ---------------------------------------------------------

    model = XGBClassifier(
        n_estimators=500,
        learning_rate=0.05,
        max_depth=6,
        min_child_weight=2,
        subsample=0.8,
        colsample_bytree=0.8,

        objective="multi:softprob",

        num_class=num_classes,

        eval_metric="mlogloss",

        random_state=42,

        n_jobs=-1,

        tree_method="hist"
    )

    # ---------------------------------------------------------
    # Train
    # ---------------------------------------------------------

    logging.info(
        "Starting XGBoost training..."
    )

    model.fit(
        X_train,
        y_train,
        eval_set=[
            (
                X_val,
                y_val
            )
        ],
        verbose=False
    )

    logging.info(
        "XGBoost training completed."
    )

    # ---------------------------------------------------------
    # Generate predictions
    # ---------------------------------------------------------

    logging.info(
        "Generating validation predictions..."
    )

    val_raw_pred = model.predict(
        X_val
    )

    logging.info(
        "Raw validation prediction shape: %s",
        np.asarray(val_raw_pred).shape
    )

    logging.info(
        "Generating test predictions..."
    )

    test_raw_pred = model.predict(
        X_test
    )

    logging.info(
        "Raw test prediction shape: %s",
        np.asarray(test_raw_pred).shape
    )

    # ---------------------------------------------------------
    # Normalize predictions to 1-D class IDs.
    # ---------------------------------------------------------

    val_pred = normalize_predictions(
        val_raw_pred,
        num_classes
    )

    test_pred = normalize_predictions(
        test_raw_pred,
        num_classes
    )

    # ---------------------------------------------------------
    # Final shape validation.
    # ---------------------------------------------------------

    if y_val.shape != val_pred.shape:

        raise ValueError(
            "Validation target/prediction shape mismatch: "
            f"y_val={y_val.shape}, "
            f"val_pred={val_pred.shape}"
        )

    if y_test.shape != test_pred.shape:

        raise ValueError(
            "Test target/prediction shape mismatch: "
            f"y_test={y_test.shape}, "
            f"test_pred={test_pred.shape}"
        )

    logging.info(
        "Validation prediction shape: %s",
        val_pred.shape
    )

    logging.info(
        "Test prediction shape: %s",
        test_pred.shape
    )

    # ---------------------------------------------------------
    # Metrics
    # ---------------------------------------------------------

    val_accuracy = accuracy_score(
        y_val,
        val_pred
    )

    test_accuracy = accuracy_score(
        y_test,
        test_pred
    )

    val_f1 = f1_score(
        y_val,
        val_pred,
        average="macro"
    )

    test_f1 = f1_score(
        y_test,
        test_pred,
        average="macro"
    )

    # ---------------------------------------------------------
    # Build artifact
    # ---------------------------------------------------------

    artifact = {

        "model": model,

        "feature_order": list(
            X_train.columns
        ),

        "class_to_encoded":
            class_to_encoded,

        "encoded_to_class":
            encoded_to_class,

        "target_names":
            TARGET_NAMES,

        "train_classes":
            train_classes,

        "num_classes":
            num_classes,

        "validation_accuracy":
            float(val_accuracy),

        "validation_macro_f1":
            float(val_f1),

        "test_accuracy":
            float(test_accuracy),

        "test_macro_f1":
            float(test_f1),

        "model_version":
            "M3-XGB-v2.1",

        "feature_version":
            "M2-v2.0"
    }

    # ---------------------------------------------------------
    # Save model
    # ---------------------------------------------------------

    model_path = Path(
        "models/"
        "xgboost_classifier.pkl"
    )

    model_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    joblib.dump(
        artifact,
        model_path
    )

    # ---------------------------------------------------------
    # Console report
    # ---------------------------------------------------------

    print()
    print("=" * 60)
    print("XGBOOST TRAINING COMPLETE")
    print("=" * 60)

    print(
        f"Training classes: {train_classes}"
    )

    print(
        f"Class encoding: {class_to_encoded}"
    )

    print(
        f"Validation accuracy: "
        f"{val_accuracy:.4f}"
    )

    print(
        f"Validation macro F1: "
        f"{val_f1:.4f}"
    )

    print(
        f"Test accuracy: "
        f"{test_accuracy:.4f}"
    )

    print(
        f"Test macro F1: "
        f"{test_f1:.4f}"
    )

    print(
        f"Model: {model_path}"
    )

    print("=" * 60)


if __name__ == "__main__":
    main()