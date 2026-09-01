import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score
)

from preprocessing import transform_features


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)


def load_artifact():

    model_path = Path(
        "models/xgboost_classifier.pkl"
    )

    if not model_path.exists():

        raise FileNotFoundError(
            f"XGBoost model not found: {model_path}"
        )

    artifact = joblib.load(
        model_path
    )

    required_keys = [
        "model",
        "encoded_to_class",
        "target_names",
        "num_classes"
    ]

    missing = [
        key
        for key in required_keys
        if key not in artifact
    ]

    if missing:

        raise ValueError(
            "XGBoost artifact is missing required "
            f"fields: {missing}"
        )

    return artifact


def normalize_predictions(
    predictions,
    num_classes
):
    """
    Convert XGBoost predictions into a 1-D array
    of encoded class IDs.

    Supported prediction forms:

        [0, 1, 0, 1]

    or:

        [[0.90, 0.10],
         [0.20, 0.80]]

    The final output is always:

        [0, 1, ...]
    """

    predictions = np.asarray(
        predictions
    )

    logging.info(
        "Raw prediction shape: %s",
        predictions.shape
    )

    # ---------------------------------------------------------
    # Standard class-ID prediction.
    # ---------------------------------------------------------

    if predictions.ndim == 1:

        return predictions.astype(
            int
        )

    # ---------------------------------------------------------
    # Multiclass probability / score matrix.
    # ---------------------------------------------------------

    if predictions.ndim == 2:

        if predictions.shape[1] != num_classes:

            raise ValueError(
                "Unexpected XGBoost prediction shape: "
                f"{predictions.shape}. "
                f"Expected shape "
                f"(n_samples, {num_classes})."
            )

        return np.argmax(
            predictions,
            axis=1
        ).astype(int)

    raise ValueError(
        "Unsupported XGBoost prediction shape: "
        f"{predictions.shape}"
    )


def map_label_to_sih_id(
    label
):
    """
    Convert dataset labels into the project's
    SIH threat taxonomy.

    Uses the exact same mapping function as the
    XGBoost training script.
    """

    from train_xgboost import map_threat_class

    return map_threat_class(
        label
    )


def main():

    print("=" * 60)
    print("XGBOOST TEST EVALUATION")
    print("=" * 60)

    # ---------------------------------------------------------
    # Load trained XGBoost artifact.
    # ---------------------------------------------------------

    logging.info(
        "Loading XGBoost artifact..."
    )

    artifact = load_artifact()

    model = artifact[
        "model"
    ]

    num_classes = int(
        artifact[
            "num_classes"
        ]
    )

    # ---------------------------------------------------------
    # Normalize target-name keys to normal Python integers.
    #
    # This also prevents Pylance from treating the keys
    # as NumPy integer types.
    # ---------------------------------------------------------

    target_names = {
        int(key): str(value)
        for key, value
        in artifact[
            "target_names"
        ].items()
    }

    # ---------------------------------------------------------
    # Normalize encoded-to-project class mapping.
    # ---------------------------------------------------------

    encoded_to_class = {
        int(key): int(value)
        for key, value
        in artifact[
            "encoded_to_class"
        ].items()
    }

    logging.info(
        "Model classes: %d",
        num_classes
    )

    logging.info(
        "Encoded-to-SIH mapping: %s",
        encoded_to_class
    )

    # ---------------------------------------------------------
    # Validate class mapping.
    # ---------------------------------------------------------

    if len(
        encoded_to_class
    ) != num_classes:

        raise ValueError(
            "Class mapping size does not match "
            f"num_classes={num_classes}."
        )

    # ---------------------------------------------------------
    # Load test dataset.
    # ---------------------------------------------------------

    test_path = Path(
        "data/processed/test/test.csv"
    )

    if not test_path.exists():

        raise FileNotFoundError(
            f"Test dataset not found: {test_path}"
        )

    test = pd.read_csv(
        test_path,
        low_memory=False
    )

    logging.info(
        "Test rows: %d",
        len(test)
    )

    if "Label" not in test.columns:

        raise ValueError(
            "Test dataset is missing Label."
        )

    # ---------------------------------------------------------
    # Transform test features using the existing M2
    # preprocessing contract.
    # ---------------------------------------------------------

    logging.info(
        "Transforming test features..."
    )

    X = transform_features(
        test
    )

    logging.info(
        "Test feature count: %d",
        X.shape[1]
    )

    # ---------------------------------------------------------
    # Reconstruct true SIH/project class IDs.
    # ---------------------------------------------------------

    logging.info(
        "Converting test labels to SIH threat IDs..."
    )

    true_sih_ids = (
        test["Label"]
        .apply(
            map_label_to_sih_id
        )
        .astype(int)
        .to_numpy()
    )

    # ---------------------------------------------------------
    # Generate XGBoost predictions.
    # ---------------------------------------------------------

    logging.info(
        "Generating XGBoost predictions..."
    )

    raw_predictions = model.predict(
        X
    )

    # ---------------------------------------------------------
    # Normalize predictions to 1-D encoded class IDs.
    # ---------------------------------------------------------

    predictions_encoded = normalize_predictions(
        raw_predictions,
        num_classes
    )

    logging.info(
        "Normalized prediction shape: %s",
        predictions_encoded.shape
    )

    # ---------------------------------------------------------
    # Validate prediction count.
    # ---------------------------------------------------------

    if len(
        predictions_encoded
    ) != len(
        true_sih_ids
    ):

        raise ValueError(
            "Prediction count does not match "
            "test sample count: "
            f"predictions={len(predictions_encoded)}, "
            f"test={len(true_sih_ids)}"
        )

    # ---------------------------------------------------------
    # Convert encoded XGBoost IDs back to SIH IDs.
    # ---------------------------------------------------------

    predictions_sih = []

    for prediction in predictions_encoded:

        encoded_id = int(
            prediction
        )

        if encoded_id not in encoded_to_class:

            raise ValueError(
                "XGBoost produced unknown encoded "
                f"class ID: {encoded_id}"
            )

        sih_id = int(
            encoded_to_class[
                encoded_id
            ]
        )

        predictions_sih.append(
            sih_id
        )

    predictions_sih = np.asarray(
        predictions_sih,
        dtype=int
    )

    # ---------------------------------------------------------
    # Determine classes present in evaluation.
    #
    # Convert every class ID to a normal Python int.
    # This avoids NumPy typing issues with dictionary .get().
    # ---------------------------------------------------------

    present_classes = sorted(
        int(class_id)
        for class_id
        in (
            set(
                true_sih_ids
            )
            |
            set(
                predictions_sih
            )
        )
    )

    # ---------------------------------------------------------
    # Generate readable class names.
    # ---------------------------------------------------------

    names = [
        target_names.get(
            int(class_id),
            f"class_{int(class_id)}"
        )
        for class_id
        in present_classes
    ]

    # ---------------------------------------------------------
    # Calculate metrics.
    # ---------------------------------------------------------

    accuracy = accuracy_score(
        true_sih_ids,
        predictions_sih
    )

    macro_f1 = f1_score(
        true_sih_ids,
        predictions_sih,
        labels=present_classes,
        average="macro",
        zero_division=0
    )

    weighted_f1 = f1_score(
        true_sih_ids,
        predictions_sih,
        labels=present_classes,
        average="weighted",
        zero_division=0
    )

    # ---------------------------------------------------------
    # Console report.
    # ---------------------------------------------------------

    print()

    print(
        f"Model classes       : {num_classes}"
    )

    print(
        f"Evaluation classes  : {present_classes}"
    )

    print(
        f"Accuracy            : {accuracy:.4f}"
    )

    print(
        f"Macro F1            : {macro_f1:.4f}"
    )

    print(
        f"Weighted F1         : {weighted_f1:.4f}"
    )

    print()

    print(
        "Classification Report:"
    )

    print(
        classification_report(
            true_sih_ids,
            predictions_sih,
            labels=present_classes,
            target_names=names,
            zero_division=0
        )
    )

    print(
        "Confusion Matrix:"
    )

    print(
        confusion_matrix(
            true_sih_ids,
            predictions_sih,
            labels=present_classes
        )
    )

    print()
    print("=" * 60)
    print("XGBOOST EVALUATION COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()