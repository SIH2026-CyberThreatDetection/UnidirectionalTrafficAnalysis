import joblib
import logging
from pathlib import Path

from anomaly_detector import build_anomaly_detector
from classifier import build_baseline_classifier
from data_loader import load_dataset
from schema_validator import validate_columns
from preprocessing import transform_features


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)


TRAIN_PATH = Path(
    "data/processed/train/train.csv"
)

FEATURES = joblib.load(
    "models/preprocessing/"
    "preprocessing_contract.pkl"
)["feature_order"]


def main():

    df = load_dataset(
        TRAIN_PATH
    )

    validate_columns(
        df,
        FEATURES + [
            "is_attack"
        ]
    )

    X = transform_features(
        df
    )

    y = df[
        "is_attack"
    ].astype(int)

    model_dir = Path(
        "models"
    )

    model_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    # ---------------------------------------------------------
    # Isolation Forest
    # ---------------------------------------------------------

    logging.info(
        "Training Isolation Forest..."
    )

    isolation_forest = (
        build_anomaly_detector()
    )

    isolation_forest.fit(
        X
    )

    joblib.dump(
        isolation_forest,
        model_dir /
        "isolation_forest.pkl"
    )

    # ---------------------------------------------------------
    # Random Forest
    # ---------------------------------------------------------

    logging.info(
        "Training Random Forest..."
    )

    random_forest = (
        build_baseline_classifier()
    )

    random_forest.fit(
        X,
        y
    )

    joblib.dump(
        random_forest,
        model_dir /
        "random_forest.pkl"
    )

    logging.info(
        "Isolation Forest saved."
    )

    logging.info(
        "Random Forest saved."
    )

    print(
        "\nM3 baseline training complete."
    )


if __name__ == "__main__":
    main()