import joblib
import pandas as pd
from pathlib import Path


CONTRACT_PATH = Path(
    "models/preprocessing/"
    "preprocessing_contract.pkl"
)


SCALER_PATH = Path(
    "models/preprocessing/"
    "standard_scaler.pkl"
)


def load_contract():

    if not CONTRACT_PATH.exists():
        raise FileNotFoundError(
            CONTRACT_PATH
        )

    return joblib.load(
        CONTRACT_PATH
    )


def transform_features(
    df: pd.DataFrame
):

    contract = load_contract()

    feature_order = contract[
        "feature_order"
    ]

    continuous = contract[
        "continuous_features"
    ]

    binary = contract[
        "binary_features"
    ]

    medians = pd.Series(
        contract[
            "training_medians"
        ]
    )

    missing = [
        feature
        for feature in feature_order
        if feature not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing inference features: "
            f"{missing}"
        )

    X = df[
        feature_order
    ].copy()

    X = X.apply(
        pd.to_numeric,
        errors="coerce"
    )

    X = X.replace(
        [float("inf"), float("-inf")],
        pd.NA
    )

    X = X.fillna(
        medians
    )

    scaler = joblib.load(
        SCALER_PATH
    )

    if continuous:

        X.loc[
            :,
            continuous
        ] = scaler.transform(
            X[continuous]
        )

    for column in binary:

        X[column] = (
            X[column]
            .clip(0, 1)
            .astype(int)
        )

    return X