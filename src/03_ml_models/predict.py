import json
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from preprocessing import transform_features


TARGET_NAMES = {
    0: "benign",
    1: "ddos",
    2: "botnet_c2",
    3: "dns_tunneling",
    4: "encrypted_malware",
    5: "reconnaissance",
    6: "data_exfiltration"
}


def predict_dataframe(
    df: pd.DataFrame
):

    iso_model = joblib.load(
        "models/isolation_forest.pkl"
    )

    rf_model = joblib.load(
        "models/random_forest.pkl"
    )

    xgb_artifact = joblib.load(
        "models/xgboost_classifier.pkl"
    )

    xgb_model = xgb_artifact[
        "model"
    ]

    encoded_to_class = {
        int(k): int(v)
        for k, v in xgb_artifact[
            "encoded_to_class"
        ].items()
    }

    X = transform_features(
        df
    )

    # ---------------------------------------------------------
    # Engine 1
    # ---------------------------------------------------------

    anomaly_prediction = (
        iso_model.predict(X)
    )

    anomaly_score = (
        iso_model.decision_function(X)
    )

    # Normalize anomaly score only for
    # presentation/fusion. It is NOT a probability.
    anomaly_signal = (
        -anomaly_score
    )

    # ---------------------------------------------------------
    # Engine 2
    # ---------------------------------------------------------

    xgb_probabilities = (
        xgb_model.predict_proba(X)
    )

    xgb_encoded = (
        np.argmax(
            xgb_probabilities,
            axis=1
        )
    )

    xgb_confidence = (
        np.max(
            xgb_probabilities,
            axis=1
        )
    )

    xgb_sih_class = [
        encoded_to_class[
            int(pred)
        ]
        for pred in xgb_encoded
    ]

    results = []

    for index in range(
        len(df)
    ):

        predicted_class = (
            xgb_sih_class[index]
        )

        # Dual-engine rule:
        #
        # If XGBoost says benign but
        # Isolation Forest says anomalous,
        # preserve both pieces of information.
        #
        # Do NOT pretend IF knows the attack class.

        if (
            predicted_class == 0
            and
            anomaly_prediction[index] == -1
        ):

            threat_class = (
                "zero_day_anomaly"
            )

        else:

            threat_class = (
                TARGET_NAMES.get(
                    predicted_class,
                    "unknown"
                )
            )

        result = {

            "timestamp":
                datetime.now(
                    timezone.utc
                ).isoformat(),

            "flow_id":
                str(
                    df.iloc[index]
                    .get(
                        "flow_id",
                        f"flow-{index}"
                    )
                ),

            "threat_class":
                threat_class,

            "classifier_class":
                TARGET_NAMES.get(
                    predicted_class,
                    "unknown"
                ),

            "classifier_confidence":
                round(
                    float(
                        xgb_confidence[index]
                    ),
                    4
                ),

            "anomaly_score":
                round(
                    float(
                        anomaly_signal[index]
                    ),
                    6
                ),

            "is_anomaly":
                bool(
                    anomaly_prediction[index]
                    == -1
                ),

            "model_version":
                "M3-DualEngine-v2.0",

            "feature_version":
                "M2-v2.0"
        }

        results.append(
            result
        )

    return results


def main():

    print("=" * 60)
    print(
        "M3 DUAL-ENGINE PREDICTION"
    )
    print("=" * 60)

    test_path = Path(
        "data/processed/test/test.csv"
    )

    df = pd.read_csv(
        test_path,
        low_memory=False
    )

    start = time.perf_counter()

    results = predict_dataframe(
        df.head(20)
    )

    elapsed = (
        time.perf_counter()
        - start
    )

    print(
        json.dumps(
            results,
            indent=2
        )
    )

    print()
    print(
        f"Inference time: "
        f"{elapsed:.6f}s"
    )


if __name__ == "__main__":
    main()