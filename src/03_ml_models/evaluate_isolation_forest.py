import joblib
import pandas as pd

from preprocessing import transform_features


def main():

    print("=" * 60)
    print("ISOLATION FOREST ANOMALY EVALUATION")
    print("=" * 60)

    df = pd.read_csv(
        "data/processed/test/test.csv",
        low_memory=False
    )

    X = transform_features(df)

    model = joblib.load(
        "models/isolation_forest.pkl"
    )

    predictions = model.predict(X)

    scores = model.decision_function(X)

    df["anomaly_prediction"] = predictions
    df["anomaly_score"] = scores

    df["is_anomaly"] = (
        predictions == -1
    )

    total = len(df)

    anomalies = int(
        df["is_anomaly"].sum()
    )

    anomaly_rate = (
        anomalies / total
        if total > 0
        else 0
    )

    print()
    print(f"Total flows       : {total}")
    print(f"Anomalies detected: {anomalies}")
    print(
        f"Anomaly rate      : "
        f"{anomaly_rate:.4%}"
    )

    print()
    print("Anomaly score statistics")
    print("-" * 60)

    print(
        df["anomaly_score"]
        .describe()
    )

    # Descriptive comparison only.
    # This does NOT turn Isolation Forest
    # into a supervised classifier.

    if "is_attack" in df.columns:

        attack_scores = df.loc[
            df["is_attack"] == 1,
            "anomaly_score"
        ]

        benign_scores = df.loc[
            df["is_attack"] == 0,
            "anomaly_score"
        ]

        print()
        print("Attack anomaly scores")
        print(
            attack_scores.describe()
        )

        print()
        print("Benign anomaly scores")
        print(
            benign_scores.describe()
        )

    print()
    print(
        "Isolation Forest evaluation complete."
    )


if __name__ == "__main__":
    main()