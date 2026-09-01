import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score
)

from preprocessing import transform_features


def main():

    print("=" * 60)
    print("RANDOM FOREST BASELINE EVALUATION")
    print("=" * 60)

    df = pd.read_csv(
        "data/processed/test/test.csv",
        low_memory=False
    )

    X = transform_features(df)

    y = (
        pd.to_numeric(
            df["is_attack"],
            errors="coerce"
        )
        .fillna(0)
        .astype(int)
    )

    model = joblib.load(
        "models/random_forest.pkl"
    )

    predictions = model.predict(X)

    accuracy = accuracy_score(
        y,
        predictions
    )

    macro_f1 = f1_score(
        y,
        predictions,
        average="macro"
    )

    print()
    print(f"Accuracy : {accuracy:.4f}")
    print(f"Macro F1 : {macro_f1:.4f}")

    print()
    print("Classification Report")
    print("-" * 60)

    print(
        classification_report(
            y,
            predictions,
            target_names=[
                "BENIGN",
                "ATTACK"
            ],
            zero_division=0
        )
    )

    print("Confusion Matrix")
    print("-" * 60)

    print(
        confusion_matrix(
            y,
            predictions
        )
    )

    print()
    print("Random Forest evaluation complete.")


if __name__ == "__main__":
    main()