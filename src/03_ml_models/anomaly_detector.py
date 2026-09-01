from sklearn.ensemble import IsolationForest


def build_anomaly_detector():

    return IsolationForest(
        n_estimators=300,
        max_samples="auto",
        contamination="auto",
        random_state=42,
        n_jobs=-1
    )