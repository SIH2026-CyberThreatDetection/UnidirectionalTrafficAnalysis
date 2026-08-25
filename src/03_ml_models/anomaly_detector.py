from sklearn.ensemble import IsolationForest

def build_anomaly_detector():
    return IsolationForest(
        n_estimators=200,
        random_state=42,
        contamination="auto"
    )
