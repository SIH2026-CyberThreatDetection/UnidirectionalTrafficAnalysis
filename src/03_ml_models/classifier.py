from sklearn.ensemble import RandomForestClassifier

def build_baseline_classifier():
    return RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"
    )
