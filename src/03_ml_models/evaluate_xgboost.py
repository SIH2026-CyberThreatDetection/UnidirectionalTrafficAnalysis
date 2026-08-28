import pandas as pd
import joblib
from sklearn.metrics import classification_report, accuracy_score
from pathlib import Path

def evaluate_model():
    print("--- XGBoost Final Exam (Unseen Test Data) ---")
    
    test_file = Path("data/processed/test/test.csv")
    if not test_file.exists():
        print(f"Error: Could not find {test_file}")
        return
        
    print("Loading chronological test dataset...")
    df_test = pd.read_csv(test_file, low_memory=False)
    
    # Bridge the CIC-IDS2017 'Label' column just like we did in training
    if 'Label' in df_test.columns:
        cic_is_attack = df_test['Label'].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1)
        if 'is_attack' in df_test.columns:
            df_test['is_attack'] = df_test['is_attack'].fillna(cic_is_attack)
        else:
            df_test['is_attack'] = cic_is_attack
            
    df_test = df_test.dropna(subset=['is_attack'])
    
    # The 12-Feature Golden Schema
    features = [
        'Destination Port', 'Flow Duration', 'Total Packets', 
        'Total Length of Packets', 'Flow Bytes/s', 'Flow Packets/s', 
        'Packet Length Max', 'Packet Length Mean', 'Average Packet Size', 
        'Down/Up Ratio', 'dns_query_length', 'dns_entropy'
    ]
    
    # Ensure all features exist (pad synthetic ones with 0 if missing)
    for col in features:
        if col not in df_test.columns:
            df_test[col] = 0.0
            
    X_test = df_test[features].fillna(0)
    y_test = df_test['is_attack'].astype(int)
    
    model_path = Path("models/xgboost_classifier.pkl")
    print("Waking up trained XGBoost model...")
    model = joblib.load(model_path)
    
    print(f"Testing AI on {len(X_test)} future network flows...")
    predictions = model.predict(X_test)
    
    accuracy = accuracy_score(y_test, predictions) * 100
    print(f"\n[FINAL EXAM RESULT] True Unseen Accuracy: {accuracy:.4f}%\n")
    print("Unseen Threat Classification Report:")
    print(classification_report(y_test, predictions, target_names=['Normal (0)', 'Attack (1)']))

if __name__ == "__main__":
    evaluate_model()
