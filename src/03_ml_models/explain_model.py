import pandas as pd
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix
import numpy as np
from pathlib import Path
import warnings

warnings.filterwarnings("ignore")

def map_threat_class(row):
    """SIH 26145 Mapping Function"""
    if pd.isna(row.get('Label')):
        if row.get('is_attack') == 1: return 3
        return 0
        
    label = str(row['Label']).strip().upper()
    if label in ['BENIGN', 'NAN']: return 0
    elif 'DOS' in label or 'HEARTBLEED' in label: return 1
    elif 'BOT' in label: return 2
    elif 'PATATOR' in label or 'BRUTE FORCE' in label or 'WEB ATTACK' in label: return 4
    elif 'PORTSCAN' in label: return 5
    elif 'INFILTRATION' in label: return 6
    else: return 0

def generate_explainability_reports():
    print("===================================================")
    print("   PHASE 6: GENERATING SIH EXPLAINABILITY REPORTS  ")
    print("===================================================\n")
    
    print("Loading unseen chronological test data...")
    df_test = pd.read_csv("data/processed/test/test.csv", low_memory=False)
    df_test['threat_class_id'] = df_test.apply(map_threat_class, axis=1)
    
    features = [
        'Destination Port', 'Flow Duration', 'Total Packets', 
        'Total Length of Packets', 'Flow Bytes/s', 'Flow Packets/s', 
        'Packet Length Max', 'Packet Length Mean', 'Average Packet Size', 
        'Down/Up Ratio', 'dns_query_length', 'dns_entropy'
    ]
    
    # FIX: Inject missing engineered columns as 0.0 to satisfy XGBoost's strict schema
    for feature in features:
        if feature not in df_test.columns:
            df_test[feature] = 0.0
            
    X_test = df_test[features].fillna(0)
    y_test = df_test['threat_class_id'].astype(int)
    
    print("Waking up XGBoost AI...")
    model = joblib.load("models/xgboost_classifier.pkl")
    predictions = model.predict(X_test)
    
    target_names = [
        'benign', 'ddos', 'botnet_c2', 'dns_tunneling', 
        'encrypted_malware', 'reconnaissance', 'data_exfiltration'
    ]
    
    present_classes = sorted(y_test.unique())
    labels = [target_names[i] for i in present_classes]
    
    # 1. Generate Confusion Matrix
    print("\nGenerating Confusion Matrix...")
    cm = confusion_matrix(y_test, predictions, labels=present_classes)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=labels, yticklabels=labels)
    plt.title('SIH 26145 - XGBoost Confusion Matrix (Unseen Data)')
    plt.ylabel('Actual Threat Class')
    plt.xlabel('AI Predicted Threat Class')
    plt.tight_layout()
    plt.savefig("reports/confusion_matrix.png", dpi=300)
    print("-> Saved to reports/confusion_matrix.png")
    
    # 2. Generate Feature Importance
    print("\nGenerating Global Feature Importance...")
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    plt.figure(figsize=(12, 6))
    plt.title("SIH 26145 - Global Feature Importance (What drives the AI's decisions?)")
    plt.bar(range(X_test.shape[1]), importances[indices], align="center", color="#2c3e50")
    plt.xticks(range(X_test.shape[1]), [features[i] for i in indices], rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig("reports/feature_importance.png", dpi=300)
    print("-> Saved to reports/feature_importance.png")
    
    print("\n[SUCCESS] Phase 6 Complete. Explainability charts are ready for the presentation!")

if __name__ == "__main__":
    # Ensure the reports folder exists
    Path("reports").mkdir(exist_ok=True)
    generate_explainability_reports()
