from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score

def evaluate_classifier(y_true, y_pred):
    print("Precision:", precision_score(y_true, y_pred, average="macro", zero_division=0))
    print("Recall:", recall_score(y_true, y_pred, average="macro", zero_division=0))
    print("Macro F1:", f1_score(y_true, y_pred, average="macro", zero_division=0))
    print("\nClassification report:\n", classification_report(y_true, y_pred, zero_division=0))
    print("Confusion matrix:\n", confusion_matrix(y_true, y_pred))
