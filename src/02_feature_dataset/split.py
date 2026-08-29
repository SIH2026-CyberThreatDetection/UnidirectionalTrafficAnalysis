import warnings
warnings.filterwarnings("ignore", category=RuntimeWarning)
import pandas as pd
import logging
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def time_aware_split_and_scale(input_file: Path):
    logging.info(f"Loading final feature matrix from {input_file}...")
    
    if not input_file.exists():
        logging.error("Final matrix not found! Ensure merge_datasets.py has run successfully.")
        return

    df = pd.read_csv(input_file, low_memory=False)

    # 1. Normalize the Target Variable
    if 'is_attack' not in df.columns:
        if 'Label' in df.columns:
            df['is_attack'] = df['Label'].apply(lambda x: 0 if str(x).lower() in ['benign', 'normal'] else 1)
            df.drop(columns=['Label'], inplace=True)
        else:
            logging.warning("No target label found. Defaulting to 0 (baseline traffic).")
            df['is_attack'] = 0

    # 2. Enforce Chronological Order (Time-Awareness)
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df.sort_values('timestamp', inplace=True)
        df.drop(columns=['timestamp'], inplace=True)

    # 3. Drop Identifiers and ALL String/Text Columns
    text_columns = df.select_dtypes(include=['object', 'string']).columns.tolist()
    base_drop = ['is_attack', 'flow_id', 'src_ip', 'dst_ip']
    drop_cols = list(set(base_drop + text_columns))
    
    logging.info(f"Dropping non-numeric and identifier columns: {drop_cols}")
    X = df.drop(columns=[col for col in drop_cols if col in df.columns])
    y = df['is_attack']

    # 4. Strict Time-Aware Split (80% Train, 10% Val, 10% Test)
    logging.info("Performing Strict Time-Aware Split (shuffle=False)...")
    X_temp, X_test, y_temp, y_test = train_test_split(X, y, test_size=0.10, shuffle=False)
    X_train, X_val, y_train, y_val = train_test_split(X_temp, y_temp, test_size=0.1111, shuffle=False) 

    # 5. Initialize the Scaler
    scaler = StandardScaler()

    # Identify continuous numerical columns to scale (Ignore 0/1 binary flags)
    binary_cols = ['is_encrypted', 'uses_deprecated_crypto']
    scale_cols = [col for col in X_train.columns if col not in binary_cols]

    # 6. Fit ONLY on training data
    logging.info("Fitting StandardScaler STRICTLY on Training Data (Zero Leakage)...")
    X_train[scale_cols] = scaler.fit_transform(X_train[scale_cols])
    
    logging.info("Transforming Validation and Test sets safely...")
    X_val[scale_cols] = scaler.transform(X_val[scale_cols])
    X_test[scale_cols] = scaler.transform(X_test[scale_cols])

    # 7. Re-attach labels to save to disk
    train_df = X_train.copy()
    train_df['is_attack'] = y_train
    val_df = X_val.copy()
    val_df['is_attack'] = y_val
    test_df = X_test.copy()
    test_df['is_attack'] = y_test

    # 8. Setup Absolute Output Directories (Bypasses Windows String Bugs)
    base_dir = Path.cwd().resolve()
    
    train_dir = base_dir / "data" / "processed" / "train"
    val_dir = base_dir / "data" / "processed" / "val"
    test_dir = base_dir / "data" / "processed" / "test"
    models_dir = base_dir / "models" / "preprocessing"
    
    train_dir.mkdir(parents=True, exist_ok=True)
    val_dir.mkdir(parents=True, exist_ok=True)
    test_dir.mkdir(parents=True, exist_ok=True)
    models_dir.mkdir(parents=True, exist_ok=True)

    # 9. Save all artifacts using Native Path Objects (No strings used!)
    logging.info("Saving processed datasets via absolute paths...")
    
    train_file = train_dir / "train.csv"
    val_file = val_dir / "val.csv"
    test_file = test_dir / "test.csv"
    scaler_file = models_dir / "standard_scaler.pkl"
    
    train_df.to_csv(train_file, index=False)
    val_df.to_csv(val_file, index=False)
    test_df.to_csv(test_file, index=False)

    joblib.dump(scaler, scaler_file)
    
    logging.info(f"SUCCESS: Saved fitted scaler to {scaler_file}")
    logging.info("M2 PHASE COMPLETE. Data is secured and ready for M3 XGBoost Training.")

if __name__ == "__main__":
    input_csv = Path.cwd().resolve() / "data" / "processed" / "final_feature_matrix.csv"
    time_aware_split_and_scale(input_csv)
