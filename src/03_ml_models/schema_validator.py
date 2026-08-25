def validate_columns(df, required_columns):
    missing = [c for c in required_columns if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")
    return True

def validate_target(df, target):
    if target not in df.columns:
        raise ValueError(f"Target column not found: {target}")
    if df[target].isna().any():
        raise ValueError("Target contains missing values.")
    return True
