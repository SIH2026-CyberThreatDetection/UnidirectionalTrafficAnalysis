from pathlib import Path
import pandas as pd

def load_dataset(path: str | Path) -> pd.DataFrame:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")
    
    df = pd.read_parquet(path)
    print(f"Loaded: {path}")
    print(f"Rows: {len(df)}")
    print(f"Columns: {len(df.columns)}")
    return df

if __name__ == "__main__":
    print("Dataset loader module ready.")
