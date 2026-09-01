from pathlib import Path

import pandas as pd


def load_dataset(
    path: str | Path
) -> pd.DataFrame:

    dataset_path = Path(path)

    if not dataset_path.exists():
        raise FileNotFoundError(
            f"Dataset not found: "
            f"{dataset_path}"
        )

    df = pd.read_csv(
        dataset_path,
        low_memory=False
    )

    if df.empty:
        raise ValueError(
            f"Dataset is empty: "
            f"{dataset_path}"
        )

    print(
        f"Loaded: {dataset_path}"
    )

    print(
        f"Shape: {df.shape}"
    )

    return df