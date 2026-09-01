import logging
from pathlib import Path

import numpy as np
import pandas as pd


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)


def engineer_features(
    df: pd.DataFrame
) -> pd.DataFrame:

    required = [
        "bytes_out",
        "bytes_in",
        "packets_out",
        "packets_in",
        "duration"
    ]

    missing = [
        column
        for column in required
        if column not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing flow columns: {missing}"
        )

    logging.info(
        "Engineering flow features..."
    )

    numeric = required

    for column in numeric:
        df[column] = pd.to_numeric(
            df[column],
            errors="coerce"
        ).fillna(0)

    df["duration"] = (
        df["duration"]
        .clip(lower=0)
    )

    # ---------------------------------------------------------
    # Volume
    # ---------------------------------------------------------

    df["total_bytes"] = (
        df["bytes_out"]
        + df["bytes_in"]
    )

    df["total_packets"] = (
        df["packets_out"]
        + df["packets_in"]
    )

    # ---------------------------------------------------------
    # Directional behavior
    # ---------------------------------------------------------

    df["byte_ratio"] = (
        (df["bytes_out"] + 1.0)
        /
        (df["bytes_in"] + 1.0)
    )

    df["packet_ratio"] = (
        (df["packets_out"] + 1.0)
        /
        (df["packets_in"] + 1.0)
    )

    df["outbound_fraction"] = (
        df["bytes_out"]
        /
        (df["total_bytes"] + 1.0)
    )

    # ---------------------------------------------------------
    # Rate features
    # ---------------------------------------------------------

    safe_duration = (
        df["duration"]
        .clip(lower=1e-6)
    )

    df["bytes_per_second"] = (
        df["total_bytes"]
        / safe_duration
    )

    df["packets_per_second"] = (
        df["total_packets"]
        / safe_duration
    )

    df["bytes_per_packet"] = (
        df["total_bytes"]
        /
        df["total_packets"].clip(lower=1)
    )

    # ---------------------------------------------------------
    # Directional packet size
    # ---------------------------------------------------------

    df["mean_packet_size_out"] = (
        df["bytes_out"]
        /
        df["packets_out"].clip(lower=1)
    )

    df["mean_packet_size_in"] = (
        df["bytes_in"]
        /
        df["packets_in"].clip(lower=1)
    )

    feature_columns = [
        "duration",
        "bytes_out",
        "bytes_in",
        "packets_out",
        "packets_in",
        "total_bytes",
        "total_packets",
        "byte_ratio",
        "packet_ratio",
        "outbound_fraction",
        "bytes_per_second",
        "packets_per_second",
        "bytes_per_packet",
        "mean_packet_size_out",
        "mean_packet_size_in"
    ]

    df[feature_columns] = (
        df[feature_columns]
        .replace(
            [np.inf, -np.inf],
            np.nan
        )
        .fillna(0)
    )

    logging.info(
        "Flow features generated: %d",
        len(feature_columns)
    )

    return df


if __name__ == "__main__":

    input_path = Path(
        "data/interim/clean_telemetry.csv"
    )

    output_path = Path(
        "data/processed/flow_features.csv"
    )

    if not input_path.exists():
        raise FileNotFoundError(
            input_path
        )

    df = pd.read_csv(
        input_path,
        low_memory=False
    )

    result = engineer_features(df)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    result.to_csv(
        output_path,
        index=False
    )

    logging.info(
        "Saved: %s",
        output_path
    )