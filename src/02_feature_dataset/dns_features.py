import ast
import logging
import math
from pathlib import Path

import pandas as pd


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)


def shannon_entropy(value):

    if not isinstance(
        value,
        str
    ) or not value:

        return 0.0

    value = value.strip()

    if not value:
        return 0.0

    counts = {}

    for char in value:
        counts[char] = (
            counts.get(char, 0) + 1
        )

    length = len(value)

    entropy = 0.0

    for count in counts.values():

        probability = (
            count / length
        )

        entropy -= (
            probability
            * math.log2(probability)
        )

    return round(
        entropy,
        4
    )


def extract_query(value):

    if value is None:
        return ""

    if isinstance(value, dict):
        return str(
            value.get("query")
            or ""
        )

    text = str(value).strip()

    if text.lower() in [
        "",
        "nan",
        "none"
    ]:
        return ""

    try:

        parsed = ast.literal_eval(
            text
        )

        if isinstance(
            parsed,
            dict
        ):

            return str(
                parsed.get("query")
                or ""
            )

    except (
        ValueError,
        SyntaxError
    ):
        pass

    return ""


def extract_dns_features(df):

    logging.info(
        "Extracting DNS features..."
    )

    if "dns" not in df.columns:

        df["dns_query_length"] = 0
        df["dns_entropy"] = 0.0
        df["dns_digit_fraction"] = 0.0
        df["dns_subdomain_depth"] = 0

        return df

    df["dns_query"] = (
        df["dns"]
        .apply(extract_query)
    )

    df["dns_query_length"] = (
        df["dns_query"]
        .str.len()
        .fillna(0)
        .astype(int)
    )

    df["dns_entropy"] = (
        df["dns_query"]
        .apply(shannon_entropy)
    )

    def digit_fraction(value):

        if not value:
            return 0.0

        return round(
            sum(
                char.isdigit()
                for char in value
            )
            / len(value),
            4
        )

    def subdomain_depth(value):

        if not value:
            return 0

        return max(
            0,
            value.count(".")
        )

    df["dns_digit_fraction"] = (
        df["dns_query"]
        .apply(digit_fraction)
    )

    df["dns_subdomain_depth"] = (
        df["dns_query"]
        .apply(subdomain_depth)
    )

    df.drop(
        columns=["dns_query"],
        inplace=True
    )

    logging.info(
        "DNS features complete."
    )

    return df


if __name__ == "__main__":

    input_path = Path(
        "data/processed/flow_features.csv"
    )

    output_path = Path(
        "data/processed/"
        "flow_features_with_dns.csv"
    )

    df = pd.read_csv(
        input_path,
        low_memory=False
    )

    result = extract_dns_features(
        df
    )

    result.to_csv(
        output_path,
        index=False
    )

    logging.info(
        "Saved: %s",
        output_path
    )