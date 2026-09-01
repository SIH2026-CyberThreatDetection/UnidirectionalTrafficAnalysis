import ast
import hashlib
import logging
import math
from pathlib import Path

import pandas as pd


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)


def entropy(value):

    if not isinstance(
        value,
        str
    ) or not value:

        return 0.0

    counts = {}

    for char in value:
        counts[char] = (
            counts.get(char, 0) + 1
        )

    length = len(value)

    result = 0.0

    for count in counts.values():

        p = count / length

        result -= (
            p * math.log2(p)
        )

    return round(
        result,
        4
    )


def parse_tls(value):

    if value is None:
        return "", "", ""

    if isinstance(value, dict):

        return (
            str(
                value.get("version")
                or ""
            ),
            str(
                value.get("server_name")
                or ""
            ),
            str(
                value.get("ja3")
                or ""
            )
        )

    text = str(value).strip()

    if not text or text.lower() in [
        "nan",
        "none"
    ]:
        return "", "", ""

    try:

        parsed = ast.literal_eval(
            text
        )

        if isinstance(
            parsed,
            dict
        ):

            return (
                str(
                    parsed.get(
                        "version"
                    )
                    or ""
                ),
                str(
                    parsed.get(
                        "server_name"
                    )
                    or ""
                ),
                str(
                    parsed.get(
                        "ja3"
                    )
                    or ""
                )
            )

    except (
        ValueError,
        SyntaxError
    ):
        pass

    return "", "", ""


def ja3_numeric(value):

    if not value:
        return 0

    digest = hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()

    return int(
        digest[:8],
        16
    )


def extract_tls_features(df):

    logging.info(
        "Extracting TLS metadata..."
    )

    if "tls" not in df.columns:

        df["is_encrypted"] = 0
        df["sni_entropy"] = 0.0
        df["uses_deprecated_crypto"] = 0
        df["ja3_numeric"] = 0

        return df

    parsed = (
        df["tls"]
        .apply(parse_tls)
    )

    df[
        [
            "_tls_version",
            "_sni",
            "_ja3"
        ]
    ] = pd.DataFrame(
        parsed.tolist(),
        index=df.index
    )

    df["is_encrypted"] = (
        df["_tls_version"]
        .ne("")
        .astype(int)
    )

    df["sni_entropy"] = (
        df["_sni"]
        .apply(entropy)
    )

    df["uses_deprecated_crypto"] = (
        df["_tls_version"]
        .isin([
            "SSLv2",
            "SSLv3",
            "TLSv10",
            "TLSv11",
            "TLS1.0",
            "TLS1.1"
        ])
        .astype(int)
    )

    df["ja3_numeric"] = (
        df["_ja3"]
        .apply(ja3_numeric)
    )

    df.drop(
        columns=[
            "tls",
            "_tls_version",
            "_sni",
            "_ja3"
        ],
        inplace=True,
        errors="ignore"
    )

    logging.info(
        "TLS features complete."
    )

    return df


if __name__ == "__main__":

    input_path = Path(
        "data/processed/"
        "flow_features_with_dns.csv"
    )

    output_path = Path(
        "data/processed/"
        "final_feature_matrix.csv"
    )

    df = pd.read_csv(
        input_path,
        low_memory=False
    )

    result = extract_tls_features(
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