def validate_columns(
    df,
    required_columns
):

    missing = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing required columns: "
            f"{missing}"
        )

    return True


def validate_target(
    df,
    target
):

    if target not in df.columns:
        raise ValueError(
            f"Target column not found: "
            f"{target}"
        )

    if df[target].isna().any():
        raise ValueError(
            f"Target contains missing values: "
            f"{target}"
        )

    return True