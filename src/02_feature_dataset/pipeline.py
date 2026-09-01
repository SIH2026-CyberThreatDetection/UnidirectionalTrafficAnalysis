import logging
import subprocess
import sys


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)


SCRIPTS = [
    (
        "src/02_feature_dataset/clean.py",
        "Clean telemetry"
    ),

    (
        "src/02_feature_dataset/flow_features.py",
        "Generate flow features"
    ),

    (
        "src/02_feature_dataset/dns_features.py",
        "Generate DNS features"
    ),

    (
        "src/02_feature_dataset/tls_features.py",
        "Generate TLS features"
    ),

    (
        "src/02_feature_dataset/generate_dns_tunnels.py",
        "Generate synthetic DNS scenario"
    ),

    (
        "src/02_feature_dataset/merge_datasets.py",
        "Merge historical + synthetic data"
    ),

    (
        "src/02_feature_dataset/split.py",
        "Chronological split + training-only preprocessing"
    ),

    (
        "src/02_feature_dataset/generate_reports.py",
        "Generate reports"
    )
]


def run_script(path):

    logging.info(
        "Running: %s",
        path
    )

    result = subprocess.run(
        [
            sys.executable,
            path
        ],
        text=True
    )

    if result.returncode != 0:

        logging.error(
            "FAILED: %s",
            path
        )

        return False

    logging.info(
        "COMPLETED: %s",
        path
    )

    return True


def run_pipeline():

    print("=" * 70)
    print(
        "M2 FEATURE + DATASET PIPELINE"
    )
    print("=" * 70)

    for script, description in SCRIPTS:

        print()
        print(
            f">>> {description}"
        )

        if not run_script(script):

            print()
            print(
                "M2 PIPELINE STOPPED"
            )

            print(
                f"Failed step: {script}"
            )

            return False

    print()
    print("=" * 70)
    print(
        "M2 COMPLETE"
    )
    print("=" * 70)

    return True


if __name__ == "__main__":

    if not run_pipeline():
        raise SystemExit(1)