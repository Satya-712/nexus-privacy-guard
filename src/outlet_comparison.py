
import json
from pathlib import Path

from src.privacy_detector import detect_sensitive_data


DATA_PATH = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "experiments.json"
)


def run_outlet_comparison():
    with DATA_PATH.open("r", encoding="utf-8") as file:
        cases = json.load(file)

    expected_only_recovered = 0
    all_channels_recovered = 0
    total_sensitive_exposures = 0
    missed_by_expected_only = 0

    results = []

    for case in cases:
        expected_type = case["data_type"]

        if expected_type == "NONE":
            continue

        total_sensitive_exposures += 1

        findings = detect_sensitive_data(case["text"])

        # Does the detector identify the expected sensitive type?
        detected = any(
            item["type"] == expected_type
            for item in findings
        )

        # Strategy 1: inspect only the expected outlet.
        expected_only_found = (
            detected
            and case["channel"] == case["expected_channel"]
        )

        # Strategy 2: inspect every channel declared in this dataset
        # as a visible output channel.
        all_channels_found = detected

        if expected_only_found:
            expected_only_recovered += 1

        if all_channels_found:
            all_channels_recovered += 1

        missed = all_channels_found and not expected_only_found

        if missed:
            missed_by_expected_only += 1

        results.append({
            "case_id": case["case_id"],
            "channel": case["channel"],
            "sensitive_type": expected_type,
            "expected_channel": case["expected_channel"],
            "expected_only_found": expected_only_found,
            "all_channels_found": all_channels_found,
            "missed_by_expected_only": missed,
        })

    expected_only_rate = (
        expected_only_recovered / total_sensitive_exposures
        if total_sensitive_exposures else 0.0
    )

    all_channels_rate = (
        all_channels_recovered / total_sensitive_exposures
        if total_sensitive_exposures else 0.0
    )

    missed_rate = (
        missed_by_expected_only / all_channels_recovered
        if all_channels_recovered else 0.0
    )

    print("=== OUTLET COMPARISON EXPERIMENT ===")
    print("Sensitive exposure cases:", total_sensitive_exposures)
    print(
        "Expected-outlet-only recovered:",
        expected_only_recovered,
    )
    print(
        "All-visible-channels recovered:",
        all_channels_recovered,
    )
    print(
        "Expected-outlet-only recovery rate:",
        f"{expected_only_rate:.1%}",
    )
    print(
        "All-visible-channels recovery rate:",
        f"{all_channels_rate:.1%}",
    )
    print(
        "Exposures missed by expected-only strategy:",
        missed_by_expected_only,
    )
    print(
        "Miss rate among recovered exposures:",
        f"{missed_rate:.1%}",
    )

    print("\n=== CASE DETAILS ===")
    for result in results:
        print(result)


if __name__ == "__main__":
    run_outlet_comparison()
