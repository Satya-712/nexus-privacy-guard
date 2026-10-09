
import json
from pathlib import Path

from src.privacy_detector import detect_sensitive_data


DATA_PATH = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "experiments.json"
)


def get_outlet_comparison():
    with DATA_PATH.open("r", encoding="utf-8") as file:
        cases = json.load(file)

    # Only explicitly declared visible cases are counted
    # as visible exposure opportunities.
    visible_cases = [
        case for case in cases
        if case.get("visibility") == "visible"
    ]

    results = []

    for case in visible_cases:
        expected_type = case["data_type"]

        if expected_type == "NONE":
            continue

        findings = detect_sensitive_data(case["text"])

        detected = any(
            item["type"] == expected_type
            for item in findings
        )

        expected_only_found = (
            detected
            and case["channel"] == case["expected_channel"]
        )

        all_channels_found = detected

        results.append({
            "Case ID": case["case_id"],
            "Channel": case["channel"],
            "Visibility": case["visibility"],
            "Sensitive Type": expected_type,
            "Expected Channel": case["expected_channel"],
            "Expected-Only Found": expected_only_found,
            "All-Channels Found": all_channels_found,
            "Missed by Expected-Only": (
                all_channels_found and not expected_only_found
            ),
        })

    total = len(results)
    expected_recovered = sum(
        row["Expected-Only Found"] for row in results
    )
    all_recovered = sum(
        row["All-Channels Found"] for row in results
    )
    missed = sum(
        row["Missed by Expected-Only"] for row in results
    )

    return {
        "total": total,
        "expected_recovered": expected_recovered,
        "all_recovered": all_recovered,
        "missed": missed,
        "expected_rate": (
            expected_recovered / total if total else 0.0
        ),
        "all_rate": (
            all_recovered / total if total else 0.0
        ),
        "missed_rate": (
            missed / all_recovered if all_recovered else 0.0
        ),
        "details": results,
    }
