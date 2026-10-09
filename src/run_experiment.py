
import json
from pathlib import Path

from src.privacy_detector import detect_sensitive_data


DATA_PATH = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "experiments.json"
)


def run_experiment():
    with DATA_PATH.open("r", encoding="utf-8") as file:
        cases = json.load(file)

    results = []

    tp = fp = fn = tn = 0
    displaced_count = 0
    positive_cases = 0

    for case in cases:
        findings = detect_sensitive_data(case["text"])

        expected_sensitive = case["data_type"] != "NONE"
        predicted_sensitive = len(findings) > 0

        if expected_sensitive and predicted_sensitive:
            tp += 1
        elif not expected_sensitive and predicted_sensitive:
            fp += 1
        elif expected_sensitive and not predicted_sensitive:
            fn += 1
        else:
            tn += 1

        displaced = (
            expected_sensitive
            and case["channel"] != case["expected_channel"]
        )

        if expected_sensitive:
            positive_cases += 1
            if displaced:
                displaced_count += 1

        results.append({
            "case_id": case["case_id"],
            "expected_sensitive": expected_sensitive,
            "predicted_sensitive": predicted_sensitive,
            "correct_decision": (
                expected_sensitive == predicted_sensitive
            ),
            "displaced": displaced,
        })

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    accuracy = (
        (tp + tn) / len(cases) if cases else 0.0
    )
    displacement_rate = (
        displaced_count / positive_cases if positive_cases else 0.0
    )

    print("=== EXPERIMENT METRICS ===")
    print("Total cases:", len(cases))
    print("TP:", tp, "| FP:", fp, "| FN:", fn, "| TN:", tn)
    print("Accuracy:", round(accuracy, 3))
    print("Precision:", round(precision, 3))
    print("Recall:", round(recall, 3))
    print("Displaced exposures:", displaced_count)
    print("Displacement rate:", round(displacement_rate, 3))

    print("\n=== CASE-LEVEL RESULTS ===")
    for result in results:
        print(result)


if __name__ == "__main__":
    run_experiment()
