
import json
from pathlib import Path

from src.privacy_detector import detect_sensitive_data

DATA_PATH = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "expanded_experiments.json"
)


def detect_data_type(text):
    findings = detect_sensitive_data(text)
    detected_types = {item["type"] for item in findings}

    # A case is positive if any sensitive type is detected.
    return "SENSITIVE" if detected_types else "NONE"


def main():
    with DATA_PATH.open("r", encoding="utf-8") as file:
        records = json.load(file)

    labels = []
    predictions = []
    correct = 0
    per_type = {}

    for record in records:
        expected = (
            "NONE"
            if record["data_type"] == "NONE"
            else "SENSITIVE"
        )

        predicted = detect_data_type(record["text"])

        labels.append(expected)
        predictions.append(predicted)

        if expected == predicted:
            correct += 1

        kind = record["data_type"]
        stats = per_type.setdefault(
            kind, {"total": 0, "correct": 0}
        )
        stats["total"] += 1

        if expected == predicted:
            stats["correct"] += 1

    total = len(records)
    accuracy = correct / total if total else 0

    tp = sum(
        actual == "SENSITIVE" and predicted == "SENSITIVE"
        for actual, predicted in zip(labels, predictions)
    )
    tn = sum(
        actual == "NONE" and predicted == "NONE"
        for actual, predicted in zip(labels, predictions)
    )
    fp = sum(
        actual == "NONE" and predicted == "SENSITIVE"
        for actual, predicted in zip(labels, predictions)
    )
    fn = sum(
        actual == "SENSITIVE" and predicted == "NONE"
        for actual, predicted in zip(labels, predictions)
    )

    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0
    )

    print("\n=== EXPANDED DATASET EVALUATION ===")
    print(f"Total test cases : {total}")
    print(f"Correct cases    : {correct}")
    print(f"Accuracy         : {accuracy:.2%}")
    print(f"Precision        : {precision:.2%}")
    print(f"Recall           : {recall:.2%}")
    print(f"F1-score         : {f1:.2%}")

    print("\n=== CONFUSION MATRIX ===")
    print(f"True Positives  (TP): {tp}")
    print(f"True Negatives  (TN): {tn}")
    print(f"False Positives (FP): {fp}")
    print(f"False Negatives (FN): {fn}")

    print("\n=== ACCURACY BY DATA TYPE ===")
    for kind, stats in sorted(per_type.items()):
        rate = stats["correct"] / stats["total"]
        print(
            f"{kind:8} : {stats['correct']}/"
            f"{stats['total']} ({rate:.2%})"
        )

    print("\nNote: Results use synthetic test data.")
    print("They are demonstration metrics, not real-world validation.")


if __name__ == "__main__":
    main()
