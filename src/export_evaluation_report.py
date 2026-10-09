
import csv
import json
from pathlib import Path
from collections import Counter

from src.privacy_detector import detect_sensitive_data


ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = ROOT_DIR / "data" / "expanded_experiments.json"
REPORT_DIR = ROOT_DIR / "reports"

DETAILS_PATH = REPORT_DIR / "evaluation_details.csv"
SUMMARY_PATH = REPORT_DIR / "evaluation_summary.csv"


def classify_text(text):
    findings = detect_sensitive_data(text)
    detected_types = sorted({item["type"] for item in findings})

    return ("SENSITIVE" if findings else "NONE"), detected_types


def main():
    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATA_PATH}\n"
            "Run: python -m src.generate_test_dataset"
        )

    with DATA_PATH.open("r", encoding="utf-8") as file:
        records = json.load(file)

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    details = []
    confusion = Counter()
    type_stats = {}

    for record in records:
        expected_type = record.get("data_type", "NONE")
        expected = (
            "NONE" if expected_type == "NONE" else "SENSITIVE"
        )

        predicted, detected_types = classify_text(
            record.get("text", "")
        )

        if expected == "SENSITIVE" and predicted == "SENSITIVE":
            confusion["TP"] += 1
        elif expected == "NONE" and predicted == "NONE":
            confusion["TN"] += 1
        elif expected == "NONE" and predicted == "SENSITIVE":
            confusion["FP"] += 1
        else:
            confusion["FN"] += 1

        stats = type_stats.setdefault(
            expected_type, {"total": 0, "correct": 0}
        )
        stats["total"] += 1

        is_correct = expected == predicted
        if is_correct:
            stats["correct"] += 1

        details.append({
            "case_id": record.get("case_id", ""),
            "channel": record.get("channel", ""),
            "visibility": record.get("visibility", ""),
            "expected_type": expected_type,
            "expected_class": expected,
            "detected_types": "|".join(detected_types),
            "predicted_class": predicted,
            "correct": is_correct,
        })

    total = len(details)
    tp = confusion["TP"]
    tn = confusion["TN"]
    fp = confusion["FP"]
    fn = confusion["FN"]

    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0
    )

    with DETAILS_PATH.open(
        "w", newline="", encoding="utf-8-sig"
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "case_id",
                "channel",
                "visibility",
                "expected_type",
                "expected_class",
                "detected_types",
                "predicted_class",
                "correct",
            ],
        )
        writer.writeheader()
        writer.writerows(details)

    summary_rows = [
        {"metric": "total_cases", "value": total},
        {"metric": "true_positives", "value": tp},
        {"metric": "true_negatives", "value": tn},
        {"metric": "false_positives", "value": fp},
        {"metric": "false_negatives", "value": fn},
        {"metric": "accuracy", "value": round(accuracy, 4)},
        {"metric": "precision", "value": round(precision, 4)},
        {"metric": "recall", "value": round(recall, 4)},
        {"metric": "f1_score", "value": round(f1, 4)},
    ]

    for kind, stats in sorted(type_stats.items()):
        rate = stats["correct"] / stats["total"]
        summary_rows.append({
            "metric": f"{kind.lower()}_accuracy",
            "value": round(rate, 4),
        })

    with SUMMARY_PATH.open(
        "w", newline="", encoding="utf-8-sig"
    ) as file:
        writer = csv.DictWriter(
            file, fieldnames=["metric", "value"]
        )
        writer.writeheader()
        writer.writerows(summary_rows)

    print("\n=== CSV REPORTS GENERATED ===")
    print(f"Detailed report: {DETAILS_PATH}")
    print(f"Summary report : {SUMMARY_PATH}")
    print(f"Total cases    : {total}")
    print(f"Accuracy       : {accuracy:.2%}")
    print(f"Precision      : {precision:.2%}")
    print(f"Recall         : {recall:.2%}")
    print(f"F1-score       : {f1:.2%}")
    print("\nNote: Metrics use synthetic data only.")


if __name__ == "__main__":
    main()
