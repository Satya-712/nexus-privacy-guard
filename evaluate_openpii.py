"""
Evaluate the project's regex detector against supported OpenPII annotations.

Run from project root:
    python evaluate_openpii.py

This evaluation covers only:
  - OpenPII EMAIL -> detector EMAIL
  - OpenPII TELEPHONENUM -> detector PHONE

Only exact entity type + exact character-span matches count as true positives.
Unsupported OpenPII labels are excluded from the metrics. API_KEY is not annotated
as a supported ground-truth category in the inspected sample, so API-key detection
is not evaluated here.

OpenPII examples are synthetic. Results are a public synthetic benchmark sample,
not real-world validation.
"""

import csv
import json
from collections import Counter
from pathlib import Path

from src.privacy_detector import detect_sensitive_data

ROOT = Path(__file__).resolve().parent
INPUT_FILE = ROOT / "data" / "openpii_sample.jsonl"
REPORT_DIR = ROOT / "reports"
DETAILS_FILE = REPORT_DIR / "openpii_evaluation_details.csv"
SUMMARY_FILE = REPORT_DIR / "openpii_evaluation_summary.csv"

# Map benchmark annotation labels to detector output types.
LABEL_MAP = {
    "EMAIL": "EMAIL",
    "TELEPHONENUM": "PHONE",
}


def safe_text(value, limit=500):
    """Keep reports readable and avoid writing entire long source records."""
    text = "" if value is None else str(value)
    return text.replace("\r", " ").replace("\n", " ")[:limit]


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Dataset sample not found: {INPUT_FILE}\n"
            "Run download_openpii_sample.py first."
        )

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    counts = {
        "EMAIL": Counter(tp=0, fp=0, fn=0),
        "PHONE": Counter(tp=0, fp=0, fn=0),
    }
    detail_rows = []
    total_examples = 0
    total_annotations = 0
    ignored_annotations = Counter()
    detected_predictions = Counter()

    with INPUT_FILE.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue

            row = json.loads(line)
            total_examples += 1
            text = row.get("source_text", "")
            annotations = row.get("privacy_mask", []) or []
            total_annotations += len(annotations)

            # Keep only labels this regex detector currently supports.
            ground_truth = []
            for annotation in annotations:
                label = str(annotation.get("label", "")).upper()
                if label not in LABEL_MAP:
                    ignored_annotations[label or "UNKNOWN"] += 1
                    continue

                try:
                    start = int(annotation["start"])
                    end = int(annotation["end"])
                except (KeyError, TypeError, ValueError):
                    ignored_annotations[f"{label}_INVALID_SPAN"] += 1
                    continue

                ground_truth.append({
                    "type": LABEL_MAP[label],
                    "start": start,
                    "end": end,
                    "value": annotation.get("value", ""),
                })

            predictions = []
            for finding in detect_sensitive_data(text):
                kind = str(finding.get("type", "")).upper()
                if kind not in counts:
                    continue
                prediction = {
                    "type": kind,
                    "start": int(finding["start"]),
                    "end": int(finding["end"]),
                    "value": finding.get("value", ""),
                }
                predictions.append(prediction)
                detected_predictions[kind] += 1

            # Greedy one-to-one exact span + type matching.
            matched_prediction_indices = set()
            matched_truth_indices = set()

            for truth_index, truth in enumerate(ground_truth):
                for prediction_index, prediction in enumerate(predictions):
                    if prediction_index in matched_prediction_indices:
                        continue
                    if (
                        truth["type"] == prediction["type"]
                        and truth["start"] == prediction["start"]
                        and truth["end"] == prediction["end"]
                    ):
                        matched_truth_indices.add(truth_index)
                        matched_prediction_indices.add(prediction_index)
                        counts[truth["type"]]["tp"] += 1
                        break

            for prediction_index, prediction in enumerate(predictions):
                if prediction_index not in matched_prediction_indices:
                    counts[prediction["type"]]["fp"] += 1

            for truth_index, truth in enumerate(ground_truth):
                if truth_index not in matched_truth_indices:
                    counts[truth["type"]]["fn"] += 1

            unmatched_truth = [
                f'{x["type"]}@{x["start"]}:{x["end"]}'
                for i, x in enumerate(ground_truth)
                if i not in matched_truth_indices
            ]
            unmatched_predictions = [
                f'{x["type"]}@{x["start"]}:{x["end"]}'
                for i, x in enumerate(predictions)
                if i not in matched_prediction_indices
            ]

            detail_rows.append({
                "uid": row.get("uid", f"line-{line_number}"),
                "language": row.get("language", ""),
                "supported_ground_truth_count": len(ground_truth),
                "detector_prediction_count": len(predictions),
                "matched_exact_spans": len(matched_truth_indices),
                "unmatched_ground_truth_spans": "; ".join(unmatched_truth),
                "unmatched_prediction_spans": "; ".join(unmatched_predictions),
                "source_text_preview": safe_text(text),
            })

    summary_rows = []
    for kind in ("EMAIL", "PHONE"):
        tp = counts[kind]["tp"]
        fp = counts[kind]["fp"]
        fn = counts[kind]["fn"]
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision + recall
            else 0.0
        )
        summary_rows.append({
            "category": kind,
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1_score": round(f1, 6),
            "matching_rule": "exact entity type and exact character span",
            "dataset": "OpenPII synthetic sample (English)",
        })

    tp_total = sum(c["tp"] for c in counts.values())
    fp_total = sum(c["fp"] for c in counts.values())
    fn_total = sum(c["fn"] for c in counts.values())
    p = tp_total / (tp_total + fp_total) if tp_total + fp_total else 0.0
    r = tp_total / (tp_total + fn_total) if tp_total + fn_total else 0.0
    f1_total = 2 * p * r / (p + r) if p + r else 0.0
    summary_rows.append({
        "category": "MICRO_AVERAGE_SUPPORTED_LABELS",
        "true_positive": tp_total,
        "false_positive": fp_total,
        "false_negative": fn_total,
        "precision": round(p, 6),
        "recall": round(r, 6),
        "f1_score": round(f1_total, 6),
        "matching_rule": "exact entity type and exact character span",
        "dataset": "OpenPII synthetic sample (English)",
    })

    with DETAILS_FILE.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(detail_rows[0].keys()) if detail_rows else [
            "uid", "language", "supported_ground_truth_count",
            "detector_prediction_count", "matched_exact_spans",
            "unmatched_ground_truth_spans", "unmatched_prediction_spans",
            "source_text_preview",
        ])
        writer.writeheader()
        writer.writerows(detail_rows)

    with SUMMARY_FILE.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summary_rows[0].keys()))
        writer.writeheader()
        writer.writerows(summary_rows)

    print("\nOpenPII evaluation complete")
    print("---------------------------")
    print(f"Examples processed: {total_examples}")
    print(f"All dataset annotations: {total_annotations}")
    print(f"Supported categories evaluated: EMAIL, TELEPHONENUM -> PHONE")
    print(f"Unsupported annotations excluded: {sum(ignored_annotations.values())}")
    print("\nExact-span metrics:")
    for result in summary_rows:
        print(
            f'{result["category"]:32} '
            f'TP={result["true_positive"]:4} '
            f'FP={result["false_positive"]:4} '
            f'FN={result["false_negative"]:4} '
            f'P={result["precision"]:.3f} '
            f'R={result["recall"]:.3f} '
            f'F1={result["f1_score"]:.3f}'
        )
    print(f"\nDetails: {DETAILS_FILE}")
    print(f"Summary: {SUMMARY_FILE}")
    print("\nCaution: OpenPII is synthetic; these metrics are not real-world performance estimates.")


if __name__ == "__main__":
    main()
