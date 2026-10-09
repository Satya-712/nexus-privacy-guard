"""
Analyze OpenPII false positives and false negatives for the current detector evaluation.

Run from the project root:
    python analyze_openpii_errors.py

Inputs:
    data/openpii_sample.jsonl
    reports/openpii_evaluation_details.csv

Outputs:
    reports/openpii_false_positives.csv
    reports/openpii_false_negatives.csv
    reports/openpii_error_analysis.txt

This is a diagnostic helper for the supported labels EMAIL and TELEPHONENUM -> PHONE.
It does not change the detector or claim real-world performance.
"""
import csv
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA_PATH = ROOT / "data" / "openpii_sample.jsonl"
DETAILS_PATH = ROOT / "reports" / "openpii_evaluation_details.csv"
REPORTS_DIR = ROOT / "reports"

LABEL_MAP = {
    "EMAIL": "EMAIL",
    "TELEPHONENUM": "PHONE",
}


def load_dataset():
    records = {}
    with DATA_PATH.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            records[str(row.get("uid"))] = row
    return records


def parse_spans(value):
    """Parse entries like PHONE@111:121; EMAIL@55:73."""
    spans = []
    if not value:
        return spans
    for item in value.split("; "):
        match = re.fullmatch(r"([A-Z_]+)@(\d+):(\d+)", item.strip())
        if match:
            spans.append({
                "type": match.group(1),
                "start": int(match.group(2)),
                "end": int(match.group(3)),
            })
    return spans


def context_for(text, start, end, radius=70):
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    return text[left:right].replace("\n", "\\n")


def annotation_value(text, annotation):
    start = int(annotation.get("start", 0))
    end = int(annotation.get("end", 0))
    return text[start:end]


def main():
    if not DATA_PATH.exists():
        raise SystemExit(f"Dataset not found: {DATA_PATH}")
    if not DETAILS_PATH.exists():
        raise SystemExit(
            f"Evaluation details not found: {DETAILS_PATH}\n"
            "Run `python evaluate_openpii.py` first."
        )

    records = load_dataset()
    false_positives = []
    false_negatives = []

    with DETAILS_PATH.open("r", encoding="utf-8-sig", newline="") as handle:
        detail_rows = list(csv.DictReader(handle))

    for row in detail_rows:
        uid = str(row.get("uid", ""))
        record = records.get(uid)
        if record is None:
            continue
        text = record.get("source_text", "") or ""

        for span in parse_spans(row.get("unmatched_prediction_spans", "")):
            start, end = span["start"], span["end"]
            false_positives.append({
                "uid": uid,
                "predicted_type": span["type"],
                "start": start,
                "end": end,
                "predicted_text": text[start:end],
                "context": context_for(text, start, end),
            })

        for span in parse_spans(row.get("unmatched_ground_truth_spans", "")):
            start, end = span["start"], span["end"]
            # Resolve the original annotation label using exact offsets.
            original_label = ""
            original_value = ""
            for annotation in record.get("privacy_mask", []) or []:
                try:
                    a_start = int(annotation.get("start", -1))
                    a_end = int(annotation.get("end", -1))
                except (TypeError, ValueError):
                    continue
                mapped = LABEL_MAP.get(str(annotation.get("label", "")).upper())
                if a_start == start and a_end == end and mapped == span["type"]:
                    original_label = str(annotation.get("label", ""))
                    original_value = str(annotation.get("value", text[start:end]))
                    break

            false_negatives.append({
                "uid": uid,
                "expected_type": span["type"],
                "original_label": original_label,
                "start": start,
                "end": end,
                "expected_text": text[start:end],
                "annotation_value": original_value,
                "context": context_for(text, start, end),
            })

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    fp_path = REPORTS_DIR / "openpii_false_positives.csv"
    fn_path = REPORTS_DIR / "openpii_false_negatives.csv"
    txt_path = REPORTS_DIR / "openpii_error_analysis.txt"

    def write_csv(path, rows):
        fieldnames = list(rows[0].keys()) if rows else (
            ["uid", "predicted_type", "start", "end", "predicted_text", "context"]
            if "positives" in path.name else
            ["uid", "expected_type", "original_label", "start", "end",
             "expected_text", "annotation_value", "context"]
        )
        with path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    write_csv(fp_path, false_positives)
    write_csv(fn_path, false_negatives)

    fp_by_type = {}
    for row in false_positives:
        fp_by_type[row["predicted_type"]] = fp_by_type.get(row["predicted_type"], 0) + 1
    fn_by_type = {}
    for row in false_negatives:
        fn_by_type[row["expected_type"]] = fn_by_type.get(row["expected_type"], 0) + 1

    lines = [
        "OpenPII error analysis",
        "======================",
        f"Dataset examples loaded: {len(records)}",
        f"Evaluation rows: {len(detail_rows)}",
        f"Unmatched predictions (false positives): {len(false_positives)}",
        f"Unmatched supported annotations (false negatives): {len(false_negatives)}",
        "",
        "False positives by predicted type:",
    ]
    lines.extend([f"  {key}: {value}" for key, value in sorted(fp_by_type.items())] or ["  None"])
    lines += ["", "False negatives by expected type:"]
    lines.extend([f"  {key}: {value}" for key, value in sorted(fn_by_type.items())] or ["  None"])
    lines += ["", "First 15 false positives (value and surrounding context):"]
    for item in false_positives[:15]:
        lines.append(
            f"- UID {item['uid']} [{item['predicted_type']} {item['start']}:{item['end']}] "
            f"value={item['predicted_text']!r}\n  context={item['context']}"
        )
    lines += ["", "First 15 false negatives (expected value and surrounding context):"]
    for item in false_negatives[:15]:
        lines.append(
            f"- UID {item['uid']} [{item['expected_type']} {item['start']}:{item['end']}] "
            f"value={item['expected_text']!r} annotation={item['annotation_value']!r}\n"
            f"  context={item['context']}"
        )
    lines += [
        "",
        "Caution: these are synthetic OpenPII examples and exact-span evaluation diagnostics,",
        "not estimates of real-world detector performance.",
        "",
        f"Full false-positive CSV: {fp_path}",
        f"Full false-negative CSV: {fn_path}",
    ]
    txt_path.write_text("\n".join(lines), encoding="utf-8")

    print("\n".join(lines))
    print("\nSaved:")
    print(f"  {fp_path}")
    print(f"  {fn_path}")
    print(f"  {txt_path}")


if __name__ == "__main__":
    main()
