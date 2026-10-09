"""
Download a small English sample from OpenPII 1M without downloading the full dataset.

Run from the project root:
    python download_openpii_sample.py

Dataset: ai4privacy/pii-masking-openpii-1m
The dataset contains synthetic PII examples. This is a public benchmark sample,
not real-world personal data and not real-world validation.
"""

import json
from pathlib import Path

from datasets import load_dataset

REPO_ROOT = Path(__file__).resolve().parent
OUTPUT_DIR = REPO_ROOT / "data"
OUTPUT_FILE = OUTPUT_DIR / "openpii_sample.jsonl"

SAMPLE_SIZE = 200
LANGUAGE = "en"


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading OpenPII in streaming mode (this avoids downloading the full dataset)...")
    dataset = load_dataset(
        "ai4privacy/pii-masking-openpii-1m",
        split="train",
        streaming=True,
    )

    saved = 0
    scanned = 0

    with OUTPUT_FILE.open("w", encoding="utf-8") as out:
        for row in dataset:
            scanned += 1

            if row.get("language") != LANGUAGE:
                continue

            source_text = row.get("source_text")
            privacy_mask = row.get("privacy_mask")

            if not isinstance(source_text, str) or not isinstance(privacy_mask, list):
                continue

            clean_row = {
                "uid": row.get("uid"),
                "language": row.get("language"),
                "region": row.get("region"),
                "source_text": source_text,
                "masked_text": row.get("masked_text", ""),
                "privacy_mask": privacy_mask,
            }

            out.write(json.dumps(clean_row, ensure_ascii=False) + "\n")
            saved += 1

            if saved % 25 == 0:
                print(f"Saved {saved}/{SAMPLE_SIZE} English examples (scanned {scanned} rows)...")

            if saved >= SAMPLE_SIZE:
                break

    if saved == 0:
        OUTPUT_FILE.unlink(missing_ok=True)
        raise RuntimeError(
            "No English examples were saved. Check your internet connection, "
            "dataset availability, and the dataset's language column."
        )

    print("\nDone!")
    print(f"English examples saved: {saved}")
    print(f"Output file: {OUTPUT_FILE}")
    print("Note: OpenPII is synthetic data; report results as a synthetic public-benchmark evaluation.")


if __name__ == "__main__":
    main()
