
import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
OUTPUT_PATH = DATA_DIR / "expanded_experiments.json"


def generate_test_dataset():
    cases = []
    case_number = 1

    examples = [
        ("Contact student@example.com", "EMAIL"),
        ("Phone: 9876543210", "PHONE"),
        ("Key: sk-AbCdEfGh1234", "API_KEY"),
        ("Welcome to our AI project", "NONE"),
        ("No private information here", "NONE"),
        ("Email: user.name+test@sample.org", "EMAIL"),
        ("Call 1234567890 for support", "PHONE"),
        ("Token sk-12345678", "API_KEY"),
        ("Version 2.5 is available", "NONE"),
        ("Contact admin@example.net", "EMAIL"),
        ("Phone number: 9123456780", "PHONE"),
        ("Secret: sk-ZyxWvuTs9876", "API_KEY"),
    ]

    channels = ["console", "browser", "tool_output"]
    visibility_options = ["visible", "internal"]

    for index in range(60):
        text, data_type = examples[index % len(examples)]
        channel = channels[index % len(channels)]
        visibility = visibility_options[index % len(visibility_options)]

        expected_channel = (
            "console" if data_type != "NONE" else "browser"
        )

        # These are synthetic labels for demonstration only.
        authorized = (index % 3 == 0)

        cases.append({
            "case_id": f"X{case_number:03d}",
            "channel": channel,
            "visibility": visibility,
            "text": text,
            "data_type": data_type,
            "expected_channel": expected_channel,
            "authorized": authorized,
        })

        case_number += 1

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open("w", encoding="utf-8") as file:
        json.dump(cases, file, indent=2)

    print(f"Generated {len(cases)} synthetic test cases.")
    print(f"Output file: {OUTPUT_PATH}")

    counts = {}
    for case in cases:
        kind = case["data_type"]
        counts[kind] = counts.get(kind, 0) + 1

    print("Cases by data type:")
    for kind, count in sorted(counts.items()):
        print(f"  {kind}: {count}")


if __name__ == "__main__":
    generate_test_dataset()
