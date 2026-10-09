
from src.privacy_detector import detect_sensitive_data


REDACTION_LABELS = {
    "EMAIL": "[REDACTED_EMAIL]",
    "PHONE": "[REDACTED_PHONE]",
    "API_KEY": "[REDACTED_API_KEY]",
}


def redact_sensitive_data(text):
    """
    Detect and mask supported sensitive-data patterns.
    Returns the redacted text without changing other content.
    """
    findings = detect_sensitive_data(text)

    # Replace from right to left so earlier character
    # positions remain valid.
    for finding in sorted(
        findings,
        key=lambda item: item["start"],
        reverse=True,
    ):
        start = finding["start"]
        end = finding["end"]
        data_type = finding["type"]

        replacement = REDACTION_LABELS.get(
            data_type,
            "[REDACTED]",
        )

        text = text[:start] + replacement + text[end:]

    return text


if __name__ == "__main__":
    sample = (
        "Contact: student@example.com, "
        "Phone: 9876543210, "
        "Key: sk-AbCdEfGh1234"
    )

    print("Original:", sample)
    print("Redacted:", redact_sensitive_data(sample))
