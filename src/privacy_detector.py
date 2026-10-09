
import re


def detect_sensitive_data(text):
    """
    Detect common sensitive information in text.

    Supports standard emails, common obfuscated email formats,
    10-digit phone numbers, and synthetic sk- API key examples.

    This is a research prototype, not a production-grade
    privacy detector.
    """

    if not isinstance(text, str) or not text:
        return []

    findings = []

    def add_finding(data_type, value, start, end):
        findings.append({
            "type": data_type,
            "value": value,
            "start": start,
            "end": end,
        })

    # 1. Standard email addresses
    email_pattern = (
        r"(?<![\w.+%-])"
        r"[A-Za-z0-9._%+-]+"
        r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
        r"(?![\w.-])"
    )

    for match in re.finditer(email_pattern, text):
        add_finding("EMAIL", match.group(), match.start(), match.end())

    # 2. Common obfuscated email formats, e.g.
    # student [at] example [dot] com
    # student at example dot com
    obfuscated_email_pattern = (
        r"(?<![\w.+%-])"
        r"[A-Za-z0-9._%+-]+"
        r"\s*(?:\[at\]|\(at\)|\sat\s)"
        r"\s*[A-Za-z0-9-]+"
        r"\s*(?:\[dot\]|\(dot\)|\sdot\s)"
        r"\s*[A-Za-z]{2,}"
        r"(?![\w.-])"
    )

    for match in re.finditer(
        obfuscated_email_pattern, text, re.IGNORECASE
    ):
        # Avoid duplicating a match already covered by the standard
        # email pattern.
        overlaps = any(
            item["type"] == "EMAIL"
            and match.start() < item["end"]
            and match.end() > item["start"]
            for item in findings
        )

        if not overlaps:
            add_finding(
                "EMAIL", match.group(), match.start(), match.end()
            )

    # 3. Phone numbers: 10 digits, optionally separated by
    # spaces, dots, or hyphens.
   
  
    phone_pattern = (
        r"(?<!\w)"
        r"\+?\d(?:[\d .()/\-]*\d)?"
        r"(?!\w)"
    )

    # These nearby field labels suggest that a number is not a phone.
    non_phone_context = re.compile(
        r"(?:social\s*security|tax\s*(?:id|number|no\.?)|"
        r"credit\s*card|passport|driver'?s?\s*licen[cs]e|"
        r"date\s*of\s*birth|birth\s*date|dob|"
        r"zip\s*code|postal\s*code|signature\s*date)",
        re.IGNORECASE,
    )

    for match in re.finditer(phone_pattern, text):
        value = match.group()
        digits = re.sub(r"\D", "", value)

        if not 7 <= len(digits) <= 15:
            continue

        # Exclude date-like values such as 28/10/2017.
        if re.fullmatch(r"\d{1,4}[./-]\d{1,2}[./-]\d{1,4}", value.strip()):
            continue

        # Exclude decimal-style values such as 17468.48681.
        if re.fullmatch(r"\d+\.\d+", value.strip()):
            continue

        # Check the nearby text for a non-phone field label.
        context = text[max(0, match.start() - 80):match.start()].lower()
        recent_context = context.rsplit("\n", 1)[-1]

        if non_phone_context.search(recent_context):
            continue

        add_finding("PHONE", value, match.start(), match.end())

    # 4. Synthetic API-key format used in this project.
    api_key_pattern = r"(?<![A-Za-z0-9_])sk-[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_])"

    for match in re.finditer(api_key_pattern, text):
        add_finding(
            "API_KEY", match.group(), match.start(), match.end()
        )

    # Keep findings in their original text order.
    findings.sort(key=lambda item: (item["start"], item["end"]))

    return findings


if __name__ == "__main__":
    sample_text = (
        "Contact: student@example.com, "
        "Obfuscated: student [at] example [dot] com, "
        "Phone: 987-654-3210, "
        "Key: sk-AbCdEfGh1234"
    )

    for item in detect_sensitive_data(sample_text):
        print(item)
