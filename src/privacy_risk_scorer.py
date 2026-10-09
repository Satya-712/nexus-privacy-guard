
from src.privacy_detector import detect_sensitive_data


# Prototype-only weights; these are not calibrated risk estimates.
SENSITIVITY_WEIGHTS = {
    "EMAIL": 3,
    "PHONE": 3,
    "API_KEY": 5,
}

VISIBILITY_MULTIPLIERS = {
    "visible": 1.0,
    "internal": 0.5,
}


def calculate_privacy_risk(text, visibility="visible", authorized=False):
    """
    Calculate an illustrative privacy-risk score.

    The score is a heuristic for prioritizing synthetic examples.
    It is not a real-world probability or validated security rating.
    """
    if visibility not in VISIBILITY_MULTIPLIERS:
        raise ValueError(
            "visibility must be 'visible' or 'internal'"
        )

    findings = detect_sensitive_data(text)
    visibility_multiplier = VISIBILITY_MULTIPLIERS[visibility]

    total_score = 0
    detected_types = []

    for finding in findings:
        data_type = finding["type"]
        weight = SENSITIVITY_WEIGHTS.get(data_type, 0)

        if weight:
            total_score += weight
            detected_types.append(data_type)

    total_score *= visibility_multiplier

    if findings and not authorized:
        total_score *= 1.5

    return {
        "risk_score": round(total_score, 2),
        "visibility": visibility,
        "authorized_label": authorized,
        "detected_types": sorted(set(detected_types)),
        "finding_count": len(findings),
        "risk_model": "prototype_heuristic",
    }


if __name__ == "__main__":
    example = (
        "Contact: student@example.com; "
        "Key: sk-AbCdEfGh1234"
    )

    report = calculate_privacy_risk(
        example,
        visibility="visible",
        authorized=False,
    )

    print("Privacy risk report:")
    print(report)
