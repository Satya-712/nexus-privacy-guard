
from src.displacement_analyzer import analyze_outlet_displacement
from src.authorization_checker import audit_exposures


def evaluate_session(exposures, expected_channels, authorized_types):
    """Combine displacement analysis and authorization auditing."""

    displacement_report = analyze_outlet_displacement(
        exposures,
        expected_channels,
    )

    authorization_report = audit_exposures(
        exposures,
        authorized_types,
    )

    unauthorized_count = sum(
        not item["authorized"]
        for item in authorization_report
    )

    return {
        "total_visible_exposures": len(exposures),
        "unauthorized_exposures": unauthorized_count,
        "displacement": displacement_report,
        "authorization_audit": authorization_report,
    }
