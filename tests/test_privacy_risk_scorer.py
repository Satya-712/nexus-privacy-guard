
import unittest

from src.privacy_risk_scorer import calculate_privacy_risk


class TestPrivacyRiskScorer(unittest.TestCase):

    def test_unauthorized_visible_data(self):
        report = calculate_privacy_risk(
            "Contact: student@example.com",
            visibility="visible",
            authorized=False,
        )

        self.assertEqual(report["risk_score"], 4.5)
        self.assertEqual(report["finding_count"], 1)

    def test_api_key_has_higher_weight(self):
        report = calculate_privacy_risk(
            "Key: sk-AbCdEfGh1234",
            visibility="visible",
            authorized=True,
        )

        self.assertEqual(report["risk_score"], 5.0)
        self.assertIn("API_KEY", report["detected_types"])

    def test_authorized_data_has_no_unauthorized_multiplier(self):
        report = calculate_privacy_risk(
            "Contact: student@example.com",
            visibility="visible",
            authorized=True,
        )

        self.assertEqual(report["risk_score"], 3.0)

    def test_internal_visibility_reduces_heuristic_score(self):
        report = calculate_privacy_risk(
            "Contact: student@example.com",
            visibility="internal",
            authorized=True,
        )

        self.assertEqual(report["risk_score"], 1.5)

    def test_no_sensitive_data_has_zero_score(self):
        report = calculate_privacy_risk(
            "Welcome to our AI project",
            visibility="visible",
            authorized=False,
        )

        self.assertEqual(report["risk_score"], 0.0)
        self.assertEqual(report["finding_count"], 0)

    def test_invalid_visibility_raises_error(self):
        with self.assertRaises(ValueError):
            calculate_privacy_risk(
                "student@example.com",
                visibility="unknown",
                authorized=False,
            )


if __name__ == "__main__":
    unittest.main()
