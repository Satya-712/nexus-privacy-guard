
import unittest

from src.privacy_detector import detect_sensitive_data
from src.privacy_redactor import redact_sensitive_data


class TestPrivacyEdgeCases(unittest.TestCase):

    def test_empty_text(self):
        self.assertEqual(detect_sensitive_data(""), [])

    def test_normal_text(self):
        findings = detect_sensitive_data(
            "Welcome to our AI project."
        )
        self.assertEqual(findings, [])

    def test_version_number_not_email_or_api_key(self):
        findings = detect_sensitive_data(
            "Version 2.5 is available."
        )
        self.assertEqual(findings, [])

    def test_valid_email(self):
        findings = detect_sensitive_data(
            "Contact student@example.com"
        )
        self.assertIn(
            "EMAIL",
            [item["type"] for item in findings],
        )

    def test_valid_phone(self):
        findings = detect_sensitive_data(
            "Call 9876543210"
        )
        self.assertIn(
            "PHONE",
            [item["type"] for item in findings],
        )

    def test_valid_api_key(self):
        findings = detect_sensitive_data(
            "Token: sk-AbCdEfGh1234"
        )
        self.assertIn(
            "API_KEY",
            [item["type"] for item in findings],
        )

    def test_multiple_sensitive_values(self):
        text = (
            "Email student@example.com, "
            "phone 9876543210, "
            "key sk-AbCdEfGh1234"
        )
        findings = detect_sensitive_data(text)
        detected_types = {item["type"] for item in findings}

        self.assertTrue(
            {"EMAIL", "PHONE", "API_KEY"}.issubset(
                detected_types
            )
        )

    def test_redaction_removes_original_email(self):
        text = "Contact student@example.com"
        redacted = redact_sensitive_data(text)

        self.assertNotIn("student@example.com", redacted)
        self.assertIn("[REDACTED_EMAIL]", redacted)

    
    def test_unusual_email_format_is_detected(self):
        text = "Contact student [at] example [dot] com"
        findings = detect_sensitive_data(text)

        emails = [
            item for item in findings
            if item["type"] == "EMAIL"
        ]

        self.assertEqual(len(emails), 1)
        self.assertEqual(
            emails[0]["value"],
            "student [at] example [dot] com",
        )
    
    def test_redact_obfuscated_email(self):
        text = "Contact student [at] example [dot] com"
        redacted = redact_sensitive_data(text)

        self.assertNotIn(
            "student [at] example [dot] com",
            redacted,
        )
        self.assertIn("[REDACTED_EMAIL]", redacted)

    def test_redact_formatted_phone(self):
        text = "Call 987-654-3210"
        redacted = redact_sensitive_data(text)

        self.assertNotIn("987-654-3210", redacted)
        self.assertIn("[REDACTED_PHONE]", redacted)

    def test_redact_multiple_sensitive_values_preserves_text(self):
        text = (
            "User student@example.com called 987-654-3210. "
            "Key: sk-AbCdEfGh1234. Status: active."
        )
        redacted = redact_sensitive_data(text)

        self.assertNotIn("student@example.com", redacted)
        self.assertNotIn("987-654-3210", redacted)
        self.assertNotIn("sk-AbCdEfGh1234", redacted)

        self.assertIn("[REDACTED_EMAIL]", redacted)
        self.assertIn("[REDACTED_PHONE]", redacted)
        self.assertIn("[REDACTED_API_KEY]", redacted)
        self.assertIn("Status: active.", redacted)




if __name__ == "__main__":
    unittest.main()
