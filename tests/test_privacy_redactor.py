
import unittest

from src.privacy_redactor import redact_sensitive_data


class TestPrivacyRedactor(unittest.TestCase):

    def test_redact_email(self):
        result = redact_sensitive_data(
            "Contact student@example.com"
        )
        self.assertEqual(
            result,
            "Contact [REDACTED_EMAIL]",
        )

    def test_redact_phone(self):
        result = redact_sensitive_data(
            "Phone: 9876543210"
        )
        self.assertEqual(
            result,
            "Phone: [REDACTED_PHONE]",
        )

    def test_redact_api_key(self):
        result = redact_sensitive_data(
            "Key: sk-AbCdEfGh1234"
        )
        self.assertEqual(
            result,
            "Key: [REDACTED_API_KEY]",
        )

    def test_redact_multiple_values(self):
        result = redact_sensitive_data(
            "student@example.com 9876543210"
        )
        self.assertEqual(
            result,
            "[REDACTED_EMAIL] [REDACTED_PHONE]",
        )

    def test_preserve_normal_text(self):
        text = "Welcome to our AI project"
        self.assertEqual(
            redact_sensitive_data(text),
            text,
        )

    def test_empty_text(self):
        self.assertEqual(
            redact_sensitive_data(""),
            "",
        )


if __name__ == "__main__":
    unittest.main()
