
import unittest

from src.privacy_detector import detect_sensitive_data


class TestPrivacyDetector(unittest.TestCase):

    def test_detect_email(self):
        result = detect_sensitive_data(
            "Contact student@example.com"
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "EMAIL")

    def test_detect_phone(self):
        result = detect_sensitive_data(
            "Phone: 9876543210"
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "PHONE")

    def test_detect_api_key(self):
        result = detect_sensitive_data(
            "Key: sk-AbCdEfGh1234"
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "API_KEY")

    def test_no_sensitive_data(self):
        result = detect_sensitive_data(
            "Hello, welcome to our AI project"
        )
        self.assertEqual(len(result), 0)


if __name__ == "__main__":
    unittest.main()
