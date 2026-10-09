
import unittest

from src.evaluation_pipeline import evaluate_session


class TestEvaluationPipeline(unittest.TestCase):

    def test_displacement_and_authorization(self):
        exposures = [
            {
                "channel": "browser",
                "type": "EMAIL",
                "value": "student@example.com",
            },
            {
                "channel": "console",
                "type": "PHONE",
                "value": "9876543210",
            },
        ]

        expected_channels = {
            "EMAIL": "console",
            "PHONE": "console",
        }

        authorized_types = []

        report = evaluate_session(
            exposures,
            expected_channels,
            authorized_types,
        )

        self.assertEqual(
            report["total_visible_exposures"], 2
        )
        self.assertEqual(
            report["unauthorized_exposures"], 2
        )
        self.assertEqual(
            report["displacement"]["displaced_exposures"], 1
        )
        self.assertEqual(
            report["displacement"]["displacement_rate"], 0.5
        )

    def test_empty_session(self):
        report = evaluate_session([], {}, [])

        self.assertEqual(
            report["total_visible_exposures"], 0
        )
        self.assertEqual(
            report["unauthorized_exposures"], 0
        )
        self.assertEqual(
            report["displacement"]["displacement_rate"], 0.0
        )


if __name__ == "__main__":
    unittest.main()
