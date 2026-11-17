import unittest
from unittest.mock import patch, Mock

import requests

from app import app


TEST_HASH = "a" * 64


class HashIntelligenceTests(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    @patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test-key"})
    @patch("services.intelligence.requests.get")
    def test_successful_hash_lookup(self, mock_get):
        response = Mock()
        response.status_code = 200
        response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 2,
                        "harmless": 60,
                        "undetected": 3
                    }
                }
            }
        }
        mock_get.return_value = response

        result = self.client.post(
            "/api/investigate",
            json={"type": "sha256", "value": TEST_HASH}
        )

        self.assertEqual(result.status_code, 200)
        data = result.get_json()

        self.assertEqual(data["intelligence_status"], "completed")
        self.assertEqual(data["intelligence"]["reputation"]["malicious"], 5)
        self.assertEqual(data["intelligence"]["reputation"]["suspicious"], 2)
        self.assertEqual(data["verdict"], "unknown")
        mock_get.assert_called_once()

    @patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test-key"})
    @patch("services.intelligence.requests.get")
    def test_hash_not_found(self, mock_get):
        mock_get.return_value.status_code = 404

        result = self.client.post(
            "/api/investigate",
            json={"type": "sha256", "value": TEST_HASH}
        )

        self.assertEqual(
            result.get_json()["intelligence_status"],
            "not_found"
        )

    @patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test-key"})
    @patch("services.intelligence.requests.get")
    def test_rate_limit(self, mock_get):
        mock_get.return_value.status_code = 429

        result = self.client.post(
            "/api/investigate",
            json={"type": "sha256", "value": TEST_HASH}
        )

        self.assertEqual(
            result.get_json()["intelligence_status"],
            "rate_limited"
        )

    @patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test-key"})
    @patch("services.intelligence.requests.get")
    def test_provider_failure(self, mock_get):
        mock_get.side_effect = requests.RequestException(
            "Connection failed"
        )

        result = self.client.post(
            "/api/investigate",
            json={"type": "sha256", "value": TEST_HASH}
        )

        self.assertEqual(
            result.get_json()["intelligence_status"],
            "unavailable"
        )
        self.assertEqual(result.get_json()["verdict"], "unknown")


if __name__ == "__main__":
    unittest.main()
