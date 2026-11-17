import unittest
from unittest.mock import patch
from app import app


class IndicatorAPITests(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    @patch("app.investigate_ip")
    def test_valid_ip(self, mock_investigate):
        mock_investigate.return_value = {
            "status": "completed",
            "indicator": "8.8.8.8",
            "network": {
                "prefix": "8.8.8.0/24",
                "asns": ["15169"]
            },
            "source": {"provider": "RIPEstat"},
            "verdict": "unknown",
            "message": "Public network routing metadata retrieved."
        }

        response = self.client.post(
            "/api/investigate",
            json={"type": "ip", "value": "8.8.8.8"}
        )

        self.assertEqual(response.status_code, 200)

        data = response.get_json()

        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["intelligence_status"], "completed")
        self.assertEqual(data["verdict"], "unknown")
        self.assertEqual(
            data["intelligence"]["network"]["prefix"],
            "8.8.8.0/24"
        )

        mock_investigate.assert_called_once_with("8.8.8.8")

    @patch("services.intelligence.requests.get")
    def test_private_ip_not_queried(self, mock_get):
        response = self.client.post(
            "/api/investigate",
            json={"type": "ip", "value": "192.168.1.1"}
        )

        self.assertEqual(response.status_code, 200)

        data = response.get_json()

        self.assertEqual(data["intelligence_status"], "not_queried")
        self.assertEqual(data["verdict"], "unknown")

        mock_get.assert_not_called()

    @patch("app.investigate_ip")
    def test_intelligence_provider_unavailable(self, mock_investigate):
        mock_investigate.return_value = {
            "status": "unavailable",
            "message": "Network intelligence could not be retrieved.",
            "verdict": "unknown"
        }

        response = self.client.post(
            "/api/investigate",
            json={"type": "ip", "value": "8.8.8.8"}
        )

        self.assertEqual(response.status_code, 200)

        data = response.get_json()

        self.assertEqual(data["intelligence_status"], "unavailable")
        self.assertEqual(data["verdict"], "unknown")

    def test_valid_domain(self):
        response = self.client.post(
            "/api/investigate",
            json={"type": "domain", "value": "example.com"}
        )
        self.assertEqual(response.status_code, 200)

    def test_valid_sha256(self):
        response = self.client.post(
            "/api/investigate",
            json={"type": "sha256", "value": "a" * 64}
        )
        self.assertEqual(response.status_code, 200)

    def test_invalid_hash(self):
        response = self.client.post(
            "/api/investigate",
            json={"type": "sha256", "value": "invalid"}
        )
        self.assertEqual(response.status_code, 400)

    def test_missing_json(self):
        response = self.client.post(
            "/api/investigate",
            data="invalid",
            content_type="text/plain"
        )
        self.assertEqual(response.status_code, 415)

    def test_health_unchanged(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["version"],
            "1.1"
        )


if __name__ == "__main__":
    unittest.main()
