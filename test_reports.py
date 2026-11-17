import unittest
from unittest.mock import patch

from app import app


class PDFReportTests(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_private_ip_report(self):
        response = self.client.post(
            "/api/report",
            json={
                "type": "ip",
                "value": "192.168.1.1"
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/pdf")
        self.assertTrue(response.data.startswith(b"%PDF-"))

    def test_missing_json(self):
        response = self.client.post(
            "/api/report",
            data="not json",
            content_type="text/plain"
        )

        self.assertEqual(response.status_code, 415)

    def test_invalid_hash(self):
        response = self.client.post(
            "/api/report",
            json={
                "type": "sha256",
                "value": "invalid-hash"
            }
        )

        self.assertEqual(response.status_code, 400)

    @patch("app.investigate_hash")
    def test_hash_report(self, mock_investigate):
        mock_investigate.return_value = {
            "status": "completed",
            "message": "Mocked reputation lookup.",
            "reputation": {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 60
            },
            "source": {
                "provider": "VirusTotal"
            }
        }

        response = self.client.post(
            "/api/report",
            json={
                "type": "sha256",
                "value": "a" * 64
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data.startswith(b"%PDF-"))
        mock_investigate.assert_called_once()


if __name__ == "__main__":
    unittest.main()
