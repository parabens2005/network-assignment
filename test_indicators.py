import unittest
from app import app


class IndicatorAPITests(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_valid_ip(self):
        response = self.client.post(
            "/api/investigate",
            json={"type": "ip", "value": "8.8.8.8"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["status"],
            "validated"
        )

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
