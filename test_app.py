import unittest
from app import app

class AppTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_homepage(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"CyberSentinel", response.data)

    def test_health(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {"status": "healthy", "version": "1.1"}
        )

if __name__ == "__main__":
    unittest.main()
