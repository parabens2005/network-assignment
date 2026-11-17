import unittest

from flask import Flask, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


class RateLimitingTests(unittest.TestCase):

    def test_investigation_rate_limit(self):
        # Isolated application with rate limiting enabled.
        test_app = Flask(__name__)
        test_app.config["RATELIMIT_ENABLED"] = True

        limiter = Limiter(
            key_func=get_remote_address,
            app=test_app,
            default_limits=[],
            storage_uri="memory://"
        )

        @test_app.route("/test-investigate", methods=["POST"])
        @limiter.limit("2 per minute")
        def investigate():
            return jsonify(status="completed")

        client = test_app.test_client()
        responses = []

        for _ in range(4):
            response = client.post(
                "/test-investigate",
                environ_overrides={
                    "REMOTE_ADDR": "198.51.100.88"
                }
            )
            responses.append(response.status_code)

        self.assertEqual(responses, [200, 200, 429, 429])


if __name__ == "__main__":
    unittest.main()
