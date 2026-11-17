import os
import unittest
from unittest.mock import patch

from services.intelligence import investigate_hash


class CloudRunSafetyTests(unittest.TestCase):

    def test_virustotal_disabled_on_cloud_run(self):
        test_hash = "a" * 64

        with patch.dict(os.environ, {
            "K_SERVICE": "cybersecurity-webapp",
            "CYBERSENTINEL_ALLOW_VT_CLOUD_RUN": "0",
            "VIRUSTOTAL_API_KEY": "test-key"
        }):
            with patch("services.intelligence.requests.get") as mock_get:
                result = investigate_hash(test_hash)

                self.assertEqual(result["status"], "not_configured")
                mock_get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
