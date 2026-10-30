"""CI integration test: full secured HTTP regression probe against ephemeral app."""
import unittest
from scripts.http_security_probes import verify


class SecureHttpRegression(unittest.TestCase):
    def test_idor_injection_csrf_clickjacking_and_xss(self):
        verify()
