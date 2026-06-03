from oss_sentinel.server import verify_signature
import hashlib
import hmac
import unittest


class ServerTests(unittest.TestCase):
    def test_signature_verification(self) -> None:
        secret = "abc"
        body = b'{"ok":true}'
        signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        self.assertTrue(verify_signature(secret, body, signature))
        self.assertFalse(verify_signature(secret, body, "sha256=bad"))

    def test_missing_secret_allows_local_dev(self) -> None:
        self.assertTrue(verify_signature(None, b"{}", None))


if __name__ == "__main__":
    unittest.main()

