from pathlib import Path
import base64
import json
import unittest

from oss_sentinel.auth import GitHubAppCredentials, build_app_jwt
from oss_sentinel.config import Settings


class AuthTests(unittest.TestCase):
    def test_build_app_jwt_uses_expected_claims(self) -> None:
        token = build_app_jwt(
            "12345",
            Path("unused.pem"),
            now=1_700_000_000,
            signer=lambda _path, payload: b"signed:" + payload,
        )
        header_raw, payload_raw, signature_raw = token.split(".")
        header = self._decode_json(header_raw)
        payload = self._decode_json(payload_raw)
        self.assertEqual(header["alg"], "RS256")
        self.assertEqual(payload["iss"], "12345")
        self.assertEqual(payload["iat"], 1_699_999_940)
        self.assertEqual(payload["exp"], 1_700_000_480)
        self.assertTrue(self._decode_bytes(signature_raw).startswith(b"signed:"))

    def test_partial_app_settings_are_rejected(self) -> None:
        settings = Settings(
            github_token=None,
            github_app_id="1",
            github_app_private_key_path=None,
            github_app_installation_id=None,
            webhook_secret=None,
            dry_run=True,
            security_cmd=None,
            security_timeout=120,
            threat_model_path=Path("threat_model.json"),
            repo_config_path=None,
            host="127.0.0.1",
            port=8080,
            approve_label="security/approved",
            block_label="security/blocked",
            review_label="security/review",
            submit_reviews=False,
            comment_on_approval=False,
            github_api_url="https://api.github.com",
        )
        with self.assertRaises(RuntimeError):
            GitHubAppCredentials.from_settings(settings)

    @staticmethod
    def _decode_json(value: str) -> dict[str, object]:
        return json.loads(AuthTests._decode_bytes(value).decode("utf-8"))

    @staticmethod
    def _decode_bytes(value: str) -> bytes:
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(value + padding)


if __name__ == "__main__":
    unittest.main()

