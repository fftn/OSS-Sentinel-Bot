from dataclasses import replace
from pathlib import Path
import json
import sys
import unittest

from oss_sentinel.config import Settings
from oss_sentinel.server import handle_event


FIXTURES = Path(__file__).parent / "fixtures"


class IntegrationDecisionTests(unittest.TestCase):
    def test_clean_docs_pr_is_approved(self) -> None:
        result = handle_event("pull_request", self._payload("pr_clean_docs.json"), self._settings())
        self.assertEqual(result["status"], "processed")
        self.assertEqual(result["action"], "approve")
        self.assertEqual(result["max_severity"], "INFO")

    def test_dependency_pr_requires_review(self) -> None:
        result = handle_event("pull_request", self._payload("pr_dependency.json"), self._settings())
        self.assertEqual(result["status"], "processed")
        self.assertEqual(result["action"], "review")
        self.assertEqual(result["max_severity"], "MEDIUM")

    def test_external_scanner_failure_blocks_security_sensitive_pr(self) -> None:
        settings = replace(self._settings(), security_cmd="/definitely/missing/oss-sentinel-scanner")
        result = handle_event("pull_request", self._payload("pr_auth_change.json"), settings)
        self.assertEqual(result["status"], "processed")
        self.assertEqual(result["action"], "block")
        self.assertEqual(result["max_severity"], "HIGH")

    def test_external_scanner_result_blocks_security_sensitive_pr(self) -> None:
        settings = replace(
            self._settings(),
            security_cmd=f"{sys.executable} -m oss_sentinel.adapters.rule_based",
        )
        result = handle_event("pull_request", self._payload("pr_auth_change.json"), settings)
        self.assertEqual(result["status"], "processed")
        self.assertEqual(result["action"], "block")
        self.assertEqual(result["max_severity"], "HIGH")

    @staticmethod
    def _payload(name: str) -> dict[str, object]:
        return json.loads((FIXTURES / name).read_text(encoding="utf-8"))

    @staticmethod
    def _settings() -> Settings:
        return Settings(
            github_token=None,
            github_app_id=None,
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


if __name__ == "__main__":
    unittest.main()
