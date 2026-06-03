from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from oss_sentinel.models import Finding, ScanReport
from oss_sentinel.policy import decide
from oss_sentinel.repo_config import (
    load_repository_config,
    merge_config_into_threat_model,
    parse_simple_yaml,
)
from oss_sentinel.models import PullRequestFile
from oss_sentinel.scanner import scan_changed_files
from oss_sentinel.threat_model import default_threat_model


class RepositoryConfigTests(unittest.TestCase):
    def test_parse_simple_yaml_lists_and_maps(self) -> None:
        payload = parse_simple_yaml(
            """
ignore_paths:
  - "docs/generated/**"
security_critical_patterns:
  - glob: "src/auth/**"
    reason: "Auth changed"
policy:
  block_at: CRITICAL
  comment_on_approval: true
"""
        )
        self.assertEqual(payload["ignore_paths"], ["docs/generated/**"])
        self.assertEqual(payload["security_critical_patterns"][0]["glob"], "src/auth/**")
        self.assertEqual(payload["policy"]["block_at"], "CRITICAL")
        self.assertTrue(payload["policy"]["comment_on_approval"])

    def test_config_can_ignore_pr_paths(self) -> None:
        with TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "sentinel.yml"
            config_path.write_text(
                """
ignore_paths:
  - "fixtures/**"
""",
                encoding="utf-8",
            )
            repo_config = load_repository_config(config_path)
        threat_model = merge_config_into_threat_model(default_threat_model(), repo_config)
        report = scan_changed_files(
            [
                PullRequestFile(
                    filename="fixtures/.env",
                    patch="@@ -0,0 +1 @@\n+API_KEY=abc123abc123abc123\n",
                )
            ],
            threat_model,
        )
        self.assertEqual(report.max_severity, "INFO")

    def test_policy_thresholds_are_configurable(self) -> None:
        report = ScanReport(
            scanner="test",
            summary="high",
            findings=[
                Finding(
                    severity="HIGH",
                    category="test",
                    path="app.py",
                    message="high",
                    recommendation="fix",
                )
            ],
        )
        decision = decide(report, block_at="CRITICAL", review_at="MEDIUM")
        self.assertEqual(decision.action, "review")


if __name__ == "__main__":
    unittest.main()

