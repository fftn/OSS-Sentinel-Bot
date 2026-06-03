from pathlib import Path
import json
import sys
import unittest

from oss_sentinel.adapters.rule_based import analyze
from oss_sentinel.models import PullRequestFile, validate_scan_report_payload
from oss_sentinel.scanner import run_external_security_cmd, scan_changed_files
from oss_sentinel.threat_model import default_threat_model


FIXTURES = Path(__file__).parent / "fixtures"


class ExternalAdapterTests(unittest.TestCase):
    def test_rule_based_adapter_detects_ssrf_pattern(self) -> None:
        payload = self._scanner_payload("pr_auth_change.json")
        report = analyze(payload)
        self.assertEqual(report.max_severity, "HIGH")
        self.assertTrue(any(finding.category == "ssrf" for finding in report.findings))
        self.assertEqual(validate_scan_report_payload(report.to_dict()), [])

    def test_rule_based_adapter_accepts_pr_fixture_shape(self) -> None:
        payload = json.loads((FIXTURES / "pr_auth_change.json").read_text(encoding="utf-8"))
        report = analyze(payload)
        self.assertEqual(report.max_severity, "HIGH")

    def test_invalid_external_report_becomes_scanner_error(self) -> None:
        files = [
            PullRequestFile(
                filename="src/auth/callback.py",
                patch="@@ -1 +1 @@\n+return requests.get(next_url).text\n",
            )
        ]
        fallback = scan_changed_files(files, default_threat_model())
        report = run_external_security_cmd(
            f"{sys.executable} -c \"print('{{}}')\"",
            {"files": [item.to_dict() for item in files]},
            30,
            fallback,
        )
        self.assertEqual(report.max_severity, "HIGH")
        self.assertTrue(any(finding.category == "scanner-error" for finding in report.findings))

    def test_contract_validation_rejects_bad_schema_version(self) -> None:
        errors = validate_scan_report_payload(
            {
                "schema_version": "bad",
                "scanner": "test",
                "summary": "bad",
                "findings": [],
                "metadata": {},
            }
        )
        self.assertIn("schema_version must be 1", errors)

    @staticmethod
    def _scanner_payload(name: str) -> dict[str, object]:
        fixture = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
        return {
            "schema_version": 1,
            "context": {"repository": fixture["repository"]["full_name"]},
            "threat_model": default_threat_model(),
            "files": fixture["sentinel"]["files"],
            "builtin_report": {},
        }


if __name__ == "__main__":
    unittest.main()
