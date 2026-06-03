from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from oss_sentinel.audit import append_audit_record, build_audit_record, read_audit_records
from oss_sentinel.models import Finding, ScanReport
from oss_sentinel.policy import Decision


class AuditTests(unittest.TestCase):
    def test_build_record_does_not_include_finding_evidence(self) -> None:
        record = build_audit_record(
            {
                "event": "pull_request",
                "repository": "owner/repo",
                "pull_number": 7,
                "title": "Secret",
                "actor": "contributor",
            },
            Decision(
                action="block",
                label="security/blocked",
                title="Security risk blocked",
                request_changes=True,
                comment=True,
            ),
            ScanReport(
                scanner="test",
                summary="secret",
                findings=[
                    Finding(
                        severity="HIGH",
                        category="secret-exposure",
                        path=".env",
                        message="secret",
                        recommendation="remove",
                        evidence="API_KEY=abc123abc123abc123",
                    )
                ],
            ),
            dry_run=True,
        )
        finding = record["report"]["findings"][0]
        self.assertNotIn("evidence", finding)
        self.assertEqual(record["decision"]["action"], "block")

    def test_append_and_read_records_with_filters(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            append_audit_record(path, {"repository": "owner/repo", "decision": {"action": "block"}})
            append_audit_record(path, {"repository": "other/repo", "decision": {"action": "approve"}})
            records = read_audit_records(path, repository="owner/repo", action="block")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["repository"], "owner/repo")


if __name__ == "__main__":
    unittest.main()

