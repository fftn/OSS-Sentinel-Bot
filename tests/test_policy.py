from oss_sentinel.models import Finding, ScanReport
from oss_sentinel.policy import decide
import unittest


class PolicyTests(unittest.TestCase):
    def test_high_blocks(self) -> None:
        report = ScanReport(
            scanner="test",
            summary="bad",
            findings=[
                Finding(
                    severity="HIGH",
                    category="secret",
                    path=".env",
                    message="secret",
                    recommendation="remove",
                )
            ],
        )
        decision = decide(report)
        self.assertEqual(decision.action, "block")
        self.assertTrue(decision.request_changes)

    def test_clean_approves(self) -> None:
        report = ScanReport(scanner="test", summary="clean", findings=[])
        decision = decide(report)
        self.assertEqual(decision.action, "approve")
        self.assertFalse(decision.comment)


if __name__ == "__main__":
    unittest.main()

