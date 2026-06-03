from oss_sentinel.models import PullRequestFile
from oss_sentinel.scanner import added_lines, scan_changed_files
from oss_sentinel.threat_model import default_threat_model
import unittest


class ScannerTests(unittest.TestCase):
    def test_added_lines_tracks_new_line_numbers(self) -> None:
        patch = "@@ -1,2 +1,3 @@\n old\n+new_secret = 'x'\n unchanged\n"
        self.assertEqual(list(added_lines(patch)), [(2, "new_secret = 'x'")])

    def test_secret_filename_blocks(self) -> None:
        report = scan_changed_files(
            [PullRequestFile(filename=".env", patch="@@ -0,0 +1 @@\n+TOKEN=abc123abc123abc123\n")],
            default_threat_model(),
        )
        self.assertEqual(report.max_severity, "HIGH")
        self.assertTrue(any(item.category == "sensitive-path" for item in report.findings))

    def test_eval_is_high(self) -> None:
        report = scan_changed_files(
            [PullRequestFile(filename="app.py", patch="@@ -1 +1 @@\n+result = eval(user_input)\n")],
            default_threat_model(),
        )
        self.assertEqual(report.max_severity, "HIGH")
        self.assertTrue(any(item.category == "code-injection" for item in report.findings))

    def test_env_example_is_not_sensitive_path(self) -> None:
        report = scan_changed_files(
            [PullRequestFile(filename=".env.example", patch="@@ -0,0 +1 @@\n+APP_ENV=dev\n")],
            default_threat_model(),
        )
        self.assertEqual(report.max_severity, "INFO")


if __name__ == "__main__":
    unittest.main()
