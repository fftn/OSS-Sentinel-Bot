from __future__ import annotations

from typing import Any
import json
import sys

from ..models import Finding, PullRequestFile, ScanReport
from ..scanner import added_lines


SSRF_CALL_HINTS = (
    ("requests.", "get("),
    ("requests.", "post("),
    ("fetch", "("),
    ("urllib.request.", "urlopen("),
)
AUTH_BYPASS_HINTS = ("is_admin = true", "skip_auth", "disable_auth", "allow_all")
SQL_HINTS = ("execute(f\"", "execute(\"select", "rawsql", "raw_sql")


def analyze(payload: dict[str, Any]) -> ScanReport:
    files_payload = payload.get("files")
    if files_payload is None:
        files_payload = payload.get("sentinel", {}).get("files", [])
    files = [PullRequestFile.from_github(item) for item in files_payload]
    findings: list[Finding] = []
    for item in files:
        lowered_path = item.filename.lower()
        for line_no, text in added_lines(item.patch):
            lowered = text.lower()
            if any(all(part in lowered for part in hint) for hint in SSRF_CALL_HINTS) and any(
                token in lowered for token in ("url", "next", "redirect", "callback", "webhook")
            ):
                findings.append(
                    Finding(
                        severity="HIGH",
                        category="ssrf",
                        path=item.filename,
                        line=line_no,
                        message="Network request appears to use attacker-influenced URL material.",
                        recommendation="Validate the destination host against an allowlist and disable unsafe redirects.",
                        evidence=text.strip()[:180],
                    )
                )
            if "auth" in lowered_path and any(hint in lowered for hint in AUTH_BYPASS_HINTS):
                findings.append(
                    Finding(
                        severity="HIGH",
                        category="authz",
                        path=item.filename,
                        line=line_no,
                        message="Authentication or authorization bypass marker was added.",
                        recommendation="Require an explicit maintainer review and remove bypass behavior.",
                        evidence=text.strip()[:180],
                    )
                )
            if any(hint in lowered for hint in SQL_HINTS) and any(op in text for op in ("+", "%", "{")):
                findings.append(
                    Finding(
                        severity="HIGH",
                        category="injection",
                        path=item.filename,
                        line=line_no,
                        message="Raw SQL construction appears to include interpolation.",
                        recommendation="Use parameterized queries and keep SQL fragments separate from user input.",
                        evidence=text.strip()[:180],
                    )
                )
    if findings:
        summary = f"Rule-based adapter found {len(findings)} deep-review finding(s)."
    else:
        summary = "Rule-based adapter found no additional deep-review findings."
    return ScanReport(
        scanner="rule-based-adapter",
        summary=summary,
        findings=findings,
        metadata={"adapter": "oss_sentinel.adapters.rule_based"},
    )


def main() -> int:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        report = analyze(payload)
    except Exception as exc:
        report = ScanReport(
            scanner="rule-based-adapter",
            summary="Rule-based adapter failed.",
            findings=[
                Finding(
                    severity="HIGH",
                    category="scanner-error",
                    path="",
                    message=f"Rule-based adapter failed: {exc}",
                    recommendation="Fix the scanner adapter input or disable the adapter until it is healthy.",
                )
            ],
        )
    sys.stdout.write(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
