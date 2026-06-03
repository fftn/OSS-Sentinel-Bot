from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
import json

from .models import ScanReport
from .policy import Decision


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def build_audit_record(
    context: dict[str, Any],
    decision: Decision,
    report: ScanReport,
    dry_run: bool,
) -> dict[str, Any]:
    return {
        "created_at": utc_now(),
        "event": context.get("event"),
        "repository": context.get("repository"),
        "pull_number": context.get("pull_number"),
        "pull_title": context.get("title"),
        "actor": context.get("actor"),
        "base_ref": context.get("base_ref"),
        "head_ref": context.get("head_ref"),
        "dry_run": dry_run,
        "decision": {
            "action": decision.action,
            "label": decision.label,
            "title": decision.title,
            "request_changes": decision.request_changes,
            "comment": decision.comment,
        },
        "report": {
            "scanner": report.scanner,
            "summary": report.summary,
            "max_severity": report.max_severity,
            "findings": [sanitize_finding(finding.to_dict()) for finding in report.findings],
        },
    }


def sanitize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    sanitized = dict(finding)
    sanitized.pop("evidence", None)
    return sanitized


def append_audit_record(path: Path | None, record: dict[str, Any]) -> None:
    if path is None:
        return
    if path.parent and str(path.parent) != ".":
        path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def read_audit_records(
    path: Path,
    limit: int | None = None,
    repository: str | None = None,
    action: str | None = None,
) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records = [
        record
        for record in _iter_audit_records(path)
        if (repository is None or record.get("repository") == repository)
        and (action is None or record.get("decision", {}).get("action") == action)
    ]
    if limit is not None and limit >= 0:
        records = records[-limit:]
    return records


def _iter_audit_records(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL audit record at {path}:{line_no}: {exc}") from exc
            if not isinstance(payload, dict):
                raise ValueError(f"Invalid JSONL audit record at {path}:{line_no}: expected object")
            yield payload

