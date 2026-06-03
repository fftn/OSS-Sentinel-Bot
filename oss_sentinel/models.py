from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


SEVERITY_RANK = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

REQUIRED_FINDING_FIELDS = {"severity", "category", "path", "message", "recommendation"}


def normalize_severity(value: str | None) -> str:
    severity = (value or "INFO").upper()
    if severity not in SEVERITY_RANK:
        return "INFO"
    return severity


def max_severity(values: list[str]) -> str:
    if not values:
        return "INFO"
    return max((normalize_severity(value) for value in values), key=lambda item: SEVERITY_RANK[item])


@dataclass
class Finding:
    severity: str
    category: str
    path: str
    message: str
    recommendation: str
    line: int | None = None
    evidence: str | None = None

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "severity": self.severity,
            "category": self.category,
            "path": self.path,
            "message": self.message,
            "recommendation": self.recommendation,
        }
        if self.line is not None:
            payload["line"] = self.line
        if self.evidence:
            payload["evidence"] = self.evidence
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Finding":
        return cls(
            severity=str(payload.get("severity", "INFO")),
            category=str(payload.get("category", "general")),
            path=str(payload.get("path", "")),
            line=payload.get("line"),
            message=str(payload.get("message", "")),
            recommendation=str(payload.get("recommendation", "")),
            evidence=payload.get("evidence"),
        )


@dataclass
class ScanReport:
    scanner: str
    summary: str
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: int = 1

    @property
    def max_severity(self) -> str:
        return max_severity([finding.severity for finding in self.findings])

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scanner": self.scanner,
            "summary": self.summary,
            "max_severity": self.max_severity,
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ScanReport":
        findings = [Finding.from_dict(item) for item in payload.get("findings", [])]
        return cls(
            schema_version=int(payload.get("schema_version", 1)),
            scanner=str(payload.get("scanner", "external")),
            summary=str(payload.get("summary", "")),
            findings=findings,
            metadata=dict(payload.get("metadata", {})),
        )


def validate_scan_report_payload(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["report must be a JSON object"]
    try:
        schema_version = int(payload.get("schema_version", 0) or 0)
    except (TypeError, ValueError):
        schema_version = 0
    if schema_version != 1:
        errors.append("schema_version must be 1")
    if not str(payload.get("scanner", "")).strip():
        errors.append("scanner is required")
    if not str(payload.get("summary", "")).strip():
        errors.append("summary is required")
    findings = payload.get("findings")
    if not isinstance(findings, list):
        errors.append("findings must be a list")
        return errors
    for index, item in enumerate(findings):
        if not isinstance(item, dict):
            errors.append(f"findings[{index}] must be an object")
            continue
        missing = sorted(REQUIRED_FINDING_FIELDS - set(item))
        if missing:
            errors.append(f"findings[{index}] missing required fields: {', '.join(missing)}")
        severity = str(item.get("severity", "")).upper()
        if severity not in SEVERITY_RANK:
            errors.append(f"findings[{index}].severity must be one of {', '.join(SEVERITY_RANK)}")
        line = item.get("line")
        if line is not None and not isinstance(line, int):
            errors.append(f"findings[{index}].line must be an integer when present")
    metadata = payload.get("metadata", {})
    if metadata is not None and not isinstance(metadata, dict):
        errors.append("metadata must be an object when present")
    return errors


@dataclass
class PullRequestFile:
    filename: str
    status: str = "modified"
    patch: str = ""
    additions: int = 0
    deletions: int = 0
    raw_url: str | None = None

    @classmethod
    def from_github(cls, payload: dict[str, Any]) -> "PullRequestFile":
        return cls(
            filename=str(payload.get("filename", "")),
            status=str(payload.get("status", "modified")),
            patch=str(payload.get("patch", "")),
            additions=int(payload.get("additions", 0)),
            deletions=int(payload.get("deletions", 0)),
            raw_url=payload.get("raw_url"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "status": self.status,
            "patch": self.patch,
            "additions": self.additions,
            "deletions": self.deletions,
            "raw_url": self.raw_url,
        }
