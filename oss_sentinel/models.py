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

