from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable
import fnmatch
import json
import re
import shlex
import subprocess

from .models import Finding, PullRequestFile, SEVERITY_RANK, ScanReport
from .threat_model import SKIP_DIRS, matches_any


TEXT_FILE_LIMIT_BYTES = 1024 * 1024
RELEASE_SKIP_DIRS = SKIP_DIRS | {"test", "tests", "fixtures", "examples"}
RELEASE_SKIP_FILES = {"security_report.json", "threat_model.json", "RELEASE_NOTES.md"}

SENSITIVE_NAME_EXEMPTIONS = (
    ".example",
    ".sample",
    ".template",
    ".dist",
)

DEPENDENCY_FILES = {
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "poetry.lock",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
}

LINE_RULES: list[tuple[re.Pattern[str], str, str, str, str]] = [
    (
        re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |)PRIVATE KEY-----"),
        "CRITICAL",
        "secret-exposure",
        "A private key appears to be added.",
        "Remove the key from the repository and rotate the credential.",
    ),
    (
        re.compile(
            r"(?i)\b(?:aws_access_key_id|aws_secret_access_key|api[_-]?key|client_secret|"
            r"private[_-]?key|password|passwd|token)\b\s*[:=]\s*[\"']?[A-Za-z0-9_./+=:-]{12,}"
        ),
        "HIGH",
        "secret-exposure",
        "A likely hard-coded credential appears in an added line.",
        "Move secrets to a secret manager or CI secret store and rotate exposed values.",
    ),
    (
        re.compile(r"\beval\s*\("),
        "HIGH",
        "code-injection",
        "Dynamic eval was added.",
        "Replace eval with explicit parsing or a safe expression evaluator.",
    ),
    (
        re.compile(r"\bexec\s*\("),
        "HIGH",
        "code-injection",
        "Dynamic exec was added.",
        "Remove dynamic code execution or strictly validate the executed source.",
    ),
    (
        re.compile(r"\bos\.system\s*\("),
        "HIGH",
        "command-injection",
        "Shell command execution was added through os.system.",
        "Use subprocess with argument arrays and avoid shell interpolation.",
    ),
    (
        re.compile(r"subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True"),
        "HIGH",
        "command-injection",
        "A subprocess call with shell=True was added.",
        "Pass arguments as a list and keep shell=False unless there is a documented need.",
    ),
    (
        re.compile(r"\bpickle\.loads?\s*\("),
        "HIGH",
        "unsafe-deserialization",
        "Pickle deserialization was added.",
        "Do not unpickle untrusted data; use JSON or a constrained serializer.",
    ),
    (
        re.compile(r"\byaml\.load\s*\("),
        "HIGH",
        "unsafe-deserialization",
        "yaml.load was added.",
        "Use yaml.safe_load unless the source is fully trusted and documented.",
    ),
    (
        re.compile(r"verify\s*=\s*False"),
        "MEDIUM",
        "tls-disabled",
        "TLS certificate verification appears to be disabled.",
        "Keep certificate verification enabled or pin a trusted CA bundle.",
    ),
    (
        re.compile(r"ssl\._create_unverified_context\s*\("),
        "MEDIUM",
        "tls-disabled",
        "An unverified TLS context was added.",
        "Use the default verified SSL context.",
    ),
    (
        re.compile(r"(?i)\bselect\b.+(?:\+|%|\.format\(|f[\"'])"),
        "HIGH",
        "sql-injection",
        "SQL construction with string interpolation was added.",
        "Use parameterized queries from the database driver.",
    ),
    (
        re.compile(r"\bdangerouslySetInnerHTML\b|\.innerHTML\s*="),
        "MEDIUM",
        "xss",
        "Raw HTML injection was added.",
        "Sanitize content with a reviewed sanitizer or render text nodes.",
    ),
    (
        re.compile(r"\brequests\.(?:get|post|put|patch|delete)\s*\(|\bfetch\s*\("),
        "MEDIUM",
        "network-boundary",
        "Network request code was added.",
        "Validate URLs, timeouts, redirects, and trust boundaries.",
    ),
]

DEEP_SCAN_HINTS = [
    "auth",
    "login",
    "permission",
    "jwt",
    "oauth",
    "parser",
    "parse",
    "request",
    "http",
    "url",
    "webhook",
    "unsafe",
    "eval",
    "exec",
]


def added_lines(patch: str) -> Iterable[tuple[int | None, str]]:
    new_line_no: int | None = None
    for raw_line in patch.splitlines():
        if raw_line.startswith("@@"):
            match = re.search(r"\+(\d+)(?:,\d+)?", raw_line)
            new_line_no = int(match.group(1)) if match else None
            continue
        if raw_line.startswith("+++") or raw_line.startswith("---"):
            continue
        if raw_line.startswith("+"):
            yield new_line_no, raw_line[1:]
            if new_line_no is not None:
                new_line_no += 1
            continue
        if raw_line.startswith("-"):
            continue
        if new_line_no is not None:
            new_line_no += 1


def is_sensitive_filename(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    if is_sensitive_filename_exempt(path):
        return False
    if name in {".env", "id_rsa", "id_dsa"}:
        return True
    if any(token in name for token in ("secret", "password", "token")):
        return True
    return any(
        fnmatch.fnmatch(normalized, pattern)
        for pattern in ("**/*.pem", "**/*.key", "**/*secret*", "**/*password*", "**/*token*")
    )


def is_sensitive_filename_exempt(path: str) -> bool:
    name = path.replace("\\", "/").lower().rsplit("/", 1)[-1]
    return name.endswith(SENSITIVE_NAME_EXEMPTIONS)


def dependency_file(path: str) -> bool:
    return path.replace("\\", "/").rsplit("/", 1)[-1] in DEPENDENCY_FILES


def scan_line(path: str, line_no: int | None, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for pattern, severity, category, message, recommendation in LINE_RULES:
        if pattern.search(text):
            findings.append(
                Finding(
                    severity=severity,
                    category=category,
                    path=path,
                    line=line_no,
                    message=message,
                    recommendation=recommendation,
                    evidence=text.strip()[:180],
                )
            )
    return findings


def scan_changed_files(files: list[PullRequestFile], threat_model: dict[str, Any]) -> ScanReport:
    findings: list[Finding] = []
    sensitive_paths = list(threat_model.get("sensitive_paths", []))
    critical_patterns = list(threat_model.get("security_critical_patterns", []))
    ignored_paths = list(threat_model.get("ignored_paths", []))

    for item in files:
        path = item.filename
        if matches_any(path, ignored_paths):
            continue
        if not is_sensitive_filename_exempt(path) and (
            is_sensitive_filename(path) or matches_any(path, sensitive_paths)
        ):
            findings.append(
                Finding(
                    severity="HIGH",
                    category="sensitive-path",
                    path=path,
                    message="A sensitive path or credential-like filename changed.",
                    recommendation="Confirm no secret material is committed and require maintainer review.",
                )
            )
        for rule in critical_patterns:
            glob = str(rule.get("glob", ""))
            if glob and fnmatch.fnmatch(path.replace("\\", "/"), glob):
                findings.append(
                    Finding(
                        severity="MEDIUM",
                        category="security-critical-area",
                        path=path,
                        message=str(rule.get("reason", "Security-critical file changed.")),
                        recommendation="Run a deeper security review before merging.",
                    )
                )
                break
        if dependency_file(path):
            findings.append(
                Finding(
                    severity="MEDIUM",
                    category="dependency-change",
                    path=path,
                    message="Dependency metadata changed.",
                    recommendation="Check advisory status and verify that lockfile changes match the intended upgrade.",
                )
            )
        for line_no, text in added_lines(item.patch):
            findings.extend(scan_line(path, line_no, text))

    summary = "No security-sensitive changes detected."
    if findings:
        summary = f"Detected {len(findings)} security-relevant finding(s)."
    return ScanReport(scanner="builtin-heuristic", summary=summary, findings=findings)


def report_from_external(payload: dict[str, Any]) -> ScanReport:
    return ScanReport.from_dict(payload)


def should_run_deep_scan(files: list[PullRequestFile], built_in_report: ScanReport) -> bool:
    if SEVERITY_RANK[built_in_report.max_severity] >= SEVERITY_RANK["MEDIUM"]:
        return True
    joined = "\n".join([item.filename + "\n" + item.patch for item in files]).lower()
    return any(hint in joined for hint in DEEP_SCAN_HINTS)


def run_external_security_cmd(
    command: str,
    input_payload: dict[str, Any],
    timeout: int,
    fallback_report: ScanReport,
) -> ScanReport:
    args = shlex.split(command)
    try:
        completed = subprocess.run(
            args,
            input=json.dumps(input_payload),
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except Exception as exc:
        fallback_report.findings.append(
            Finding(
                severity="HIGH",
                category="scanner-error",
                path="",
                message=f"External security scanner failed before producing a report: {exc}",
                recommendation="Treat the PR as blocked until the scanner can run successfully.",
            )
        )
        fallback_report.metadata["external_scanner_error"] = str(exc)
        return fallback_report

    if completed.returncode != 0:
        fallback_report.findings.append(
            Finding(
                severity="HIGH",
                category="scanner-error",
                path="",
                message=f"External security scanner exited with status {completed.returncode}.",
                recommendation="Treat the PR as blocked until the scanner can run successfully.",
                evidence=(completed.stderr or completed.stdout).strip()[:180],
            )
        )
        fallback_report.metadata["external_scanner_returncode"] = completed.returncode
        return fallback_report

    try:
        report = report_from_external(json.loads(completed.stdout))
    except json.JSONDecodeError as exc:
        fallback_report.findings.append(
            Finding(
                severity="HIGH",
                category="scanner-error",
                path="",
                message=f"External security scanner returned invalid JSON: {exc}",
                recommendation="Fix the scanner adapter so it emits the documented ScanReport schema.",
                evidence=completed.stdout.strip()[:180],
            )
        )
        return fallback_report

    report.metadata.setdefault("builtin_report", fallback_report.to_dict())
    return report


def run_security_analysis(
    files: list[PullRequestFile],
    threat_model: dict[str, Any],
    security_cmd: str | None = None,
    security_timeout: int = 120,
    context: dict[str, Any] | None = None,
) -> ScanReport:
    built_in_report = scan_changed_files(files, threat_model)
    if not security_cmd or not should_run_deep_scan(files, built_in_report):
        return built_in_report
    payload = {
        "schema_version": 1,
        "context": context or {},
        "threat_model": threat_model,
        "files": [item.to_dict() for item in files],
        "builtin_report": built_in_report.to_dict(),
    }
    return run_external_security_cmd(security_cmd, payload, security_timeout, built_in_report)


def scan_repository_path(
    repo_path: Path,
    threat_model: dict[str, Any],
    include_tests: bool = False,
) -> ScanReport:
    repo_path = repo_path.resolve()
    findings: list[Finding] = []
    skip_dirs = SKIP_DIRS if include_tests else RELEASE_SKIP_DIRS
    ignored_paths = [
        *list(threat_model.get("ignored_paths", [])),
        *list(threat_model.get("release_ignored_paths", [])),
    ]
    for path in repo_path.rglob("*"):
        rel = path.relative_to(repo_path)
        if any(part in skip_dirs for part in rel.parts) or not path.is_file():
            continue
        if rel.name in RELEASE_SKIP_FILES:
            continue
        rel_text = rel.as_posix()
        if matches_any(rel_text, ignored_paths):
            continue
        if path.stat().st_size > TEXT_FILE_LIMIT_BYTES:
            continue
        if is_sensitive_filename(rel_text):
            findings.append(
                Finding(
                    severity="HIGH",
                    category="sensitive-path",
                    path=rel_text,
                    message="A sensitive path or credential-like filename exists in the release tree.",
                    recommendation="Remove secret material before publishing.",
                )
            )
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for index, line in enumerate(content.splitlines(), start=1):
            findings.extend(scan_line(rel_text, index, line))
    summary = "No release-blocking security patterns detected."
    if findings:
        summary = f"Detected {len(findings)} release audit finding(s)."
    return ScanReport(scanner="builtin-release-audit", summary=summary, findings=findings)
