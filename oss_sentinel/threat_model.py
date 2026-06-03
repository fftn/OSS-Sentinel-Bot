from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import fnmatch
import json


SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    ".next",
    ".tox",
}

DEFAULT_SENSITIVE_PATHS = [
    ".env",
    ".env.*",
    "**/.env",
    "**/.env.*",
    "**/*secret*",
    "**/*token*",
    "**/*password*",
    "**/*.pem",
    "**/*.key",
    "**/id_rsa",
    "**/id_dsa",
]

DEFAULT_SECURITY_PATTERNS = [
    {"glob": "**/auth/**", "reason": "Authentication code changed"},
    {"glob": "**/*auth*", "reason": "Authentication code changed"},
    {"glob": "**/*login*", "reason": "Login flow changed"},
    {"glob": "**/*permission*", "reason": "Permission logic changed"},
    {"glob": "**/*parser*", "reason": "Parser logic changed"},
    {"glob": "**/*http*", "reason": "Network-facing logic changed"},
    {"glob": "**/*route*", "reason": "Request routing changed"},
    {"glob": "**/requirements*.txt", "reason": "Python dependency set changed"},
    {"glob": "**/package*.json", "reason": "Node dependency set changed"},
    {"glob": "**/go.mod", "reason": "Go dependency set changed"},
    {"glob": "**/Cargo.toml", "reason": "Rust dependency set changed"},
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def default_threat_model(repository: str | None = None) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "repository": repository,
        "generated_at": utc_now(),
        "entrypoints": [],
        "languages": {},
        "sensitive_paths": DEFAULT_SENSITIVE_PATHS,
        "security_critical_patterns": DEFAULT_SECURITY_PATTERNS,
        "notes": [
            "Generated baseline. Review sensitive_paths and security_critical_patterns before production use."
        ],
    }


def load_threat_model(path: Path) -> dict[str, Any]:
    if not path.exists():
        return default_threat_model()
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    baseline = default_threat_model(payload.get("repository"))
    baseline.update(payload)
    baseline.setdefault("sensitive_paths", DEFAULT_SENSITIVE_PATHS)
    baseline.setdefault("security_critical_patterns", DEFAULT_SECURITY_PATTERNS)
    return baseline


def write_threat_model(path: Path, model: dict[str, Any]) -> None:
    path.write_text(json.dumps(model, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def infer_entrypoint(path: Path) -> bool:
    lowered = "/".join(path.parts).lower()
    name = path.name.lower()
    return (
        name in {"app.py", "main.py", "server.py", "index.js", "server.js", "main.go", "main.rs"}
        or lowered.endswith("/cmd/server/main.go")
        or lowered.endswith("/src/main.rs")
    )


def detect_language(path: Path) -> str | None:
    suffix = path.suffix.lower()
    return {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".go": "go",
        ".rs": "rust",
        ".java": "java",
        ".rb": "ruby",
        ".php": "php",
        ".cs": "csharp",
        ".c": "c",
        ".cc": "cpp",
        ".cpp": "cpp",
    }.get(suffix)


def generate_threat_model(repo_path: Path, repository: str | None = None) -> dict[str, Any]:
    repo_path = repo_path.resolve()
    model = default_threat_model(repository)
    entrypoints: list[str] = []
    languages: dict[str, int] = {}
    critical_paths: set[str] = set()

    for path in repo_path.rglob("*"):
        rel = path.relative_to(repo_path)
        if should_skip(rel) or not path.is_file():
            continue
        rel_text = rel.as_posix()
        language = detect_language(path)
        if language:
            languages[language] = languages.get(language, 0) + 1
        if infer_entrypoint(rel):
            entrypoints.append(rel_text)
        lowered = rel_text.lower()
        if any(token in lowered for token in ("auth", "login", "permission", "parser", "route", "http")):
            critical_paths.add(rel_text)

    model["entrypoints"] = sorted(entrypoints)
    model["languages"] = dict(sorted(languages.items()))
    if critical_paths:
        model["observed_security_files"] = sorted(critical_paths)
    return model


def matches_any(path: str, patterns: list[str]) -> bool:
    normalized = path.replace("\\", "/")
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in patterns)

