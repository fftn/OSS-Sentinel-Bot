from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import json

from .models import SEVERITY_RANK


DEFAULT_CONFIG_PATHS = (
    "sentinel.yml",
    "sentinel.yaml",
    ".oss-sentinel.yml",
    ".oss-sentinel.yaml",
    "sentinel.json",
)


@dataclass(frozen=True)
class RepositoryConfig:
    ignore_paths: list[str] = field(default_factory=list)
    sensitive_paths: list[str] = field(default_factory=list)
    security_critical_patterns: list[dict[str, str]] = field(default_factory=list)
    release_ignore_paths: list[str] = field(default_factory=list)
    block_at: str = "HIGH"
    review_at: str = "MEDIUM"
    approve_label: str | None = None
    block_label: str | None = None
    review_label: str | None = None
    comment_on_approval: bool | None = None

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RepositoryConfig":
        policy = _dict(payload.get("policy"))
        labels = _dict(payload.get("labels"))
        release = _dict(payload.get("release"))
        return cls(
            ignore_paths=_string_list(payload.get("ignore_paths")),
            sensitive_paths=_string_list(payload.get("sensitive_paths")),
            security_critical_patterns=_critical_patterns(payload.get("security_critical_patterns")),
            release_ignore_paths=_string_list(release.get("ignore_paths")),
            block_at=_severity_setting(policy.get("block_at", "HIGH"), "policy.block_at"),
            review_at=_severity_setting(policy.get("review_at", "MEDIUM"), "policy.review_at"),
            approve_label=_optional_string(labels.get("approve")),
            block_label=_optional_string(labels.get("block")),
            review_label=_optional_string(labels.get("review")),
            comment_on_approval=_optional_bool(policy.get("comment_on_approval")),
        )


def _dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    raise ValueError(f"Expected boolean value, got {value!r}")


def _severity_setting(value: Any, name: str) -> str:
    severity = str(value).strip().upper()
    if severity not in SEVERITY_RANK:
        raise ValueError(f"{name} must be one of {', '.join(SEVERITY_RANK)}")
    return severity


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"Expected a list, got {type(value).__name__}")
    return [str(item) for item in value if str(item).strip()]


def _critical_patterns(value: Any) -> list[dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("security_critical_patterns must be a list")
    patterns: list[dict[str, str]] = []
    for item in value:
        if isinstance(item, str):
            patterns.append({"glob": item, "reason": "Configured security-critical path changed"})
            continue
        if not isinstance(item, dict):
            raise ValueError("security_critical_patterns items must be strings or maps")
        glob = str(item.get("glob", "")).strip()
        if not glob:
            raise ValueError("security_critical_patterns items require glob")
        patterns.append(
            {
                "glob": glob,
                "reason": str(item.get("reason", "Configured security-critical path changed")),
            }
        )
    return patterns


def find_config_path(start: Path = Path(".")) -> Path | None:
    for name in DEFAULT_CONFIG_PATHS:
        candidate = start / name
        if candidate.exists():
            return candidate
    return None


def load_repository_config(path: Path | None = None) -> RepositoryConfig:
    actual = path if path is not None else find_config_path()
    if actual is None or not actual.exists():
        return RepositoryConfig()
    if actual.suffix.lower() == ".json":
        payload = json.loads(actual.read_text(encoding="utf-8"))
    else:
        payload = parse_simple_yaml(actual.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{actual} must contain a mapping at the top level")
    return RepositoryConfig.from_dict(payload)


def merge_config_into_threat_model(
    threat_model: dict[str, Any],
    repo_config: RepositoryConfig,
) -> dict[str, Any]:
    merged = dict(threat_model)
    merged["ignored_paths"] = _dedupe([*list(merged.get("ignored_paths", [])), *repo_config.ignore_paths])
    merged["release_ignored_paths"] = _dedupe(
        [*list(merged.get("release_ignored_paths", [])), *repo_config.release_ignore_paths]
    )
    merged["sensitive_paths"] = _dedupe(
        [*list(merged.get("sensitive_paths", [])), *repo_config.sensitive_paths]
    )
    merged["security_critical_patterns"] = [
        *list(merged.get("security_critical_patterns", [])),
        *repo_config.security_critical_patterns,
    ]
    return merged


def _dedupe(values: list[Any]) -> list[Any]:
    seen: set[str] = set()
    result: list[Any] = []
    for value in values:
        key = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def parse_simple_yaml(text: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    current_key: str | None = None
    current_child_key: str | None = None
    current_item: dict[str, Any] | None = None

    for raw_line in text.splitlines():
        line = _strip_comment(raw_line.rstrip())
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()

        if indent == 0:
            key, value = _split_key_value(stripped)
            root[key] = _parse_scalar(value) if value is not None else None
            current_key = key if value is None else None
            current_child_key = None
            current_item = None
            continue

        if current_key is None:
            raise ValueError(f"Unexpected indented line without a parent key: {raw_line!r}")

        if indent == 2 and stripped.startswith("- "):
            if root[current_key] is None:
                root[current_key] = []
            if not isinstance(root[current_key], list):
                raise ValueError(f"{current_key} cannot mix list and map values")
            item_text = stripped[2:].strip()
            if _looks_like_key_value(item_text):
                key, value = _split_key_value(item_text)
                current_item = {key: _parse_scalar(value)}
                root[current_key].append(current_item)
            else:
                current_item = None
                root[current_key].append(_parse_scalar(item_text))
            current_child_key = None
            continue

        if indent == 2:
            if root[current_key] is None:
                root[current_key] = {}
            if not isinstance(root[current_key], dict):
                raise ValueError(f"{current_key} cannot mix map and list values")
            key, value = _split_key_value(stripped)
            root[current_key][key] = _parse_scalar(value)
            current_child_key = key if value is None else None
            current_item = None
            continue

        if indent == 4 and current_child_key is not None:
            parent = root[current_key]
            if not isinstance(parent, dict):
                raise ValueError(f"{current_key} cannot contain nested list values")
            if stripped.startswith("- "):
                if parent[current_child_key] is None:
                    parent[current_child_key] = []
                if not isinstance(parent[current_child_key], list):
                    raise ValueError(f"{current_key}.{current_child_key} cannot mix list and scalar values")
                item_text = stripped[2:].strip()
                if _looks_like_key_value(item_text):
                    key, value = _split_key_value(item_text)
                    current_item = {key: _parse_scalar(value)}
                    parent[current_child_key].append(current_item)
                else:
                    current_item = None
                    parent[current_child_key].append(_parse_scalar(item_text))
                continue
            key, value = _split_key_value(stripped)
            if parent[current_child_key] is None:
                parent[current_child_key] = {}
            if not isinstance(parent[current_child_key], dict):
                raise ValueError(f"{current_key}.{current_child_key} cannot mix map and list values")
            parent[current_child_key][key] = _parse_scalar(value)
            continue

        if indent >= 4 and current_item is not None:
            key, value = _split_key_value(stripped)
            current_item[key] = _parse_scalar(value)
            continue

        raise ValueError(f"Unsupported YAML shape near line: {raw_line!r}")

    return root


def _strip_comment(line: str) -> str:
    in_single = False
    in_double = False
    for index, char in enumerate(line):
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            return line[:index].rstrip()
    return line


def _looks_like_key_value(text: str) -> bool:
    return ":" in text and not text.startswith(("'", '"'))


def _split_key_value(text: str) -> tuple[str, str | None]:
    if ":" not in text:
        raise ValueError(f"Expected key/value line, got {text!r}")
    key, value = text.split(":", 1)
    key = key.strip()
    if not key:
        raise ValueError(f"Empty key in {text!r}")
    value = value.strip()
    return key, value if value else None


def _parse_scalar(value: str | None) -> Any:
    if value is None:
        return None
    lowered = value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if lowered in {"null", "none", "~"}:
        return None
    if value in {"[]", "{}"}:
        return json.loads(value)
    if value.startswith(('"', "'", "[", "{")):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            if value.startswith("'") and value.endswith("'"):
                return value[1:-1]
            raise
    if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
        return int(value)
    return value
