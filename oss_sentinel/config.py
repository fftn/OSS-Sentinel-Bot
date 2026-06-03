from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os


def env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


@dataclass(frozen=True)
class Settings:
    github_token: str | None
    webhook_secret: str | None
    dry_run: bool
    security_cmd: str | None
    security_timeout: int
    threat_model_path: Path
    host: str
    port: int
    approve_label: str
    block_label: str
    review_label: str
    submit_reviews: bool
    comment_on_approval: bool
    github_api_url: str

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            github_token=os.getenv("OSS_SENTINEL_GITHUB_TOKEN"),
            webhook_secret=os.getenv("OSS_SENTINEL_WEBHOOK_SECRET"),
            dry_run=env_bool("OSS_SENTINEL_DRY_RUN", True),
            security_cmd=os.getenv("OSS_SENTINEL_SECURITY_CMD"),
            security_timeout=env_int("OSS_SENTINEL_SECURITY_TIMEOUT", 120),
            threat_model_path=Path(os.getenv("OSS_SENTINEL_THREAT_MODEL", "threat_model.json")),
            host=os.getenv("OSS_SENTINEL_HOST", "127.0.0.1"),
            port=env_int("OSS_SENTINEL_PORT", 8080),
            approve_label=os.getenv("OSS_SENTINEL_APPROVE_LABEL", "security/approved"),
            block_label=os.getenv("OSS_SENTINEL_BLOCK_LABEL", "security/blocked"),
            review_label=os.getenv("OSS_SENTINEL_REVIEW_LABEL", "security/review"),
            submit_reviews=env_bool("OSS_SENTINEL_SUBMIT_REVIEWS", False),
            comment_on_approval=env_bool("OSS_SENTINEL_COMMENT_ON_APPROVAL", False),
            github_api_url=os.getenv("GITHUB_API_URL", "https://api.github.com"),
        )

