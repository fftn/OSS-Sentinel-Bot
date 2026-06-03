from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import base64
import json
import subprocess
import time

from .config import Settings


class GitHubAppAuthError(RuntimeError):
    pass


Signer = Callable[[Path, bytes], bytes]


@dataclass(frozen=True)
class GitHubAppCredentials:
    app_id: str
    private_key_path: Path
    installation_id: str

    @classmethod
    def from_settings(cls, settings: Settings) -> "GitHubAppCredentials | None":
        values = [
            settings.github_app_id,
            settings.github_app_private_key_path,
            settings.github_app_installation_id,
        ]
        if not any(values):
            return None
        if not all(values):
            raise GitHubAppAuthError(
                "Set OSS_SENTINEL_GITHUB_APP_ID, OSS_SENTINEL_GITHUB_APP_PRIVATE_KEY_PATH, "
                "and OSS_SENTINEL_GITHUB_APP_INSTALLATION_ID together."
            )
        assert settings.github_app_id is not None
        assert settings.github_app_private_key_path is not None
        assert settings.github_app_installation_id is not None
        return cls(
            app_id=settings.github_app_id,
            private_key_path=settings.github_app_private_key_path,
            installation_id=settings.github_app_installation_id,
        )


def resolve_github_token(settings: Settings) -> str | None:
    if settings.github_token:
        return settings.github_token
    credentials = GitHubAppCredentials.from_settings(settings)
    if credentials is None:
        return None
    return fetch_installation_token(credentials, settings.github_api_url)


def fetch_installation_token(
    credentials: GitHubAppCredentials,
    github_api_url: str,
    now: int | None = None,
    signer: Signer | None = None,
) -> str:
    jwt = build_app_jwt(credentials.app_id, credentials.private_key_path, now=now, signer=signer)
    url = (
        f"{github_api_url.rstrip('/')}/app/installations/"
        f"{credentials.installation_id}/access_tokens"
    )
    request = Request(
        url,
        data=b"{}",
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {jwt}",
            "Content-Type": "application/json",
            "User-Agent": "oss-sentinel-bot/0.1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise GitHubAppAuthError(f"GitHub App token exchange failed: {exc.code} {body}") from exc
    token = payload.get("token")
    if not token:
        raise GitHubAppAuthError("GitHub App token exchange response did not include token")
    return str(token)


def build_app_jwt(
    app_id: str,
    private_key_path: Path,
    now: int | None = None,
    signer: Signer | None = None,
) -> str:
    issued_at = int(time.time() if now is None else now) - 60
    expires_at = issued_at + 9 * 60
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"iat": issued_at, "exp": expires_at, "iss": app_id}
    signing_input = (
        f"{base64url_json(header)}.{base64url_json(payload)}"
    ).encode("ascii")
    actual_signer = signer or sign_rs256
    signature = actual_signer(private_key_path, signing_input)
    return f"{signing_input.decode('ascii')}.{base64url(signature)}"


def sign_rs256(private_key_path: Path, signing_input: bytes) -> bytes:
    if not private_key_path.exists():
        raise GitHubAppAuthError(f"GitHub App private key not found: {private_key_path}")
    try:
        completed = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(private_key_path)],
            input=signing_input,
            capture_output=True,
            check=True,
        )
    except FileNotFoundError as exc:
        raise GitHubAppAuthError("openssl is required for GitHub App JWT signing") from exc
    except subprocess.CalledProcessError as exc:
        message = exc.stderr.decode("utf-8", errors="replace").strip()
        raise GitHubAppAuthError(f"GitHub App JWT signing failed: {message}") from exc
    return completed.stdout


def base64url_json(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64url(raw)


def base64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
