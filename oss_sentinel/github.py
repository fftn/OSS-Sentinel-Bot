from __future__ import annotations

from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import json


class GitHubError(RuntimeError):
    pass


class GitHubClient:
    def __init__(
        self,
        token: str | None,
        api_url: str = "https://api.github.com",
        dry_run: bool = True,
    ) -> None:
        self.token = token
        self.api_url = api_url.rstrip("/")
        self.dry_run = dry_run

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "oss-sentinel-bot/0.1",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _request(
        self,
        method: str,
        path_or_url: str,
        body: dict[str, Any] | None = None,
    ) -> tuple[Any, dict[str, str]]:
        method = method.upper()
        if self.dry_run and method != "GET":
            return {"dry_run": True, "method": method, "path": path_or_url, "body": body}, {}
        if method != "GET" and not self.token:
            raise GitHubError("OSS_SENTINEL_GITHUB_TOKEN is required for GitHub write operations.")

        url = path_or_url if path_or_url.startswith("http") else f"{self.api_url}{path_or_url}"
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        request = Request(url, data=data, method=method, headers=self._headers())
        try:
            with urlopen(request, timeout=30) as response:
                raw = response.read().decode("utf-8")
                headers = dict(response.headers.items())
        except HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            raise GitHubError(f"GitHub API {method} {url} failed: {exc.code} {raw}") from exc
        if not raw:
            return None, headers
        return json.loads(raw), headers

    def get_pull_files(self, owner: str, repo: str, pull_number: int) -> list[dict[str, Any]]:
        encoded_owner = quote(owner, safe="")
        encoded_repo = quote(repo, safe="")
        url = f"/repos/{encoded_owner}/{encoded_repo}/pulls/{pull_number}/files?per_page=100"
        files: list[dict[str, Any]] = []
        while url:
            page, headers = self._request("GET", url)
            files.extend(page)
            url = self._next_url(headers.get("Link", ""))
        return files

    def add_labels(self, owner: str, repo: str, issue_number: int, labels: list[str]) -> Any:
        return self._request(
            "POST",
            f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/issues/{issue_number}/labels",
            {"labels": labels},
        )[0]

    def remove_label(self, owner: str, repo: str, issue_number: int, label: str) -> Any:
        try:
            return self._request(
                "DELETE",
                f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/issues/{issue_number}/labels/{quote(label, safe='')}",
            )[0]
        except GitHubError as exc:
            if " 404 " in str(exc):
                return None
            raise

    def create_comment(self, owner: str, repo: str, issue_number: int, body: str) -> Any:
        return self._request(
            "POST",
            f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/issues/{issue_number}/comments",
            {"body": body},
        )[0]

    def submit_pull_review(self, owner: str, repo: str, pull_number: int, body: str, event: str) -> Any:
        return self._request(
            "POST",
            f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/pulls/{pull_number}/reviews",
            {"body": body, "event": event},
        )[0]

    @staticmethod
    def _next_url(link_header: str) -> str | None:
        for part in link_header.split(","):
            if 'rel="next"' not in part:
                continue
            start = part.find("<")
            end = part.find(">")
            if start != -1 and end != -1 and end > start:
                return part[start + 1 : end]
        return None

