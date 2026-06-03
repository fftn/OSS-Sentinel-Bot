from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
import hashlib
import hmac
import json

from .config import Settings
from .github import GitHubClient
from .models import PullRequestFile
from .policy import decide, render_comment
from .scanner import run_security_analysis
from .threat_model import load_threat_model


SUPPORTED_PR_ACTIONS = {"opened", "reopened", "synchronize", "ready_for_review"}


def verify_signature(secret: str | None, body: bytes, header: str | None) -> bool:
    if not secret:
        return True
    if not header or not header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)


def _repo_parts(payload: dict[str, Any]) -> tuple[str, str]:
    full_name = payload.get("repository", {}).get("full_name")
    if not full_name or "/" not in full_name:
        raise ValueError("payload.repository.full_name is required")
    owner, repo = full_name.split("/", 1)
    return owner, repo


def _files_from_payload_or_github(
    payload: dict[str, Any],
    client: GitHubClient,
    owner: str,
    repo: str,
    pull_number: int,
) -> list[PullRequestFile]:
    embedded = payload.get("sentinel", {}).get("files")
    if embedded is not None:
        return [PullRequestFile.from_github(item) for item in embedded]
    return [PullRequestFile.from_github(item) for item in client.get_pull_files(owner, repo, pull_number)]


def apply_decision(
    client: GitHubClient,
    owner: str,
    repo: str,
    pull_number: int,
    settings: Settings,
    report_body: str,
    action: str,
    label: str,
    request_changes: bool,
    comment: bool,
) -> None:
    stale_labels = {
        settings.approve_label,
        settings.block_label,
        settings.review_label,
    } - {label}
    for stale_label in stale_labels:
        client.remove_label(owner, repo, pull_number, stale_label)
    client.add_labels(owner, repo, pull_number, [label])
    if comment:
        client.create_comment(owner, repo, pull_number, report_body)
    if request_changes and settings.submit_reviews:
        client.submit_pull_review(owner, repo, pull_number, report_body, "REQUEST_CHANGES")


def handle_pull_request(payload: dict[str, Any], settings: Settings, client: GitHubClient) -> dict[str, Any]:
    action = str(payload.get("action", ""))
    if action not in SUPPORTED_PR_ACTIONS:
        return {"status": "ignored", "reason": f"unsupported action {action}"}
    pull_request = payload.get("pull_request", {})
    if pull_request.get("draft"):
        return {"status": "ignored", "reason": "draft pull request"}

    owner, repo = _repo_parts(payload)
    pull_number = int(payload.get("number") or pull_request.get("number"))
    files = _files_from_payload_or_github(payload, client, owner, repo, pull_number)
    threat_model = load_threat_model(settings.threat_model_path)
    actor = pull_request.get("user", {}).get("login")
    context = {
        "event": "pull_request",
        "action": action,
        "repository": f"{owner}/{repo}",
        "pull_number": pull_number,
        "title": pull_request.get("title"),
        "actor": actor,
        "is_dependabot": bool(actor and actor.startswith("dependabot")),
        "base_ref": pull_request.get("base", {}).get("ref"),
        "head_ref": pull_request.get("head", {}).get("ref"),
    }
    report = run_security_analysis(
        files,
        threat_model,
        settings.security_cmd,
        settings.security_timeout,
        context,
    )
    decision = decide(
        report,
        approve_label=settings.approve_label,
        block_label=settings.block_label,
        review_label=settings.review_label,
        comment_on_approval=settings.comment_on_approval,
    )
    comment_body = render_comment(report, decision)
    apply_decision(
        client,
        owner,
        repo,
        pull_number,
        settings,
        comment_body,
        decision.action,
        decision.label,
        decision.request_changes,
        decision.comment,
    )
    return {
        "status": "processed",
        "action": decision.action,
        "label": decision.label,
        "max_severity": report.max_severity,
        "findings": len(report.findings),
        "dry_run": settings.dry_run,
    }


def handle_event(event: str, payload: dict[str, Any], settings: Settings) -> dict[str, Any]:
    client = GitHubClient(settings.github_token, settings.github_api_url, settings.dry_run)
    if event == "pull_request":
        return handle_pull_request(payload, settings, client)
    return {"status": "ignored", "reason": f"unsupported event {event}"}


def make_handler(settings: Settings) -> type[BaseHTTPRequestHandler]:
    class WebhookHandler(BaseHTTPRequestHandler):
        server_version = "OSSSentinelBot/0.1"

        def do_GET(self) -> None:
            if self.path == "/healthz":
                self._send_json(200, {"status": "ok", "dry_run": settings.dry_run})
                return
            self._send_json(404, {"error": "not found"})

        def do_POST(self) -> None:
            if self.path != "/webhook":
                self._send_json(404, {"error": "not found"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            if not verify_signature(settings.webhook_secret, body, self.headers.get("X-Hub-Signature-256")):
                self._send_json(401, {"error": "invalid signature"})
                return
            try:
                payload = json.loads(body.decode("utf-8"))
                event = self.headers.get("X-GitHub-Event", "")
                result = handle_event(event, payload, settings)
            except Exception as exc:
                self._send_json(500, {"error": str(exc)})
                return
            self._send_json(200, result)

        def log_message(self, format: str, *args: Any) -> None:
            print(f"{self.address_string()} - {format % args}")

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            raw = json.dumps(payload, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    return WebhookHandler


def run_server(settings: Settings) -> None:
    server = ThreadingHTTPServer((settings.host, settings.port), make_handler(settings))
    print(f"OSS Sentinel Bot listening on http://{settings.host}:{settings.port}")
    print(f"dry_run={settings.dry_run}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping OSS Sentinel Bot")
    finally:
        server.server_close()


def main() -> None:
    settings = Settings.from_env()
    run_server(settings)


if __name__ == "__main__":
    main()
