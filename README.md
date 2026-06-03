# OSS Sentinel Bot

OSS Sentinel Bot is a lightweight MVP for automated PR security review and release auditing. It follows the design in the original `README.txt`: receive GitHub PR webhooks, inspect changed files, run a security scan path, and add a security label/comment before maintainers merge.

This first version keeps the heavy scanner pluggable. If `OSS_SENTINEL_SECURITY_CMD` is configured, the bot sends PR context, patches, and `threat_model.json` to that command over stdin and expects JSON back. If no external scanner is configured, it uses the built-in heuristic scanner so the workflow is runnable immediately.

## What is implemented

- GitHub webhook server for `pull_request` events.
- HMAC verification for `X-Hub-Signature-256`.
- PR file retrieval through the GitHub REST API.
- Threat-model baseline generation.
- Built-in checks for secret exposure, command/code injection, unsafe deserialization, TLS disablement, XSS sinks, SQL string interpolation, network-boundary changes, auth/parser/dependency changes.
- Policy engine:
  - `HIGH` or `CRITICAL`: label `security/blocked`, comment, optionally request changes.
  - `MEDIUM`: label `security/review`, comment.
  - `LOW` or `INFO`: label `security/approved`.
- Release-tree audit command for pre-publish checks.
- Repository-level `sentinel.yml` tuning for ignored paths, labels, severity thresholds, and critical path rules.
- Dry-run mode by default.

## Quick start

```bash
cd OSS-Sentinel-Bot
python3 -m oss_sentinel.cli baseline . --repository owner/repo
python3 -m unittest discover -s tests
python3 -m oss_sentinel.cli serve
```

Copy `.env.example` into your deployment environment and set:

```bash
export OSS_SENTINEL_GITHUB_TOKEN=...
export OSS_SENTINEL_WEBHOOK_SECRET=...
export OSS_SENTINEL_DRY_RUN=false
```

For production, prefer GitHub App installation auth over a personal token:

```bash
export OSS_SENTINEL_GITHUB_APP_ID=123456
export OSS_SENTINEL_GITHUB_APP_PRIVATE_KEY_PATH=/srv/oss-sentinel/github-app.pem
export OSS_SENTINEL_GITHUB_APP_INSTALLATION_ID=987654
```

`OSS_SENTINEL_GITHUB_TOKEN` takes precedence when it is set. GitHub App JWT signing uses the system `openssl` command.

Then configure a GitHub webhook:

- Payload URL: `https://your-host.example/webhook`
- Content type: `application/json`
- Secret: same value as `OSS_SENTINEL_WEBHOOK_SECRET`
- Events: Pull requests

## External scanner adapter

Set:

```bash
export OSS_SENTINEL_SECURITY_CMD="your-scanner --format json"
# or use the bundled local adapter:
export OSS_SENTINEL_SECURITY_CMD="python3 -m oss_sentinel.adapters.rule_based"
```

The command receives JSON on stdin:

```json
{
  "schema_version": 1,
  "context": {"repository": "owner/repo", "pull_number": 12},
  "threat_model": {},
  "files": [],
  "builtin_report": {}
}
```

It must print a ScanReport-compatible JSON document:

```json
{
  "schema_version": 1,
  "scanner": "your-scanner",
  "summary": "No exploitable issue found.",
  "findings": [],
  "metadata": {"confidence": "medium"}
}
```

The full prompt contract lives in `prompts/security_decision.md`.

Validate a scanner command before using it in webhook mode:

```bash
python3 -m oss_sentinel.cli validate-scanner \
  tests/fixtures/pr_auth_change.json \
  python3 -m oss_sentinel.adapters.rule_based
```

`validate-scanner` sends a realistic scanner payload to the command and fails if the command cannot emit a valid `ScanReport`.

## Commands

```bash
python3 -m oss_sentinel.cli baseline . -o threat_model.json
python3 -m oss_sentinel.cli serve
python3 -m oss_sentinel.cli audit-release . -o security_report.json
python3 -m oss_sentinel.cli simulate-pr tests/fixtures/pr_secret.json
```

`audit-release` exits with status `2` when a `HIGH` or `CRITICAL` finding is present. Use that in `npm publish`, PyPI, or other release pipelines.
By default it skips tests, fixtures, and examples; add `--include-tests` when those files are part of the release artifact you want to audit.

## Local verification

The CI workflow runs the same checks:

```bash
python3 -m unittest discover -s tests
python3 -m compileall oss_sentinel scripts
python3 -m oss_sentinel.cli audit-release . -o security_report.json
python3 -m oss_sentinel.cli validate-scanner tests/fixtures/pr_auth_change.json python3 -m oss_sentinel.adapters.rule_based
```

Integration fixtures in `tests/fixtures` cover clean PRs, dependency PRs, sensitive-file PRs, and external scanner failures.

## Repository config

`sentinel.yml` lets maintainers tune rules without changing bot code:

```yaml
ignore_paths:
  - "docs/generated/**"
sensitive_paths:
  - "config/production/**"
security_critical_patterns:
  - glob: "src/auth/**"
    reason: "Authentication code changed"
policy:
  block_at: HIGH
  review_at: MEDIUM
labels:
  approve: "security/approved"
  review: "security/review"
  block: "security/blocked"
release:
  ignore_paths:
    - "docs/**"
```

## GitHub permissions

Use a GitHub App installation token or fine-scoped token with:

- Pull requests: read, write if submitting reviews.
- Issues: write for comments and labels.
- Metadata: read.

Keep `OSS_SENTINEL_DRY_RUN=true` until label/comment behavior is verified.
