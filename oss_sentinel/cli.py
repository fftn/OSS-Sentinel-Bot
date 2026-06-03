from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import argparse
import json
import shlex
import sys

from .audit import read_audit_records
from .config import Settings
from .models import SEVERITY_RANK, validate_scan_report_payload
from .repo_config import load_repository_config, merge_config_into_threat_model
from .scanner import run_external_security_cmd, scan_repository_path
from .server import handle_event, run_server
from .threat_model import generate_threat_model, load_threat_model, write_threat_model


def cmd_baseline(args: argparse.Namespace) -> int:
    model = generate_threat_model(Path(args.path), args.repository)
    output = Path(args.output)
    write_threat_model(output, model)
    print(f"Wrote threat model to {output}")
    return 0


def cmd_audit_release(args: argparse.Namespace) -> int:
    repo_path = Path(args.path)
    repo_config = load_repository_config(Path(args.config) if args.config else None)
    threat_model = merge_config_into_threat_model(load_threat_model(Path(args.threat_model)), repo_config)
    report = scan_repository_path(repo_path, threat_model, include_tests=args.include_tests)
    output = Path(args.output)
    output.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{report.summary} Max severity: {report.max_severity}")
    print(f"Wrote release audit report to {output}")
    if SEVERITY_RANK[report.max_severity] >= SEVERITY_RANK["HIGH"]:
        return 2
    return 0


def cmd_simulate_pr(args: argparse.Namespace) -> int:
    payload = json.loads(Path(args.payload).read_text(encoding="utf-8"))
    settings = Settings.from_env()
    settings = replace(settings, dry_run=not args.write)
    result = handle_event("pull_request", payload, settings)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def cmd_validate_scanner(args: argparse.Namespace) -> int:
    if not args.command:
        print("ERROR: scanner command is required")
        return 2
    fixture = json.loads(Path(args.fixture).read_text(encoding="utf-8"))
    files = fixture.get("sentinel", {}).get("files", [])
    payload = {
        "schema_version": 1,
        "context": {
            "event": "scanner-contract",
            "repository": fixture.get("repository", {}).get("full_name", "owner/repo"),
            "pull_number": fixture.get("number", 0),
        },
        "threat_model": load_threat_model(Path(args.threat_model)),
        "files": files,
        "builtin_report": {
            "schema_version": 1,
            "scanner": "contract-fixture",
            "summary": "Contract validation fixture.",
            "findings": [],
            "metadata": {},
        },
    }
    command = " ".join(shlex.quote(part) for part in args.command)
    report = run_external_security_cmd(
        command,
        payload,
        args.timeout,
        fallback_report=scan_repository_path(Path("."), payload["threat_model"]),
    )
    serialized = report.to_dict()
    errors = validate_scan_report_payload(serialized)
    if args.output:
        Path(args.output).write_text(json.dumps(serialized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 2
    print(f"Scanner contract valid. Max severity: {report.max_severity}. Findings: {len(report.findings)}")
    return 0 if report.scanner != "builtin-release-audit" else 2


def cmd_audit_log(args: argparse.Namespace) -> int:
    records = read_audit_records(
        Path(args.path),
        limit=args.limit,
        repository=args.repository,
        action=args.action,
    )
    print(json.dumps(records, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="oss-sentinel", description="OSS Sentinel Bot")
    subcommands = parser.add_subparsers(dest="command", required=True)

    serve = subcommands.add_parser("serve", help="Run the GitHub webhook server.")
    serve.set_defaults(func=lambda args: run_server(Settings.from_env()) or 0)

    baseline = subcommands.add_parser("baseline", help="Generate a baseline threat_model.json.")
    baseline.add_argument("path", nargs="?", default=".", help="Repository path to inspect.")
    baseline.add_argument("-o", "--output", default="threat_model.json", help="Output JSON path.")
    baseline.add_argument("--repository", help="owner/repo name to store in the model.")
    baseline.set_defaults(func=cmd_baseline)

    audit = subcommands.add_parser("audit-release", help="Scan a release tree before publishing.")
    audit.add_argument("path", nargs="?", default=".", help="Repository path to audit.")
    audit.add_argument("-m", "--threat-model", default="threat_model.json", help="Threat model JSON path.")
    audit.add_argument("-c", "--config", help="Repository sentinel config path.")
    audit.add_argument("-o", "--output", default="security_report.json", help="Output report JSON path.")
    audit.add_argument("--include-tests", action="store_true", help="Also scan tests, fixtures, and examples.")
    audit.set_defaults(func=cmd_audit_release)

    simulate = subcommands.add_parser("simulate-pr", help="Run the PR decision path against a fixture payload.")
    simulate.add_argument("payload", help="JSON payload with a sentinel.files array.")
    simulate.add_argument("--write", action="store_true", help="Apply GitHub labels/comments instead of dry-run.")
    simulate.set_defaults(func=cmd_simulate_pr)

    validate = subcommands.add_parser("validate-scanner", help="Validate an external scanner command contract.")
    validate.add_argument("fixture", help="PR fixture JSON with a sentinel.files array.")
    validate.add_argument("command", nargs=argparse.REMAINDER, help="Scanner command to execute.")
    validate.add_argument("-m", "--threat-model", default="threat_model.json", help="Threat model JSON path.")
    validate.add_argument("-o", "--output", help="Write scanner report JSON to this path.")
    validate.add_argument("--timeout", type=int, default=30, help="Scanner timeout in seconds.")
    validate.set_defaults(func=cmd_validate_scanner)

    audit_log = subcommands.add_parser("audit-log", help="Read OSS Sentinel JSONL audit records.")
    audit_log.add_argument("path", nargs="?", default="audit_log.jsonl", help="Audit JSONL path.")
    audit_log.add_argument("--limit", type=int, default=20, help="Maximum recent records to print.")
    audit_log.add_argument("--repository", help="Only include records for owner/repo.")
    audit_log.add_argument("--action", choices=["approve", "review", "block"], help="Only include one decision.")
    audit_log.set_defaults(func=cmd_audit_log)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    result = args.func(args)
    return int(result or 0)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
