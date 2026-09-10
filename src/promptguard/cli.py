"""Command line interface.

    promptguard scan "text"              # check one payload
    promptguard scan -f prompts.txt      # one payload per line
    promptguard scan --stage output ...  # run the output policy instead
    promptguard redact "text"            # print the sanitized text only
    promptguard report audit.jsonl       # control-coverage report
    promptguard verify audit.jsonl       # audit chain integrity
    promptguard rules                    # list every rule the guard can fire

Exit codes are CI-friendly: 0 clean, 1 findings present, 2 blocked, 3 usage.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import AuditLog
from .compliance import build_report
from .config import ComplianceConfig, GuardConfig
from .detectors import injection, jailbreak, secrets
from .guard import PromptGuard
from .policy import pii
from .types import Action, GuardResult

EXIT_CLEAN, EXIT_FINDINGS, EXIT_BLOCKED, EXIT_USAGE = 0, 1, 2, 3


def _load_config(path: str | None, preset: str) -> GuardConfig:
    if path:
        return GuardConfig.from_file(path)
    if preset == "strict":
        return GuardConfig.strict()
    if preset == "permissive":
        return GuardConfig.permissive()
    return GuardConfig()


def _payloads(args: argparse.Namespace) -> list[str]:
    if args.file:
        text = Path(args.file).read_text(encoding="utf-8")
        return [line for line in text.splitlines() if line.strip()] if args.lines else [text]
    if args.text:
        return [args.text]
    stdin = sys.stdin.read()
    return [line for line in stdin.splitlines() if line.strip()] if args.lines else [stdin]


def _render_human(payload: str, result: GuardResult, show_text: bool) -> str:
    icon = {
        Action.ALLOW: "PASS",
        Action.FLAG: "FLAG",
        Action.REDACT: "REDACT",
        Action.BLOCK: "BLOCK",
    }[result.action]
    head = (
        f"[{icon}] risk={result.risk_score:.2f} severity={result.max_severity.value} "
        f"({result.elapsed_ms:.1f} ms) :: {_clip(payload)}"
    )
    lines = [head]
    for finding in result.findings:
        lines.append(
            f"    {finding.rule_id} {finding.severity.value:<8} {finding.category:<16} "
            f"{finding.message}"
        )
        if finding.evidence:
            lines.append(f"        evidence: {_clip(finding.evidence, 90)}")
    if show_text and result.modified:
        lines.append(f"    sanitized: {_clip(result.text, 160)}")
    return "\n".join(lines)


def _clip(value: str, limit: int = 100) -> str:
    flat = " ".join(value.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def cmd_scan(args: argparse.Namespace) -> int:
    config = _load_config(args.config, args.preset)
    if args.audit_log:
        config.compliance.audit_log_path = args.audit_log
    guard = PromptGuard(config)

    results: list[GuardResult] = []
    payloads = _payloads(args)
    for payload in payloads:
        if args.stage == "output":
            result = guard.check_output(payload)
        else:
            result = guard.check_input(payload, context=args.channel)
        results.append(result)

    if args.json:
        print(
            json.dumps(
                {
                    "stage": args.stage,
                    "results": [r.to_dict() for r in results],
                    "summary": build_report(results, config.compliance.frameworks).to_dict(),
                },
                indent=2,
            )
        )
    else:
        for payload, result in zip(payloads, results, strict=True):
            print(_render_human(payload, result, args.show_text))
        if len(results) > 1:
            print()
            print(build_report(results, config.compliance.frameworks).render())

    if any(r.action is Action.BLOCK for r in results):
        return EXIT_BLOCKED
    if any(r.findings for r in results):
        return EXIT_FINDINGS
    return EXIT_CLEAN


def cmd_redact(args: argparse.Namespace) -> int:
    config = _load_config(args.config, args.preset)
    guard = PromptGuard(config)
    for payload in _payloads(args):
        result = (
            guard.output.check(payload) if args.stage == "output" else guard.input.check(payload)
        )
        print(result.text)
    return EXIT_CLEAN


def cmd_report(args: argparse.Namespace) -> int:
    log = AuditLog(ComplianceConfig(audit_log_path=args.audit_log))
    records = list(log.records())
    if not records:
        print("no audit records found", file=sys.stderr)
        return EXIT_USAGE

    # Rebuild a lightweight report straight from persisted records so the
    # command works against logs produced by another process.
    from collections import Counter

    categories: Counter[str] = Counter()
    controls: Counter[str] = Counter()
    rules: Counter[str] = Counter()
    actions: Counter[str] = Counter()

    for record in records:
        actions[record["action"]] += 1
        for finding in record.get("findings", []):
            categories[finding["category"]] += 1
            rules[finding["rule_id"]] += 1
            for control in finding.get("controls", []):
                controls[f"{control['framework']}:{control['control_id']}"] += 1

    summary = {
        "records": len(records),
        "actions": dict(actions),
        "findings_by_category": dict(categories),
        "controls_exercised": dict(controls),
        "top_rules": rules.most_common(10),
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"Audit records      : {len(records)}")
        for action, count in sorted(actions.items()):
            print(f"  {action:<16} {count}")
        print("\nFindings by category:")
        for category, count in categories.most_common():
            print(f"  {category:<20} {count}")
        print("\nControls exercised:")
        for control, count in sorted(controls.items()):
            print(f"  {control:<28} {count}")
    return EXIT_CLEAN


def cmd_verify(args: argparse.Namespace) -> int:
    log = AuditLog(ComplianceConfig(audit_log_path=args.audit_log))
    ok, broken = log.verify_chain()
    if ok:
        print(f"audit chain intact ({sum(1 for _ in log.records())} records)")
        return EXIT_CLEAN
    print(f"audit chain BROKEN at event {broken}", file=sys.stderr)
    return EXIT_FINDINGS


def cmd_rules(args: argparse.Namespace) -> int:
    rows: list[tuple[str, str, str, str]] = []
    for pat in injection.ALL_PATTERNS:
        rows.append((pat.rule_id, "prompt_injection", pat.severity.value, pat.message))
    for pat in jailbreak.PATTERNS:
        rows.append((pat.rule_id, "jailbreak", pat.severity.value, pat.message))
    for rule in secrets.RULES:
        rows.append((rule.rule_id, "secret", rule.severity.value, rule.name))
    for rule in pii.RULES:
        rows.append((rule.rule_id, "pii", rule.severity.value, rule.entity))

    if args.json:
        print(json.dumps([dict(zip(("rule_id", "category", "severity", "detail"), r, strict=True)) for r in rows], indent=2))
    else:
        print(f"{'RULE':<14} {'CATEGORY':<18} {'SEVERITY':<10} DETAIL")
        for row in sorted(rows):
            print(f"{row[0]:<14} {row[1]:<18} {row[2]:<10} {row[3]}")
        print(f"\n{len(rows)} rules loaded")
    return EXIT_CLEAN


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="promptguard",
        description="Input validation, output policy and compliance controls for LLM apps.",
    )
    parser.add_argument("--version", action="store_true", help="print version and exit")
    sub = parser.add_subparsers(dest="command")

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("text", nargs="?", help="payload to evaluate (or use -f / stdin)")
        p.add_argument("-f", "--file", help="read the payload from a file")
        p.add_argument("--lines", action="store_true", help="treat each input line as a payload")
        p.add_argument("-c", "--config", help="path to a YAML/JSON policy file")
        p.add_argument(
            "--preset", choices=["default", "strict", "permissive"], default="default"
        )
        p.add_argument("--stage", choices=["input", "output"], default="input")

    scan = sub.add_parser("scan", help="evaluate a payload against the guard")
    add_common(scan)
    scan.add_argument("--channel", default="user", help="input channel: user, retrieved, tool")
    scan.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    scan.add_argument("--show-text", action="store_true", help="print the sanitized payload")
    scan.add_argument("--audit-log", help="append decisions to this JSONL audit log")
    scan.set_defaults(func=cmd_scan)

    redact = sub.add_parser("redact", help="print the sanitized payload only")
    add_common(redact)
    redact.set_defaults(func=cmd_redact)

    report = sub.add_parser("report", help="control-coverage report from an audit log")
    report.add_argument("audit_log")
    report.add_argument("--json", action="store_true")
    report.set_defaults(func=cmd_report)

    verify = sub.add_parser("verify", help="verify audit log hash chain integrity")
    verify.add_argument("audit_log")
    verify.set_defaults(func=cmd_verify)

    rules = sub.add_parser("rules", help="list every rule the guard can fire")
    rules.add_argument("--json", action="store_true")
    rules.set_defaults(func=cmd_rules)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "version", False):
        from . import __version__

        print(f"promptguard {__version__}")
        return EXIT_CLEAN

    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_USAGE

    try:
        return int(args.func(args))
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
