import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from app.config import get_settings
from app.core.rules import RULES, SecurityRule, load_control_pack
from app.core.scanner import run_scan
from app.core.targets import (
    AuthorizedHttpTarget,
    DemoTarget,
    TargetConfigurationError,
    TargetRequestError,
)
from app.reporting import serialize_report
from app.schemas import ScanResponse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ragshield", description="Run defensive RAG security controls."
    )
    parser.add_argument(
        "--profile",
        choices=["demo-vulnerable", "demo-hardened", "authorized-http"],
        default="demo-vulnerable",
    )
    parser.add_argument("--name", default="RAGShield CLI target")
    parser.add_argument("--endpoint", help="Allowlisted JSON endpoint for authorized-http")
    parser.add_argument("--response-field", default="answer")
    parser.add_argument(
        "--bearer-token", help="Bearer token; prefer an ephemeral environment wrapper"
    )
    parser.add_argument("--control-pack", help="Optional path to a data-only JSON control pack")
    parser.add_argument(
        "--list-controls",
        action="store_true",
        help="List built-in controls (or controls from --control-pack) and exit",
    )
    parser.add_argument("--format", choices=["markdown", "json", "sarif"], default="markdown")
    parser.add_argument("--output", help="Write the report to this path instead of stdout")
    parser.add_argument(
        "--fail-on",
        choices=["never", "critical", "high", "medium", "low"],
        default="high",
    )
    return parser


def _render_control_catalog(rules: list[SecurityRule]) -> str:
    """Render a compact, copy-friendly catalogue without contacting a target."""
    rows = ["ID       Severity  Category           Control"]
    rows.extend(
        f"{rule.id:<8} {rule.severity.value:<9} {rule.category:<18} {rule.title}"
        for rule in rules
    )
    return "\n".join(rows)


def _exit_code(scan: ScanResponse, fail_on: str) -> int:
    if fail_on == "never":
        return 0
    threshold = {"critical": 4, "high": 3, "medium": 2, "low": 1}[fail_on]
    values = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return int(
        any(
            not item.passed and values[item.severity.value] >= threshold
            for item in scan.findings
        )
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.list_controls:
            rules = load_control_pack(args.control_pack) if args.control_pack else list(RULES)
            print(_render_control_catalog(rules))
            return 0

        settings = get_settings()
        if args.profile == "authorized-http":
            if not args.endpoint:
                raise TargetConfigurationError("--endpoint is required for authorized-http")
            target = AuthorizedHttpTarget(
                args.endpoint, args.response_field, settings, args.bearer_token
            )
        else:
            target = DemoTarget(args.profile)
        rules = load_control_pack(args.control_pack) if args.control_pack else None
        result = run_scan(target, rules=rules)
    except (OSError, ValueError, TargetConfigurationError, TargetRequestError) as exc:
        print(f"ragshield: {exc}", file=sys.stderr)
        return 2

    scan = ScanResponse(
        id=str(uuid4()),
        target_name=args.name,
        target_profile=args.profile,
        status="completed",
        score=result.score,
        risk_level=result.risk_level,
        passed=result.passed,
        failed=result.failed,
        duration_ms=result.duration_ms,
        findings=result.findings,
        created_at=datetime.now(UTC),
    )
    report = serialize_report(scan, args.format)
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"Wrote {args.format} report to {args.output}", file=sys.stderr)
    else:
        print(report)
    return _exit_code(scan, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
