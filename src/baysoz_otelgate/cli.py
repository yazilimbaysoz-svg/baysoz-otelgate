"""CLI for baysoz-otelgate.

Built by Baysöz Labs <baysozlabs@proton.me>.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import __author__, __email__, __version__
from .analyzer import analyze_paths
from .formatters import render_json, render_sarif, render_text
from .models import Severity


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="otelgate",
        description=(
            "baysoz-otelgate: static policy gate and semantic linter for OpenTelemetry "
            "Collector configurations. Built by Baysöz Labs <baysozlabs@proton.me>."
        ),
        epilog=f"Baysöz Labs <{__email__}> | https://github.com/yazilimbaysoz-svg/baysoz-otelgate",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"otelgate {__version__} - {__author__} <{__email__}>",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser(
        "scan",
        help="Scan OpenTelemetry Collector config files or directories for policy violations.",
        description=(
            "Scan OpenTelemetry Collector YAML configs for semantic, security, and "
            f"reliability issues. Built by {__author__} <{__email__}>."
        ),
    )
    scan.add_argument("paths", nargs="+", help="Config files or directories to scan.")
    scan.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text).",
    )
    scan.add_argument(
        "--fail-on",
        choices=["error", "warning", "never"],
        default="error",
        help="Exit non-zero threshold (default: error).",
    )
    scan.add_argument(
        "--output",
        "-o",
        default=None,
        help="Write report to file instead of stdout.",
    )

    rules = sub.add_parser("rules", help="List built-in rules.")
    rules.add_argument("--format", choices=["text", "json"], default="text")

    return parser


def _rules_command(fmt: str) -> int:
    from .rules import ALL_RULES

    if fmt == "json":
        import json

        payload = {
            "tool": "baysoz-otelgate",
            "vendor": __author__,
            "contact": __email__,
            "rules": [
                {
                    "id": r.rule_id,
                    "title": r.title,
                    "description": r.description,
                }
                for r in ALL_RULES
            ],
        }
        sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
        return 0

    for r in ALL_RULES:
        sys.stdout.write(f"{r.rule_id}\t{r.title}\t{r.description}\n")
    sys.stdout.write(f"\n{len(ALL_RULES)} rules - {__author__} <{__email__}>\n")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "rules":
        return _rules_command(args.format)

    if args.command == "scan":
        results = analyze_paths(args.paths)
        if args.format == "json":
            report = render_json(results)
        elif args.format == "sarif":
            report = render_sarif(results)
        else:
            report = render_text(results)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(report)
        else:
            sys.stdout.write(report)

        if args.fail_on == "never":
            return 0
        has_error = any(r.errors for r in results)
        has_warning = any(
            any(f.severity == Severity.WARNING for f in r.findings) for r in results
        )
        if args.fail_on == "error" and has_error:
            return 1
        if args.fail_on == "warning" and (has_error or has_warning):
            return 1
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
