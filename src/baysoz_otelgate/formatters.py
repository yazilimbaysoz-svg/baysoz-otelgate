"""Output formatters for analysis results.

Built by Baysöz Labs <baysozlabs@proton.me>.
"""

from __future__ import annotations

import json
from typing import Any

from . import __author__, __email__, __version__
from .models import AnalysisResult, Severity

_SEVERITY_ORDER = {Severity.ERROR: 0, Severity.WARNING: 1, Severity.INFO: 2}


def render_text(results: list[AnalysisResult]) -> str:
    """Render human-readable text output."""
    lines: list[str] = []
    total_errors = 0
    total_warnings = 0
    total_infos = 0
    for result in results:
        findings = sorted(
            result.findings,
            key=lambda f: (_SEVERITY_ORDER[f.severity], f.line or 0, f.rule_id),
        )
        for f in findings:
            loc = f.path
            if f.line is not None:
                loc += f":{f.line}"
                if f.column is not None:
                    loc += f":{f.column}"
            lines.append(f"{loc}: {f.severity.value.upper()} {f.rule_id} {f.message}")
            if f.suggestion:
                lines.append(f"  suggestion: {f.suggestion}")
        total_errors += len(result.errors)
        total_warnings += len(result.warnings)
        total_infos += len([x for x in result.findings if x.severity == Severity.INFO])

    lines.append("")
    lines.append(
        f"Summary: {len(results)} file(s), {total_errors} error(s), "
        f"{total_warnings} warning(s), {total_infos} info(s)"
    )
    status = "PASS" if total_errors == 0 else "FAIL"
    lines.append(f"Gate: {status}")
    lines.append(f"Powered by baysoz-otelgate {__version__} - {__author__} <{__email__}>")
    return "\n".join(lines)


def render_json(results: list[AnalysisResult]) -> str:
    """Render JSON output."""
    payload = {
        "tool": {
            "name": "baysoz-otelgate",
            "version": __version__,
            "vendor": __author__,
            "contact": __email__,
        },
        "summary": {
            "files": len(results),
            "errors": sum(len(r.errors) for r in results),
            "warnings": sum(len(r.warnings) for r in results),
            "infos": sum(
                len([f for f in r.findings if f.severity == Severity.INFO]) for r in results
            ),
            "ok": all(r.ok for r in results),
        },
        "results": [r.to_dict() for r in results],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def render_sarif(results: list[AnalysisResult]) -> str:
    """Render SARIF v2.1.0 output for CI/code scanning integrations."""
    rules: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []
    for result in results:
        for f in result.findings:
            if f.rule_id not in rules:
                rules[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.rule_id,
                    "shortDescription": {"text": f.rule_id},
                    "fullDescription": {"text": f.message},
                    "defaultConfiguration": {"level": _sarif_level(f.severity)},
                    "properties": {"vendor": __author__},
                }
            sarif_result: dict[str, Any] = {
                "ruleId": f.rule_id,
                "level": _sarif_level(f.severity),
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": result.source},
                            "region": _region(f.line, f.column),
                        }
                    }
                ],
            }
            if f.suggestion:
                sarif_result["fixes"] = [{"description": {"text": f.suggestion}}]
            sarif_results.append(sarif_result)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "baysoz-otelgate",
                        "version": __version__,
                        "informationUri": "https://github.com/yazilimbaysoz-svg/baysoz-otelgate",
                        "organization": __author__,
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"


def _sarif_level(severity: Severity) -> str:
    if severity == Severity.ERROR:
        return "error"
    if severity == Severity.WARNING:
        return "warning"
    return "note"


def _region(line: int | None, column: int | None) -> dict[str, int]:
    region: dict[str, int] = {}
    if line is not None and line > 0:
        region["startLine"] = line
    if column is not None and column > 0:
        region["startColumn"] = column
    return region or {"startLine": 1}
