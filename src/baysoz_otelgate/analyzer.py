"""Analyze OpenTelemetry Collector configuration files.

Built by Baysöz Labs <baysozlabs@proton.me>.
"""

from __future__ import annotations

from pathlib import Path

from .loader import load_yaml
from .models import AnalysisResult
from .rules import run_rules


def analyze_text(text: str, source: str = "<memory>") -> AnalysisResult:
    """Analyze configuration text and return findings."""
    result = AnalysisResult(source=source)
    loaded = load_yaml(text, source=source)
    result.findings.extend(loaded.findings)
    if loaded.data is None:
        return result
    result.parsed = True
    result.findings.extend(run_rules(loaded.data, source=source))
    _dedupe(result)
    return result


def analyze_file(path: str | Path) -> AnalysisResult:
    """Analyze a configuration file path."""
    p = Path(path)
    source = str(p)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        result = AnalysisResult(source=source)
        result.findings.append(
            _io_finding(source, f"Cannot read file: {exc}")
        )
        return result
    return analyze_text(text, source=source)


def analyze_paths(paths: list[str | Path]) -> list[AnalysisResult]:
    """Analyze multiple paths, expanding directories to *.yml/*.yaml files."""
    files: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            files.extend(sorted(p.glob("*.yaml")))
            files.extend(sorted(p.glob("*.yml")))
        else:
            files.append(p)
    # Deduplicate while preserving order
    seen: set[Path] = set()
    uniq: list[Path] = []
    for f in files:
        resolved = f.resolve()
        if resolved not in seen:
            seen.add(resolved)
            uniq.append(f)
    return [analyze_file(f) for f in uniq]


def _io_finding(source: str, message: str):
    from .models import Finding, Severity

    return Finding(
        rule_id="OG000",
        severity=Severity.ERROR,
        message=message,
        path=source,
        suggestion="Check file path and permissions.",
    )


def _dedupe(result: AnalysisResult) -> None:
    seen: set[tuple[str, str, str, int | None, int | None]] = set()
    deduped = []
    for f in result.findings:
        key = (f.rule_id, f.severity.value, f.message, f.line, f.column)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    result.findings = deduped
