"""Data models for baysoz-otelgate.

Built by Baysöz Labs <baysozlabs@proton.me>.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Finding severity levels."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    """A single policy or semantic finding."""

    rule_id: str
    severity: Severity
    message: str
    path: str
    line: int | None = None
    column: int | None = None
    suggestion: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "suggestion": self.suggestion,
        }


@dataclass
class AnalysisResult:
    """Result of analyzing one configuration file."""

    source: str
    findings: list[Finding] = field(default_factory=list)
    parsed: bool = False

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.ERROR]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.WARNING]

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "parsed": self.parsed,
            "ok": self.ok,
            "summary": {
                "errors": len(self.errors),
                "warnings": len(self.warnings),
                "infos": len([f for f in self.findings if f.severity == Severity.INFO]),
                "total": len(self.findings),
            },
            "findings": [f.to_dict() for f in self.findings],
        }
