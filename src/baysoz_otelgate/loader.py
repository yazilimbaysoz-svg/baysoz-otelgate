"""YAML loading with source location and duplicate-key detection.

Built by Baysöz Labs <baysozlabs@proton.me>.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import yaml

from .models import Finding, Severity


@dataclass
class LoadResult:
    """Result of loading a YAML document."""

    data: Any
    findings: list[Finding]


class _LineLoader(yaml.SafeLoader):
    """SafeLoader that attaches line/column metadata to mappings."""


def _construct_mapping(
    loader: yaml.SafeLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    seen: dict[Any, tuple[int, int]] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            first_line, first_col = seen[key]
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                (
                    f"found duplicate key {key!r} "
                    f"(first defined at line {first_line + 1}, column {first_col + 1})"
                ),
                key_node.start_mark,
            )
        seen[key] = (key_node.start_mark.line, key_node.start_mark.column)
        value = loader.construct_object(value_node, deep=deep)
        mapping[key] = value
    return mapping


_LineLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def load_yaml(text: str, source: str = "<memory>") -> LoadResult:
    """Load YAML text safely, reporting parse/duplicate-key errors as findings."""
    findings: list[Finding] = []
    try:
        data = yaml.load(text, Loader=_LineLoader)  # noqa: S506 - SafeLoader subclass
    except yaml.MarkedYAMLError as exc:
        mark = exc.problem_mark
        line = mark.line + 1 if mark is not None else None
        column = mark.column + 1 if mark is not None else None
        problem = exc.problem or str(exc)
        findings.append(
            Finding(
                rule_id="OG001",
                severity=Severity.ERROR,
                message=f"YAML parse error: {problem}",
                path=source,
                line=line,
                column=column,
                suggestion="Fix YAML syntax or remove duplicate keys.",
            )
        )
        return LoadResult(data=None, findings=findings)
    except yaml.YAMLError as exc:
        findings.append(
            Finding(
                rule_id="OG001",
                severity=Severity.ERROR,
                message=f"YAML parse error: {exc}",
                path=source,
                suggestion="Fix YAML syntax.",
            )
        )
        return LoadResult(data=None, findings=findings)

    if data is None:
        data = {}
    if not isinstance(data, dict):
        findings.append(
            Finding(
                rule_id="OG002",
                severity=Severity.ERROR,
                message="Top-level OpenTelemetry Collector config must be a mapping/object.",
                path=source,
                suggestion=(
                    "Use a YAML mapping with keys like receivers, processors, "
                    "exporters, service."
                ),
            )
        )
        return LoadResult(data=None, findings=findings)
    return LoadResult(data=data, findings=findings)
