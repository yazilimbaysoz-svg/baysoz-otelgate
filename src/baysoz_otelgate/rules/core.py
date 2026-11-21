"""Core static rules for OpenTelemetry Collector configurations.

Built by Baysöz Labs <baysozlabs@proton.me>.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from ..models import Finding, Severity

RuleFn = Callable[[dict[str, Any], str], Iterable[Finding]]

SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|authorization)",
    re.IGNORECASE,
)
SENSITIVE_VALUE_RE = re.compile(r"^(?:\$\{[^}]+\}|env:[A-Za-z_][A-Za-z0-9_]*)$")
ENDPOINT_KEY_RE = re.compile(r"(^endpoint$|_endpoint$|address$|listen$)", re.IGNORECASE)
INSECURE_ENDPOINT_RE = re.compile(r"^(0\.0\.0\.0(?::\d+)?|\[::\](?::\d+)?|::(?::\d+)?)$")


@dataclass(frozen=True)
class Rule:
    """Static rule definition."""

    rule_id: str
    title: str
    description: str
    fn: RuleFn


def _is_mapping(value: Any) -> bool:
    return isinstance(value, dict)


def _walk(obj: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], Any]]:
    yield path, obj
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, path + (str(k),))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, path + (f"[{i}]",))


def _path_str(parts: tuple[str, ...]) -> str:
    if not parts:
        return "$"
    out = "$"
    for p in parts:
        if p.startswith("["):
            out += p
        else:
            out += f".{p}"
    return out


def _get_section(config: dict[str, Any], name: str) -> dict[str, Any]:
    section = config.get(name)
    return section if isinstance(section, dict) else {}


def _component_exists(config: dict[str, Any], section: str, component_id: str) -> bool:
    components = _get_section(config, section)
    if component_id in components:
        return True
    # Allow type/id form where base type may be declared only as specific instance.
    base = component_id.split("/", 1)[0]
    return base in components


def rule_og002_top_level_sections(config: dict[str, Any], source: str) -> Iterable[Finding]:
    required = ["receivers", "exporters", "service"]
    for key in required:
        if key not in config:
            yield Finding(
                rule_id="OG002",
                severity=Severity.ERROR,
                message=f"Missing required top-level section '{key}'.",
                path=source,
                suggestion=f"Add a '{key}' section to the collector configuration.",
            )
        elif not isinstance(config.get(key), dict):
            yield Finding(
                rule_id="OG002",
                severity=Severity.ERROR,
                message=f"Top-level section '{key}' must be a mapping/object.",
                path=source,
                suggestion=f"Define '{key}' as a YAML mapping.",
            )


def rule_og003_service_pipelines(config: dict[str, Any], source: str) -> Iterable[Finding]:
    service = config.get("service")
    if not isinstance(service, dict):
        return
    pipelines = service.get("pipelines")
    if pipelines is None:
        yield Finding(
            rule_id="OG003",
            severity=Severity.ERROR,
            message="service.pipelines is missing; collector has no telemetry pipelines.",
            path=source,
            suggestion="Define at least one pipeline under service.pipelines.",
        )
        return
    if not isinstance(pipelines, dict) or not pipelines:
        yield Finding(
            rule_id="OG003",
            severity=Severity.ERROR,
            message="service.pipelines must be a non-empty mapping.",
            path=source,
            suggestion="Add pipelines such as traces, metrics, or logs under service.pipelines.",
        )
        return

    for pname, pipeline in pipelines.items():
        ppath = f"$.service.pipelines.{pname}"
        if not isinstance(pipeline, dict):
            yield Finding(
                rule_id="OG003",
                severity=Severity.ERROR,
                message=f"Pipeline '{pname}' must be a mapping/object.",
                path=source,
                suggestion=f"Define {ppath} with receivers/processors/exporters lists.",
            )
            continue
        for key in ("receivers", "exporters"):
            val = pipeline.get(key)
            if not isinstance(val, list) or not val:
                yield Finding(
                    rule_id="OG003",
                    severity=Severity.ERROR,
                    message=f"Pipeline '{pname}' must define a non-empty '{key}' list.",
                    path=source,
                    suggestion=f"Add at least one {key[:-1]} to {ppath}.{key}.",
                )
        processors = pipeline.get("processors")
        if processors is not None and not isinstance(processors, list):
            yield Finding(
                rule_id="OG003",
                severity=Severity.ERROR,
                message=f"Pipeline '{pname}' processors must be a list when present.",
                path=source,
                suggestion=f"Set {ppath}.processors to a YAML list.",
            )


def rule_og004_cross_references(config: dict[str, Any], source: str) -> Iterable[Finding]:
    service = config.get("service")
    if not isinstance(service, dict):
        return
    pipelines = service.get("pipelines")
    if not isinstance(pipelines, dict):
        return

    section_map = {
        "receivers": "receivers",
        "processors": "processors",
        "exporters": "exporters",
    }
    for pname, pipeline in pipelines.items():
        if not isinstance(pipeline, dict):
            continue
        for key, section in section_map.items():
            refs = pipeline.get(key, [])
            if not isinstance(refs, list):
                continue
            for ref in refs:
                if not isinstance(ref, str):
                    yield Finding(
                        rule_id="OG004",
                        severity=Severity.ERROR,
                        message=f"Pipeline '{pname}' has non-string {key[:-1]} reference {ref!r}.",
                        path=source,
                        suggestion="Use string component IDs in pipeline references.",
                    )
                    continue
                if not _component_exists(config, section, ref):
                    yield Finding(
                        rule_id="OG004",
                        severity=Severity.ERROR,
                        message=(
                            f"Pipeline '{pname}' references undefined {key[:-1]} '{ref}' "
                            f"in section '{section}'."
                        ),
                        path=source,
                        suggestion=(
                            f"Define '{ref}' under top-level '{section}' or fix the reference."
                        ),
                    )


def rule_og005_unused_components(config: dict[str, Any], source: str) -> Iterable[Finding]:
    service = config.get("service")
    if not isinstance(service, dict):
        return
    pipelines = service.get("pipelines")
    if not isinstance(pipelines, dict):
        return
    used: dict[str, set[str]] = {"receivers": set(), "processors": set(), "exporters": set()}
    for pipeline in pipelines.values():
        if not isinstance(pipeline, dict):
            continue
        for section in used:
            refs = pipeline.get(section, [])
            if isinstance(refs, list):
                for ref in refs:
                    if isinstance(ref, str):
                        used[section].add(ref)
    for section in ("receivers", "processors", "exporters"):
        components = _get_section(config, section)
        for comp_id in components:
            if comp_id not in used[section]:
                yield Finding(
                    rule_id="OG005",
                    severity=Severity.WARNING,
                    message=(
                        f"Component '{section}.{comp_id}' is defined but not used by any pipeline."
                    ),
                    path=source,
                    suggestion="Remove unused component or reference it in service.pipelines.",
                )


def rule_og006_memory_limiter_order(config: dict[str, Any], source: str) -> Iterable[Finding]:
    service = config.get("service")
    if not isinstance(service, dict):
        return
    pipelines = service.get("pipelines")
    if not isinstance(pipelines, dict):
        return
    for pname, pipeline in pipelines.items():
        if not isinstance(pipeline, dict):
            continue
        processors = pipeline.get("processors", [])
        if not isinstance(processors, list) or not processors:
            continue
        str_procs = [p for p in processors if isinstance(p, str)]
        ml_indices = [
            i
            for i, p in enumerate(str_procs)
            if p == "memory_limiter" or p.startswith("memory_limiter/")
        ]
        if not ml_indices:
            continue
        if ml_indices[0] != 0:
            yield Finding(
                rule_id="OG006",
                severity=Severity.WARNING,
                message=(
                    f"Pipeline '{pname}' has memory_limiter but it is not first in processors; "
                    "memory pressure protection may be ineffective."
                ),
                path=source,
                suggestion="Place memory_limiter as the first processor in the pipeline.",
            )


def rule_og007_batch_processor(config: dict[str, Any], source: str) -> Iterable[Finding]:
    service = config.get("service")
    if not isinstance(service, dict):
        return
    pipelines = service.get("pipelines")
    if not isinstance(pipelines, dict):
        return
    for pname, pipeline in pipelines.items():
        if not isinstance(pipeline, dict):
            continue
        exporters = pipeline.get("exporters", [])
        processors = pipeline.get("processors", [])
        if not isinstance(exporters, list) or not exporters:
            continue
        str_procs = [p for p in processors if isinstance(p, str)]
        has_batch = any(p == "batch" or p.startswith("batch/") for p in str_procs)
        if not has_batch:
            yield Finding(
                rule_id="OG007",
                severity=Severity.WARNING,
                message=(
                    f"Pipeline '{pname}' has no batch processor; exporter calls may be inefficient."
                ),
                path=source,
                suggestion=(
                    "Add a batch processor before exporters unless you have a "
                    "measured reason not to."
                ),
            )


def rule_og008_insecure_tls(config: dict[str, Any], source: str) -> Iterable[Finding]:
    for parts, value in _walk(config):
        if not parts:
            continue
        key = parts[-1]
        if key == "insecure" and value is True:
            yield Finding(
                rule_id="OG008",
                severity=Severity.ERROR,
                message=f"Insecure TLS setting detected at {_path_str(parts)}: insecure=true.",
                path=source,
                suggestion=(
                    "Disable insecure mode and configure proper TLS certificates/verification."
                ),
            )
        if key == "insecure_skip_verify" and value is True:
            yield Finding(
                rule_id="OG008",
                severity=Severity.ERROR,
                message=(
                    f"TLS verification bypass detected at {_path_str(parts)}: "
                    "insecure_skip_verify=true."
                ),
                path=source,
                suggestion="Set insecure_skip_verify to false and trust valid CA certificates.",
            )


def rule_og009_plaintext_secrets(config: dict[str, Any], source: str) -> Iterable[Finding]:
    for parts, value in _walk(config):
        if not parts or not isinstance(value, str):
            continue
        key = parts[-1]
        if key.startswith("["):
            continue
        if not SECRET_KEY_RE.search(key):
            continue
        if not value or SENSITIVE_VALUE_RE.match(value.strip()):
            continue
        # Allow obvious placeholders that are not secret-like in tests/examples? No, be strict.
        if value.strip().lower() in {"changeme", "replace-me", "example"}:
            yield Finding(
                rule_id="OG009",
                severity=Severity.WARNING,
                message=f"Potential placeholder secret at {_path_str(parts)}.",
                path=source,
                suggestion="Use environment variable substitution like ${ENV_VAR} for secrets.",
            )
            continue
        yield Finding(
            rule_id="OG009",
            severity=Severity.ERROR,
            message=f"Potential plaintext secret at {_path_str(parts)}.",
            path=source,
            suggestion="Do not hardcode secrets; use ${ENV_VAR} or a secrets manager reference.",
        )


def rule_og010_exposed_endpoints(config: dict[str, Any], source: str) -> Iterable[Finding]:
    for parts, value in _walk(config):
        if not parts or not isinstance(value, str):
            continue
        key = parts[-1]
        if key.startswith("[") or not ENDPOINT_KEY_RE.search(key):
            continue
        v = value.strip()
        if INSECURE_ENDPOINT_RE.match(v):
            yield Finding(
                rule_id="OG010",
                severity=Severity.WARNING,
                message=f"Endpoint {_path_str(parts)} binds to all interfaces ({v}).",
                path=source,
                suggestion=(
                    "Bind to localhost or a specific private interface unless "
                    "external exposure is required."
                ),
            )


def rule_og011_receiver_auth_hint(config: dict[str, Any], source: str) -> Iterable[Finding]:
    receivers = _get_section(config, "receivers")
    service = config.get("service")
    pipelines = service.get("pipelines") if isinstance(service, dict) else None
    if not isinstance(pipelines, dict):
        return
    used_receivers: set[str] = set()
    for pipeline in pipelines.values():
        if isinstance(pipeline, dict) and isinstance(pipeline.get("receivers"), list):
            used_receivers.update(r for r in pipeline["receivers"] if isinstance(r, str))
    for rid in used_receivers:
        rdef = receivers.get(rid)
        if not isinstance(rdef, dict):
            continue
        base = rid.split("/", 1)[0]
        if base not in {"otlp", "otlphttp", "jaeger", "zipkin", "prometheus"}:
            continue
        protocols = rdef.get("protocols") if isinstance(rdef.get("protocols"), dict) else rdef
        has_auth = False
        if isinstance(protocols, dict):
            for pval in protocols.values():
                if isinstance(pval, dict) and "auth" in pval:
                    has_auth = True
        if "auth" in rdef:
            has_auth = True
        if not has_auth:
            # endpoint exposure makes it more important; still report as info/warn.
            exposed = any(
                isinstance(v, str) and INSECURE_ENDPOINT_RE.match(v.strip())
                for _, v in _walk(rdef)
            )
            sev = Severity.WARNING if exposed else Severity.INFO
            yield Finding(
                rule_id="OG011",
                severity=sev,
                message=f"Receiver '{rid}' has no explicit auth configuration.",
                path=source,
                suggestion=(
                    "Configure receiver authentication/authorization where supported, "
                    "especially on non-local endpoints."
                ),
            )


def rule_og012_telemetry_defaults(config: dict[str, Any], source: str) -> Iterable[Finding]:
    service = config.get("service")
    if not isinstance(service, dict):
        return
    telemetry = service.get("telemetry")
    if not isinstance(telemetry, dict):
        yield Finding(
            rule_id="OG012",
            severity=Severity.INFO,
            message="service.telemetry is not configured.",
            path=source,
            suggestion="Configure service.telemetry.metrics/logs for collector self-observability.",
        )
        return
    metrics = telemetry.get("metrics")
    if isinstance(metrics, dict):
        addr = metrics.get("address")
        if isinstance(addr, str) and INSECURE_ENDPOINT_RE.match(addr.strip()):
            yield Finding(
                rule_id="OG010",
                severity=Severity.WARNING,
                message=f"Telemetry metrics address binds to all interfaces ({addr}).",
                path=source,
                suggestion="Bind telemetry metrics to localhost or a private interface.",
            )


def rule_og013_empty_exporters(config: dict[str, Any], source: str) -> Iterable[Finding]:
    exporters = _get_section(config, "exporters")
    if "exporters" in config and not exporters:
        yield Finding(
            rule_id="OG013",
            severity=Severity.ERROR,
            message="Exporters section is present but empty or invalid.",
            path=source,
            suggestion="Define at least one exporter and reference it from a pipeline.",
        )


ALL_RULES: list[Rule] = [
    Rule(
        "OG002",
        "Required top-level sections",
        "Config must define receivers/exporters/service.",
        rule_og002_top_level_sections,
    ),
    Rule(
        "OG003",
        "Valid service pipelines",
        "Service pipelines must be present and complete.",
        rule_og003_service_pipelines,
    ),
    Rule(
        "OG004",
        "Cross-reference integrity",
        "Pipeline component references must exist.",
        rule_og004_cross_references,
    ),
    Rule(
        "OG005",
        "Unused components",
        "Defined components should be referenced by pipelines.",
        rule_og005_unused_components,
    ),
    Rule(
        "OG006",
        "Memory limiter ordering",
        "memory_limiter should be first processor.",
        rule_og006_memory_limiter_order,
    ),
    Rule(
        "OG007",
        "Batch processor recommendation",
        "Pipelines should usually include batch processor.",
        rule_og007_batch_processor,
    ),
    Rule(
        "OG008",
        "Insecure TLS",
        "TLS verification must not be disabled.",
        rule_og008_insecure_tls,
    ),
    Rule(
        "OG009",
        "Plaintext secrets",
        "Secrets must not be hardcoded in config.",
        rule_og009_plaintext_secrets,
    ),
    Rule(
        "OG010",
        "Exposed endpoints",
        "Avoid binding sensitive endpoints to all interfaces.",
        rule_og010_exposed_endpoints,
    ),
    Rule(
        "OG011",
        "Receiver auth hint",
        "Receivers should have explicit auth where possible.",
        rule_og011_receiver_auth_hint,
    ),
    Rule(
        "OG012",
        "Collector self-telemetry",
        "Service telemetry should be configured.",
        rule_og012_telemetry_defaults,
    ),
    Rule(
        "OG013",
        "Empty exporters",
        "Exporters section must contain exporters.",
        rule_og013_empty_exporters,
    ),
]


def run_rules(config: dict[str, Any], source: str) -> list[Finding]:
    """Run all static rules against a config."""
    findings: list[Finding] = []
    for rule in ALL_RULES:
        findings.extend(rule.fn(config, source))
    return findings
