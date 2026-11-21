# Architecture - baysoz-otelgate

**Baysöz Labs** (`baysozlabs@proton.me`)

## Overview

`baysoz-otelgate` is a static analysis CLI/library for OpenTelemetry Collector YAML configurations. It performs deterministic offline checks and produces text, JSON, or SARIF reports.

## Design Principles

- **Offline & deterministic**: no network calls, no collector binary, no LLMs.
- **Safe parsing**: YAML loaded via `yaml.SafeLoader` subclass with duplicate-key detection.
- **Rule modularity**: rules are small pure functions over parsed config; easy to test and extend.
- **CI-first**: stable exit codes, machine formats, SARIF 2.1.0.
- **Zero heavy services**: pure Python + PyYAML.

## Components

```text
src/baysoz_otelgate/
  cli.py          # argparse CLI, exit codes, format/output selection
  analyzer.py     # file loading, orchestration, dedupe
  loader.py       # YAML parse + duplicate key detection + top-level type checks
  models.py       # Finding, Severity, AnalysisResult
  formatters.py   # text/json/sarif rendering
  rules/
    core.py       # built-in OGxxx rules
```

## Data Flow

1. CLI resolves file/directory inputs.
2. `analyzer` reads UTF-8 text and calls `loader`.
3. `loader` parses YAML, detects duplicate keys, validates top-level mapping.
4. `rules.run_rules` executes built-in static rules.
5. Findings are deduped and formatted.
6. CLI exits based on `--fail-on` policy.

## Rule Model

Each rule emits `Finding(rule_id, severity, message, path, line?, column?, suggestion)`. Rules are intentionally conservative: they favor high-signal security/semantic checks over distro-specific schema guessing.

## Security Model

- No `yaml.load` unsafe loader.
- No shell execution of user config.
- No network egress.
- Secrets detection is pattern-based and redacts nothing into external systems; it only reports locations/messages.
- SARIF/output includes rule IDs and messages, not secret values beyond the original config line context already provided by user files.

## Extensibility

Future rule packs can be added under `rules/` and registered in `ALL_RULES`. A plugin interface can be added later without breaking CLI contract.
