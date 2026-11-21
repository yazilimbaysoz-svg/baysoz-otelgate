# Plan - baysoz-otelgate

**Baysöz Labs** (`baysozlabs@proton.me`)

## Goal

Deliver a production-grade, offline CLI/library that statically validates OpenTelemetry Collector configs for security and reliability footguns, with CI-friendly outputs.

## Milestones

- [x] Inspect existing repos and mine ecosystem gaps.
- [x] Define scope: static policy gate, not runtime distro validator.
- [x] Scaffold Python 3.13 package with enterprise docs and CI.
- [x] Implement YAML loader with duplicate-key detection.
- [x] Implement OG rule pack: structure, cross-refs, TLS/secrets, endpoint exposure, processor hygiene.
- [x] Implement text/JSON/SARIF formatters and CLI exit policy.
- [x] Add pytest suite covering loader, rules, CLI, formatters.
- [x] Run ruff + pytest + semgrep; fix findings.
- [x] Run live adversarial CLI smoke tests.
- [x] Publish to GitHub and record factory result JSON.

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| False positives on component-specific schemas | Limit rules to high-confidence semantic/security invariants |
| YAML alias bombs / unsafe load | Use SafeLoader subclass; no unsafe constructors |
| Secret detection over-reporting | Match key names + ignore env substitutions; severity/message tuned |
| CI noise | `--fail-on` and severity levels; SARIF for code scanning |
