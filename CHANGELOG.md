# Changelog

All notable changes to **baysoz-otelgate** by **Baysöz Labs** (`baysozlabs@proton.me`) are documented here.

## [0.1.0] - 2026-11-21

### Added
- Initial release of `baysoz-otelgate`, a static policy gate for OpenTelemetry Collector configs.
- YAML loader with duplicate-key detection and safe parsing.
- Core rule pack (OG001-OG013) for structure, cross-references, TLS/secrets, endpoint exposure, and processor hygiene.
- CLI with `scan` and `rules` commands, text/JSON/SARIF output, and configurable fail threshold.
- Pytest suite, ruff configuration, Semgrep-friendly codebase, and GitHub Actions CI.
- Enterprise documentation: market research, architecture, plan, security policy, README.
