# Market Research - baysoz-otelgate

**Baysöz Labs** (`baysozlabs@proton.me`)  
Date: 2026-11-21

## Problem Statement

OpenTelemetry Collector configuration is a high-impact control plane for telemetry pipelines. Small config mistakes cause silent data loss, security exposure, runaway resource usage, and expensive incident response. The ecosystem has strong runtime components, but static pre-deploy validation is fragmented.

## Evidence Mined

### Existing repos inspected

- `/home/runner/work/_temp/existing-repos.json` shows no existing Baysöz Labs project focused on OpenTelemetry Collector config policy gating. Closest adjacent projects are `baysoz-cardinalis` (cardinality risk) and `baysoz-logmask` (PII masking), but neither validates collector config semantics or CI policy.
- GitHub search via `gh api` (2026-11-21) for `opentelemetry collector config validator` returned mostly small/early repos:
  - `s3onghyun/otelcol-doctor` (Shell, 8 stars) - skill/helper around config writing; not a CI policy gate with SARIF and deterministic static rules.
  - `buhtik/otel-config-validator` (JS, 0 stars) - web UI validator; not CLI-first CI gate.
  - `OllyStack/validate-otel-config` (Shell, 0 stars) - wraps real collector binary; catches runtime parse/validation but does not provide opinionated security/policy lint rules, SARIF, or static semantic checks independent of collector binary availability.
  - `gateway-observability-starter` (Python, 0 stars) - starter configs; not a reusable linter.

### Live issue signals

GitHub issue search surfaced real collector config pain:

- `open-telemetry/opentelemetry-collector-contrib#50153` - supervisor validation passed while effective config masked a broken remote config; collector later restart-looped. Shows validation gaps and dangerous false positives.
- `open-telemetry/opentelemetry-collector-contrib#47039` - default config fails round-trip validation due to empty component IDs.
- `open-telemetry/opentelemetry-collector-contrib#41282` - `validate` command requires local Kubernetes API access for kubeletstats, making CI/local validation painful.
- `open-telemetry/opentelemetry-collector-contrib#39299` - users need validation before running; core `otelcol validate` only validates components compiled into that distribution.
- `open-telemetry/opentelemetry-collector-contrib#42293` - loadbalancing exporter validation fails in environments without expected runtime dependencies.

## Gap

There is room for a **static, dependency-light, CI-native policy gate** that:

1. Validates structure and cross-references without requiring a running collector distro or cluster credentials.
2. Detects risky but syntactically plausible configs: plaintext secrets, insecure TLS, exposed endpoints, missing memory_limiter/batch ordering, unused components.
3. Emits machine-readable SARIF/JSON for GitHub code scanning and CI gates.
4. Runs offline in seconds with zero heavy services.

## Product Decision

Build **baysoz-otelgate**: a Python 3.13+ CLI/library by Baysöz Labs for static OpenTelemetry Collector config policy checks. It complements, not replaces, `otelcol validate`: runtime validation catches distro-specific component schemas; otelgate catches semantic/policy/security footguns early and portably.

## Target Users

- Platform/SRE teams reviewing collector config PRs.
- Security teams enforcing no-plaintext-secrets/insecure-TLS policies.
- CI pipelines needing deterministic pass/fail and SARIF output.
- Developers generating or editing collector configs before deployment.

## Non-goals

- Full schema emulation of every contrib component.
- Running or spawning collector binaries.
- Remote SaaS, telemetry upload, or LLM-based analysis.
