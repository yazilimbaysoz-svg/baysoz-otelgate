# Security Policy - baysoz-otelgate

**Baysöz Labs** (`baysozlabs@proton.me`)

## Supported Version

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes |

## Reporting a Vulnerability

Report security issues privately to **Baysöz Labs** at `baysozlabs@proton.me`. Include:

- affected version/commit
- reproduction steps or proof-of-concept config
- impact assessment
- suggested remediation if available

We aim to acknowledge reports within 3 business days.

## Security Design

- Uses PyYAML `SafeLoader` subclass; does not use unsafe YAML loading.
- No command execution, no network calls, no telemetry exfiltration.
- File reads are local and explicit; output is written only when `--output` is requested.
- Rule engine is deterministic and operates on parsed in-memory data.

## Secure Development Controls

- `ruff` with security rules (`S`, `B`) in CI.
- `semgrep --config p/default --error`.
- Pytest suite includes adversarial parsing and security rule cases.
- Dependencies are minimal (`PyYAML` only at runtime).
