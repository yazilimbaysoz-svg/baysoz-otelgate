"""Rule behavior tests for baysoz-otelgate.

Built by Baysöz Labs <baysozlabs@proton.me>.
"""

from pathlib import Path

from baysoz_otelgate.analyzer import analyze_file, analyze_text

FIXTURES = Path(__file__).parent / "fixtures"


def _rule_ids(text: str) -> set[str]:
    result = analyze_text(text, source="inline.yaml")
    return {f.rule_id for f in result.findings}


def test_valid_fixture_has_no_errors() -> None:
    result = analyze_file(FIXTURES / "valid_collector.yaml")
    assert result.parsed
    assert result.ok, result.to_dict()
    # May have INFO findings, but no errors
    assert not result.errors


def test_bad_fixture_reports_expected_errors() -> None:
    result = analyze_file(FIXTURES / "bad_collector.yaml")
    ids = {f.rule_id for f in result.findings}
    assert "OG004" in ids  # missing component refs
    assert "OG006" in ids  # memory_limiter not first
    assert "OG008" in ids  # insecure tls
    assert "OG009" in ids  # plaintext secret
    assert "OG010" in ids  # 0.0.0.0 endpoint


def test_missing_sections() -> None:
    ids = _rule_ids("processors: {}\n")
    assert "OG002" in ids


def test_missing_pipelines() -> None:
    ids = _rule_ids("receivers: {}\nexporters: {}\nservice: {}\n")
    assert "OG003" in ids


def test_unused_component_warning() -> None:
    text = """
receivers:
  otlp: {}
  jaeger: {}
exporters:
  debug: {}
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [debug]
"""
    result = analyze_text(text, source="unused.yaml")
    og005 = [f for f in result.findings if f.rule_id == "OG005"]
    assert any("jaeger" in f.message for f in og005)


def test_batch_recommendation() -> None:
    text = """
receivers:
  otlp: {}
exporters:
  debug: {}
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [debug]
"""
    ids = _rule_ids(text)
    assert "OG007" in ids


def test_env_secret_not_flagged() -> None:
    text = """
receivers:
  otlp: {}
exporters:
  otlp:
    headers:
      api_key: ${OTEL_API_KEY}
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [otlp]
"""
    result = analyze_text(text, source="env.yaml")
    assert not any(f.rule_id == "OG009" for f in result.findings)


def test_insecure_skip_verify_flagged() -> None:
    text = """
receivers: {otlp: {}}
exporters:
  otlp:
    tls:
      insecure_skip_verify: true
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [otlp]
"""
    ids = _rule_ids(text)
    assert "OG008" in ids
