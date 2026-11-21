"""Loader tests for baysoz-otelgate.

Built by Baysöz Labs <baysozlabs@proton.me>.
"""

from baysoz_otelgate.loader import load_yaml


def test_load_valid_yaml() -> None:
    result = load_yaml("receivers: {}\nexporters: {}\nservice: {}\n", source="test.yaml")
    assert not result.findings
    assert isinstance(result.data, dict)
    assert "receivers" in result.data


def test_duplicate_key_reports_og001() -> None:
    text = "receivers:\n  otlp: {}\n  otlp: {}\n"
    result = load_yaml(text, source="dup.yaml")
    assert result.data is None
    assert any(f.rule_id == "OG001" for f in result.findings)
    assert "duplicate key" in result.findings[0].message.lower()


def test_non_mapping_reports_og002() -> None:
    result = load_yaml("- a\n- b\n", source="list.yaml")
    assert result.data is None
    assert any(f.rule_id == "OG002" for f in result.findings)


def test_invalid_yaml_reports_og001() -> None:
    result = load_yaml("receivers: [\n", source="bad.yaml")
    assert result.data is None
    assert result.findings[0].rule_id == "OG001"
