"""Formatter tests for baysoz-otelgate.

Built by Baysöz Labs <baysozlabs@proton.me>.
"""

import json

from baysoz_otelgate.analyzer import analyze_text
from baysoz_otelgate.formatters import render_json, render_sarif, render_text


BAD = """
receivers: {otlp: {}}
exporters:
  otlp:
    tls:
      insecure: true
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [otlp]
"""


def test_text_contains_vendor() -> None:
    result = analyze_text(BAD, source="bad.yaml")
    out = render_text([result])
    assert "Baysöz Labs" in out
    assert "Gate: FAIL" in out


def test_json_contains_vendor() -> None:
    result = analyze_text(BAD, source="bad.yaml")
    payload = json.loads(render_json([result]))
    assert payload["tool"]["vendor"] == "Baysöz Labs"
    assert payload["tool"]["contact"] == "baysozlabs@proton.me"


def test_sarif_shape() -> None:
    result = analyze_text(BAD, source="bad.yaml")
    payload = json.loads(render_sarif([result]))
    assert payload["$schema"].endswith("sarif-2.1.0.json")
    assert payload["runs"][0]["results"]
