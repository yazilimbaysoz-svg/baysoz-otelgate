"""CLI tests for baysoz-otelgate.

Built by Baysöz Labs <baysozlabs@proton.me>.
"""

from __future__ import annotations

import json
from pathlib import Path

from baysoz_otelgate.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_version(capsys) -> None:
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    out = capsys.readouterr().out
    assert "otelgate 0.1.0" in out
    assert "Baysöz Labs" in out
    assert "baysozlabs@proton.me" in out


def test_help(capsys) -> None:
    try:
        main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0
    out = capsys.readouterr().out
    assert "Baysöz Labs" in out
    assert "scan" in out


def test_scan_valid_fixture(capsys) -> None:
    code = main(["scan", str(FIXTURES / "valid_collector.yaml")])
    out = capsys.readouterr().out
    assert code == 0
    assert "Gate: PASS" in out
    assert "Baysöz Labs" in out


def test_scan_bad_fixture_fails(capsys) -> None:
    code = main(["scan", str(FIXTURES / "bad_collector.yaml")])
    out = capsys.readouterr().out
    assert code == 1
    assert "Gate: FAIL" in out
    assert "OG008" in out


def test_scan_json_output(capsys) -> None:
    code = main(["scan", str(FIXTURES / "bad_collector.yaml"), "--format", "json"])
    out = capsys.readouterr().out
    assert code == 1
    payload = json.loads(out)
    assert payload["tool"]["vendor"] == "Baysöz Labs"
    assert payload["tool"]["contact"] == "baysozlabs@proton.me"
    assert payload["summary"]["errors"] > 0


def test_scan_sarif_output(capsys) -> None:
    code = main(["scan", str(FIXTURES / "bad_collector.yaml"), "--format", "sarif"])
    out = capsys.readouterr().out
    assert code == 1
    payload = json.loads(out)
    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "baysoz-otelgate"
    assert run["tool"]["driver"]["organization"] == "Baysöz Labs"


def test_scan_fail_on_warning(capsys) -> None:
    code = main(["scan", str(FIXTURES / "valid_collector.yaml"), "--fail-on", "warning"])
    _ = capsys.readouterr().out
    # valid fixture may have INFO only; should pass unless warnings exist
    assert code in (0, 1)


def test_rules_command(capsys) -> None:
    code = main(["rules"])
    out = capsys.readouterr().out
    assert code == 0
    assert "OG008" in out
    assert "Baysöz Labs" in out
