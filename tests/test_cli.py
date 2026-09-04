from __future__ import annotations

import io
import json
from pathlib import Path

from mcp_discovery_sanitizer.cli import main

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_cli_clean_allow(capsys):
    code = main([str(FIXTURES / "clean_discovery.json")])
    captured = capsys.readouterr()
    assert code == 0
    payload = json.loads(captured.out)
    assert payload["verdict"] == "allow"
    assert payload["server_id"] == "weather.internal"


def test_cli_poisoned_exits_2(capsys):
    code = main([str(FIXTURES / "poisoned_instructions.json")])
    payload = json.loads(capsys.readouterr().out)
    assert code == 2
    assert payload["verdict"] == "block"
    assert any(r["code"] == "instructions_blocklist" for r in payload["reasons"])


def test_cli_fail_open_strips_poison(capsys):
    code = main(
        [
            str(FIXTURES / "poisoned_instructions.json"),
            "--no-fail-closed",
            "--policy",
            str(FIXTURES / "policy_fail_open.json"),
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["verdict"] == "allow_stripped"
    assert payload["sanitized"]["result"]["instructions"] == ""


def test_cli_trusted_server_allows_public_cache(capsys):
    code = main(
        [
            str(FIXTURES / "public_cache_untrusted.json"),
            "--trusted-server",
            "cdn-poison.example",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["verdict"] == "allow"


def test_cli_missing_file(capsys):
    code = main(["/tmp/does-not-exist-mcp-sanitizer.json"])
    assert code == 1
    assert "error:" in capsys.readouterr().err


def test_cli_stdin(monkeypatch, capsys):
    monkeypatch.setattr(
        "mcp_discovery_sanitizer.cli.sys.stdin",
        io.StringIO(json.dumps({"tools": [], "cacheScope": "private"})),
    )
    code = main(["-"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["verdict"] == "allow"


def test_cli_server_id_override(capsys):
    code = main(
        [
            str(FIXTURES / "clean_discovery.json"),
            "--server-id",
            "override.example",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["server_id"] == "override.example"
