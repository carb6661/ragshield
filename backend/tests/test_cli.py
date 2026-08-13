import json

from app.cli import main


def test_cli_hardened_profile_passes(capsys):
    assert main(["--profile", "demo-hardened", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["score"] == 100
    assert payload["failed"] == 0


def test_cli_vulnerable_profile_fails_policy(capsys):
    assert main(["--profile", "demo-vulnerable", "--format", "sarif"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["runs"][0]["results"]) == 6


def test_cli_writes_markdown_report(tmp_path, capsys):
    output = tmp_path / "report.md"
    exit_code = main(
        [
            "--profile",
            "demo-vulnerable",
            "--format",
            "markdown",
            "--output",
            str(output),
            "--fail-on",
            "never",
        ]
    )
    assert exit_code == 0
    assert "RAGShield Security Report" in output.read_text(encoding="utf-8")
    assert "Wrote markdown report" in capsys.readouterr().err


def test_cli_requires_endpoint_for_http_target(capsys):
    assert main(["--profile", "authorized-http"]) == 2
    assert "--endpoint is required" in capsys.readouterr().err


def test_cli_rejects_invalid_control_pack(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text("{}", encoding="utf-8")
    assert main(["--control-pack", str(path)]) == 2
    assert "controls array" in capsys.readouterr().err

