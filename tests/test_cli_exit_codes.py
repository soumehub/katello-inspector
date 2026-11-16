from __future__ import annotations

import json
from pathlib import Path

import pytest

from katello_inspector.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_help_exits_zero() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0


def test_missing_subcommand_is_usage_error_manual() -> None:
    assert main([]) == 2


def test_missing_subcommand_is_unknown_in_monitoring() -> None:
    assert main(["--monitoring"]) == 3


def test_unknown_option_is_usage_error_manual(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["summary", "--bogus-option"])
    assert code == 2
    assert capsys.readouterr().out == ""


def test_unknown_option_detected_as_monitoring_before_argparse(capsys: pytest.CaptureFixture[str]) -> None:
    # --monitoring doit etre repere avant meme que l'analyse des arguments echoue,
    # pour convertir le code 2 d'argparse en 3 (convention Nagios UNKNOWN).
    code = main(["--monitoring", "summary", "--bogus-option"])
    assert code == 3
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["status"] == "UNKNOWN"


def test_not_implemented_command_manual(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["summary"])
    assert code == 1
    assert "pas encore implementee" in capsys.readouterr().err


def test_not_implemented_command_monitoring(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--monitoring", "list"])
    assert code == 3
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["status"] == "UNKNOWN"


def test_version_command_success_manual(capsys: pytest.CaptureFixture[str]) -> None:
    fixtures_dir = str(FIXTURES_DIR / "version_ok")
    code = main(["version", "--fixtures", fixtures_dir])
    assert code == 0
    out = capsys.readouterr().out
    assert "3.19.1" in out
    assert "4.21.1.1" in out


def test_version_command_success_monitoring(capsys: pytest.CaptureFixture[str]) -> None:
    fixtures_dir = str(FIXTURES_DIR / "version_ok")
    code = main(["--monitoring", "version", "--fixtures", fixtures_dir])
    assert code == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["status"] == "OK"


def test_version_command_missing_field_is_unknown_monitoring(capsys: pytest.CaptureFixture[str]) -> None:
    fixtures_dir = str(FIXTURES_DIR / "version_missing")
    code = main(["--monitoring", "version", "--fixtures", fixtures_dir])
    assert code == 3
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["status"] == "UNKNOWN"
    assert payload["server"]["foreman_version"] == "3.19.1"
    assert payload["server"]["katello_version"] is None


def test_version_format_json_manual_mode_still_returns_zero(capsys: pytest.CaptureFixture[str]) -> None:
    fixtures_dir = str(FIXTURES_DIR / "version_missing")
    code = main(["version", "--fixtures", fixtures_dir, "--format", "json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["status"] == "UNKNOWN"


def test_insecure_flag_reported_in_json_envelope(capsys: pytest.CaptureFixture[str]) -> None:
    fixtures_dir = str(FIXTURES_DIR / "version_ok")
    main(["version", "--fixtures", fixtures_dir, "--format", "json", "--insecure"])
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["server"]["tls_verified"] is False


def test_token_never_leaks_through_cli(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("KATELLO_INSPECTOR_TOKEN", "s3cr3t-cli")
    monkeypatch.setenv("KATELLO_INSPECTOR_USER", "inspector-ro")
    # Hote invalide (RFC 2606) : l'appel reseau echoue, mais la commande se
    # degrade en UNKNOWN au lieu de planter (le code retour manuel reste 0,
    # seul le statut constate est UNKNOWN).
    code = main(["version", "--url", "https://host.invalid.example", "--timeout", "2"])
    assert code == 0
    captured = capsys.readouterr()
    assert "s3cr3t-cli" not in captured.out
    assert "s3cr3t-cli" not in captured.err
