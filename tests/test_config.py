from __future__ import annotations

import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from katello_inspector import config as config_mod
from katello_inspector.config import ThresholdSet, build_config, cv_lag_enabled, threshold_for
from katello_inspector.exceptions import ConfigError


def _ini(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.ini"
    path.write_text(text, encoding="utf-8")
    return path


def test_defaults_match_cadrage() -> None:
    config = build_config(SimpleNamespace())
    assert config.thresholds == ThresholdSet(
        checkin_days=7,
        security_warn=1,
        security_crit=10,
        stale_publish_days=14,
        cv_lag_warn_days=14,
        cv_lag_crit_days=45,
        disk_warn_pct=20,
        disk_crit_pct=10,
    )
    assert config.page_size == 200
    assert config.timeout == 30.0
    assert config.insecure is False


def test_priority_cli_over_env_over_ini_over_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ini = _ini(tmp_path, "[thresholds]\ncheckin_days = 3\n")

    # Seul l'INI : la valeur de l'INI l'emporte sur le defaut.
    config = build_config(SimpleNamespace(config=str(ini)))
    assert config.thresholds.checkin_days == 3

    monkeypatch.setenv("KATELLO_INSPECTOR_CHECKIN_DAYS", "5")
    config = build_config(SimpleNamespace(config=str(ini)))
    assert config.thresholds.checkin_days == 5  # l'env l'emporte sur l'INI

    config = build_config(SimpleNamespace(config=str(ini), checkin_days=1))
    assert config.thresholds.checkin_days == 1  # l'option CLI l'emporte sur tout


def test_config_search_order(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home_config = tmp_path / "home" / "config.ini"
    etc_config = tmp_path / "etc" / "config.ini"
    home_config.parent.mkdir(parents=True)
    etc_config.parent.mkdir(parents=True)
    home_config.write_text("[server]\nurl = https://home.example.com\n", encoding="utf-8")
    etc_config.write_text("[server]\nurl = https://etc.example.com\n", encoding="utf-8")

    monkeypatch.setattr(config_mod, "CONFIG_SEARCH_PATHS", (str(home_config), str(etc_config)))
    config = build_config(SimpleNamespace())
    assert config.url == "https://home.example.com"

    home_config.unlink()
    config = build_config(SimpleNamespace())
    assert config.url == "https://etc.example.com"


def test_explicit_config_file_missing_is_usage_error() -> None:
    with pytest.raises(ConfigError):
        build_config(SimpleNamespace(config="/inexistant/config.ini"))


def test_invalid_ini_file_is_usage_error(tmp_path: Path) -> None:
    ini = tmp_path / "config.ini"
    ini.write_text("ceci n'est pas de l'ini valide [[[", encoding="utf-8")
    with pytest.raises(ConfigError):
        build_config(SimpleNamespace(config=str(ini)))


def test_threshold_priority_cv_then_lce_then_global(tmp_path: Path) -> None:
    ini = _ini(
        tmp_path,
        "[thresholds]\ncv_lag_warn_days = 14\n\n"
        "[lce:Production]\ncv_lag_warn_days = 30\n\n"
        "[cv:cv-app-tomcat]\ncv_lag_warn_days = 45\n",
    )
    config = build_config(SimpleNamespace(config=str(ini)))

    assert threshold_for(config, "cv_lag_warn_days") == 14
    assert threshold_for(config, "cv_lag_warn_days", lce="Production") == 30
    assert threshold_for(config, "cv_lag_warn_days", cv="cv-app-tomcat") == 45
    # Le couple (CV, environnement) l'emporte sur le seul environnement.
    assert threshold_for(config, "cv_lag_warn_days", lce="Production", cv="cv-app-tomcat") == 45


def test_cv_lag_check_false_disables_the_indicator(tmp_path: Path) -> None:
    ini = _ini(tmp_path, "[lce:Development]\ncv_lag_check = false\n")
    config = build_config(SimpleNamespace(config=str(ini)))
    assert cv_lag_enabled(config, lce="Development") is False
    assert cv_lag_enabled(config, lce="Production") is True


def test_token_read_from_token_file(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("un-jeton-secret\n", encoding="utf-8")
    token_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
    config = build_config(SimpleNamespace(token_file=str(token_file)))
    assert config.token == "un-jeton-secret"
    assert config.token_warning is None


def test_token_read_from_environment_variable_when_no_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KATELLO_INSPECTOR_TOKEN", "jeton-env")
    config = build_config(SimpleNamespace())
    assert config.token == "jeton-env"


def test_no_cli_option_to_pass_the_token_directly() -> None:
    args = SimpleNamespace(token="ne-doit-pas-exister")
    config = build_config(args)
    # build_config ne lit jamais args.token : seul token_file ou la variable
    # d'environnement alimentent le jeton.
    assert config.token is None


def test_token_file_readable_by_others_warns(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("secret", encoding="utf-8")
    token_file.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IROTH)
    config = build_config(SimpleNamespace(token_file=str(token_file)))
    assert config.token_warning is not None


def test_token_file_writable_by_others_refuses_monitoring(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("secret", encoding="utf-8")
    token_file.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IWOTH)
    with pytest.raises(ConfigError):
        build_config(SimpleNamespace(token_file=str(token_file), monitoring=True))
    # En mode manuel, la meme configuration n'est qu'un avertissement.
    config = build_config(SimpleNamespace(token_file=str(token_file), monitoring=False))
    assert config.token_warning is not None


def test_no_color_env_var_is_respected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    config = build_config(SimpleNamespace())
    assert config.color == "never"
