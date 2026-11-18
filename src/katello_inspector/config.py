"""Configuration : fichier INI, variables d'environnement, priorites.

Priorite pour chaque parametre : option en ligne de commande, variable
`KATELLO_INSPECTOR_*`, fichier INI, valeur par defaut. Exception : `--insecure`
doit etre explicite a chaque appel (voir docs/cadrage.md), il n'est donc jamais lu
depuis l'environnement ou le fichier INI.
"""
from __future__ import annotations

import configparser
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .exceptions import ConfigError

ENV_PREFIX = "KATELLO_INSPECTOR_"

DEFAULT_THRESHOLDS: dict[str, int] = {
    "checkin_days": 7,
    "security_warn": 1,
    "security_crit": 10,
    "stale_publish_days": 14,
    "cv_lag_warn_days": 14,
    "cv_lag_crit_days": 45,
    "disk_warn_pct": 20,
    "disk_crit_pct": 10,
}

DEFAULT_TIMEOUT = 30.0
DEFAULT_PAGE_SIZE = 200

CONFIG_SEARCH_PATHS = (
    "~/.config/katello-inspector/config.ini",
    "/etc/katello-inspector/config.ini",
)


@dataclass
class ThresholdSet:
    checkin_days: int = DEFAULT_THRESHOLDS["checkin_days"]
    security_warn: int = DEFAULT_THRESHOLDS["security_warn"]
    security_crit: int = DEFAULT_THRESHOLDS["security_crit"]
    stale_publish_days: int = DEFAULT_THRESHOLDS["stale_publish_days"]
    cv_lag_warn_days: int = DEFAULT_THRESHOLDS["cv_lag_warn_days"]
    cv_lag_crit_days: int = DEFAULT_THRESHOLDS["cv_lag_crit_days"]
    disk_warn_pct: int = DEFAULT_THRESHOLDS["disk_warn_pct"]
    disk_crit_pct: int = DEFAULT_THRESHOLDS["disk_crit_pct"]


@dataclass
class Config:
    url: str | None
    organization: str | None
    ca_file: str | None
    insecure: bool
    timeout: float
    page_size: int
    user: str | None
    token: str | None
    thresholds: ThresholdSet
    lce_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)
    cv_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)
    color: str = "auto"
    fixtures_dir: str | None = None
    token_warning: str | None = None

    def __repr__(self) -> str:  # le jeton ne doit jamais apparaitre, meme en debogage
        return (
            f"Config(url={self.url!r}, organization={self.organization!r}, "
            f"user={self.user!r}, token=<masque>, insecure={self.insecure!r})"
        )


def find_config_file(cli_value: str | None) -> Path | None:
    if cli_value:
        path = Path(cli_value)
        if not path.is_file():
            raise ConfigError(f"fichier de configuration introuvable : {cli_value}")
        return path
    env_value = os.environ.get(ENV_PREFIX + "CONFIG")
    if env_value:
        path = Path(env_value)
        if not path.is_file():
            raise ConfigError(f"fichier de configuration introuvable : {env_value}")
        return path
    for raw in CONFIG_SEARCH_PATHS:
        path = Path(raw).expanduser()
        if path.is_file():
            return path
    return None


def load_ini(path: Path | None) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    if path is not None:
        try:
            with path.open("r", encoding="utf-8") as fh:
                parser.read_file(fh)
        except (OSError, configparser.Error) as exc:
            raise ConfigError(f"fichier de configuration invalide ({path}) : {exc}") from exc
    return parser


def _resolve_str(cli_value: str | None, env_name: str, ini_value: str | None, default: str | None = None) -> str | None:
    if cli_value:
        return cli_value
    env_value = os.environ.get(ENV_PREFIX + env_name)
    if env_value:
        return env_value
    if ini_value:
        return ini_value
    return default


def _resolve_int(
    cli_value: int | None,
    env_name: str,
    ini_value: str | None,
    default: int,
    *,
    minimum: int | None = None,
) -> int:
    raw: Any = cli_value
    if raw is None:
        raw = os.environ.get(ENV_PREFIX + env_name)
    if raw is None:
        raw = ini_value
    if raw is None:
        return default
    if isinstance(raw, bool):
        raise ConfigError(f"valeur numerique attendue pour {env_name} : {raw!r}")
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"valeur numerique attendue pour {env_name} : {raw!r}") from exc
    if minimum is not None and value < minimum:
        raise ConfigError(f"{env_name} doit etre superieur ou egal a {minimum} (recu {value})")
    return value


def _resolve_float(cli_value: float | None, env_name: str, ini_value: str | None, default: float) -> float:
    raw: Any = cli_value
    if raw is None:
        raw = os.environ.get(ENV_PREFIX + env_name)
    if raw is None:
        raw = ini_value
    if raw is None:
        return default
    try:
        return float(raw)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"valeur numerique attendue pour {env_name} : {raw!r}") from exc


def _parse_overrides(parser: configparser.ConfigParser, prefix: str) -> dict[str, dict[str, Any]]:
    overrides: dict[str, dict[str, Any]] = {}
    for section in parser.sections():
        if not section.startswith(prefix):
            continue
        name = section[len(prefix) :]
        values: dict[str, Any] = {}
        for key, raw in parser.items(section):
            if key == "cv_lag_check":
                values[key] = parser.getboolean(section, key)
            else:
                try:
                    values[key] = int(raw)
                except ValueError as exc:
                    raise ConfigError(f"valeur numerique attendue pour [{section}] {key} : {raw!r}") from exc
        overrides[name] = values
    return overrides


def _check_token_file_permissions(path: Path, *, monitoring: bool) -> str | None:
    mode = path.stat().st_mode
    readable_by_others = bool(mode & (stat.S_IRGRP | stat.S_IROTH))
    writable_by_others = bool(mode & (stat.S_IWGRP | stat.S_IWOTH))
    if writable_by_others and monitoring:
        raise ConfigError(
            f"le fichier de jeton {path} est accessible en ecriture par le groupe ou par "
            "tous, refus de demarrer en mode monitoring"
        )
    if readable_by_others or writable_by_others:
        return f"le fichier de jeton {path} est accessible au-dela de son proprietaire"
    return None


def _resolve_token(
    args: Any, parser: configparser.ConfigParser, *, monitoring: bool
) -> tuple[str | None, str | None]:
    token_file_value = getattr(args, "token_file", None) or os.environ.get(ENV_PREFIX + "TOKEN_FILE")
    if not token_file_value and parser.has_option("auth", "token_file"):
        token_file_value = parser.get("auth", "token_file")
    if token_file_value:
        path = Path(token_file_value)
        if not path.is_file():
            raise ConfigError(f"fichier de jeton introuvable : {token_file_value}")
        warning = _check_token_file_permissions(path, monitoring=monitoring)
        token = path.read_text(encoding="utf-8").strip()
        return token, warning
    env_token = os.environ.get(ENV_PREFIX + "TOKEN")
    if env_token:
        return env_token, None
    return None, None


def _validate_warn_crit(warn: int, crit: int, *, label: str) -> None:
    if warn > crit:
        raise ConfigError(f"{label} : le seuil WARN ({warn}) ne peut pas depasser le seuil CRIT ({crit})")


def _validate_override_sections(overrides: dict[str, dict[str, Any]], *, prefix: str) -> None:
    for name, values in overrides.items():
        if "cv_lag_warn_days" in values and "cv_lag_crit_days" in values:
            _validate_warn_crit(
                values["cv_lag_warn_days"],
                values["cv_lag_crit_days"],
                label=f"[{prefix}:{name}] cv_lag_warn_days/cv_lag_crit_days",
            )


def build_config(args: Any) -> Config:
    monitoring = bool(getattr(args, "monitoring", False))
    config_path = find_config_file(getattr(args, "config", None))
    parser = load_ini(config_path)

    url = _resolve_str(getattr(args, "url", None), "URL", parser.get("server", "url", fallback=None))
    organization = _resolve_str(
        getattr(args, "org", None), "ORG", parser.get("server", "organization", fallback=None)
    )
    ca_file = _resolve_str(
        getattr(args, "ca_file", None), "CA_FILE", parser.get("server", "ca_file", fallback=None)
    )
    insecure = bool(getattr(args, "insecure", False))
    timeout = _resolve_float(
        getattr(args, "timeout", None), "TIMEOUT", parser.get("server", "timeout", fallback=None), DEFAULT_TIMEOUT
    )
    page_size = _resolve_int(
        None, "PAGE_SIZE", parser.get("server", "page_size", fallback=None), DEFAULT_PAGE_SIZE, minimum=1
    )
    user = _resolve_str(None, "USER", parser.get("auth", "user", fallback=None))

    token, token_warning = _resolve_token(args, parser, monitoring=monitoring)

    thresholds = ThresholdSet(
        checkin_days=_resolve_int(
            getattr(args, "checkin_days", None),
            "CHECKIN_DAYS",
            parser.get("thresholds", "checkin_days", fallback=None),
            DEFAULT_THRESHOLDS["checkin_days"],
        ),
        security_warn=_resolve_int(
            getattr(args, "security_warn", None),
            "SECURITY_WARN",
            parser.get("thresholds", "security_warn", fallback=None),
            DEFAULT_THRESHOLDS["security_warn"],
        ),
        security_crit=_resolve_int(
            getattr(args, "security_crit", None),
            "SECURITY_CRIT",
            parser.get("thresholds", "security_crit", fallback=None),
            DEFAULT_THRESHOLDS["security_crit"],
        ),
        stale_publish_days=_resolve_int(
            None,
            "STALE_PUBLISH_DAYS",
            parser.get("thresholds", "stale_publish_days", fallback=None),
            DEFAULT_THRESHOLDS["stale_publish_days"],
        ),
        cv_lag_warn_days=_resolve_int(
            None,
            "CV_LAG_WARN_DAYS",
            parser.get("thresholds", "cv_lag_warn_days", fallback=None),
            DEFAULT_THRESHOLDS["cv_lag_warn_days"],
        ),
        cv_lag_crit_days=_resolve_int(
            None,
            "CV_LAG_CRIT_DAYS",
            parser.get("thresholds", "cv_lag_crit_days", fallback=None),
            DEFAULT_THRESHOLDS["cv_lag_crit_days"],
        ),
        disk_warn_pct=_resolve_int(
            None,
            "DISK_WARN_PCT",
            parser.get("thresholds", "disk_warn_pct", fallback=None),
            DEFAULT_THRESHOLDS["disk_warn_pct"],
        ),
        disk_crit_pct=_resolve_int(
            None,
            "DISK_CRIT_PCT",
            parser.get("thresholds", "disk_crit_pct", fallback=None),
            DEFAULT_THRESHOLDS["disk_crit_pct"],
        ),
    )

    _validate_warn_crit(thresholds.security_warn, thresholds.security_crit, label="security_warn/security_crit")
    _validate_warn_crit(
        thresholds.cv_lag_warn_days, thresholds.cv_lag_crit_days, label="cv_lag_warn_days/cv_lag_crit_days"
    )

    lce_overrides = _parse_overrides(parser, "lce:")
    cv_overrides = _parse_overrides(parser, "cv:")
    _validate_override_sections(lce_overrides, prefix="lce")
    _validate_override_sections(cv_overrides, prefix="cv")

    color = _resolve_str(None, "COLOR", parser.get("output", "color", fallback=None), "auto") or "auto"
    if getattr(args, "no_color", False) or os.environ.get("NO_COLOR"):
        color = "never"

    return Config(
        url=url,
        organization=organization,
        ca_file=ca_file,
        insecure=insecure,
        timeout=timeout,
        page_size=page_size,
        user=user,
        token=token,
        thresholds=thresholds,
        lce_overrides=lce_overrides,
        cv_overrides=cv_overrides,
        color=color,
        fixtures_dir=getattr(args, "fixtures", None),
        token_warning=token_warning,
    )


def threshold_for(config: Config, name: str, *, lce: str | None = None, cv: str | None = None) -> Any:
    """Seuil applicable, priorite [cv:NOM] puis [lce:NOM] puis [thresholds]."""
    if cv and cv in config.cv_overrides and name in config.cv_overrides[cv]:
        return config.cv_overrides[cv][name]
    if lce and lce in config.lce_overrides and name in config.lce_overrides[lce]:
        return config.lce_overrides[lce][name]
    return getattr(config.thresholds, name)


def cv_lag_enabled(config: Config, *, lce: str | None = None, cv: str | None = None) -> bool:
    """False si `cv_lag_check = false` dans la section CV ou LCE applicable (priorite CV)."""
    if cv and cv in config.cv_overrides and "cv_lag_check" in config.cv_overrides[cv]:
        return bool(config.cv_overrides[cv]["cv_lag_check"])
    if lce and lce in config.lce_overrides and "cv_lag_check" in config.lce_overrides[lce]:
        return bool(config.lce_overrides[lce]["cv_lag_check"])
    return True
