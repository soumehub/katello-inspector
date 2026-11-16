"""Interface en ligne de commande : sous-commandes, options, codes retour.

Un gestionnaire central convertit toute erreur en code retour conforme au
cadrage, pour deux pieges d'argparse et des exceptions non interceptees :
- argparse renvoie 2 par defaut sur une erreur d'usage (CRITICAL pour une
  supervision) ;
- une exception non interceptee renverrait 1 (WARNING pour une supervision).
En mode --monitoring, les deux doivent donner 3 (UNKNOWN), jamais 1 ni 2.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from typing import Any, Callable

from . import __version__
from .api import ApiClient, BaseApiClient, FixtureClient
from .config import Config, build_config
from .exceptions import ApiError, ConfigError, InspectorError, UsageError

SCHEMA_VERSION = "1"

_NAGIOS_CODES = {"OK": 0, "WARN": 1, "CRIT": 2, "UNKNOWN": 3}


class _StrictArgumentParser(argparse.ArgumentParser):
    """Leve une exception sur une erreur d'usage au lieu d'appeler sys.exit(2)."""

    def error(self, message: str) -> None:  # type: ignore[override]
        raise UsageError(message)


def _build_global_parent() -> _StrictArgumentParser:
    # default=SUPPRESS partout : ces options sont partagees entre le parseur
    # principal et chaque sous-commande (pour fonctionner avant ou apres le nom
    # de la sous-commande). Un vrai defaut y ferait perdre une valeur deja
    # fixee avant la sous-commande, qui reparse dans un namespace separe et
    # ecrase ensuite le namespace principal (cf. argparse._SubParsersAction).
    parent = _StrictArgumentParser(add_help=False)
    parent.add_argument("--config", default=argparse.SUPPRESS)
    parent.add_argument("--url", default=argparse.SUPPRESS)
    parent.add_argument("--org", dest="org", default=argparse.SUPPRESS)
    parent.add_argument("--token-file", dest="token_file", default=argparse.SUPPRESS)
    parent.add_argument("--ca-file", dest="ca_file", default=argparse.SUPPRESS)
    parent.add_argument("--insecure", action="store_true", default=argparse.SUPPRESS)
    parent.add_argument("--format", choices=("text", "json"), default=argparse.SUPPRESS)
    parent.add_argument("--monitoring", action="store_true", default=argparse.SUPPRESS)
    parent.add_argument("--no-color", dest="no_color", action="store_true", default=argparse.SUPPRESS)
    parent.add_argument("--timeout", type=float, default=argparse.SUPPRESS)
    parent.add_argument("--capsule", default=argparse.SUPPRESS)  # reserve, sans effet en v1
    parent.add_argument("--fixtures", dest="fixtures", default=argparse.SUPPRESS)
    parent.add_argument("--checkin-days", dest="checkin_days", type=int, default=argparse.SUPPRESS)
    parent.add_argument("--security-warn", dest="security_warn", type=int, default=argparse.SUPPRESS)
    parent.add_argument("--security-crit", dest="security_crit", type=int, default=argparse.SUPPRESS)
    return parent


def _not_implemented(name: str) -> Callable[[argparse.Namespace], int]:
    def _run(args: argparse.Namespace) -> int:
        raise InspectorError(f"sous-commande '{name}' pas encore implementee")

    return _run


def build_parser() -> argparse.ArgumentParser:
    global_parent = _build_global_parent()
    parser = _StrictArgumentParser(prog="katello-inspector", parents=[global_parent])
    subparsers = parser.add_subparsers(dest="command", required=True, parser_class=_StrictArgumentParser)

    version_parser = subparsers.add_parser("version", parents=[global_parent])
    version_parser.set_defaults(func=_cmd_version)

    summary_parser = subparsers.add_parser("summary", parents=[global_parent])
    summary_parser.add_argument("--by-lce", action="store_true")
    summary_parser.set_defaults(func=_not_implemented("summary"))

    list_parser = subparsers.add_parser("list", parents=[global_parent])
    list_parser.add_argument("--lce")
    list_parser.add_argument("--cv")
    list_parser.add_argument("--hostgroup")
    list_parser.add_argument("--problems-only", action="store_true")
    list_parser.add_argument("--search")
    list_parser.add_argument("--sort", choices=("nom", "check-in", "errata"))
    list_parser.add_argument("--limit", type=int)
    list_parser.set_defaults(func=_not_implemented("list"))

    content_parser = subparsers.add_parser("content", parents=[global_parent])
    content_parser.add_argument("--stale-only", action="store_true")
    content_parser.set_defaults(func=_not_implemented("content"))

    host_parser = subparsers.add_parser("host", parents=[global_parent])
    host_parser.add_argument("name")
    host_parser.set_defaults(func=_not_implemented("host"))

    return parser


def build_client(config: Config) -> BaseApiClient:
    if config.fixtures_dir:
        return FixtureClient(config.fixtures_dir, page_size=config.page_size)
    if not config.url:
        raise ConfigError("adresse du serveur manquante (--url, KATELLO_INSPECTOR_URL ou [server] url)")
    if not config.user:
        raise ConfigError("compte d'authentification manquant ([auth] user ou KATELLO_INSPECTOR_USER)")
    if not config.token:
        raise ConfigError("jeton manquant (--token-file, KATELLO_INSPECTOR_TOKEN ou [auth] token_file)")
    return ApiClient(
        config.url,
        config.user,
        config.token,
        timeout=config.timeout,
        ca_file=config.ca_file,
        insecure=config.insecure,
        page_size=config.page_size,
    )


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _status_to_nagios(status: str) -> int:
    return _NAGIOS_CODES.get(status, 3)


def _build_envelope(
    *,
    command: str,
    config: Config,
    status: str,
    data: Any,
    unknown: list[dict[str, str]],
    server_extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    server: dict[str, Any] = {"url": config.url, "organization": config.organization}
    if config.insecure:
        server["tls_verified"] = False
    if server_extra:
        server.update(server_extra)
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "katello-inspector", "version": __version__},
        "generated_at": _now_iso(),
        "command": command,
        "server": server,
        "status": status,
        "data": data,
        "unknown": unknown,
    }


def _cmd_version(args: argparse.Namespace) -> int:
    config = build_config(args)
    if config.token_warning:
        print(f"katello-inspector : {config.token_warning}", file=sys.stderr)
    client = build_client(config)

    foreman_version: str | None = None
    katello_version: str | None = None
    unknown: list[dict[str, str]] = []

    try:
        foreman_status = client.get("/api/status").data or {}
        foreman_version = foreman_status.get("version")
        if not foreman_version:
            unknown.append({"indicator": "foreman_version", "reason": "champ absent de /api/status"})
    except ApiError as exc:
        unknown.append({"indicator": "foreman_version", "reason": str(exc)})

    try:
        katello_status = client.get("/katello/api/status").data or {}
        katello_version = katello_status.get("version")
        if not katello_version:
            unknown.append({"indicator": "katello_version", "reason": "champ absent de /katello/api/status"})
    except ApiError as exc:
        unknown.append({"indicator": "katello_version", "reason": str(exc)})

    status = "UNKNOWN" if unknown else "OK"

    envelope = _build_envelope(
        command="version",
        config=config,
        status=status,
        data={},
        unknown=unknown,
        server_extra={"foreman_version": foreman_version, "katello_version": katello_version},
    )

    monitoring = bool(getattr(args, "monitoring", False))
    output_format = getattr(args, "format", "text")

    if monitoring or output_format == "json":
        print(json.dumps(envelope, ensure_ascii=False))
    else:
        print(f"katello-inspector {__version__}")
        print(f"Foreman : {foreman_version or '?'}")
        print(f"Katello : {katello_version or '?'}")
        if config.insecure:
            print("TLS non verifie (--insecure)")

    if monitoring:
        return _status_to_nagios(status)
    return 0


def _report_failure(message: str, *, monitoring: bool, manual_code: int) -> int:
    print(f"katello-inspector : {message}", file=sys.stderr)
    if not monitoring:
        return manual_code
    envelope = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "katello-inspector", "version": __version__},
        "generated_at": _now_iso(),
        "status": "UNKNOWN",
        "unknown": [{"indicator": "tool", "reason": message}],
    }
    print(json.dumps(envelope, ensure_ascii=False))
    return 3


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    monitoring_hint = "--monitoring" in raw_argv

    try:
        parser = build_parser()
        args = parser.parse_args(raw_argv)
    except UsageError as exc:
        return _report_failure(str(exc), monitoring=monitoring_hint, manual_code=2)

    monitoring = bool(getattr(args, "monitoring", False))

    try:
        return int(args.func(args))
    except UsageError as exc:
        return _report_failure(str(exc), monitoring=monitoring, manual_code=2)
    except ApiError as exc:
        return _report_failure(str(exc), monitoring=monitoring, manual_code=1)
    except InspectorError as exc:
        return _report_failure(str(exc), monitoring=monitoring, manual_code=1)
    except Exception as exc:  # garde-fou : jamais de code retour non maitrise
        return _report_failure(f"erreur inattendue : {exc}", monitoring=monitoring, manual_code=1)


def run() -> None:
    sys.exit(main())


if __name__ == "__main__":
    run()
