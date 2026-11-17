"""Enveloppe JSON commune et codes retour du mode monitoring.

Toutes les sous-commandes partagent la meme enveloppe (`docs/cadrage.md`,
section "Sortie JSON, mode monitoring et codes retour") : seul le contenu de
`data` change d'une commande a l'autre. Les fonctions d'ici ne savent rien
des regles de statut ; elles assemblent une enveloppe deja decidee par
`analyze.py`.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

from . import __version__
from .config import Config

SCHEMA_VERSION = "1"

NAGIOS_CODES = {"OK": 0, "WARN": 1, "CRIT": 2, "UNKNOWN": 3}


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def status_to_nagios(status: str) -> int:
    return NAGIOS_CODES.get(status, 3)


def build_envelope(
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
        "generated_at": now_iso(),
        "command": command,
        "server": server,
        "status": status,
        "data": data,
        "unknown": unknown,
    }


def failure_envelope(message: str, *, command: str | None, server: dict[str, Any]) -> dict[str, Any]:
    # Memes cles que build_envelope : un consommateur JSONPath en mode
    # monitoring ne doit jamais rencontrer une forme differente parce que la
    # commande a echoue.
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "katello-inspector", "version": __version__},
        "generated_at": now_iso(),
        "command": command,
        "server": server,
        "status": "UNKNOWN",
        "data": {},
        "unknown": [{"indicator": "tool", "reason": message}],
        "error": message,
    }
