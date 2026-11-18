"""Sous-commande `summary` : sante globale, un ecran.

Assemble ici le dictionnaire `data` (meme forme pour le texte et le JSON,
voir `render_text.py`) a partir de `collect.py` et `analyze.py`. `cli.py`
construit la configuration et le client puis appelle `run`.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from typing import Any

from ..analyze import (
    FleetSummary,
    LceSummary,
    collect_unknown_entries,
    compute_by_lce,
    compute_fleet_summary,
    compute_ping_status,
    compute_pulp_disk_free_pct,
    compute_pulp_disk_status,
    compute_tasks_status,
    evaluate_host,
    worst_of,
)
from ..api import BaseApiClient
from ..collect import (
    collect_content_view_versions,
    collect_environments,
    collect_foreman_version,
    collect_hosts,
    collect_katello_version,
    collect_ping,
    collect_pulp_disk,
    collect_recent_task_failures,
    order_environments_by_promotion,
    resolve_organization,
)
from ..config import Config
from ..exceptions import ApiError, ConfigError
from ..render_json import build_envelope, status_to_nagios
from ..render_text import render_summary_text

_THRESHOLD_FIELDS = (
    "checkin_days",
    "security_warn",
    "security_crit",
    "cv_lag_warn_days",
    "cv_lag_crit_days",
    "disk_warn_pct",
    "disk_crit_pct",
)


def _fleet_dict(fleet: FleetSummary) -> dict[str, Any]:
    return {
        "total": fleet.total,
        "evaluated": fleet.evaluated,
        "na": fleet.na,
        "status_counts": fleet.status_counts,
        "update_state_counts": fleet.update_state_counts,
        "stale_data": fleet.stale_data,
        "security_installable_total": fleet.security_installable_total,
        "reboot_required": fleet.reboot_required,
        "in_build": fleet.in_build,
        "cv_lag_environments": fleet.cv_lag_environments,
    }


def _lce_dict(entry: LceSummary) -> dict[str, Any]:
    return {
        "name": entry.name,
        "vms": entry.vms,
        "status_counts": entry.status_counts,
        "update_state_counts": entry.update_state_counts,
        "security_installable_total": entry.security_installable_total,
        "security_critical_total": entry.security_critical_total,
        "stale_data_vms": entry.stale_data_vms,
        "in_build": entry.in_build,
        "max_cv_waiting_days": entry.max_cv_waiting_days,
        "status": entry.status,
    }


def build_data(
    args: argparse.Namespace, config: Config, client: BaseApiClient
) -> tuple[dict[str, Any], str, list[dict[str, str]]]:
    if not config.organization:
        raise ConfigError("organisation manquante (--org, KATELLO_INSPECTOR_ORG ou [server] organization)")
    org = resolve_organization(client, config.organization)

    unknown: list[dict[str, str]] = []
    platform: dict[str, Any] = {}
    statuses: list[str] = []

    try:
        ping = collect_ping(client)
        platform["ping"] = {"status": compute_ping_status(ping), "services": ping.services}
        statuses.append(platform["ping"]["status"])
    except ApiError as exc:
        platform["ping"] = None
        unknown.append({"indicator": "ping", "reason": str(exc)})
        statuses.append("UNKNOWN")

    try:
        tasks = collect_recent_task_failures(client)
        platform["tasks"] = {
            "status": compute_tasks_status(tasks),
            "failing_or_paused_24h": tasks.total,
            "tasks": [
                {"label": t.label, "state": t.state, "result": t.result, "started_at": t.started_at}
                for t in tasks.tasks
            ],
            "tasks_omitted": tasks.omitted,
        }
        statuses.append(platform["tasks"]["status"])
    except ApiError as exc:
        platform["tasks"] = None
        unknown.append({"indicator": "tasks", "reason": str(exc)})
        statuses.append("UNKNOWN")

    try:
        disk = collect_pulp_disk(client)
        platform["pulp_disk"] = {
            "status": compute_pulp_disk_status(disk, config),
            "free_pct": round(compute_pulp_disk_free_pct(disk), 2),
            "total_bytes": disk.total_bytes,
            "used_bytes": disk.used_bytes,
            "free_bytes": disk.free_bytes,
        }
        statuses.append(platform["pulp_disk"]["status"])
    except ApiError as exc:
        platform["pulp_disk"] = None
        unknown.append({"indicator": "pulp_disk", "reason": str(exc)})
        statuses.append("UNKNOWN")

    environments = collect_environments(client, org.id)
    ordered_names = [e.name for e in order_environments_by_promotion(environments)]
    versions_by_cv = collect_content_view_versions(client, org.id)
    hosts = list(collect_hosts(client, org.id, page_size=config.page_size))
    now = dt.datetime.now(dt.timezone.utc)
    evaluated = [evaluate_host(h, versions_by_cv, config, now=now) for h in hosts]

    fleet = compute_fleet_summary(evaluated)
    fleet_worst = worst_of(
        [s for s, count in fleet.status_counts.items() if count > 0] or ["UNKNOWN"]
    )
    statuses.append(fleet_worst)

    by_lce = compute_by_lce(evaluated, ordered_names) if getattr(args, "by_lce", False) else None
    unknown.extend(collect_unknown_entries(evaluated))

    data: dict[str, Any] = {
        "platform": platform,
        "fleet": _fleet_dict(fleet),
        "by_lce": [_lce_dict(e) for e in by_lce] if by_lce is not None else None,
    }
    overall_status = worst_of(statuses)
    return data, overall_status, unknown


def _collect_server_versions(client: BaseApiClient) -> tuple[dict[str, Any], list[dict[str, str]]]:
    server_extra: dict[str, Any] = {}
    unknown: list[dict[str, str]] = []
    try:
        server_extra["foreman_version"] = collect_foreman_version(client)
    except ApiError as exc:
        server_extra["foreman_version"] = None
        unknown.append({"indicator": "foreman_version", "reason": str(exc)})
    try:
        server_extra["katello_version"] = collect_katello_version(client)
    except ApiError as exc:
        server_extra["katello_version"] = None
        unknown.append({"indicator": "katello_version", "reason": str(exc)})
    return server_extra, unknown


def run(args: argparse.Namespace, config: Config, client: BaseApiClient) -> int:
    data, status, unknown = build_data(args, config, client)
    server_extra, version_unknown = _collect_server_versions(client)
    unknown = unknown + version_unknown
    thresholds = {name: getattr(config.thresholds, name) for name in _THRESHOLD_FIELDS}

    monitoring = bool(getattr(args, "monitoring", False))
    output_format = getattr(args, "format", "text")

    if monitoring or output_format == "json":
        envelope = build_envelope(
            command="summary",
            config=config,
            status=status,
            data=data,
            unknown=unknown,
            thresholds=thresholds,
            server_extra=server_extra,
        )
        print(json.dumps(envelope, ensure_ascii=False))
    else:
        print(render_summary_text(data))

    if monitoring:
        return status_to_nagios(status)
    return 0
