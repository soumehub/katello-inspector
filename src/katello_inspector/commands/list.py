"""Sous-commande `list` : tableau des VMs, une entree par VM dans `data`."""
from __future__ import annotations

import argparse
import datetime as dt
import json
from typing import Any

from ..analyze import EvaluatedHost, collect_unknown_entries, evaluate_host, worst_of
from ..api import BaseApiClient
from ..collect import (
    ContentViewVersion,
    build_search,
    collect_content_view_versions,
    collect_hosts,
    resolve_organization,
)
from ..config import Config
from ..exceptions import ConfigError
from ..render_json import build_envelope, status_to_nagios
from ..render_text import render_list_text

_THRESHOLD_FIELDS = ("checkin_days", "security_warn", "security_crit", "cv_lag_warn_days", "cv_lag_crit_days")

_SORT_KEYS = {
    "nom": lambda e: e.host.name,
    "check-in": lambda e: e.indicators.checkin.reason or "",
    "errata": lambda e: -(((e.host.errata_installable or {}).get("security")) or 0),
}


def _latest_version(versions: list[ContentViewVersion]) -> str | None:
    if not versions:
        return None
    epoch = dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    chosen = max(versions, key=lambda v: v.created_at or epoch)
    return chosen.version


def _host_dict(eh: EvaluatedHost, versions_by_cv: dict[int, list[ContentViewVersion]]) -> dict[str, Any]:
    host = eh.host
    environments = sorted(eh.environments)
    lifecycle_environment = ", ".join(environments) if environments else None
    content_views = [
        {
            "name": pair.content_view_name,
            "version_deployed": pair.version_deployed,
            "latest_published": _latest_version(versions_by_cv.get(pair.content_view_id, []))
            if pair.content_view_id is not None
            else None,
            "waiting_days": next(
                (r.waiting_days for r in eh.indicators.cv_lag_pairs if r.pair is pair),
                None,
            ),
        }
        for pair in host.content_view_pairs
    ]
    installable = host.errata_installable or {}
    applicable = host.errata_applicable or {}
    applicable_not_installable = {
        t: (applicable.get(t) or 0) - (installable.get(t) or 0) for t in ("security", "bugfix", "enhancement")
    }
    return {
        "name": host.name,
        "status": eh.status,
        "update_state": eh.update_state,
        "lifecycle_environment": lifecycle_environment,
        "content_views": content_views,
        "freshness": {
            "last_checkin": host.last_checkin.isoformat() if host.last_checkin else None,
            "checkin_age_days": None,
            "package_profile_age_days": None,
        },
        "errata": {
            "installable": {k: installable.get(k) for k in ("security", "bugfix", "enhancement")},
            "applicable_not_installable": applicable_not_installable,
        },
        "reboot_required": eh.indicators.traces.status == "WARN",
        "in_build": host.build,
        "content_source": host.content_source,
        "indicators": {
            "checkin": eh.indicators.checkin.status,
            "profile": eh.indicators.profile.status,
            "errata_security": eh.indicators.errata_security.status,
            "cv_lag": eh.indicators.cv_lag.status,
            "traces": eh.indicators.traces.status,
            "build": eh.indicators.build.status,
        },
    }


def build_data(
    args: argparse.Namespace, config: Config, client: BaseApiClient
) -> tuple[list[dict[str, Any]], str, list[dict[str, str]]]:
    if not config.organization:
        raise ConfigError("organisation manquante (--org, KATELLO_INSPECTOR_ORG ou [server] organization)")
    org = resolve_organization(client, config.organization)

    search = build_search(
        lce=getattr(args, "lce", None),
        cv=getattr(args, "cv", None),
        hostgroup=getattr(args, "hostgroup", None),
        raw=getattr(args, "search", None),
    )

    versions_by_cv = collect_content_view_versions(client, org.id)
    hosts = list(collect_hosts(client, org.id, search=search, page_size=config.page_size))
    evaluated = [evaluate_host(h, versions_by_cv, config) for h in hosts]

    if getattr(args, "problems_only", False):
        evaluated = [eh for eh in evaluated if eh.status not in ("OK", "N/A")]

    sort_key = _SORT_KEYS.get(getattr(args, "sort", None) or "nom", _SORT_KEYS["nom"])
    evaluated.sort(key=sort_key)

    unknown = collect_unknown_entries(evaluated)
    status = worst_of([eh.status for eh in evaluated if eh.status != "N/A"] or ["UNKNOWN"])
    data = [_host_dict(eh, versions_by_cv) for eh in evaluated]
    return data, status, unknown


def run(args: argparse.Namespace, config: Config, client: BaseApiClient) -> int:
    data, status, unknown = build_data(args, config, client)
    thresholds = {name: getattr(config.thresholds, name) for name in _THRESHOLD_FIELDS}

    monitoring = bool(getattr(args, "monitoring", False))
    output_format = getattr(args, "format", "text")
    limit = getattr(args, "limit", None)

    if monitoring or output_format == "json":
        envelope = build_envelope(
            command="list", config=config, status=status, data=data, unknown=unknown, thresholds=thresholds
        )
        print(json.dumps(envelope, ensure_ascii=False))
    else:
        print(render_list_text(data, limit=limit if limit is not None else 50))

    if monitoring:
        return status_to_nagios(status)
    return 0
