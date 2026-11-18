"""Lecture des donnees Katello : uniquement des appels GET, aucun calcul de statut.

Chaque fonction lit un endpoint (ou pagine sur un endpoint) et renvoie une
structure simple. Les seuils, les statuts et les regles d'agregation sont
dans `analyze.py` ; ce module ne decide jamais rien.
"""
from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from .api import BaseApiClient
from .exceptions import ApiError

_DATE_FORMAT = "%Y-%m-%d %H:%M:%S UTC"

# Libelles de taches qui donnent CRIT s'ils figurent parmi les taches en
# erreur ou en pause des dernieres 24h (docs/api-findings.md, point V9).
CRIT_TASK_LABELS = frozenset(
    {
        "Actions::Katello::Repository::Sync",
        "Actions::Katello::ContentView::Publish",
        "Actions::Katello::ContentView::Promote",
        "Actions::Katello::SyncPlan::Run",
    }
)

# Seule valeur confirmee pour traces_status (docs/api-findings.md, point V13 :
# "0 = No processes require restarting"). Aucune autre valeur n'a ete
# observee sur l'instance de validation ; une valeur hors de ce dictionnaire
# est donc UNKNOWN plutot que supposee (voir analyze.py).
TRACES_STATUS_LABELS = {0: "aucune trace"}

_RECENT_TASKS_PAGE_SIZE = 50


def parse_api_datetime(value: str | None) -> dt.datetime | None:
    """Convertit une date Foreman ("2026-08-14 11:56:26 UTC") en datetime aware.

    `None` si la valeur est absente, nulle ou dans une forme inattendue :
    jamais d'exception, jamais une date par defaut qui masquerait l'absence.
    """
    if not value:
        return None
    try:
        return dt.datetime.strptime(value, _DATE_FORMAT).replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def _escape_search_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_search(
    *,
    lce: str | None = None,
    cv: str | None = None,
    hostgroup: str | None = None,
    raw: str | None = None,
) -> str | None:
    """Traduit les options de filtrage en expression de recherche Foreman.

    Champs confirmes acceptes par /api/hosts : `lifecycle_environment`,
    `content_view` (docs/api-findings.md, V2), et `hostgroup` (verifie a la
    main : 7 hotes trouves, alors que `hostgroup_fullname` et
    `hostgroup_title` n'en trouvent aucun). `--hostgroup` prend donc le nom
    du groupe, jamais son chemin complet.
    """
    clauses: list[str] = []
    if lce:
        clauses.append(f'lifecycle_environment = "{_escape_search_value(lce)}"')
    if cv:
        clauses.append(f'content_view = "{_escape_search_value(cv)}"')
    if hostgroup:
        clauses.append(f'hostgroup = "{_escape_search_value(hostgroup)}"')
    if raw:
        # Parentheses uniquement quand --search se combine a un autre filtre,
        # pour que son propre "or" ne s'applique pas a tort aux autres clauses.
        clauses.append(f"({raw})" if clauses else raw)
    if not clauses:
        return None
    return " and ".join(clauses)


@dataclass
class Organization:
    id: int
    name: str


def resolve_organization(client: BaseApiClient, name: str) -> Organization:
    response = client.get("/api/organizations", {"search": f'name="{_escape_search_value(name)}"'})
    body = response.data or {}
    results = body.get("results") or []
    if not results:
        raise ApiError(f"organisation introuvable : {name}")
    first = results[0]
    org_id = first.get("id")
    org_name = first.get("name")
    if org_id is None or org_name is None:
        raise ApiError(f"reponse d'organisation incomplete pour : {name}")
    return Organization(id=org_id, name=org_name)


@dataclass
class Environment:
    id: int
    name: str
    label: str
    prior_id: int | None


def collect_environments(client: BaseApiClient, org_id: int, *, page_size: int = 100) -> list[Environment]:
    environments: list[Environment] = []
    for page in client.iter_results(
        "/katello/api/environments", {"organization_id": org_id}, page_size=page_size
    ):
        for raw in page:
            prior = raw.get("prior")
            environments.append(
                Environment(
                    id=raw["id"],
                    name=raw.get("name", ""),
                    label=raw.get("label", raw.get("name", "")),
                    prior_id=prior.get("id") if isinstance(prior, dict) else None,
                )
            )
    return environments


def order_environments_by_promotion(environments: list[Environment]) -> list[Environment]:
    """Library -> ... -> Production, reconstruit via la chaine `prior`.

    Alphabetique pour toute racine multiple ou tout environnement non
    rattache a la chaine (cas non observe, mais pour rester deterministe).
    """
    candidates = sorted(environments, key=lambda e: e.name)
    ordered: list[Environment] = []
    seen: set[int] = set()
    current_prior: int | None = None
    while True:
        next_env = next((e for e in candidates if e.prior_id == current_prior and e.id not in seen), None)
        if next_env is None:
            break
        ordered.append(next_env)
        seen.add(next_env.id)
        current_prior = next_env.id
    ordered.extend(e for e in candidates if e.id not in seen)
    return ordered


@dataclass
class ContentView:
    id: int
    name: str
    label: str
    rolling: bool
    composite: bool


def collect_content_views(client: BaseApiClient, org_id: int, *, page_size: int = 100) -> dict[int, ContentView]:
    views: dict[int, ContentView] = {}
    for page in client.iter_results(
        "/katello/api/content_views", {"organization_id": org_id}, page_size=page_size
    ):
        for raw in page:
            cv_id = raw["id"]
            views[cv_id] = ContentView(
                id=cv_id,
                name=raw.get("name", ""),
                label=raw.get("label", raw.get("name", "")),
                rolling=bool(raw.get("rolling", False)),
                composite=bool(raw.get("composite", False)),
            )
    return views


@dataclass
class ContentViewVersion:
    id: int
    content_view_id: int
    version: str
    created_at: dt.datetime | None
    environment_ids: frozenset[int]


def collect_content_view_versions(
    client: BaseApiClient, org_id: int, *, page_size: int = 100
) -> dict[int, list[ContentViewVersion]]:
    """Une seule requete, sur toute l'organisation (pas d'appel par CV)."""
    by_cv: dict[int, list[ContentViewVersion]] = {}
    for page in client.iter_results(
        "/katello/api/content_view_versions", {"organization_id": org_id}, page_size=page_size
    ):
        for raw in page:
            cv_id = raw.get("content_view_id")
            if cv_id is None:
                continue
            env_ids = frozenset(e["id"] for e in (raw.get("environments") or []) if "id" in e)
            by_cv.setdefault(cv_id, []).append(
                ContentViewVersion(
                    id=raw["id"],
                    content_view_id=cv_id,
                    version=raw.get("version", ""),
                    created_at=parse_api_datetime(raw.get("created_at")),
                    environment_ids=env_ids,
                )
            )
    epoch = dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    for versions in by_cv.values():
        versions.sort(key=lambda v: v.created_at or epoch)
    return by_cv


@dataclass
class HostContentViewPair:
    content_view_id: int | None
    content_view_name: str | None
    content_view_rolling: bool
    environment_id: int | None
    environment_name: str | None
    version_deployed: str | None
    version_deployed_id: int | None


@dataclass
class Host:
    id: int | None
    name: str
    has_content: bool
    last_checkin: dt.datetime | None
    build: bool
    traces_status: int | None
    errata_installable: dict[str, int] | None
    errata_applicable: dict[str, int] | None
    content_view_pairs: list[HostContentViewPair]
    content_source: str | None


def host_from_api(raw: dict[str, Any]) -> Host:
    """Convertit un enregistrement brut de /api/hosts en `Host`.

    Separee de `collect_hosts` pour pouvoir construire des hotes de test par
    surcharge d'un enregistrement reel, sans fixture dediee.
    """
    cfa = raw.get("content_facet_attributes")
    sfa = raw.get("subscription_facet_attributes")
    has_content = cfa is not None

    errata_installable: dict[str, int] | None = None
    errata_applicable: dict[str, int] | None = None
    content_source: str | None = None
    pairs: list[HostContentViewPair] = []

    if has_content:
        assert cfa is not None
        counts = cfa.get("errata_counts")
        if counts is not None:
            errata_installable = {k: v for k, v in counts.items() if k != "applicable"}
            errata_applicable = counts.get("applicable")
        content_source = cfa.get("content_source_name")
        for entry in cfa.get("content_view_environments") or []:
            cv = entry.get("content_view") or {}
            lce = entry.get("lifecycle_environment") or {}
            pairs.append(
                HostContentViewPair(
                    content_view_id=cv.get("id"),
                    content_view_name=cv.get("name"),
                    content_view_rolling=bool(cv.get("rolling", False)),
                    environment_id=lce.get("id"),
                    environment_name=lce.get("name"),
                    version_deployed=cv.get("content_view_version"),
                    version_deployed_id=cv.get("content_view_version_id"),
                )
            )

    last_checkin = parse_api_datetime(sfa.get("last_checkin")) if sfa else None

    return Host(
        id=raw.get("id"),
        name=raw.get("name", ""),
        has_content=has_content,
        last_checkin=last_checkin,
        build=bool(raw.get("build", False)),
        traces_status=raw.get("traces_status"),
        errata_installable=errata_installable,
        errata_applicable=errata_applicable,
        content_view_pairs=pairs,
        content_source=content_source,
    )


def collect_hosts(
    client: BaseApiClient,
    org_id: int,
    *,
    search: str | None = None,
    page_size: int = 200,
) -> Iterator[Host]:
    params: dict[str, Any] = {"organization_id": org_id}
    if search:
        params["search"] = search
    for page in client.iter_results("/api/hosts", params, page_size=page_size):
        for raw in page:
            yield host_from_api(raw)


@dataclass
class PingResult:
    services: dict[str, str]


def collect_ping(client: BaseApiClient) -> PingResult:
    response = client.get("/katello/api/ping")
    body = response.data or {}
    services_raw = body.get("services") or {}
    services = {name: (info or {}).get("status", "") for name, info in services_raw.items()}
    return PingResult(services=services)


@dataclass
class TaskSummary:
    label: str
    state: str | None
    result: str | None
    started_at: str | None


@dataclass
class RecentTaskFailures:
    total: int
    tasks: list[TaskSummary]
    omitted: int


def collect_recent_task_failures(
    client: BaseApiClient, *, page_size: int = _RECENT_TASKS_PAGE_SIZE
) -> RecentTaskFailures:
    """Taches en erreur ou en pause des dernieres 24h, liste bornee a `page_size`."""
    search = '(state = paused or result = error) and started_at > "24 hours ago"'
    response = client.get(
        "/foreman_tasks/api/tasks",
        {"search": search, "per_page": page_size, "page": 1, "order": "started_at DESC"},
    )
    body = response.data or {}
    total = body.get("subtotal")
    if total is None:
        raise ApiError("compteur de taches en erreur ou en pause indisponible")
    results = body.get("results") or []
    tasks = [
        TaskSummary(
            label=item.get("label", ""),
            state=item.get("state"),
            result=item.get("result"),
            started_at=item.get("started_at"),
        )
        for item in results
    ]
    omitted = max(0, total - len(tasks))
    return RecentTaskFailures(total=total, tasks=tasks, omitted=omitted)


@dataclass
class PulpDisk:
    total_bytes: int
    used_bytes: int
    free_bytes: int


def collect_pulp_disk(client: BaseApiClient) -> PulpDisk:
    """Lu hors API Foreman/Katello, sans authentification (docs/api-findings.md)."""
    response = client.get("/pulp/api/v3/status/", anonymous=True)
    body = response.data or {}
    storage = body.get("storage")
    if not storage:
        raise ApiError("informations de stockage Pulp indisponibles")
    total = storage.get("total")
    used = storage.get("used")
    free = storage.get("free")
    if total is None or used is None or free is None:
        raise ApiError("informations de stockage Pulp incompletes")
    return PulpDisk(total_bytes=total, used_bytes=used, free_bytes=free)


def collect_foreman_version(client: BaseApiClient) -> str | None:
    body = client.get("/api/status").data or {}
    version = body.get("version")
    return version if isinstance(version, str) else None


def collect_katello_version(client: BaseApiClient) -> str | None:
    body = client.get("/katello/api/status").data or {}
    version = body.get("version")
    return version if isinstance(version, str) else None
