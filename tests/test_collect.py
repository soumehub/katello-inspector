from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest

from katello_inspector.api import FixtureClient
from katello_inspector.collect import (
    Environment,
    build_search,
    collect_content_view_versions,
    collect_content_views,
    collect_environments,
    collect_foreman_version,
    collect_hosts,
    collect_katello_version,
    collect_ping,
    collect_pulp_disk,
    collect_recent_task_failures,
    format_iso_z,
    host_from_api,
    order_environments_by_promotion,
    parse_api_datetime,
    resolve_organization,
)
from katello_inspector.exceptions import ApiError, UnsupportedSearchError

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _client() -> FixtureClient:
    # Les fixtures de tests/fixtures/ (chargees ensemble, sans conflit : la
    # cle de correspondance est (chemin, parametres)).
    return FixtureClient(FIXTURES_DIR)


def _load_raw_host(index: int) -> dict:
    with (FIXTURES_DIR / "009_hosts_list.json").open(encoding="utf-8") as fh:
        doc = json.load(fh)
    result: dict = doc["response"]["results"][index]
    return result


# --------------------------------------------------------------------------
# parse_api_datetime
# --------------------------------------------------------------------------


def test_parse_api_datetime_valid() -> None:
    value = parse_api_datetime("2026-08-14 11:56:26 UTC")
    assert value is not None
    assert value.year == 2026 and value.month == 8 and value.day == 14


def test_parse_api_datetime_none() -> None:
    assert parse_api_datetime(None) is None


def test_parse_api_datetime_empty_string() -> None:
    assert parse_api_datetime("") is None


def test_parse_api_datetime_unexpected_format() -> None:
    assert parse_api_datetime("pas une date") is None


def test_format_iso_z_round_trips_with_parse() -> None:
    value = parse_api_datetime("2026-08-14 11:56:26 UTC")
    assert format_iso_z(value) == "2026-08-14T11:56:26Z"


def test_format_iso_z_never_produces_plus_zero_offset() -> None:
    value = parse_api_datetime("2026-08-14 11:56:26 UTC")
    assert value is not None
    assert "+00:00" not in format_iso_z(value)


def test_format_iso_z_none_stays_none() -> None:
    assert format_iso_z(None) is None


# --------------------------------------------------------------------------
# collect_foreman_version / collect_katello_version
# --------------------------------------------------------------------------


def test_collect_foreman_version_reads_version_field(tmp_path: Path) -> None:
    _write_fixture(
        tmp_path, "status.json", path="/api/status", params={}, status=200, response={"version": "3.19.1"}
    )
    assert collect_foreman_version(FixtureClient(tmp_path)) == "3.19.1"


def test_collect_katello_version_reads_version_field(tmp_path: Path) -> None:
    _write_fixture(
        tmp_path,
        "status.json",
        path="/katello/api/status",
        params={},
        status=200,
        response={"version": "4.21.1.1"},
    )
    assert collect_katello_version(FixtureClient(tmp_path)) == "4.21.1.1"


def test_collect_foreman_version_missing_field_is_none(tmp_path: Path) -> None:
    _write_fixture(tmp_path, "status.json", path="/api/status", params={}, status=200, response={})
    assert collect_foreman_version(FixtureClient(tmp_path)) is None


# --------------------------------------------------------------------------
# build_search
# --------------------------------------------------------------------------


def test_build_search_no_filter_returns_none() -> None:
    assert build_search() is None


def test_build_search_single_filter() -> None:
    assert build_search(lce="Production") == 'lifecycle_environment = "Production"'


def test_build_search_hostgroup_uses_plain_field_not_fullname() -> None:
    # Verifie a la main sur une vraie instance : "hostgroup" trouve des
    # hotes, "hostgroup_fullname"/"hostgroup_title" n'en trouvent aucun.
    # --hostgroup prend donc le nom du groupe, pas son chemin complet.
    assert build_search(hostgroup="Groupe") == 'hostgroup = "Groupe"'


def test_build_search_hostgroup_escapes_quotes() -> None:
    result = build_search(hostgroup='Groupe "Test"')
    assert result == 'hostgroup = "Groupe \\"Test\\""'


def test_build_search_combines_filters_with_and() -> None:
    result = build_search(lce="Production", cv="cv-os-rocky")
    assert result == 'lifecycle_environment = "Production" and content_view = "cv-os-rocky"'


def test_build_search_escapes_quotes() -> None:
    result = build_search(lce='Prod"uction')
    assert result == 'lifecycle_environment = "Prod\\"uction"'


def test_build_search_raw_alone_has_no_parentheses() -> None:
    assert build_search(raw="name ~ vm") == "name ~ vm"


def test_build_search_raw_combined_gets_parentheses() -> None:
    result = build_search(lce="Production", raw="name ~ vm or name ~ host")
    assert result == 'lifecycle_environment = "Production" and (name ~ vm or name ~ host)'


# --------------------------------------------------------------------------
# resolve_organization -- tests/fixtures/004_organizations.json
# --------------------------------------------------------------------------


def test_resolve_organization_finds_id() -> None:
    org = resolve_organization(_client(), "MonOrganisation")
    assert org.id == 1
    assert org.name == "MonOrganisation"


def test_resolve_organization_not_found_raises() -> None:
    with pytest.raises(ApiError):
        resolve_organization(_client(), "Inexistante")


# --------------------------------------------------------------------------
# collect_environments / order_environments_by_promotion -- 006_environments.json
# --------------------------------------------------------------------------


def test_collect_environments_reads_all_three() -> None:
    environments = collect_environments(_client(), 1, page_size=100)
    names = sorted(e.name for e in environments)
    assert names == ["Library", "Production", "Staging"]


def test_collect_environments_prior_chain() -> None:
    environments = collect_environments(_client(), 1, page_size=100)
    by_name = {e.name: e for e in environments}
    assert by_name["Library"].prior_id is None
    assert by_name["Staging"].prior_id == by_name["Library"].id
    assert by_name["Production"].prior_id == by_name["Staging"].id


def test_order_environments_by_promotion_follows_the_chain() -> None:
    environments = collect_environments(_client(), 1, page_size=100)
    ordered = order_environments_by_promotion(environments)
    assert [e.name for e in ordered] == ["Library", "Staging", "Production"]


def test_order_environments_by_promotion_unattached_goes_last_alphabetically() -> None:
    envs = [
        Environment(id=1, name="Library", label="Library", prior_id=None),
        Environment(id=2, name="Orpheline", label="Orpheline", prior_id=999),
    ]
    ordered = order_environments_by_promotion(envs)
    assert [e.name for e in ordered] == ["Library", "Orpheline"]


# --------------------------------------------------------------------------
# collect_content_views -- 007_content_views.json
# --------------------------------------------------------------------------


def test_collect_content_views_distinguishes_rolling_and_composite() -> None:
    views = collect_content_views(_client(), 1, page_size=100)
    assert len(views) == 9
    by_name = {v.name: v for v in views.values()}
    assert by_name["cv-os-rocky"].rolling is False
    assert by_name["cv-os-rocky"].composite is False


# --------------------------------------------------------------------------
# collect_content_view_versions -- 008_content_view_versions.json
# --------------------------------------------------------------------------


def test_collect_content_view_versions_single_org_wide_request() -> None:
    client = _client()
    by_cv = collect_content_view_versions(client, 1, page_size=100)
    total_versions = sum(len(v) for v in by_cv.values())
    assert total_versions == 20
    # Une seule requete : aucun parametre content_view_id dans la fixture
    # chargee (docs/fixtures.md / point 4 : pas d'appel par CV).
    with (FIXTURES_DIR / "008_content_view_versions.json").open(encoding="utf-8") as fh:
        recorded_params = json.load(fh)["request"]["params"]
    assert "content_view_id" not in recorded_params


def test_collect_content_view_versions_sorted_by_date() -> None:
    by_cv = collect_content_view_versions(_client(), 1, page_size=100)
    for versions in by_cv.values():
        dates = [v.created_at for v in versions if v.created_at is not None]
        assert dates == sorted(dates)


def test_collect_content_view_versions_environment_ids() -> None:
    by_cv = collect_content_view_versions(_client(), 1, page_size=100)
    some_version = next(v for versions in by_cv.values() for v in versions if v.environment_ids)
    assert isinstance(some_version.environment_ids, frozenset)
    assert all(isinstance(i, int) for i in some_version.environment_ids)


# --------------------------------------------------------------------------
# collect_hosts / host_from_api -- 009_hosts_list.json, 017_hosts_p1.json, 018_hosts_p2.json
# --------------------------------------------------------------------------


def test_collect_hosts_full_list_single_page() -> None:
    hosts = list(collect_hosts(_client(), 1, page_size=100))
    assert len(hosts) == 19


def test_collect_hosts_pagination_matches_real_captures() -> None:
    # page_size=2 : les deux seules pages capturees (017 et 018). La
    # consommation partielle via islice evite de demander une page 3, qui
    # n'existe pas dans les fixtures.
    hosts = list(itertools.islice(collect_hosts(_client(), 1, page_size=2), 4))
    assert len(hosts) == 4
    assert all(h.name for h in hosts)


def test_host_from_api_with_content_data() -> None:
    raw = _load_raw_host(0)
    host = host_from_api(raw)
    assert host.has_content is True
    assert host.last_checkin is not None
    assert host.errata_installable is not None
    assert host.errata_applicable is not None
    assert len(host.content_view_pairs) == 2
    pair = host.content_view_pairs[0]
    assert pair.environment_name == "Production"
    assert pair.content_view_name == "cv-os-rocky"


def test_host_from_api_without_content_data() -> None:
    raw = next(h for h in (_load_raw_host(i) for i in range(19)) if h.get("content_facet_attributes") is None)
    host = host_from_api(raw)
    assert host.has_content is False
    assert host.errata_installable is None
    assert host.errata_applicable is None
    assert host.content_view_pairs == []


def test_collect_hosts_unsupported_search_raises_clearly(tmp_path: Path) -> None:
    # Meme message que tests/fixtures/search_rejected/hosts_500.json, mais
    # avec exactement les parametres que collect_hosts envoie (organisation,
    # pagination) : la fixture existante ne portait que `search`.
    _write_fixture(
        tmp_path,
        "hosts_500.json",
        path="/api/hosts",
        params={"organization_id": 1, "search": "bogus = 1", "per_page": 200},
        status=500,
        response={"error": {"message": "Field 'bogus' not recognized for searching!"}},
    )
    with pytest.raises(UnsupportedSearchError):
        list(collect_hosts(FixtureClient(tmp_path), 1, search="bogus = 1"))


# --------------------------------------------------------------------------
# collect_ping / collect_recent_task_failures / collect_pulp_disk
#
# Pas de fixture commise pour l'instant (003_ping.json, la fixture de taches
# fabriquee et 075_disk_pulp_api_v3_status.json sont proposees mais pas
# encore ajoutees) : repertoires de fixtures ecrits a la volee dans tmp_path,
# au meme format d'enveloppe, jamais commits.
# --------------------------------------------------------------------------


def _write_fixture(directory: Path, name: str, *, path: str, params: dict, status: int, response: object) -> None:
    doc = {
        "request": {"method": "GET", "path": path, "params": params},
        "status": status,
        "kind": "ok" if status < 400 else "error",
        "elapsed_ms": 1,
        "response": response,
    }
    (directory / name).write_text(json.dumps(doc), encoding="utf-8")


def test_collect_ping_reads_services(tmp_path: Path) -> None:
    _write_fixture(
        tmp_path,
        "ping.json",
        path="/katello/api/ping",
        params={},
        status=200,
        response={"status": "ok", "services": {"candlepin": {"status": "ok"}, "pulp3": {"status": "ok"}}},
    )
    result = collect_ping(FixtureClient(tmp_path))
    assert result.services == {"candlepin": "ok", "pulp3": "ok"}


def test_collect_recent_task_failures_reads_label_state_result(tmp_path: Path) -> None:
    params = {
        "search": '(state = paused or result = error) and started_at > "24 hours ago"',
        "per_page": 50,
        "page": 1,
        "order": "started_at DESC",
    }
    _write_fixture(
        tmp_path,
        "tasks.json",
        path="/foreman_tasks/api/tasks",
        params=params,
        status=200,
        response={
            "subtotal": 1,
            "results": [
                {
                    "label": "Actions::Katello::Repository::Sync",
                    "state": "stopped",
                    "result": "error",
                    "started_at": "2026-11-16 01:00:19 UTC",
                }
            ],
        },
    )
    result = collect_recent_task_failures(FixtureClient(tmp_path))
    assert result.total == 1
    assert result.omitted == 0
    assert result.tasks[0].started_at is not None
    assert result.tasks[0].started_at.year == 2026
    assert result.tasks[0].label == "Actions::Katello::Repository::Sync"


def test_collect_recent_task_failures_reports_omitted_beyond_page_size(tmp_path: Path) -> None:
    params = {
        "search": '(state = paused or result = error) and started_at > "24 hours ago"',
        "per_page": 2,
        "page": 1,
        "order": "started_at DESC",
    }
    _write_fixture(
        tmp_path,
        "tasks.json",
        path="/foreman_tasks/api/tasks",
        params=params,
        status=200,
        response={
            "subtotal": 5,
            "results": [
                {"label": "A", "state": "stopped", "result": "error", "started_at": "2026-11-16 01:00:00 UTC"},
                {"label": "B", "state": "stopped", "result": "error", "started_at": "2026-11-16 01:00:01 UTC"},
            ],
        },
    )
    result = collect_recent_task_failures(FixtureClient(tmp_path), page_size=2)
    assert result.total == 5
    assert len(result.tasks) == 2
    assert result.omitted == 3


def test_collect_pulp_disk_reads_storage(tmp_path: Path) -> None:
    _write_fixture(
        tmp_path,
        "pulp.json",
        path="/pulp/api/v3/status/",
        params={},
        status=200,
        response={"storage": {"total": 300, "used": 100, "free": 200}},
    )
    result = collect_pulp_disk(FixtureClient(tmp_path))
    assert result.total_bytes == 300
    assert result.used_bytes == 100
    assert result.free_bytes == 200


def test_collect_pulp_disk_missing_storage_raises(tmp_path: Path) -> None:
    # Repertoire vide : aucune fixture pour /pulp/api/v3/status/.
    with pytest.raises(ApiError):
        collect_pulp_disk(FixtureClient(tmp_path))
