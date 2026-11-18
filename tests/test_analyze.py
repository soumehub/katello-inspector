"""Tests des regles de statut (docs/cadrage.md).

Les hotes sont construits par surcharge d'un enregistrement reel de
tests/fixtures/009_hosts_list.json (host_from_api), jamais par une nouvelle
fixture. Les versions de CV, quand il en faut, sont construites directement
(ContentViewVersion), pour un controle exact des dates aux limites.
"""
from __future__ import annotations

import copy
import datetime as dt
import json
from pathlib import Path
from types import SimpleNamespace

from katello_inspector.analyze import (
    CRIT,
    NA,
    OK,
    UNKNOWN,
    UPDATE_STATE_CONTENT_PENDING,
    UPDATE_STATE_NA,
    UPDATE_STATE_OUTDATED,
    UPDATE_STATE_UNVERIFIABLE,
    UPDATE_STATE_UP_TO_DATE,
    WARN,
    aggregate_status,
    collect_unknown_entries,
    compute_build_indicator,
    compute_by_lce,
    compute_checkin_indicator,
    compute_cv_lag_environments,
    compute_cv_lag_for_pair,
    compute_errata_security_indicator,
    compute_fleet_summary,
    compute_host_indicators,
    compute_ping_status,
    compute_profile_indicator,
    compute_pulp_disk_status,
    compute_tasks_status,
    compute_traces_indicator,
    compute_update_state,
    evaluate_host,
)
from katello_inspector.collect import (
    ContentViewVersion,
    Host,
    HostContentViewPair,
    PingResult,
    PulpDisk,
    RecentTaskFailures,
    TaskSummary,
    host_from_api,
)
from katello_inspector.config import build_config

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
NOW = dt.datetime(2026, 11, 17, 12, 0, 0, tzinfo=dt.timezone.utc)


def _raw_host(index: int = 0) -> dict:
    with (FIXTURES_DIR / "009_hosts_list.json").open(encoding="utf-8") as fh:
        doc = json.load(fh)
    raw: dict = copy.deepcopy(doc["response"]["results"][index])
    return raw


def _host(index: int = 0, **top_level_overrides: object) -> Host:
    raw = _raw_host(index)
    raw.update(top_level_overrides)
    return host_from_api(raw)


def _host_without_content(**top_level_overrides: object) -> Host:
    with (FIXTURES_DIR / "009_hosts_list.json").open(encoding="utf-8") as fh:
        doc = json.load(fh)
    raw = next(h for h in doc["response"]["results"] if h.get("content_facet_attributes") is None)
    raw = copy.deepcopy(raw)
    raw.update(top_level_overrides)
    return host_from_api(raw)


def _config(ini_text: str | None = None, tmp_path: Path | None = None, **cli_overrides: object):
    if ini_text and tmp_path is not None:
        ini = tmp_path / "config.ini"
        ini.write_text(ini_text, encoding="utf-8")
        return build_config(SimpleNamespace(config=str(ini), **cli_overrides))
    return build_config(SimpleNamespace(**cli_overrides))


# --------------------------------------------------------------------------
# compute_checkin_indicator
# --------------------------------------------------------------------------


def test_checkin_no_content_is_na() -> None:
    host = _host_without_content()
    assert compute_checkin_indicator(host, _config(), now=NOW).status == NA


def test_checkin_null_is_unknown() -> None:
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = None
    host = host_from_api(raw)
    indicator = compute_checkin_indicator(host, _config(), now=NOW)
    assert indicator.status == UNKNOWN
    assert indicator.reason


def test_checkin_fresh_is_ok() -> None:
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = "2026-11-17 11:00:00 UTC"
    host = host_from_api(raw)
    assert compute_checkin_indicator(host, _config(), now=NOW).status == OK


def test_checkin_exactly_at_threshold_is_ok() -> None:
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = "2026-11-10 12:00:00 UTC"  # 7 jours, seuil par defaut
    host = host_from_api(raw)
    assert compute_checkin_indicator(host, _config(), now=NOW).status == OK


def test_checkin_one_day_beyond_threshold_is_crit() -> None:
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = "2026-11-09 12:00:00 UTC"  # 8 jours
    host = host_from_api(raw)
    assert compute_checkin_indicator(host, _config(), now=NOW).status == CRIT


def test_checkin_in_the_future_is_unknown() -> None:
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = "2026-11-18 12:00:00 UTC"  # apres `now`
    host = host_from_api(raw)
    indicator = compute_checkin_indicator(host, _config(), now=NOW)
    assert indicator.status == UNKNOWN
    assert indicator.reason


def test_checkin_malformed_date_is_unknown() -> None:
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = "pas une date valide"
    host = host_from_api(raw)
    indicator = compute_checkin_indicator(host, _config(), now=NOW)
    assert indicator.status == UNKNOWN


def test_checkin_default_now_uses_current_time_without_crashing() -> None:
    # L'horloge est injectee explicitement dans tous les autres tests ; ici
    # on verifie seulement que l'absence d'injection (now=None) fonctionne
    # avec l'heure reelle, sur une date tres ancienne (CRIT quel que soit le
    # jour ou le test tourne).
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = "2000-01-01 00:00:00 UTC"
    host = host_from_api(raw)
    assert compute_checkin_indicator(host, _config()).status == CRIT


# --------------------------------------------------------------------------
# compute_errata_security_indicator
# --------------------------------------------------------------------------


def test_errata_security_no_content_is_na() -> None:
    host = _host_without_content()
    assert compute_errata_security_indicator(host, _config()).status == NA


def test_errata_security_in_build_is_na() -> None:
    host = _host(0, build=True)
    assert compute_errata_security_indicator(host, _config()).status == NA


def test_errata_security_counts_absent_is_unknown() -> None:
    raw = _raw_host(0)
    del raw["content_facet_attributes"]["errata_counts"]
    host = host_from_api(raw)
    assert compute_errata_security_indicator(host, _config()).status == UNKNOWN


def test_errata_security_count_absent_is_unknown() -> None:
    raw = _raw_host(0)
    del raw["content_facet_attributes"]["errata_counts"]["security"]
    host = host_from_api(raw)
    assert compute_errata_security_indicator(host, _config()).status == UNKNOWN


def test_errata_security_zero_is_ok() -> None:
    raw = _raw_host(0)
    raw["content_facet_attributes"]["errata_counts"]["security"] = 0
    host = host_from_api(raw)
    assert compute_errata_security_indicator(host, _config()).status == OK


def test_errata_security_at_warn_threshold() -> None:
    raw = _raw_host(0)
    raw["content_facet_attributes"]["errata_counts"]["security"] = 1  # defaut security_warn=1
    host = host_from_api(raw)
    assert compute_errata_security_indicator(host, _config()).status == WARN


def test_errata_security_just_below_crit_threshold() -> None:
    raw = _raw_host(0)
    raw["content_facet_attributes"]["errata_counts"]["security"] = 9  # defaut security_crit=10
    host = host_from_api(raw)
    assert compute_errata_security_indicator(host, _config()).status == WARN


def test_errata_security_at_crit_threshold() -> None:
    raw = _raw_host(0)
    raw["content_facet_attributes"]["errata_counts"]["security"] = 10
    host = host_from_api(raw)
    assert compute_errata_security_indicator(host, _config()).status == CRIT


# --------------------------------------------------------------------------
# compute_traces_indicator
# --------------------------------------------------------------------------


def test_traces_no_content_is_na() -> None:
    host = _host_without_content()
    assert compute_traces_indicator(host).status == NA


def test_traces_in_build_is_na() -> None:
    host = _host(0, build=True)
    assert compute_traces_indicator(host).status == NA


def test_traces_null_is_unknown() -> None:
    host = _host(0, traces_status=None)
    assert compute_traces_indicator(host).status == UNKNOWN


def test_traces_zero_is_ok() -> None:
    host = _host(0, traces_status=0)
    assert compute_traces_indicator(host).status == OK


def test_traces_unmapped_value_is_unknown_with_raw_value_in_reason() -> None:
    host = _host(0, traces_status=1)
    indicator = compute_traces_indicator(host)
    assert indicator.status == UNKNOWN
    assert indicator.reason is not None
    assert "1" in indicator.reason


# --------------------------------------------------------------------------
# compute_profile_indicator / compute_build_indicator (V4 / V14, exclus de
# aggregate_status : voir plus bas)
# --------------------------------------------------------------------------


def test_profile_no_content_is_na() -> None:
    assert compute_profile_indicator(_host_without_content()).status == NA


def test_profile_with_content_is_always_unknown() -> None:
    host = _host(0)
    indicator = compute_profile_indicator(host)
    assert indicator.status == UNKNOWN
    assert "V4" in (indicator.reason or "")


def test_build_indicator_not_building_is_na() -> None:
    host = _host(0, build=False)
    assert compute_build_indicator(host).status == NA


def test_build_indicator_building_is_unknown_never_warn_or_crit() -> None:
    host = _host(0, build=True)
    indicator = compute_build_indicator(host)
    assert indicator.status == UNKNOWN
    assert "V14" in (indicator.reason or "")


# --------------------------------------------------------------------------
# compute_cv_lag_for_pair
# --------------------------------------------------------------------------


def _pair(**overrides: object) -> HostContentViewPair:
    base = dict(
        content_view_id=3,
        content_view_name="cv-os-rocky",
        content_view_rolling=False,
        environment_id=3,
        environment_name="Production",
        version_deployed="2.0",
        version_deployed_id=24,
    )
    base.update(overrides)
    return HostContentViewPair(**base)  # type: ignore[arg-type]


def _version(version_id: int, created_at: dt.datetime | None, environment_ids: frozenset[int]) -> ContentViewVersion:
    return ContentViewVersion(
        id=version_id, content_view_id=3, version="x", created_at=created_at, environment_ids=environment_ids
    )


def test_cv_lag_rolling_is_na() -> None:
    pair = _pair(content_view_rolling=True)
    result = compute_cv_lag_for_pair(pair, {}, _config(), now=NOW)
    assert result.status == NA


def test_cv_lag_disabled_for_lce_is_na(tmp_path: Path) -> None:
    config = _config("[lce:Production]\ncv_lag_check = false\n", tmp_path)
    pair = _pair()
    result = compute_cv_lag_for_pair(pair, {}, config, now=NOW)
    assert result.status == NA


def test_cv_lag_disabled_for_cv_is_na(tmp_path: Path) -> None:
    config = _config("[cv:cv-os-rocky]\ncv_lag_check = false\n", tmp_path)
    pair = _pair()
    result = compute_cv_lag_for_pair(pair, {}, config, now=NOW)
    assert result.status == NA


def test_cv_lag_missing_deployed_version_id_is_unknown() -> None:
    pair = _pair(version_deployed_id=None)
    result = compute_cv_lag_for_pair(pair, {}, _config(), now=NOW)
    assert result.status == UNKNOWN


def test_cv_lag_deployed_version_not_in_version_list_is_unknown() -> None:
    pair = _pair()
    result = compute_cv_lag_for_pair(pair, {3: []}, _config(), now=NOW)
    assert result.status == UNKNOWN


def test_cv_lag_deployed_version_without_publish_date_is_unknown() -> None:
    deployed = _version(24, None, frozenset({3}))
    pair = _pair()
    result = compute_cv_lag_for_pair(pair, {3: [deployed]}, _config(), now=NOW)
    assert result.status == UNKNOWN
    assert result.reason


def test_cv_lag_no_newer_version_is_ok_zero_waiting() -> None:
    deployed = _version(24, NOW - dt.timedelta(days=30), frozenset({3}))
    pair = _pair()
    result = compute_cv_lag_for_pair(pair, {3: [deployed]}, _config(), now=NOW)
    assert result.status == OK
    assert result.waiting_days == 0


def test_cv_lag_newer_version_within_tolerance_is_ok() -> None:
    deployed = _version(24, NOW - dt.timedelta(days=30), frozenset({3}))
    newer = _version(25, NOW - dt.timedelta(days=5), frozenset())  # pas encore promue en Production
    pair = _pair()
    result = compute_cv_lag_for_pair(pair, {3: [deployed, newer]}, _config(), now=NOW)
    assert result.status == OK
    assert result.waiting_days == 5


def test_cv_lag_at_warn_threshold() -> None:
    deployed = _version(24, NOW - dt.timedelta(days=60), frozenset({3}))
    newer = _version(25, NOW - dt.timedelta(days=14), frozenset())  # defaut cv_lag_warn_days=14
    pair = _pair()
    result = compute_cv_lag_for_pair(pair, {3: [deployed, newer]}, _config(), now=NOW)
    assert result.status == WARN
    assert result.waiting_days == 14


def test_cv_lag_at_crit_threshold() -> None:
    deployed = _version(24, NOW - dt.timedelta(days=90), frozenset({3}))
    newer = _version(25, NOW - dt.timedelta(days=45), frozenset())  # defaut cv_lag_crit_days=45
    pair = _pair()
    result = compute_cv_lag_for_pair(pair, {3: [deployed, newer]}, _config(), now=NOW)
    assert result.status == CRIT
    assert result.waiting_days == 45


def test_cv_lag_per_cv_override_wins_over_lce(tmp_path: Path) -> None:
    config = _config(
        "[lce:Production]\ncv_lag_warn_days = 30\ncv_lag_crit_days = 90\n\n"
        "[cv:cv-os-rocky]\ncv_lag_warn_days = 5\ncv_lag_crit_days = 10\n",
        tmp_path,
    )
    deployed = _version(24, NOW - dt.timedelta(days=60), frozenset({3}))
    newer = _version(25, NOW - dt.timedelta(days=10), frozenset())
    pair = _pair()
    result = compute_cv_lag_for_pair(pair, {3: [deployed, newer]}, config, now=NOW)
    # Avec le seuil LCE (30/90) ce serait OK ; avec le seuil CV (5/10), c'est CRIT.
    assert result.status == CRIT


def test_cv_lag_several_pairs_takes_the_worst() -> None:
    host_raw = _raw_host(4)  # vm16 : 3 couples CV/LCE (cv-os-rocky, cv-infra-agents, cv-app-elasticsearch)
    host = host_from_api(host_raw)
    assert len(host.content_view_pairs) == 3
    # Aucune version fournie : chaque couple devient UNKNOWN (version introuvable).
    indicators = compute_host_indicators(host, {}, _config(), now=NOW)
    assert indicators.cv_lag.status == UNKNOWN


# --------------------------------------------------------------------------
# aggregate_status : ordre de gravite, N/A exclu, profile/build jamais pris
# en compte (point 1)
# --------------------------------------------------------------------------


def test_aggregate_status_all_ok() -> None:
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = "2026-11-17 11:00:00 UTC"
    raw["content_facet_attributes"]["errata_counts"]["security"] = 0
    raw["content_facet_attributes"]["content_view_environments"] = []
    raw["traces_status"] = 0
    host = host_from_api(raw)
    indicators = compute_host_indicators(host, {}, _config(), now=NOW)
    assert aggregate_status(indicators) == OK


def test_aggregate_status_crit_wins_over_warn() -> None:
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = "2026-11-09 12:00:00 UTC"  # CRIT
    raw["content_facet_attributes"]["errata_counts"]["security"] = 1  # WARN
    raw["content_facet_attributes"]["content_view_environments"] = []
    raw["traces_status"] = 0
    host = host_from_api(raw)
    indicators = compute_host_indicators(host, {}, _config(), now=NOW)
    assert aggregate_status(indicators) == CRIT


def test_aggregate_status_unknown_when_no_warn_or_crit() -> None:
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = None  # UNKNOWN
    raw["content_facet_attributes"]["errata_counts"]["security"] = 0
    raw["content_facet_attributes"]["content_view_environments"] = []
    raw["traces_status"] = 0
    host = host_from_api(raw)
    indicators = compute_host_indicators(host, {}, _config(), now=NOW)
    assert aggregate_status(indicators) == UNKNOWN


def test_aggregate_status_na_when_no_content() -> None:
    # traces est aussi N/A sans donnees de contenu (comme les trois autres
    # indicateurs pertinents) : les quatre sont N/A, le statut global l'est
    # donc aussi.
    host = _host_without_content()
    indicators = compute_host_indicators(host, {}, _config(), now=NOW)
    assert aggregate_status(indicators) == NA


def test_aggregate_status_ignores_profile_and_build_unknown() -> None:
    # profile est toujours UNKNOWN avec du contenu ; si tout le reste est OK,
    # le statut global doit rester OK (point 1 : profile/build exclus).
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = "2026-11-17 11:00:00 UTC"
    raw["content_facet_attributes"]["errata_counts"]["security"] = 0
    raw["content_facet_attributes"]["content_view_environments"] = []
    raw["traces_status"] = 0
    host = host_from_api(raw)
    indicators = compute_host_indicators(host, {}, _config(), now=NOW)
    assert indicators.profile.status == UNKNOWN
    assert aggregate_status(indicators) == OK


def test_unknown_reason_text_never_changes_the_status() -> None:
    # La liste "unknown" (les raisons) est informative : seuls les statuts
    # comptent pour aggregate_status/compute_update_state (point 3).
    raw_a = _raw_host(0)
    raw_a["subscription_facet_attributes"]["last_checkin"] = None
    raw_a["content_facet_attributes"]["errata_counts"]["security"] = 0
    raw_a["content_facet_attributes"]["content_view_environments"] = []
    raw_a["traces_status"] = 0
    host_a = host_from_api(raw_a)

    raw_b = _raw_host(1)  # un hote different, mais avec le meme defaut de check-in
    raw_b["subscription_facet_attributes"]["last_checkin"] = None
    raw_b["content_facet_attributes"]["errata_counts"]["security"] = 0
    raw_b["content_facet_attributes"]["content_view_environments"] = []
    raw_b["traces_status"] = 0
    host_b = host_from_api(raw_b)

    indicators_a = compute_host_indicators(host_a, {}, _config(), now=NOW)
    indicators_b = compute_host_indicators(host_b, {}, _config(), now=NOW)
    assert indicators_a.checkin.reason != indicators_b.checkin.reason or host_a.name != host_b.name
    assert aggregate_status(indicators_a) == aggregate_status(indicators_b) == UNKNOWN


# --------------------------------------------------------------------------
# compute_update_state
# --------------------------------------------------------------------------


def test_update_state_no_content_is_na() -> None:
    host = _host_without_content()
    indicators = compute_host_indicators(host, {}, _config(), now=NOW)
    assert compute_update_state(host, indicators) == UPDATE_STATE_NA


def test_update_state_checkin_crit_is_unverifiable() -> None:
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = "2026-11-09 12:00:00 UTC"
    host = host_from_api(raw)
    indicators = compute_host_indicators(host, {}, _config(), now=NOW)
    assert compute_update_state(host, indicators) == UPDATE_STATE_UNVERIFIABLE


def test_update_state_checkin_unknown_is_unverifiable() -> None:
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = None
    host = host_from_api(raw)
    indicators = compute_host_indicators(host, {}, _config(), now=NOW)
    assert compute_update_state(host, indicators) == UPDATE_STATE_UNVERIFIABLE


def test_update_state_errata_counts_unknown_is_unverifiable() -> None:
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = "2026-11-17 11:00:00 UTC"
    del raw["content_facet_attributes"]["errata_counts"]
    host = host_from_api(raw)
    indicators = compute_host_indicators(host, {}, _config(), now=NOW)
    assert compute_update_state(host, indicators) == UPDATE_STATE_UNVERIFIABLE


def test_update_state_installable_security_is_outdated() -> None:
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = "2026-11-17 11:00:00 UTC"
    raw["content_facet_attributes"]["errata_counts"]["security"] = 1
    host = host_from_api(raw)
    indicators = compute_host_indicators(host, {}, _config(), now=NOW)
    assert compute_update_state(host, indicators) == UPDATE_STATE_OUTDATED


def test_update_state_installable_bugfix_alone_is_outdated() -> None:
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = "2026-11-17 11:00:00 UTC"
    raw["content_facet_attributes"]["errata_counts"]["security"] = 0
    raw["content_facet_attributes"]["errata_counts"]["bugfix"] = 1
    raw["content_facet_attributes"]["errata_counts"]["applicable"]["security"] = 0
    raw["content_facet_attributes"]["content_view_environments"] = []
    host = host_from_api(raw)
    indicators = compute_host_indicators(host, {}, _config(), now=NOW)
    assert compute_update_state(host, indicators) == UPDATE_STATE_OUTDATED


def test_update_state_applicable_not_installable_is_content_pending() -> None:
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = "2026-11-17 11:00:00 UTC"
    raw["content_facet_attributes"]["errata_counts"]["security"] = 0
    raw["content_facet_attributes"]["errata_counts"]["bugfix"] = 0
    raw["content_facet_attributes"]["errata_counts"]["applicable"]["security"] = 3
    raw["content_facet_attributes"]["content_view_environments"] = []
    host = host_from_api(raw)
    indicators = compute_host_indicators(host, {}, _config(), now=NOW)
    assert compute_update_state(host, indicators) == UPDATE_STATE_CONTENT_PENDING


def test_update_state_cv_waiting_is_content_pending() -> None:
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = "2026-11-17 11:00:00 UTC"
    raw["content_facet_attributes"]["errata_counts"]["security"] = 0
    raw["content_facet_attributes"]["errata_counts"]["bugfix"] = 0
    raw["content_facet_attributes"]["errata_counts"]["applicable"]["security"] = 0
    host = host_from_api(raw)
    deployed = _version(24, NOW - dt.timedelta(days=30), frozenset({3}))
    newer = _version(25, NOW - dt.timedelta(days=2), frozenset())
    indicators = compute_host_indicators(host, {3: [deployed, newer]}, _config(), now=NOW)
    assert compute_update_state(host, indicators) == UPDATE_STATE_CONTENT_PENDING


def test_update_state_fully_up_to_date() -> None:
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = "2026-11-17 11:00:00 UTC"
    raw["content_facet_attributes"]["errata_counts"]["security"] = 0
    raw["content_facet_attributes"]["errata_counts"]["bugfix"] = 0
    raw["content_facet_attributes"]["errata_counts"]["applicable"]["security"] = 0
    host = host_from_api(raw)
    deployed = _version(24, NOW - dt.timedelta(days=30), frozenset({3}))
    indicators = compute_host_indicators(host, {3: [deployed]}, _config(), now=NOW)
    assert compute_update_state(host, indicators) == UPDATE_STATE_UP_TO_DATE


# --------------------------------------------------------------------------
# Priorites de compute_update_state (ordre des regles)
# --------------------------------------------------------------------------


def test_update_state_priority_checkin_crit_wins_over_outdated() -> None:
    # Check-in CRIT et des errata installables en meme temps : unverifiable
    # l'emporte (on ne peut pas se fier aux donnees d'un hote qui n'a pas
    # fait de check-in recent, meme si elles semblent indiquer "outdated").
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = "2026-11-09 12:00:00 UTC"  # CRIT
    raw["content_facet_attributes"]["errata_counts"]["security"] = 5
    host = host_from_api(raw)
    indicators = compute_host_indicators(host, {}, _config(), now=NOW)
    assert compute_update_state(host, indicators) == UPDATE_STATE_UNVERIFIABLE


def test_update_state_priority_outdated_wins_over_content_pending() -> None:
    # Au moins un erratum installable ET du contenu en attente (CV) en meme
    # temps : outdated l'emporte (installable est plus grave que "en
    # attente de promotion").
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = "2026-11-17 11:00:00 UTC"
    raw["content_facet_attributes"]["errata_counts"]["security"] = 1
    host = host_from_api(raw)
    deployed = _version(24, NOW - dt.timedelta(days=30), frozenset({3}))
    newer = _version(25, NOW - dt.timedelta(days=5), frozenset())
    indicators = compute_host_indicators(host, {3: [deployed, newer]}, _config(), now=NOW)
    assert compute_update_state(host, indicators) == UPDATE_STATE_OUTDATED


def test_update_state_priority_na_before_everything_else() -> None:
    # Sans donnees de contenu, n/a l'emporte meme si le reste des champs
    # bruts (check-in, etc.) semble en bon etat.
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = "2026-11-17 11:00:00 UTC"
    raw["content_facet_attributes"] = None
    host = host_from_api(raw)
    indicators = compute_host_indicators(host, {}, _config(), now=NOW)
    assert compute_update_state(host, indicators) == UPDATE_STATE_NA


def test_update_state_in_build_is_always_unverifiable() -> None:
    # Pendant un build, les compteurs ne sont pas fiables (c'est pour ca que
    # errata_security et traces sont N/A) : update_state ne conclut jamais
    # outdated/pending/up_to_date sur ces donnees, meme si le check-in est
    # bon et les compteurs installables a zero.
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = "2026-11-17 11:00:00 UTC"
    raw["content_facet_attributes"]["errata_counts"]["security"] = 0
    raw["content_facet_attributes"]["errata_counts"]["bugfix"] = 0
    raw["content_facet_attributes"]["errata_counts"]["applicable"]["security"] = 0
    raw["content_facet_attributes"]["content_view_environments"] = []
    raw["build"] = True
    host = host_from_api(raw)
    indicators = compute_host_indicators(host, {}, _config(), now=NOW)
    assert indicators.errata_security.status == NA
    assert indicators.traces.status == NA
    assert compute_update_state(host, indicators) == UPDATE_STATE_UNVERIFIABLE


# --------------------------------------------------------------------------
# Agregats parc et par LCE
# --------------------------------------------------------------------------


def test_compute_fleet_summary_security_installable_excludes_na_and_build() -> None:
    raw_ok = _raw_host(0)
    raw_ok["subscription_facet_attributes"]["last_checkin"] = "2026-11-17 11:00:00 UTC"
    raw_ok["content_facet_attributes"]["errata_counts"]["security"] = 2
    host_ok = host_from_api(raw_ok)

    host_build = _host(1, build=True)  # a du contenu mais en build : exclu
    host_no_content = _host_without_content()  # N/A sur les 4 indicateurs : exclu

    config = _config()
    evaluated = [
        evaluate_host(host_ok, {}, config, now=NOW),
        evaluate_host(host_build, {}, config, now=NOW),
        evaluate_host(host_no_content, {}, config, now=NOW),
    ]
    summary = compute_fleet_summary(evaluated)
    assert summary.security_installable_total == 2
    assert summary.in_build == 1
    assert summary.na == 1
    assert summary.total == 3
    assert summary.evaluated == 2


def test_compute_cv_lag_environments_counts_distinct_lce_in_warn_or_crit() -> None:
    config = _config()
    pair_prod = _pair(environment_name="Production", content_view_id=3)
    pair_staging = _pair(environment_name="Staging", content_view_id=3)
    deployed = _version(24, NOW - dt.timedelta(days=90), frozenset({3}))
    newer_crit = _version(25, NOW - dt.timedelta(days=45), frozenset())

    raw = _raw_host(0)
    host = host_from_api(raw)
    host.content_view_pairs = [pair_prod, pair_staging]
    evaluated = evaluate_host(host, {3: [deployed, newer_crit]}, config, now=NOW)

    assert compute_cv_lag_environments([evaluated]) == 2


def test_compute_by_lce_groups_and_picks_worst_status() -> None:
    config = _config()
    raw_a = _raw_host(0)
    raw_a["subscription_facet_attributes"]["last_checkin"] = "2026-11-17 11:00:00 UTC"
    raw_a["content_facet_attributes"]["errata_counts"]["security"] = 0
    host_a = host_from_api(raw_a)  # Production

    raw_b = _raw_host(1)  # Staging, reste tel quel (peut etre WARN/CRIT selon les donnees reelles)
    host_b = host_from_api(raw_b)

    evaluated = [evaluate_host(host_a, {}, config, now=NOW), evaluate_host(host_b, {}, config, now=NOW)]
    by_lce = compute_by_lce(evaluated, ["Library", "Staging", "Production"])
    names = [s.name for s in by_lce]
    assert "Production" in names and "Staging" in names
    production = next(s for s in by_lce if s.name == "Production")
    assert production.vms == 1


def test_compute_by_lce_host_with_multiple_lce_counted_in_each(tmp_path: Path) -> None:
    # Cas theorique (jamais observe) : un hote dont les couples CV/LCE
    # couvrent deux environnements distincts compte dans chacune des deux
    # lignes --by-lce (docs/cadrage.md : la somme peut alors depasser le
    # total du parc).
    config = _config()
    raw = _raw_host(0)
    host = host_from_api(raw)
    host.content_view_pairs = [
        _pair(environment_name="Production", content_view_id=3),
        _pair(environment_name="Staging", content_view_id=3),
    ]
    evaluated = [evaluate_host(host, {}, config, now=NOW)]
    by_lce = compute_by_lce(evaluated, ["Library", "Staging", "Production"])
    counted = {s.name: s.vms for s in by_lce}
    assert counted.get("Production") == 1
    assert counted.get("Staging") == 1


def test_compute_by_lce_excludes_na_hosts() -> None:
    config = _config()
    host_na = _host_without_content()
    evaluated = [evaluate_host(host_na, {}, config, now=NOW)]
    by_lce = compute_by_lce(evaluated, ["Library", "Staging", "Production"])
    # Un hote N/A n'a aucun environnement (point 2b) : aucune ligne --by-lce
    # ne le compte, et aucune ligne n'est meme creee puisque personne n'y
    # appartient.
    assert by_lce == []


def test_compute_by_lce_order_is_promotion_then_alphabetical() -> None:
    config = _config()
    host = host_from_api(_raw_host(0))
    host.content_view_pairs = [
        _pair(environment_name="Zorg", content_view_id=3),
        _pair(environment_name="Alpha", content_view_id=3),
    ]
    evaluated = [evaluate_host(host, {}, config, now=NOW)]
    # "Production" et "Staging" sont dans l'ordre de promotion fourni (mais
    # aucun hote n'y appartient ici, donc ils ne produisent pas de ligne) ;
    # "Zorg" et "Alpha" ne sont dans aucun ordre de promotion connu : ils
    # doivent sortir par ordre alphabetique, jamais par ordre de rencontre
    # (les environnements d'un hote sont stockes dans un frozenset,
    # non ordonne).
    by_lce = compute_by_lce(evaluated, ["Library", "Staging", "Production"])
    assert [s.name for s in by_lce] == ["Alpha", "Zorg"]


def test_compute_by_lce_security_critical_total_is_always_none() -> None:
    config = _config()
    host = host_from_api(_raw_host(0))
    evaluated = [evaluate_host(host, {}, config, now=NOW)]
    by_lce = compute_by_lce(evaluated, ["Library", "Staging", "Production"])
    assert all(s.security_critical_total is None for s in by_lce)


# --------------------------------------------------------------------------
# Indicateurs de plateforme
# --------------------------------------------------------------------------


def test_ping_status_all_ok() -> None:
    assert compute_ping_status(PingResult(services={"candlepin": "ok", "pulp3": "ok"})) == OK


def test_ping_status_one_service_down_is_crit() -> None:
    assert compute_ping_status(PingResult(services={"candlepin": "ok", "pulp3": "down"})) == CRIT


def test_tasks_status_empty_is_ok() -> None:
    assert compute_tasks_status(RecentTaskFailures(total=0, tasks=[], omitted=0)) == OK


def test_tasks_status_non_sync_label_is_warn() -> None:
    summary = TaskSummary(
        label="Actions::RemoteExecution::RunHostJob", state="stopped", result="error", started_at=None
    )
    tasks = RecentTaskFailures(total=1, tasks=[summary], omitted=0)
    assert compute_tasks_status(tasks) == WARN


def test_tasks_status_sync_label_is_crit() -> None:
    summary = TaskSummary(label="Actions::Katello::Repository::Sync", state="stopped", result="error", started_at=None)
    tasks = RecentTaskFailures(total=1, tasks=[summary], omitted=0)
    assert compute_tasks_status(tasks) == CRIT


def test_tasks_status_sync_plan_run_is_crit() -> None:
    tasks = RecentTaskFailures(
        total=1,
        tasks=[TaskSummary(label="Actions::Katello::SyncPlan::Run", state="stopped", result="error", started_at=None)],
        omitted=0,
    )
    assert compute_tasks_status(tasks) == CRIT


def test_pulp_disk_status_ok() -> None:
    disk = PulpDisk(total_bytes=100, used_bytes=10, free_bytes=90)  # 90% libre
    assert compute_pulp_disk_status(disk, _config()) == OK


def test_pulp_disk_status_warn_at_threshold() -> None:
    disk = PulpDisk(total_bytes=100, used_bytes=81, free_bytes=19)  # 19% libre, seuil WARN=20
    assert compute_pulp_disk_status(disk, _config()) == WARN


def test_pulp_disk_status_crit_at_threshold() -> None:
    disk = PulpDisk(total_bytes=100, used_bytes=91, free_bytes=9)  # 9% libre, seuil CRIT=10
    assert compute_pulp_disk_status(disk, _config()) == CRIT


# --------------------------------------------------------------------------
# collect_unknown_entries : deduplication
# --------------------------------------------------------------------------


def test_collect_unknown_entries_deduplicates_profile_across_many_hosts() -> None:
    config = _config()
    hosts = [host_from_api(_raw_host(i)) for i in range(5) if i != 10]
    evaluated = [evaluate_host(h, {}, config, now=NOW) for h in hosts]
    entries = collect_unknown_entries(evaluated)
    profile_entries = [e for e in entries if e["indicator"] == "profile"]
    assert len(profile_entries) == 1


def test_collect_unknown_entries_excludes_na_and_non_unknown() -> None:
    config = _config()
    raw = _raw_host(0)
    raw["subscription_facet_attributes"]["last_checkin"] = "2026-11-17 11:00:00 UTC"  # OK, pas d'entree
    host = host_from_api(raw)
    evaluated = [evaluate_host(host, {}, config, now=NOW)]
    entries = collect_unknown_entries(evaluated)
    assert all(e["indicator"] != "checkin" for e in entries)
