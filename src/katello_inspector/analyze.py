"""Calcul des statuts et des seuils. Aucun appel API ici.

Toutes les fonctions sont pures : donnees collectees (`collect.py`) et
configuration (`config.py`) en entree, statuts en sortie. `profile` et
`build` sont des indicateurs structurellement indisponibles en v1 (V4, V14) :
affiches avec leur raison mais exclus du calcul du statut d'une VM
(`aggregate_status`).
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from . import config as config_mod
from .collect import ContentViewVersion, Host, HostContentViewPair

OK = "OK"
WARN = "WARN"
CRIT = "CRIT"
UNKNOWN = "UNKNOWN"
NA = "N/A"

UPDATE_STATE_UNVERIFIABLE = "unverifiable"
UPDATE_STATE_OUTDATED = "outdated"
UPDATE_STATE_CONTENT_PENDING = "up_to_date_content_pending"
UPDATE_STATE_UP_TO_DATE = "up_to_date"
UPDATE_STATE_NA = "n/a"

_SEVERITY_ORDER = {CRIT: 0, WARN: 1, UNKNOWN: 2, OK: 3}

# Seule valeur confirmee pour traces_status (docs/api-findings.md, V13 :
# "0 = No processes require restarting"). Toute autre valeur est UNKNOWN :
# son codage n'a jamais ete observe, on ne le suppose pas.
TRACES_STATUS_NO_TRACE = 0


def _now(now: dt.datetime | None) -> dt.datetime:
    return now if now is not None else dt.datetime.now(dt.timezone.utc)


# --------------------------------------------------------------------------
# Indicateurs par VM
# --------------------------------------------------------------------------


@dataclass
class Indicator:
    status: str
    reason: str | None = None


@dataclass
class CvLagPairResult:
    pair: HostContentViewPair
    status: str
    reason: str | None
    waiting_days: int | None


@dataclass
class HostIndicators:
    checkin: Indicator
    profile: Indicator
    errata_security: Indicator
    cv_lag: Indicator
    traces: Indicator
    build: Indicator
    cv_lag_pairs: list[CvLagPairResult] = field(default_factory=list)


def compute_checkin_indicator(host: Host, config: config_mod.Config, *, now: dt.datetime | None = None) -> Indicator:
    if not host.has_content:
        return Indicator(NA)
    if host.last_checkin is None:
        return Indicator(UNKNOWN, "date de dernier check-in absente ou invalide")
    age_days = (_now(now) - host.last_checkin).days
    if age_days < 0:
        return Indicator(UNKNOWN, f"date de dernier check-in dans le futur ({host.last_checkin.isoformat()})")
    threshold = config_mod.threshold_for(config, "checkin_days")
    if age_days > threshold:
        return Indicator(CRIT, f"dernier check-in il y a {age_days} jours (seuil {threshold})")
    return Indicator(OK)


def compute_errata_security_indicator(host: Host, config: config_mod.Config) -> Indicator:
    if not host.has_content:
        return Indicator(NA)
    if host.build:
        return Indicator(NA)
    if host.errata_installable is None:
        return Indicator(UNKNOWN, "compteurs d'errata installables absents")
    security = host.errata_installable.get("security")
    if security is None:
        return Indicator(UNKNOWN, "compteur d'errata security installable absent")
    crit = config_mod.threshold_for(config, "security_crit")
    warn = config_mod.threshold_for(config, "security_warn")
    if security >= crit:
        return Indicator(CRIT, f"{security} errata security installables (seuil CRIT {crit})")
    if security >= warn:
        return Indicator(WARN, f"{security} errata security installables (seuil WARN {warn})")
    return Indicator(OK)


def compute_traces_indicator(host: Host) -> Indicator:
    if not host.has_content:
        return Indicator(NA)
    if host.build:
        return Indicator(NA)
    if host.traces_status is None:
        return Indicator(UNKNOWN, "champ traces_status absent")
    if host.traces_status == TRACES_STATUS_NO_TRACE:
        return Indicator(OK)
    return Indicator(UNKNOWN, f"codage de traces_status={host.traces_status!r} non confirme (V13)")


def compute_profile_indicator(host: Host) -> Indicator:
    if not host.has_content:
        return Indicator(NA)
    return Indicator(UNKNOWN, "aucune date de profil de paquets exposee par l'API (V4)")


def compute_build_indicator(host: Host) -> Indicator:
    if not host.build:
        return Indicator(NA)
    return Indicator(UNKNOWN, "duree de build non exposee par l'API (V14)")


def compute_cv_lag_for_pair(
    pair: HostContentViewPair,
    versions_by_cv: dict[int, list[ContentViewVersion]],
    config: config_mod.Config,
    *,
    now: dt.datetime | None = None,
) -> CvLagPairResult:
    if pair.content_view_rolling:
        return CvLagPairResult(pair, NA, None, None)
    if not config_mod.cv_lag_enabled(config, lce=pair.environment_name, cv=pair.content_view_name):
        return CvLagPairResult(pair, NA, None, None)
    if pair.version_deployed_id is None or pair.environment_id is None:
        return CvLagPairResult(pair, UNKNOWN, "couple CV/environnement incomplet", None)

    versions = versions_by_cv.get(pair.content_view_id, []) if pair.content_view_id is not None else []
    deployed = next((v for v in versions if v.id == pair.version_deployed_id), None)
    if deployed is None or deployed.created_at is None:
        return CvLagPairResult(pair, UNKNOWN, "date de publication de la version deployee absente", None)

    candidates = [
        v
        for v in versions
        if v.created_at is not None
        and v.created_at > deployed.created_at
        and pair.environment_id not in v.environment_ids
    ]
    if not candidates:
        return CvLagPairResult(pair, OK, None, 0)

    earliest = min(candidates, key=lambda v: v.created_at or dt.datetime.max.replace(tzinfo=dt.timezone.utc))
    assert earliest.created_at is not None
    waiting_days = (_now(now) - earliest.created_at).days

    crit = config_mod.threshold_for(config, "cv_lag_crit_days", lce=pair.environment_name, cv=pair.content_view_name)
    warn = config_mod.threshold_for(config, "cv_lag_warn_days", lce=pair.environment_name, cv=pair.content_view_name)
    if waiting_days >= crit:
        return CvLagPairResult(pair, CRIT, f"version plus recente en attente depuis {waiting_days} jours", waiting_days)
    if waiting_days >= warn:
        return CvLagPairResult(pair, WARN, f"version plus recente en attente depuis {waiting_days} jours", waiting_days)
    return CvLagPairResult(pair, OK, None, waiting_days)


def compute_cv_lag_indicator(
    host: Host,
    versions_by_cv: dict[int, list[ContentViewVersion]],
    config: config_mod.Config,
    *,
    now: dt.datetime | None = None,
) -> tuple[Indicator, list[CvLagPairResult]]:
    if not host.content_view_pairs:
        return Indicator(NA), []
    results = [compute_cv_lag_for_pair(pair, versions_by_cv, config, now=now) for pair in host.content_view_pairs]
    non_na = [r for r in results if r.status != NA]
    if not non_na:
        return Indicator(NA), results
    worst = min(non_na, key=lambda r: _SEVERITY_ORDER[r.status])
    return Indicator(worst.status, worst.reason), results


def compute_host_indicators(
    host: Host,
    versions_by_cv: dict[int, list[ContentViewVersion]],
    config: config_mod.Config,
    *,
    now: dt.datetime | None = None,
) -> HostIndicators:
    cv_lag, cv_lag_pairs = compute_cv_lag_indicator(host, versions_by_cv, config, now=now)
    return HostIndicators(
        checkin=compute_checkin_indicator(host, config, now=now),
        profile=compute_profile_indicator(host),
        errata_security=compute_errata_security_indicator(host, config),
        cv_lag=cv_lag,
        traces=compute_traces_indicator(host),
        build=compute_build_indicator(host),
        cv_lag_pairs=cv_lag_pairs,
    )


def aggregate_status(indicators: HostIndicators) -> str:
    """CRIT > WARN > UNKNOWN > OK ; N/A exclu. `profile`/`build` n'entrent

    jamais ici (indisponibles structurellement en v1, voir le module).
    """
    relevant = [
        indicators.checkin.status,
        indicators.errata_security.status,
        indicators.cv_lag.status,
        indicators.traces.status,
    ]
    non_na = [s for s in relevant if s != NA]
    if not non_na:
        return NA
    return min(non_na, key=lambda s: _SEVERITY_ORDER[s])


_ERRATA_TYPES = ("security", "bugfix", "enhancement")


def compute_applicable_not_installable(host: Host) -> dict[str, int]:
    """Detail par type (securite/bugfix/enhancement) : applicable moins installable.

    Erratum applicable mais present seulement dans du contenu que la VM ne
    voit pas encore (version publiee non promue, ou contenu non publie).
    """
    installable = host.errata_installable or {}
    applicable = host.errata_applicable or {}
    return {t: (applicable.get(t) or 0) - (installable.get(t) or 0) for t in _ERRATA_TYPES}


def compute_update_state(host: Host, indicators: HostIndicators) -> str:
    if not host.has_content:
        return UPDATE_STATE_NA
    if host.build:
        # Les compteurs ne sont pas fiables pendant un build (errata_security
        # et traces sont d'ailleurs N/A pour cette raison) : on ne conclut
        # jamais outdated/pending/up_to_date sur des donnees potentiellement
        # obsoletes.
        return UPDATE_STATE_UNVERIFIABLE

    errata_unknown = host.errata_installable is None or host.errata_installable.get("security") is None
    if indicators.checkin.status in (CRIT, UNKNOWN) or errata_unknown:
        return UPDATE_STATE_UNVERIFIABLE

    installable = host.errata_installable or {}
    installable_total = sum(installable.get(k, 0) or 0 for k in _ERRATA_TYPES)
    if installable_total > 0:
        return UPDATE_STATE_OUTDATED

    applicable_not_installable_total = sum(compute_applicable_not_installable(host).values())
    cv_waiting = any((r.waiting_days or 0) > 0 for r in indicators.cv_lag_pairs if r.status != NA)
    if applicable_not_installable_total > 0 or cv_waiting:
        return UPDATE_STATE_CONTENT_PENDING

    return UPDATE_STATE_UP_TO_DATE


@dataclass
class EvaluatedHost:
    host: Host
    indicators: HostIndicators
    update_state: str
    status: str
    environments: frozenset[str] = field(default_factory=frozenset)


def evaluate_host(
    host: Host,
    versions_by_cv: dict[int, list[ContentViewVersion]],
    config: config_mod.Config,
    *,
    now: dt.datetime | None = None,
) -> EvaluatedHost:
    indicators = compute_host_indicators(host, versions_by_cv, config, now=now)
    update_state = compute_update_state(host, indicators)
    status = aggregate_status(indicators)
    environments = frozenset(
        p.environment_name for p in host.content_view_pairs if p.environment_name is not None
    )
    return EvaluatedHost(
        host=host, indicators=indicators, update_state=update_state, status=status, environments=environments
    )


# --------------------------------------------------------------------------
# Agregats parc et par LCE
# --------------------------------------------------------------------------

_UPDATE_STATE_KEYS = (
    UPDATE_STATE_UP_TO_DATE,
    UPDATE_STATE_CONTENT_PENDING,
    UPDATE_STATE_OUTDATED,
    UPDATE_STATE_UNVERIFIABLE,
    UPDATE_STATE_NA,
)
_STATUS_KEYS = (OK, WARN, CRIT, UNKNOWN)


def _empty_update_state_counts() -> dict[str, int]:
    return dict.fromkeys(_UPDATE_STATE_KEYS, 0)


def _empty_status_counts() -> dict[str, int]:
    return dict.fromkeys(_STATUS_KEYS, 0)


@dataclass
class FleetSummary:
    total: int
    evaluated: int
    na: int
    status_counts: dict[str, int]
    update_state_counts: dict[str, int]
    stale_data: int
    security_installable_total: int
    reboot_required: int
    in_build: int
    cv_lag_environments: int


def compute_cv_lag_environments(evaluated_hosts: list[EvaluatedHost]) -> int:
    """Nombre de LCE distincts avec au moins un couple CV/LCE en WARN ou CRIT."""
    flagged: set[str] = set()
    for eh in evaluated_hosts:
        for result in eh.indicators.cv_lag_pairs:
            if result.status in (WARN, CRIT) and result.pair.environment_name is not None:
                flagged.add(result.pair.environment_name)
    return len(flagged)


def compute_fleet_summary(evaluated_hosts: list[EvaluatedHost]) -> FleetSummary:
    status_counts = _empty_status_counts()
    update_state_counts = _empty_update_state_counts()
    stale_data = 0
    security_installable_total = 0
    reboot_required = 0
    in_build = 0
    na = 0

    for eh in evaluated_hosts:
        update_state_counts[eh.update_state] += 1
        if eh.host.build:
            in_build += 1
        if eh.status == NA:
            na += 1
        else:
            status_counts[eh.status] += 1
        if eh.indicators.checkin.status == CRIT:
            stale_data += 1
        if eh.indicators.errata_security.status != NA and eh.host.errata_installable is not None:
            security_installable_total += eh.host.errata_installable.get("security") or 0
        if eh.indicators.traces.status == WARN:
            reboot_required += 1

    return FleetSummary(
        total=len(evaluated_hosts),
        evaluated=len(evaluated_hosts) - na,
        na=na,
        status_counts=status_counts,
        update_state_counts=update_state_counts,
        stale_data=stale_data,
        security_installable_total=security_installable_total,
        reboot_required=reboot_required,
        in_build=in_build,
        cv_lag_environments=compute_cv_lag_environments(evaluated_hosts),
    )


@dataclass
class LceSummary:
    name: str
    vms: int
    status_counts: dict[str, int]
    update_state_counts: dict[str, int]
    security_installable_total: int
    security_critical_total: None
    stale_data_vms: int
    in_build: int
    max_cv_waiting_days: int
    status: str


def compute_by_lce(evaluated_hosts: list[EvaluatedHost], environment_order: list[str]) -> list[LceSummary]:
    # Ordre de promotion d'abord (environment_order, tel que fourni par
    # order_environments_by_promotion) ; tout environnement non rattache a
    # cette liste (cas non observe) vient apres, par ordre alphabetique,
    # jamais dans l'ordre de rencontre (non deterministe, les environnements
    # d'un hote sont stockes dans un frozenset).
    names = list(environment_order)
    extra = sorted({name for eh in evaluated_hosts for name in eh.environments} - set(names))
    names.extend(extra)

    summaries: list[LceSummary] = []
    for name in names:
        members = [eh for eh in evaluated_hosts if name in eh.environments]
        if not members:
            continue
        status_counts = _empty_status_counts()
        update_state_counts = _empty_update_state_counts()
        stale_data_vms = 0
        security_installable_total = 0
        in_build = 0
        max_waiting = 0
        for eh in members:
            update_state_counts[eh.update_state] += 1
            if eh.host.build:
                in_build += 1
            if eh.status != NA:
                status_counts[eh.status] += 1
            if eh.indicators.checkin.status == CRIT:
                stale_data_vms += 1
            if eh.indicators.errata_security.status != NA and eh.host.errata_installable is not None:
                security_installable_total += eh.host.errata_installable.get("security") or 0
            for result in eh.indicators.cv_lag_pairs:
                if result.pair.environment_name == name and result.waiting_days:
                    max_waiting = max(max_waiting, result.waiting_days)

        worst_status = NA
        non_na = [s for s in (eh.status for eh in members) if s != NA]
        if non_na:
            worst_status = min(non_na, key=lambda s: _SEVERITY_ORDER[s])

        summaries.append(
            LceSummary(
                name=name,
                vms=sum(1 for eh in members if eh.status != NA),
                status_counts=status_counts,
                update_state_counts=update_state_counts,
                security_installable_total=security_installable_total,
                # Toujours null : la severite par erratum vient de l'endpoint
                # par hote (/api/hosts/:id/errata), hors de summary (pas
                # d'appel par VM) ; voir docs/cadrage.md.
                security_critical_total=None,
                stale_data_vms=stale_data_vms,
                in_build=in_build,
                max_cv_waiting_days=max_waiting,
                status=worst_status,
            )
        )
    return summaries
