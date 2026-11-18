"""Sortie lisible (mode manuel, pas de JSON). Aucun calcul de statut ici.

Les deux fonctions ci-dessous lisent le meme dictionnaire `data` que celui
mis dans l'enveloppe JSON (construit par `commands/summary.py` et
`commands/list.py`) : un seul calcul, deux presentations.
"""
from __future__ import annotations

from typing import Any

_UPDATE_STATE_LABELS = {
    "up_to_date": "Oui",
    "up_to_date_content_pending": "Oui*",
    "outdated": "Non",
    "unverifiable": "?",
    "n/a": "-",
}


def _pad(value: str, width: int) -> str:
    return value if len(value) >= width else value + " " * (width - len(value))


def _row(values: list[str], widths: list[int]) -> str:
    return "".join(_pad(v, w) for v, w in zip(values, widths))


def render_summary_text(data: dict[str, Any]) -> str:
    platform = data["platform"]
    fleet = data["fleet"]
    lines: list[str] = ["Plateforme"]

    ping = platform.get("ping")
    if ping is not None:
        lines.append(f"  Ping des services : {ping['status']}")
        for name, status in sorted(ping["services"].items()):
            lines.append(f"    - {name} : {status}")
    else:
        lines.append("  Ping des services : ? (indisponible)")

    tasks = platform.get("tasks")
    if tasks is not None:
        lines.append(
            f"  Taches en erreur ou en pause (24h) : {tasks['status']}"
            f" ({tasks['failing_or_paused_24h']} au total, {len(tasks['tasks'])} affichees,"
            f" {tasks['tasks_omitted']} omises)"
        )
    else:
        lines.append("  Taches en erreur ou en pause (24h) : ? (indisponible)")

    disk = platform.get("pulp_disk")
    if disk is not None:
        lines.append(f"  Disque Pulp : {disk['status']} ({disk['free_pct']:.1f}% libre)")
    else:
        lines.append("  Disque Pulp : ? (indisponible)")

    lines.append("")
    lines.append("Parc")
    lines.append(f"  Total : {fleet['total']} ({fleet['evaluated']} evaluees, {fleet['na']} N/A)")
    lines.append("  Statuts : OK={OK} WARN={WARN} CRIT={CRIT} UNKNOWN={UNKNOWN}".format(**fleet["status_counts"]))
    lines.append(
        "  A jour : Oui={up_to_date} Oui*={up_to_date_content_pending} Non={outdated} ?={unverifiable}".format(
            **fleet["update_state_counts"]
        )
    )
    lines.append(f"  Donnees obsoletes : {fleet['stale_data']}")
    lines.append(f"  Errata security installables (somme) : {fleet['security_installable_total']}")
    lines.append(f"  Redemarrage requis : {fleet['reboot_required']}")
    lines.append(f"  En build : {fleet['in_build']}")
    lines.append(f"  Environnements en retard de CV : {fleet['cv_lag_environments']}")

    by_lce = data.get("by_lce")
    if by_lce is not None:
        lines.append("")
        lines.append("Conformite par Lifecycle Environment")
        header = ["LCE", "VMs", "OK", "WARN", "CRIT", "?", "Sec.inst.", "Obsoletes", "Attente CV", "Statut"]
        widths = [14, 5, 4, 5, 5, 3, 10, 10, 11, 7]
        lines.append("  " + _row(header, widths))
        for entry in by_lce:
            row = [
                entry["name"],
                str(entry["vms"]),
                str(entry["status_counts"]["OK"]),
                str(entry["status_counts"]["WARN"]),
                str(entry["status_counts"]["CRIT"]),
                str(entry["status_counts"]["UNKNOWN"]),
                str(entry["security_installable_total"]),
                str(entry["stale_data_vms"]),
                f"{entry['max_cv_waiting_days']}j",
                entry["status"],
            ]
            lines.append("  " + _row(row, widths))

    return "\n".join(lines)


def _primary_content_view(content_views: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Pour une VM multi-CV, la CV montree dans la colonne compacte du texte.

    Celle dont l'attente de promotion (`waiting_days`) est la plus longue :
    c'est la plus susceptible d'etre le probleme a regarder. A egalite (y
    compris 0 partout), ordre alphabetique du nom pour rester deterministe
    (`max` renvoie le premier maximum rencontre, d'ou le tri prealable). Le
    detail complet des CV reste dans `content_views` en JSON ; cette regle
    ne vaut que pour la colonne unique du mode texte.
    """
    if not content_views:
        return None
    ordered = sorted(content_views, key=lambda cv: cv.get("name") or "")
    return max(ordered, key=lambda cv: cv.get("waiting_days") or 0)


def render_list_text(hosts: list[dict[str, Any]], *, limit: int | None = None) -> str:
    header = ["Nom", "LCE", "CV (version)", "Check-in", "Sec.inst.", "Reboot", "A jour", "Statut"]
    widths = [22, 12, 32, 10, 10, 7, 7, 8]
    lines = [_row(header, widths)]

    shown = hosts if limit is None else hosts[:limit]
    for entry in shown:
        content_views = entry.get("content_views") or []
        primary = _primary_content_view(content_views)
        if primary is not None:
            cv_text = f"{primary['name']} ({primary['version_deployed']})"
            if len(content_views) > 1:
                cv_text += f" (+{len(content_views) - 1})"
        else:
            cv_text = "-"
        indicators = entry["indicators"]
        checkin_text = indicators["checkin"]
        security = entry["errata"]["installable"].get("security")
        security_text = "?" if security is None else str(security)
        reboot_text = "oui" if entry.get("reboot_required") else "non"
        up_to_date_text = _UPDATE_STATE_LABELS.get(entry["update_state"], "?")
        row = [
            entry["name"],
            entry.get("lifecycle_environment") or "-",
            cv_text,
            checkin_text,
            security_text,
            reboot_text,
            up_to_date_text,
            entry["status"],
        ]
        lines.append(_row(row, widths))

    omitted = len(hosts) - len(shown)
    if omitted > 0:
        lines.append(f"... {omitted} ligne(s) omise(s) (--limit, --format json ou --monitoring pour tout voir)")
    return "\n".join(lines)
