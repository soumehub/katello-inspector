from __future__ import annotations

import re

from katello_inspector.render_text import (
    _column_widths,
    _primary_content_view,
    _render_table,
    render_list_text,
    render_summary_text,
)


def _entry(**overrides: object) -> dict:
    base = {
        "name": "vmXX",
        "status": "OK",
        "update_state": "up_to_date",
        "lifecycle_environment": "Production",
        "content_views": [],
        "freshness": {"last_checkin": None, "checkin_age_days": None, "package_profile_age_days": None},
        "errata": {"installable": {"security": 0, "bugfix": 0, "enhancement": 0}, "applicable_not_installable": {}},
        "reboot_required": False,
        "in_build": False,
        "content_source": None,
        "indicators": {
            "checkin": "OK",
            "profile": "UNKNOWN",
            "errata_security": "OK",
            "cv_lag": "OK",
            "traces": "OK",
            "build": "N/A",
        },
    }
    base.update(overrides)
    return base


def test_primary_content_view_empty_list_is_none() -> None:
    assert _primary_content_view([]) is None


def test_primary_content_view_single_entry() -> None:
    cvs = [{"name": "cv-un", "version_deployed": "1.0", "waiting_days": 0}]
    assert _primary_content_view(cvs) is cvs[0]


def test_primary_content_view_picks_the_longest_wait() -> None:
    cvs = [
        {"name": "cv-a", "version_deployed": "1.0", "waiting_days": 3},
        {"name": "cv-b", "version_deployed": "1.0", "waiting_days": 20},
        {"name": "cv-c", "version_deployed": "1.0", "waiting_days": 7},
    ]
    assert _primary_content_view(cvs)["name"] == "cv-b"


def test_primary_content_view_ties_broken_alphabetically() -> None:
    cvs = [
        {"name": "cv-zebre", "version_deployed": "1.0", "waiting_days": 5},
        {"name": "cv-alpha", "version_deployed": "1.0", "waiting_days": 5},
    ]
    assert _primary_content_view(cvs)["name"] == "cv-alpha"


def test_primary_content_view_missing_waiting_days_treated_as_zero() -> None:
    cvs = [
        {"name": "cv-a", "version_deployed": "1.0", "waiting_days": None},
        {"name": "cv-b", "version_deployed": "1.0", "waiting_days": 4},
    ]
    assert _primary_content_view(cvs)["name"] == "cv-b"


def test_render_list_text_shows_primary_cv_and_extra_count() -> None:
    entry = _entry(
        content_views=[
            {"name": "cv-a", "version_deployed": "1.0", "waiting_days": 1},
            {"name": "cv-b", "version_deployed": "2.0", "waiting_days": 30},
        ]
    )
    rendered = render_list_text([entry])
    assert "cv-b (2.0) (+1)" in rendered


# --------------------------------------------------------------------------
# Largeur des colonnes : maximum entre en-tete et cellules, deux espaces
# entre colonnes, aucun debordement sur un nom ou une CV longs.
# --------------------------------------------------------------------------


def test_column_widths_is_max_of_header_and_cells() -> None:
    header = ["Nom", "LCE"]
    rows = [["court", "Production"], ["vm-nom-tres-long-de-plus-de-vingt-caracteres", "QA"]]
    widths = _column_widths(header, rows)
    assert widths == [len("vm-nom-tres-long-de-plus-de-vingt-caracteres"), len("Production")]


def test_render_table_separates_columns_with_two_spaces() -> None:
    header = ["Nom", "LCE"]
    rows = [["vm-nom-tres-long-de-plus-de-quarante-caracteres-ou-plus", "Production"]]
    lines = _render_table(header, rows)
    name_width = max(len(header[0]), len(rows[0][0]))
    assert lines[1][name_width : name_width + 2] == "  "


def test_render_list_text_keeps_columns_separated_with_long_names() -> None:
    long_name = "vm-" + "x" * 45 + ".example.com"
    long_cv = "cv-" + "y" * 40
    entry = _entry(
        name=long_name,
        content_views=[{"name": long_cv, "version_deployed": "12.0", "waiting_days": 0}],
    )
    rendered = render_list_text([entry])
    header_line, data_line = rendered.splitlines()[:2]

    # Chaque colonne reste separee d'au moins deux espaces : aucun champ ne
    # deborde sur le suivant, meme avec un FQDN et un nom de CV de plus de
    # 40 caracteres.
    fields = re.split(r" {2,}", data_line.rstrip())
    assert fields[0] == long_name
    assert fields[1] == "Production"
    assert fields[2] == f"{long_cv} (12.0)"

    header_fields = re.split(r" {2,}", header_line.rstrip())
    assert header_fields[0] == "Nom"
    assert header_fields[1] == "LCE"


def _summary_data(**overrides: object) -> dict:
    base = {
        "platform": {"ping": None, "tasks": None, "pulp_disk": None},
        "fleet": {
            "total": 0,
            "evaluated": 0,
            "na": 0,
            "status_counts": {"OK": 0, "WARN": 0, "CRIT": 0, "UNKNOWN": 0},
            "update_state_counts": {
                "up_to_date": 0,
                "up_to_date_content_pending": 0,
                "outdated": 0,
                "unverifiable": 0,
            },
            "stale_data": 0,
            "security_installable_total": 0,
            "reboot_required": 0,
            "in_build": 0,
            "cv_lag_environments": 0,
        },
        "by_lce": None,
    }
    base.update(overrides)
    return base


def test_render_summary_text_by_lce_table_keeps_columns_separated_with_long_names() -> None:
    long_lce = "Lifecycle-Environment-Avec-Un-Nom-Tres-Long-De-Plus-De-Quarante-Caracteres"
    data = _summary_data(
        by_lce=[
            {
                "name": long_lce,
                "vms": 3,
                "status_counts": {"OK": 2, "WARN": 1, "CRIT": 0, "UNKNOWN": 0},
                "security_installable_total": 0,
                "stale_data_vms": 0,
                "max_cv_waiting_days": 0,
                "status": "WARN",
            }
        ]
    )
    rendered = render_summary_text(data)
    lines = [line for line in rendered.splitlines() if line.strip()]
    header_line = next(line for line in lines if line.strip().startswith("LCE"))
    data_line = lines[lines.index(header_line) + 1]

    fields = re.split(r" {2,}", data_line.strip())
    assert fields[0] == long_lce
    assert fields[-1] == "WARN"
