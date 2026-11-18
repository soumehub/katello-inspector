from __future__ import annotations

from katello_inspector.render_text import _primary_content_view, render_list_text


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
