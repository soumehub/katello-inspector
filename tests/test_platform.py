"""Indicateurs de plateforme (ping, taches, disque Pulp), collecte + statut.

Complete test_analyze.py (qui teste compute_ping_status/compute_tasks_status/
compute_pulp_disk_status avec des objets construits a la main) en passant
par le vrai chargement JSON (collect.py) pour les trois cas ou une fixture
reelle (anonymisee) existe, et par des fixtures fabriquees dans tmp_path
pour les cas qu'une seule fixture committee ne peut pas representer.
"""
from __future__ import annotations

import json
from pathlib import Path

from katello_inspector.analyze import compute_ping_status, compute_pulp_disk_status, compute_tasks_status
from katello_inspector.api import FixtureClient
from katello_inspector.collect import collect_ping, collect_pulp_disk, collect_recent_task_failures
from katello_inspector.config import build_config

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _config():
    from types import SimpleNamespace

    return build_config(SimpleNamespace())


def _write_fixture(directory: Path, name: str, *, path: str, params: dict, response: object) -> None:
    doc = {
        "request": {"method": "GET", "path": path, "params": params},
        "status": 200,
        "kind": "ok",
        "elapsed_ms": 1,
        "response": response,
    }
    (directory / name).write_text(json.dumps(doc), encoding="utf-8")


# --------------------------------------------------------------------------
# Fixtures reelles committees : tests/fixtures/003_ping.json,
# 075_disk_pulp_api_v3_status.json, 064_tasks_echec_ou_pause_24h.json
# --------------------------------------------------------------------------


def test_ping_from_real_fixture_is_ok() -> None:
    client = FixtureClient(FIXTURES_DIR)
    ping = collect_ping(client)
    assert compute_ping_status(ping) == "OK"


def test_pulp_disk_from_real_fixture_is_ok() -> None:
    client = FixtureClient(FIXTURES_DIR)
    disk = collect_pulp_disk(client)
    assert compute_pulp_disk_status(disk, _config()) == "OK"
    # ~64% libre sur la capture reelle : loin des deux seuils par defaut.
    free_pct = disk.free_bytes / disk.total_bytes * 100
    assert 60 < free_pct < 70


def test_tasks_from_fabricated_fixture_is_crit_on_sync_in_error() -> None:
    # La fixture contient une Actions::Katello::Repository::Sync en erreur
    # et une Actions::Katello::ContentView::Publish en pause (toutes deux
    # critiques), plus une Actions::RemoteExecution::RunHostJob en erreur
    # (non critique) : au moins un libelle critique present -> CRIT.
    client = FixtureClient(FIXTURES_DIR)
    tasks = collect_recent_task_failures(client)
    assert tasks.total == 3
    assert tasks.omitted == 0
    labels = {t.label for t in tasks.tasks}
    assert "Actions::Katello::Repository::Sync" in labels
    assert "Actions::Katello::ContentView::Publish" in labels
    assert compute_tasks_status(tasks) == "CRIT"


# --------------------------------------------------------------------------
# Scenarios qu'une seule fixture committee ne peut pas representer (une
# fixture avec un libelle critique donne toujours CRIT) : fabriquees dans
# tmp_path, jamais commises.
# --------------------------------------------------------------------------


def test_tasks_warn_without_any_critical_label(tmp_path: Path) -> None:
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
        response={
            "subtotal": 1,
            "results": [
                {
                    "label": "Actions::RemoteExecution::RunHostJob",
                    "state": "stopped",
                    "result": "error",
                    "started_at": "2026-11-18 03:00:00 UTC",
                }
            ],
        },
    )
    tasks = collect_recent_task_failures(FixtureClient(tmp_path))
    assert compute_tasks_status(tasks) == "WARN"


def test_ping_with_one_service_down_is_crit(tmp_path: Path) -> None:
    _write_fixture(
        tmp_path,
        "ping.json",
        path="/katello/api/ping",
        params={},
        response={
            "status": "error",
            "services": {
                "candlepin": {"status": "ok"},
                "pulp3": {"status": "down"},
            },
        },
    )
    ping = collect_ping(FixtureClient(tmp_path))
    assert compute_ping_status(ping) == "CRIT"


def test_pulp_disk_at_warn_threshold(tmp_path: Path) -> None:
    # 19% libre, seuil WARN par defaut = 20%.
    _write_fixture(
        tmp_path,
        "pulp.json",
        path="/pulp/api/v3/status/",
        params={},
        response={"storage": {"total": 100, "used": 81, "free": 19}},
    )
    disk = collect_pulp_disk(FixtureClient(tmp_path))
    assert compute_pulp_disk_status(disk, _config()) == "WARN"


def test_pulp_disk_at_crit_threshold(tmp_path: Path) -> None:
    # 9% libre, seuil CRIT par defaut = 10%.
    _write_fixture(
        tmp_path,
        "pulp.json",
        path="/pulp/api/v3/status/",
        params={},
        response={"storage": {"total": 100, "used": 91, "free": 9}},
    )
    disk = collect_pulp_disk(FixtureClient(tmp_path))
    assert compute_pulp_disk_status(disk, _config()) == "CRIT"
