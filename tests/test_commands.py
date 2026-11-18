"""Bout en bout collect+analyze+render pour summary et list, via les fixtures.

Verifie en particulier que l'enveloppe complete se serialise en JSON sans
lever d'exception : `TaskSummary.started_at` est un datetime depuis le
correctif ISO-Z, et doit passer par `format_iso_z` avant d'atterrir dans le
dictionnaire envoye a `json.dumps` (sinon TypeError a l'execution, jamais vu
par les tests qui n'exercent que les fonctions pures).

La fixture des taches est fabriquee ici (pas de dependance sur une fixture
plateforme particuliere committee) : seule la presence d'au moins une tache
critique, pour exercer le chemin "taches non vides", nous interesse.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from katello_inspector.api import FixtureClient
from katello_inspector.commands import list as list_command
from katello_inspector.commands import summary as summary_command
from katello_inspector.config import build_config

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

_TASKS_PARAMS = {
    "search": '(state = paused or result = error) and started_at > "24 hours ago"',
    "per_page": 50,
    "page": 1,
    "order": "started_at DESC",
}


@pytest.fixture(autouse=True)
def _page_size_matches_fixtures(monkeypatch: pytest.MonkeyPatch) -> None:
    # 009_hosts_list.json a ete capturee avec per_page=100 (une seule page,
    # 19 hotes) : il faut la meme valeur pour que FixtureClient retrouve la
    # requete.
    monkeypatch.setenv("KATELLO_INSPECTOR_PAGE_SIZE", "100")


@pytest.fixture()
def fixtures_with_tasks(tmp_path: Path) -> Path:
    for item in FIXTURES_DIR.glob("*.json"):
        shutil.copy(item, tmp_path / item.name)
    doc = {
        "request": {"method": "GET", "path": "/foreman_tasks/api/tasks", "params": _TASKS_PARAMS},
        "status": 200,
        "kind": "ok",
        "elapsed_ms": 1,
        "response": {
            "subtotal": 2,
            "results": [
                {
                    "label": "Actions::Katello::Repository::Sync",
                    "state": "stopped",
                    "result": "error",
                    "started_at": "2026-11-18 01:00:00 UTC",
                },
                {
                    "label": "Actions::Katello::ContentView::Publish",
                    "state": "paused",
                    "result": None,
                    "started_at": "2026-11-18 02:00:00 UTC",
                },
            ],
        },
    }
    (tmp_path / "tasks_non_vides.json").write_text(json.dumps(doc), encoding="utf-8")
    return tmp_path


def _config():
    return build_config(SimpleNamespace(org="MonOrganisation"))


def test_summary_json_envelope_serializes_with_nonempty_tasks(
    fixtures_with_tasks: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = _config()
    client = FixtureClient(fixtures_with_tasks, page_size=config.page_size)
    args = SimpleNamespace(format="json", by_lce=False)

    code = summary_command.run(args, config, client)

    assert code == 0
    envelope = json.loads(capsys.readouterr().out)  # ne doit jamais lever
    assert envelope["status"] == "CRIT"

    tasks = envelope["data"]["platform"]["tasks"]
    assert tasks["status"] == "CRIT"
    assert tasks["failing_or_paused_24h"] == 2
    labels = {t["label"] for t in tasks["tasks"]}
    assert "Actions::Katello::Repository::Sync" in labels
    assert "Actions::Katello::ContentView::Publish" in labels
    for t in tasks["tasks"]:
        assert t["started_at"] is not None
        assert t["started_at"].endswith("Z")
        assert "+00:00" not in t["started_at"]


def test_summary_json_envelope_by_lce_also_serializes(
    fixtures_with_tasks: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = _config()
    client = FixtureClient(fixtures_with_tasks, page_size=config.page_size)
    args = SimpleNamespace(format="json", by_lce=True)

    code = summary_command.run(args, config, client)

    assert code == 0
    envelope = json.loads(capsys.readouterr().out)
    assert isinstance(envelope["data"]["by_lce"], list)
    assert len(envelope["data"]["by_lce"]) >= 1


def test_list_json_envelope_serializes(fixtures_with_tasks: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = _config()
    client = FixtureClient(fixtures_with_tasks, page_size=config.page_size)
    args = SimpleNamespace(format="json")

    code = list_command.run(args, config, client)

    assert code == 0
    envelope = json.loads(capsys.readouterr().out)  # ne doit jamais lever
    assert isinstance(envelope["data"], list)
    assert len(envelope["data"]) >= 1
    for host in envelope["data"]:
        checkin = host["freshness"]["last_checkin"]
        if checkin is not None:
            assert checkin.endswith("Z")
            assert "+00:00" not in checkin
