from __future__ import annotations

from types import SimpleNamespace

from katello_inspector.config import build_config
from katello_inspector.render_json import build_envelope


def test_build_envelope_without_thresholds_omits_the_key() -> None:
    config = build_config(SimpleNamespace())
    envelope = build_envelope(command="version", config=config, status="OK", data={}, unknown=[])
    assert "thresholds" not in envelope


def test_build_envelope_with_thresholds_includes_them() -> None:
    config = build_config(SimpleNamespace())
    envelope = build_envelope(
        command="summary",
        config=config,
        status="OK",
        data={},
        unknown=[],
        thresholds={"checkin_days": 7},
    )
    assert envelope["thresholds"] == {"checkin_days": 7}
