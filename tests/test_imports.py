"""Chaque module du paquet doit s'importer seul, sans effet de bord qui casse."""
from __future__ import annotations

import importlib
import pkgutil

import katello_inspector


def _module_names() -> list[str]:
    prefix = katello_inspector.__name__ + "."
    names = [katello_inspector.__name__]
    for info in pkgutil.walk_packages(katello_inspector.__path__, prefix):
        names.append(info.name)
    return names


def test_every_module_in_the_package_imports_cleanly() -> None:
    names = _module_names()
    assert len(names) >= 5  # __init__, api, cli, config, exceptions
    for name in names:
        importlib.import_module(name)
