"""Garanties de securite verifiees sur le code source, pas seulement documentees.

Ces tests analysent le texte des fichiers de src/katello_inspector : aucune
methode HTTP autre que GET, aucun appel shell/eval/exec, et urllib.request
reserve a api.py.
"""
from __future__ import annotations

from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "katello_inspector"

FORBIDDEN_HTTP_METHODS = ("POST", "PUT", "DELETE", "PATCH")
FORBIDDEN_CALLS = ("subprocess", "os.system(", "eval(", "exec(")


def _python_files() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def test_no_http_method_other_than_get() -> None:
    for path in _python_files():
        text = path.read_text(encoding="utf-8")
        for method in FORBIDDEN_HTTP_METHODS:
            assert f'"{method}"' not in text and f"'{method}'" not in text, (
                f"{path} mentionne la methode HTTP {method}"
            )


def test_no_shell_or_dynamic_execution() -> None:
    for path in _python_files():
        text = path.read_text(encoding="utf-8")
        for forbidden in FORBIDDEN_CALLS:
            assert forbidden not in text, f"{path} contient un appel interdit : {forbidden}"


def test_urllib_request_restricted_to_api_module() -> None:
    for path in _python_files():
        if path.name == "api.py":
            continue
        text = path.read_text(encoding="utf-8")
        assert "urllib.request" not in text, f"{path} utilise urllib.request, reserve a api.py"
