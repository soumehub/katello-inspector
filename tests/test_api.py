from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from katello_inspector.api import ApiClient, FixtureClient, _SameHostRedirectHandler
from katello_inspector.exceptions import ApiError, UnsupportedSearchError

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _http_error(status: int, body: bytes) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        url="https://katello.example.com/x", code=status, msg="erreur", hdrs=None, fp=io.BytesIO(body)
    )


class _FakeResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


class _ScriptedOpener:
    """Remplace ApiClient._opener : rejoue une sequence programmee d'actions.

    Chaque entree est soit une exception a lever, soit (status, corps) pour un
    succes ou une erreur HTTP. Une fois la liste epuisee, la derniere entree
    est reutilisee indefiniment (simule un serveur qui se comporte toujours
    de la meme facon).
    """

    def __init__(self, script: list[Any]) -> None:
        self._script = script
        self.calls: list[str] = []

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> _FakeResponse:
        self.calls.append(req.full_url)
        index = min(len(self.calls) - 1, len(self._script) - 1)
        action = self._script[index]
        if isinstance(action, BaseException):
            raise action
        status, body = action
        if status >= 400:
            raise _http_error(status, body)
        return _FakeResponse(status, body)


def _client(**kwargs) -> ApiClient:
    return ApiClient("https://katello.example.com", "inspector-ro", "s3cr3t", **kwargs)


def test_get_success_parses_json() -> None:
    client = _client()
    client._opener = _ScriptedOpener([(200, b'{"a": 1}')])
    response = client.get("/api/status")
    assert response.status == 200
    assert response.data == {"a": 1}


def test_retry_once_on_network_error_then_success() -> None:
    client = _client()
    opener = _ScriptedOpener([urllib.error.URLError("panne reseau"), (200, b"{}")])
    client._opener = opener
    response = client.get("/api/status")
    assert response.status == 200
    assert len(opener.calls) == 2


def test_network_error_twice_raises_api_error() -> None:
    client = _client()
    opener = _ScriptedOpener([urllib.error.URLError("panne reseau")])
    client._opener = opener
    with pytest.raises(ApiError):
        client.get("/api/status")
    assert len(opener.calls) == 2


def test_retry_once_on_generic_5xx() -> None:
    client = _client()
    opener = _ScriptedOpener([(503, b"{}"), (200, b"{}")])
    client._opener = opener
    response = client.get("/api/hosts")
    assert response.status == 200
    assert len(opener.calls) == 2


def test_no_retry_on_4xx() -> None:
    client = _client()
    opener = _ScriptedOpener([(404, b"{}")])
    client._opener = opener
    with pytest.raises(ApiError):
        client.get("/api/hosts/999")
    assert len(opener.calls) == 1


def test_unsupported_search_500_not_retried() -> None:
    client = _client()
    body = json.dumps({"error": {"message": "Field 'bogus' not recognized for searching!"}}).encode()
    opener = _ScriptedOpener([(500, body)])
    client._opener = opener
    with pytest.raises(UnsupportedSearchError):
        client.get("/api/hosts", {"search": "bogus = 1"})
    assert len(opener.calls) == 1


def test_unsupported_search_400_on_tasks_not_retried() -> None:
    client = _client()
    body = json.dumps({"error": "not recognized for searching"}).encode()
    opener = _ScriptedOpener([(400, body)])
    client._opener = opener
    with pytest.raises(UnsupportedSearchError):
        client.get("/foreman_tasks/api/tasks", {"search": "bogus = 1"})
    assert len(opener.calls) == 1


def test_token_never_appears_in_exception_message() -> None:
    client = _client()
    opener = _ScriptedOpener([urllib.error.URLError("panne reseau")])
    client._opener = opener
    with pytest.raises(ApiError) as excinfo:
        client.get("/api/status")
    assert "s3cr3t" not in str(excinfo.value)


def test_pagination_assembles_results_across_pages() -> None:
    client = _client()
    page1 = (200, json.dumps({"results": [1, 2], "subtotal": 3, "total": 3}).encode())
    page2 = (200, json.dumps({"results": [3], "subtotal": 3, "total": 3}).encode())
    client._opener = _ScriptedOpener([page1, page2])
    pages = list(client.iter_results("/api/hosts", page_size=2))
    assert pages == [[1, 2], [3]]


def test_pagination_stops_on_empty_page() -> None:
    client = _client()
    page1 = (200, json.dumps({"results": [], "subtotal": 0, "total": 0}).encode())
    client._opener = _ScriptedOpener([page1])
    pages = list(client.iter_results("/api/hosts"))
    assert pages == [[]]


def test_pagination_guards_against_infinite_loop() -> None:
    client = _client(max_pages=5)
    page = (200, json.dumps({"results": [1]}).encode())  # jamais de subtotal/total
    opener = _ScriptedOpener([page])
    client._opener = opener
    with pytest.raises(ApiError):
        list(client.iter_results("/api/hosts"))
    assert len(opener.calls) == 5


def test_count_uses_subtotal_without_downloading_results() -> None:
    client = _client()
    client._opener = _ScriptedOpener([(200, json.dumps({"results": [], "subtotal": 42, "total": 42}).encode())])
    assert client.count("/api/hosts") == 42


def test_redirect_to_same_host_is_allowed() -> None:
    handler = _SameHostRedirectHandler()
    req = urllib.request.Request("https://katello.example.com/api/status")
    new_req = handler.redirect_request(req, None, 302, "Found", None, "https://katello.example.com/api/status/")
    assert new_req is not None


def test_redirect_to_another_host_is_refused() -> None:
    handler = _SameHostRedirectHandler()
    req = urllib.request.Request("https://katello.example.com/api/status")
    with pytest.raises(ApiError):
        handler.redirect_request(req, None, 302, "Found", None, "https://attaquant.example.com/api/status")


def test_fixture_client_replays_recorded_response() -> None:
    client = FixtureClient(FIXTURES_DIR / "version_ok")
    response = client.get("/api/status")
    assert response.data["version"] == "3.19.1"


def test_fixture_client_replays_search_rejected_500() -> None:
    client = FixtureClient(FIXTURES_DIR / "search_rejected")
    with pytest.raises(UnsupportedSearchError):
        client.get("/api/hosts", {"search": "bogus = 1"})
