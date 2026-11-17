from __future__ import annotations

import http.server
import io
import json
import socket
import ssl
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from katello_inspector.api import ApiClient, FixtureClient, _NoRedirectHandler
from katello_inspector.exceptions import ApiError, ConfigError, UnsupportedSearchError

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
        self.requests: list[urllib.request.Request] = []

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> _FakeResponse:
        self.calls.append(req.full_url)
        self.requests.append(req)
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


def test_retry_on_raw_timeout_error() -> None:
    client = _client()
    opener = _ScriptedOpener([TimeoutError("delai depasse"), (200, b"{}")])
    client._opener = opener
    response = client.get("/api/status")
    assert response.status == 200
    assert len(opener.calls) == 2


def test_retry_on_url_error_wrapping_a_timeout() -> None:
    client = _client()
    opener = _ScriptedOpener([urllib.error.URLError(TimeoutError("delai depasse")), (200, b"{}")])
    client._opener = opener
    response = client.get("/api/status")
    assert response.status == 200
    assert len(opener.calls) == 2


def test_retry_on_connection_reset() -> None:
    client = _client()
    opener = _ScriptedOpener([ConnectionResetError("connexion reinitialisee"), (200, b"{}")])
    client._opener = opener
    response = client.get("/api/status")
    assert response.status == 200
    assert len(opener.calls) == 2


def test_timeout_twice_raises_api_error() -> None:
    client = _client()
    opener = _ScriptedOpener([TimeoutError("delai depasse")])
    client._opener = opener
    with pytest.raises(ApiError):
        client.get("/api/status")
    assert len(opener.calls) == 2


def test_no_retry_on_connection_refused() -> None:
    client = _client()
    opener = _ScriptedOpener([urllib.error.URLError(ConnectionRefusedError("connexion refusee"))])
    client._opener = opener
    with pytest.raises(ApiError):
        client.get("/api/status")
    assert len(opener.calls) == 1


def test_no_retry_on_dns_failure() -> None:
    client = _client()
    opener = _ScriptedOpener([urllib.error.URLError(socket.gaierror("hote introuvable"))])
    client._opener = opener
    with pytest.raises(ApiError):
        client.get("/api/status")
    assert len(opener.calls) == 1


def test_no_retry_on_tls_certificate_error() -> None:
    client = _client()
    opener = _ScriptedOpener([urllib.error.URLError(ssl.SSLCertVerificationError("certificat invalide"))])
    client._opener = opener
    with pytest.raises(ApiError):
        client.get("/api/status")
    assert len(opener.calls) == 1


def test_retry_on_502() -> None:
    client = _client()
    opener = _ScriptedOpener([(502, b"{}"), (200, b"{}")])
    client._opener = opener
    response = client.get("/api/hosts")
    assert response.status == 200
    assert len(opener.calls) == 2


def test_retry_on_503() -> None:
    client = _client()
    opener = _ScriptedOpener([(503, b"{}"), (200, b"{}")])
    client._opener = opener
    response = client.get("/api/hosts")
    assert response.status == 200
    assert len(opener.calls) == 2


def test_retry_on_504() -> None:
    client = _client()
    opener = _ScriptedOpener([(504, b"{}"), (200, b"{}")])
    client._opener = opener
    response = client.get("/api/hosts")
    assert response.status == 200
    assert len(opener.calls) == 2


def test_no_retry_on_500() -> None:
    client = _client()
    opener = _ScriptedOpener([(500, b"{}")])
    client._opener = opener
    with pytest.raises(ApiError):
        client.get("/api/hosts")
    assert len(opener.calls) == 1


def test_no_retry_on_501() -> None:
    client = _client()
    opener = _ScriptedOpener([(501, b"{}")])
    client._opener = opener
    with pytest.raises(ApiError):
        client.get("/api/hosts")
    assert len(opener.calls) == 1


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


def test_page_size_must_be_a_positive_integer() -> None:
    with pytest.raises(ValueError):
        _client(page_size=0)


def test_max_pages_must_be_a_positive_integer() -> None:
    with pytest.raises(ValueError):
        _client(max_pages=0)


def test_page_size_rejects_bool() -> None:
    with pytest.raises(ValueError):
        _client(page_size=True)


def test_pagination_rejects_results_that_is_not_a_list() -> None:
    client = _client()
    client._opener = _ScriptedOpener([(200, json.dumps({"results": "oops"}).encode())])
    with pytest.raises(ApiError):
        list(client.iter_results("/api/hosts"))


def test_pagination_rejects_non_integer_total() -> None:
    client = _client()
    body = json.dumps({"results": [1], "subtotal": "beaucoup"}).encode()
    client._opener = _ScriptedOpener([(200, body)])
    with pytest.raises(ApiError):
        list(client.iter_results("/api/hosts"))


def test_count_rejects_non_integer_total() -> None:
    client = _client()
    client._opener = _ScriptedOpener([(200, json.dumps({"subtotal": "beaucoup"}).encode())])
    with pytest.raises(ApiError):
        client.count("/api/hosts")


def test_invalid_json_body_becomes_api_error() -> None:
    client = _client()
    client._opener = _ScriptedOpener([(200, b"ceci n'est pas du json")])
    with pytest.raises(ApiError):
        client.get("/api/status")


def test_unexpected_json_root_list_becomes_api_error() -> None:
    client = _client()
    client._opener = _ScriptedOpener([(200, b"[1, 2, 3]")])
    with pytest.raises(ApiError):
        client.get("/api/status")


def test_unexpected_json_root_scalar_becomes_api_error() -> None:
    client = _client()
    client._opener = _ScriptedOpener([(200, b"42")])
    with pytest.raises(ApiError):
        client.get("/api/status")


def test_null_json_root_is_treated_as_empty() -> None:
    client = _client()
    client._opener = _ScriptedOpener([(200, b"null")])
    response = client.get("/api/status")
    assert response.data is None


def test_empty_body_is_treated_as_empty() -> None:
    client = _client()
    client._opener = _ScriptedOpener([(200, b"")])
    response = client.get("/api/status")
    assert response.data is None


def test_redirect_handler_refuses_same_host_redirect() -> None:
    handler = _NoRedirectHandler()
    req = urllib.request.Request("https://katello.example.com/api/status")
    with pytest.raises(ApiError):
        handler.redirect_request(req, None, 302, "Found", None, "https://katello.example.com/api/status/")


def test_redirect_handler_refuses_cross_host_redirect() -> None:
    handler = _NoRedirectHandler()
    req = urllib.request.Request("https://katello.example.com/api/status")
    with pytest.raises(ApiError):
        handler.redirect_request(req, None, 302, "Found", None, "https://attaquant.example.com/api/status")


def test_redirect_handler_refuses_downgrade_to_http() -> None:
    handler = _NoRedirectHandler()
    req = urllib.request.Request("https://katello.example.com/api/status")
    with pytest.raises(ApiError):
        handler.redirect_request(req, None, 302, "Found", None, "http://katello.example.com/api/status")


class _RecordingHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (nom impose par http.server)
        self.server.seen_requests.append(dict(self.headers))  # type: ignore[attr-defined]
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args: object) -> None:
        pass


class _RedirectingHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.server.seen_requests.append(dict(self.headers))  # type: ignore[attr-defined]
        self.send_response(302)
        self.send_header("Location", self.server.redirect_target)  # type: ignore[attr-defined]
        self.end_headers()

    def log_message(self, *args: object) -> None:
        pass


def _start_local_server(handler_cls: type[http.server.BaseHTTPRequestHandler]) -> http.server.HTTPServer:
    server = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    server.seen_requests = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_redirect_is_never_followed_authorization_never_reaches_another_origin() -> None:
    # Serveurs http.server reels (pas de mock) : un serveur B qui ne doit
    # jamais recevoir la moindre requete, et un serveur A qui redirige vers B
    # en http://. Si la redirection etait suivie, l'en-tete Authorization
    # partirait vers B.
    target = _start_local_server(_RecordingHandler)
    try:
        redirect_url = f"http://127.0.0.1:{target.server_port}/elsewhere"
        redirector = _start_local_server(_RedirectingHandler)
        redirector.redirect_target = redirect_url  # type: ignore[attr-defined]
        try:
            opener = urllib.request.build_opener(_NoRedirectHandler())
            req = urllib.request.Request(f"http://127.0.0.1:{redirector.server_port}/start")
            req.add_header("Authorization", "Basic c2VjcmV0")
            with pytest.raises(ApiError):
                opener.open(req, timeout=2)
            assert target.seen_requests == []
        finally:
            redirector.shutdown()
    finally:
        target.shutdown()


def test_base_url_must_be_https() -> None:
    with pytest.raises(ConfigError):
        ApiClient("http://katello.example.com", "inspector-ro", "s3cr3t")


def test_base_url_must_have_a_hostname() -> None:
    with pytest.raises(ConfigError):
        ApiClient("https://", "inspector-ro", "s3cr3t")


def test_base_url_https_is_accepted() -> None:
    client = _client()
    assert client is not None


def test_get_without_anonymous_sends_authorization_header() -> None:
    client = _client()
    opener = _ScriptedOpener([(200, b"{}")])
    client._opener = opener
    client.get("/api/status")
    assert opener.requests[0].get_header("Authorization") is not None


def test_get_anonymous_omits_authorization_header() -> None:
    client = _client()
    opener = _ScriptedOpener([(200, b"{}")])
    client._opener = opener
    client.get("/pulp/api/v3/status/", anonymous=True)
    assert opener.requests[0].get_header("Authorization") is None


def test_malformed_request_value_error_becomes_api_error() -> None:
    client = _client()

    class _BoomOpener:
        def open(self, req: urllib.request.Request, timeout: float | None = None) -> _FakeResponse:
            raise ValueError("en-tete invalide")

    client._opener = _BoomOpener()
    with pytest.raises(ApiError):
        client.get("/api/status")


def test_fixture_client_replays_recorded_response() -> None:
    client = FixtureClient(FIXTURES_DIR / "version_ok")
    response = client.get("/api/status")
    assert response.data["version"] == "3.19.1"


def test_fixture_client_replays_search_rejected_500() -> None:
    client = FixtureClient(FIXTURES_DIR / "search_rejected")
    with pytest.raises(UnsupportedSearchError):
        client.get("/api/hosts", {"search": "bogus = 1"})


def test_fixture_client_rejects_non_object_root(tmp_path: Path) -> None:
    (tmp_path / "bad.json").write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ApiError):
        FixtureClient(tmp_path)


def test_fixture_client_rejects_non_integer_status(tmp_path: Path) -> None:
    doc = {"request": {"path": "/api/status", "params": {}}, "status": "200", "response": {}}
    (tmp_path / "bad.json").write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ApiError):
        FixtureClient(tmp_path)
