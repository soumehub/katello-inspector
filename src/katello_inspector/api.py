"""Client HTTP : seule source de requetes vers Foreman/Katello, GET uniquement.

Aucune autre methode HTTP ne doit apparaitre dans ce fichier ni ailleurs dans le
paquet (verifie par un test statique). Le jeton n'est jamais journalise ni inclus
dans un message d'exception.
"""
from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

from . import __version__
from .exceptions import ApiError, ConfigError, UnsupportedSearchError

DEFAULT_PAGE_SIZE = 200
DEFAULT_MAX_PAGES = 10_000

# Message observe sur /api/hosts (HTTP 500) et /foreman_tasks/api/tasks (HTTP 400)
# pour un champ de recherche inconnu. Ne jamais retenter cette reponse.
_UNSUPPORTED_SEARCH_MARKER = "not recognized for searching"


class Response:
    """Reponse HTTP deja decodee en JSON."""

    __slots__ = ("status", "data", "path")

    def __init__(self, status: int, data: Any, path: str) -> None:
        self.status = status
        self.data = data
        self.path = path


def _is_unsupported_search(status: int, text: str) -> bool:
    return status in (400, 500) and _UNSUPPORTED_SEARCH_MARKER in text.lower()


def _coerce_total(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ApiError(f"pagination : total/subtotal invalide sur {path}")
    return value


def _parse_json_object(text: str, path: str) -> dict[str, Any] | None:
    """Decode un corps JSON en objet, jamais une exception brute ni le corps lui-meme.

    Tous les endpoints utilises renvoient soit rien, soit un objet a la
    racine : une liste, une chaine ou un nombre a la racine est une reponse
    inattendue, traitee comme une erreur plutot que transmise telle quelle.
    """
    if not text:
        return None
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ApiError(f"reponse JSON invalide sur {path}") from exc
    if data is not None and not isinstance(data, dict):
        raise ApiError(f"reponse JSON inattendue sur {path} (racine de type {type(data).__name__})")
    return data


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Ne suit jamais de redirection, quelle que soit sa cible.

    Le jeton est transmis dans l'en-tete Authorization, qu'urllib reconduit
    par defaut sur une redirection meme vers une autre origine ou vers
    http://. La seule politique sure est de n'en suivre aucune.
    """

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        target = urllib.parse.urlsplit(newurl).netloc
        raise ApiError(f"redirection HTTP {code} refusee (vers {target!r})")


def _validate_base_url(base_url: str) -> str:
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme != "https":
        raise ConfigError(
            "adresse du serveur refusee : seul https:// est accepte "
            "(le jeton circulerait en clair sur http://)"
        )
    if not parsed.hostname:
        raise ConfigError("adresse du serveur invalide : hote manquant")
    return base_url.rstrip("/")


def _build_ssl_context(*, ca_file: str | None, insecure: bool) -> ssl.SSLContext:
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if ca_file:
        return ssl.create_default_context(cafile=ca_file)
    return ssl.create_default_context()


class BaseApiClient:
    """Logique commune : retenue d'erreur, pagination, comptage.

    Les sous-classes fournissent uniquement `_send`, qui renvoie un statut HTTP
    et un corps brut sans jamais lever d'exception pour un code d'erreur HTTP
    (seules les pannes reseau levent une `OSError`, seul cas retente).
    """

    def __init__(self, *, page_size: int = DEFAULT_PAGE_SIZE, max_pages: int = DEFAULT_MAX_PAGES) -> None:
        # Filet de securite : config.py valide deja page_size avant d'arriver
        # ici (ConfigError, code retour propre) ; cette verification protege
        # un appel direct du constructeur (tests, usage futur).
        if isinstance(page_size, bool) or page_size < 1:
            raise ValueError(f"page_size doit etre un entier positif (recu {page_size!r})")
        if isinstance(max_pages, bool) or max_pages < 1:
            raise ValueError(f"max_pages doit etre un entier positif (recu {max_pages!r})")
        self._page_size = page_size
        self._max_pages = max_pages

    def _send(self, path: str, params: Mapping[str, Any]) -> tuple[int, bytes]:
        raise NotImplementedError

    def get(self, path: str, params: Mapping[str, Any] | None = None) -> Response:
        query = dict(params or {})
        last_exc: BaseException | None = None
        for attempt in (1, 2):
            try:
                status, body = self._send(path, query)
            except OSError as exc:
                last_exc = exc
                if attempt == 1:
                    continue
                raise ApiError(f"erreur reseau sur {path} : {exc}") from exc
            else:
                text = body.decode("utf-8", "replace") if body else ""
                if status < 400:
                    data = _parse_json_object(text, path)
                    return Response(status, data, path)
                if _is_unsupported_search(status, text):
                    raise UnsupportedSearchError(f"recherche non supportee sur {path}")
                if status >= 500 and attempt == 1:
                    last_exc = ApiError(f"erreur HTTP {status} sur {path}")
                    continue
                raise ApiError(f"erreur HTTP {status} sur {path}")
        raise ApiError(f"echec apres nouvelle tentative sur {path}") from last_exc

    def iter_results(
        self,
        path: str,
        params: Mapping[str, Any] | None = None,
        *,
        page_size: int | None = None,
    ) -> Iterator[list[Any]]:
        page_size = page_size or self._page_size
        base_params = dict(params or {})
        page = 1
        fetched = 0
        expected: int | None = None
        while True:
            query = dict(base_params)
            query["page"] = page
            query["per_page"] = page_size
            response = self.get(path, query)
            body = response.data or {}
            results = body.get("results", [])
            if not isinstance(results, list):
                raise ApiError(f"pagination : 'results' n'est pas une liste sur {path}")
            yield results
            fetched += len(results)
            subtotal = body.get("subtotal", body.get("total"))
            if expected is None and subtotal is not None:
                expected = _coerce_total(subtotal, path)
            if not results:
                break
            if expected is not None and fetched >= expected:
                break
            page += 1
            if page > self._max_pages:
                raise ApiError(
                    f"pagination : plus de {self._max_pages} pages sur {path} sans atteindre "
                    "le total attendu, arret pour eviter une boucle infinie"
                )

    def count(self, path: str, params: Mapping[str, Any] | None = None) -> int:
        query = dict(params or {})
        query["page"] = 1
        query["per_page"] = 1
        response = self.get(path, query)
        body = response.data or {}
        total = body.get("subtotal", body.get("total"))
        if total is None:
            raise ApiError(f"compteur indisponible sur {path}")
        return _coerce_total(total, path)


class ApiClient(BaseApiClient):
    """Client reel : urllib uniquement, GET uniquement."""

    def __init__(
        self,
        base_url: str,
        user: str,
        token: str,
        *,
        timeout: float = 30.0,
        ca_file: str | None = None,
        insecure: bool = False,
        page_size: int = DEFAULT_PAGE_SIZE,
        max_pages: int = DEFAULT_MAX_PAGES,
    ) -> None:
        super().__init__(page_size=page_size, max_pages=max_pages)
        self._base_url = _validate_base_url(base_url)
        self._timeout = timeout
        self._auth_header = "Basic " + base64.b64encode(f"{user}:{token}".encode()).decode("ascii")
        self._user_agent = f"katello-inspector/{__version__}"
        self.tls_verified = not insecure
        ctx = _build_ssl_context(ca_file=ca_file, insecure=insecure)
        self._opener = urllib.request.build_opener(_NoRedirectHandler(), urllib.request.HTTPSHandler(context=ctx))

    def _send(self, path: str, params: Mapping[str, Any]) -> tuple[int, bytes]:
        qs = urllib.parse.urlencode(params, doseq=True) if params else ""
        url = self._base_url + path + (("?" + qs) if qs else "")
        req = urllib.request.Request(url, method="GET")
        req.add_header("Accept", "application/json")
        req.add_header("Authorization", self._auth_header)
        req.add_header("User-Agent", self._user_agent)
        try:
            with self._opener.open(req, timeout=self._timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, (exc.read() or b"")
        except ValueError as exc:
            raise ApiError(f"requete invalide sur {path} : {exc}") from exc


def _fixture_key(path: str, params: Mapping[str, Any]) -> tuple[str, tuple[tuple[str, str], ...]]:
    normalized = tuple(sorted((str(k), str(v)) for k, v in params.items()))
    return path, normalized


class FixtureClient(BaseApiClient):
    """Rejoue des reponses enregistrees (`--fixtures REPERTOIRE`), pour les tests."""

    def __init__(
        self,
        directory: str | Path,
        *,
        page_size: int = DEFAULT_PAGE_SIZE,
        max_pages: int = DEFAULT_MAX_PAGES,
    ) -> None:
        super().__init__(page_size=page_size, max_pages=max_pages)
        self._fixtures: dict[tuple[str, tuple[tuple[str, str], ...]], tuple[int, bytes]] = {}
        for entry in sorted(Path(directory).glob("*.json")):
            with entry.open("r", encoding="utf-8") as fh:
                doc = json.load(fh)
            request = doc.get("request", {})
            path = request.get("path", "")
            params = request.get("params", {}) or {}
            status = doc.get("status", 200)
            response = doc.get("response")
            body = json.dumps(response).encode("utf-8") if response is not None else b""
            self._fixtures[_fixture_key(path, params)] = (status, body)

    def _send(self, path: str, params: Mapping[str, Any]) -> tuple[int, bytes]:
        try:
            return self._fixtures[_fixture_key(path, params)]
        except KeyError:
            raise ApiError(f"aucune fixture enregistree pour {path} {dict(params)}") from None
