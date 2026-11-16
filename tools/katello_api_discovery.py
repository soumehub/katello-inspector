#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""katello_api_discovery.py - outil TEMPORAIRE de decouverte de l'API Katello/Foreman.

Valide techniquement les points V1 a V17 du document de cadrage de katello-inspector
sur une instance reelle (Katello 4.21 / Foreman 3.19 visees).

Garanties :
  * Python 3.9+, bibliotheque standard uniquement.
  * Requetes HTTP GET uniquement (une seule fonction emet des requetes, voir Client.get).
  * Aucune modification de la plateforme.
  * Jeton lu dans un fichier ou une variable d'environnement, jamais en argument.
  * Validation TLS active par defaut (--ca-file pour une CA interne).
  * Les redirections ne sont jamais suivies (le jeton ne peut pas fuiter vers un autre hote).

Ce que l'outil NE fait PAS : il ne conclut jamais sur la signification metier d'un champ.
Il constate l'existence, le type, la presence et des coherences mesurables ; la semantique
reste a valider manuellement (voir la colonne "Semantique" du mapping dans le rapport).

Exemple :
  export KATELLO_DISCOVERY_USER=inspector-ro
  export KATELLO_DISCOVERY_TOKEN_FILE=/etc/katello-inspector/token   # chmod 600
  ./katello_api_discovery.py --url https://katello.example.com --org MonOrg --ca-file ca.pem
"""
from __future__ import annotations

import argparse
import base64
import collections
import datetime as dt
import json
import math
import os
import re
import ssl
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "0.2.1"

CONF = "CONFIRMÉ"
PART = "PARTIELLEMENT CONFIRMÉ"
NOAV = "NON DISPONIBLE"
NOTEST = "NON VÉRIFIABLE"

CAUSES = {
    "network": "serveur injoignable ou délai dépassé",
    "auth": "authentification refusée (401)",
    "forbidden": "droits insuffisants (403)",
    "missing": "endpoint non exposé (404)",
    "bad_request": "paramètre ou recherche refusé (400/422)",
    "server_error": "erreur serveur (5xx)",
    "redirect": "redirection refusée (3xx)",
    "non_json": "réponse non JSON",
    "other": "réponse HTTP inattendue",
}
CAUSE_ORDER = ["network", "auth", "forbidden", "missing", "bad_request", "server_error",
               "redirect", "non_json", "other"]

SECRET_KEY = re.compile(r"(pass(word|wd)?|secret|token|private|authorization|api[_-]?key|ssh)", re.I)
RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
RE_MAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
RE_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}")


# --------------------------------------------------------------------------- HTTP

class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Ne suit jamais une redirection : l'en-tete Authorization ne quitte pas le serveur."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def classify(status):
    if status is None:
        return "network"
    if 200 <= status < 300:
        return "ok"
    if status == 401:
        return "auth"
    if status == 403:
        return "forbidden"
    if status == 404:
        return "missing"
    if status in (400, 422):
        return "bad_request"
    if 300 <= status < 400:
        return "redirect"
    if status >= 500:
        return "server_error"
    return "other"


class Resp:
    def __init__(self, path, params, status, kind, data, elapsed, text="", location=None, nbytes=0):
        self.path = path
        self.params = params or {}
        self.status = status
        self.kind = kind
        self.data = data
        self.elapsed = elapsed
        self.text = text
        self.location = location
        self.nbytes = nbytes

    @property
    def ok(self):
        return self.kind == "ok" and self.data is not None

    def meta(self, key, default=None):
        return self.data.get(key, default) if isinstance(self.data, dict) else default

    def results(self):
        d = self.data
        if isinstance(d, dict) and isinstance(d.get("results"), list):
            return d["results"]
        if isinstance(d, list):
            return d
        return []

    def message(self):
        d = self.data
        if isinstance(d, dict):
            err = d.get("error")
            if isinstance(err, dict):
                return str(err.get("message") or err)[:200]
            if err:
                return str(err)[:200]
            if d.get("message"):
                return str(d["message"])[:200]
        return (self.text or "")[:200]


class Client:
    """Seul point d'emission de requetes : methode GET codee en dur."""

    def __init__(self, base, user, token, timeout, ctx, raw_dir, quiet=True):
        self.base = base.rstrip("/")
        self.auth = "Basic " + base64.b64encode(f"{user}:{token}".encode()).decode()
        self.timeout = timeout
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), NoRedirect())
        self.raw_dir = raw_dir
        self.n = 0
        self.calls = []          # (n, path, params, status, kind, ms)
        self.seen_paths = {}     # chemin API -> ensemble de chemins de champs
        self.page_meta = {}      # chemin API -> cles de pagination observees
        self.timing = collections.defaultdict(list)
        self.redactor = None
        self.keep = set()      # chaînes à ne pas masquer (versions à 4 composantes qui ressemblent à une IPv4)

    def get(self, path, params=None, tag=None, save=True, anonymous=False):
        qs = urllib.parse.urlencode(params, doseq=True) if params else ""
        url = self.base + path + ("?" + qs if qs else "")
        req = urllib.request.Request(url, method="GET")
        req.add_header("Accept", "application/json")
        if not anonymous:
            req.add_header("Authorization", self.auth)
        req.add_header("User-Agent", "katello-api-discovery/" + VERSION)
        t0 = time.monotonic()
        status, body, text_err, location = None, b"", "", None
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                status, body = r.status, r.read()
        except urllib.error.HTTPError as e:
            status, body = e.code, (e.read() or b"")
            location = e.headers.get("Location") if e.headers else None
        except (urllib.error.URLError, OSError, ssl.SSLError) as e:
            text_err = str(getattr(e, "reason", e))
        elapsed = time.monotonic() - t0
        kind = classify(status)
        data, text = None, text_err
        if body:
            text = body.decode("utf-8", "replace")
            try:
                data = json.loads(text)
            except ValueError:
                data = None
                if kind == "ok":
                    kind = "non_json"
        r = Resp(path, params, status, kind, data, elapsed, text[:300], location, len(body))
        self.n += 1
        self.calls.append((self.n, path, dict(params or {}), status, kind, round(elapsed * 1000)))
        self.timing[tag or path].append(elapsed)
        if tag != "apidoc" and r.ok:
            self._learn(path, data)
        if save and self.raw_dir:
            self._save(r, tag)
        return r

    def _learn(self, path, data):
        paths = self.seen_paths.setdefault(path, set())
        sample = data
        if isinstance(data, dict) and isinstance(data.get("results"), list):
            sample = data["results"][:20]
            self.page_meta.setdefault(path, set()).update(
                k for k in ("total", "subtotal", "page", "per_page") if k in data)
        for p, _v in flatten(sample):
            paths.add(p)

    def _save(self, r, tag):
        slug = re.sub(r"[^a-zA-Z0-9]+", "_", tag or r.path).strip("_")[:50]
        name = os.path.join(self.raw_dir, f"{self.n:03d}_{slug}.json")
        doc = {"request": {"method": "GET", "path": r.path, "params": r.params},
               "status": r.status, "kind": r.kind, "elapsed_ms": round(r.elapsed * 1000),
               "response": r.data if r.data is not None else r.text}
        with open(name, "w", encoding="utf-8") as fh:
            json.dump(self.sanitize(doc), fh, ensure_ascii=False, indent=1)

    def sanitize(self, obj):
        if isinstance(obj, dict):
            return {k: ("***" if SECRET_KEY.search(str(k)) and v not in (None, "") else self.sanitize(v))
                    for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.sanitize(v) for v in obj]
        if isinstance(obj, str) and self.redactor:
            return self.redactor(obj)
        return obj


# --------------------------------------------------------------------------- champs

def flatten(obj, prefix=""):
    """Liste de (chemin, valeur) ; les listes sont notees 'chemin[]'."""
    out = []
    if isinstance(obj, dict):
        if not obj and prefix:
            out.append((prefix, None))
        for k, v in obj.items():
            out.extend(flatten(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(obj, list):
        p = prefix + "[]"
        if not obj:
            out.append((p, None))
        for item in obj:
            out.extend(flatten(item, p))
    else:
        out.append((prefix, obj))
    return out


class Catalog:
    """Catalogue des champs vus sur un ensemble d'enregistrements."""

    def __init__(self):
        self.records = 0
        self.f = {}

    def add(self, rec):
        self.records += 1
        local = {}
        for p, v in flatten(rec):
            nn = v is not None
            if p not in local:
                local[p] = [nn, v if nn else None]
            elif nn and not local[p][0]:
                local[p] = [True, v]
        for p, (nn, v) in local.items():
            e = self.f.setdefault(p, {"present": 0, "nonnull": 0, "types": set(), "ex": None})
            e["present"] += 1
            if nn:
                e["nonnull"] += 1
                e["types"].add(type(v).__name__)
                if e["ex"] is None:
                    e["ex"] = v

    def add_all(self, recs):
        for r in recs:
            self.add(r)
        return self

    def find(self, rx, nonnull=False):
        r = re.compile(rx, re.I)
        out = []
        for p in sorted(self.f):
            if r.search(p) and (not nonnull or self.f[p]["nonnull"] > 0):
                out.append((p, self.f[p]))
        return out

    def has(self, rx):
        return bool(self.find(rx, nonnull=True))


def short(v, n=60):
    if isinstance(v, bool):
        return "true" if v else "false"
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
    s = s.replace("\n", " ")
    return s if len(s) <= n else s[: n - 1] + "…"


def md(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def is_date(v):
    return isinstance(v, str) and bool(RE_DATE.match(v))


# --------------------------------------------------------------------------- constats

class Finding:
    def __init__(self, ref, title):
        self.ref = ref
        self.title = title
        self.result = NOTEST
        self.cause = ""
        self.endpoints = []   # (path, params, status, kind, ms, methods)
        self.fields = []      # (endpoint, path, presence, exemple)
        self.checks = []      # (libelle, oui/non/n.d., detail)
        self.notes = []
        self.tables = []      # (titre, entetes, lignes)
        self.kinds = []

    def ep(self, r, methods=""):
        self.endpoints.append((r.path, r.params, r.status, r.kind, round(r.elapsed * 1000), methods))
        self.kinds.append(r.kind)

    def check(self, label, ok, detail=""):
        self.checks.append((label, "oui" if ok is True else "non" if ok is False else "n.d.", detail))

    def table(self, title, headers, rows):
        self.tables.append((title, headers, rows))

    def failure_cause(self):
        for k in CAUSE_ORDER:
            if k in self.kinds:
                return CAUSES[k]
        return ""


# --------------------------------------------------------------------------- decouverte

HOST_GROUPS = [
    ("check-in", r"checkin", True),
    ("content view", r"content_view", True),
    ("lifecycle environment", r"lifecycle_environment", True),
    ("errata (compteurs)", r"errata", True),
    ("paquets upgradables/applicables", r"upgradable|applicable_package|installable_package", True),
    ("content source", r"content_source", False),
    ("statut global", r"global_status", False),
    ("build", r"(^|\.)build($|_)", False),
]
STRICT_PROFILE = r"(package.*(profile|upload)|profile.*(upload|updat|time|date)|applicab.*(updat|time|date|calc|regen))"
GENERIC_TIME = r"(_at$|checkin|_time$|_date$|(^|\.)(date|time)$|last_)"


class Discovery:
    def __init__(self, client, args):
        self.c = client
        self.args = args
        self.page_size = args.page_size
        self.org_name = args.org
        self.org_id = args.org_id
        self.orgp = {}
        self.findings = {}
        self.only = set(x.strip().upper() for x in args.only.split(",")) if args.only else None
        self.apidoc = None
        self.versions = {}
        self.paths = collections.defaultdict(list)   # cle de mapping -> [(endpoint, chemin, exemple)]
        self.flags = {}
        self.totals = {}
        self.hosts = None
        self.hosts_cat = None
        self.hosts_resp = None
        self.samples = []
        self.host_show = {}
        self.lce = None
        self.cv = None
        self.cvv = None
        self.errata_items = []
        self.errata_cat = Catalog()
        self.base_resps = {}
        self.sample_why = {}

    # ----- utilitaires
    def want(self, ref):
        return self.only is None or ref in self.only

    def F(self, ref, title):
        f = Finding(ref, title)
        self.findings[ref] = f
        return f

    def log(self, msg):
        print(msg, file=sys.stderr, flush=True)

    def get(self, path, params=None, tag=None, anonymous=False):
        return self.c.get(path, params, tag, anonymous=anonymous)

    def methods_for(self, path):
        if not self.apidoc:
            return ""
        key = norm_url(path)
        return ",".join(sorted(self.apidoc.get(key, {}).get("methods", []))) or "absent d'Apipie"

    def apidoc_find(self, rx):
        if not self.apidoc:
            return []
        r = re.compile(rx, re.I)
        return [(m, u) for u, e in self.apidoc.items() for m in e["methods"] if r.search(u)]

    def fill(self, f, res, cause_default=None):
        f.result = res
        if res != CONF and not f.cause:
            f.cause = cause_default or f.failure_cause()

    # ----- contexte
    def connect(self):
        f = self.F("V10", "Statut et santé des services")
        a = self.get("/api/status", tag="status_foreman")
        b = self.get("/katello/api/status", tag="status_katello")
        p = self.get("/katello/api/ping", tag="ping")
        for r in (a, b, p):
            f.ep(r)
        self.base_resps = {"foreman": a, "katello": b, "ping": p}
        for label, r in (("foreman", a), ("katello", b)):
            if r.ok and isinstance(r.data, dict):
                self.versions[label] = r.data.get("version") or r.data.get("katello_version")
                if self.versions[label]:
                    self.c.keep.add(str(self.versions[label]))
        if p.ok and isinstance(p.data, dict):
            for k, v in p.data.items():
                f.fields.append(("/katello/api/ping", k, "1/1", short(v, 70)))
        return a, b, p

    def resolve_org(self):
        if self.org_id:
            self.orgp = {"organization_id": self.org_id}
            return
        r = self.get("/api/organizations", {"search": f'name="{self.org_name}"'}, tag="organizations")
        self.org_resp = r
        res = r.results() if r.ok else []
        if res:
            self.org_id = res[0].get("id")
            self.orgp = {"organization_id": self.org_id}
        else:
            self.log(f"! organisation '{self.org_name}' non résolue ({CAUSES.get(r.kind, r.kind)}) ; "
                     "utiliser --org-id si besoin.")

    def load_apidoc(self):
        r = self.get("/apidoc/v2.json", tag="apidoc")
        self.apidoc_resp = r
        if not (r.ok and isinstance(r.data, dict)):
            self.log(f"! Apipie indisponible ({CAUSES.get(r.kind, r.kind)}) : méthodes non listées.")
            return
        out = {}
        try:
            for _name, res in r.data["docs"]["resources"].items():
                for m in res.get("methods", []):
                    pnames = [p.get("name") for p in m.get("params", [])]
                    for api in m.get("apis", []):
                        e = out.setdefault(norm_url(api["api_url"]), {"methods": set(), "params": set(), "urls": set()})
                        e["methods"].add(api.get("http_method", "?"))
                        e["params"].update(pnames)
                        e["urls"].add(api["api_url"])
        except (KeyError, TypeError, AttributeError):
            self.log("! Structure Apipie inattendue.")
            return
        self.apidoc = out
        self.apidoc_urls = {u: e for e in out.values() for u in e["urls"]}

    def ctx_lifecycle(self):
        if self.lce is not None:
            return
        base = {**self.orgp, "per_page": self.page_size}
        self.lce = self.get("/katello/api/environments", base, tag="environments")
        self.cv = self.get("/katello/api/content_views", base, tag="content_views")
        self.cvv = self.get("/katello/api/content_view_versions", base, tag="content_view_versions")
        for key, r in (("environments", self.lce), ("content_views", self.cv), ("cv_versions", self.cvv)):
            if r.ok:
                self.totals[key] = r.meta("total", len(r.results()))

    def ctx_hosts(self, f=None):
        if self.hosts is None:
            r = self.get("/api/hosts", {**self.orgp, "per_page": self.page_size, "page": 1}, tag="hosts_list")
            self.hosts_resp = r
            self.hosts = r.results() if r.ok else []
            self.totals["hosts"] = r.meta("total", len(self.hosts)) if r.ok else None
            self.hosts_cat = Catalog().add_all(self.hosts)
            if self.hosts_resp.ok and self.hosts_resp.meta("results") is None:
                self.log("! réponse /api/hosts sans clé 'results'.")
            if (self.redactor_setup) and self.hosts:
                self.redactor_setup([h.get("name") for h in self.hosts if h.get("name")])
            self._pick_samples()
        if f is not None:
            f.ep(self.hosts_resp)
        return self.hosts

    redactor_setup = None

    def _pick_samples(self):
        """Choisit des hôtes informatifs : multi-CV, écart applicable/installable, traces, compteurs élevés."""
        def counts(h):
            cf = h.get("content_facet_attributes") or {}
            ec = cf.get("errata_counts") or {}
            inst = ec.get("total") if isinstance(ec.get("total"), (int, float)) else 0
            app = (ec.get("applicable") or {}).get("total") if isinstance(ec.get("applicable"), dict) else 0
            return inst or 0, app or 0
        def n_cve(h):
            cve = h.get("content_view_environments")
            if not isinstance(cve, list):
                cve = (h.get("content_facet_attributes") or {}).get("content_view_environments")
            return len(cve) if isinstance(cve, list) else 0
        def has_trace(h):
            for p, v in flatten(h):
                if "trace" in p.lower() and v not in (None, "", 0, False, "0"):
                    return True
            return False
        buckets = [
            ("multi-CV", sorted((h for h in self.hosts if n_cve(h) > 1), key=lambda h: -n_cve(h))),
            ("écart applicable/installable", sorted((h for h in self.hosts if counts(h)[1] > counts(h)[0]),
                                                    key=lambda h: -(counts(h)[1] - counts(h)[0]))),
            ("traces", [h for h in self.hosts if has_trace(h)]),
            ("compteurs élevés", sorted(self.hosts, key=lambda h: -sum(counts(h)))),
        ]
        chosen, why = [], {}
        i = 0
        # tour de rôle entre les catégories, pour qu'aucune ne monopolise l'échantillon
        while len(chosen) < self.args.sample_hosts and i < len(self.hosts) + 1:
            progressed = False
            for label, lst in buckets:
                if i < len(lst) and lst[i].get("id") is not None and lst[i]["id"] not in why:
                    why[lst[i]["id"]] = label
                    chosen.append(lst[i])
                    progressed = True
                    if len(chosen) >= self.args.sample_hosts:
                        break
            i += 1
            if not progressed and i > len(self.hosts):
                break
        self.samples = chosen
        self.sample_why = why

    # ----- V10
    def v10(self):
        f = self.findings["V10"]
        a, b, p = self.base_resps["foreman"], self.base_resps["katello"], self.base_resps["ping"]
        f.check("version de Foreman lisible", bool(self.versions.get("foreman")), str(self.versions.get("foreman")))
        kv = self.versions.get("katello")
        if not usable_version(kv):
            alt = self._katello_version_alternatives(f)
            if alt:
                self.versions["katello"] = kv = alt
        f.check("version de Katello lisible (0.0.0.0 = inutilisable)", usable_version(kv), str(kv))
        services = None
        if p.ok and isinstance(p.data, dict):
            services = p.data.get("services") if isinstance(p.data.get("services"), dict) else None
        f.check("ping : statut par service", services is not None,
                ", ".join(f"{k}={v.get('status') if isinstance(v, dict) else v}" for k, v in (services or {}).items())[:150])
        f.notes.append("Appels faits avec le compte fourni : un 403 sur /katello/api/ping est une restriction de droits, pas une absence.")
        ok = [bool(self.versions.get("foreman")), usable_version(self.versions.get("katello")), services is not None]
        self.fill(f, CONF if all(ok) else PART if any(ok) else NOAV)
        if services:
            self.paths["ping"].append(("/katello/api/ping", "services.*.status", short(list(services.items())[0][1], 40)))

    def _katello_version_alternatives(self, f):
        """Cherche la version de Katello ailleurs que dans /katello/api/status (qui renvoie 0.0.0.0)."""
        rx = re.compile(r"\bkatello\b[^\n]{0,40}?(\d+\.\d+(?:\.\d+)*)", re.I)
        found = None
        for path in ("/api/plugins", "/api/about", "/katello/api/about", "/api/v2/plugins"):
            r = self.get(path, tag="katello_version_" + re.sub(r"\W+", "_", path))
            f.ep(r, self.methods_for(path))
            if r.ok and not found:
                txt = json.dumps(r.data, ensure_ascii=False)
                for item in (r.data if isinstance(r.data, list) else r.results() if isinstance(r.data, dict) else []):
                    if isinstance(item, dict) and "katello" in str(item.get("name", "")).lower() and usable_version(item.get("version")):
                        found = str(item["version"])
                        break
                if not found:
                    m = rx.search(txt)
                    if m and usable_version(m.group(1)):
                        found = m.group(1)
        if self.apidoc_resp_ok():
            info = (self.apidoc_resp.data or {}).get("docs", {})
            for k in ("info", "name", "api_version", "version"):
                m = rx.search(str(info.get(k, "")))
                if m and usable_version(m.group(1)) and not found:
                    found = m.group(1)
        f.notes.append("Autres sources de la version de Katello essayées : /api/plugins, /api/about, /katello/api/about, "
                       "/api/v2/plugins, en-tête d'Apipie. " + (f"Trouvée : {found}." if found else "Aucune ne donne une version utilisable."))
        return found

    def apidoc_resp_ok(self):
        r = getattr(self, "apidoc_resp", None)
        return bool(r is not None and r.ok and isinstance(r.data, dict))

    # ----- V7
    def v7(self):
        f = self.F("V7", "Content Views, versions et environnements")
        self.ctx_lifecycle()
        for r in (self.lce, self.cv, self.cvv):
            f.ep(r, self.methods_for(r.path))
        cats = {}
        for key, r in (("environnements", self.lce), ("content_views", self.cv), ("versions", self.cvv)):
            cats[key] = Catalog().add_all(r.results()) if r.ok else Catalog()
        add_fields(f, "/katello/api/content_views", cats["content_views"],
                   r"(composite|rolling|needs_publish|publish|component|last_|version)")
        add_fields(f, "/katello/api/content_view_versions", cats["versions"],
                   r"(created_at|updated_at|environments|major|minor|version$|composite|description)")
        add_fields(f, "/katello/api/environments", cats["environnements"], r"(prior|successor|library|^name$)")
        found = {
            "date de publication d'une version": cats["versions"].find(r"(^|\.)created_at$", True),
            "environnements d'une version": cats["versions"].find(r"^environments", True),
            "ordre de promotion (prior/successor)": cats["environnements"].find(r"(prior|successor)", True),
            "indicateur composite": cats["content_views"].find(r"composite", True),
            "indicateur rolling": cats["content_views"].find(r"rolling", True),
            "indicateur à republier": cats["content_views"].find(r"needs_publish|needs_.*publish", True),
        }
        for label, paths in found.items():
            f.check(label, bool(paths), ", ".join(p for p, _ in paths[:4]))
        f.check("composants d'une CV composite", cats["content_views"].has(r"component"),
                ", ".join(p for p, _ in cats["content_views"].find(r"component", True)[:3]))
        f.notes.append("Sémantique non établie : 'created_at' d'une version = date de publication ? "
                       "À comparer avec l'interface (Content > Content Views > Versions).")
        f.notes.append(f"Totaux observés : {self.totals.get('environments')} environnements, "
                       f"{self.totals.get('content_views')} CV, {self.totals.get('cv_versions')} versions.")
        for k, rx, cat in (("cv_date", r"(^|\.)created_at$", "versions"), ("cv_env", r"^environments", "versions"),
                           ("lce_order", r"(prior|successor)", "environnements"),
                           ("cv_publish", r"needs_publish|rolling|composite", "content_views")):
            for p, e in cats[cat].find(rx, True)[:3]:
                self.paths[k].append((self._path_of(cat), p, short(e["ex"])))
        if not all(r.ok for r in (self.lce, self.cv, self.cvv)):
            self.fill(f, NOAV)
            return
        core = [bool(found[k]) for k in found]
        self.fill(f, CONF if all(core) else PART if any(core) else NOAV, "champ absent")

    def _path_of(self, cat):
        return {"versions": "/katello/api/content_view_versions", "content_views": "/katello/api/content_views",
                "environnements": "/katello/api/environments"}.get(cat, cat)

    # ----- V1
    def v1(self):
        f = self.F("V1", "Liste des hôtes : champs contenu / abonnement")
        recs = self.ctx_hosts(f)
        f.endpoints[-1] = f.endpoints[-1][:5] + (self.methods_for("/api/hosts"),)
        if not self.hosts_resp.ok:
            self.fill(f, NOAV)
            return
        if not recs:
            self.fill(f, NOTEST, "aucun hôte visible avec ce compte et cette organisation")
            return
        show_cat = Catalog()
        for h in self.samples or recs[:1]:
            r = self.get(f"/api/hosts/{h['id']}", tag="host_show")
            f.ep(r, self.methods_for("/api/hosts/:id"))
            if r.ok and isinstance(r.data, dict):
                self.host_show[h["id"]] = r.data
                show_cat.add(r.data)
        self.show_cat = show_cat
        rows, req_list, req_show, n_req = [], 0, 0, 0
        for name, rx, required in HOST_GROUPS:
            lp = self.hosts_cat.find(rx, True)
            sp = show_cat.find(rx, True)
            rows.append([name, "oui" if lp else "non", "oui" if sp else "non",
                         "; ".join(f"{p} = {short(e['ex'], 30)}" for p, e in (lp or sp)[:3]) or "-"])
            if required:
                n_req += 1
                req_list += 1 if lp else 0
                req_show += 1 if (lp or sp) else 0
            key = {"check-in": "checkin", "content view": "cv_host", "lifecycle environment": "lce_host",
                   "errata (compteurs)": "errata_counts", "paquets upgradables/applicables": "pkg_counts",
                   "content source": "content_source", "statut global": "global_status", "build": "build"}[name]
            for p, e in (lp or sp)[:6]:
                self.paths[key].append(("/api/hosts" if lp else "/api/hosts/:id", p, short(e["ex"], 40)))
            for p, e in lp[:12]:
                f.fields.append(("/api/hosts (liste)", p, f"{e['nonnull']}/{self.hosts_cat.records}", short(e["ex"], 50)))
        f.table("Groupes de champs : liste vs fiche détaillée", ["Groupe", "Dans la liste", "Dans la fiche", "Champs trouvés (exemple)"], rows)
        facets = self.hosts_cat.find(r"(content|subscription)_facet", False)
        with_facet = max((e["nonnull"] for _p, e in facets), default=0)
        f.notes.append(f"Hôtes échantillonnés : {self.hosts_cat.records} sur {self.totals.get('hosts')} ; "
                       f"au plus {with_facet} avec des données de facette non nulles.")
        f.notes.append("Existence uniquement : la signification de chaque champ reste à valider (voir mapping).")
        self.flags["v1_all_in_list"] = req_list == n_req
        self.flags["v1_all_in_show"] = req_show == n_req
        self.flags["v1_missing_in_list"] = [r[0] for r in rows[:n_req] if r[1] == "non"]
        if req_list == n_req:
            self.fill(f, CONF)
        elif req_show > 0 or req_list > 0:
            self.fill(f, PART, "champ absent de la liste" if req_show else "champ absent")
        else:
            self.fill(f, NOAV, "champ absent")

    # ----- V12
    def v12(self):
        f = self.F("V12", "Pagination, comptage et plafond de per_page")
        self.ctx_hosts()
        n = self.totals.get("hosts")
        base = dict(self.orgp)
        r1 = self.get("/api/hosts", {**base, "per_page": 1, "page": 1}, tag="hosts_count")
        f.ep(r1, self.methods_for("/api/hosts"))
        rows = []
        if r1.ok:
            keys = ("total", "subtotal", "page", "per_page")
            for k in keys:
                f.check(f"clé '{k}' dans la réponse", k in r1.data, short(r1.data.get(k)))
            f.check("per_page=1 renvoie une seule ligne", len(r1.results()) == 1, f"{len(r1.results())} ligne(s)")
            f.check("temps d'un comptage (per_page=1)", None, f"{round(r1.elapsed * 1000)} ms")
        sweep = {self.page_size, 500}
        if self.args.probe_large_page:
            sweep |= {1000, 5000}
        for pp in sorted(sweep):
            r = self.get("/api/hosts", {**base, "per_page": pp, "page": 1}, tag=f"hosts_pp{pp}")
            f.ep(r, "")
            if r.ok:
                rows.append([pp, r.meta("per_page"), len(r.results()), r.meta("total"), f"{round(r.elapsed * 1000)}"])
            else:
                rows.append([pp, CAUSES.get(r.kind, r.kind), "-", "-", f"{round(r.elapsed * 1000)}"])
        f.table("Effet de per_page sur /api/hosts", ["per_page demandé", "per_page annoncé", "lignes reçues", "total", "durée (ms)"], rows)
        cap = [r for r in rows if isinstance(r[2], int) and isinstance(r[0], int) and r[2] < r[0] and (r[3] is None or r[3] > r[2])]
        f.notes.append("Plafond détecté : " + ", ".join(f"per_page={r[0]} → {r[2]} lignes" for r in cap) if cap
                       else "Aucun plafond observé sur les valeurs testées (valeurs plus grandes : --probe-large-page).")
        # chevauchement des pages
        if isinstance(n, int) and n >= 3:
            a = self.get("/api/hosts", {**base, "per_page": 2, "page": 1}, tag="hosts_p1")
            b = self.get("/api/hosts", {**base, "per_page": 2, "page": 2}, tag="hosts_p2")
            f.ep(a)
            f.ep(b)
            ia, ib = {h.get("id") for h in a.results()}, {h.get("id") for h in b.results()}
            f.check("pages 1 et 2 disjointes", a.ok and b.ok and not (ia & ib) and bool(ib), f"{sorted(ia)} / {sorted(ib)}")
        else:
            f.check("pages disjointes", None, "moins de 3 hôtes : non testable")
        t = self.get("/api/hosts", {**base, "per_page": 2, "thin": "true"}, tag="hosts_thin")
        f.ep(t)
        if t.ok and t.results() and self.hosts:
            f.check("paramètre thin réduit les champs", len(flatten(t.results()[0])) < len(flatten(self.hosts[0])),
                    f"{len(flatten(t.results()[0]))} chemins contre {len(flatten(self.hosts[0]))}")
        else:
            f.check("paramètre thin réduit les champs", None, CAUSES.get(t.kind, t.kind))
        meta_rows = [[p, ", ".join(sorted(k)) or "-"] for p, k in sorted(self.c.page_meta.items())]
        f.table("Clés de pagination observées par endpoint", ["Endpoint", "Clés"], meta_rows)
        ok_meta = r1.ok and all(k in r1.data for k in ("total", "subtotal", "per_page"))
        checks_ko = [c for c in f.checks if c[1] == "non" and not c[0].startswith("paramètre thin")]
        self.flags["v12_count_ok"] = bool(ok_meta and len(r1.results()) == 1)
        self.flags["v12_cap"] = cap[0][2] if cap else None
        if not r1.ok:
            self.fill(f, NOAV)
        elif ok_meta and not checks_ko:
            self.fill(f, CONF)
        else:
            self.fill(f, PART, "clé de pagination ou comportement manquant")

    # ----- V2
    def v2(self):
        f = self.F("V2", "Recherche côté API sur les hôtes")
        self.ctx_hosts()
        self.ctx_lifecycle()
        lce_name = first_name(self.lce)
        cv_name = first_name(self.cv)
        queries = [
            ("last_checkin (ancien)", 'last_checkin < "7 days ago"', "last_checkin"),
            ("last_checkin (récent)", 'last_checkin > "7 days ago"', "last_checkin"),
            ("errata_status", "errata_status = security_needed", "errata_status"),
            ("trace_status", "trace_status = reboot_needed", "trace_status"),
            ("subscription_status", "subscription_status = valid", "subscription_status"),
            ("build", "build = true", "build"),
        ]
        if lce_name:
            queries.append(("lifecycle_environment", f'lifecycle_environment = "{lce_name}"', "lifecycle_environment"))
        if cv_name:
            queries.append(("content_view", f'content_view = "{cv_name}"', "content_view"))
        ctl = self.get("/api/hosts", {**self.orgp, "per_page": 1, "search": "champ_inexistant_katello_discovery = 1"}, tag="search_control")
        f.ep(ctl)
        msg_ctl = ctl.message().lower()
        # Katello/Foreman renvoie 400/422, ou 500 avec "not recognized for searching" sur /api/hosts.
        control_ok = ctl.kind == "bad_request" or (ctl.kind == "server_error" and ("not recognized" in msg_ctl or "non reconnu" in msg_ctl))
        f.check("requête de contrôle invalide rejetée (400/422, ou 500 'not recognized for searching')", control_ok,
                f"HTTP {ctl.status} : {ctl.message()[:90]}")
        if ctl.kind == "server_error":
            f.notes.append("Un champ de recherche inconnu renvoie HTTP 500 sur /api/hosts : l'outil final ne doit pas retenter ce 500.")
        total = self.totals.get("hosts")
        rows, accepted = [], []
        for label, q, field in queries:
            r = self.get("/api/hosts", {**self.orgp, "per_page": 1, "search": q}, tag="search_" + re.sub(r"\W+", "_", label))
            f.ep(r)
            if r.ok:
                verdict = "acceptée"
                accepted.append(field)
                rows.append([label, q, verdict, r.meta("subtotal"), r.meta("total"), ""])
            else:
                msg = r.message()
                unknown = "not recognized" in msg.lower() or "non reconnu" in msg.lower()
                rows.append([label, q, "champ inconnu" if unknown else CAUSES.get(r.kind, r.kind) + f" (HTTP {r.status})",
                             "-", "-", msg[:90]])
        f.table("Requêtes testées sur /api/hosts (per_page=1)", ["Test", "Recherche", "Résultat", "subtotal", "total", "Message"], rows)
        ac = self.apidoc_find(r"hosts/auto_complete")
        if ac:
            f.notes.append("Complétion automatique déclarée par Apipie : " + ", ".join(u for _m, u in ac[:2]))
        f.notes.append("Une recherche acceptée prouve que le champ est reconnu, pas que la valeur testée "
                       "(par exemple 'security_needed') est valide ni que le filtre a le sens attendu.")
        n_req = len([q for q in queries if q[2] in ("last_checkin", "errata_status", "trace_status", "build", "lifecycle_environment", "content_view")])
        wanted = {"last_checkin", "errata_status", "trace_status", "build", "lifecycle_environment", "content_view"}
        got = wanted & set(accepted)
        self.flags["v2_ok_fields"] = sorted(got)
        self.flags["v2_counts_ok"] = bool(control_ok and {"last_checkin", "errata_status", "trace_status", "build"} <= set(accepted))
        if not control_ok:
            self.fill(f, NOTEST, "le serveur n'a pas rejeté la requête de contrôle : résultats non interprétables"
                      if ctl.ok else f.failure_cause())
        elif got == wanted:
            self.fill(f, CONF)
        elif accepted:
            self.fill(f, PART, "champ de recherche inconnu ou valeur refusée")
        else:
            self.fill(f, NOAV, f.failure_cause() or "champ de recherche inconnu")
        for fld in sorted(got):
            self.paths["search"].append(("/api/hosts?search=", fld, "accepté"))

    # ----- V6
    def v6(self):
        f = self.F("V6", "Lien hôte, CV, environnement et version servie")
        self.ctx_hosts()
        self.ctx_lifecycle()
        if not self.samples:
            self.fill(f, NOTEST, "aucun hôte échantillonnable")
            return
        multi = sum(1 for h in self.hosts if len(host_cves(h)) > 1)
        with_cve = sum(1 for h in self.hosts if host_cves(h))
        f.check("hôtes avec content_view_environments[] renseigné", with_cve > 0, f"{with_cve} sur {len(self.hosts)}")
        f.check("hôtes avec plusieurs couples (CV, LCE)", None, f"{multi} sur {len(self.hosts)}")
        rows, ok_count, tested = [], 0, 0
        for h in self.samples:
            rec = self.host_show.get(h["id"], h)
            cves = host_cves(rec) or host_cves(h)
            why = self.sample_why.get(h["id"], "")
            if not cves:
                rows.append([h.get("name"), why, "-", "-", "-", "content_view_environments[] absent"])
                continue
            for c in cves:
                if c["cv_id"] is None or c["lce_id"] is None:
                    rows.append([h.get("name"), why, c["cv"], c["lce"], c["ver"], "identifiants absents"])
                    continue
                tested += 1
                r = self.get("/katello/api/content_view_versions", {"content_view_id": c["cv_id"], "environment_id": c["lce_id"]}, tag="cvv_pair")
                f.ep(r, self.methods_for("/katello/api/content_view_versions"))
                if not r.ok:
                    rows.append([h.get("name"), why, c["cv"], c["lce"], c["ver"], CAUSES.get(r.kind, r.kind)])
                    continue
                vs = r.results()
                ids = [v.get("id") for v in vs]
                match = c["ver_id"] in ids
                if match and len(vs) == 1:
                    ok_count += 1
                rows.append([h.get("name"), why, c["cv"], c["lce"],
                             f"{c['ver']} (id {c['ver_id']}, latest={c['latest']})",
                             f"{len(vs)} version(s) dans le couple : " + ("version servie retrouvée" if match else "version servie ABSENTE")])
        f.table("Couples (CV, LCE) des hôtes échantillonnés, version servie et versions du couple",
                ["Hôte", "Choisi pour", "CV", "LCE", "Version servie (fiche hôte)", "Comparaison avec l'API des versions"], rows)
        f.notes.append("La version servie vient de la fiche hôte ; la comparaison vérifie sa présence dans les versions du couple. "
                       "Le sens (version réellement reçue par la VM) reste à valider dans l'interface.")
        for key, ex in (("cv_env_list", "content_view_environments[]"),):
            self.paths["cv_env"].append(("/api/hosts", ex, f"{with_cve}/{len(self.hosts)} hôtes"))
        if tested == 0:
            self.fill(f, NOAV if with_cve == 0 else PART, "couples (CV, LCE) absents ou incomplets dans la fiche hôte")
        elif ok_count == tested:
            self.fill(f, CONF)
        else:
            self.fill(f, PART, "version servie non retrouvée dans les versions du couple, ou plusieurs versions par couple")
        self.flags["v6_multi_cv_hosts"] = multi

    # ----- V3 + V5
    def v3(self):
        f = self.F("V3", "Errata : applicables, installables et compteurs")
        self.ctx_hosts()
        if not self.samples:
            self.fill(f, NOTEST, "aucun hôte échantillonnable")
            return
        h0 = self.samples[0]["id"]
        cands = []
        for _m, u in self.apidoc_find(r"errata"):
            if _m == "GET" and len(re.findall(r":\w+", u)) == 1 and re.search(r"host", u):
                cands.append(("tpl", u))
        for u in ("/api/hosts/:id/errata", "/katello/api/hosts/:id/errata"):
            if ("tpl", u) not in cands:
                cands.append(("tpl", u))
        cands.append(("param", "/katello/api/errata"))
        chosen = None
        for kind, u in cands:
            path = re.sub(r":\w+", str(h0), u) if kind == "tpl" else u
            params = {"per_page": 1} if kind == "tpl" else {"host_id": h0, "per_page": 1, **self.orgp}
            r = self.get(path, params, tag="errata_probe")
            f.ep(r, self.methods_for(u))
            if r.ok and isinstance(r.data, dict) and "total" in r.data:
                chosen = (kind, u)
                break
        if not chosen:
            self.fill(f, NOAV, f.failure_cause() or "aucun endpoint d'errata par hôte trouvé")
            return
        kind, u = chosen
        f.notes.append(f"Endpoint retenu : {u}")
        cap = min(self.page_size, 200)
        rows, subset_ok, diff_seen, truncated = [], True, False, False
        facet_matches = []
        for h in self.samples:
            hid = h["id"]
            path = re.sub(r":\w+", str(hid), u) if kind == "tpl" else u
            base = {} if kind == "tpl" else {"host_id": hid, **self.orgp}
            got = {}
            for label, extra in (("défaut", {}), ("applicable", {"errata_restrict_applicable": "true"}),
                                 ("installable", {"errata_restrict_installable": "true"})):
                r = self.get(path, {**base, **extra, "per_page": cap}, tag=f"errata_{label}")
                f.ep(r)
                if not r.ok:
                    got[label] = None
                    continue
                items = r.results()
                tot = r.meta("subtotal", r.meta("total", len(items)))
                got[label] = {"total": tot, "ids": {i.get("errata_id") or i.get("id") for i in items}, "full": tot is not None and len(items) >= tot}
                for it in items:
                    if isinstance(it, dict):
                        self.errata_cat.add(it)
                        self.errata_items.append(it)
            a, i = got.get("applicable"), got.get("installable")
            if a and i:
                if a["full"] and i["full"]:
                    subset_ok &= i["ids"] <= a["ids"]
                else:
                    truncated = True
                diff_seen |= (a["total"] or 0) > (i["total"] or 0)
            vals = {}
            for p, v in flatten(self.host_show.get(hid, h)):
                if "errata" in p.lower() and isinstance(v, (int, float)) and not isinstance(v, bool):
                    vals[p] = v
            for p, v in vals.items():
                eq = [lab for lab in ("défaut", "applicable", "installable") if got.get(lab) and got[lab]["total"] == v]
                if v and eq:
                    facet_matches.append((p, v, eq))
            rows.append([h.get("name"), *(got[l]["total"] if got.get(l) else "-" for l in ("défaut", "applicable", "installable")),
                         "; ".join(f"{p}={v}" for p, v in list(vals.items())[:4]) or "-"])
        f.table("Totaux par hôte échantillonné", ["Hôte", "défaut", "applicable", "installable", "compteurs de la fiche hôte"], rows)
        f.check("installables ⊆ applicables (identifiants)", None if truncated else subset_ok,
                "listes tronquées" if truncated else "")
        f.check("écart applicable − installable observé", diff_seen)
        f.check("compteur de la fiche égal à un total d'errata", bool(facet_matches),
                "; ".join(f"{p}={v}→{'/'.join(eq)}" for p, v, eq in facet_matches[:4]))
        types = collections.Counter(str(i.get("type") or i.get("errata_type")) for i in self.errata_items)
        f.check("type d'erratum présent (security, bugfix…)", bool(types) and "None" not in types or any(k != "None" for k in types),
                ", ".join(f"{k}={v}" for k, v in types.most_common(5)))
        add_fields(f, u, self.errata_cat, r"^(errata_id|type|errata_type|severity|issued|updated|title|id)$")
        f.notes.append("Ce contrôle mesure une cohérence, il ne prouve pas la sémantique d'« applicable » et "
                       "d'« installable » : comparer 2 hôtes avec l'interface (Hôte > Errata, filtre installable).")
        f.notes.append("Des totaux identiques partout peuvent signifier que le paramètre est ignoré OU qu'aucun écart n'existe sur ces hôtes.")
        for p, v, eq in facet_matches[:6]:
            self.paths["errata_counts"].append(("/api/hosts/:id (cohérence)", p, f"{v} = total {'/'.join(eq)}"))
        self.paths["errata_detail"].append((u, "total / results[] (params errata_restrict_*)", "-"))
        self.flags["v3_endpoint"] = u
        self.flags["v3_endpoint_kind"] = kind
        if not subset_ok:
            self.fill(f, PART, "incohérence : des installables ne sont pas applicables")
        elif diff_seen and (facet_matches or True) and not truncated:
            self.fill(f, CONF if facet_matches else PART, "" if facet_matches else "aucun compteur de la fiche ne correspond à un total d'errata")
        else:
            self.fill(f, PART, "aucun écart applicable/installable observé ou listes tronquées : "
                      "essayer des hôtes ayant du contenu en attente")

    def v5(self):
        f = self.F("V5", "Sévérité des errata")
        if not self.errata_items:
            self.v3_if_needed()
        r = self.get("/katello/api/errata", {**self.orgp, "per_page": min(self.page_size, 100)}, tag="errata_list")
        f.ep(r, self.methods_for("/katello/api/errata"))
        items = list(self.errata_items) + (r.results() if r.ok else [])
        if not items:
            self.fill(f, NOTEST if r.ok else NOAV, "aucun erratum visible" if r.ok else f.failure_cause())
            return
        cat = Catalog().add_all(items)
        add_fields(f, "errata (hôtes + liste)", cat, r"(severity|type|issued)")
        sec = [i for i in items if str(i.get("type") or i.get("errata_type")).lower() == "security"]
        sev_all = collections.Counter(str(i.get("severity")) for i in items)
        sev_sec = collections.Counter(str(i.get("severity")) for i in sec)
        f.table("Répartition de la sévérité", ["Population", "Effectif", "Valeurs de severity"],
                [["tous les errata observés", len(items), ", ".join(f"{k}={v}" for k, v in sev_all.most_common(6))],
                 ["errata de type security", len(sec), ", ".join(f"{k}={v}" for k, v in sev_sec.most_common(6)) or "-"]])
        has_field = any("severity" in i for i in items)
        sec_with = [i for i in sec if i.get("severity") not in (None, "", "None")]
        for p, e in cat.find(r"severity", True)[:2]:
            self.paths["severity"].append(("errata", p, short(e["ex"])))
        f.notes.append("La sévérité n'est jamais déduite : une valeur absente reste absente.")
        if not has_field:
            self.fill(f, NOAV, "champ 'severity' absent des errata")
        elif sec_with:
            self.fill(f, CONF)
        elif not sec:
            self.fill(f, NOTEST, "aucun erratum security dans l'échantillon")
        else:
            self.fill(f, PART, "champ présent mais vide pour les errata security (métadonnées des dépôts)")

    def v3_if_needed(self):
        if "V3" not in self.findings:
            self.v3()

    # ----- V4
    def v4(self):
        f = self.F("V4", "Date du profil de paquets / de l'applicabilité")
        self.ctx_hosts()
        cats = [("liste", self.hosts_cat)] + ([("fiche", self.show_cat)] if getattr(self, "show_cat", None) else [])
        strict, generic = [], []
        for where, cat in cats:
            for p, e in cat.find(STRICT_PROFILE, True):
                strict.append((where, p, e))
            for p, e in cat.find(GENERIC_TIME, True):
                if is_date(e["ex"]) or isinstance(e["ex"], (int, float)):
                    generic.append((where, p, e))
        f.table("Champs au nom explicite (profil de paquets / applicabilité)", ["Source", "Chemin", "Exemple"],
                [[w, p, short(e["ex"], 50)] for w, p, e in strict] or [["-", "aucun", "-"]])
        f.table("Horodatages génériques observés (signification non établie)", ["Source", "Chemin", "Exemple"],
                [[w, p, short(e["ex"], 50)] for w, p, e in generic[:25]] or [["-", "aucun", "-"]])
        for w, p, e in strict[:4]:
            self.paths["profile"].append(("/api/hosts" if w == "liste" else "/api/hosts/:id", p, short(e["ex"], 40)))
        f.notes.append("Les horodatages génériques (updated_at, last_checkin…) ne sont PAS retenus comme date de profil.")
        f.notes.append("Savoir si la date avance quand rien ne change sur la VM demande une observation dans le temps : "
                       "relancer l'outil plus tard et comparer les fichiers bruts.")
        if any(is_date(e["ex"]) for _w, _p, e in strict):
            self.fill(f, CONF)
        elif strict:
            self.fill(f, PART, "champ au nom explicite mais valeur non datée")
        else:
            self.fill(f, NOAV, "champ absent : seuls des horodatages génériques sont exposés")

    # ----- V13
    def v13(self):
        f = self.F("V13", "Traces (reboot, services à redémarrer)")
        self.ctx_hosts()
        if not self.samples:
            self.fill(f, NOTEST, "aucun hôte échantillonnable")
            return
        cands = [u for _m, u in self.apidoc_find(r"trace") if _m == "GET" and len(re.findall(r":\w+", u)) == 1]
        for u in ("/api/hosts/:id/traces", "/katello/api/hosts/:id/traces"):
            if u not in cands:
                cands.append(u)
        in_list = self.hosts_cat.find(r"trace", True)
        for p, e in in_list[:4]:
            f.fields.append(("/api/hosts (liste)", p, f"{e['nonnull']}/{self.hosts_cat.records}", short(e["ex"], 50)))
            self.paths["traces"].append(("/api/hosts", p, short(e["ex"], 40)))
        f.check("champs de traces dans la liste des hôtes", bool(in_list), ", ".join(p for p, _ in in_list[:3]))
        working, with_items, cat = None, False, Catalog()
        for u in cands:
            for h in self.samples:
                r = self.get(re.sub(r":\w+", str(h["id"]), u), {"per_page": 20}, tag="traces")
                f.ep(r, self.methods_for(u))
                if r.ok:
                    working = u
                    items = r.results()
                    if items:
                        with_items = True
                        cat.add_all(i for i in items if isinstance(i, dict))
                        break
                else:
                    break
            if working:
                break
        if working:
            add_fields(f, working, cat, r".*")
            self.paths["traces"].append((working, "results[] (1 appel par hôte)", "-"))
            self.flags["v13_per_host"] = working
        f.check("endpoint de traces répond (200)", bool(working), working or "")
        f.check("au moins une trace observée (champs relevables)", with_items if working else None)
        f.notes.append("Une réponse vide ne dit rien sur les champs : aucun hôte échantillonné n'avait de trace.")
        if not working:
            self.fill(f, NOAV if in_list == [] else PART, f.failure_cause() or "endpoint absent")
        elif with_items:
            self.fill(f, CONF)
        else:
            self.fill(f, PART, "endpoint présent, champs non observés (aucune trace sur l'échantillon)")

    # ----- V14
    def v14(self):
        f = self.F("V14", "Durée en build")
        self.ctx_hosts()
        r = self.get("/api/hosts", {**self.orgp, "per_page": 5, "search": "build = true"}, tag="hosts_build")
        f.ep(r)
        builds = r.results() if r.ok else []
        cats = [("liste", self.hosts_cat)] + ([("fiche", self.show_cat)] if getattr(self, "show_cat", None) else [])
        rows = []
        for where, cat in cats:
            for p, e in cat.find(r"(build|install|provision)", True):
                rows.append([where, p, short(e["ex"], 40), f"{e['nonnull']}/{cat.records}"])
        f.table("Champs liés au build ou à l'installation", ["Source", "Chemin", "Exemple", "Présence"], rows or [["-", "aucun", "-", "-"]])
        strict = [x for x in rows if re.search(r"build.*(start|begin|since|time|date|at$)|(start|begin).*build", x[1], re.I)]
        f.check("hôtes actuellement en build", bool(builds), f"{len(builds)} (page de 5)")
        ini = []
        for h in (builds or [])[:5]:
            for p, v in flatten(h):
                if re.search(r"(initiated_at|build_.*(at|time)|installed_at)$", p, re.I):
                    ini.append([h.get("name"), p, short(v, 40)])
        pool = self.hosts_cat.find(r"(initiated_at|installed_at)", True)
        f.table("initiated_at / installed_at : présence dans la liste des hôtes", ["Chemin", "Exemple", "Présence"],
                [[p, short(e["ex"], 40), f"{e['nonnull']}/{self.hosts_cat.records}"] for p, e in pool] or [["-", "aucun", "-"]])
        f.table("Hôtes en build : horodatages candidats", ["Hôte", "Chemin", "Valeur"], ini or [["-", "aucun hôte en build ou champ absent", "-"]])
        f.notes.append("Si initiated_at est renseigné pour un hôte en build, il reste un CANDIDAT : il faut le comparer "
                       "avec l'heure réelle de lancement du build avant de l'adopter.")
        f.notes.append("created_at et updated_at d'un hôte ne sont pas retenus comme début de build : "
                       "updated_at change à chaque modification.")
        for x in rows[:4]:
            self.paths["build"].append(("/api/hosts", x[1], x[2]))
        if strict:
            self.fill(f, CONF if any(is_date(x[2]) for x in strict) else PART, "")
        elif ini and any(is_date(x[2]) for x in ini):
            self.fill(f, PART, "initiated_at renseigné sur un hôte en build : candidat à valider avec un build réel")
        elif not r.ok:
            self.fill(f, NOAV)
        else:
            self.fill(f, NOAV, "champ absent : aucun horodatage de début de build explicite"
                      + ("" if builds else " (aucun hôte en build pour observer)"))

    # ----- V8
    def v8(self):
        f = self.F("V8", "Dépôts et produits : synchronisation")
        base = {**self.orgp, "per_page": self.page_size}
        rp = self.get("/katello/api/repositories", base, tag="repositories")
        pr = self.get("/katello/api/products", base, tag="products")
        sp = self.get("/katello/api/sync_plans", base, tag="sync_plans")
        for r in (rp, pr, sp):
            f.ep(r, self.methods_for(r.path))
        for key, r in (("repos", rp), ("products", pr), ("sync_plans", sp)):
            if r.ok:
                self.totals[key] = r.meta("total", len(r.results()))
        if not rp.ok:
            self.fill(f, NOAV)
            return
        cat = Catalog().add_all(rp.results())
        pcat = Catalog().add_all(pr.results()) if pr.ok else Catalog()
        add_fields(f, "/katello/api/repositories", cat, r"(last_sync|sync_state|content_counts|(^|\.)url$|upstream|content_type|library_instance)")
        add_fields(f, "/katello/api/products", pcat, r"(last_sync|sync_plan|sync_summary)")
        date = cat.find(r"last_sync.*(ended|finished|_at|date|time)|^last_sync$", True)
        date = [(p, e) for p, e in date if is_date(e["ex"])]
        result = cat.find(r"(last_sync.*(result|state|status)|sync_state)", True)
        change = cat.find(r"content_counts", True)
        f.check("date de dernière synchronisation (valeur datée)", bool(date), ", ".join(p for p, _ in date[:3]))
        f.check("résultat de la dernière synchronisation", bool(result), ", ".join(p for p, _ in result[:3]))
        f.check("indicateur de changement de contenu", bool(change),
                "candidat : " + ", ".join(p for p, _ in change[:2]) + " (compteurs, sémantique à valider)" if change else "")
        res = rp.results()
        no_url = sum(1 for r in res if not r.get("url"))
        f.notes.append(f"Dépôts sans URL source (candidats N/A) : {no_url} sur {len(res)}.")
        f.notes.append("Des compteurs de contenu ne sont pas un indicateur de changement : ils permettraient au mieux "
                       "de comparer deux exécutions, ce que l'outil ne ferait pas en v1.")
        for p, e in (date + result)[:6]:
            self.paths["sync"].append(("/katello/api/repositories", p, short(e["ex"], 40)))
        for p, e in change[:2]:
            self.paths["sync_change"].append(("/katello/api/repositories", p, short(e["ex"], 40)))
        self.flags["v8_no_url"] = no_url
        if date and result and change:
            self.fill(f, CONF if not change else PART, "indicateur de changement : seulement des compteurs")
            f.result = PART
        elif date or result:
            self.fill(f, PART, "champ absent : " + ", ".join(n for n, ok in (("date", bool(date)), ("résultat", bool(result))) if not ok) or "indicateur de changement absent")
        else:
            self.fill(f, NOAV, "champ absent")

    # ----- V9
    def v9(self):
        f = self.F("V9", "Tâches : recherche par état et libellés")
        base = "/foreman_tasks/api/tasks"
        probes = [("state = paused", "state = paused"), ("result = error", "result = error"),
                  ("stopped et error", "state = stopped and result = error"),
                  ("depuis 24 h", 'started_at > "24 hours ago"')]
        ctl = self.get(base, {"per_page": 1, "search": "champ_inexistant_katello_discovery = 1"}, tag="tasks_control")
        f.ep(ctl, self.methods_for(base))
        f.check("requête de contrôle invalide rejetée", ctl.kind == "bad_request", f"HTTP {ctl.status}")
        rows, accepted = [], 0
        for label, q in probes:
            r = self.get(base, {"per_page": 1, "search": q}, tag="tasks_" + re.sub(r"\W+", "_", label))
            f.ep(r)
            rows.append([label, "acceptée" if r.ok else CAUSES.get(r.kind, r.kind), r.meta("subtotal") if r.ok else "-", r.meta("total") if r.ok else "-"])
            accepted += 1 if r.ok else 0
        f.table("Recherches testées sur /foreman_tasks/api/tasks", ["Recherche", "Résultat", "subtotal", "total"], rows)
        rec = self.get(base, {"per_page": 100, "order": "started_at DESC"}, tag="tasks_recent")
        f.ep(rec)
        labels = collections.Counter()
        cat = Catalog()
        if rec.ok:
            for t in rec.results():
                labels[str(t.get("label"))] += 1
                cat.add(t)
        add_fields(f, base, cat, r"^(label|state|result|started_at|ended_at|action|id)$")
        kinds = {"synchronisation": r"sync", "publication": r"publish", "promotion": r"promote"}
        # Sonde ciblée : la fenêtre des 100 dernières tâches peut ne contenir ni publication ni promotion.
        for lab_rx in ("Publish", "Promote", "ContentView"):
            rr = self.get(base, {"per_page": 50, "search": f"label ~ {lab_rx}", "order": "started_at DESC"}, tag="tasks_label_" + lab_rx)
            f.ep(rr)
            if rr.ok:
                for t in rr.results():
                    labels[str(t.get("label"))] += 1
                    cat.add(t)
        found = {k: [l for l in labels if re.search(rx, l, re.I)] for k, rx in kinds.items()}
        # Détail d'une tâche de chaque famille : la CV concernée est-elle identifiable ?
        if True:
            rows_d = []
            for fam, labs in found.items():
                if not labs:
                    continue
                rr = self.get(base, {"per_page": 1, "search": f'label = "{labs[0]}"', "order": "started_at DESC"}, tag="task_one_" + fam)
                f.ep(rr)
                t = (rr.results() or [None])[0] if rr.ok else None
                if t and t.get("id"):
                    d1 = self.get(f"{base}/{t['id']}", tag="task_detail_" + fam)
                    f.ep(d1)
                    if d1.ok and isinstance(d1.data, dict):
                        keys = [p for p, _v in flatten(d1.data.get("input", {})) if re.search(r"(content_view|repository|environment|version|product)", p, re.I)]
                        rows_d.append([fam, labs[0], ", ".join(keys[:6]) or "aucun champ identifiant"])
            f.table("Tâche détaillée : champs d'entrée (input) identifiant la cible", ["Famille", "Libellé", "Champs input utiles"],
                    rows_d or [["-", "aucune tâche à détailler", "-"]])
        f.table("Libellés observés dans les 100 dernières tâches", ["Famille", "Libellés réels", "Occurrences"],
                [[k, ", ".join(v[:3]) or "aucun observé", sum(labels[x] for x in v)] for k, v in found.items()])
        for p, e in cat.find(r"^(label|state|result)$", True):
            self.paths["tasks"].append((base, p, short(e["ex"], 40)))
        self.flags["v9_labels"] = {k: v[:1] for k, v in found.items()}
        self.flags["v9_search_ok"] = accepted == len(probes) and ctl.kind == "bad_request"
        if not rec.ok and accepted == 0:
            self.fill(f, NOAV)
        elif accepted == len(probes) and all(found.values()) and ctl.kind == "bad_request":
            self.fill(f, CONF)
        else:
            self.fill(f, PART, "libellé non observé dans les 100 dernières tâches (peut simplement ne pas avoir eu lieu)"
                      if accepted == len(probes) else "recherche refusée ou contrôle non rejeté")

    # ----- V11
    def v11(self):
        f = self.F("V11", "Espace disque de Pulp")
        cands = ["/pulp/api/v3/status/", "/api/smart_proxies"]
        for u in cands:
            r = self.get(u, {"per_page": 5} if "smart" in u else None, tag="disk_" + re.sub(r"\W+", "_", u))
            f.ep(r, self.methods_for(u))
            if r.kind == "redirect":
                f.notes.append(f"{u} : redirection vers {r.location} (non suivie, par sécurité).")
        rx = re.compile(r"(?<!name)(disk|storage|free_space|(?<![a-z])space|capacity|used_bytes|free_bytes)", re.I)
        hits = [(ep, p) for ep, paths in self.c.seen_paths.items() for p in paths if rx.search(p) and not re.search(r"namespace", p, re.I)]
        an = self.get("/pulp/api/v3/status/", tag="disk_pulp_anonymous", anonymous=True)
        f.ep(an)
        f.check("/pulp/api/v3/status/ lisible SANS authentification", an.ok, f"HTTP {an.status}")
        if an.ok and isinstance(an.data, dict):
            st = an.data.get("storage") if isinstance(an.data.get("storage"), dict) else None
            if st:
                t, u, fr = st.get("total"), st.get("used"), st.get("free")
                if all(isinstance(x, (int, float)) for x in (t, u, fr)) and t:
                    f.table("Pulp storage : valeurs brutes et lecture en octets (unité à valider avec df -B1)",
                            ["Champ", "Valeur brute", "En GiB si octets", "Part du total"],
                            [[k, v, round(v / 1024 ** 3, 1), f"{round(100 * v / t, 1)} %"] for k, v in (("total", t), ("used", u), ("free", fr))])
                    f.notes.append("Si 'used' + 'free' ≈ 'total' et que la part utilisée correspond à df, l'unité est cohérente ; "
                                   "comparer avec: df -B1 /var/lib/pulp")
        f.table("Champs au nom évocateur de stockage dans toutes les réponses reçues", ["Endpoint", "Chemin"],
                [[ep, p] for ep, p in sorted(set(hits))[:20]] or [["-", "aucun"]])
        f.notes.append("Le balayage porte sur les noms de champs de TOUTES les réponses JSON reçues pendant cette exécution.")
        f.notes.append("Pulp 3 n'est en général pas joignable avec un jeton Foreman : il demande un certificat client.")
        if hits:
            self.fill(f, PART, "champ au nom évocateur trouvé : valeur et unité à valider (l'égalité avec df a été constatée à la main)")
            for ep, p in sorted(set(hits))[:3]:
                self.paths["disk"].append((ep, p, "-"))
        else:
            self.fill(f, NOAV, f.failure_cause() or "non exposé par l'API Foreman/Katello")

    # ----- V16
    def v16(self):
        f = self.F("V16", "Lien dépôt, version de CV et contenu publié")
        self.ctx_lifecycle()
        if not (self.cvv and self.cvv.ok and self.cvv.results()):
            self.fill(f, NOTEST, "aucune version de CV lisible")
            return
        lib = self.get("/katello/api/repositories", {**self.orgp, "per_page": 1}, tag="repos_count")
        f.ep(lib, self.methods_for("/katello/api/repositories"))
        rows, ok = [], 0
        versions = self.cvv.results()[:3]
        for v in versions:
            vid = v.get("id")
            r = self.get("/katello/api/repositories", {"content_view_version_id": vid, "per_page": 100}, tag="repos_of_version")
            f.ep(r, self.methods_for("/katello/api/repositories"))
            names = [str(x.get("name") or x.get("id")) for x in r.results()] if r.ok else []
            det = self.get(f"/katello/api/content_view_versions/{vid}", tag="cvv_detail")
            f.ep(det)
            keys = []
            if det.ok and isinstance(det.data, dict):
                keys = [p for p, _v in flatten(det.data) if re.search(r"(repositor|content_counts|package_count|errata_counts|component)", p, re.I)]
            rows.append([v.get("name") or v.get("version"), r.meta("total", len(names)) if r.ok else CAUSES.get(r.kind, r.kind),
                         ", ".join(names[:4]), ", ".join(sorted(set(keys))[:5]) or "-"])
            ok += 1 if r.ok and names else 0
        f.table("Dépôts par version de CV (filtre content_view_version_id)",
                ["Version", "Nb dépôts", "Exemples", "Champs repositories/compteurs sur la fiche version"], rows)
        f.check("dépôts filtrables par version de CV", ok > 0, f"{ok}/{len(versions)} versions avec dépôts")
        f.notes.append("Ce lien dit quels dépôts alimentent une CV ; il ne dit pas si le contenu a CHANGÉ depuis la dernière "
                       "publication (aucun indicateur de changement n'est exposé, voir V8).")
        for p in ("content_view_version_id (filtre)",):
            self.paths["repo_cv"].append(("/katello/api/repositories", p, "oui" if ok else "non"))
        self.fill(f, CONF if ok == len(versions) else PART if ok else NOAV, "filtre refusé ou résultat vide" if not ok else "")

    # ----- V17
    def v17(self):
        f = self.F("V17", "CV composites et rolling")
        self.ctx_lifecycle()
        if not (self.cv and self.cv.ok):
            self.fill(f, NOTEST, "liste des CV illisible")
            return
        cvs = self.cv.results()
        comp = [c for c in cvs if c.get("composite")]
        roll = [c for c in cvs if c.get("rolling")]
        f.check("CV composites présentes", bool(comp), f"{len(comp)} sur {len(cvs)}")
        f.check("CV rolling présentes", bool(roll), f"{len(roll)} sur {len(cvs)}")
        rows = []
        for fam, lst in (("composite", comp), ("rolling", roll)):
            for c in lst[:2]:
                det = self.get(f"/katello/api/content_views/{c['id']}", tag="cv_detail_" + fam)
                f.ep(det)
                keys = [p for p, _v in flatten(det.data)
                        if re.search(r"(component|latest_version|environments|last_published|needs_publish)", p, re.I)] if det.ok else []
                rows.append([fam, c.get("name"), ", ".join(sorted(set(keys))[:6]) or "-"])
        f.table("Champs observés sur les CV composites et rolling", ["Type", "CV", "Champs utiles"], rows or [["-", "aucune CV de ce type", "-"]])
        f.notes.append("Sans CV composite ni rolling sur l'instance, le comportement n'est pas observable : la règle "
                       "d'exemption du retard de CV (rolling = N/A) reste une hypothèse à tester sur une instance qui en a.")
        if comp or roll:
            self.fill(f, PART, "champs relevés, comportement à valider dans l'interface")
        else:
            self.fill(f, NOTEST, "aucune CV composite ni rolling sur cette instance")

    # ----- V15
    def v15(self):
        f = self.F("V15", "Authentification par jeton et droits en lecture seule")
        calls = self.c.calls
        auth_fail = [c for c in calls if c[4] == "auth"]
        okc = [c for c in calls if c[4] == "ok"]
        f.check("authentification Basic (utilisateur + jeton) acceptée", bool(okc) and not auth_fail,
                f"{len(auth_fail)} réponse(s) 401" if auth_fail else "")
        by = collections.defaultdict(collections.Counter)
        for _n, path, _p, status, kind, _ms in calls:
            if path == "/apidoc/v2.json":
                continue
            by[re.sub(r"/\d+(?=/|$)", "/:id", path)][status if status else "réseau"] += 1
        rows = [[p, ", ".join(f"{k}×{v}" for k, v in sorted(c.items(), key=lambda t: str(t[0])))] for p, c in sorted(by.items())]
        f.table("Statuts HTTP par endpoint (appels réellement faits)", ["Endpoint", "Statuts"], rows)
        forb = [p for p, c in by.items() if 403 in c]
        f.check("aucun 403 sur les endpoints GET sondés", not forb, ", ".join(forb))
        u = self.get("/api/users", {"search": f'login="{self.args.user}"'}, tag="users_self")
        f.ep(u)
        if u.ok and u.results():
            roles = u.results()[0].get("roles")
            f.notes.append("Rôles du compte lisibles : " + ", ".join(str(r.get("name")) for r in roles) if isinstance(roles, list)
                           else "Compte lisible ; rôles non listés dans la réponse.")
        else:
            f.notes.append(f"Rôles du compte non lisibles ({CAUSES.get(u.kind, u.kind)}) : à vérifier dans l'interface "
                           "(Administrer > Utilisateurs). Un refus ici est normal pour un rôle Viewer.")
        f.notes.append("Les droits sont constatés sur les GET effectués, pas déduits du nom du rôle.")
        if auth_fail and not okc:
            self.fill(f, NOAV, CAUSES["auth"])
        elif not forb and okc:
            self.fill(f, CONF)
        else:
            self.fill(f, PART, "droits insuffisants (403) sur : " + ", ".join(forb))

    # ----- orchestration
    def run(self):
        self.log("→ connexion, version, santé")
        self.connect()
        if self.base_resps["foreman"].kind == "network" and self.base_resps["katello"].kind == "network":
            self.log("✗ serveur injoignable : arrêt.")
            self.v10()
            return False
        self.log("→ organisation et Apipie")
        self.resolve_org()
        self.load_apidoc()
        for f_ in self.findings.values():
            pass
        steps = [("V10", self.v10), ("V7", self.v7), ("V1", self.v1), ("V12", self.v12), ("V2", self.v2),
                 ("V6", self.v6), ("V3", self.v3), ("V5", self.v5), ("V4", self.v4), ("V13", self.v13),
                 ("V14", self.v14), ("V8", self.v8), ("V9", self.v9), ("V11", self.v11), ("V15", self.v15),
                 ("V16", self.v16), ("V17", self.v17)]
        need = {"V5": ["V3"], "V6": ["V1"], "V3": ["V1"], "V4": ["V1"], "V13": ["V1"], "V14": ["V1"]}
        wanted = set()
        for ref, _fn in steps:
            if self.want(ref):
                wanted.add(ref)
                wanted.update(need.get(ref, []))
        for ref, fn in steps:
            if ref in wanted:
                self.log(f"→ {ref}")
                try:
                    fn()
                except Exception as e:  # une erreur d'analyse ne doit pas masquer les autres points
                    f = self.findings.get(ref) or self.F(ref, ref)
                    f.result, f.cause = NOTEST, f"erreur interne de l'outil : {type(e).__name__}: {e}"
        return True


# --------------------------------------------------------------------------- aides

def find_key(obj, key):
    """Premier objet sous la clé donnée, n'importe où dans la structure."""
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            r = find_key(v, key)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_key(v, key)
            if r is not None:
                return r
    return None


def host_cves(h):
    """Liste des couples (CV, LCE, version servie) d'un hôte, d'après content_view_environments[]."""
    lst = find_key(h, "content_view_environments")
    out = []
    for e in lst if isinstance(lst, list) else []:
        if not isinstance(e, dict):
            continue
        cv = e.get("content_view") if isinstance(e.get("content_view"), dict) else {}
        lc = e.get("lifecycle_environment") if isinstance(e.get("lifecycle_environment"), dict) else {}
        ver = e.get("content_view_version") if isinstance(e.get("content_view_version"), dict) else {}
        out.append({"cv_id": cv.get("id", e.get("content_view_id")), "cv": cv.get("name"),
                    "lce_id": lc.get("id", e.get("lifecycle_environment_id")), "lce": lc.get("name"),
                    # Katello 4.21 : la version servie est DANS content_view (content_view_version, _id, _latest)
                    "ver_id": ver.get("id", cv.get("content_view_version_id", e.get("content_view_version_id"))),
                    "ver": ver.get("version", cv.get("content_view_version", e.get("content_view_version") if not isinstance(e.get("content_view_version"), dict) else None)),
                    "latest": cv.get("content_view_version_latest", e.get("content_view_version_latest", ver.get("latest")))})
    return out


def usable_version(v):
    """Une version est utilisable si elle existe et n'est pas du type 0.0.0.0."""
    return bool(v) and not re.fullmatch(r"0+(\.0+)*", str(v).strip())


def norm_url(u):
    return re.sub(r":\w+", ":x", re.sub(r"\{\w+\}", ":x", u)).rstrip("/")


def first_name(resp):
    if resp is not None and resp.ok:
        for r in resp.results():
            if isinstance(r, dict) and r.get("name") and not r.get("library"):
                return r["name"]
        for r in resp.results():
            if isinstance(r, dict) and r.get("name"):
                return r["name"]
    return None


def id_values(rec, rx):
    r = re.compile(rx, re.I)
    return [v for p, v in flatten(rec) if r.search(p) and isinstance(v, int) and not isinstance(v, bool)]


def add_fields(f, endpoint, cat, rx, limit=14):
    for p, e in cat.find(rx)[:limit]:
        f.fields.append((endpoint, p, f"{e['nonnull']}/{cat.records}", short(e["ex"], 50) if e["ex"] is not None else "null"))


# --------------------------------------------------------------------------- rapport

MAPPING = [
    ("Dernier check-in", "checkin", "V1", "Comparer la valeur à « Dernier check-in » dans la fiche de l'hôte (interface)."),
    ("Profil de paquets (fraîcheur)", "profile", "V4", "Aucun champ sans nom explicite ; valider qu'il avance seulement quand le profil est envoyé."),
    ("Errata security installables", "errata_counts", "V3", "Pour 2 VMs, comparer les compteurs aux listes d'errata filtrées « installable » dans l'interface."),
    ("Errata applicables non installables", "errata_detail", "V3", "Même comparaison avec « applicable » ; l'outil ne déduit la différence que si V3 est CONFIRMÉ."),
    ("Paquets upgradables", "pkg_counts", "V1", "Comparer à « Paquets » > « Mettables à jour » dans la fiche de l'hôte."),
    ("Sévérité d'un erratum", "severity", "V5", "Ne jamais déduire une sévérité absente."),
    ("CV et environnement d'une VM", "cv_host", "V6", "Vérifier avec 2 VMs que la CV affichée correspond à l'interface."),
    ("Version déployée par environnement", "cv_env", "V6/V7", "Contrôler dans Content > Content Views."),
    ("Date de publication d'une version", "cv_date", "V7", "Vérifier que created_at correspond à la date de publication affichée."),
    ("Ordre de promotion des environnements", "lce_order", "V7", "Comparer au chemin de promotion de l'interface."),
    ("CV composite / rolling / à republier", "cv_publish", "V7", "Contrôler sur une CV de chaque type."),
    ("Dernière synchronisation et résultat", "sync", "V8", "Comparer à Content > Sync Status pour 2 dépôts."),
    ("Contenu changé depuis la publication", "sync_change", "V8", "Aucun indicateur direct : valeur à ne pas interpréter sans validation."),
    ("Traces (reboot, services)", "traces", "V13", "Comparer à l'onglet Traces de la fiche d'un hôte."),
    ("Build", "build", "V14", "Aucun début de build déduit d'un horodatage générique."),
    ("Statut global Foreman", "global_status", "V1", "Comparer au statut affiché dans la liste des hôtes."),
    ("Content source (capsule)", "content_source", "V1", "Vérifier avec un hôte rattaché à une capsule si possible."),
    ("Tâches en erreur ou en pause", "tasks", "V9", "Comparer au nombre dans Surveiller > Tâches."),
    ("Santé des services", "ping", "V10", "Comparer à la sortie de hammer ping ou à l'interface."),
    ("Espace disque de Pulp", "disk", "V11", "Non exposé sauf découverte : à mesurer en dehors de l'API."),
    ("Recherche côté API (filtres, comptage)", "search", "V2/V12", "Comparer un comptage à l'interface avec le même filtre."),
]


def render_report(d, redacted):
    out = []
    w = out.append
    now = dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    w("# Rapport de validation technique de l'API Katello")
    w("")
    w(f"- Généré le {now} par katello_api_discovery {VERSION}")
    w(f"- Serveur : {d.c.base}, organisation : {d.org_name} (id {d.org_id})")
    w(f"- Versions annoncées : Foreman {d.versions.get('foreman')}, Katello {d.versions.get('katello')}")
    w(f"- Appels GET effectués : {d.c.n} (aucune autre méthode HTTP n'est émise par l'outil)")
    w(f"- Redaction des identités : {'oui (best effort, relire avant partage)' if redacted else 'non : les fichiers bruts contiennent des noms d’hôtes'}")
    w("- Limite : l'outil constate l'existence et la cohérence des données ; il ne prouve jamais leur sens métier.")
    w("")
    w("## 1. Synthèse")
    w("")
    w("| Réf. | Point | Résultat | Cause ou restriction |")
    w("| --- | --- | --- | --- |")
    for ref in sorted(d.findings, key=lambda r: int(r[1:])):
        f = d.findings[ref]
        if d.want(ref) or d.only is not None:
            w(f"| {ref} | {md(f.title)} | {f.result} | {md(f.cause) or '-'} |")
    w("")
    w("## 2. Détail par point")
    for ref in sorted(d.findings, key=lambda r: int(r[1:])):
        f = d.findings[ref]
        w("")
        w(f"### {ref} - {f.title}")
        w("")
        w(f"**Résultat : {f.result}**" + (f" - {f.cause}" if f.cause else ""))
        w("")
        if f.endpoints:
            w("Endpoints testés :")
            w("")
            w("| Endpoint | Paramètres | HTTP | Durée (ms) | Méthodes déclarées par Apipie |")
            w("| --- | --- | --- | --- | --- |")
            seen = set()
            for path, params, status, kind, ms, meth in f.endpoints:
                key = (path, json.dumps(params, sort_keys=True))
                if key in seen:
                    continue
                seen.add(key)
                w(f"| {md(path)} | {md(json.dumps(params, ensure_ascii=False)) if params else '-'} | {status or CAUSES['network']} | {ms} | {md(meth) or '-'} |")
            w("")
        if f.checks:
            w("| Vérification | Résultat | Détail |")
            w("| --- | --- | --- |")
            for label, ok, detail in f.checks:
                w(f"| {md(label)} | {ok} | {md(detail)} |")
            w("")
        for title, headers, rows in f.tables:
            w(f"**{title}**")
            w("")
            w("| " + " | ".join(headers) + " |")
            w("| " + " | ".join("---" for _ in headers) + " |")
            for r in rows:
                w("| " + " | ".join(md(c) for c in r) + " |")
            w("")
        if f.fields:
            w("Champs relevés (présence non nulle / enregistrements, exemple) :")
            w("")
            w("| Endpoint | Champ | Présence | Exemple |")
            w("| --- | --- | --- | --- |")
            for ep, p, pres, ex in f.fields[:40]:
                w(f"| {md(ep)} | {md(p)} | {pres} | {md(ex)} |")
            w("")
        for n in f.notes:
            w(f"- {n}")
    w("")
    w("## 3. Mapping proposé : champs observés vers indicateurs de katello-inspector")
    w("")
    w("Le mapping liste des **candidats observés**. La colonne « Sémantique » indique ce qui doit être validé à la main : "
      "aucun champ n'est considéré comme équivalent à un indicateur tant que ce contrôle n'est pas fait.")
    w("")
    w("| Indicateur | Champs candidats (endpoint : chemin = exemple) | Points | Sémantique à valider |")
    w("| --- | --- | --- | --- |")
    for label, key, pts, sem in MAPPING:
        cands = d.paths.get(key, [])
        txt = "; ".join(f"{ep} : {p} = {ex}" for ep, p, ex in cands[:3]) or "**aucun champ observé** : indicateur UNKNOWN en v1"
        w(f"| {md(label)} | {md(txt)} | {pts} | {md(sem)} |")
    w("")
    w("## 4. Données nécessitant plusieurs appels")
    w("")
    for line in multi_call_notes(d):
        w(f"- {line}")
    w("")
    w("## 5. Estimation du nombre d'appels par sous-commande")
    w("")
    hdr, rows, notes = estimates(d)
    w("| " + " | ".join(hdr) + " |")
    w("| " + " | ".join("---" for _ in hdr) + " |")
    for r in rows:
        w("| " + " | ".join(md(c) for c in r) + " |")
    w("")
    for n in notes:
        w(f"- {n}")
    w("")
    w("## 6. Appels effectués")
    w("")
    w("| N° | Chemin | Paramètres | HTTP | ms |")
    w("| --- | --- | --- | --- | --- |")
    for n, path, params, status, kind, ms in d.c.calls:
        w(f"| {n} | {md(path)} | {md(json.dumps(params, ensure_ascii=False)) if params else '-'} | {status or kind} | {ms} |")
    return "\n".join(out) + "\n"


def multi_call_notes(d):
    L = []
    miss = d.flags.get("v1_missing_in_list")
    if d.flags.get("v1_all_in_list") is False:
        if miss and d.flags.get("v1_all_in_show"):
            L.append("Absents de la liste des hôtes mais présents dans la fiche : " + ", ".join(miss) +
                     " → un appel /api/hosts/:id par VM (non retenu pour summary, list et content).")
        elif miss:
            L.append("Absents de la liste et de la fiche : " + ", ".join(miss) + " → indicateurs UNKNOWN.")
    if d.flags.get("v13_per_host"):
        L.append(f"Traces : endpoint par hôte ({d.flags['v13_per_host']}) → un appel par VM, sauf champ dans la liste.")
    if d.flags.get("v3_endpoint"):
        L.append(f"Errata détaillés : {d.flags['v3_endpoint']} → un à trois appels par VM (défaut, applicable, installable) ; "
                 "à réserver à `host`.")
    L.append("CV, versions, environnements : trois endpoints paginés distincts, et la date de publication vient de "
             "l'endpoint des versions, pas de la liste des hôtes.")
    L.append("Dépôts, produits et plans de sync : trois endpoints paginés distincts.")
    L.append("Tâches : une recherche par compteur, plus une page récente pour identifier les libellés.")
    if d.flags.get("v6_multi_cv_hosts"):
        L.append(f"{d.flags['v6_multi_cv_hosts']} hôte(s) de l'échantillon ont plusieurs CV : le modèle « une CV par VM » ne suffit pas.")
    return L


def estimates(d):
    ps = d.page_size
    pages = lambda n: max(1, math.ceil(n / ps)) if isinstance(n, int) else None
    T = d.totals
    N = T.get("hosts")
    pg = {k: pages(T.get(k)) for k in ("hosts", "environments", "content_views", "cv_versions", "repos", "products")}
    num = lambda x: x if x is not None else "n.d."
    add = lambda *xs: sum(xs) if all(isinstance(x, int) for x in xs) else None
    cv_block = add(*(pg[k] or 0 for k in ("environments", "content_views", "cv_versions"))) if all(pg[k] for k in ("environments", "content_views", "cv_versions")) else None
    sum_a = add(3, 3, 5, cv_block, pg["repos"]) if cv_block and pg["repos"] else None
    sum_b = add(3, 3, pg["hosts"], cv_block, pg["repos"]) if pg["hosts"] and cv_block and pg["repos"] else None
    lst = add(pg["hosts"], cv_block) if pg["hosts"] and cv_block else None
    cont = add(pg["products"] or 0, pg["repos"] or 0, cv_block or 0, pg["hosts"] or 0) if pg["hosts"] and cv_block and pg["repos"] and pg["products"] else None
    host_calls = 1 + (3 if d.flags.get("v3_endpoint") else 0) + (1 if d.flags.get("v13_per_host") else 0) + 1
    avg = lambda tag: (sum(d.c.timing[tag]) / len(d.c.timing[tag])) if d.c.timing.get(tag) else None
    page_t = avg("hosts_list") or 0
    other_t = (sum(sum(v) for v in d.c.timing.values()) / max(1, sum(len(v) for v in d.c.timing.values())))
    def dur(calls_pages, calls_other):
        if calls_pages is None or calls_other is None:
            return "n.d."
        return f"≈ {calls_pages * page_t + calls_other * other_t:.1f} s"
    hdr = ["Sous-commande", "Appels estimés", "Détail", "Durée indicative (mesures de cette exécution)"]
    rows = [
        ["summary (comptages filtrés, si V2 et V12 CONFIRMÉS)", num(sum_a),
         "3 statut/ping + 3 tâches + 5 comptages + CV/versions/environnements + dépôts", dur(0, sum_a)],
        ["summary (repli : liste complète des hôtes)", num(sum_b),
         "3 statut/ping + 3 tâches + pages d'hôtes + CV/versions/environnements + dépôts", dur(pg["hosts"], add(3, 3, cv_block or 0, pg["repos"] or 0))],
        ["summary --by-lce", "comme summary (repli)", "nécessite les compteurs par hôte : la liste complète est requise", "-"],
        ["list", num(lst), "pages d'hôtes + CV/versions/environnements", dur(pg["hosts"], cv_block)],
        ["content", num(cont), "produits + dépôts + CV/versions/environnements + pages d'hôtes pour compter les VMs par version", dur(pg["hosts"], add(pg["products"] or 0, pg["repos"] or 0, cv_block or 0))],
        ["host", host_calls, "fiche + errata (défaut/applicable/installable) + traces + versions du couple CV/LCE", dur(0, host_calls)],
    ]
    notes = [f"Base de calcul : {num(N)} hôte(s), page de {ps}, soit {num(pg['hosts'])} page(s) d'hôtes.",
             "Si V1 n'est pas CONFIRMÉ, ajouter autant d'appels /api/hosts/:id que de VMs pour récupérer les champs "
             "absents de la liste : non retenu dans le cadrage."]
    if d.flags.get("v12_cap"):
        notes.append(f"Un plafond de per_page a été observé ({d.flags['v12_cap']} lignes) : recalculer avec cette taille de page.")
    notes.append("Les durées extrapolent les temps mesurés ici sur une seule exécution : ordre de grandeur, pas une mesure de charge.")
    return hdr, rows, notes


def render_console(d):
    lines = ["", "Synthèse", "-" * 78]
    for ref in sorted(d.findings, key=lambda r: int(r[1:])):
        f = d.findings[ref]
        lines.append(f"{ref:<4} {f.result:<24} {f.title[:34]:<34} {f.cause[:60]}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- main

def read_token(args):
    path = args.token_file or os.environ.get("KATELLO_DISCOVERY_TOKEN_FILE")
    if path:
        try:
            st = os.stat(path)
            if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                print(f"! {path} est lisible par d'autres utilisateurs : chmod 600 recommandé.", file=sys.stderr)
            with open(path, encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError as e:
            sys.exit(f"Lecture du fichier de jeton impossible : {e}")
    tok = os.environ.get("KATELLO_DISCOVERY_TOKEN")
    if tok:
        return tok.strip()
    sys.exit("Aucun jeton : utiliser --token-file ou KATELLO_DISCOVERY_TOKEN_FILE (ou KATELLO_DISCOVERY_TOKEN).")


def build_redactor(c):
    state = {"rx": None, "map": {}}

    def setup(names):
        names = sorted({n for n in names if isinstance(n, str) and len(n) > 2}, key=len, reverse=True)
        state["map"] = {n: f"host-{i + 1:04d}" for i, n in enumerate(names)}
        state["rx"] = re.compile("|".join(re.escape(n) for n in names)) if names else None

    def red(s):
        if state["rx"]:
            s = state["rx"].sub(lambda m: state["map"][m.group(0)], s)
        return RE_MAIL.sub("user@redacted", RE_MAC.sub("00:00:00:00:00:00", RE_IPV4.sub(lambda m: m.group(0) if m.group(0) in c.keep else "0.0.0.0", s)))

    c.keep = c.keep if hasattr(c, "keep") else set()
    c.redactor = red
    return setup


def main(argv=None):
    ap = argparse.ArgumentParser(description="Découverte de l'API Katello/Foreman (GET uniquement) pour valider V1 à V17.")
    ap.add_argument("--url", default=os.environ.get("KATELLO_DISCOVERY_URL"), help="https://katello.example.com")
    ap.add_argument("--org", default=os.environ.get("KATELLO_DISCOVERY_ORG"), help="nom de l'organisation")
    ap.add_argument("--org-id", type=int, default=None, help="identifiant d'organisation (si la résolution par nom est refusée)")
    ap.add_argument("--user", default=os.environ.get("KATELLO_DISCOVERY_USER"), help="compte en lecture seule")
    ap.add_argument("--token-file", default=None, help="fichier contenant le jeton (chmod 600)")
    ap.add_argument("--ca-file", default=None, help="bundle de CA interne")
    ap.add_argument("--insecure", action="store_true", help="désactive la validation TLS (explicite, déconseillé)")
    ap.add_argument("--allow-http", action="store_true", help="autorise http:// vers un hôte distant (jeton en clair !)")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--page-size", type=int, default=100)
    ap.add_argument("--sample-hosts", type=int, default=4, help="nombre d'hôtes examinés en détail")
    ap.add_argument("--probe-large-page", action="store_true", help="teste aussi per_page=1000 et 5000 (réponses volumineuses)")
    ap.add_argument("--only", default=None, help="liste de points, par exemple V1,V3")
    ap.add_argument("--out", default=None, help="répertoire de sortie (défaut : ./discovery-AAAAMMJJ-HHMMSS)")
    ap.add_argument("--redact", action="store_true", help="masque noms d'hôtes, IP, MAC, e-mails dans les fichiers (best effort)")
    ap.add_argument("--no-raw", action="store_true", help="n'exporte pas les réponses JSON brutes")
    args = ap.parse_args(argv)
    for name in ("url", "org", "user"):
        if not getattr(args, name):
            ap.error(f"--{name} est requis (ou KATELLO_DISCOVERY_{name.upper()})")
    parsed = urllib.parse.urlparse(args.url)
    if parsed.scheme not in ("https", "http") or not parsed.netloc:
        ap.error("--url doit être de la forme https://hote")
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1") and not args.allow_http:
        ap.error("http:// refusé hors localhost (le jeton circulerait en clair) ; utiliser https ou --allow-http")
    token = read_token(args)
    if args.insecure:
        print("! Validation TLS désactivée.", file=sys.stderr)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx = ssl.create_default_context(cafile=args.ca_file) if args.ca_file else ssl.create_default_context()
    out = args.out or "discovery-" + dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    raw = None if args.no_raw else os.path.join(out, "raw")
    os.makedirs(raw or out, mode=0o700, exist_ok=True)
    client = Client(args.url, args.user, token, args.timeout, ctx, raw)
    d = Discovery(client, args)
    if args.redact:
        d.redactor_setup = build_redactor(client)
    started = time.time()
    d.run()
    report = render_report(d, args.redact)
    if args.redact:
        report = client.redactor(report)
    if args.redact and raw:
        for fn in os.listdir(raw):  # les noms d'hôtes ne sont connus qu'après le premier appel : repasse finale
            fp = os.path.join(raw, fn)
            with open(fp, encoding="utf-8") as fh:
                txt = fh.read()
            with open(fp, "w", encoding="utf-8") as fh:
                fh.write(client.redactor(txt))
    with open(os.path.join(out, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(report)
    summary = {"tool_version": VERSION, "url": args.url, "org": args.org, "calls": client.n,
               "versions": d.versions, "seconds": round(time.time() - started, 1),
               "results": {r: {"title": f.title, "result": f.result, "cause": f.cause} for r, f in sorted(d.findings.items())}}
    with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(client.sanitize(summary), fh, ensure_ascii=False, indent=1)
    print(render_console(d))
    print(f"\nRapport : {os.path.join(out, 'report.md')}  |  réponses brutes : {raw or 'non exportées'}  |  {client.n} appels GET")
    return 0


if __name__ == "__main__":
    sys.exit(main())
