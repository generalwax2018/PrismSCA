"""OSV (Open Source Vulnerabilities) integration.

Every lookup result carries an explicit status so that a failed lookup is never
mistaken for a clean package:

    {"status": "ok",      "vulns": [<full OSV vuln records>]}
    {"status": "error",   "error": "<reason>"}
    {"status": "skipped", "reason": "<reason>"}   # e.g. version not pinned
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Iterable, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .inventory import Package

OSV_BASE = "https://api.osv.dev/v1"
CACHE_DIR = Path.home() / ".prismsca" / "osv_cache"
DEFAULT_CACHE_TTL = 24 * 3600  # seconds
BATCH_SIZE = 1000  # OSV querybatch limit
TIMEOUT = 30

ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "cargo": "crates.io",
    "go": "Go",
}


def _session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1.0,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "POST"}),
    )
    s.mount("https://", HTTPAdapter(max_retries=retry))
    return s


# --------------------------------------------------------------------------- cache


def _cache_file(kind: str, ident: str) -> Path:
    digest = hashlib.sha256(ident.encode("utf-8")).hexdigest()[:32]
    return CACHE_DIR / kind / f"{digest}.json"


def _cache_get(kind: str, ident: str, ttl: Optional[float]) -> Optional[dict]:
    if ttl is None:
        return None
    f = _cache_file(kind, ident)
    try:
        if time.time() - f.stat().st_mtime > ttl:
            return None
        return json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _cache_put(kind: str, ident: str, data: dict) -> None:
    f = _cache_file(kind, ident)
    try:
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass  # cache is best effort


# --------------------------------------------------------------------------- queries


def _query_for(p: Package) -> dict:
    return {
        "version": p.version,
        "package": {"name": p.name, "ecosystem": ECOSYSTEMS.get(p.ecosystem.lower(), p.ecosystem)},
    }


def _batch_vuln_ids(session: requests.Session, queries: list[dict]) -> list[list[str]]:
    """Return the vuln ids for each query, following per-query pagination."""
    out: list[list[str]] = [[] for _ in queries]
    pending = list(range(len(queries)))
    tokens: dict[int, str] = {}
    while pending:
        body = {"queries": [dict(queries[i], **({"page_token": tokens[i]} if i in tokens else {})) for i in pending]}
        r = session.post(f"{OSV_BASE}/querybatch", json=body, timeout=TIMEOUT)
        r.raise_for_status()
        results = r.json().get("results", [])
        if len(results) != len(pending):
            raise ValueError(f"OSV returned {len(results)} results for {len(pending)} queries")
        next_pending = []
        for i, res in zip(pending, results):
            out[i].extend(v["id"] for v in res.get("vulns", []) if "id" in v)
            if res.get("next_page_token"):
                tokens[i] = res["next_page_token"]
                next_pending.append(i)
        pending = next_pending
    return out


def _vuln_details(session: requests.Session, vuln_id: str, ttl: Optional[float]) -> dict:
    cached = _cache_get("vulns", vuln_id, ttl)
    if cached is not None:
        return cached
    r = session.get(f"{OSV_BASE}/vulns/{vuln_id}", timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    if ttl is not None:
        _cache_put("vulns", vuln_id, data)
    return data


def query_osv_batch(
    packages: Iterable[Package],
    cache_ttl: Optional[float] = DEFAULT_CACHE_TTL,
    session: Optional[requests.Session] = None,
) -> dict[str, dict]:
    """Look up many packages at once. Returns {package.key: result} (see module docstring).

    Pass cache_ttl=None to bypass the cache.
    """
    session = session or _session()
    results: dict[str, dict] = {}
    to_query: list[Package] = []

    for p in packages:
        if p.key in results:
            continue
        if not p.is_pinned:
            results[p.key] = {"status": "skipped", "reason": f"version not pinned ({p.version})"}
            continue
        cached = _cache_get("queries", p.key, cache_ttl)
        if cached is not None:
            results[p.key] = cached
        else:
            to_query.append(p)
            results[p.key] = {"status": "error", "error": "not queried"}  # placeholder

    for start in range(0, len(to_query), BATCH_SIZE):
        chunk = to_query[start : start + BATCH_SIZE]
        try:
            ids_per_pkg = _batch_vuln_ids(session, [_query_for(p) for p in chunk])
        except (requests.RequestException, ValueError, KeyError) as e:
            for p in chunk:
                results[p.key] = {"status": "error", "error": f"OSV query failed: {e}"}
            continue

        for p, ids in zip(chunk, ids_per_pkg):
            try:
                vulns = [_vuln_details(session, vid, cache_ttl) for vid in ids]
            except (requests.RequestException, ValueError) as e:
                results[p.key] = {"status": "error", "error": f"OSV vuln fetch failed: {e}"}
                continue
            res = {"status": "ok", "vulns": vulns}
            results[p.key] = res
            if cache_ttl is not None:
                _cache_put("queries", p.key, res)

    return results


def query_osv(package: Package, use_cache: bool = True) -> dict:
    """Query OSV for a single package (convenience wrapper around query_osv_batch)."""
    ttl = DEFAULT_CACHE_TTL if use_cache else None
    return query_osv_batch([package], cache_ttl=ttl)[package.key]


# --------------------------------------------------------------------------- summary


def summarize_vulns(osv_result: Optional[dict]) -> dict:
    """Compact summary of a lookup result. `count` is None unless the lookup succeeded."""
    if osv_result is None:
        return {"status": "not_queried", "count": None, "ids": [], "severities": []}
    status = osv_result.get("status", "ok")  # a raw OSV response ({} or {"vulns": [...]}) is "ok"
    if status != "ok":
        return {
            "status": status,
            "count": None,
            "ids": [],
            "severities": [],
            "detail": osv_result.get("error") or osv_result.get("reason"),
        }

    vulns = osv_result.get("vulns", [])
    severities = []
    for v in vulns:
        entry: dict = {"id": v.get("id", "")}
        label = (v.get("database_specific") or {}).get("severity")
        if label:
            entry["label"] = str(label).upper()
        vectors = [s.get("score") for s in v.get("severity", []) if s.get("score")]
        if vectors:
            entry["vectors"] = vectors
        severities.append(entry)
    return {
        "status": "ok",
        "count": len(vulns),
        "ids": [v.get("id", "") for v in vulns],
        "aliases": sorted({a for v in vulns for a in v.get("aliases", [])}),
        "severities": severities,
    }
