"""OSV (Open Source Vulnerabilities) integration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import requests

from .inventory import Package

OSV_API = "https://api.osv.dev/v1/query"
CACHE_DIR = Path.home() / ".prismsca" / "osv_cache"


def _cache_path(ecosystem: str, name: str, version: str) -> Path:
    safe = f"{ecosystem}_{name}_{version}".replace("/", "_").replace("@", "_")
    return CACHE_DIR / f"{safe}.json"


def query_osv(package: Package, use_cache: bool = True) -> Optional[dict]:
    """Query OSV for vulnerabilities affecting this package version."""
    eco_map = {
        "npm": "npm",
        "pypi": "PyPI",
        "cargo": "crates.io",
        "go": "Go",
    }
    ecosystem = eco_map.get(package.ecosystem.lower(), package.ecosystem)

    cache_file = _cache_path(ecosystem, package.name, package.version)
    if use_cache and cache_file.exists():
        try:
            return json.loads(cache_file.read_text())
        except Exception:
            pass

    payload = {
        "version": package.version,
        "package": {"name": package.name, "ecosystem": ecosystem},
    }
    try:
        r = requests.post(OSV_API, json=payload, timeout=20)
        r.raise_for_status()
        data = r.json()
        if use_cache:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(data, indent=2))
        return data
    except Exception:
        return None


def summarize_vulns(osv_result: Optional[dict]) -> dict:
    """Extract a compact summary from an OSV response."""
    if not osv_result or "vulns" not in osv_result:
        return {"count": 0, "ids": [], "severities": []}
    vulns = osv_result["vulns"]
    ids = [v.get("id", "") for v in vulns]
    sevs = []
    for v in vulns:
        for sev in v.get("severity", []):
            sevs.append(sev.get("score", ""))
    return {"count": len(vulns), "ids": ids, "severities": sevs}
