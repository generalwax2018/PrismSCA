"""OSV (Open Source Vulnerabilities) integration."""

import requests
from typing import Optional

OSV_API = "https://api.osv.dev/v1/query"


def query_osv(ecosystem: str, name: str, version: str) -> Optional[dict]:
    """Query OSV for a specific package version. Returns raw response or None."""
    payload = {
        "version": version,
        "package": {
            "name": name,
            "ecosystem": ecosystem.upper(),
        },
    }
    try:
        r = requests.post(OSV_API, json=payload, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None
