"""Generate structured handoff for PrismRedline."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from .inventory import ProjectInventory, Package
from .osv import summarize_vulns


def generate_handoff(
    inventory: ProjectInventory,
    signals: dict,
    osv_results: Optional[dict] = None,
) -> dict:
    """Produce a JSON-serializable handoff document for PrismRedline."""
    packages_out = []
    for p in inventory.packages:
        key = f"{p.ecosystem}:{p.name}@{p.version}"
        entry = {
            "name": p.name,
            "version": p.version,
            "ecosystem": p.ecosystem,
            "is_direct": p.is_direct,
            "source": p.source,
            "signals": signals.get(key, {}),
            "osv": None,
        }
        if osv_results and key in osv_results:
            entry["osv"] = summarize_vulns(osv_results[key])
        packages_out.append(entry)

    return {
        "tool": "PrismSCA",
        "version": "0.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_path": inventory.project_path,
        "package_count": len(packages_out),
        "packages": packages_out,
        "notes": "Structured handoff for deeper behavioral / dynamic analysis in PrismRedline. High risk_score or OSV findings should be prioritized.",
    }


def write_handoff(handoff: dict, path: str) -> None:
    """Write handoff JSON to disk."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(handoff, f, indent=2)
