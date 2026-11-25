"""Generate structured handoff for PrismRedline.

Handoff document (schema_version 1):

    tool, tool_version, schema_version, generated_at, project_path, package_count,
    warnings: [str],
    packages: [{name, version, ecosystem, is_direct, source, path,
                signals: {<flag>: bool, ..., risk_score: int},
                osv: null | {status: ok|error|skipped|not_queried, count: int|null,
                             ids, aliases, severities, detail?}}]

`osv` is null when OSV was skipped for the whole run (--skip-osv). A package whose
lookup failed has osv.status == "error" and count == null — never count == 0.
Bump SCHEMA_VERSION on any breaking change to this shape.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from . import __version__
from .inventory import ProjectInventory
from .osv import summarize_vulns

SCHEMA_VERSION = 1


def generate_handoff(
    inventory: ProjectInventory,
    signals: dict,
    osv_results: Optional[dict] = None,
) -> dict:
    """Produce a JSON-serializable handoff document for PrismRedline."""
    packages_out = []
    for p in inventory.packages:
        entry = {
            "name": p.name,
            "version": p.version,
            "ecosystem": p.ecosystem,
            "is_direct": p.is_direct,
            "source": p.source,
            "path": p.path,
            "signals": signals.get(p.key, {}),
            "osv": None,
        }
        if osv_results is not None:
            entry["osv"] = summarize_vulns(osv_results.get(p.key))
        packages_out.append(entry)

    return {
        "tool": "PrismSCA",
        "tool_version": __version__,
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_path": inventory.project_path,
        "package_count": len(packages_out),
        "warnings": list(inventory.warnings),
        "packages": packages_out,
        "notes": "Structured handoff for deeper behavioral / dynamic analysis in PrismRedline. "
        "High risk_score or OSV findings should be prioritized; osv.status 'error' means unknown, not clean.",
    }


def write_handoff(handoff: dict, path: str) -> None:
    """Write handoff JSON to disk."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(handoff, f, indent=2)
