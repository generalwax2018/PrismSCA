"""Generate structured handoff for PrismRedline."""

from .inventory import ProjectInventory


def generate_handoff(inventory: ProjectInventory, signals: dict) -> dict:
    """Produce a JSON-serializable handoff document for PrismRedline."""
    return {
        "tool": "PrismSCA",
        "version": "0.1.0",
        "project": inventory.project_path,
        "packages": [
            {
                "name": p.name,
                "version": p.version,
                "ecosystem": p.ecosystem,
                "signals": signals.get(p.name, {}),
            }
            for p in inventory.packages
        ],
        "notes": "Handoff for deeper behavioral / dynamic analysis in PrismRedline",
    }
