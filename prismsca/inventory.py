"""Third-party library inventory."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Package:
    name: str
    version: str
    ecosystem: str  # pypi, npm, cargo, go, maven, etc.
    source: Optional[str] = None
    path: Optional[str] = None  # how it was introduced
    is_direct: bool = False
    metadata: dict = field(default_factory=dict)


@dataclass
class ProjectInventory:
    project_path: str
    packages: list[Package] = field(default_factory=list)


def scan_project(path: str) -> ProjectInventory:
    """Scan a project directory and return its inventory. Not yet implemented."""
    raise NotImplementedError("Inventory scanning coming soon")
