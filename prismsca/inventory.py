"""Third-party library inventory — multi-ecosystem scanner."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore


@dataclass
class Package:
    name: str
    version: str
    ecosystem: str  # npm, pypi, cargo, go, etc.
    source: Optional[str] = None
    path: Optional[str] = None
    is_direct: bool = False
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ProjectInventory:
    project_path: str
    packages: list[Package] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "project_path": self.project_path,
            "packages": [p.to_dict() for p in self.packages],
        }


def _read_json(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _scan_npm(lock_path: Path, root: Path) -> list[Package]:
    data = _read_json(lock_path)
    if not data:
        return []
    pkgs: list[Package] = []
    # package-lock v2/v3
    packages = data.get("packages") or {}
    for key, info in packages.items():
        if not key or key == "":
            continue
        name = info.get("name") or key.split("node_modules/")[-1]
        version = info.get("version", "unknown")
        is_direct = not key.startswith("node_modules/") or key.count("node_modules/") == 1
        source = info.get("resolved")
        pkgs.append(
            Package(
                name=name,
                version=version,
                ecosystem="npm",
                source=source,
                path=str(lock_path.relative_to(root)),
                is_direct=is_direct,
                metadata={"integrity": info.get("integrity"), "hasInstallScript": info.get("hasInstallScript", False)},
            )
        )
    return pkgs


def _scan_poetry(lock_path: Path, root: Path) -> list[Package]:
    try:
        data = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except Exception:
        return []
    pkgs: list[Package] = []
    for pkg in data.get("package", []):
        name = pkg.get("name", "")
        version = pkg.get("version", "unknown")
        category = pkg.get("category", "main")
        is_direct = category == "main"
        source = None
        if "source" in pkg:
            source = pkg["source"].get("url") or pkg["source"].get("reference")
        pkgs.append(
            Package(
                name=name,
                version=version,
                ecosystem="pypi",
                source=source,
                path=str(lock_path.relative_to(root)),
                is_direct=is_direct,
                metadata={"category": category},
            )
        )
    return pkgs


def _scan_cargo(lock_path: Path, root: Path) -> list[Package]:
    try:
        data = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except Exception:
        return []
    pkgs: list[Package] = []
    for pkg in data.get("package", []):
        name = pkg.get("name", "")
        version = pkg.get("version", "unknown")
        source = pkg.get("source")
        pkgs.append(
            Package(
                name=name,
                version=version,
                ecosystem="cargo",
                source=source,
                path=str(lock_path.relative_to(root)),
                is_direct=False,  # Cargo.lock does not mark direct; refined later if Cargo.toml present
                metadata={},
            )
        )
    return pkgs


def _scan_go_mod(mod_path: Path, root: Path) -> list[Package]:
    text = mod_path.read_text(encoding="utf-8", errors="ignore")
    pkgs: list[Package] = []
    # Simple require block parser
    in_require = False
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")"::
            in_require = False
            continue
        if in_require or line.startswith("require "):
            parts = line.replace("require ", "").split()
            if len(parts) >= 2:
                name, version = parts[0], parts[1]
                is_direct = not line.endswith("// indirect")
                pkgs.append(
                    Package(
                        name=name,
                        version=version.lstrip("v"),
                        ecosystem="go",
                        source=None,
                        path=str(mod_path.relative_to(root)),
                        is_direct=is_direct,
                        metadata={},
                    )
                )
    return pkgs


def _scan_requirements(req_path: Path, root: Path) -> list[Package]:
    pkgs: list[Package] = []
    for line in req_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # name==version or name>=version etc.
        m = re.match(r"^([A-Za-z0-9_.-]+)([=<>!~].*)?$", line)
        if m:
            name = m.group(1)
            version = m.group(2) or "*"
            pkgs.append(
                Package(
                    name=name,
                    version=version.lstrip("=<>!~"),
                    ecosystem="pypi",
                    source=None,
                    path=str(req_path.relative_to(root)),
                    is_direct=True,
                    metadata={"raw": line},
                )
            )
    return pkgs


def scan_project(path: str) -> ProjectInventory:
    """Scan a project directory for supported lockfiles / manifests."""
    root = Path(path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {path}")

    inv = ProjectInventory(project_path=str(root))
    seen: set[tuple[str, str, str]] = set()

    def add(pkgs: list[Package]) -> None:
        for p in pkgs:
            key = (p.ecosystem, p.name, p.version)
            if key not in seen:
                seen.add(key)
                inv.packages.append(p)

    # npm
    for lock in root.rglob("package-lock.json"):
        add(_scan_npm(lock, root))
    for lock in root.rglob("npm-shrinkwrap.json"):
        add(_scan_npm(lock, root))

    # Poetry
    for lock in root.rglob("poetry.lock"):
        add(_scan_poetry(lock, root))

    # Cargo
    for lock in root.rglob("Cargo.lock"):
        add(_scan_cargo(lock, root))

    # Go
    for mod in root.rglob("go.mod"):
        add(_scan_go_mod(mod, root))

    # requirements.txt
    for req in root.rglob("requirements*.txt"):
        add(_scan_requirements(req, root))

    # uv.lock (simple JSON-like)
    for lock in root.rglob("uv.lock"):
        data = _read_json(lock)
        if data and "package" in data:
            for pkg in data["package"]:
                add([
                    Package(
                        name=pkg.get("name", ""),
                        version=pkg.get("version", "unknown"),
                        ecosystem="pypi",
                        source=pkg.get("source", {}).get("url") if isinstance(pkg.get("source"), dict) else None,
                        path=str(lock.relative_to(root)),
                        is_direct=False,
                        metadata={},
                    )
                ])

    return inv
