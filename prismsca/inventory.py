"""Third-party library inventory — multi-ecosystem scanner."""

from __future__ import annotations

import fnmatch
import json
import os
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable, Optional

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib  # type: ignore

from packaging.requirements import InvalidRequirement, Requirement

# Directories that hold installed/vendored/build output rather than project manifests.
SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        ".tox",
        ".nox",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        "site-packages",
        "target",  # cargo build output
        "dist",
        "build",
        "vendor",
    }
)


@dataclass
class Package:
    name: str
    version: str
    ecosystem: str  # npm, pypi, cargo, go
    source: Optional[str] = None
    path: Optional[str] = None
    is_direct: bool = False
    metadata: dict = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"

    @property
    def is_pinned(self) -> bool:
        """True when `version` is one concrete version (safe to look up in OSV)."""
        v = self.version or ""
        if v in ("*", "latest", "unknown", ""):
            return False
        return not any(c in v for c in "<>=!~^*, ")

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ProjectInventory:
    project_path: str
    packages: list[Package] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "project_path": self.project_path,
            "packages": [p.to_dict() for p in self.packages],
            "warnings": list(self.warnings),
        }


class LockfileError(Exception):
    """A manifest or lockfile could not be parsed."""


# --------------------------------------------------------------------------- helpers


def _find(root: Path, patterns: Iterable[str]) -> list[Path]:
    """Walk `root`, skipping SKIP_DIRS, returning files matching any glob pattern."""
    patterns = tuple(patterns)
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            if any(fnmatch.fnmatch(fn, p) for p in patterns):
                found.append(Path(dirpath) / fn)
    return found


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as e:
        raise LockfileError(f"{path}: {e}") from e


def _load_toml(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as e:  # tomllib.TOMLDecodeError subclasses ValueError
        raise LockfileError(f"{path}: {e}") from e


def _norm_pypi(name: str) -> str:
    """PEP 503 normalized project name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


# --------------------------------------------------------------------------- npm


def _scan_npm(lock_path: Path, root: Path) -> list[Package]:
    data = _load_json(lock_path)
    packages = data.get("packages")
    if packages is None:
        raise LockfileError(
            f"{lock_path}: lockfileVersion {data.get('lockfileVersion', 1)} is not supported "
            "(regenerate with npm >= 7 for lockfileVersion 2/3)"
        )

    root_info = packages.get("", {})
    direct_names: set[str] = set()
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        direct_names.update((root_info.get(section) or {}).keys())

    pkgs: list[Package] = []
    for key, info in packages.items():
        # "" is the project itself; keys without node_modules/ are workspace members (first party);
        # link entries point at those workspace members.
        if not key or "node_modules/" not in key or info.get("link"):
            continue
        name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
        is_direct = key == f"node_modules/{name}" and name in direct_names
        pkgs.append(
            Package(
                name=name,
                version=info.get("version", "unknown"),
                ecosystem="npm",
                source=info.get("resolved"),
                path=_rel(lock_path, root),
                is_direct=is_direct,
                metadata={
                    "integrity": info.get("integrity") or False,
                    "hasInstallScript": bool(info.get("hasInstallScript", False)),
                    "dev": bool(info.get("dev", False)),
                },
            )
        )
    return pkgs


# --------------------------------------------------------------------------- python


def _pyproject_direct_names(pyproject: Path) -> Optional[set[str]]:
    """Direct dependency names declared in pyproject.toml (PEP 621 + Poetry), normalized."""
    if not pyproject.is_file():
        return None
    data = _load_toml(pyproject)
    names: set[str] = set()

    def add_reqs(reqs: Iterable[str]) -> None:
        for r in reqs:
            try:
                names.add(_norm_pypi(Requirement(r).name))
            except InvalidRequirement:
                continue

    project = data.get("project", {})
    add_reqs(project.get("dependencies", []))
    for group in (project.get("optional-dependencies") or {}).values():
        add_reqs(group)
    for group in (data.get("dependency-groups") or {}).values():  # PEP 735
        add_reqs(g for g in group if isinstance(g, str))

    poetry = data.get("tool", {}).get("poetry", {})
    sections = [poetry.get("dependencies", {}), poetry.get("dev-dependencies", {})]
    sections += [g.get("dependencies", {}) for g in (poetry.get("group") or {}).values()]
    for section in sections:
        names.update(_norm_pypi(n) for n in section if n.lower() != "python")

    uv = data.get("tool", {}).get("uv", {})
    add_reqs(uv.get("dev-dependencies", []))
    return names


def _scan_poetry(lock_path: Path, root: Path) -> list[Package]:
    data = _load_toml(lock_path)
    direct = _pyproject_direct_names(lock_path.parent / "pyproject.toml") or set()
    legacy_files = (data.get("metadata") or {}).get("files") or {}  # poetry < 1.5 layout

    pkgs: list[Package] = []
    for pkg in data.get("package", []):
        name = pkg.get("name", "")
        src = pkg.get("source") or {}
        source = None
        if src:
            source = src.get("url")
            if src.get("type") == "git" and source:
                source = f"git+{source}"
        files = pkg.get("files") or legacy_files.get(name) or []
        pkgs.append(
            Package(
                name=name,
                version=pkg.get("version", "unknown"),
                ecosystem="pypi",
                source=source,
                path=_rel(lock_path, root),
                is_direct=_norm_pypi(name) in direct,
                metadata={
                    "category": pkg.get("category"),
                    "integrity": any(f.get("hash") for f in files),
                },
            )
        )
    return pkgs


def _scan_uv(lock_path: Path, root: Path) -> list[Package]:
    data = _load_toml(lock_path)
    entries = data.get("package", [])

    # The project itself (and workspace members) are editable/virtual entries; their
    # dependency lists are the direct dependencies.
    direct: set[str] = set()
    for pkg in entries:
        src = pkg.get("source") or {}
        if "editable" in src or "virtual" in src:
            deps = list(pkg.get("dependencies", []))
            for group in (pkg.get("optional-dependencies") or {}).values():
                deps += group
            for group in (pkg.get("dev-dependencies") or {}).values():
                deps += group
            direct.update(_norm_pypi(d["name"]) for d in deps if "name" in d)

    pkgs: list[Package] = []
    for pkg in entries:
        src = pkg.get("source") or {}
        if "editable" in src or "virtual" in src or "path" in src or "directory" in src:
            continue  # first-party / local code
        if "git" in src:
            source = f"git+{src['git']}"
        else:
            source = src.get("registry") or src.get("url")
        hashes = [w.get("hash") for w in pkg.get("wheels", [])]
        if pkg.get("sdist"):
            hashes.append(pkg["sdist"].get("hash"))
        pkgs.append(
            Package(
                name=pkg.get("name", ""),
                version=pkg.get("version", "unknown"),
                ecosystem="pypi",
                source=source,
                path=_rel(lock_path, root),
                is_direct=_norm_pypi(pkg.get("name", "")) in direct,
                metadata={"integrity": any(hashes)},
            )
        )
    return pkgs


_EGG_RE = re.compile(r"#egg=([A-Za-z0-9_.\-]+)")


def _scan_requirements(req_path: Path, root: Path) -> list[Package]:
    text = req_path.read_text(encoding="utf-8-sig", errors="ignore")
    text = re.sub(r"\\\r?\n", " ", text)  # join backslash continuations (used with --hash)

    pkgs: list[Package] = []
    for raw in text.splitlines():
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()  # strip comments, keep URL #fragments
        if not line:
            continue

        has_hash = "--hash=" in line
        line_no_opts = re.sub(r"\s--hash=\S+", "", line).strip()

        # VCS / URL lines: "-e git+https://...#egg=name" or "git+https://...#egg=name"
        if line_no_opts.startswith(("-e ", "--editable ")):
            line_no_opts = line_no_opts.split(None, 1)[1].strip()
        if re.match(r"^(git|hg|svn|bzr)\+", line_no_opts) or line_no_opts.startswith(("http://", "https://")):
            m = _EGG_RE.search(line_no_opts)
            if m:
                pkgs.append(
                    Package(
                        name=m.group(1),
                        version="*",
                        ecosystem="pypi",
                        source=line_no_opts,
                        path=_rel(req_path, root),
                        is_direct=True,
                        metadata={"raw": raw.strip(), "integrity": has_hash},
                    )
                )
            continue
        if line_no_opts.startswith("-"):
            continue  # -r, -c, --index-url, local paths with -e, etc.

        try:
            req = Requirement(line_no_opts)
        except InvalidRequirement:
            continue

        specs = list(req.specifier)
        if len(specs) == 1 and specs[0].operator in ("==", "===") and "*" not in specs[0].version:
            version = specs[0].version
        else:
            version = str(req.specifier) or "*"

        pkgs.append(
            Package(
                name=req.name,
                version=version,
                ecosystem="pypi",
                source=req.url,
                path=_rel(req_path, root),
                is_direct=True,
                metadata={"raw": raw.strip(), "integrity": has_hash},
            )
        )
    return pkgs


# --------------------------------------------------------------------------- cargo


def _cargo_direct_names(search_root: Path) -> set[str]:
    """Crate names declared as dependencies in any Cargo.toml under the lockfile's directory."""
    names: set[str] = set()
    for manifest in _find(search_root, ["Cargo.toml"]):
        data = _load_toml(manifest)
        tables = [data, data.get("workspace", {})]
        tables += list((data.get("target") or {}).values())
        for t in tables:
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                for alias, spec in (t.get(section) or {}).items():
                    real = spec.get("package", alias) if isinstance(spec, dict) else alias
                    names.add(real)
    return names


def _scan_cargo(lock_path: Path, root: Path) -> list[Package]:
    data = _load_toml(lock_path)
    direct = _cargo_direct_names(lock_path.parent)
    pkgs: list[Package] = []
    for pkg in data.get("package", []):
        source = pkg.get("source")
        if not source:
            continue  # workspace member or path dependency (first party)
        pkgs.append(
            Package(
                name=pkg.get("name", ""),
                version=pkg.get("version", "unknown"),
                ecosystem="cargo",
                source=source,
                path=_rel(lock_path, root),
                is_direct=pkg.get("name", "") in direct,
                metadata={"integrity": bool(pkg.get("checksum")) or source.startswith("git+")},
            )
        )
    return pkgs


# --------------------------------------------------------------------------- go


def _scan_go_mod(mod_path: Path, root: Path) -> list[Package]:
    text = mod_path.read_text(encoding="utf-8-sig", errors="ignore")
    pkgs: list[Package] = []
    in_require = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("require (") or line == "require(":
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue

        if in_require:
            spec = line
        elif line.startswith("require "):
            spec = line[len("require "):].strip()
        else:
            continue

        code, _, comment = spec.partition("//")
        parts = code.split()
        if len(parts) < 2:
            continue
        name, version = parts[0], parts[1]
        pkgs.append(
            Package(
                name=name,
                version=version.lstrip("v"),  # OSV Go entries use versions without the "v" prefix
                ecosystem="go",
                source=None,
                path=_rel(mod_path, root),
                is_direct="indirect" not in comment,
                metadata={},
            )
        )
    return pkgs


# --------------------------------------------------------------------------- pipenv


def _scan_pipfile_lock(lock_path: Path, root: Path) -> list[Package]:
    data = _load_json(lock_path)
    pkgs: list[Package] = []
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            version = (info.get("version") or "").lstrip("=") or "*"
            source = f"git+{info['git']}" if "git" in info else None
            pkgs.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem="pypi",
                    source=source,
                    path=_rel(lock_path, root),
                    is_direct=False,  # Pipfile.lock does not record which entries are direct
                    metadata={"integrity": bool(info.get("hashes")), "dev": section == "develop"},
                )
            )
    return pkgs


# --------------------------------------------------------------------------- manifest fallbacks
# Used only when a directory has a manifest but no lockfile. Versions are whatever the
# manifest declares (usually ranges), so most entries will be unpinned.

_PY_LOCKS = ("poetry.lock", "uv.lock", "Pipfile.lock")
_NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json")


def _version_from_requirement(req: Requirement) -> str:
    specs = list(req.specifier)
    if len(specs) == 1 and specs[0].operator in ("==", "===") and "*" not in specs[0].version:
        return specs[0].version
    return str(req.specifier) or "*"


def _poetry_spec_version(spec: object) -> tuple[str, Optional[str]]:
    """(version, source) for a [tool.poetry.dependencies] value."""
    if isinstance(spec, dict):
        if "git" in spec:
            return "*", f"git+{spec['git']}"
        if "url" in spec:
            return "*", spec["url"]
        spec = spec.get("version", "*")
    spec = str(spec).strip()
    if re.fullmatch(r"\d+(\.\d+)*[0-9A-Za-z.+-]*", spec):
        return spec, None  # Poetry: a bare version means exactly that version
    if spec.startswith("==") and "," not in spec:
        return spec[2:].strip(), None
    return spec or "*", None


def _scan_pyproject(path: Path, root: Path) -> list[Package]:
    if any((path.parent / lock).exists() for lock in _PY_LOCKS):
        return []
    data = _load_toml(path)
    rel = _rel(path, root)
    pkgs: list[Package] = []

    def add_req(r: object) -> None:
        if not isinstance(r, str):
            return  # e.g. PEP 735 {include-group = ...}
        try:
            req = Requirement(r)
        except InvalidRequirement:
            return
        pkgs.append(Package(req.name, _version_from_requirement(req), "pypi", source=req.url, path=rel,
                            is_direct=True, metadata={"from_manifest": True}))

    project = data.get("project", {})
    reqs = list(project.get("dependencies", []))
    for group in (project.get("optional-dependencies") or {}).values():
        reqs += group
    for group in (data.get("dependency-groups") or {}).values():
        reqs += group
    for r in reqs:
        add_req(r)

    poetry = data.get("tool", {}).get("poetry", {})
    sections = [poetry.get("dependencies", {}), poetry.get("dev-dependencies", {})]
    sections += [g.get("dependencies", {}) for g in (poetry.get("group") or {}).values()]
    for section in sections:
        for name, spec in section.items():
            if name.lower() == "python" or (isinstance(spec, dict) and "path" in spec):
                continue
            version, source = _poetry_spec_version(spec)
            pkgs.append(Package(name, version, "pypi", source=source, path=rel, is_direct=True,
                                metadata={"from_manifest": True}))
    return pkgs


_NPM_REMOTE = re.compile(r"^(git\+|git://|github:|gitlab:|bitbucket:|https?://)|^[\w.-]+/[\w.-]+(#.*)?$")
_NPM_EXACT = re.compile(r"^=?v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$")


def _scan_package_json(path: Path, root: Path) -> list[Package]:
    if any((path.parent / lock).exists() for lock in _NPM_LOCKS):
        return []
    data = _load_json(path)
    rel = _rel(path, root)
    pkgs: list[Package] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            spec = str(spec).strip()
            if spec.startswith(("file:", "link:", "workspace:", "portal:")):
                continue  # local code
            source = None
            if _NPM_REMOTE.match(spec):
                source, version = spec, "*"
            elif m := _NPM_EXACT.match(spec):
                version = m.group(1)
            else:
                version = spec or "*"
            pkgs.append(Package(name, version, "npm", source=source, path=rel, is_direct=True,
                                metadata={"from_manifest": True, "dev": section == "devDependencies"}))
    return pkgs


# --------------------------------------------------------------------------- entry point

_SCANNERS = [
    (("package-lock.json", "npm-shrinkwrap.json"), _scan_npm),
    (("poetry.lock",), _scan_poetry),
    (("uv.lock",), _scan_uv),
    (("Pipfile.lock",), _scan_pipfile_lock),
    (("requirements*.txt",), _scan_requirements),
    (("Cargo.lock",), _scan_cargo),
    (("go.mod",), _scan_go_mod),
    (("pyproject.toml",), _scan_pyproject),  # only where no Python lockfile sits beside it
    (("package.json",), _scan_package_json),  # only where no npm lockfile sits beside it
]

# Files we recognise but cannot parse yet; reported so an empty or partial result is explained.
_JS_FALLBACK = "is not supported yet; versions for this directory come from package.json"
UNSUPPORTED = {
    "yarn.lock": f"yarn.lock {_JS_FALLBACK}",
    "pnpm-lock.yaml": f"pnpm-lock.yaml {_JS_FALLBACK}",
    "bun.lock": f"bun.lock {_JS_FALLBACK}",
    "bun.lockb": f"bun.lockb {_JS_FALLBACK}",
    "Gemfile.lock": "Ruby (Gemfile.lock) is not supported yet",
    "composer.lock": "PHP (composer.lock) is not supported yet",
    "pom.xml": "Java/Maven (pom.xml) is not supported yet",
    "build.gradle": "Java/Gradle (build.gradle) is not supported yet",
    "build.gradle.kts": "Java/Gradle (build.gradle.kts) is not supported yet",
    "packages.lock.json": ".NET (packages.lock.json) is not supported yet",
}

SUPPORTED_FILES = (
    "package-lock.json, npm-shrinkwrap.json, package.json, poetry.lock, uv.lock, Pipfile.lock, "
    "requirements*.txt, pyproject.toml, Cargo.lock, go.mod"
)


def scan_project(path: str) -> ProjectInventory:
    """Scan a project directory for supported lockfiles / manifests."""
    root = Path(path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {path}")

    inv = ProjectInventory(project_path=str(root))
    by_key: dict[str, Package] = {}

    for patterns, scanner in _SCANNERS:
        for file in _find(root, patterns):
            try:
                found = scanner(file, root)
            except LockfileError as e:
                inv.warnings.append(str(e))
                continue
            for p in found:
                existing = by_key.get(p.key)
                if existing is None:
                    by_key[p.key] = p
                    inv.packages.append(p)
                else:
                    existing.is_direct = existing.is_direct or p.is_direct
                    if p.path and p.path != existing.path:
                        others = existing.metadata.setdefault("other_paths", [])
                        if p.path not in others:
                            others.append(p.path)

    for file in _find(root, UNSUPPORTED):
        inv.warnings.append(f"{_rel(file, root)}: {UNSUPPORTED[file.name]}")
    return inv
