"""Behavioral risk signals for third-party packages.

Every boolean signal except `is_direct` is a *risk* indicator (True = riskier).
"""

from __future__ import annotations

from .inventory import Package

# Packages at or above this score are reported as high risk.
HIGH_RISK_THRESHOLD = 3

WEIGHTS = {
    "has_install_script": 3,
    "git_source": 2,
    "unusual_source": 2,
    "unpinned_version": 1,
    "missing_integrity": 1,
}

RISK_FLAGS = tuple(WEIGHTS)

KNOWN_REGISTRIES = (
    "https://registry.npmjs.org/",
    "https://registry.yarnpkg.com/",
    "https://pypi.org/",
    "https://files.pythonhosted.org/",
    "https://proxy.golang.org/",
    "https://crates.io/",
    "https://static.crates.io/",
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
)

_GIT_PREFIXES = ("git+", "git://", "git@", "github:", "gitlab:", "bitbucket:")
_GIT_HOSTS = ("github.com", "gitlab.com", "bitbucket.org")


def _is_git_source(source: str) -> bool:
    if source.startswith(_GIT_PREFIXES):
        return True
    if source.startswith(("registry+", "sparse+")):
        return False  # cargo registry index URLs live on github.com but are not git deps
    host = source.split("://", 1)[-1].split("/", 1)[0]
    return any(host == h or host.endswith("." + h) for h in _GIT_HOSTS)


def compute_signals(package: Package) -> dict:
    """Return behavioral risk signals for a single package."""
    meta = package.metadata or {}
    source = (package.source or "").lower()

    signals = {
        "has_install_script": bool(meta.get("hasInstallScript")),
        "git_source": bool(source) and _is_git_source(source),
        "unusual_source": bool(source) and not _is_git_source(source) and not source.startswith(KNOWN_REGISTRIES),
        "unpinned_version": not package.is_pinned,
        # Only flag missing integrity when the format records it ("integrity" key present).
        # Formats that never carry hashes (e.g. go.mod) get no penalty.
        "missing_integrity": "integrity" in meta and not meta["integrity"],
        "is_direct": package.is_direct,
    }
    signals["risk_score"] = sum(w for flag, w in WEIGHTS.items() if signals[flag])
    return signals


def compute_all_signals(packages: list[Package]) -> dict[str, dict]:
    """Compute signals for every package, keyed by ecosystem:name@version."""
    return {p.key: compute_signals(p) for p in packages}
