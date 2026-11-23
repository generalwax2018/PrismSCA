"""Behavioral risk signals for third-party packages."""

from __future__ import annotations

import re
from .inventory import Package


def compute_signals(package: Package) -> dict:
    """Return behavioral risk signals for a single package."""
    meta = package.metadata or {}
    signals = {
        "has_install_script": bool(meta.get("hasInstallScript")),
        "git_source": False,
        "unpinned_version": False,
        "unusual_source": False,
        "integrity_present": bool(meta.get("integrity")),
        "is_direct": package.is_direct,
    }

    source = (package.source or "").lower()
    if source:
        if source.startswith("git+") or "github.com" in source or "gitlab.com" in source:
            signals["git_source"] = True
        if not any(
            source.startswith(p)
            for p in (
                "https://registry.npmjs.org",
                "https://pypi.org",
                "https://files.pythonhosted.org",
                "https://proxy.golang.org",
                "https://crates.io",
                "registry+",
            )
        ):
            signals["unusual_source"] = True

    ver = package.version or ""
    if ver in ("*", "latest", "") or any(op in ver for op in (">=", "<=", ">", "<", "~", "^")):
        signals["unpinned_version"] = True

    # Score (higher = riskier)
    score = 0
    if signals["has_install_script"]:
        score += 3
    if signals["git_source"]:
        score += 2
    if signals["unusual_source"]:
        score += 2
    if signals["unpinned_version"]:
        score += 1
    if not signals["integrity_present"] and package.ecosystem in ("npm", "pypi"):
        score += 1
    signals["risk_score"] = score

    return signals


def compute_all_signals(packages: list[Package]) -> dict[str, dict]:
    """Compute signals for every package, keyed by name@version."""
    out = {}
    for p in packages:
        key = f"{p.ecosystem}:{p.name}@{p.version}"
        out[key] = compute_signals(p)
    return out
