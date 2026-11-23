"""Behavioral risk signals for third-party packages."""

from .inventory import Package


def compute_signals(package: Package) -> dict:
    """Return a dict of behavioral risk signals for a package."""
    signals = {
        "has_install_script": False,
        "git_source": False,
        "unpinned_version": False,
        "unusual_source": False,
        # more signals later
    }
    # TODO: implement based on lockfile evidence and metadata
    return signals
