import textwrap
from pathlib import Path

import pytest


@pytest.fixture
def write(tmp_path: Path):
    """write("sub/file.txt", "...") -> creates a dedented file under tmp_path."""

    def _write(rel: str, content: str) -> Path:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")
        return p

    return _write
