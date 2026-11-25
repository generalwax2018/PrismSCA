import json

import pytest

from prismsca import __version__, cli
from prismsca.handoff import SCHEMA_VERSION, generate_handoff
from prismsca.inventory import Package, scan_project
from prismsca.signals import compute_all_signals, compute_signals


def test_crates_io_is_not_a_git_source():
    s = compute_signals(
        Package("serde", "1.0.0", "cargo", source="registry+https://github.com/rust-lang/crates.io-index", metadata={"integrity": True})
    )
    assert not s["git_source"] and not s["unusual_source"]
    assert s["risk_score"] == 0


def test_git_and_install_script_score():
    s = compute_signals(
        Package("x", "1.0.0", "npm", source="git+ssh://git@github.com/a/x.git", metadata={"hasInstallScript": True, "integrity": False})
    )
    assert s["git_source"] and s["has_install_script"] and s["missing_integrity"]
    assert not s["unusual_source"]
    assert s["risk_score"] == 3 + 2 + 1


def test_unknown_integrity_is_not_penalized():
    s = compute_signals(Package("golang.org/x/net", "0.20.0", "go"))
    assert not s["missing_integrity"]
    assert s["risk_score"] == 0


def test_ranged_requirement_is_unpinned():
    assert compute_signals(Package("requests", ">=2.0", "pypi"))["unpinned_version"]


def test_handoff_shape():
    from prismsca.inventory import ProjectInventory

    p = Package("a", "1.0.0", "pypi")
    inv = ProjectInventory("/p", [p], warnings=["w"])
    h = generate_handoff(inv, compute_all_signals([p]), {p.key: {"status": "error", "error": "boom"}})
    assert h["schema_version"] == SCHEMA_VERSION and h["tool_version"] == __version__
    assert h["warnings"] == ["w"]
    assert h["packages"][0]["osv"]["status"] == "error" and h["packages"][0]["osv"]["count"] is None
    assert generate_handoff(inv, {}, None)["packages"][0]["osv"] is None


def test_cli_help_and_version(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_cli_handoff_skip_osv(tmp_path, write):
    write("requirements.txt", "flask==3.0.3\n")
    out = tmp_path / "h.json"
    assert cli.main(["handoff", str(tmp_path), "--skip-osv", "--out", str(out)]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["package_count"] == 1


def test_cli_osv_exits_nonzero_on_lookup_failure(tmp_path, write, monkeypatch):
    write("requirements.txt", "flask==3.0.3\n")
    monkeypatch.setattr(cli, "query_osv_batch", lambda pkgs: {p.key: {"status": "error", "error": "down"} for p in pkgs})
    assert cli.main(["osv", str(tmp_path)]) == 1


def test_cli_bad_path():
    assert cli.main(["inventory", "/definitely/not/here"]) == 2
