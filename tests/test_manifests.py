import json

from prismsca import cli
from prismsca.inventory import scan_project


def by_name(inv):
    return {p.name: p for p in inv.packages}


def test_pyproject_without_lockfile(write, tmp_path):
    write(
        "pyproject.toml",
        """
        [project]
        name = "app"
        dependencies = ["requests>=2.31", "packaging==24.0", "tomli>=2; python_version < '3.11'"]

        [project.optional-dependencies]
        dev = ["pytest"]
        """,
    )
    pkgs = by_name(scan_project(str(tmp_path)))
    assert set(pkgs) == {"requests", "packaging", "tomli", "pytest"}
    assert pkgs["packaging"].is_pinned and pkgs["packaging"].version == "24.0"
    assert not pkgs["requests"].is_pinned
    assert all(p.is_direct and p.metadata["from_manifest"] for p in pkgs.values())


def test_poetry_pyproject_specs(write, tmp_path):
    write(
        "pyproject.toml",
        """
        [tool.poetry.dependencies]
        python = "^3.11"
        flask = "3.0.3"
        rich = "^13"
        local = { path = "../local" }
        forked = { git = "https://github.com/acme/forked.git" }
        """,
    )
    pkgs = by_name(scan_project(str(tmp_path)))
    assert set(pkgs) == {"flask", "rich", "forked"}
    assert pkgs["flask"].version == "3.0.3" and pkgs["flask"].is_pinned
    assert pkgs["rich"].version == "^13" and not pkgs["rich"].is_pinned
    assert pkgs["forked"].source.startswith("git+")


def test_pyproject_ignored_when_lockfile_present(write, tmp_path):
    write("pyproject.toml", '[project]\nname = "a"\ndependencies = ["requests"]\n')
    write("uv.lock", "version = 1\n")
    assert scan_project(str(tmp_path)).packages == []


def test_package_json_without_lockfile_and_yarn_warning(write, tmp_path):
    write(
        "package.json",
        json.dumps(
            {
                "dependencies": {"express": "^4.18.0", "lodash": "4.17.20", "mine": "file:../mine", "gh": "acme/gh#main"},
                "devDependencies": {"jest": "29.7.0"},
            }
        ),
    )
    write("yarn.lock", "# yarn lockfile v1\n")
    inv = scan_project(str(tmp_path))
    pkgs = by_name(inv)
    assert set(pkgs) == {"express", "lodash", "gh", "jest"}
    assert pkgs["lodash"].is_pinned and not pkgs["express"].is_pinned
    assert pkgs["gh"].source == "acme/gh#main"
    assert pkgs["jest"].metadata["dev"]
    assert any("yarn.lock" in w for w in inv.warnings)


def test_package_json_ignored_when_lockfile_present(write, tmp_path):
    write("package.json", json.dumps({"dependencies": {"express": "^4"}}))
    write("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {"": {}}}))
    assert scan_project(str(tmp_path)).packages == []


def test_pipfile_lock(write, tmp_path):
    write(
        "Pipfile.lock",
        json.dumps(
            {
                "default": {"requests": {"version": "==2.32.3", "hashes": ["sha256:aa"]}},
                "develop": {"pytest": {"version": "==8.2.0", "hashes": []}},
            }
        ),
    )
    pkgs = by_name(scan_project(str(tmp_path)))
    assert pkgs["requests"].version == "2.32.3" and pkgs["requests"].metadata["integrity"]
    assert pkgs["pytest"].metadata["dev"] and not pkgs["pytest"].metadata["integrity"]


def test_empty_project_explains_itself(tmp_path, capsys):
    assert cli.main(["inventory", str(tmp_path)]) == 0
    assert "No dependencies found" in capsys.readouterr().err


def test_osv_collapses_unpinned_into_hint(write, tmp_path, capsys, monkeypatch):
    write("requirements.txt", "requests\nflask==3.0.3\n")
    monkeypatch.setattr(
        cli,
        "query_osv_batch",
        lambda pkgs: {p.key: ({"status": "ok", "vulns": []} if p.is_pinned else {"status": "skipped", "reason": "x"}) for p in pkgs},
    )
    assert cli.main(["osv", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "pypi:flask@3.0.3: clean" in out
    assert "1 package(s) not checked" in out and "requests *" in out
