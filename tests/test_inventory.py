import json

from prismsca.inventory import scan_project


def by_name(inv):
    return {p.name: p for p in inv.packages}


def test_npm_direct_vs_transitive_and_skips(tmp_path, write):
    write(
        "package-lock.json",
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app", "dependencies": {"express": "^4"}, "devDependencies": {"jest": "^29"}},
                    "node_modules/express": {
                        "version": "4.18.2",
                        "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
                        "integrity": "sha512-abc",
                    },
                    "node_modules/jest": {"version": "29.0.0", "dev": True, "integrity": "sha512-x"},
                    "node_modules/debug": {"version": "2.6.9", "integrity": "sha512-y"},  # hoisted transitive
                    "node_modules/express/node_modules/debug": {"version": "4.0.0"},
                    "packages/lib": {"name": "lib", "version": "1.0.0"},  # workspace member
                    "node_modules/lib": {"resolved": "packages/lib", "link": True},
                },
            }
        ),
    )
    # lockfiles inside node_modules must be ignored
    write("node_modules/foo/package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {"node_modules/evil": {"version": "1"}}}))

    inv = scan_project(str(tmp_path))
    pkgs = {(p.name, p.version): p for p in inv.packages}
    assert set(pkgs) == {("express", "4.18.2"), ("jest", "29.0.0"), ("debug", "2.6.9"), ("debug", "4.0.0")}
    assert pkgs[("express", "4.18.2")].is_direct
    assert pkgs[("jest", "29.0.0")].is_direct and pkgs[("jest", "29.0.0")].metadata["dev"]
    assert not pkgs[("debug", "2.6.9")].is_direct
    assert not pkgs[("debug", "4.0.0")].is_direct
    assert pkgs[("debug", "4.0.0")].metadata["integrity"] is False
    assert inv.warnings == []


def test_npm_v1_lockfile_warns(tmp_path, write):
    write("package-lock.json", json.dumps({"lockfileVersion": 1, "dependencies": {}}))
    inv = scan_project(str(tmp_path))
    assert inv.packages == []
    assert len(inv.warnings) == 1 and "lockfileVersion 1" in inv.warnings[0]


def test_corrupt_lockfile_warns_instead_of_silently_empty(tmp_path, write):
    write("package-lock.json", "{not json")
    write("poetry.lock", "[[package]\nbroken")
    inv = scan_project(str(tmp_path))
    assert inv.packages == []
    assert len(inv.warnings) == 2


def test_uv_lock_is_parsed_as_toml(tmp_path, write):
    write(
        "uv.lock",
        """
        version = 1
        requires-python = ">=3.10"

        [[package]]
        name = "myapp"
        version = "0.1.0"
        source = { editable = "." }
        dependencies = [{ name = "requests" }]

        [[package]]
        name = "requests"
        version = "2.32.3"
        source = { registry = "https://pypi.org/simple" }
        dependencies = [{ name = "idna" }]
        sdist = { url = "https://files.pythonhosted.org/r.tar.gz", hash = "sha256:aa" }

        [[package]]
        name = "idna"
        version = "3.7"
        source = { registry = "https://pypi.org/simple" }

        [[package]]
        name = "forked"
        version = "1.0.0"
        source = { git = "https://github.com/acme/forked?rev=main#abc123" }
        """,
    )
    pkgs = by_name(scan_project(str(tmp_path)))
    assert set(pkgs) == {"requests", "idna", "forked"}  # editable project itself excluded
    assert pkgs["requests"].is_direct and not pkgs["idna"].is_direct
    assert pkgs["requests"].metadata["integrity"] is True
    assert pkgs["idna"].metadata["integrity"] is False
    assert pkgs["forked"].source.startswith("git+https://github.com/")


def test_poetry_direct_from_pyproject(tmp_path, write):
    write(
        "pyproject.toml",
        """
        [tool.poetry.dependencies]
        python = "^3.11"
        Flask = "^3.0"

        [tool.poetry.group.dev.dependencies]
        pytest = "^8"
        """,
    )
    write(
        "poetry.lock",
        """
        [[package]]
        name = "flask"
        version = "3.0.3"
        files = [{ file = "flask-3.0.3.whl", hash = "sha256:aa" }]

        [[package]]
        name = "werkzeug"
        version = "3.0.3"
        files = []

        [[package]]
        name = "pytest"
        version = "8.2.0"
        files = [{ file = "pytest.whl", hash = "sha256:bb" }]
        """,
    )
    pkgs = by_name(scan_project(str(tmp_path)))
    assert pkgs["flask"].is_direct and pkgs["pytest"].is_direct
    assert not pkgs["werkzeug"].is_direct
    assert pkgs["flask"].metadata["integrity"] is True
    assert pkgs["werkzeug"].metadata["integrity"] is False


def test_requirements_keeps_specifiers(tmp_path, write):
    write(
        "requirements.txt",
        """
        # comment
        requests>=2.0
        flask==3.0.3  # pinned
        Django[argon2]==5.0.1 ; python_version >= "3.10"
        numpy
        hashed==1.0 \\
            --hash=sha256:abc
        -r other.txt
        --index-url https://example.com/simple
        -e git+https://github.com/acme/tool.git@main#egg=acme-tool
        """,
    )
    pkgs = by_name(scan_project(str(tmp_path)))
    assert pkgs["requests"].version == ">=2.0" and not pkgs["requests"].is_pinned
    assert pkgs["flask"].version == "3.0.3" and pkgs["flask"].is_pinned
    assert pkgs["Django"].version == "5.0.1"
    assert pkgs["numpy"].version == "*"
    assert pkgs["hashed"].metadata["integrity"] is True
    assert pkgs["flask"].metadata["integrity"] is False
    assert pkgs["acme-tool"].source.startswith("git+https://github.com/acme/tool.git")
    assert len(pkgs) == 6


def test_utf8_bom_is_tolerated(tmp_path):
    # Windows tools (e.g. PowerShell 5 Set-Content -Encoding utf8) prepend a BOM
    (tmp_path / "requirements.txt").write_bytes(b"\xef\xbb\xbfdjango==3.0.0\nflask==3.0.3\n")
    assert set(by_name(scan_project(str(tmp_path)))) == {"django", "flask"}


def test_cargo_direct_and_skips_local_crates(tmp_path, write):
    write(
        "Cargo.toml",
        """
        [package]
        name = "app"
        version = "0.1.0"

        [dependencies]
        serde = "1"
        json = { package = "serde_json", version = "1" }
        """,
    )
    write(
        "Cargo.lock",
        """
        version = 3

        [[package]]
        name = "app"
        version = "0.1.0"

        [[package]]
        name = "serde"
        version = "1.0.200"
        source = "registry+https://github.com/rust-lang/crates.io-index"
        checksum = "abc"

        [[package]]
        name = "serde_json"
        version = "1.0.117"
        source = "registry+https://github.com/rust-lang/crates.io-index"
        checksum = "def"

        [[package]]
        name = "itoa"
        version = "1.0.11"
        source = "registry+https://github.com/rust-lang/crates.io-index"
        checksum = "ghi"
        """,
    )
    pkgs = by_name(scan_project(str(tmp_path)))
    assert set(pkgs) == {"serde", "serde_json", "itoa"}
    assert pkgs["serde"].is_direct and pkgs["serde_json"].is_direct
    assert not pkgs["itoa"].is_direct


def test_go_mod(tmp_path, write):
    write(
        "go.mod",
        """
        module example.com/app

        go 1.22

        require github.com/single/dep v1.0.0

        require (
            github.com/gin-gonic/gin v1.9.1
            golang.org/x/net v0.20.0 // indirect
        )

        replace github.com/old/thing => github.com/new/thing v1.2.3
        """,
    )
    pkgs = by_name(scan_project(str(tmp_path)))
    assert set(pkgs) == {"github.com/single/dep", "github.com/gin-gonic/gin", "golang.org/x/net"}
    assert pkgs["github.com/gin-gonic/gin"].version == "1.9.1"
    assert pkgs["github.com/gin-gonic/gin"].is_direct
    assert not pkgs["golang.org/x/net"].is_direct


def test_duplicates_merge_paths_and_directness(tmp_path, write):
    write("a/requirements.txt", "flask==3.0.3\n")
    write("b/requirements-dev.txt", "flask==3.0.3\n")
    inv = scan_project(str(tmp_path))
    assert len(inv.packages) == 1
    assert inv.packages[0].metadata["other_paths"] == ["b/requirements-dev.txt"]
