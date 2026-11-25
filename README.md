# PrismSCA

[![CI](https://github.com/generalwax2018/PrismSCA/actions/workflows/ci.yml/badge.svg)](https://github.com/generalwax2018/PrismSCA/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Local-first software composition analysis (SCA): one command to inventory your third-party dependencies across ecosystems, check them against [OSV](https://osv.dev), and flag supply-chain risk signals.**

```console
$ prismsca osv .
Querying OSV for 3 packages...

  pypi:django@3.0.0: 41 vulns -> GHSA-2m34-jcjv-45xf, GHSA-3gh2-xw74-jmcw, GHSA-3h9f-r86x-qvjx, ...
  pypi:flask@3.0.3: 2 vulns -> GHSA-68rp-wp8r-4726, PYSEC-2026-2151

1 package(s) not checked because no single version is pinned: requests >=2.0
Pin them with a lockfile (uv lock, poetry lock, pip-compile / pip freeze, npm install) to check them against OSV.
```

## Why another SCA tool?

`npm audit`, `pip-audit` and `osv-scanner` are good at answering *"which of my packages have known CVEs?"*. PrismSCA answers that too (it uses the same OSV data), and adds:

- **Behavioral risk signals**: install scripts, git or non-registry sources, unpinned versions and missing integrity hashes, which are risks a CVE database won't show you.
- **Mixed-ecosystem repos in one pass**: npm, PyPI, crates.io and Go modules, with direct and transitive dependencies told apart.
- **A stable JSON handoff** (`schema_version`ed) to feed into your own triage pipeline, or into [PrismRedline](https://github.com/generalwax2018/PrismRedline) (integration planned).

If you only need CVE matching for one ecosystem, the native tools are great. PrismSCA is for when you want one view across all of them, plus the supply-chain signals.

## Install

Requires Python 3.10+.

```bash
pip install git+https://github.com/generalwax2018/PrismSCA
```

## Usage

```bash
prismsca inventory .                      # what's in this project?
prismsca inventory . --format json --out inventory.json

prismsca osv .                            # known vulnerabilities (network: api.osv.dev)

prismsca signals .                        # behavioral risk signals, highest score first

prismsca handoff . --out prismsca-handoff.json   # everything, as one JSON document
prismsca handoff . --skip-osv                     # fully offline
```

Exit codes: `0` success · `1` one or more OSV lookups **failed** (those packages are *unchecked*, not clean) · `2` bad path.

## What it reads

| Ecosystem | Lockfiles (exact versions) | Manifests (used only when there is no lockfile) |
|---|---|---|
| npm | `package-lock.json` / `npm-shrinkwrap.json` (v2/v3) | `package.json` |
| PyPI | `poetry.lock`, `uv.lock`, `Pipfile.lock` | `pyproject.toml` (PEP 621 / Poetry), `requirements*.txt` |
| crates.io | `Cargo.lock` (+ `Cargo.toml` for direct deps) | |
| Go | `go.mod` | |

`yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, Ruby, PHP, Java and .NET files are detected and reported as **not yet supported**, so they don't silently produce an empty result. `node_modules`, `.venv`, `target`, `vendor`, `dist`, `build` and `.git` are not scanned.

**Vulnerability checks need pinned versions.** A range like `requests>=2.0` can't be matched to a single version, so it is reported as *not checked* rather than guessed. For the best results, scan a lockfile (or a `pip freeze` output).

## Risk signals

Each package gets these flags (True means riskier) and an additive `risk_score`:

| Signal | Weight | Meaning |
|---|---|---|
| `has_install_script` | 3 | runs code at install time (npm `hasInstallScript`) |
| `git_source` | 2 | installed from a git repo rather than a registry |
| `unusual_source` | 2 | installed from a URL that isn't a known public registry |
| `unpinned_version` | 1 | no single version pinned |
| `missing_integrity` | 1 | the lockfile format supports hashes but this entry has none |

Scores of 3 or more are reported as high risk. **The score is a triage heuristic, not a verdict.** A high score means "look at this first", not "this is malicious".

## Privacy and network use

PrismSCA runs locally and has no telemetry. The only network traffic is to the public OSV API (`api.osv.dev`), which receives the **names and versions** of your dependencies, never your code or file paths, and only for the `osv` and `handoff` commands. Use `handoff --skip-osv`, `inventory` or `signals` for fully offline runs. OSV responses are cached for 24 hours under `~/.prismsca/osv_cache`.

## Handoff format

`prismsca handoff` writes one JSON document with `tool`, `tool_version`, `schema_version`, `generated_at`, `warnings` and a `packages` list. Each entry carries the package's `signals` and an `osv` summary whose `status` is `ok`, `error`, `skipped` or `not_queried`. A failed lookup always has `count: null`, never `0`. The full shape is documented in [`prismsca/handoff.py`](prismsca/handoff.py), and breaking changes bump `schema_version`.

## Roadmap

- `yarn.lock` and `pnpm-lock.yaml` support
- npm lockfile v1
- CycloneDX / SPDX SBOM export
- CVSS score parsing and a severity threshold for CI (`--fail-on high`)
- Install-time code detection beyond npm (`setup.py`, `build.rs`)
- License inventory

Issues and PRs are welcome, especially lockfiles that parse wrong. Please attach a minimal, sanitized example.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Security

To report a vulnerability in PrismSCA itself, see [SECURITY.md](SECURITY.md).

## License

MIT
