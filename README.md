# PrismSCA

Local-first Software Composition Analysis (SCA) for third-party library inventory, version tracking, OSV patch awareness, behavioral risk signals, and PrismRedline handoff.

Part of the Prism family (PrismRedline, RiskPrism, etc.).

## Features

- **Inventory** — scans `package-lock.json`, `poetry.lock`, `Cargo.lock`, `go.mod`, `requirements*.txt`, and `uv.lock`
- **OSV** — queries the Open Source Vulnerabilities database (with local cache)
- **Behavioral signals** — install scripts, Git sources, unpinned versions, unusual sources, integrity presence, risk score
- **Handoff** — structured JSON for deeper analysis in PrismRedline

## Install

```bash
# from source
pip install -e .

# or just run with python -m
python -m prismsca.cli --help
```

## Usage

```bash
# Inventory a project
prismsca inventory /path/to/project
prismsca inventory . --format json --out inventory.json

# Check against OSV
prismsca osv .

# Behavioral risk signals
prismsca signals . --format text

# Full handoff for PrismRedline
prismsca handoff . --out prismsca-handoff.json
prismsca handoff . --skip-osv   # local-only, no network
```

## Status

Functional MVP. Supports common lockfiles. OSV queries are cached under `~/.prismsca/osv_cache`.

## License

MIT
