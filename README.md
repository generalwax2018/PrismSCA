# PrismSCA

Local-first Software Composition Analysis (SCA) for third-party library inventory, version tracking, OSV patch awareness, behavioral risk signals, and PrismRedline handoff.

Part of the Prism family (PrismRedline, RiskPrism, etc.).

## Goals

- Inventory every third-party library across your projects (local-first, no forced cloud).
- Track versions and identify outdated packages.
- Surface known vulnerabilities and available patches via OSV.
- Detect behavioral risk signals (install scripts, unusual sources, build behavior, etc.).
- Generate structured handoff for deeper analysis in PrismRedline.

## Current structure

```
prismsca/
  __init__.py
  cli.py          # CLI entrypoint (inventory, osv, signals, handoff)
  inventory.py    # Package & ProjectInventory models + scanner stub
  osv.py          # OSV API client stub
  signals.py      # Behavioral risk signals stub
  handoff.py      # PrismRedline handoff generator stub
tests/
pyproject.toml
```

## Status

Scaffold only. Next steps: implement project scanning (npm/pnpm/Poetry/Cargo/Go/etc.), wire OSV queries, and flesh out signals + handoff.

## License

MIT
