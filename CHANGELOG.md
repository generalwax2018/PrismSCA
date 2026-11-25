# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0]

First public release.

### Added
- `inventory`, `osv`, `signals` and `handoff` commands.
- Lockfiles: `package-lock.json` / `npm-shrinkwrap.json` (v2/v3), `poetry.lock`, `uv.lock`, `Pipfile.lock`, `Cargo.lock`, `go.mod`, `requirements*.txt`.
- Manifest fallback for `pyproject.toml` and `package.json` when no lockfile is present.
- Direct vs transitive detection for npm, Poetry, uv, Cargo and Go.
- OSV batch queries with retries, pagination and a 24h local cache.
- Explicit OSV status per package (`ok`, `error`, `skipped`, `not_queried`): failed lookups are never reported as clean, and `osv` / `handoff` exit with code 1 when any lookup fails.
- Behavioral risk signals: install scripts, git sources, unusual sources, unpinned versions, missing integrity.
- Versioned handoff JSON (`schema_version: 1`).
- Warnings for unparseable lockfiles and for detected-but-unsupported ones (yarn, pnpm, bun, Ruby, PHP, Java, .NET).

[Unreleased]: https://github.com/generalwax2018/PrismSCA/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/generalwax2018/PrismSCA/releases/tag/v0.1.0
