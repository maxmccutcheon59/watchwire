# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-09-16

### Added

- `watchwire.toml` policy file: exclude path globs, rule kind toggles, and
  entropy thresholds (`min_entropy`, `min_entropy_length`). Loaded from the
  current working directory or via `watchwire scan --config PATH`.
- Example policy at `examples/watchwire.toml`; schema documented in the README.
- Default exclude globs for lockfiles (`**/*.lock`, `package-lock.json`,
  `poetry.lock`, `go.sum`, and similar) on top of existing vendor dir skips.
- Entropy false-positive filters for UUIDs, pure hex digests (≥32 chars), and
  low-diversity base64 padding noise, with fixtures under `tests/fixtures/fp/`.

### Changed

- Version bump to 0.3.0. Pre-commit / Action pin examples recommend `v0.3.0`.
- Python 3.10 installs pull optional `tomli` only when stdlib `tomllib` is
  unavailable (3.11+ remains stdlib-only for TOML).

## [0.2.0] - 2026-09-16

### Added

- Machine-readable `scan --json` / `--sarif` (SARIF 2.1.0); JSON also on
  `hygiene` and `proc`.
- Reusable pre-commit hook (`.pre-commit-hooks.yaml`, id `watchwire-scan`).
- Composite GitHub Action (`action.yml`) with optional SARIF output for
  `github/codeql-action/upload-sarif`.
- Example consumer workflow under `examples/github-action-scan.yml`.

### Notes

- OSS core stays local-first: no SaaS, telemetry, or Marketplace listing claims.

[0.3.0]: https://github.com/maxmccutcheon59/watchwire/releases/tag/v0.3.0
[0.2.0]: https://github.com/maxmccutcheon59/watchwire/releases/tag/v0.2.0
