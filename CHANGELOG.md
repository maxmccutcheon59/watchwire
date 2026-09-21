# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.1] - 2026-09-21

### Added

- `SECURITY.md` — vulnerability disclosure contact and authorized-testing-only policy.
- `COMPLIANCE_NOTES.md` — defensive/local posture, authorized systems only, data inventory.
- CI reference jobs for **gitleaks** secret scanning and **pip-audit** (`ci/security-ci.yml`; merge requires GitHub `workflow` OAuth scope).
- `.gitleaks.toml` allowlist for synthetic test fixtures (fake AKIA/ghp_ patterns only).

### Changed

- `.gitignore` expanded for `.env*` / key material patterns.
- Patch version bump to 0.4.1.

### Security

- Local gitleaks: findings limited to intentional test fixtures (allowlisted).
- `pip-audit`: no high/critical issues in project runtime dependencies (stdlib + optional `tomli`); toolchain `pip` CVEs are CI-image concerns, not shipped with Watchwire.

## [0.4.0] - 2026-09-16

### Added

- Example **policy packs** under `examples/policies/`:
  - `student.toml` — aggressive excludes for course / homework repos
  - `indie.toml` — balanced defaults for small personal projects
  - `small-team.toml` — stricter entropy / fewer excludes for shared repos
- Optional composite Action input `run-hygiene` (default `false`): when `true`,
  runs `watchwire hygiene` on the same path after the secret scan and writes
  `watchwire-hygiene.json`. Scan / SARIF behavior unchanged when left false.

### Changed

- Version bump to 0.4.0. Pre-commit / Action pin examples recommend `v0.4.0`.
- Package metadata author email set to `MaxMcCutcheon1@outlook.com`.

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

[0.4.0]: https://github.com/maxmccutcheon59/watchwire/releases/tag/v0.4.0
[0.3.0]: https://github.com/maxmccutcheon59/watchwire/releases/tag/v0.3.0
[0.2.0]: https://github.com/maxmccutcheon59/watchwire/releases/tag/v0.2.0
