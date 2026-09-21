# CI

Live workflow: [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)

Matrix: Python 3.10 / 3.12 / 3.13 — `ruff check` + `pytest`.
`github-actions.yml` here is a mirror of that file for convenience.

## Templates (when workflow scope is blocked on the Watchwire repo)

| File | Purpose |
|------|---------|
| `consumer-scan.yml` | 5-min install for **other** repos — pin `@v0.5.0` |
| `security-ci.yml` | Reference gitleaks + pip-audit jobs to merge into this repo’s CI when the pushing credential has GitHub OAuth `workflow` scope |
| `github-actions.yml` | Mirror of live `.github/workflows/ci.yml` |

Copy `consumer-scan.yml` into a consumer repo as `.github/workflows/watchwire.yml`.
