# CI templates

Live workflows for this repo are in [`.github/workflows/`](../.github/workflows/):
`ci.yml` (Ruff + pytest on Python 3.10, 3.12, and 3.13) and `security.yml`
(gitleaks secret scan + pip-audit).

## For other repos

| File | Purpose |
|------|---------|
| `consumer-scan.yml` | 5-minute Watchwire setup for **other** repos. Copy it into your repo as `.github/workflows/watchwire.yml`; it pins `@v0.5.0`. |
