# Watchwire

[![CI](https://github.com/maxmccutcheon59/watchwire/actions/workflows/ci.yml/badge.svg)](https://github.com/maxmccutcheon59/watchwire/actions/workflows/ci.yml)

**Local-first defensive CLI** for catching leaked secrets, inspecting Linux processes, and spotting risky file permissions — without sending anything off-box.

Built as a portfolio / internship project demonstrating practical defensive security tooling in pure Python (stdlib only at runtime).

---

## Sellable v1 (5-minute CI install)

Watchwire v0.5.0 is the first **sellable OSS layer** for founders who want local-first
secret scanning in CI without a SaaS bill or telemetry. Pin a release tag — no Marketplace
listing required.

### 1) Init policy files (optional but recommended)

```bash
pip install "git+https://github.com/maxmccutcheon59/watchwire.git@v0.5.0"
watchwire init                 # writes watchwire.toml + .watchwireignore
# watchwire init --with-suppressions   # also writes watchwire.suppressions.toml (commented)
watchwire scan .
watchwire scan --staged        # git staged files only (local git; no network)
```

### 2) GitHub Actions (copy-paste)

Use the composite Action pinned to **`@v0.5.0`** (template also under [`ci/consumer-scan.yml`](ci/consumer-scan.yml)):

```yaml
- uses: actions/checkout@v4

- name: Scan with Watchwire
  id: ww
  uses: maxmccutcheon59/watchwire@v0.5.0
  with:
    path: "."
    sarif-file: watchwire.sarif
    fail-on-findings: "true"

- name: Upload SARIF (optional)
  if: success() || failure()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.ww.outputs.sarif-path }}
```

### 3) Pre-commit

```yaml
repos:
  - repo: https://github.com/maxmccutcheon59/watchwire
    rev: v0.5.0
    hooks:
      - id: watchwire-scan
```

### Sellable v1 surface

| Feature | What it does |
|---------|----------------|
| `.watchwireignore` | gitignore-style path skips (local file) |
| `watchwire init` | starter `watchwire.toml` + `.watchwireignore` |
| `watchwire scan --staged` | only git staged files (`git diff --cached`; no network) |
| `watchwire.suppressions.toml` | path + rule-id allowlist for noisy repos (**abuse risk** — see COMPLIANCE_NOTES) |
| JSON / SARIF / Action / pre-commit | CI wiring from earlier releases |

**Not claimed:** SaaS product, paid traction, Marketplace publication, or remote scanning.


## The problem

Credentials and private keys still leak into repos, config dumps, and scratch files. Operators also need quick answers about “what is this process doing?” and “are there world-writable or setuid files under this tree?” — without installing a heavyweight agent or shipping filesystem contents to a SaaS scanner.

Watchwire answers those questions **locally**: regex + entropy for secrets, `/proc` reads for processes, and permission bits for hygiene. No network exfiltration by design.

---

## Install

```bash
git clone https://github.com/maxmccutcheon59/watchwire.git
cd watchwire
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Requires **Python 3.10+**. Runtime depends on the standard library only. The `proc` subcommand is Linux-oriented (`/proc`).

---

## 2-minute demo

```bash
# 1) Scan fixture tree (fake AKIA / ghp_ patterns only — never real secrets)
watchwire scan tests/fixtures/
# Expect exit code 1 and redacted findings like:
#   …/aws.env:2: [aws_access_key_id] AKIA…0001

# 2) Summarize processes (read-only /proc)
watchwire proc
watchwire proc 1          # detail one PID

# 3) Permission hygiene under a tree
watchwire hygiene .
```

Matches are **redacted** in output. `scan` / `hygiene` exit `1` if findings exist (CI-friendly); `0` if clean.

Machine-readable:

```bash
watchwire scan PATH --json
watchwire scan PATH --sarif -o watchwire.sarif
watchwire hygiene PATH --json
watchwire proc --json
```

---

## Usage

### Scan for leaked secrets

```bash
watchwire scan ./my-project
```

Detects (among others):

| Kind | Example signal (fixtures only) |
|------|--------------------------------|
| AWS access key ID | `AKIA…` |
| GitHub tokens | `ghp_…`, `github_pat_…` |
| Private key PEM headers | `-----BEGIN … PRIVATE KEY-----` |
| Slack tokens | `xoxb-…` |
| High-entropy strings | long base64-ish runs |


### Init starter files

```bash
watchwire init                 # cwd: watchwire.toml + .watchwireignore
watchwire init ./my-app        # target directory
watchwire init --force         # overwrite
watchwire init --with-suppressions
```

### `.watchwireignore` (gitignore-style)

Place a [`.watchwireignore`](examples/.watchwireignore) at the repo root (or pass
`--ignore-file PATH`). Syntax mirrors `.gitignore`: `#` comments, `!` negation,
trailing `/` for directories, `*` / `**` globs. Loaded automatically from the
current working directory when present. Combined with `[scan].exclude` in
`watchwire.toml`.

### Staged-only scan

```bash
watchwire scan --staged        # all staged files in this git repo
watchwire scan --staged ./src  # staged files under ./src only
```

Uses local `git diff --cached` only (no remotes, no network). Exit `2` if not a
git work tree or git is missing.

### Suppressions (path + rule allowlist)

Optional [`watchwire.suppressions.toml`](examples/suppressions/watchwire.suppressions.toml)
(or `--suppressions PATH`):

```toml
[[suppress]]
path = "docs/examples/demo.env"
rule = "aws_access_key_id"
reason = "synthetic demo credential; reviewed 2026-09-21"
```

`rule` may be a finding kind or `"*"`. **Abuse risk:** suppressions can hide real
secrets — document reasons, review in PRs, prefer excludes/fixes first. See
[`COMPLIANCE_NOTES.md`](COMPLIANCE_NOTES.md).


### Policy file (`watchwire.toml`)

Optional local policy. Loaded from `./watchwire.toml` in the current working
directory, or via `--config PATH`.

```bash
watchwire scan ./my-project
watchwire scan ./my-project --config ./examples/watchwire.toml
```

#### Example policy packs

Ready-to-use packs live under [`examples/policies/`](examples/policies/):

| Pack | File | Fit |
|------|------|-----|
| Student | `student.toml` | Aggressive excludes for course / homework repos |
| Indie | `indie.toml` | Balanced for small personal projects |
| Small team | `small-team.toml` | Stricter entropy, fewer excludes |

```bash
watchwire scan . --config examples/policies/indie.toml
watchwire scan . --config examples/policies/student.toml
watchwire scan . --config examples/policies/small-team.toml
```

Copy a pack to `./watchwire.toml` or keep pointing `--config` at it.

Example schema (see also [`examples/watchwire.toml`](examples/watchwire.toml)):

```toml
[scan]
# Additive excludes (defaults already cover node_modules, *.lock, poetry.lock, …)
exclude = ["**/vendor/**", "**/*.min.js"]
# use_default_excludes = true
min_entropy = 4.5
min_entropy_length = 20

[rules]
aws_access_key_id = true
github_token = true
github_fine_grained = true
private_key_header = true
slack_token = true
generic_api_key_assignment = true
high_entropy = true   # alias: entropy = true|false
```

| Key | Meaning |
|-----|---------|
| `[scan].exclude` | Path globs to skip (`**` supported) |
| `[scan].use_default_excludes` | Keep built-in lockfile/vendor globs (default `true`) |
| `[scan].min_entropy` | Shannon threshold for `high_entropy` (default `4.5`) |
| `[scan].min_entropy_length` | Min token length for entropy pass (default `20`) |
| `[rules].*` | Booleans to enable/disable rule kinds |

**Entropy FP classes** (auto-suppressed; see `tests/fixtures/fp/`): UUIDs, pure
hex digests ≥32 chars, low-diversity base64 padding. Lockfile hashes are also
skipped via default exclude globs.

### Process summary (`/proc`)

```bash
watchwire proc          # list processes
watchwire proc 42       # detail one PID
```

Shows cmdline, open FD count, VmRSS / VmSize, and state. Read-only; no signals sent to processes.

### Filesystem hygiene

```bash
watchwire hygiene /path/to/tree
```

Reports **world-writable**, **setuid**, and **setgid** entries. Useful before packaging artifacts or reviewing shared directories.

---

## Use in CI

OSS core stays local-first: these integrations run the same scanner in your pipeline. No SaaS claims; pin a tag/SHA for reproducibility.

### Pre-commit

In another repo’s `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/maxmccutcheon59/watchwire
    rev: v0.5.0   # or a commit SHA
    hooks:
      - id: watchwire-scan
```

The hook scans staged / `pass_filenames` paths and fails (exit `1`) on findings.

### Composite GitHub Action

Root [`action.yml`](action.yml) installs Watchwire from this repo and runs `scan`. Example consumer workflow (also under [`examples/github-action-scan.yml`](examples/github-action-scan.yml)):

```yaml
- uses: actions/checkout@v4

- name: Scan with Watchwire
  id: ww
  uses: maxmccutcheon59/watchwire@v0.5.0   # pin tag or SHA
  with:
    path: "."
    sarif-file: watchwire.sarif
    fail-on-findings: "true"
    run-hygiene: "false"   # set "true" to also run `watchwire hygiene`

- name: Upload SARIF (optional)
  if: success() || failure()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.ww.outputs.sarif-path }}
```

Optional `run-hygiene: true` runs `watchwire hygiene` on the same path after
the secret scan (writes `watchwire-hygiene.json`). Default is `false` so
existing scan / SARIF wiring stays unchanged.

Requires `permissions: security-events: write` for Code Scanning upload. **Not** published to the GitHub Marketplace yet — use `uses: maxmccutcheon59/watchwire@…` directly.

### JSON / SARIF

| Flag | Commands | Notes |
|------|----------|--------|
| `--json` | `scan`, `hygiene`, `proc` | Stable schema; exit codes unchanged (`1` on findings for scan/hygiene) |
| `--sarif` / `--format sarif` | `scan` | SARIF 2.1.0; redacted messages; rule ids = finding kinds |
| `-o FILE` / `--sarif-file FILE` | `scan` (and `-o` for JSON) | Write to file for upload-sarif |

---

## Architecture

```
watchwire/
├── action.yml                 # composite Action (scan + optional SARIF / hygiene)
├── .pre-commit-hooks.yaml     # reusable pre-commit hook definition
├── ci/
│   ├── consumer-scan.yml      # 5-min consumer CI template (@v0.5.0)
│   └── security-ci.yml        # gitleaks + pip-audit reference jobs
├── examples/
│   ├── github-action-scan.yml
│   ├── .watchwireignore
│   ├── watchwire.toml
│   ├── suppressions/          # example suppressions TOML
│   └── policies/              # student / indie / small-team packs
├── CHANGELOG.md
├── src/watchwire/
│   ├── cli.py           # scan / init / proc / hygiene
│   ├── scan.py          # walk tree → regex + entropy
│   ├── ignore.py        # .watchwireignore (gitignore-style)
│   ├── suppressions.py  # path + rule allowlist
│   ├── staged.py        # git staged file list (local only)
│   ├── policy.py        # watchwire.toml loader
│   ├── output.py        # JSON + SARIF 2.1.0
│   ├── entropy.py       # Shannon + FP filters
│   ├── proc.py          # /proc reader
│   └── hygiene.py       # permission bit checks
├── tests/
│   ├── fixtures/        # fake secrets + fp/ (must stay clean)
│   └── test_*.py
└── .github/workflows/ci.yml
```

**Design choices**

- **Local-only**: no HTTP clients, no telemetry, no cloud API keys.
- **Injectable `/proc` root**: tests use a fake tree; production uses `/proc`.
- **Redaction**: findings print truncated snippets, not full secrets.
- **Stdlib runtime**: easy to audit; optional `pytest` / `ruff` only for development.
- **CI-friendly**: JSON/SARIF, pre-commit, and a composite Action — still no off-box exfiltration by the tool itself.
- **Policy file**: optional `watchwire.toml` for path globs and rule toggles; example packs under `examples/policies/`.
- **Ignore + suppressions**: `.watchwireignore` (gitignore-style) and optional path+rule suppressions file; staged-only scan via local git.
- **Init**: `watchwire init` writes starter policy/ignore files for new repos.

---

## What Watchwire is NOT

- **Not** an exploit framework, scanner for remote targets, or penetration-testing toolkit.
- **Not** a replacement for dedicated secret managers (Vault, cloud KMS) or full EDR.
- **Not** guaranteed to catch every secret format — entropy and regex are heuristics with false positives/negatives.
- **Not** a SaaS product, company traction claim, or Marketplace-listed Action (yet) — this is an open-source learning / portfolio tool with optional CI wiring.
- **Not** a network monitor or packet capture utility.

If you need enterprise secret scanning in CI at scale, evaluate established tools (e.g. gitleaks, trufflehog) alongside or instead of Watchwire.

---

## Development

```bash
pip install -e ".[dev]"
ruff check src tests
pytest -v
```

CI runs on Python 3.10 / 3.12 / 3.13 via GitHub Actions (pytest + ruff).

---

## License

MIT — see [LICENSE](LICENSE).

---

## Author

Max McCutcheon — [github.com/maxmccutcheon59](https://github.com/maxmccutcheon59)
