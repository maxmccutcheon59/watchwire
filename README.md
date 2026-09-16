# Watchwire

[![CI](https://github.com/maxmccutcheon59/watchwire/actions/workflows/ci.yml/badge.svg)](https://github.com/maxmccutcheon59/watchwire/actions/workflows/ci.yml)

**Local-first defensive CLI** for catching leaked secrets, inspecting Linux processes, and spotting risky file permissions — without sending anything off-box.

Built as a portfolio / internship project demonstrating practical defensive security tooling in pure Python (stdlib only at runtime).

---

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
    rev: v0.2.0   # or a commit SHA
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
  uses: maxmccutcheon59/watchwire@v0.2.0   # pin tag or SHA
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
├── action.yml                 # composite GitHub Action (scan + optional SARIF)
├── .pre-commit-hooks.yaml     # reusable pre-commit hook definition
├── examples/github-action-scan.yml
├── src/watchwire/
│   ├── cli.py        # argparse entry; subcommands only
│   ├── scan.py       # walk tree → regex patterns + entropy
│   ├── output.py     # JSON + SARIF 2.1.0 serializers
│   ├── entropy.py    # Shannon entropy helper
│   ├── proc.py       # /proc reader (proc_root injectable)
│   └── hygiene.py    # permission bit checks
├── tests/
│   ├── fixtures/     # fake AKIA/ghp_/PEM/Slack samples
│   └── test_*.py
└── .github/workflows/ci.yml
```

**Design choices**

- **Local-only**: no HTTP clients, no telemetry, no cloud API keys.
- **Injectable `/proc` root**: tests use a fake tree; production uses `/proc`.
- **Redaction**: findings print truncated snippets, not full secrets.
- **Stdlib runtime**: easy to audit; optional `pytest` / `ruff` only for development.
- **CI-friendly**: JSON/SARIF, pre-commit, and a composite Action — still no off-box exfiltration by the tool itself.

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
