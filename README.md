# Watchwire

**Local-first defensive CLI** for catching leaked secrets, inspecting Linux processes, and spotting risky file permissions — without sending anything off-box.

Built as a portfolio / internship project demonstrating practical defensive security tooling in pure Python (stdlib only at runtime).

---

## The problem

Credentials and private keys still leak into repos, config dumps, and scratch files. Operators also need quick answers about “what is this process doing?” and “are there world-writable or setuid files under this tree?” — without installing a heavyweight agent or shipping filesystem contents to a SaaS scanner.

Watchwire answers those questions **locally**: regex + entropy for secrets, `/proc` reads for processes, and permission bits for hygiene. No network exfiltration by design.

---

## Install

```bash
# From source (recommended while evaluating)
git clone https://github.com/maxmccutcheon59/watchwire.git
cd watchwire
pip install -e ".[dev]"
```

Requires **Python 3.10+**. Runtime depends on the standard library only. The `proc` subcommand is Linux-oriented (`/proc`).

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

Matches are **redacted** in output. Exit code `1` if findings exist (CI-friendly); `0` if clean.

```bash
# Example (fake fixture values)
$ watchwire scan tests/
…/aws.env:1: [aws_access_key_id] AKIA…0000
2 finding(s)
```

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

## Architecture

```
watchwire/
├── src/watchwire/
│   ├── cli.py        # argparse entry; subcommands only
│   ├── scan.py       # walk tree → regex patterns + entropy
│   ├── entropy.py    # Shannon entropy helper
│   ├── proc.py       # /proc reader (proc_root injectable)
│   └── hygiene.py    # permission bit checks
├── tests/            # pytest; fake secrets + mocked /proc
└── .github/workflows/ci.yml
```

**Design choices**

- **Local-only**: no HTTP clients, no telemetry, no cloud API keys.
- **Injectable `/proc` root**: tests use a fake tree; production uses `/proc`.
- **Redaction**: findings print truncated snippets, not full secrets.
- **Stdlib runtime**: easy to audit; optional `pytest` only for development.

---

## What Watchwire is NOT

- **Not** an exploit framework, scanner for remote targets, or penetration-testing toolkit.
- **Not** a replacement for dedicated secret managers (Vault, cloud KMS) or full EDR.
- **Not** guaranteed to catch every secret format — entropy and regex are heuristics with false positives/negatives.
- **Not** a SaaS product, company, or revenue claim — this is an open-source learning / portfolio tool.
- **Not** a network monitor or packet capture utility.

If you need enterprise secret scanning in CI at scale, evaluate established tools (e.g. gitleaks, trufflehog) alongside or instead of Watchwire.

---

## Development

```bash
pip install -e ".[dev]"
pytest -v
```

CI runs on Python 3.10–3.13 via GitHub Actions.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Author

Max McCutcheon — [github.com/maxmccutcheon59](https://github.com/maxmccutcheon59)
