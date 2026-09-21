# Compliance Notes — Watchwire

> Human / lawyer review recommended before any commercial or organizational deployment.
> This file flags legal and compliance-relevant aspects; it is **not** legal advice.

## Product posture

- **Defensive and local-first:** Local secret scanning, process inspection via `/proc`, and file-permission hygiene. Stdlib-only at runtime.
- **No network exfiltration by design** for core scan/inspect paths (reads local files / `/proc` / permission bits).
- Portfolio / educational project demonstrating defensive systems and security tooling.

## Authorized systems only

Operators must only run Watchwire on:

1. Machines and trees **they own**, or
2. Environments where they have **written authorization** to perform defensive checks.

Unauthorized use against third-party systems can implicate the CFAA and related computer-crime / unauthorized-access laws, as well as contractual Terms of Service. See also `SECURITY.md`.

## Data handled

| Data | Collected? | Stored? | Shared? |
|------|------------|---------|---------|
| Source / config file contents during scan | Read locally when scanning | Not retained by tool (stdout/files you choose) | No (local only) |
| Process metadata from `/proc` | Read locally | Not retained by tool | No (local only) |
| File permission metadata | Read locally | Not retained by tool | No (local only) |
| Telemetry / analytics | **None** | — | — |
| Accounts / cloud sync | **None** | — | — |

## Privacy / regulatory flags

- **No SaaS, no accounts, no intentional PII collection** in the default CLI.
- If an operator points Watchwire at directories containing personal data, secrets, or regulated content, **the operator** remains responsible for lawful handling of that data (GDPR/CCPA/etc.). The tool does not implement DSAR export/deletion because it does not operate a service that stores user PII.
- **Export controls:** general-purpose defensive utilities; no cryptographic export product claims. Escalate if packaging for sanctioned jurisdictions.

## Security tooling ethics

- Report-only / defensive checks; no exploit payloads, privilege escalation, or unauthorized access features.
- Fixture secrets in tests (if any) are **synthetic** and must never be real credentials.

## Suppressions allowlist — abuse risk

`watchwire.suppressions.toml` (and `--suppressions`) is a **path + rule-id allowlist**.
Matched findings are dropped from the report and do not fail CI.

**Risks**

- Operators (or a malicious PR) can suppress **real** secrets by adding broad
  entries such as `path = "**"` / `rule = "*"` or silencing high-value rules
  (`private_key_header`, `aws_access_key_id`, token kinds).
- Suppressions are not a substitute for rotating exposed credentials.
- Unlike `.watchwireignore` (skip reading a path) or `[scan].exclude`, suppressions
  imply “we looked and accept this hit” — that claim can be false if entries are
  rubber-stamped.

**Required practice (operators)**

1. Prefer fixing the leak, rotating credentials, or narrowing excludes/ignores.
2. Every `[[suppress]]` row should include a human `reason` and a review date.
3. Require PR review for changes to suppressions / ignore / policy files.
4. Never commit real secrets “under” a suppression; fixtures must stay synthetic.
5. Treat suppressions as temporary debt — revisit and delete when possible.

Flag for human / lawyer review before organizational mandates that rely on
suppressions as an acceptance control.

## Items needing human review before commercial use

- [ ] Privacy Policy / Terms if a hosted or multi-user product is built on top of this CLI
- [ ] Organizational acceptable-use policy alignment for internal deployment
- [ ] Any future network features (webhooks, SaaS upload) — would require fresh threat model + privacy review
- [ ] Organizational policy for suppressions / ignore governance (who may approve allowlist entries)
