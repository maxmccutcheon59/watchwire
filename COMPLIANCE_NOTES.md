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

## Items needing human review before commercial use

- [ ] Privacy Policy / Terms if a hosted or multi-user product is built on top of this CLI
- [ ] Organizational acceptable-use policy alignment for internal deployment
- [ ] Any future network features (webhooks, SaaS upload) — would require fresh threat model + privacy review
