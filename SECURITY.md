# Security Policy

## Supported versions

Security fixes are applied on the latest release of **Watchwire** on `main`. Older tags are not backported unless noted in a release.

## Reporting a vulnerability

Please report security issues privately — do **not** open a public GitHub issue for undisclosed vulnerabilities.

- **Contact:** [MaxMcCutcheon1@outlook.com](mailto:MaxMcCutcheon1@outlook.com)
- Include: affected version/commit, reproduction steps, impact, and any suggested fix.
- You should receive an acknowledgment within a few business days.

We will work with you to understand and remediate the issue, then credit reporters who want acknowledgment (optional).

## Authorized testing only

Watchwire is a **defensive / educational** tool. You may only run it against systems **you own** or for which you have **explicit written authorization**.

Unauthorized scanning, access, or testing of third-party systems may violate the Computer Fraud and Abuse Act (CFAA), similar laws, and site Terms of Service. Do not use this software to attack, probe, or exfiltrate from systems without permission.

- Prefer scanning your own working trees and CI checkouts you control.
## Secrets and credentials

- Never commit secrets (`.env`, API keys, tokens, private keys).
- Use environment variables or a secrets manager for any credentials.
- If a secret is exposed: **rotate it first**, then clean history if needed.

## Preferred disclosure process

1. Email the contact above with details.
2. Allow reasonable time for a fix before public disclosure.
3. Coordinated disclosure is appreciated; please do not weaponize findings.

## Local controls (ignore / suppressions / staged)

- `.watchwireignore` and `watchwire.toml` `[scan].exclude` skip paths locally.
- `watchwire.suppressions.toml` can silence findings by path + rule — treat as a
  privileged allowlist (see `COMPLIANCE_NOTES.md`). Abuse can hide real secrets.
- `watchwire scan --staged` reads the local git index only; it does not contact remotes.

