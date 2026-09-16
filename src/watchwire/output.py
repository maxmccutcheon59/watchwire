"""Machine-readable output helpers (JSON + SARIF 2.1.0). Local only; no network."""

from __future__ import annotations

import json
from typing import Any

from watchwire import __version__
from watchwire.hygiene import HygieneFinding
from watchwire.proc import ProcSummary
from watchwire.scan import SECRET_PATTERNS, Finding

# Human-readable rule descriptions for SARIF (stable rule ids = Finding.kind).
RULE_DESCRIPTIONS: dict[str, str] = {
    "aws_access_key_id": "AWS Access Key ID pattern (AKIA…)",
    "github_token": "GitHub token pattern (ghp_/gho_/ghu_/ghs_/ghr_…)",
    "github_fine_grained": "GitHub fine-grained personal access token",
    "private_key_header": "PEM/OpenSSH private key header",
    "slack_token": "Slack API token pattern (xox…)",
    "generic_api_key_assignment": "Generic API/secret key assignment",
    "high_entropy": "High-entropy token (heuristic)",
}


def findings_to_json_dict(
    findings: list[Finding],
    *,
    path: str,
    command: str = "scan",
) -> dict[str, Any]:
    """Stable JSON document for scan findings."""
    return {
        "tool": "watchwire",
        "version": __version__,
        "command": command,
        "path": path,
        "finding_count": len(findings),
        "findings": [
            {
                "path": f.path,
                "line": f.line,
                "kind": f.kind,
                "snippet": f.snippet,
            }
            for f in findings
        ],
    }


def hygiene_to_json_dict(
    findings: list[HygieneFinding],
    *,
    path: str,
) -> dict[str, Any]:
    """Stable JSON document for hygiene findings."""
    return {
        "tool": "watchwire",
        "version": __version__,
        "command": "hygiene",
        "path": path,
        "finding_count": len(findings),
        "findings": [
            {
                "path": f.path,
                "kind": f.kind,
                "mode": f.mode,
            }
            for f in findings
        ],
    }


def proc_to_json_dict(
    summaries: list[ProcSummary],
    *,
    proc_root: str,
) -> dict[str, Any]:
    """Stable JSON document for proc summaries."""
    return {
        "tool": "watchwire",
        "version": __version__,
        "command": "proc",
        "proc_root": proc_root,
        "process_count": len(summaries),
        "processes": [
            {
                "pid": s.pid,
                "cmdline": s.cmdline,
                "fd_count": s.fd_count,
                "vm_rss_kb": s.vm_rss_kb,
                "vm_size_kb": s.vm_size_kb,
                "state": s.state,
            }
            for s in summaries
        ],
    }


def dumps_json(doc: dict[str, Any]) -> str:
    """Serialize a JSON document with stable formatting."""
    return json.dumps(doc, indent=2, sort_keys=False) + "\n"


def _sarif_rules() -> list[dict[str, Any]]:
    """SARIF rule metadata for known scan kinds (+ high_entropy)."""
    kinds = [kind for kind, _ in SECRET_PATTERNS] + ["high_entropy"]
    rules: list[dict[str, Any]] = []
    for kind in kinds:
        rules.append(
            {
                "id": kind,
                "name": kind,
                "shortDescription": {
                    "text": RULE_DESCRIPTIONS.get(kind, kind),
                },
                "fullDescription": {
                    "text": RULE_DESCRIPTIONS.get(kind, kind),
                },
                "defaultConfiguration": {"level": "error"},
                "helpUri": "https://github.com/maxmccutcheon59/watchwire",
            }
        )
    return rules


def _uri_for_path(path: str) -> str:
    """SARIF artifact URIs use forward slashes; keep relative when possible."""
    return path.replace("\\", "/")


def findings_to_sarif(
    findings: list[Finding],
    *,
    path: str | None = None,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from scan findings (redacted messages)."""
    results: list[dict[str, Any]] = []
    for f in findings:
        results.append(
            {
                "ruleId": f.kind,
                "level": "error",
                "message": {
                    "text": f"[{f.kind}] {f.snippet}",
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": _uri_for_path(f.path),
                            },
                            "region": {
                                "startLine": f.line,
                            },
                        }
                    }
                ],
            }
        )

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "watchwire",
                "version": __version__,
                "informationUri": "https://github.com/maxmccutcheon59/watchwire",
                "rules": _sarif_rules(),
            }
        },
        "results": results,
    }
    if path is not None:
        run["originalUriBaseIds"] = {
            "SCANROOT": {
                "uri": _uri_for_path(path if path.endswith("/") else path + "/"),
            }
        }

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


def dumps_sarif(doc: dict[str, Any]) -> str:
    """Serialize a SARIF document."""
    return json.dumps(doc, indent=2) + "\n"
