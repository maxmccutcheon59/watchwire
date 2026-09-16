"""Local secret scanner — regex patterns + entropy. Never phones home."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from watchwire.entropy import looks_high_entropy
from watchwire.policy import ScanPolicy, default_policy

# Skip binary-ish and huge files by extension / size.
SKIP_EXTENSIONS = {
    ".pyc",
    ".pyo",
    ".so",
    ".o",
    ".a",
    ".dll",
    ".exe",
    ".bin",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp3",
    ".mp4",
    ".avi",
    ".mov",
}
# Directory name short-circuit (still applied; policy globs add lockfiles etc.).
SKIP_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".eggs",
}
MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MiB

# Known secret patterns. Fixtures use obvious placeholders (AKIAEXAMPLE…).
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "aws_access_key_id",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    ),
    (
        "github_token",
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{20,})\b"),
    ),
    (
        "github_fine_grained",
        re.compile(r"\b(github_pat_[A-Za-z0-9_]{20,})\b"),
    ),
    (
        "private_key_header",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    (
        "slack_token",
        re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b"),
    ),
    (
        "generic_api_key_assignment",
        re.compile(
            r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[=:]\s*['\"]?"
            r"([A-Za-z0-9_\-]{20,})['\"]?"
        ),
    ),
]

# Candidate tokens for entropy pass (base64-ish / hex-ish runs).
ENTROPY_CANDIDATE = re.compile(r"\b([A-Za-z0-9+/_\-]{24,}={0,2})\b")


@dataclass(frozen=True)
class Finding:
    """A single secret-like hit."""

    path: str
    line: int
    kind: str
    snippet: str

    def format(self) -> str:
        return f"{self.path}:{self.line}: [{self.kind}] {self.snippet}"


def _redact(match: str, keep: int = 4) -> str:
    if len(match) <= keep * 2:
        return "*" * len(match)
    return match[:keep] + "…" + match[-keep:]


def _iter_text_files(root: Path, policy: ScanPolicy) -> Iterator[Path]:
    if root.is_file():
        if not policy.is_path_excluded(root, root=root.parent):
            yield root
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIR_NAMES for part in path.parts):
            continue
        if path.suffix.lower() in SKIP_EXTENSIONS:
            continue
        if policy.is_path_excluded(path, root=root):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def _scan_line(path: str, line_no: int, line: str, policy: ScanPolicy) -> list[Finding]:
    findings: list[Finding] = []
    seen_spans: set[tuple[int, int]] = set()

    for kind, pattern in SECRET_PATTERNS:
        if not policy.is_rule_enabled(kind):
            continue
        for m in pattern.finditer(line):
            span = m.span(1) if m.lastindex else m.span(0)
            if span in seen_spans:
                continue
            seen_spans.add(span)
            raw = m.group(1) if m.lastindex else m.group(0)
            findings.append(
                Finding(
                    path=path,
                    line=line_no,
                    kind=kind,
                    snippet=_redact(raw),
                )
            )

    if policy.is_rule_enabled("high_entropy"):
        for m in ENTROPY_CANDIDATE.finditer(line):
            token = m.group(1)
            span = m.span(1)
            if span in seen_spans:
                continue
            # Skip if already matched a known pattern overlapping this span.
            if any(s[0] <= span[0] < s[1] or s[0] < span[1] <= s[1] for s in seen_spans):
                continue
            if looks_high_entropy(
                token,
                min_length=policy.min_entropy_length,
                threshold=policy.min_entropy,
            ):
                seen_spans.add(span)
                findings.append(
                    Finding(
                        path=path,
                        line=line_no,
                        kind="high_entropy",
                        snippet=_redact(token),
                    )
                )

    return findings


def scan_path(
    target: str | Path,
    *,
    policy: ScanPolicy | None = None,
) -> list[Finding]:
    """Scan *target* (file or directory) for leaked secrets. Local only."""
    root = Path(target).resolve()
    if not root.exists():
        raise FileNotFoundError(f"path not found: {root}")

    pol = policy if policy is not None else default_policy()
    results: list[Finding] = []
    for file_path in _iter_text_files(root, pol):
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(file_path)
        for line_no, line in enumerate(text.splitlines(), start=1):
            results.extend(_scan_line(rel, line_no, line, pol))
    return results
