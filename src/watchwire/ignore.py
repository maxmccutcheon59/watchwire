"""Load and match ``.watchwireignore`` (gitignore-style). Local-only; no network."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from watchwire.policy import path_matches_glob


@dataclass(frozen=True)
class IgnoreRule:
    """One parsed ignore line."""

    pattern: str
    negated: bool = False
    directory_only: bool = False


@dataclass
class IgnoreMatcher:
    """gitignore-style matcher relative to *base* (directory of the ignore file)."""

    base: Path
    rules: list[IgnoreRule] = field(default_factory=list)
    source: Path | None = None

    def is_ignored(self, path: Path) -> bool:
        """Return True if *path* is ignored (last matching rule wins; ``!`` un-ignores)."""
        try:
            rel = path.resolve().relative_to(self.base.resolve()).as_posix()
        except (ValueError, OSError):
            # Outside base — do not ignore via this file.
            return False
        if rel in ("", "."):
            return False

        is_dir = path.is_dir()
        ignored = False
        for rule in self.rules:
            if rule.directory_only and not is_dir:
                # Still match files under a directory pattern via **/ trailing logic
                # by testing the path as if under the dir, but gitignore treats
                # trailing-/ rules as directory-only for the named entry itself.
                # For files, match "dir/**" semantics when pattern is "dir/".
                dir_pat = rule.pattern.rstrip("/")
                if not (
                    path_matches_glob(rel, dir_pat)
                    or path_matches_glob(rel, dir_pat + "/**")
                    or path_matches_glob(rel, "**/" + dir_pat)
                    or path_matches_glob(rel, "**/" + dir_pat + "/**")
                ):
                    continue
            else:
                if not _rule_matches(rel, rule.pattern, directory_only=rule.directory_only):
                    continue
            ignored = not rule.negated
        return ignored


def _rule_matches(rel: str, pattern: str, *, directory_only: bool) -> bool:
    """Match *rel* (posix, relative) against a single gitignore-ish *pattern*."""
    pat = pattern.replace("\\", "/").strip()
    if not pat:
        return False
    # Bare name without slash → match in any directory (gitignore semantics).
    if "/" not in pat.rstrip("/"):
        candidates = (
            pat,
            "**/" + pat,
            pat + "/**",
            "**/" + pat + "/**",
        )
    elif pat.startswith("/"):
        # Anchored to base
        candidates = (pat.lstrip("/"),)
    else:
        candidates = (pat, "**/" + pat if not pat.startswith("**/") else pat)
        if pat.endswith("/"):
            stem = pat.rstrip("/")
            candidates = (stem, stem + "/**", "**/" + stem, "**/" + stem + "/**")
        elif directory_only:
            candidates = (pat, pat + "/**", "**/" + pat, "**/" + pat + "/**")

    for c in candidates:
        c = c.rstrip("/") if c.endswith("/") and not c.endswith("/**") else c
        if path_matches_glob(rel, c):
            return True
        # Basename fallthrough already in path_matches_glob for simple globs
    return False


def parse_ignore_text(text: str) -> list[IgnoreRule]:
    """Parse gitignore-style text into rules (order preserved)."""
    rules: list[IgnoreRule] = []
    for raw in text.splitlines():
        line = raw.rstrip("\n\r")
        if not line.strip():
            continue
        if line.lstrip().startswith("#"):
            continue
        # Leading escaped \# is a literal; treat simple # comments only at start
        negated = False
        if line.startswith("!"):
            negated = True
            line = line[1:]
        if not line:
            continue
        directory_only = line.endswith("/")
        pattern = line.rstrip("/") if directory_only else line
        # Unescape leading \#
        if pattern.startswith("\\#"):
            pattern = pattern[1:]
        rules.append(
            IgnoreRule(pattern=pattern, negated=negated, directory_only=directory_only)
        )
    return rules


def load_ignore_file(path: str | Path) -> IgnoreMatcher:
    """Load ``.watchwireignore`` from *path*. Raises FileNotFoundError if missing."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"ignore file not found: {p}")
    text = p.read_text(encoding="utf-8", errors="replace")
    base = p.parent.resolve()
    return IgnoreMatcher(base=base, rules=parse_ignore_text(text), source=p)


def find_ignore_file(start: Path | None = None) -> Path | None:
    """Return ``.watchwireignore`` in *start* (default: cwd) if present."""
    base = start if start is not None else Path.cwd()
    candidate = base / ".watchwireignore"
    if candidate.is_file():
        return candidate
    return None


def resolve_ignore(
    *,
    ignore_file: str | Path | None = None,
    cwd: Path | None = None,
    scan_root: Path | None = None,
) -> IgnoreMatcher | None:
    """Load explicit ``--ignore-file``, else ``./.watchwireignore``, else under scan root."""
    if ignore_file is not None:
        return load_ignore_file(ignore_file)
    base = cwd if cwd is not None else Path.cwd()
    found = find_ignore_file(base)
    if found is not None:
        return load_ignore_file(found)
    if scan_root is not None:
        root = scan_root if scan_root.is_dir() else scan_root.parent
        found = find_ignore_file(root)
        if found is not None:
            return load_ignore_file(found)
    return None


# Starter content written by ``watchwire init``.
STARTER_WATCHWIREIGNORE = """\
# .watchwireignore — gitignore-style paths Watchwire will skip (local-only).
# Docs: README → Sellable v1. Abuse of broad ignores can hide real secrets;
# prefer narrow patterns and review in PRs.

# VCS / virtualenvs / caches
.git/
.hg/
.svn/
__pycache__/
.pytest_cache/
.mypy_cache/
.tox/
.venv/
venv/
node_modules/

# Build / dist
dist/
build/
*.egg-info/
*.min.js
*.min.css

# Lockfiles (integrity hashes trip entropy heuristics)
*.lock
package-lock.json
yarn.lock
pnpm-lock.yaml
poetry.lock
Pipfile.lock
Cargo.lock
composer.lock
Gemfile.lock
go.sum
"""
