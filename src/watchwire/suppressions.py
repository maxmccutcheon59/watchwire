"""Path + rule-id suppressions allowlist (local file). See COMPLIANCE_NOTES abuse risk."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

from watchwire.policy import path_matches_glob

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib  # type: ignore[import-not-found,no-redef]
    except ModuleNotFoundError:  # pragma: no cover
        import tomli as tomllib  # type: ignore[no-redef]


@dataclass(frozen=True)
class Suppression:
    """One allowlisted (path glob, rule kind) pair."""

    path: str
    rule: str
    reason: str = ""


@dataclass
class SuppressionSet:
    """Collection of suppressions loaded from a local TOML file."""

    items: list[Suppression] = field(default_factory=list)
    source: Path | None = None

    def matches(self, *, path: str, rule: str) -> bool:
        """True if *path* + *rule* is allowlisted (should not be reported)."""
        normalized = path.replace("\\", "/")
        name = normalized.rsplit("/", 1)[-1]
        for item in self.items:
            rule_ok = item.rule == "*" or item.rule == rule
            if not rule_ok:
                # entropy alias
                if item.rule == "entropy" and rule == "high_entropy":
                    rule_ok = True
                elif item.rule == "high_entropy" and rule == "entropy":
                    rule_ok = True
            if not rule_ok:
                continue
            if path_matches_glob(normalized, item.path) or path_matches_glob(name, item.path):
                return True
            # Also try matching basename-anchored globs against full path suffixes
            if path_matches_glob(normalized, "**/" + item.path.lstrip("./")):
                return True
        return False


def load_suppressions(path: str | Path) -> SuppressionSet:
    """Load suppressions TOML. Raises FileNotFoundError / ValueError."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"suppressions file not found: {p}")
    raw = p.read_bytes()
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"invalid TOML in {p}: {exc}") from exc
    return suppressions_from_dict(data, source=p)


def suppressions_from_dict(
    data: dict, *, source: Path | None = None
) -> SuppressionSet:
    """Build SuppressionSet from parsed TOML."""
    if not isinstance(data, dict):
        raise ValueError("suppressions root must be a table")
    rows = data.get("suppress", []) or []
    if not isinstance(rows, list):
        raise ValueError("[[suppress]] must be an array of tables")
    items: list[Suppression] = []
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"suppress[{i}] must be a table")
        path = row.get("path")
        rule = row.get("rule")
        reason = row.get("reason", "") or ""
        if not isinstance(path, str) or not path.strip():
            raise ValueError(f"suppress[{i}].path must be a non-empty string")
        if not isinstance(rule, str) or not rule.strip():
            raise ValueError(f"suppress[{i}].rule must be a non-empty string")
        if not isinstance(reason, str):
            raise ValueError(f"suppress[{i}].reason must be a string")
        items.append(Suppression(path=path.strip(), rule=rule.strip(), reason=reason.strip()))
    return SuppressionSet(items=items, source=source)


def find_suppressions_file(start: Path | None = None) -> Path | None:
    """Return ``watchwire.suppressions.toml`` in *start* (default: cwd) if present."""
    base = start if start is not None else Path.cwd()
    candidate = base / "watchwire.suppressions.toml"
    if candidate.is_file():
        return candidate
    return None


def resolve_suppressions(
    *,
    suppressions: str | Path | None = None,
    cwd: Path | None = None,
) -> SuppressionSet | None:
    """Load ``--suppressions`` path, else ``./watchwire.suppressions.toml``, else None."""
    if suppressions is not None:
        return load_suppressions(suppressions)
    found = find_suppressions_file(cwd)
    if found is not None:
        return load_suppressions(found)
    return None


def apply_suppressions(
    findings: list,
    suppressions: SuppressionSet | None,
) -> list:
    """Filter *findings* that match the allowlist. Returns a new list."""
    if suppressions is None or not suppressions.items:
        return list(findings)
    return [f for f in findings if not suppressions.matches(path=f.path, rule=f.kind)]


STARTER_SUPPRESSIONS = """\
# watchwire.suppressions.toml — optional path + rule allowlist for noisy repos.
#
# ABUSE RISK: suppressions can hide REAL secrets. Prefer fixing the leak,
# narrowing .watchwireignore / [scan].exclude, or disabling a rule in
# watchwire.toml only when justified. Review every entry in PRs. See
# COMPLIANCE_NOTES.md.
#
# [[suppress]]
# path = "docs/examples/demo.env"
# rule = "aws_access_key_id"
# reason = "synthetic demo credential; reviewed YYYY-MM-DD"
#
# rule may be a kind name (e.g. high_entropy) or "*" (all rules for that path).

# Example (commented out — uncomment only after human review):
# [[suppress]]
# path = "tests/fixtures/**"
# rule = "*"
# reason = "intentional synthetic fixtures only"
"""
