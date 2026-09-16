"""Load watchwire.toml scan policy (local-only; stdlib tomllib)."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib  # type: ignore[import-not-found,no-redef]
    except ModuleNotFoundError:  # pragma: no cover - py3.10 without tomli
        import tomli as tomllib  # type: ignore[no-redef]

# Rule kind names accepted under [rules] (entropy aliases high_entropy).
KNOWN_RULE_KINDS = frozenset(
    {
        "aws_access_key_id",
        "github_token",
        "github_fine_grained",
        "private_key_header",
        "slack_token",
        "generic_api_key_assignment",
        "high_entropy",
        "entropy",  # alias → high_entropy
    }
)

# Built-in path excludes (lockfiles + common vendor trees). Additive unless
# use_default_excludes = false in [scan].
DEFAULT_EXCLUDES: tuple[str, ...] = (
    "**/node_modules/**",
    "**/.git/**",
    "**/.hg/**",
    "**/.svn/**",
    "**/__pycache__/**",
    "**/.venv/**",
    "**/venv/**",
    "**/*.lock",
    "**/package-lock.json",
    "**/yarn.lock",
    "**/pnpm-lock.yaml",
    "**/Cargo.lock",
    "**/poetry.lock",
    "**/Pipfile.lock",
    "**/composer.lock",
    "**/Gemfile.lock",
    "**/go.sum",
)


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Convert a glob with ** / * / ? to a fullmatch regex (forward-slash paths)."""
    pattern = pattern.replace("\\", "/")
    out: list[str] = []
    i = 0
    n = len(pattern)
    while i < n:
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def path_matches_glob(path: str, pattern: str) -> bool:
    """True if *path* matches glob *pattern* (supports ``**``)."""
    normalized = path.replace("\\", "/")
    rx = _glob_to_regex(pattern)
    if rx.fullmatch(normalized):
        return True
    # Also try basename-only patterns like "*.lock"
    name = normalized.rsplit("/", 1)[-1]
    if rx.fullmatch(name):
        return True
    # Patterns like "**/foo/**" should match a directory prefix "…/foo/…"
    if not pattern.endswith("/**") and not pattern.endswith("/**/*"):
        # Try matching as if path were under a trailing /**
        if pattern.endswith("/**"):
            pass
    # Directory-style: "**/node_modules/**" should match files under node_modules
    # even when the path has no trailing slash segment beyond the dir.
    if "/**" in pattern or pattern.startswith("**/"):
        # Check each suffix of the path
        parts = normalized.split("/")
        for start in range(len(parts)):
            suffix = "/".join(parts[start:])
            if rx.fullmatch(suffix):
                return True
            if rx.fullmatch(suffix + "/"):
                return True
    return False


@dataclass
class ScanPolicy:
    """Scan policy from watchwire.toml (or defaults)."""

    exclude: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    # kind → enabled; missing kinds default to True
    rules: dict[str, bool] = field(default_factory=dict)
    min_entropy: float = 4.5
    min_entropy_length: int = 20
    use_default_excludes: bool = True
    config_path: Path | None = None

    def is_rule_enabled(self, kind: str) -> bool:
        """Return whether *kind* should produce findings."""
        if kind == "high_entropy" and "entropy" in self.rules:
            # Explicit entropy alias wins if high_entropy not set
            if "high_entropy" not in self.rules:
                return bool(self.rules["entropy"])
        if kind in self.rules:
            return bool(self.rules[kind])
        return True

    def is_path_excluded(self, path: Path, *, root: Path | None = None) -> bool:
        """True if *path* matches any exclude glob."""
        candidates: list[str] = [str(path).replace("\\", "/")]
        try:
            candidates.append(path.resolve().as_posix())
        except OSError:
            pass
        if root is not None:
            try:
                rel = path.resolve().relative_to(root.resolve()).as_posix()
                candidates.append(rel)
                candidates.append("./" + rel)
            except (ValueError, OSError):
                pass
        candidates.append(path.name)
        for cand in candidates:
            for pattern in self.exclude:
                if path_matches_glob(cand, pattern):
                    return True
        # Also match if any path component is an excluded directory name
        # covered by **/name/** patterns (already handled), but ensure
        # SKIP-style dirs still work when only basename appears.
        return False


def default_policy() -> ScanPolicy:
    """Return a ScanPolicy with built-in defaults (no file)."""
    return ScanPolicy()


def load_policy(path: str | Path) -> ScanPolicy:
    """Load policy from a TOML file. Raises FileNotFoundError / ValueError."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"config not found: {p}")
    raw = p.read_bytes()
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"invalid TOML in {p}: {exc}") from exc
    return policy_from_dict(data, config_path=p)


def policy_from_dict(data: dict, *, config_path: Path | None = None) -> ScanPolicy:
    """Build ScanPolicy from a parsed TOML table."""
    if not isinstance(data, dict):
        raise ValueError("config root must be a table")

    scan = data.get("scan", {}) or {}
    if not isinstance(scan, dict):
        raise ValueError("[scan] must be a table")

    rules_tbl = data.get("rules", {}) or {}
    if not isinstance(rules_tbl, dict):
        raise ValueError("[rules] must be a table")

    use_defaults = bool(scan.get("use_default_excludes", True))
    extra_exclude = scan.get("exclude", []) or []
    if not isinstance(extra_exclude, list):
        raise ValueError("[scan].exclude must be an array of strings")
    for item in extra_exclude:
        if not isinstance(item, str):
            raise ValueError("[scan].exclude entries must be strings")

    if use_defaults:
        exclude = list(DEFAULT_EXCLUDES)
        for g in extra_exclude:
            if g not in exclude:
                exclude.append(g)
    else:
        exclude = list(extra_exclude)

    min_entropy = float(scan.get("min_entropy", 4.5))
    min_entropy_length = int(scan.get("min_entropy_length", 20))
    if min_entropy_length < 1:
        raise ValueError("[scan].min_entropy_length must be >= 1")

    rules: dict[str, bool] = {}
    for key, val in rules_tbl.items():
        if not isinstance(key, str):
            raise ValueError("[rules] keys must be strings")
        if key not in KNOWN_RULE_KINDS:
            raise ValueError(
                f"unknown rule kind {key!r}; expected one of "
                f"{', '.join(sorted(KNOWN_RULE_KINDS))}"
            )
        if not isinstance(val, bool):
            raise ValueError(f"[rules].{key} must be a boolean")
        rules[key] = val

    return ScanPolicy(
        exclude=exclude,
        rules=rules,
        min_entropy=min_entropy,
        min_entropy_length=min_entropy_length,
        use_default_excludes=use_defaults,
        config_path=config_path,
    )


def find_config(start: Path | None = None) -> Path | None:
    """Return ``watchwire.toml`` in *start* (default: cwd) if present."""
    base = start if start is not None else Path.cwd()
    candidate = base / "watchwire.toml"
    if candidate.is_file():
        return candidate
    return None


def resolve_policy(*, config: str | Path | None = None, cwd: Path | None = None) -> ScanPolicy:
    """Load ``--config`` path, else ``./watchwire.toml``, else defaults."""
    if config is not None:
        return load_policy(config)
    found = find_config(cwd)
    if found is not None:
        return load_policy(found)
    return default_policy()
