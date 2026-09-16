"""Filesystem hygiene — world-writable and setuid/setgid findings."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

SKIP_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
}


@dataclass(frozen=True)
class HygieneFinding:
    """A permission-related finding."""

    path: str
    kind: str
    mode: str

    def format(self) -> str:
        return f"{self.path}: [{self.kind}] mode={self.mode}"


def _mode_octal(mode: int) -> str:
    return oct(stat.S_IMODE(mode))


def _iter_paths(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Prune skipped directories in-place
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        base = Path(dirpath)
        yield base
        for name in filenames:
            yield base / name


def check_hygiene(target: str | Path) -> list[HygieneFinding]:
    """Find world-writable and setuid/setgid entries under *target*."""
    root = Path(target).resolve()
    if not root.exists():
        raise FileNotFoundError(f"path not found: {root}")

    findings: list[HygieneFinding] = []
    for path in _iter_paths(root):
        try:
            st = path.lstat()
        except OSError:
            continue

        mode = st.st_mode
        imode = stat.S_IMODE(mode)
        kinds: list[str] = []

        if imode & stat.S_IWOTH:
            kinds.append("world_writable")
        if mode & stat.S_ISUID:
            kinds.append("setuid")
        if mode & stat.S_ISGID:
            kinds.append("setgid")

        for kind in kinds:
            findings.append(
                HygieneFinding(
                    path=str(path),
                    kind=kind,
                    mode=_mode_octal(mode),
                )
            )
    return findings
