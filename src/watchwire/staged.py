"""List git staged files for ``watchwire scan --staged`` (local git only; no network)."""

from __future__ import annotations

import subprocess
from pathlib import Path


class StagedError(RuntimeError):
    """Raised when staged-file resolution fails (not a git repo, git missing, etc.)."""


def _run_git(args: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    """Run git with an argv list (never a shell). Local only."""
    try:
        return subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except FileNotFoundError as exc:
        raise StagedError(
            "git executable not found; --staged requires git on PATH"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise StagedError("git timed out while listing staged files") from exc


def find_git_toplevel(start: Path | None = None) -> Path:
    """Return the git work-tree root for *start* (default: cwd)."""
    base = (start if start is not None else Path.cwd()).resolve()
    proc = _run_git(["rev-parse", "--show-toplevel"], cwd=base)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip() or "not a git repository"
        raise StagedError(f"not a git repository (or git error): {err}")
    root = Path(proc.stdout.strip())
    if not root.is_dir():
        raise StagedError(f"git toplevel is not a directory: {root}")
    return root.resolve()


def list_staged_files(*, cwd: Path | None = None) -> list[Path]:
    """Return absolute paths of staged (cached index) files. Local ``git diff --cached`` only.

    Uses ``--diff-filter=ACMR`` (added/copied/modified/renamed). Deleted staged
    paths are omitted (nothing to scan). Never contacts a remote.
    """
    base = (cwd if cwd is not None else Path.cwd()).resolve()
    root = find_git_toplevel(base)
    proc = _run_git(
        [
            "diff",
            "--cached",
            "--name-only",
            "--diff-filter=ACMR",
            "-z",
        ],
        cwd=root,
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip() or "git diff --cached failed"
        raise StagedError(err)

    raw = proc.stdout
    if not raw:
        return []
    # -z → NUL-separated; trailing NUL yields empty last chunk
    names = [n for n in raw.split("\0") if n]
    out: list[Path] = []
    for name in names:
        # Reject absolute / traversal attempts from git output (defensive).
        if name.startswith("/") or name.startswith("\\") or ".." in Path(name).parts:
            continue
        candidate = (root / name).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        if candidate.is_file():
            out.append(candidate)
    return out


def filter_staged_under(
    staged: list[Path], roots: list[Path]
) -> list[Path]:
    """Keep staged files that lie under any of *roots* (files or directories)."""
    if not roots:
        return list(staged)
    resolved_roots: list[Path] = []
    for r in roots:
        try:
            resolved_roots.append(r.resolve())
        except OSError:
            continue
    kept: list[Path] = []
    for path in staged:
        for root in resolved_roots:
            try:
                if root.is_file():
                    if path == root:
                        kept.append(path)
                        break
                else:
                    path.relative_to(root)
                    kept.append(path)
                    break
            except ValueError:
                continue
            except OSError:
                continue
    return kept
