"""Linux /proc process summary — read-only, local inspection."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProcSummary:
    """Summary of a single process from /proc."""

    pid: int
    cmdline: str
    fd_count: int
    vm_rss_kb: int | None
    vm_size_kb: int | None
    state: str | None

    def format(self) -> str:
        lines = [
            f"PID:      {self.pid}",
            f"State:    {self.state or 'unknown'}",
            f"Cmdline:  {self.cmdline or '(empty)'}",
            f"Open FDs: {self.fd_count}",
        ]
        if self.vm_rss_kb is not None:
            lines.append(f"VmRSS:    {self.vm_rss_kb} kB")
        if self.vm_size_kb is not None:
            lines.append(f"VmSize:   {self.vm_size_kb} kB")
        return "\n".join(lines)


def _read_cmdline(proc_dir: Path) -> str:
    raw = (proc_dir / "cmdline").read_bytes()
    # /proc/*/cmdline is NUL-separated
    parts = [p.decode("utf-8", errors="replace") for p in raw.split(b"\0") if p]
    return " ".join(parts)


def _count_fds(proc_dir: Path) -> int:
    fd_dir = proc_dir / "fd"
    try:
        return sum(1 for _ in fd_dir.iterdir())
    except (PermissionError, FileNotFoundError, OSError):
        return 0


def _parse_status(proc_dir: Path) -> tuple[str | None, int | None, int | None]:
    state: str | None = None
    vm_rss: int | None = None
    vm_size: int | None = None
    try:
        text = (proc_dir / "status").read_text(encoding="utf-8", errors="replace")
    except (PermissionError, FileNotFoundError, OSError):
        return state, vm_rss, vm_size

    for line in text.splitlines():
        if line.startswith("State:"):
            # e.g. "State:\tS (sleeping)"
            state = line.split(":", 1)[1].strip()
        elif line.startswith("VmRSS:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                vm_rss = int(parts[1])
        elif line.startswith("VmSize:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                vm_size = int(parts[1])
    return state, vm_rss, vm_size


def summarize_pid(pid: int, *, proc_root: str | Path = "/proc") -> ProcSummary:
    """Build a ProcSummary for *pid* under *proc_root* (injectable for tests)."""
    proc_dir = Path(proc_root) / str(pid)
    if not proc_dir.is_dir():
        raise FileNotFoundError(f"process not found: {pid}")

    cmdline = _read_cmdline(proc_dir)
    fd_count = _count_fds(proc_dir)
    state, vm_rss, vm_size = _parse_status(proc_dir)
    return ProcSummary(
        pid=pid,
        cmdline=cmdline,
        fd_count=fd_count,
        vm_rss_kb=vm_rss,
        vm_size_kb=vm_size,
        state=state,
    )


def list_pids(*, proc_root: str | Path = "/proc") -> list[int]:
    """Return numeric PIDs under *proc_root*."""
    root = Path(proc_root)
    pids: list[int] = []
    for entry in root.iterdir():
        if entry.name.isdigit() and entry.is_dir():
            pids.append(int(entry.name))
    return sorted(pids)
