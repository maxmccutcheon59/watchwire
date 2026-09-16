"""Watchwire CLI entry point."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from watchwire import __version__
from watchwire.hygiene import check_hygiene
from watchwire.proc import list_pids, summarize_pid
from watchwire.scan import scan_path


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        findings = scan_path(args.path)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not findings:
        print(f"No secret-like findings under {args.path}")
        return 0

    for f in findings:
        print(f.format())
    print(f"\n{len(findings)} finding(s)")
    return 1  # non-zero so CI can fail on leaks


def _cmd_proc(args: argparse.Namespace) -> int:
    proc_root = args.proc_root
    try:
        if args.pid is not None:
            summary = summarize_pid(args.pid, proc_root=proc_root)
            print(summary.format())
            return 0

        pids = list_pids(proc_root=proc_root)
        if not pids:
            print("No processes found")
            return 0
        for pid in pids:
            try:
                s = summarize_pid(pid, proc_root=proc_root)
            except (FileNotFoundError, PermissionError, OSError):
                continue
            rss = f"{s.vm_rss_kb} kB" if s.vm_rss_kb is not None else "?"
            cmd = (s.cmdline[:60] + "…") if len(s.cmdline) > 60 else s.cmdline
            print(f"{s.pid:>7}  fds={s.fd_count:<4}  rss={rss:<12}  {cmd or '(empty)'}")
        return 0
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _cmd_hygiene(args: argparse.Namespace) -> int:
    try:
        findings = check_hygiene(args.path)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not findings:
        print(f"No world-writable or setuid/setgid findings under {args.path}")
        return 0

    for f in findings:
        print(f.format())
    print(f"\n{len(findings)} finding(s)")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="watchwire",
        description=(
            "Local-first defensive CLI: scan for leaked secrets, "
            "summarize /proc, and check file hygiene. Never exfiltrates data."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Detect leaked secrets under PATH (local only)")
    scan_p.add_argument("path", type=Path, help="File or directory to scan")
    scan_p.set_defaults(func=_cmd_scan)

    proc_p = sub.add_parser("proc", help="Summarize Linux /proc entry for PID (or list all)")
    proc_p.add_argument(
        "pid",
        nargs="?",
        type=int,
        default=None,
        help="Process ID (omit to list summaries)",
    )
    proc_p.add_argument(
        "--proc-root",
        default=os.environ.get("WATCHWIRE_PROC_ROOT", "/proc"),
        help="Override /proc root (for tests)",
    )
    proc_p.set_defaults(func=_cmd_proc)

    hyg_p = sub.add_parser("hygiene", help="Find world-writable / setuid / setgid under PATH")
    hyg_p.add_argument("path", type=Path, help="File or directory to check")
    hyg_p.set_defaults(func=_cmd_hygiene)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
