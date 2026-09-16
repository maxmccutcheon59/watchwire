"""Watchwire CLI entry point."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from watchwire import __version__
from watchwire.hygiene import check_hygiene
from watchwire.output import (
    dumps_json,
    dumps_sarif,
    findings_to_json_dict,
    findings_to_sarif,
    hygiene_to_json_dict,
    proc_to_json_dict,
)
from watchwire.proc import list_pids, summarize_pid
from watchwire.scan import Finding, scan_path


def _emit(text: str, output: Path | None) -> None:
    if output is not None:
        output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def _scan_paths(paths: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        findings.extend(scan_path(path))
    return findings


def _resolve_scan_format(args: argparse.Namespace) -> str:
    if getattr(args, "sarif_file", None) is not None:
        return "sarif"
    if getattr(args, "sarif", False):
        return "sarif"
    if getattr(args, "json", False):
        return "json"
    return getattr(args, "format", "text") or "text"


def _cmd_scan(args: argparse.Namespace) -> int:
    paths: list[Path] = args.paths
    path_label = str(paths[0]) if len(paths) == 1 else f"{len(paths)} paths"
    try:
        findings = _scan_paths(paths)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    fmt = _resolve_scan_format(args)
    output: Path | None = getattr(args, "output", None)
    if output is None and getattr(args, "sarif_file", None) is not None:
        output = args.sarif_file

    if fmt == "json":
        doc = findings_to_json_dict(findings, path=path_label, command="scan")
        _emit(dumps_json(doc), output)
    elif fmt == "sarif":
        sarif_path = str(paths[0].resolve()) if paths else path_label
        doc = findings_to_sarif(findings, path=sarif_path)
        _emit(dumps_sarif(doc), output)
    else:
        if not findings:
            print(f"No secret-like findings under {path_label}")
        else:
            for f in findings:
                print(f.format())
            print(f"\n{len(findings)} finding(s)")

    return 1 if findings else 0


def _cmd_proc(args: argparse.Namespace) -> int:
    proc_root = args.proc_root
    try:
        if args.pid is not None:
            summary = summarize_pid(args.pid, proc_root=proc_root)
            if args.json:
                doc = proc_to_json_dict([summary], proc_root=str(proc_root))
                _emit(dumps_json(doc), args.output)
            else:
                print(summary.format())
            return 0

        pids = list_pids(proc_root=proc_root)
        summaries = []
        for pid in pids:
            try:
                summaries.append(summarize_pid(pid, proc_root=proc_root))
            except (FileNotFoundError, PermissionError, OSError):
                continue

        if args.json:
            doc = proc_to_json_dict(summaries, proc_root=str(proc_root))
            _emit(dumps_json(doc), args.output)
            return 0

        if not summaries:
            print("No processes found")
            return 0
        for s in summaries:
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

    if args.json:
        doc = hygiene_to_json_dict(findings, path=str(args.path))
        _emit(dumps_json(doc), args.output)
    elif not findings:
        print(f"No world-writable or setuid/setgid findings under {args.path}")
    else:
        for f in findings:
            print(f.format())
        print(f"\n{len(findings)} finding(s)")

    return 1 if findings else 0


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
    scan_p.add_argument(
        "paths",
        nargs="+",
        type=Path,
        metavar="PATH",
        help="File(s) or directory(ies) to scan",
    )
    scan_p.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON findings (stable schema)",
    )
    scan_p.add_argument(
        "--sarif",
        action="store_true",
        help="Emit SARIF 2.1.0 (GitHub Code Scanning compatible)",
    )
    scan_p.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="Output format (default: text)",
    )
    scan_p.add_argument(
        "--sarif-file",
        type=Path,
        default=None,
        help="Write SARIF to FILE (implies --sarif)",
    )
    scan_p.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Write machine-readable output to FILE instead of stdout",
    )
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
    proc_p.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON process summaries",
    )
    proc_p.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Write JSON to FILE instead of stdout",
    )
    proc_p.set_defaults(func=_cmd_proc)

    hyg_p = sub.add_parser("hygiene", help="Find world-writable / setuid / setgid under PATH")
    hyg_p.add_argument("path", type=Path, help="File or directory to check")
    hyg_p.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON findings (stable schema)",
    )
    hyg_p.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Write JSON to FILE instead of stdout",
    )
    hyg_p.set_defaults(func=_cmd_hygiene)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
