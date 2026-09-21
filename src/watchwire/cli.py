"""Watchwire CLI entry point."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from watchwire import __version__
from watchwire.hygiene import check_hygiene
from watchwire.ignore import STARTER_WATCHWIREIGNORE, resolve_ignore
from watchwire.output import (
    dumps_json,
    dumps_sarif,
    findings_to_json_dict,
    findings_to_sarif,
    hygiene_to_json_dict,
    proc_to_json_dict,
)
from watchwire.policy import ScanPolicy, resolve_policy
from watchwire.proc import list_pids, summarize_pid
from watchwire.scan import Finding, scan_files, scan_path
from watchwire.staged import StagedError, filter_staged_under, list_staged_files
from watchwire.suppressions import (
    STARTER_SUPPRESSIONS,
    apply_suppressions,
    resolve_suppressions,
)

STARTER_WATCHWIRE_TOML = """\
# watchwire.toml — local scan policy (created by `watchwire init`).
# Loaded automatically from the current working directory, or via --config PATH.
# Docs: README → Sellable v1 / Policy file.

[scan]
# Extra globs on top of built-in defaults (node_modules, *.lock, poetry.lock, …).
# Set use_default_excludes = false to replace defaults entirely.
exclude = [
  "**/vendor/**",
  "**/dist/**",
  "**/*.min.js",
]
# use_default_excludes = true
min_entropy = 4.5
min_entropy_length = 20

[rules]
# Pattern toggles — set false to disable a kind.
aws_access_key_id = true
github_token = true
github_fine_grained = true
private_key_header = true
slack_token = true
generic_api_key_assignment = true
# "entropy" is an alias for high_entropy
high_entropy = true
"""


def _emit(text: str, output: Path | None) -> None:
    if output is not None:
        output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def _scan_paths(
    paths: list[Path],
    policy: ScanPolicy,
    *,
    ignore=None,
) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        findings.extend(scan_path(path, policy=policy, ignore=ignore))
    return findings


def _resolve_scan_format(args: argparse.Namespace) -> str:
    if getattr(args, "sarif_file", None) is not None:
        return "sarif"
    if getattr(args, "sarif", False):
        return "sarif"
    if getattr(args, "json", False):
        return "json"
    return getattr(args, "format", "text") or "text"


def _load_scan_policy(args: argparse.Namespace) -> ScanPolicy:
    try:
        return resolve_policy(config=getattr(args, "config", None))
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def _load_ignore(args: argparse.Namespace, scan_root: Path | None = None):
    try:
        return resolve_ignore(
            ignore_file=getattr(args, "ignore_file", None),
            scan_root=scan_root,
        )
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def _load_suppressions(args: argparse.Namespace):
    try:
        return resolve_suppressions(suppressions=getattr(args, "suppressions", None))
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def _cmd_scan(args: argparse.Namespace) -> int:
    paths: list[Path] = list(args.paths) if args.paths else [Path(".")]
    policy = _load_scan_policy(args)
    suppressions = _load_suppressions(args)

    scan_root = paths[0] if paths else Path(".")
    ignore = _load_ignore(args, scan_root=scan_root)

    try:
        if getattr(args, "staged", False):
            staged = list_staged_files()
            files = filter_staged_under(staged, paths)
            if not files:
                path_label = "staged (none)"
                findings: list[Finding] = []
            else:
                path_label = f"{len(files)} staged file(s)"
                findings = scan_files(files, policy=policy, ignore=ignore)
        else:
            path_label = str(paths[0]) if len(paths) == 1 else f"{len(paths)} paths"
            findings = _scan_paths(paths, policy, ignore=ignore)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except StagedError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    findings = apply_suppressions(findings, suppressions)

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


def _cmd_init(args: argparse.Namespace) -> int:
    """Write starter watchwire.toml + .watchwireignore (+ optional suppressions)."""
    dest = Path(args.directory).resolve() if args.directory else Path.cwd().resolve()
    if not dest.is_dir():
        print(f"error: not a directory: {dest}", file=sys.stderr)
        return 2

    force = bool(args.force)
    targets = [
        (dest / "watchwire.toml", STARTER_WATCHWIRE_TOML),
        (dest / ".watchwireignore", STARTER_WATCHWIREIGNORE),
    ]
    if args.with_suppressions:
        targets.append((dest / "watchwire.suppressions.toml", STARTER_SUPPRESSIONS))

    wrote = 0
    for path, content in targets:
        if path.exists() and not force:
            print(f"skip (exists): {path}")
            continue
        path.write_text(content, encoding="utf-8")
        print(f"wrote: {path}")
        wrote += 1

    if wrote == 0:
        print(
            "Nothing written (files already exist). Re-run with --force to overwrite.",
            file=sys.stderr,
        )
        return 0
    print(
        "Next: review watchwire.toml / .watchwireignore, then "
        "`watchwire scan .` (or `watchwire scan --staged` in a git repo)."
    )
    return 0


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
        nargs="*",
        type=Path,
        metavar="PATH",
        help="File(s) or directory(ies) to scan (default: .)",
    )
    scan_p.add_argument(
        "--staged",
        action="store_true",
        help=(
            "Scan only git staged files (local git diff --cached; no network). "
            "Requires a git work tree."
        ),
    )
    scan_p.add_argument(
        "--config",
        "-c",
        type=Path,
        default=None,
        metavar="PATH",
        help="Path to watchwire.toml (default: ./watchwire.toml if present)",
    )
    scan_p.add_argument(
        "--ignore-file",
        type=Path,
        default=None,
        metavar="PATH",
        help="Path to .watchwireignore (default: ./.watchwireignore if present)",
    )
    scan_p.add_argument(
        "--suppressions",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Path to watchwire.suppressions.toml (default: ./watchwire.suppressions.toml "
            "if present). Path+rule allowlist — see COMPLIANCE_NOTES.md abuse risk."
        ),
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

    init_p = sub.add_parser(
        "init",
        help="Write starter watchwire.toml and .watchwireignore into a directory",
    )
    init_p.add_argument(
        "directory",
        nargs="?",
        type=Path,
        default=None,
        help="Target directory (default: current working directory)",
    )
    init_p.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing starter files",
    )
    init_p.add_argument(
        "--with-suppressions",
        action="store_true",
        help="Also write a commented watchwire.suppressions.toml starter",
    )
    init_p.set_defaults(func=_cmd_init)

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
