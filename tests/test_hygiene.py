"""Tests for filesystem hygiene checks."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from watchwire.hygiene import check_hygiene


def test_world_writable(tmp_path: Path) -> None:
    dirty = tmp_path / "open.txt"
    dirty.write_text("x")
    dirty.chmod(0o666)
    findings = check_hygiene(tmp_path)
    assert any(f.kind == "world_writable" and f.path.endswith("open.txt") for f in findings)


def test_setuid_bit(tmp_path: Path) -> None:
    suid = tmp_path / "suid.bin"
    suid.write_text("#!/bin/true\n")
    # setuid + owner rwx
    suid.chmod(0o4755)
    findings = check_hygiene(tmp_path)
    assert any(f.kind == "setuid" for f in findings)


def test_setgid_bit(tmp_path: Path) -> None:
    sgid = tmp_path / "sgid.bin"
    sgid.write_text("#!/bin/true\n")
    sgid.chmod(0o2755)
    findings = check_hygiene(tmp_path)
    assert any(f.kind == "setgid" for f in findings)


def test_clean_tree(tmp_path: Path) -> None:
    safe = tmp_path / "safe.txt"
    safe.write_text("ok")
    safe.chmod(0o644)
    # Directory itself should not be world-writable
    os.chmod(tmp_path, 0o755)
    findings = check_hygiene(tmp_path)
    # Filter out the tmp_path dir if somehow flagged; expect no file findings
    file_findings = [f for f in findings if f.path.endswith("safe.txt")]
    assert file_findings == []


def test_missing_path(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        check_hygiene(tmp_path / "nope")
