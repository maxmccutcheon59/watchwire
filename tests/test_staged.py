"""Tests for watchwire scan --staged (local git only)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from watchwire.cli import main
from watchwire.staged import StagedError, filter_staged_under, list_staged_files


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test")
    clean = tmp_path / "clean.txt"
    clean.write_text("ok\n")
    _git(tmp_path, "add", "clean.txt")
    _git(tmp_path, "commit", "-m", "init")
    return tmp_path


def test_list_staged_files(git_repo: Path, monkeypatch) -> None:
    leak = git_repo / "leak.env"
    leak.write_text("KEY=AKIAEXAMPLEKEY000001\n")
    other = git_repo / "other.txt"
    other.write_text("no secrets\n")
    _git(git_repo, "add", "leak.env")  # only leak staged
    monkeypatch.chdir(git_repo)
    staged = list_staged_files()
    names = {p.name for p in staged}
    assert "leak.env" in names
    assert "other.txt" not in names


def test_cli_scan_staged_only(git_repo: Path, monkeypatch, capsys) -> None:
    leak = git_repo / "leak.env"
    leak.write_text("KEY=AKIAEXAMPLEKEY000001\n")
    unstaged = git_repo / "unstaged.env"
    unstaged.write_text("KEY=AKIAEXAMPLEKEY000099\n")
    _git(git_repo, "add", "leak.env")
    monkeypatch.chdir(git_repo)
    code = main(["scan", "--staged"])
    out = capsys.readouterr().out
    assert code == 1
    assert "aws_access_key_id" in out
    # unstaged must not appear
    assert "000099" not in out and "unstaged.env" not in out


def test_cli_scan_staged_empty(git_repo: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(git_repo)
    code = main(["scan", "--staged"])
    assert code == 0
    assert "No secret-like findings" in capsys.readouterr().out


def test_staged_outside_git_errors(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    code = main(["scan", "--staged"])
    err = capsys.readouterr().err
    assert code == 2
    assert "git" in err.lower() or "repository" in err.lower()


def test_filter_staged_under(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    fa = a / "x.env"
    fb = b / "y.env"
    fa.write_text("x")
    fb.write_text("y")
    kept = filter_staged_under([fa, fb], [a])
    assert kept == [fa]


def test_list_staged_not_a_repo(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(StagedError):
        list_staged_files()
