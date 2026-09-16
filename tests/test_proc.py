"""Tests for /proc summarizer with a mocked proc tree."""

from __future__ import annotations

from pathlib import Path

import pytest

from watchwire.proc import list_pids, summarize_pid


@pytest.fixture
def fake_proc(tmp_path: Path) -> Path:
    """Minimal fake /proc layout."""
    pid_dir = tmp_path / "42"
    pid_dir.mkdir()
    (pid_dir / "cmdline").write_bytes(b"python\x00-m\x00watchwire\x00")
    (pid_dir / "status").write_text(
        "Name:\tpython\n"
        "State:\tS (sleeping)\n"
        "VmSize:\t123456 kB\n"
        "VmRSS:\t65432 kB\n"
    )
    fd_dir = pid_dir / "fd"
    fd_dir.mkdir()
    (fd_dir / "0").symlink_to("/dev/null")
    (fd_dir / "1").symlink_to("/dev/null")
    (fd_dir / "2").symlink_to("/dev/null")

    other = tmp_path / "7"
    other.mkdir()
    (other / "cmdline").write_bytes(b"sleep\x00100\x00")
    (other / "status").write_text("Name:\tsleep\nState:\tS (sleeping)\n")
    (other / "fd").mkdir()

    # Non-pid entry should be ignored
    (tmp_path / "cpuinfo").write_text("processor : 0\n")
    return tmp_path


def test_summarize_pid(fake_proc: Path) -> None:
    s = summarize_pid(42, proc_root=fake_proc)
    assert s.pid == 42
    assert s.cmdline == "python -m watchwire"
    assert s.fd_count == 3
    assert s.vm_rss_kb == 65432
    assert s.vm_size_kb == 123456
    assert s.state is not None and "sleeping" in s.state


def test_list_pids(fake_proc: Path) -> None:
    assert list_pids(proc_root=fake_proc) == [7, 42]


def test_missing_pid(fake_proc: Path) -> None:
    with pytest.raises(FileNotFoundError):
        summarize_pid(99999, proc_root=fake_proc)


def test_format_contains_fields(fake_proc: Path) -> None:
    text = summarize_pid(42, proc_root=fake_proc).format()
    assert "PID:" in text
    assert "Cmdline:" in text
    assert "Open FDs:" in text
