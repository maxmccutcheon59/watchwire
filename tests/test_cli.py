"""CLI smoke tests."""

from __future__ import annotations

from pathlib import Path

from watchwire.cli import main


def test_scan_cli_finds_secret(tmp_path: Path, capsys) -> None:
    f = tmp_path / "leak.env"
    f.write_text("KEY=AKIAEXAMPLEKEY000001\n")
    code = main(["scan", str(tmp_path)])
    captured = capsys.readouterr()
    assert code == 1
    assert "aws_access_key_id" in captured.out


def test_scan_cli_clean(tmp_path: Path, capsys) -> None:
    (tmp_path / "ok.txt").write_text("nothing here\n")
    code = main(["scan", str(tmp_path)])
    assert code == 0
    assert "No secret-like findings" in capsys.readouterr().out


def test_proc_cli(tmp_path: Path, capsys) -> None:
    pid_dir = tmp_path / "1"
    pid_dir.mkdir()
    (pid_dir / "cmdline").write_bytes(b"init\x00")
    (pid_dir / "status").write_text("State:\tS (sleeping)\nVmRSS:\t100 kB\nVmSize:\t200 kB\n")
    (pid_dir / "fd").mkdir()
    code = main(["proc", "1", "--proc-root", str(tmp_path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "PID:" in out
    assert "init" in out


def test_hygiene_cli(tmp_path: Path, capsys) -> None:
    dirty = tmp_path / "w.txt"
    dirty.write_text("x")
    dirty.chmod(0o666)
    code = main(["hygiene", str(tmp_path)])
    assert code == 1
    assert "world_writable" in capsys.readouterr().out


def test_version(capsys) -> None:
    try:
        main(["--version"])
    except SystemExit as e:
        assert e.code == 0
    assert "0.2.0" in capsys.readouterr().out
