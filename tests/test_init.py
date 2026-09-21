"""Tests for watchwire init."""

from __future__ import annotations

from pathlib import Path

from watchwire.cli import main
from watchwire.ignore import load_ignore_file
from watchwire.policy import load_policy


def test_init_writes_starters(tmp_path: Path, capsys) -> None:
    code = main(["init", str(tmp_path)])
    assert code == 0
    toml = tmp_path / "watchwire.toml"
    ign = tmp_path / ".watchwireignore"
    assert toml.is_file()
    assert ign.is_file()
    assert not (tmp_path / "watchwire.suppressions.toml").exists()
    # Starters must be loadable
    pol = load_policy(toml)
    assert pol.min_entropy == 4.5
    matcher = load_ignore_file(ign)
    assert matcher.rules
    out = capsys.readouterr().out
    assert "wrote:" in out


def test_init_skips_existing(tmp_path: Path, capsys) -> None:
    (tmp_path / "watchwire.toml").write_text("# keep\n")
    (tmp_path / ".watchwireignore").write_text("# keep\n")
    code = main(["init", str(tmp_path)])
    assert code == 0
    assert (tmp_path / "watchwire.toml").read_text() == "# keep\n"
    assert "skip (exists)" in capsys.readouterr().out


def test_init_force_overwrites(tmp_path: Path) -> None:
    (tmp_path / "watchwire.toml").write_text("# old\n")
    code = main(["init", str(tmp_path), "--force"])
    assert code == 0
    assert "[scan]" in (tmp_path / "watchwire.toml").read_text()


def test_init_with_suppressions(tmp_path: Path) -> None:
    code = main(["init", str(tmp_path), "--with-suppressions"])
    assert code == 0
    sup = tmp_path / "watchwire.suppressions.toml"
    assert sup.is_file()
    assert "ABUSE RISK" in sup.read_text()
