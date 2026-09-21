"""Tests for .watchwireignore (gitignore-style)."""

from __future__ import annotations

from pathlib import Path

from watchwire.cli import main
from watchwire.ignore import load_ignore_file, parse_ignore_text, resolve_ignore
from watchwire.scan import scan_path


def test_parse_ignore_comments_and_negation() -> None:
    rules = parse_ignore_text(
        "# comment\n\n"
        "vendor/\n"
        "!vendor/keep.env\n"
        "*.min.js\n"
    )
    assert len(rules) == 3
    assert rules[0].directory_only is True
    assert rules[0].pattern == "vendor"
    assert rules[1].negated is True
    assert rules[1].pattern == "vendor/keep.env"
    assert rules[2].pattern == "*.min.js"


def test_ignore_skips_matched_paths(tmp_path: Path) -> None:
    (tmp_path / ".watchwireignore").write_text("skipme/\n*.min.js\n")
    hidden = tmp_path / "skipme"
    hidden.mkdir()
    (hidden / "leak.env").write_text("KEY=AKIAEXAMPLEKEY000001\n")
    (tmp_path / "app.min.js").write_text("KEY=AKIAEXAMPLEKEY000002\n")
    (tmp_path / "visible.env").write_text("KEY=AKIAEXAMPLEKEY000003\n")

    matcher = load_ignore_file(tmp_path / ".watchwireignore")
    findings = scan_path(tmp_path, ignore=matcher)
    assert any("visible.env" in f.path for f in findings)
    assert not any("skipme" in f.path for f in findings)
    assert not any("app.min.js" in f.path for f in findings)


def test_cli_loads_cwd_watchwireignore(tmp_path: Path, monkeypatch, capsys) -> None:
    (tmp_path / ".watchwireignore").write_text("hidden.env\n")
    (tmp_path / "hidden.env").write_text("KEY=AKIAEXAMPLEKEY000001\n")
    (tmp_path / "shown.env").write_text("KEY=AKIAEXAMPLEKEY000002\n")
    monkeypatch.chdir(tmp_path)
    code = main(["scan", "."])
    out = capsys.readouterr().out
    assert code == 1
    assert "shown.env" in out
    assert "hidden.env" not in out


def test_resolve_ignore_explicit(tmp_path: Path) -> None:
    ign = tmp_path / "custom.ignore"
    ign.write_text("*.bak\n")
    m = resolve_ignore(ignore_file=ign)
    assert m is not None
    assert m.source == ign
