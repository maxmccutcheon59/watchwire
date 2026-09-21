"""Tests for watchwire.suppressions.toml allowlist."""

from __future__ import annotations

from pathlib import Path

import pytest

from watchwire.cli import main
from watchwire.scan import Finding, scan_path
from watchwire.suppressions import (
    apply_suppressions,
    load_suppressions,
    suppressions_from_dict,
)


def test_load_and_match(tmp_path: Path) -> None:
    path = tmp_path / "watchwire.suppressions.toml"
    path.write_text(
        "[[suppress]]\n"
        'path = "docs/demo.env"\n'
        'rule = "aws_access_key_id"\n'
        'reason = "synthetic demo"\n'
    )
    s = load_suppressions(path)
    assert len(s.items) == 1
    assert s.matches(path="docs/demo.env", rule="aws_access_key_id")
    assert not s.matches(path="docs/demo.env", rule="github_token")
    assert not s.matches(path="other.env", rule="aws_access_key_id")


def test_wildcard_rule(tmp_path: Path) -> None:
    s = suppressions_from_dict(
        {"suppress": [{"path": "fixtures/**", "rule": "*"}]}
    )
    assert s.matches(path="fixtures/aws.env", rule="aws_access_key_id")
    assert s.matches(path="fixtures/nested/x.env", rule="high_entropy")


def test_apply_suppressions_filters() -> None:
    findings = [
        Finding(path="/repo/docs/demo.env", line=1, kind="aws_access_key_id", snippet="AKIA…0001"),
        Finding(path="/repo/src/app.env", line=2, kind="aws_access_key_id", snippet="AKIA…0002"),
    ]
    s = suppressions_from_dict(
        {"suppress": [{"path": "**/docs/demo.env", "rule": "aws_access_key_id"}]}
    )
    kept = apply_suppressions(findings, s)
    assert len(kept) == 1
    assert "app.env" in kept[0].path


def test_cli_suppressions_file(tmp_path: Path, monkeypatch, capsys) -> None:
    (tmp_path / "leak.env").write_text("KEY=AKIAEXAMPLEKEY000001\n")
    (tmp_path / "watchwire.suppressions.toml").write_text(
        "[[suppress]]\n"
        'path = "leak.env"\n'
        'rule = "aws_access_key_id"\n'
        'reason = "test allowlist"\n'
    )
    monkeypatch.chdir(tmp_path)
    code = main(["scan", "."])
    assert code == 0
    assert "No secret-like findings" in capsys.readouterr().out


def test_invalid_suppressions_raise(tmp_path: Path) -> None:
    bad = tmp_path / "bad.toml"
    bad.write_text("[[suppress]]\npath = 1\nrule = \"x\"\n")
    with pytest.raises(ValueError):
        load_suppressions(bad)


def test_scan_then_suppress_real_tree(tmp_path: Path) -> None:
    (tmp_path / "a.env").write_text("KEY=AKIAEXAMPLEKEY000001\n")
    findings = scan_path(tmp_path)
    assert findings
    s = suppressions_from_dict(
        {"suppress": [{"path": "**/*.env", "rule": "*"}]}
    )
    assert apply_suppressions(findings, s) == []
