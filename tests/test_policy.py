"""Tests for watchwire.toml policy loading and application."""

from __future__ import annotations

from pathlib import Path

import pytest

from watchwire.cli import main
from watchwire.policy import (
    DEFAULT_EXCLUDES,
    load_policy,
    path_matches_glob,
    policy_from_dict,
    resolve_policy,
)
from watchwire.scan import scan_path


def test_path_matches_glob_basics() -> None:
    assert path_matches_glob("a/b/node_modules/x.js", "**/node_modules/**")
    assert path_matches_glob("pkg/yarn.lock", "**/*.lock")
    assert path_matches_glob("yarn.lock", "*.lock")
    assert path_matches_glob("foo/package-lock.json", "**/package-lock.json")
    assert not path_matches_glob("src/app.py", "**/*.lock")


def test_default_policy_excludes_lockfile(tmp_path: Path) -> None:
    lock = tmp_path / "demo.lock"
    # High-entropy-looking integrity line that would flag without exclude.
    lock.write_text(
        "integrity sha512-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEf==\n"
    )
    (tmp_path / "ok.txt").write_text("hello\n")
    findings = scan_path(tmp_path)
    assert all(not f.path.endswith(".lock") for f in findings)


def test_load_policy_exclude_and_rules(tmp_path: Path) -> None:
    cfg = tmp_path / "watchwire.toml"
    cfg.write_text(
        "[scan]\n"
        'exclude = ["**/skipme/**"]\n'
        "min_entropy = 5.0\n"
        "\n"
        "[rules]\n"
        "aws_access_key_id = false\n"
        "high_entropy = true\n"
    )
    pol = load_policy(cfg)
    assert pol.min_entropy == 5.0
    assert any("skipme" in g for g in pol.exclude)
    assert "**/node_modules/**" in pol.exclude  # defaults kept
    assert pol.is_rule_enabled("aws_access_key_id") is False
    assert pol.is_rule_enabled("github_token") is True


def test_use_default_excludes_false(tmp_path: Path) -> None:
    cfg = tmp_path / "p.toml"
    cfg.write_text(
        "[scan]\n"
        "use_default_excludes = false\n"
        'exclude = ["**/only/**"]\n'
    )
    pol = load_policy(cfg)
    assert pol.exclude == ["**/only/**"]
    assert "**/node_modules/**" not in pol.exclude


def test_entropy_alias_disables_high_entropy(tmp_path: Path) -> None:
    cfg = tmp_path / "p.toml"
    cfg.write_text("[rules]\nentropy = false\n")
    pol = load_policy(cfg)
    assert pol.is_rule_enabled("high_entropy") is False


def test_scan_respects_disabled_aws(tmp_path: Path) -> None:
    cfg = tmp_path / "watchwire.toml"
    cfg.write_text("[rules]\naws_access_key_id = false\n")
    (tmp_path / "aws.env").write_text("AWS_ACCESS_KEY_ID=AKIAEXAMPLEKEY000001\n")
    pol = load_policy(cfg)
    findings = scan_path(tmp_path, policy=pol)
    assert not any(f.kind == "aws_access_key_id" for f in findings)


def test_scan_respects_exclude_glob(tmp_path: Path) -> None:
    cfg = tmp_path / "policy.toml"
    cfg.write_text(
        "[scan]\n"
        "use_default_excludes = false\n"
        'exclude = ["**/ignored/**"]\n'
    )
    hidden = tmp_path / "ignored"
    hidden.mkdir()
    (hidden / "leak.env").write_text("KEY=AKIAEXAMPLEKEY000001\n")
    (tmp_path / "visible.env").write_text("KEY=AKIAEXAMPLEKEY000002\n")
    pol = load_policy(cfg)
    findings = scan_path(tmp_path, policy=pol)
    assert any("visible.env" in f.path for f in findings)
    assert not any("ignored" in f.path for f in findings)


def test_cli_config_flag(tmp_path: Path, capsys) -> None:
    cfg = tmp_path / "ww.toml"
    cfg.write_text("[rules]\naws_access_key_id = false\n")
    leak = tmp_path / "leak.env"
    leak.write_text("KEY=AKIAEXAMPLEKEY000001\n")
    code = main(["scan", str(tmp_path), "--config", str(cfg)])
    # AWS disabled; file may still be clean of other rules
    assert code == 0
    assert "aws_access_key_id" not in capsys.readouterr().out


def test_cli_loads_cwd_watchwire_toml(tmp_path: Path, monkeypatch, capsys) -> None:
    (tmp_path / "watchwire.toml").write_text("[rules]\naws_access_key_id = false\n")
    (tmp_path / "leak.env").write_text("KEY=AKIAEXAMPLEKEY000001\n")
    monkeypatch.chdir(tmp_path)
    code = main(["scan", "."])
    assert code == 0


def test_resolve_policy_defaults(tmp_path: Path) -> None:
    # Empty cwd → defaults (no watchwire.toml).
    pol = resolve_policy(config=None, cwd=tmp_path)
    assert pol.exclude == list(DEFAULT_EXCLUDES)
    assert pol.min_entropy == 4.5


def test_unknown_rule_raises(tmp_path: Path) -> None:
    cfg = tmp_path / "bad.toml"
    cfg.write_text("[rules]\nnot_a_real_rule = false\n")
    with pytest.raises(ValueError, match="unknown rule"):
        load_policy(cfg)


def test_policy_from_dict_min_entropy_length() -> None:
    pol = policy_from_dict({"scan": {"min_entropy_length": 32}})
    assert pol.min_entropy_length == 32


# --- Example policy packs (examples/policies/) ---

_REPO_ROOT = Path(__file__).resolve().parents[1]
_POLICY_PACK_DIR = _REPO_ROOT / "examples" / "policies"
_POLICY_PACKS = ("student.toml", "indie.toml", "small-team.toml")


@pytest.mark.parametrize("name", _POLICY_PACKS)
def test_example_policy_pack_loads(name: str) -> None:
    """Each shipped pack must parse and produce a usable ScanPolicy."""
    path = _POLICY_PACK_DIR / name
    assert path.is_file(), f"missing policy pack: {path}"
    pol = load_policy(path)
    assert pol.config_path == path
    assert pol.exclude  # defaults + pack extras (or pack-only)
    assert pol.min_entropy > 0
    assert pol.min_entropy_length >= 1
    # Core credential rules stay enabled in all packs
    for kind in (
        "aws_access_key_id",
        "github_token",
        "private_key_header",
        "high_entropy",
    ):
        assert pol.is_rule_enabled(kind) is True


def test_student_pack_is_aggressive() -> None:
    pol = load_policy(_POLICY_PACK_DIR / "student.toml")
    # Aggressive excludes + raised entropy bar vs indie
    assert any("datasets" in g or "solutions" in g for g in pol.exclude)
    assert pol.min_entropy >= 5.0
    assert pol.min_entropy_length >= 24


def test_indie_pack_is_balanced() -> None:
    pol = load_policy(_POLICY_PACK_DIR / "indie.toml")
    assert pol.min_entropy == 4.5
    assert pol.min_entropy_length == 20
    assert "**/node_modules/**" in pol.exclude  # defaults kept
    assert any("dist" in g for g in pol.exclude)


def test_small_team_pack_is_stricter() -> None:
    pol = load_policy(_POLICY_PACK_DIR / "small-team.toml")
    indie = load_policy(_POLICY_PACK_DIR / "indie.toml")
    # Fewer pack-specific excludes than student; stricter entropy than indie
    student = load_policy(_POLICY_PACK_DIR / "student.toml")
    assert len(pol.exclude) < len(student.exclude)
    assert pol.min_entropy < indie.min_entropy
    assert pol.min_entropy_length < indie.min_entropy_length


def test_cli_scan_with_indie_pack(tmp_path: Path, capsys) -> None:
    leak = tmp_path / "aws.env"
    leak.write_text("AWS_ACCESS_KEY_ID=AKIAEXAMPLEKEY000001\n")
    code = main(
        [
            "scan",
            str(tmp_path),
            "--config",
            str(_POLICY_PACK_DIR / "indie.toml"),
        ]
    )
    assert code == 1
    out = capsys.readouterr().out
    assert "aws_access_key_id" in out
