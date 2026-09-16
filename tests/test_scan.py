"""Tests for secret scanning with fake fixtures only."""

from __future__ import annotations

from pathlib import Path

import pytest

from watchwire.scan import scan_path


@pytest.fixture
def secret_tree(tmp_path: Path) -> Path:
    """Tree with obvious fake secrets (never real credentials)."""
    (tmp_path / "aws.env").write_text(
        "AWS_ACCESS_KEY_ID=AKIAEXAMPLEKEY000001\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    )
    (tmp_path / "github.txt").write_text(
        "token=ghp_ExampleGitHubPersonalAccessToken0001\n"
        "pat=github_pat_ExampleFineGrainedToken00000001\n"
    )
    (tmp_path / "key.pem").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF6examplefakekeymaterialonly\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    (tmp_path / "clean.py").write_text("print('hello world')\n")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "slack.cfg").write_text("SLACK_BOT=xoxb-1234567890-exampletoken\n")
    return tmp_path


def test_detects_aws_access_key(secret_tree: Path) -> None:
    findings = scan_path(secret_tree)
    kinds = {f.kind for f in findings}
    assert "aws_access_key_id" in kinds


def test_detects_github_tokens(secret_tree: Path) -> None:
    findings = scan_path(secret_tree)
    kinds = {f.kind for f in findings}
    assert "github_token" in kinds
    assert "github_fine_grained" in kinds


def test_detects_private_key_header(secret_tree: Path) -> None:
    findings = scan_path(secret_tree)
    assert any(f.kind == "private_key_header" for f in findings)


def test_detects_slack_token(secret_tree: Path) -> None:
    findings = scan_path(secret_tree)
    assert any(f.kind == "slack_token" for f in findings)


def test_clean_file_no_findings(tmp_path: Path) -> None:
    clean = tmp_path / "ok.txt"
    clean.write_text("just a normal comment about configuration\n")
    assert scan_path(clean) == []


def test_missing_path_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        scan_path(tmp_path / "does-not-exist")


def test_snippet_is_redacted(secret_tree: Path) -> None:
    findings = scan_path(secret_tree)
    aws = next(f for f in findings if f.kind == "aws_access_key_id")
    assert "…" in aws.snippet or "*" in aws.snippet
    assert "AKIAEXAMPLEKEY000001" not in aws.snippet


def test_high_entropy_detection(tmp_path: Path) -> None:
    # Long random-looking base64-ish string
    blob = tmp_path / "entropy.txt"
    blob.write_text("secret=Qk9GVVNBRkFLRUVYQU1QTEVTRUNSRVQwMTIzNDU2Nzg5YWJjZGVm\n")
    findings = scan_path(blob)
    assert any(f.kind in {"high_entropy", "generic_api_key_assignment"} for f in findings)
