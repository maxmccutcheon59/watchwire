"""Tests for JSON and SARIF output schemas (fixture tree only)."""

from __future__ import annotations

import json
from pathlib import Path

from watchwire.cli import main
from watchwire.hygiene import check_hygiene
from watchwire.output import (
    findings_to_json_dict,
    findings_to_sarif,
    hygiene_to_json_dict,
    proc_to_json_dict,
)
from watchwire.proc import summarize_pid
from watchwire.scan import scan_path


def test_scan_json_schema(tmp_path: Path) -> None:
    f = tmp_path / "leak.env"
    f.write_text("AWS_ACCESS_KEY_ID=AKIAEXAMPLEKEY000001\n")
    findings = scan_path(tmp_path)
    doc = findings_to_json_dict(findings, path=str(tmp_path))
    assert doc["tool"] == "watchwire"
    assert doc["command"] == "scan"
    assert doc["finding_count"] == len(findings)
    assert len(findings) >= 1
    assert "version" in doc
    row = doc["findings"][0]
    assert set(row) == {"path", "line", "kind", "snippet"}
    assert "…" in row["snippet"] or "*" in row["snippet"]
    assert "AKIAEXAMPLEKEY000001" not in row["snippet"]


def test_scan_cli_json_exit_codes(tmp_path: Path, capsys) -> None:
    dirty = tmp_path / "leak.env"
    dirty.write_text("KEY=AKIAEXAMPLEKEY000001\n")
    code = main(["scan", str(tmp_path), "--json"])
    out = capsys.readouterr().out
    assert code == 1
    doc = json.loads(out)
    assert doc["finding_count"] >= 1

    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "ok.txt").write_text("hello\n")
    code = main(["scan", str(clean), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert code == 0
    assert doc["finding_count"] == 0


def test_scan_cli_sarif_schema(tmp_path: Path, capsys) -> None:
    f = tmp_path / "leak.env"
    f.write_text("KEY=AKIAEXAMPLEKEY000001\n")
    code = main(["scan", str(tmp_path), "--sarif"])
    doc = json.loads(capsys.readouterr().out)
    assert code == 1
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "watchwire"
    assert "rules" in run["tool"]["driver"]
    assert len(run["results"]) >= 1
    result = run["results"][0]
    assert "ruleId" in result
    assert "locations" in result
    msg = result["message"]["text"]
    assert "AKIAEXAMPLEKEY000001" not in msg
    loc = result["locations"][0]["physicalLocation"]
    assert "uri" in loc["artifactLocation"]
    assert loc["region"]["startLine"] >= 1


def test_sarif_file_write(tmp_path: Path) -> None:
    f = tmp_path / "leak.env"
    f.write_text("KEY=AKIAEXAMPLEKEY000001\n")
    out = tmp_path / "out.sarif"
    code = main(["scan", str(tmp_path), "--sarif-file", str(out)])
    assert code == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"]


def test_findings_to_sarif_helper(tmp_path: Path) -> None:
    f = tmp_path / "leak.env"
    f.write_text("token=ghp_ExampleGitHubPersonalAccessToken0001\n")
    findings = scan_path(tmp_path)
    doc = findings_to_sarif(findings, path=str(tmp_path))
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "github_token" in rule_ids
    assert "aws_access_key_id" in rule_ids


def test_hygiene_json_schema(tmp_path: Path, capsys) -> None:
    dirty = tmp_path / "w.txt"
    dirty.write_text("x")
    dirty.chmod(0o666)
    findings = check_hygiene(tmp_path)
    doc = hygiene_to_json_dict(findings, path=str(tmp_path))
    assert doc["command"] == "hygiene"
    assert doc["finding_count"] >= 1
    assert set(doc["findings"][0]) == {"path", "kind", "mode"}

    code = main(["hygiene", str(tmp_path), "--json"])
    assert code == 1
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["finding_count"] >= 1


def test_proc_json_schema(tmp_path: Path, capsys) -> None:
    pid_dir = tmp_path / "1"
    pid_dir.mkdir()
    (pid_dir / "cmdline").write_bytes(b"init\x00")
    (pid_dir / "status").write_text("State:\tS (sleeping)\nVmRSS:\t100 kB\nVmSize:\t200 kB\n")
    (pid_dir / "fd").mkdir()
    summary = summarize_pid(1, proc_root=tmp_path)
    doc = proc_to_json_dict([summary], proc_root=str(tmp_path))
    assert doc["command"] == "proc"
    assert doc["process_count"] == 1
    assert doc["processes"][0]["pid"] == 1

    code = main(["proc", "1", "--proc-root", str(tmp_path), "--json"])
    assert code == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["processes"][0]["cmdline"] == "init"


def test_scan_multi_path_for_precommit(tmp_path: Path) -> None:
    a = tmp_path / "a.env"
    b = tmp_path / "b.txt"
    a.write_text("KEY=AKIAEXAMPLEKEY000001\n")
    b.write_text("clean\n")
    code = main(["scan", str(a), str(b), "--json", "-o", str(tmp_path / "out.json")])
    assert code == 1
    doc = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert doc["finding_count"] >= 1


def test_fixtures_sarif_roundtrip() -> None:
    fixtures = Path(__file__).resolve().parent / "fixtures"
    findings = scan_path(fixtures)
    doc = findings_to_sarif(findings, path=str(fixtures))
    assert doc["version"] == "2.1.0"
    kinds = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "aws_access_key_id" in kinds
