from unittest.mock import patch

from typer.testing import CliRunner

from app.cli import app
from app.db import SessionLocal
from app import models

runner = CliRunner()


def test_scan_requires_authorized_flag():
    result = runner.invoke(app, ["scan", "example.com", "--scope", "ok"])

    assert result.exit_code == 1
    assert "authorized" in result.output.lower()


def test_scan_requires_confirm_active_when_active_modules_are_registered():
    result = runner.invoke(app, ["scan", "example.com", "--scope", "ok", "--authorized"])

    assert result.exit_code == 1
    assert "confirm-active" in result.output.lower() or "ativo" in result.output.lower()


def test_scan_rejects_blank_scope():
    result = runner.invoke(
        app,
        ["scan", "example.com", "--scope", "   ", "--authorized", "--confirm-active"],
    )

    assert result.exit_code == 1
    assert "scope" in result.output.lower() or "escopo" in result.output.lower()


def test_scan_creates_project_and_scan_then_runs_orchestrator():
    with patch("app.cli.run_scan") as mock_run_scan:
        result = runner.invoke(
            app,
            [
                "scan",
                "example.com",
                "--scope",
                "authorized test scope",
                "--authorized",
                "--confirm-active",
            ],
        )

    assert result.exit_code == 0, result.output
    assert mock_run_scan.call_count == 1
    called_scan_id = mock_run_scan.call_args.args[0]

    db = SessionLocal()
    try:
        scan_row = db.get(models.Scan, called_scan_id)
        assert scan_row is not None
        assert scan_row.project.target == "example.com"
        assert scan_row.project.authorized is True
        assert scan_row.project.scope_notes == "authorized test scope"
    finally:
        db.close()


def test_history_lists_past_scans():
    db = SessionLocal()
    try:
        project = models.Project(
            name="History Co", target="history.example.com", scope_notes="ok", authorized=True
        )
        db.add(project)
        db.commit()
        scan_row = models.Scan(project_id=project.id, status="complete")
        db.add(scan_row)
        db.commit()
    finally:
        db.close()

    result = runner.invoke(app, ["history"])

    assert result.exit_code == 0
    assert "history.example.com" in result.output
    assert "complete" in result.output


def test_report_prints_technology_and_cve_sections():
    db = SessionLocal()
    try:
        project = models.Project(
            name="Report Co", target="report.example.com", scope_notes="ok", authorized=True
        )
        db.add(project)
        db.commit()
        scan_row = models.Scan(project_id=project.id, status="complete")
        db.add(scan_row)
        db.commit()
        db.add(
            models.Finding(
                scan_id=scan_row.id,
                module="tech_fingerprint",
                type="technology",
                value="report.example.com",
                data={"category": "web_server", "name": "nginx", "version": "1.18.0", "confidence": "high"},
            )
        )
        db.add(
            models.Finding(
                scan_id=scan_row.id,
                module="cve_correlation",
                type="cve",
                value="CVE-2021-23017",
                data={
                    "cvss_score": 9.4,
                    "severity": "CRITICAL",
                    "description": "A vuln.",
                    "matched_technology": "nginx",
                    "matched_technology_version": "1.18.0",
                },
            )
        )
        db.commit()
        scan_id = scan_row.id
    finally:
        db.close()

    result = runner.invoke(app, ["report", str(scan_id)])

    assert result.exit_code == 0
    assert "nginx" in result.output
    assert "CVE-2021-23017" in result.output
    assert "CRITICAL" in result.output


def test_report_exits_with_error_for_unknown_scan_id():
    result = runner.invoke(app, ["report", "999999"])

    assert result.exit_code == 1
    assert "999999" in result.output
