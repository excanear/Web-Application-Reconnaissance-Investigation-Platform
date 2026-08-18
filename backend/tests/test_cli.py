from unittest.mock import patch

from typer.testing import CliRunner

from app.cli import app
from app.db import SessionLocal
from app import models

runner = CliRunner()


def test_scan_requires_authorized_flag():
    result = runner.invoke(app, ["scan", "example.com", "--scope", "ok"])

    assert result.exit_code == 1
    assert "Error:" in result.output
    assert "authorized" in result.output.lower()


def test_scan_requires_confirm_active_when_active_modules_are_registered():
    result = runner.invoke(app, ["scan", "example.com", "--scope", "ok", "--authorized"])

    assert result.exit_code == 1
    assert "confirm-active" in result.output.lower()


def test_scan_rejects_blank_scope():
    result = runner.invoke(
        app,
        ["scan", "example.com", "--scope", "   ", "--authorized", "--confirm-active"],
    )

    assert result.exit_code == 1
    assert "scope" in result.output.lower()


def test_scan_errors_are_translated_to_portuguese_with_lang_flag():
    result = runner.invoke(app, ["--lang", "pt", "scan", "example.com", "--scope", "ok"])

    assert result.exit_code == 1
    assert "Erro:" in result.output
    assert "obrigatorio" in result.output.lower()


def test_report_headers_are_translated_to_portuguese_with_lang_flag():
    db = SessionLocal()
    try:
        project = models.Project(
            name="Lang Co", target="lang.example.com", scope_notes="ok", authorized=True
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
                value="lang.example.com",
                data={"category": "web_server", "name": "nginx", "version": "1.18.0", "confidence": "high"},
            )
        )
        db.commit()
        scan_id = scan_row.id
    finally:
        db.close()

    result = runner.invoke(app, ["--lang", "pt", "report", str(scan_id)])

    assert result.exit_code == 0
    assert "Tecnologias" in result.output
    assert "Versao" in result.output


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

    assert mock_run_scan.call_args.kwargs["rate_limit"] == 5.0
    assert mock_run_scan.call_args.kwargs["circuit_breaker_threshold"] == 5


def test_scan_forwards_custom_rate_limit_and_circuit_breaker_threshold():
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
                "--max-requests-per-second",
                "2.5",
                "--circuit-breaker-threshold",
                "3",
            ],
        )

    assert result.exit_code == 0, result.output
    assert mock_run_scan.call_args.kwargs["rate_limit"] == 2.5
    assert mock_run_scan.call_args.kwargs["circuit_breaker_threshold"] == 3


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


def test_report_truncates_long_cve_descriptions():
    long_description = "A" * 500

    db = SessionLocal()
    try:
        project = models.Project(
            name="Trunc Co", target="trunc.example.com", scope_notes="ok", authorized=True
        )
        db.add(project)
        db.commit()
        scan_row = models.Scan(project_id=project.id, status="complete")
        db.add(scan_row)
        db.commit()
        db.add(
            models.Finding(
                scan_id=scan_row.id,
                module="cve_correlation",
                type="cve",
                value="CVE-9999-00001",
                data={
                    "cvss_score": 5.0,
                    "severity": "MEDIUM",
                    "description": long_description,
                    "matched_technology": "nginx",
                    "matched_technology_version": "1.0",
                },
            )
        )
        db.commit()
        scan_id = scan_row.id
    finally:
        db.close()

    result = runner.invoke(app, ["report", str(scan_id)])

    assert result.exit_code == 0
    assert long_description not in result.output
    # Rich further wraps/compresses long cells to fit the console width, so
    # only assert our own truncation actually ran (full string never shows).


def test_scan_defaults_scope_to_target_and_wildcard_subdomains():
    with patch("app.cli.run_scan"):
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
    db = SessionLocal()
    try:
        project = db.query(models.Project).filter_by(target="example.com").order_by(
            models.Project.id.desc()
        ).first()
        assert project.scope["include"] == ["example.com", "*.example.com"]
        assert project.scope["exclude"] == []
    finally:
        db.close()


def test_scan_persists_custom_scope_include_exclude_and_window():
    with patch("app.cli.run_scan"):
        result = runner.invoke(
            app,
            [
                "scan",
                "example.com",
                "--scope",
                "authorized test scope",
                "--authorized",
                "--confirm-active",
                "--scope-include",
                "example.com",
                "--scope-include",
                "*.example.com",
                "--scope-exclude",
                "internal.example.com",
                "--scope-window",
                "09:00-18:00",
            ],
        )

    assert result.exit_code == 0, result.output
    db = SessionLocal()
    try:
        project = db.query(models.Project).filter_by(target="example.com").order_by(
            models.Project.id.desc()
        ).first()
        assert project.scope["include"] == ["example.com", "*.example.com"]
        assert project.scope["exclude"] == ["internal.example.com"]
        assert project.scope["allowed_window"] == {"start": "09:00", "end": "18:00"}
    finally:
        db.close()


def test_scan_rejects_when_target_itself_is_excluded_from_scope():
    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--scope",
            "authorized test scope",
            "--authorized",
            "--confirm-active",
            "--scope-exclude",
            "example.com",
        ],
    )

    assert result.exit_code == 1
    assert "Error:" in result.output
    assert "scope" in result.output.lower()


def test_scan_rejects_malformed_scope_window():
    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--scope",
            "authorized test scope",
            "--authorized",
            "--confirm-active",
            "--scope-window",
            "not-a-window",
        ],
    )

    assert result.exit_code == 1
    assert "Error:" in result.output
    assert "scope-window" in result.output.lower()


def test_scan_accepts_ip_literal_target_with_default_scope():
    with patch("app.cli.run_scan"):
        result = runner.invoke(
            app,
            [
                "scan",
                "203.0.113.5",
                "--scope",
                "authorized test scope",
                "--authorized",
                "--confirm-active",
            ],
        )

    assert result.exit_code == 0, result.output


def test_scan_accepts_ip_literal_target_in_scope_via_cidr_include():
    with patch("app.cli.run_scan"):
        result = runner.invoke(
            app,
            [
                "scan",
                "10.1.2.3",
                "--scope",
                "authorized test scope",
                "--authorized",
                "--confirm-active",
                "--scope-include",
                "10.0.0.0/8",
            ],
        )

    assert result.exit_code == 0, result.output


def test_report_never_crashes_on_a_description_with_unencodable_characters():
    tricky_description = "vuln with a rewrite‑directive and ASLR.‑"

    db = SessionLocal()
    try:
        project = models.Project(
            name="Unicode Co", target="unicode.example.com", scope_notes="ok", authorized=True
        )
        db.add(project)
        db.commit()
        scan_row = models.Scan(project_id=project.id, status="complete")
        db.add(scan_row)
        db.commit()
        db.add(
            models.Finding(
                scan_id=scan_row.id,
                module="cve_correlation",
                type="cve",
                value="CVE-9999-00002",
                data={
                    "cvss_score": 8.1,
                    "severity": "HIGH",
                    "description": tricky_description,
                    "matched_technology": "nginx",
                    "matched_technology_version": "1.24.0",
                },
            )
        )
        db.commit()
        scan_id = scan_row.id
    finally:
        db.close()

    result = runner.invoke(app, ["report", str(scan_id)])

    assert result.exit_code == 0


def test_audit_command_prints_table_with_recorded_entries():
    db = SessionLocal()
    try:
        project = models.Project(
            name="Audit Co", target="audit.example.com", scope_notes="ok", authorized=True
        )
        db.add(project)
        db.commit()
        scan_row = models.Scan(project_id=project.id, status="complete")
        db.add(scan_row)
        db.commit()
        db.add(
            models.AuditEntry(
                scan_id=scan_row.id,
                module="crtsh",
                target="audit.example.com",
                url="https://crt.sh/",
                outcome="200",
            )
        )
        db.commit()
        scan_id = scan_row.id
    finally:
        db.close()

    result = runner.invoke(app, ["audit", str(scan_id)])

    assert result.exit_code == 0
    assert "crtsh" in result.output
    assert "audit.example.com" in result.output


def test_audit_command_csv_format_outputs_csv_rows():
    db = SessionLocal()
    try:
        project = models.Project(
            name="Audit CSV Co", target="csv.example.com", scope_notes="ok", authorized=True
        )
        db.add(project)
        db.commit()
        scan_row = models.Scan(project_id=project.id, status="complete")
        db.add(scan_row)
        db.commit()
        db.add(
            models.AuditEntry(
                scan_id=scan_row.id, module="whois", target="csv.example.com", outcome="success"
            )
        )
        db.commit()
        scan_id = scan_row.id
    finally:
        db.close()

    result = runner.invoke(app, ["audit", str(scan_id), "--format", "csv"])

    assert result.exit_code == 0
    assert "module,target,url,outcome,requested_at" in result.output
    assert "whois,csv.example.com" in result.output


def test_audit_command_exits_with_error_for_unknown_scan_id():
    result = runner.invoke(app, ["audit", "999999"])

    assert result.exit_code == 1
    assert "999999" in result.output
