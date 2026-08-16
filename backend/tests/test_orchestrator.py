from unittest.mock import patch

from app.db import Base, engine, SessionLocal
from app import models
from app.modules.base import Finding
from app.orchestrator import run_scan


def _create_authorized_project_and_scan():
    db = SessionLocal()
    try:
        project = models.Project(
            name="Test Co",
            target="example.com",
            scope_notes="only example.com",
            authorized=True,
        )
        db.add(project)
        db.commit()

        scan = models.Scan(project_id=project.id, status="pending")
        db.add(scan)
        db.commit()
        return scan.id
    finally:
        db.close()


def test_run_scan_persists_findings_and_marks_scan_complete():
    Base.metadata.create_all(bind=engine)
    scan_id = _create_authorized_project_and_scan()

    with patch(
        "app.orchestrator.SubfinderModule.run",
        return_value=[Finding("subdomain", "a.example.com")],
    ), patch("app.orchestrator.CrtShModule.run", return_value=[]), patch(
        "app.orchestrator.WhoisModule.run",
        return_value=[Finding("whois", "example.com")],
    ), patch(
        "app.orchestrator.HttpxProbeModule.run",
        return_value=[Finding("live_host", "https://a.example.com")],
    ):
        run_scan(scan_id)

    db = SessionLocal()
    try:
        scan = db.get(models.Scan, scan_id)
        findings = db.query(models.Finding).filter_by(scan_id=scan_id).all()
    finally:
        db.close()

    assert scan.status == "complete"
    assert scan.finished_at is not None
    assert {f.type for f in findings} == {"subdomain", "whois", "live_host"}


def _create_unauthorized_project_and_scan():
    db = SessionLocal()
    try:
        project = models.Project(
            name="Unauthorized Co",
            target="unauth.com",
            scope_notes="not authorized",
            authorized=False,
        )
        db.add(project)
        db.commit()

        scan = models.Scan(project_id=project.id, status="pending")
        db.add(scan)
        db.commit()
        return scan.id
    finally:
        db.close()


def test_run_scan_fails_without_running_modules_when_project_not_authorized():
    scan_id = _create_unauthorized_project_and_scan()

    with patch("app.orchestrator.SubfinderModule.run") as mock_subfinder, patch(
        "app.orchestrator.CrtShModule.run"
    ) as mock_crtsh, patch(
        "app.orchestrator.WhoisModule.run"
    ) as mock_whois, patch(
        "app.orchestrator.HttpxProbeModule.run"
    ) as mock_httpx:
        run_scan(scan_id)

    mock_subfinder.assert_not_called()
    mock_crtsh.assert_not_called()
    mock_whois.assert_not_called()
    mock_httpx.assert_not_called()

    db = SessionLocal()
    try:
        scan = db.get(models.Scan, scan_id)
    finally:
        db.close()

    assert scan.status == "failed"


def test_run_scan_isolates_a_failing_module_and_keeps_going():
    scan_id = _create_authorized_project_and_scan()

    with patch(
        "app.orchestrator.SubfinderModule.run", side_effect=RuntimeError("boom")
    ), patch(
        "app.orchestrator.CrtShModule.run",
        return_value=[Finding("subdomain", "a.example.com")],
    ), patch(
        "app.orchestrator.WhoisModule.run",
        return_value=[Finding("whois", "example.com")],
    ), patch(
        "app.orchestrator.HttpxProbeModule.run",
        return_value=[Finding("live_host", "https://a.example.com")],
    ):
        run_scan(scan_id)

    db = SessionLocal()
    try:
        scan = db.get(models.Scan, scan_id)
        findings = db.query(models.Finding).filter_by(scan_id=scan_id).all()
    finally:
        db.close()

    assert scan.status == "complete"
    assert scan.finished_at is not None

    types_by_module = {(f.module, f.type) for f in findings}
    assert ("subfinder", "module_error") in types_by_module
    assert ("crtsh", "subdomain") in types_by_module
    assert ("whois", "whois") in types_by_module
    assert ("httpx_probe", "live_host") in types_by_module

    error_finding = next(f for f in findings if f.module == "subfinder")
    assert error_finding.value == "subfinder"
    assert "boom" in error_finding.data["error"]
