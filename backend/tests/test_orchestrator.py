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


def test_run_scan_marks_scan_failed_on_module_error():
    scan_id = _create_authorized_project_and_scan()

    with patch(
        "app.orchestrator.SubfinderModule.run", side_effect=RuntimeError("boom")
    ):
        try:
            run_scan(scan_id)
        except RuntimeError:
            pass

    db = SessionLocal()
    try:
        scan = db.get(models.Scan, scan_id)
    finally:
        db.close()

    assert scan.status == "failed"
