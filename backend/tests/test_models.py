from app.db import Base, engine, SessionLocal
from app import models


def test_project_scan_finding_relationships_persist():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = models.Project(
            name="Test Co",
            target="example.com",
            scope_notes="only example.com and its subdomains",
            authorized=True,
        )
        db.add(project)
        db.commit()

        scan = models.Scan(project_id=project.id, status="pending")
        db.add(scan)
        db.commit()

        finding = models.Finding(
            scan_id=scan.id,
            module="subfinder",
            type="subdomain",
            value="www.example.com",
            data={"source": "subfinder"},
        )
        db.add(finding)
        db.commit()

        reloaded_scan = db.get(models.Scan, scan.id)
        assert reloaded_scan.project.target == "example.com"
        assert reloaded_scan.findings[0].value == "www.example.com"
    finally:
        db.close()
