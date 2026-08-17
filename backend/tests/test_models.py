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


def test_project_scope_defaults_to_empty_dict():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = models.Project(
            name="Scope Co",
            target="scope.example.com",
            scope_notes="only scope.example.com",
            authorized=True,
        )
        db.add(project)
        db.commit()

        reloaded = db.get(models.Project, project.id)
        assert reloaded.scope == {}
    finally:
        db.close()


def test_project_scope_stores_structured_include_exclude_window():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        scope = {
            "include": ["example.com", "*.example.com"],
            "exclude": ["internal.example.com"],
            "allowed_window": {"start": "09:00", "end": "18:00"},
        }
        project = models.Project(
            name="Structured Scope Co",
            target="example.com",
            scope_notes="structured",
            authorized=True,
            scope=scope,
        )
        db.add(project)
        db.commit()

        reloaded = db.get(models.Project, project.id)
        assert reloaded.scope == scope
    finally:
        db.close()
