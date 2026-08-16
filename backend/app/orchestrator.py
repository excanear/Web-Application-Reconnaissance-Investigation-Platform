from app.db import SessionLocal
from app import models
from app.modules.base import Finding, MODULE_REGISTRY
from app.timeutil import utc_now


def run_scan(scan_id: int) -> None:
    db = SessionLocal()
    scan = db.get(models.Scan, scan_id)
    try:
        if not scan.project.authorized:
            scan.status = "failed"
            scan.finished_at = utc_now()
            db.commit()
            return

        scan.status = "running"
        scan.started_at = utc_now()
        db.commit()

        target = scan.project.target
        context: dict = {"subdomains": set()}

        discovery_modules = [cls() for cls in MODULE_REGISTRY.values() if cls.discovers_subdomains]
        other_modules = [cls() for cls in MODULE_REGISTRY.values() if not cls.discovers_subdomains]

        for module in discovery_modules:
            for finding in _run_module(db, scan_id, module, target, context):
                if finding.type == "subdomain":
                    context["subdomains"].add(finding.value)

        for module in other_modules:
            _run_module(db, scan_id, module, target, context)

        scan.status = "complete"
        scan.finished_at = utc_now()
        db.commit()
    except Exception:
        scan.status = "failed"
        scan.finished_at = utc_now()
        db.commit()
        raise
    finally:
        db.close()


def _run_module(db, scan_id: int, module, target: str, context: dict) -> list:
    """Run one module, isolating its failures so one broken/missing tool
    doesn't abort the whole scan. A module that raises gets recorded as a
    module_error finding instead."""
    try:
        findings = module.run(target, context)
    except Exception as exc:
        _persist(
            db,
            scan_id,
            module.name,
            Finding(type="module_error", value=module.name, data={"error": str(exc)}),
        )
        return []

    for finding in findings:
        _persist(db, scan_id, module.name, finding)
    return findings


def _persist(db, scan_id: int, module_name: str, finding) -> None:
    db.add(
        models.Finding(
            scan_id=scan_id,
            module=module_name,
            type=finding.type,
            value=finding.value,
            data=finding.data,
        )
    )
    db.commit()
