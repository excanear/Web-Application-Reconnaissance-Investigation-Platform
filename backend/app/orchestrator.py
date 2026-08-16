from datetime import datetime

from app.db import SessionLocal
from app import models
from app.modules.crtsh import CrtShModule
from app.modules.httpx_probe import HttpxProbeModule
from app.modules.subfinder import SubfinderModule
from app.modules.whois_module import WhoisModule


def run_scan(scan_id: int) -> None:
    db = SessionLocal()
    scan = db.get(models.Scan, scan_id)
    try:
        if not scan.project.authorized:
            scan.status = "failed"
            scan.finished_at = datetime.utcnow()
            db.commit()
            return

        scan.status = "running"
        scan.started_at = datetime.utcnow()
        db.commit()

        target = scan.project.target
        context: dict = {"subdomains": set()}

        for module in (SubfinderModule(), CrtShModule()):
            for finding in module.run(target, context):
                if finding.type == "subdomain":
                    context["subdomains"].add(finding.value)
                _persist(db, scan_id, module.name, finding)

        for module in (WhoisModule(), HttpxProbeModule()):
            for finding in module.run(target, context):
                _persist(db, scan_id, module.name, finding)

        scan.status = "complete"
        scan.finished_at = datetime.utcnow()
        db.commit()
    except Exception:
        scan.status = "failed"
        scan.finished_at = datetime.utcnow()
        db.commit()
        raise
    finally:
        db.close()


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
