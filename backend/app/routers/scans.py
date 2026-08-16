from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models, schemas
from app.db import get_db
from app.modules.base import MODULE_REGISTRY
from app.tasks import run_scan_task

router = APIRouter(tags=["scans"])


@router.post("/projects/{project_id}/scans", response_model=schemas.ScanOut, status_code=201)
def create_scan(
    project_id: int, payload: schemas.ScanCreate = schemas.ScanCreate(), db: Session = Depends(get_db)
):
    project = db.get(models.Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="project not found")
    if not project.authorized:
        raise HTTPException(status_code=403, detail="project is not authorized for scanning")

    has_active_modules = any(cls.is_active for cls in MODULE_REGISTRY.values())
    if has_active_modules and not payload.confirm_active_modules:
        raise HTTPException(
            status_code=403,
            detail="this scan includes active modules that probe the target directly; "
            "set confirm_active_modules=true to acknowledge and proceed",
        )

    scan = models.Scan(project_id=project_id, status="pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    run_scan_task.delay(scan.id)
    return scan


@router.get("/scans/{scan_id}", response_model=schemas.ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(models.Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan


@router.get("/scans/{scan_id}/findings", response_model=list[schemas.FindingOut])
def get_scan_findings(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(models.Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan.findings
