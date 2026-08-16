from app.celery_app import celery_app
from app.orchestrator import run_scan


@celery_app.task(name="run_scan_task")
def run_scan_task(scan_id: int):
    run_scan(scan_id)
