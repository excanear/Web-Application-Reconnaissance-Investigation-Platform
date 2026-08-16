from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _create_authorized_project() -> int:
    response = client.post(
        "/projects",
        json={
            "name": "Test Co",
            "target": "example.com",
            "scope_notes": "only example.com",
            "authorized": True,
        },
    )
    return response.json()["id"]


def test_create_scan_enqueues_task_and_returns_pending_scan():
    project_id = _create_authorized_project()

    with patch("app.routers.scans.run_scan_task.delay") as mock_delay:
        response = client.post(f"/projects/{project_id}/scans")

    assert response.status_code == 201
    assert response.json()["status"] == "pending"
    mock_delay.assert_called_once_with(response.json()["id"])


def test_create_scan_rejects_project_not_marked_authorized():
    # The API never lets you create an unauthorized project, but the DB
    # constraint is the real safety net (e.g. a future admin path could set
    # authorized=False) — insert directly to exercise the 403 branch.
    from app.db import SessionLocal
    from app import models

    db = SessionLocal()
    try:
        project = models.Project(
            name="Unauthorized",
            target="unauth.com",
            scope_notes="not authorized yet",
            authorized=False,
        )
        db.add(project)
        db.commit()
        project_id = project.id
    finally:
        db.close()

    response = client.post(f"/projects/{project_id}/scans")
    assert response.status_code == 403


def test_get_scan_findings_returns_empty_list_for_new_scan():
    project_id = _create_authorized_project()
    with patch("app.routers.scans.run_scan_task.delay"):
        response = client.post(f"/projects/{project_id}/scans")
    scan_id = response.json()["id"]

    response = client.get(f"/scans/{scan_id}/findings")
    assert response.status_code == 200
    assert response.json() == []
