from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_create_project_requires_authorization():
    response = client.post(
        "/projects",
        json={
            "name": "Test Co",
            "target": "example.com",
            "scope_notes": "only example.com",
            "authorized": False,
        },
    )
    assert response.status_code == 422


def test_create_and_fetch_project():
    response = client.post(
        "/projects",
        json={
            "name": "Test Co",
            "target": "example.com",
            "scope_notes": "only example.com",
            "authorized": True,
        },
    )
    assert response.status_code == 201
    project_id = response.json()["id"]

    response = client.get(f"/projects/{project_id}")
    assert response.status_code == 200
    assert response.json()["target"] == "example.com"


def test_list_projects_includes_created_project():
    client.post(
        "/projects",
        json={
            "name": "Another Co",
            "target": "another.com",
            "scope_notes": "only another.com",
            "authorized": True,
        },
    )
    response = client.get("/projects")
    assert response.status_code == 200
    assert any(p["target"] == "another.com" for p in response.json())
