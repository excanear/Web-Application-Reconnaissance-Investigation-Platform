# Recon Platform — Phase 1a (Core Engine + Essential OSINT) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the plugin-based orchestration core, a minimal relational data
model, four essential passive-OSINT modules (subdomain enumeration, cert
transparency, WHOIS, live-host/tech fingerprinting), a REST API to run scans,
and a minimal React dashboard to create projects, trigger scans, and view the
aggregated report.

**Architecture:** FastAPI backend with a plugin-style `ReconModule` interface;
an orchestrator function runs modules in dependency order (subdomain discovery
→ WHOIS/live-host probing) and persists normalized `Finding` rows; a Celery
task wraps the orchestrator for async execution; a React/Vite SPA polls scan
status and renders findings in a table.

**Tech Stack:** Python 3.11+, FastAPI, SQLAlchemy, Celery + Redis, pytest;
React 18 + TypeScript + Vite + React Router, Vitest + React Testing Library.

**Spec:** `docs/superpowers/specs/2026-08-15-recon-platform-design.md`

## Scope note

This plan implements a deliberately narrowed slice of the spec's Fase 1 so it
stays reviewable as one plan:

- **Modules implemented:** subfinder, crt.sh, WHOIS, httpx (resolve + tech
  detect). The remaining Fase 1 catalog items (ASN/cloud-range matching, code
  leak search, document metadata, employee OSINT, subdomain permutation) are
  deferred to a Phase 1b plan.
- **Data model:** simplified to `Project` / `Scan` / `Finding` (no
  `Asset`/`AssetRelation` graph tables yet). The spec's graph correlation
  layer is real work but isn't needed until Phase 3 (CVE correlation) actually
  queries it — building it now would be speculative. Phase 1b or the Phase 3
  plan introduces it.
- **Progress reporting:** simple polling (`GET /scans/{id}`) instead of SSE.
  SSE is a pure UX upgrade over the same data and is deferred to Phase 1b.
- **Migrations:** `Base.metadata.create_all()` at startup instead of Alembic.
  Alembic earns its keep once the schema needs versioned changes in
  production; premature here.

## Global Constraints

- Every `Project` requires `scope_notes` (non-empty) and `authorized: true`
  before any `Scan` can be created — from spec "Autorização e controles de
  segurança".
- The platform is a locally-run web app (backend on `localhost`, no
  multi-tenant/auth concerns in this phase) — from spec "Interface".
- Modules orchestrate external tools via subprocess and normalize output into
  a common `Finding` shape — from spec "Arquitetura".

---

## File Structure

```
backend/
  requirements.txt
  docker-compose.yml
  .env.example
  app/
    __init__.py
    config.py
    db.py
    models.py
    schemas.py
    main.py
    celery_app.py
    tasks.py
    orchestrator.py
    modules/
      __init__.py
      base.py
      subfinder.py
      crtsh.py
      whois_module.py
      httpx_probe.py
    routers/
      __init__.py
      projects.py
      scans.py
  tests/
    conftest.py
    test_health.py
    test_modules_subfinder.py
    test_modules_crtsh.py
    test_modules_whois.py
    test_modules_httpx_probe.py
    test_orchestrator.py
    test_tasks.py
    test_api_projects.py
    test_api_scans.py
  scripts/
    install.ps1
    install.sh
frontend/
  package.json
  vite.config.ts
  index.html
  src/
    main.tsx
    App.tsx
    api/
      client.ts
      client.test.ts
    pages/
      ProjectsList.tsx
      NewProject.tsx
      NewProject.test.tsx
      ProjectDetail.tsx
      ScanReport.tsx
      ScanReport.test.tsx
```

---

### Task 1: Backend project skeleton and health check

**Files:**
- Create: `backend/requirements.txt`
- Create: `backend/.env.example`
- Create: `backend/docker-compose.yml`
- Create: `backend/app/__init__.py`
- Create: `backend/app/config.py`
- Create: `backend/app/db.py`
- Create: `backend/app/main.py`
- Create: `backend/tests/__init__.py`
- Create: `backend/tests/conftest.py`
- Test: `backend/tests/test_health.py`

**Interfaces:**
- Produces: `app.config.settings` (object with `.database_url: str`,
  `.redis_url: str`); `app.db.Base` (SQLAlchemy declarative base),
  `app.db.engine`, `app.db.SessionLocal`, `app.db.get_db()` generator; `app.main.app`
  (FastAPI instance).

- [ ] **Step 1: Write the failing test**

`backend/tests/conftest.py`:
```python
import os
import tempfile

_db_fd, _db_path = tempfile.mkstemp(suffix=".db")
os.close(_db_fd)
os.environ["DATABASE_URL"] = f"sqlite:///{_db_path}"
os.environ["CELERY_TASK_ALWAYS_EAGER"] = "true"

import pytest


@pytest.fixture(scope="session", autouse=True)
def _cleanup_test_db():
    yield
    os.remove(_db_path)
```

`backend/tests/__init__.py`: empty file.

`backend/tests/test_health.py`:
```python
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_returns_ok():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest tests/test_health.py -v`
Expected: FAIL (collection error — `app` package doesn't exist yet)

- [ ] **Step 3: Write minimal implementation**

`backend/requirements.txt`:
```
fastapi
uvicorn[standard]
sqlalchemy
psycopg2-binary
celery
redis
python-whois
requests
httpx
pydantic
pytest
```

`backend/.env.example`:
```
DATABASE_URL=postgresql+psycopg2://recon:recon@localhost:5432/recon
REDIS_URL=redis://localhost:6379/0
```

`backend/docker-compose.yml`:
```yaml
version: "3.9"
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: recon
      POSTGRES_PASSWORD: recon
      POSTGRES_DB: recon
    ports:
      - "5432:5432"
  redis:
    image: redis:7
    ports:
      - "6379:6379"
```

`backend/app/__init__.py`: empty file.

`backend/app/config.py`:
```python
import os
from dataclasses import dataclass


@dataclass
class Settings:
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./dev.db")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")


settings = Settings()
```

`backend/app/db.py`:
```python
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

connect_args = (
    {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
)
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

`backend/app/main.py`:
```python
from fastapi import FastAPI

app = FastAPI(title="Recon Platform API")


@app.get("/health")
def health():
    return {"status": "ok"}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest tests/test_health.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/requirements.txt backend/.env.example backend/docker-compose.yml backend/app backend/tests
git commit -m "feat: add backend skeleton with health check"
```

---

### Task 2: Database models (Project, Scan, Finding)

**Files:**
- Create: `backend/app/models.py`
- Test: `backend/tests/test_models.py`

**Interfaces:**
- Consumes: `app.db.Base` (Task 1)
- Produces: `app.models.Project(id, name, target, scope_notes, authorized,
  authorized_at, created_at)`, `app.models.Scan(id, project_id, status,
  started_at, finished_at)`, `app.models.Finding(id, scan_id, module, type,
  value, data, created_at)`. `Scan.status` is one of
  `"pending"|"running"|"complete"|"failed"`.

- [ ] **Step 1: Write the failing test**

`backend/tests/test_models.py`:
```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest tests/test_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.models'`

- [ ] **Step 3: Write minimal implementation**

`backend/app/models.py`:
```python
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship

from app.db import Base


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    target = Column(String, nullable=False)
    scope_notes = Column(Text, nullable=False)
    authorized = Column(Boolean, nullable=False, default=False)
    authorized_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("Scan", back_populates="project")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    status = Column(String, nullable=False, default="pending")
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)

    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    module = Column(String, nullable=False)
    type = Column(String, nullable=False)
    value = Column(String, nullable=False)
    data = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest tests/test_models.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/models.py backend/tests/test_models.py
git commit -m "feat: add Project, Scan, and Finding models"
```

---

### Task 3: Module base interface

**Files:**
- Create: `backend/app/modules/__init__.py`
- Create: `backend/app/modules/base.py`
- Test: `backend/tests/test_modules_base.py`

**Interfaces:**
- Produces: `app.modules.base.Finding(type: str, value: str, data: dict =
  {})` (dataclass); `app.modules.base.ReconModule` (ABC with `name: str` class
  attribute and abstract method `run(self, target: str, context: dict) ->
  list[Finding]`). `context` is a plain dict the orchestrator threads through
  modules; by convention modules that discover subdomains add them to
  `context["subdomains"]: set[str]`.

- [ ] **Step 1: Write the failing test**

`backend/tests/test_modules_base.py`:
```python
import pytest

from app.modules.base import Finding, ReconModule


def test_finding_defaults_to_empty_data_dict():
    finding = Finding(type="subdomain", value="a.example.com")
    assert finding.data == {}


def test_recon_module_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        ReconModule()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest tests/test_modules_base.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.modules'`

- [ ] **Step 3: Write minimal implementation**

`backend/app/modules/__init__.py`: empty file.

`backend/app/modules/base.py`:
```python
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class Finding:
    type: str
    value: str
    data: dict = field(default_factory=dict)


class ReconModule(ABC):
    name: str

    @abstractmethod
    def run(self, target: str, context: dict) -> list[Finding]:
        ...
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest tests/test_modules_base.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/modules/__init__.py backend/app/modules/base.py backend/tests/test_modules_base.py
git commit -m "feat: add ReconModule plugin interface"
```

---

### Task 4: Subfinder module

**Files:**
- Create: `backend/app/modules/subfinder.py`
- Test: `backend/tests/test_modules_subfinder.py`

**Interfaces:**
- Consumes: `app.modules.base.Finding`, `app.modules.base.ReconModule` (Task 3)
- Produces: `app.modules.subfinder.SubfinderModule` (`name = "subfinder"`);
  `run(target, context)` returns one `Finding(type="subdomain", value=...)`
  per discovered subdomain, sorted, deduplicated.

- [ ] **Step 1: Write the failing test**

`backend/tests/test_modules_subfinder.py`:
```python
from unittest.mock import MagicMock, patch

from app.modules.subfinder import SubfinderModule


def test_subfinder_parses_stdout_into_subdomain_findings():
    fake_result = MagicMock(stdout="b.example.com\na.example.com\na.example.com\n")
    with patch("app.modules.subfinder.subprocess.run", return_value=fake_result) as mock_run:
        findings = SubfinderModule().run("example.com", {})

    mock_run.assert_called_once_with(
        ["subfinder", "-d", "example.com", "-silent"],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )
    assert [f.value for f in findings] == ["a.example.com", "b.example.com"]
    assert all(f.type == "subdomain" for f in findings)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest tests/test_modules_subfinder.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.modules.subfinder'`

- [ ] **Step 3: Write minimal implementation**

`backend/app/modules/subfinder.py`:
```python
import subprocess

from app.modules.base import Finding, ReconModule


class SubfinderModule(ReconModule):
    name = "subfinder"

    def run(self, target: str, context: dict) -> list[Finding]:
        result = subprocess.run(
            ["subfinder", "-d", target, "-silent"],
            capture_output=True,
            text=True,
            timeout=300,
            check=True,
        )
        subdomains = {line.strip() for line in result.stdout.splitlines() if line.strip()}
        return [Finding(type="subdomain", value=s) for s in sorted(subdomains)]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest tests/test_modules_subfinder.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/modules/subfinder.py backend/tests/test_modules_subfinder.py
git commit -m "feat: add subfinder recon module"
```

---

### Task 5: crt.sh module

**Files:**
- Create: `backend/app/modules/crtsh.py`
- Test: `backend/tests/test_modules_crtsh.py`

**Interfaces:**
- Consumes: `app.modules.base.Finding`, `app.modules.base.ReconModule` (Task 3)
- Produces: `app.modules.crtsh.CrtShModule` (`name = "crtsh"`); `run(target,
  context)` returns `Finding(type="subdomain", value=..., data={"source":
  "crt.sh"})` per unique hostname found in certificate transparency logs.

- [ ] **Step 1: Write the failing test**

`backend/tests/test_modules_crtsh.py`:
```python
from unittest.mock import MagicMock, patch

from app.modules.crtsh import CrtShModule


def test_crtsh_extracts_unique_subdomains_from_certificate_entries():
    fake_response = MagicMock()
    fake_response.raise_for_status.return_value = None
    fake_response.json.return_value = [
        {"name_value": "a.example.com\n*.a.example.com"},
        {"name_value": "b.example.com"},
        {"name_value": "unrelated.org"},
    ]
    with patch("app.modules.crtsh.requests.get", return_value=fake_response) as mock_get:
        findings = CrtShModule().run("example.com", {})

    mock_get.assert_called_once_with(
        "https://crt.sh/",
        params={"q": "%.example.com", "output": "json"},
        timeout=30,
    )
    assert [f.value for f in findings] == ["a.example.com", "b.example.com"]
    assert all(f.data["source"] == "crt.sh" for f in findings)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest tests/test_modules_crtsh.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.modules.crtsh'`

- [ ] **Step 3: Write minimal implementation**

`backend/app/modules/crtsh.py`:
```python
import requests

from app.modules.base import Finding, ReconModule


class CrtShModule(ReconModule):
    name = "crtsh"

    def run(self, target: str, context: dict) -> list[Finding]:
        response = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{target}", "output": "json"},
            timeout=30,
        )
        response.raise_for_status()

        subdomains = set()
        for entry in response.json():
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.")
                if name.endswith(target):
                    subdomains.add(name)

        return [
            Finding(type="subdomain", value=s, data={"source": "crt.sh"})
            for s in sorted(subdomains)
        ]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest tests/test_modules_crtsh.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/modules/crtsh.py backend/tests/test_modules_crtsh.py
git commit -m "feat: add crt.sh recon module"
```

---

### Task 6: WHOIS module

**Files:**
- Create: `backend/app/modules/whois_module.py`
- Test: `backend/tests/test_modules_whois.py`

**Interfaces:**
- Consumes: `app.modules.base.Finding`, `app.modules.base.ReconModule` (Task 3)
- Produces: `app.modules.whois_module.WhoisModule` (`name = "whois"`);
  `run(target, context)` returns exactly one `Finding(type="whois",
  value=target, data={registrar, creation_date, expiration_date,
  name_servers})`.

- [ ] **Step 1: Write the failing test**

`backend/tests/test_modules_whois.py`:
```python
from unittest.mock import patch

from app.modules.whois_module import WhoisModule


def test_whois_returns_single_finding_with_registration_data():
    fake_record = {
        "registrar": "Example Registrar",
        "creation_date": "2010-01-01",
        "expiration_date": "2030-01-01",
        "name_servers": ["ns1.example.com", "ns2.example.com"],
    }
    with patch("app.modules.whois_module.whois.whois", return_value=fake_record):
        findings = WhoisModule().run("example.com", {})

    assert len(findings) == 1
    assert findings[0].type == "whois"
    assert findings[0].value == "example.com"
    assert findings[0].data["registrar"] == "Example Registrar"
    assert findings[0].data["name_servers"] == ["ns1.example.com", "ns2.example.com"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest tests/test_modules_whois.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.modules.whois_module'`

- [ ] **Step 3: Write minimal implementation**

`backend/app/modules/whois_module.py`:
```python
import whois

from app.modules.base import Finding, ReconModule


class WhoisModule(ReconModule):
    name = "whois"

    def run(self, target: str, context: dict) -> list[Finding]:
        record = whois.whois(target)
        data = {
            "registrar": record.get("registrar"),
            "creation_date": str(record.get("creation_date")),
            "expiration_date": str(record.get("expiration_date")),
            "name_servers": record.get("name_servers"),
        }
        return [Finding(type="whois", value=target, data=data)]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest tests/test_modules_whois.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/modules/whois_module.py backend/tests/test_modules_whois.py
git commit -m "feat: add whois recon module"
```

---

### Task 7: httpx probe module (resolve + tech detect)

**Files:**
- Create: `backend/app/modules/httpx_probe.py`
- Test: `backend/tests/test_modules_httpx_probe.py`

**Interfaces:**
- Consumes: `app.modules.base.Finding`, `app.modules.base.ReconModule` (Task
  3); reads `context["subdomains"]: set[str]` if present (populated by Task
  4/5 modules).
- Produces: `app.modules.httpx_probe.HttpxProbeModule` (`name =
  "httpx_probe"`); `run(target, context)` returns
  `Finding(type="live_host", value=url, data={status_code, technologies,
  title})` per responsive host.

- [ ] **Step 1: Write the failing test**

`backend/tests/test_modules_httpx_probe.py`:
```python
from unittest.mock import MagicMock, patch

from app.modules.httpx_probe import HttpxProbeModule


def test_httpx_probe_parses_json_lines_into_live_host_findings():
    fake_output = (
        '{"url": "https://a.example.com", "input": "a.example.com", '
        '"status_code": 200, "tech": ["nginx"], "title": "A"}\n'
    )
    fake_result = MagicMock(stdout=fake_output)
    with patch("app.modules.httpx_probe.subprocess.run", return_value=fake_result) as mock_run:
        findings = HttpxProbeModule().run(
            "example.com", {"subdomains": {"a.example.com"}}
        )

    called_input = mock_run.call_args.kwargs["input"]
    assert "a.example.com" in called_input
    assert "example.com" in called_input
    assert len(findings) == 1
    assert findings[0].type == "live_host"
    assert findings[0].value == "https://a.example.com"
    assert findings[0].data["technologies"] == ["nginx"]
    assert findings[0].data["status_code"] == 200


def test_httpx_probe_falls_back_to_target_when_no_subdomains_discovered():
    fake_result = MagicMock(stdout="")
    with patch("app.modules.httpx_probe.subprocess.run", return_value=fake_result) as mock_run:
        HttpxProbeModule().run("example.com", {})

    assert mock_run.call_args.kwargs["input"] == "example.com"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest tests/test_modules_httpx_probe.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.modules.httpx_probe'`

- [ ] **Step 3: Write minimal implementation**

`backend/app/modules/httpx_probe.py`:
```python
import json
import subprocess

from app.modules.base import Finding, ReconModule


class HttpxProbeModule(ReconModule):
    name = "httpx_probe"

    def run(self, target: str, context: dict) -> list[Finding]:
        hosts = context.get("subdomains", set()) | {target}
        result = subprocess.run(
            ["httpx", "-silent", "-json", "-tech-detect"],
            input="\n".join(sorted(hosts)),
            capture_output=True,
            text=True,
            timeout=300,
            check=True,
        )

        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            findings.append(
                Finding(
                    type="live_host",
                    value=record.get("url", record.get("input", "")),
                    data={
                        "status_code": record.get("status_code"),
                        "technologies": record.get("tech", []),
                        "title": record.get("title"),
                    },
                )
            )
        return findings
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest tests/test_modules_httpx_probe.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/modules/httpx_probe.py backend/tests/test_modules_httpx_probe.py
git commit -m "feat: add httpx resolve/tech-detect recon module"
```

---

### Task 8: Orchestrator

**Files:**
- Create: `backend/app/orchestrator.py`
- Test: `backend/tests/test_orchestrator.py`

**Interfaces:**
- Consumes: `app.db.SessionLocal` (Task 1); `app.models.Scan`,
  `app.models.Finding` (Task 2); all four modules' `.run(target, context)`
  (Tasks 4-7)
- Produces: `app.orchestrator.run_scan(scan_id: int) -> None`. Sets
  `scan.status` to `"running"` then `"complete"` (or `"failed"` on exception,
  which is re-raised after marking the scan failed), and persists one
  `Finding` row per item any module returns.

- [ ] **Step 1: Write the failing test**

`backend/tests/test_orchestrator.py`:
```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest tests/test_orchestrator.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.orchestrator'`

- [ ] **Step 3: Write minimal implementation**

`backend/app/orchestrator.py`:
```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest tests/test_orchestrator.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/orchestrator.py backend/tests/test_orchestrator.py
git commit -m "feat: add scan orchestrator"
```

---

### Task 9: Celery app and scan task

**Files:**
- Create: `backend/app/celery_app.py`
- Create: `backend/app/tasks.py`
- Test: `backend/tests/test_tasks.py`

**Interfaces:**
- Consumes: `app.orchestrator.run_scan` (Task 8), `app.config.settings`
  (Task 1)
- Produces: `app.celery_app.celery_app` (Celery instance, `task_always_eager`
  driven by `CELERY_TASK_ALWAYS_EAGER` env var); `app.tasks.run_scan_task`
  (Celery task; `.delay(scan_id)` for async dispatch, `.run(scan_id)` calls it
  synchronously in-process).

- [ ] **Step 1: Write the failing test**

`backend/tests/test_tasks.py`:
```python
from unittest.mock import patch

from app.tasks import run_scan_task


def test_run_scan_task_calls_orchestrator_run_scan():
    with patch("app.tasks.run_scan") as mock_run_scan:
        run_scan_task.run(42)

    mock_run_scan.assert_called_once_with(42)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest tests/test_tasks.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.tasks'`

- [ ] **Step 3: Write minimal implementation**

`backend/app/celery_app.py`:
```python
import os

from celery import Celery

from app.config import settings

celery_app = Celery("recon", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.task_always_eager = (
    os.getenv("CELERY_TASK_ALWAYS_EAGER", "false").lower() == "true"
)
```

`backend/app/tasks.py`:
```python
from app.celery_app import celery_app
from app.orchestrator import run_scan


@celery_app.task(name="run_scan_task")
def run_scan_task(scan_id: int):
    run_scan(scan_id)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest tests/test_tasks.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/celery_app.py backend/app/tasks.py backend/tests/test_tasks.py
git commit -m "feat: add celery task wrapping the orchestrator"
```

---

### Task 10: API — Projects router

**Files:**
- Create: `backend/app/schemas.py`
- Create: `backend/app/routers/__init__.py`
- Create: `backend/app/routers/projects.py`
- Modify: `backend/app/main.py`
- Test: `backend/tests/test_api_projects.py`

**Interfaces:**
- Consumes: `app.db.get_db` (Task 1), `app.models.Project` (Task 2)
- Produces: `app.schemas.ProjectCreate`, `app.schemas.ProjectOut`;
  `app.routers.projects.router` mounted at `/projects` with `POST /projects`
  (rejects `authorized=False` with 422), `GET /projects`, `GET
  /projects/{id}`.

- [ ] **Step 1: Write the failing test**

`backend/tests/test_api_projects.py`:
```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest tests/test_api_projects.py -v`
Expected: FAIL with 404 (no `/projects` route registered yet)

- [ ] **Step 3: Write minimal implementation**

`backend/app/schemas.py`:
```python
from datetime import datetime

from pydantic import BaseModel, field_validator


class ProjectCreate(BaseModel):
    name: str
    target: str
    scope_notes: str
    authorized: bool

    @field_validator("authorized")
    @classmethod
    def must_be_authorized(cls, v: bool) -> bool:
        if not v:
            raise ValueError("authorized must be true to create a project")
        return v

    @field_validator("scope_notes")
    @classmethod
    def scope_notes_must_not_be_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("scope_notes must not be blank")
        return v


class ProjectOut(BaseModel):
    id: int
    name: str
    target: str
    scope_notes: str
    authorized: bool
    created_at: datetime

    class Config:
        from_attributes = True


class ScanOut(BaseModel):
    id: int
    project_id: int
    status: str
    started_at: datetime | None
    finished_at: datetime | None

    class Config:
        from_attributes = True


class FindingOut(BaseModel):
    id: int
    module: str
    type: str
    value: str
    data: dict

    class Config:
        from_attributes = True
```

`backend/app/routers/__init__.py`: empty file.

`backend/app/routers/projects.py`:
```python
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models, schemas
from app.db import get_db

router = APIRouter(prefix="/projects", tags=["projects"])


@router.post("", response_model=schemas.ProjectOut, status_code=201)
def create_project(payload: schemas.ProjectCreate, db: Session = Depends(get_db)):
    project = models.Project(
        name=payload.name,
        target=payload.target,
        scope_notes=payload.scope_notes,
        authorized=payload.authorized,
        authorized_at=datetime.utcnow(),
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@router.get("", response_model=list[schemas.ProjectOut])
def list_projects(db: Session = Depends(get_db)):
    return db.query(models.Project).all()


@router.get("/{project_id}", response_model=schemas.ProjectOut)
def get_project(project_id: int, db: Session = Depends(get_db)):
    project = db.get(models.Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="project not found")
    return project
```

`backend/app/main.py`:
```python
from fastapi import FastAPI

from app.db import Base, engine
from app.routers import projects

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Recon Platform API")
app.include_router(projects.router)


@app.get("/health")
def health():
    return {"status": "ok"}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest tests/test_api_projects.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/schemas.py backend/app/routers backend/app/main.py backend/tests/test_api_projects.py
git commit -m "feat: add projects API"
```

---

### Task 11: API — Scans router

**Files:**
- Create: `backend/app/routers/scans.py`
- Modify: `backend/app/main.py`
- Test: `backend/tests/test_api_scans.py`

**Interfaces:**
- Consumes: `app.db.get_db`, `app.models.Project`, `app.models.Scan` (Task
  2); `app.schemas.ScanOut`, `app.schemas.FindingOut` (Task 10);
  `app.tasks.run_scan_task` (Task 9)
- Produces: `app.routers.scans.router` with `POST
  /projects/{project_id}/scans` (403 if project not authorized, enqueues
  `run_scan_task.delay(scan.id)`), `GET /scans/{id}`, `GET
  /scans/{id}/findings`.

- [ ] **Step 1: Write the failing test**

`backend/tests/test_api_scans.py`:
```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest tests/test_api_scans.py -v`
Expected: FAIL with 404 (no scans routes registered yet)

- [ ] **Step 3: Write minimal implementation**

`backend/app/routers/scans.py`:
```python
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models, schemas
from app.db import get_db
from app.tasks import run_scan_task

router = APIRouter(tags=["scans"])


@router.post("/projects/{project_id}/scans", response_model=schemas.ScanOut, status_code=201)
def create_scan(project_id: int, db: Session = Depends(get_db)):
    project = db.get(models.Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="project not found")
    if not project.authorized:
        raise HTTPException(status_code=403, detail="project is not authorized for scanning")

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
```

`backend/app/main.py`:
```python
from fastapi import FastAPI

from app.db import Base, engine
from app.routers import projects, scans

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Recon Platform API")
app.include_router(projects.router)
app.include_router(scans.router)


@app.get("/health")
def health():
    return {"status": "ok"}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest tests/test_api_scans.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/routers/scans.py backend/app/main.py backend/tests/test_api_scans.py
git commit -m "feat: add scans API"
```

---

### Task 12: External tool setup scripts

**Files:**
- Create: `backend/scripts/install.ps1`
- Create: `backend/scripts/install.sh`

**Interfaces:**
- None (standalone operator scripts, not imported by application code).

- [ ] **Step 1: Write the scripts**

`backend/scripts/install.ps1`:
```powershell
$tools = @{
    "subfinder" = "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "httpx"     = "github.com/projectdiscovery/httpx/cmd/httpx@latest"
}

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Host "Go is not installed. Install Go from https://go.dev/dl/ before running this script." -ForegroundColor Red
    exit 1
}

foreach ($tool in $tools.Keys) {
    if (Get-Command $tool -ErrorAction SilentlyContinue) {
        Write-Host "$tool already installed, skipping."
        continue
    }
    Write-Host "Installing $tool..."
    go install $tools[$tool]
}

Write-Host "Done. Ensure `$(go env GOPATH)\bin` is on your PATH."
```

`backend/scripts/install.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail

declare -A tools=(
  [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
)

if ! command -v go >/dev/null 2>&1; then
  echo "Go is not installed. Install Go from https://go.dev/dl/ before running this script." >&2
  exit 1
fi

for tool in "${!tools[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "$tool already installed, skipping."
    continue
  fi
  echo "Installing $tool..."
  go install "${tools[$tool]}"
done

echo "Done. Ensure \$(go env GOPATH)/bin is on your PATH."
```

- [ ] **Step 2: Make the shell script executable and verify both scripts run**

Run: `chmod +x backend/scripts/install.sh`

Manual verification (no automated test — these are operator scripts, not
application code): run `./backend/scripts/install.sh` (or `.\install.ps1` on
Windows) and confirm `subfinder -version` and `httpx -version` both succeed
afterward.

- [ ] **Step 3: Commit**

```bash
git add backend/scripts/install.ps1 backend/scripts/install.sh
git commit -m "feat: add external recon tool install scripts"
```

---

### Task 13: Frontend skeleton and API client

**Files:**
- Create: `frontend/package.json`
- Create: `frontend/vite.config.ts`
- Create: `frontend/index.html`
- Create: `frontend/src/main.tsx`
- Create: `frontend/src/App.tsx`
- Create: `frontend/src/api/client.ts`
- Test: `frontend/src/api/client.test.ts`

**Interfaces:**
- Produces: `Project`, `Scan`, `Finding` TypeScript types;
  `listProjects()`, `createProject(payload)`, `getProject(id)`,
  `createScan(projectId)`, `getScan(id)`, `getScanFindings(id)` — all
  `Promise`-returning functions in `frontend/src/api/client.ts`.

- [ ] **Step 1: Write the failing test**

`frontend/src/api/client.test.ts`:
```typescript
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createProject, listProjects } from "./client";

describe("api client", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  it("listProjects calls GET /projects and returns parsed JSON", async () => {
    const projects = [
      {
        id: 1,
        name: "Test",
        target: "example.com",
        scope_notes: "ok",
        authorized: true,
        created_at: "2026-01-01",
      },
    ];
    (fetch as any).mockResolvedValueOnce({ ok: true, json: async () => projects });

    const result = await listProjects();

    expect(fetch).toHaveBeenCalledWith(
      "http://localhost:8000/projects",
      expect.objectContaining({ headers: { "Content-Type": "application/json" } }),
    );
    expect(result).toEqual(projects);
  });

  it("createProject throws when the response is not ok", async () => {
    (fetch as any).mockResolvedValueOnce({ ok: false, status: 422 });

    await expect(
      createProject({
        name: "Test",
        target: "example.com",
        scope_notes: "ok",
        authorized: false,
      }),
    ).rejects.toThrow("Request to /projects failed with status 422");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && npm install && npm test`
Expected: FAIL (`frontend/src/api/client.ts` doesn't exist yet)

- [ ] **Step 3: Write minimal implementation**

`frontend/package.json`:
```json
{
  "name": "recon-platform-frontend",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "test": "vitest run"
  },
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router-dom": "^6.26.0"
  },
  "devDependencies": {
    "@testing-library/jest-dom": "^6.4.8",
    "@testing-library/react": "^16.0.0",
    "@types/react": "^18.3.3",
    "@types/react-dom": "^18.3.0",
    "@vitejs/plugin-react": "^4.3.1",
    "jsdom": "^24.1.1",
    "typescript": "^5.5.4",
    "vite": "^5.4.0",
    "vitest": "^2.0.5"
  }
}
```

`frontend/vite.config.ts`:
```typescript
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
  },
});
```

`frontend/index.html`:
```html
<!doctype html>
<html lang="pt-BR">
  <head>
    <meta charset="UTF-8" />
    <title>Recon Platform</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

`frontend/src/api/client.ts`:
```typescript
const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

export interface Project {
  id: number;
  name: string;
  target: string;
  scope_notes: string;
  authorized: boolean;
  created_at: string;
}

export interface Scan {
  id: number;
  project_id: number;
  status: "pending" | "running" | "complete" | "failed";
  started_at: string | null;
  finished_at: string | null;
}

export interface Finding {
  id: number;
  module: string;
  type: string;
  value: string;
  data: Record<string, unknown>;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!response.ok) {
    throw new Error(`Request to ${path} failed with status ${response.status}`);
  }
  return response.json();
}

export function listProjects(): Promise<Project[]> {
  return request("/projects");
}

export function createProject(payload: {
  name: string;
  target: string;
  scope_notes: string;
  authorized: boolean;
}): Promise<Project> {
  return request("/projects", { method: "POST", body: JSON.stringify(payload) });
}

export function getProject(id: number): Promise<Project> {
  return request(`/projects/${id}`);
}

export function createScan(projectId: number): Promise<Scan> {
  return request(`/projects/${projectId}/scans`, { method: "POST" });
}

export function getScan(id: number): Promise<Scan> {
  return request(`/scans/${id}`);
}

export function getScanFindings(id: number): Promise<Finding[]> {
  return request(`/scans/${id}/findings`);
}
```

`frontend/src/App.tsx` (routes filled in by Tasks 14-15; placeholder-free
minimal version for now):
```tsx
import { BrowserRouter, Route, Routes } from "react-router-dom";

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<div>Recon Platform</div>} />
      </Routes>
    </BrowserRouter>
  );
}
```

`frontend/src/main.tsx`:
```tsx
import React from "react";
import ReactDOM from "react-dom/client";

import { App } from "./App";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd frontend && npm test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/package.json frontend/vite.config.ts frontend/index.html frontend/src/main.tsx frontend/src/App.tsx frontend/src/api
git commit -m "feat: add frontend skeleton and API client"
```

---

### Task 14: Frontend — ProjectsList and NewProject pages

**Files:**
- Create: `frontend/src/pages/ProjectsList.tsx`
- Create: `frontend/src/pages/NewProject.tsx`
- Modify: `frontend/src/App.tsx`
- Test: `frontend/src/pages/NewProject.test.tsx`

**Interfaces:**
- Consumes: `listProjects`, `createProject`, `Project` type (Task 13)
- Produces: `ProjectsList` component (route `/`); `NewProject` component
  (route `/projects/new`) — submit button disabled until the authorization
  checkbox is checked, navigates to `/projects/:id` on success.

- [ ] **Step 1: Write the failing test**

`frontend/src/pages/NewProject.test.tsx`:
```tsx
import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { NewProject } from "./NewProject";

describe("NewProject", () => {
  it("disables submit until authorized is checked", () => {
    render(
      <MemoryRouter>
        <NewProject />
      </MemoryRouter>,
    );

    const submit = screen.getByRole("button", { name: /criar projeto/i });
    expect(submit).toBeDisabled();

    fireEvent.click(screen.getByRole("checkbox"));

    expect(submit).toBeEnabled();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && npm test`
Expected: FAIL (`frontend/src/pages/NewProject.tsx` doesn't exist yet)

- [ ] **Step 3: Write minimal implementation**

`frontend/src/pages/ProjectsList.tsx`:
```tsx
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { listProjects, type Project } from "../api/client";

export function ProjectsList() {
  const [projects, setProjects] = useState<Project[]>([]);

  useEffect(() => {
    listProjects().then(setProjects);
  }, []);

  return (
    <div>
      <h1>Projetos</h1>
      <Link to="/projects/new">Novo projeto</Link>
      <ul>
        {projects.map((project) => (
          <li key={project.id}>
            <Link to={`/projects/${project.id}`}>
              {project.name} ({project.target})
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
```

`frontend/src/pages/NewProject.tsx`:
```tsx
import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";

import { createProject } from "../api/client";

export function NewProject() {
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [target, setTarget] = useState("");
  const [scopeNotes, setScopeNotes] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    try {
      const project = await createProject({
        name,
        target,
        scope_notes: scopeNotes,
        authorized,
      });
      navigate(`/projects/${project.id}`);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <h1>Novo Projeto</h1>
      <label>
        Nome
        <input value={name} onChange={(e) => setName(e.target.value)} required />
      </label>
      <label>
        Alvo (dominio)
        <input value={target} onChange={(e) => setTarget(e.target.value)} required />
      </label>
      <label>
        Escopo autorizado
        <textarea
          value={scopeNotes}
          onChange={(e) => setScopeNotes(e.target.value)}
          required
        />
      </label>
      <label>
        <input
          type="checkbox"
          checked={authorized}
          onChange={(e) => setAuthorized(e.target.checked)}
        />
        Confirmo que tenho autorizacao para testar este alvo
      </label>
      {error && <p role="alert">{error}</p>}
      <button type="submit" disabled={!authorized}>
        Criar projeto
      </button>
    </form>
  );
}
```

`frontend/src/App.tsx`:
```tsx
import { BrowserRouter, Route, Routes } from "react-router-dom";

import { NewProject } from "./pages/NewProject";
import { ProjectsList } from "./pages/ProjectsList";

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<ProjectsList />} />
        <Route path="/projects/new" element={<NewProject />} />
      </Routes>
    </BrowserRouter>
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd frontend && npm test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/ProjectsList.tsx frontend/src/pages/NewProject.tsx frontend/src/pages/NewProject.test.tsx frontend/src/App.tsx
git commit -m "feat: add ProjectsList and NewProject pages"
```

---

### Task 15: Frontend — ProjectDetail and ScanReport pages

**Files:**
- Create: `frontend/src/pages/ProjectDetail.tsx`
- Create: `frontend/src/pages/ScanReport.tsx`
- Modify: `frontend/src/App.tsx`
- Test: `frontend/src/pages/ScanReport.test.tsx`

**Interfaces:**
- Consumes: `getProject`, `createScan`, `getScan`, `getScanFindings`,
  `Project`/`Scan`/`Finding` types (Task 13)
- Produces: `ProjectDetail` component (route `/projects/:id`) — shows project
  info and a "Novo scan" button that navigates to `/scans/:id`; `ScanReport`
  component (route `/scans/:id`) — polls `getScan` every 3s until status is
  `complete`/`failed`, then renders `getScanFindings` in a table.

- [ ] **Step 1: Write the failing test**

`frontend/src/pages/ScanReport.test.tsx`:
```tsx
import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";

import * as client from "../api/client";
import { ScanReport } from "./ScanReport";

describe("ScanReport", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows findings once the scan status is complete", async () => {
    vi.spyOn(client, "getScan").mockResolvedValue({
      id: 1,
      project_id: 1,
      status: "complete",
      started_at: null,
      finished_at: null,
    });
    vi.spyOn(client, "getScanFindings").mockResolvedValue([
      { id: 1, module: "subfinder", type: "subdomain", value: "a.example.com", data: {} },
    ]);

    render(
      <MemoryRouter initialEntries={["/scans/1"]}>
        <Routes>
          <Route path="/scans/:id" element={<ScanReport />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText("Status: complete")).toBeInTheDocument();
    expect(await screen.findByText("a.example.com")).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && npm test`
Expected: FAIL (`frontend/src/pages/ScanReport.tsx` doesn't exist yet)

- [ ] **Step 3: Write minimal implementation**

`frontend/src/pages/ProjectDetail.tsx`:
```tsx
import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

import { createScan, getProject, type Project } from "../api/client";

export function ProjectDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [project, setProject] = useState<Project | null>(null);

  useEffect(() => {
    getProject(Number(id)).then(setProject);
  }, [id]);

  async function handleNewScan() {
    const scan = await createScan(Number(id));
    navigate(`/scans/${scan.id}`);
  }

  if (!project) return <p>Carregando...</p>;

  return (
    <div>
      <h1>{project.name}</h1>
      <p>Alvo: {project.target}</p>
      <p>Escopo: {project.scope_notes}</p>
      <button onClick={handleNewScan}>Novo scan</button>
    </div>
  );
}
```

`frontend/src/pages/ScanReport.tsx`:
```tsx
import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";

import { getScan, getScanFindings, type Finding, type Scan } from "../api/client";

const POLL_INTERVAL_MS = 3000;

export function ScanReport() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);

  useEffect(() => {
    const scanId = Number(id);
    let cancelled = false;
    let timer: ReturnType<typeof setInterval>;

    async function poll() {
      const current = await getScan(scanId);
      if (cancelled) return;
      setScan(current);
      if (current.status === "complete" || current.status === "failed") {
        clearInterval(timer);
        setFindings(await getScanFindings(scanId));
      }
    }

    poll();
    timer = setInterval(poll, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [id]);

  if (!scan) return <p>Carregando...</p>;

  return (
    <div>
      <h1>Scan #{scan.id}</h1>
      <p>Status: {scan.status}</p>
      <table>
        <thead>
          <tr>
            <th>Tipo</th>
            <th>Valor</th>
            <th>Modulo</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding) => (
            <tr key={finding.id}>
              <td>{finding.type}</td>
              <td>{finding.value}</td>
              <td>{finding.module}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

`frontend/src/App.tsx`:
```tsx
import { BrowserRouter, Route, Routes } from "react-router-dom";

import { NewProject } from "./pages/NewProject";
import { ProjectDetail } from "./pages/ProjectDetail";
import { ProjectsList } from "./pages/ProjectsList";
import { ScanReport } from "./pages/ScanReport";

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<ProjectsList />} />
        <Route path="/projects/new" element={<NewProject />} />
        <Route path="/projects/:id" element={<ProjectDetail />} />
        <Route path="/scans/:id" element={<ScanReport />} />
      </Routes>
    </BrowserRouter>
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd frontend && npm test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/ProjectDetail.tsx frontend/src/pages/ScanReport.tsx frontend/src/pages/ScanReport.test.tsx frontend/src/App.tsx
git commit -m "feat: add ProjectDetail and ScanReport pages"
```
