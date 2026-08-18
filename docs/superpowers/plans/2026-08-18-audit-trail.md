# Full Audit Trail (Fase D) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record every individual network request the tool makes (target-facing and third-party) as an `AuditEntry` row, separately exportable from the findings report via a new `audit` CLI command, and close Fase C's known gap by recording an `out_of_scope` Finding when the orchestrator filters a discovered subdomain out of scope.

**Architecture:** A small `AuditLog` accumulator (mirrors Fase B's `RateLimiter`/`CircuitBreaker` shape) gets threaded through `context["audit"]` the same way `rate_limit`/`circuit_breaker_threshold`/`scope` already are. Every module that makes a real network call records into it at each call site; the orchestrator persists the accumulated entries to a new `AuditEntry` table right after each module's `run()` returns (same point it already persists that module's `Finding`s), then clears the list before the next module runs.

**Tech Stack:** Python 3.13, SQLAlchemy (SQLite), Typer, `rich`, stdlib `csv`, pytest. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-08-18-audit-trail-design.md`

## Global Constraints

- English is the primary CLI language, Portuguese is secondary via `--lang pt` (Fase A) — every new user-facing string (the `audit` command's table title/columns) needs both an `en` and `pt` entry in `app/i18n.py`.
- `context.get("scope")`/`context.get("rate_limit")`/`context.get("circuit_breaker_threshold")` already use the "a missing key means no restriction / use the default" pattern for backward compatibility with modules unit-tested outside the orchestrator (see `backend/app/modules/base.py`'s documented scope contract). `context.get("audit")` follows the exact same pattern: `None` when a module is invoked directly in a test with a bare context, a real `AuditLog` instance for every orchestrator-driven scan. Every module guards with `if audit is not None:` before calling `.record(...)`.
- A request that is attempted and fails still gets an audit entry (`outcome="error: <message>"`) — only a request that was never attempted (skipped for being out of scope, or skipped because the circuit breaker had already tripped) gets no entry at all.
- `AuditEntry` is a **new table**, not a new column on an existing table — `Base.metadata.create_all()` (already invoked via `ensure_schema()` in `app/db.py`) creates missing tables on any existing database automatically. No migration helper work needed for this table.
- `cd backend && pytest -v` must be fully green before every commit.

---

## Task 1: `AuditLog` accumulator (`app/audit.py`)

**Files:**
- Create: `backend/app/audit.py`
- Test: `backend/tests/test_audit.py`

**Interfaces:**
- Produces: `AuditLog` class with `.entries: list[dict]` and `.record(module: str, target: str, outcome: str, url: str | None = None) -> None`. Every entry dict has keys `module`, `target`, `url`, `outcome`, `requested_at`. Every later task that instruments a module or persists entries uses this exact shape.

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/test_audit.py
from app.audit import AuditLog


def test_record_appends_an_entry_with_the_given_fields():
    log = AuditLog()
    log.record(module="crtsh", target="example.com", outcome="200", url="https://crt.sh/")

    assert len(log.entries) == 1
    entry = log.entries[0]
    assert entry["module"] == "crtsh"
    assert entry["target"] == "example.com"
    assert entry["outcome"] == "200"
    assert entry["url"] == "https://crt.sh/"
    assert entry["requested_at"] is not None


def test_record_defaults_url_to_none():
    log = AuditLog()
    log.record(module="whois", target="example.com", outcome="success")

    assert log.entries[0]["url"] is None


def test_record_accumulates_multiple_entries_in_order():
    log = AuditLog()
    log.record(module="cloud_range", target="a.example.com", outcome="resolved: 1.2.3.4")
    log.record(module="cloud_range", target="b.example.com", outcome="error: timeout")

    assert [e["target"] for e in log.entries] == ["a.example.com", "b.example.com"]


def test_entries_can_be_cleared():
    log = AuditLog()
    log.record(module="crtsh", target="example.com", outcome="200")
    log.entries.clear()

    assert log.entries == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && python -m pytest tests/test_audit.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.audit'`

- [ ] **Step 3: Write the implementation**

```python
# backend/app/audit.py
"""In-memory accumulator for network-request audit entries. Every
module that makes a real network call records into the shared instance
threaded through context["audit"]; the orchestrator persists .entries
to the AuditEntry table right after each module's run() returns, then
clears the list before the next module runs."""

from app.timeutil import utc_now


class AuditLog:
    def __init__(self):
        self.entries: list[dict] = []

    def record(self, module: str, target: str, outcome: str, url: str | None = None) -> None:
        self.entries.append(
            {
                "module": module,
                "target": target,
                "url": url,
                "outcome": outcome,
                "requested_at": utc_now(),
            }
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_audit.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/audit.py backend/tests/test_audit.py
git commit -m "feat(audit): add AuditLog in-memory accumulator"
```

---

## Task 2: `AuditEntry` model

**Files:**
- Modify: `backend/app/models.py`
- Modify: `backend/tests/test_models.py`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `models.AuditEntry` (columns: `id, scan_id, module, target, url, outcome, requested_at`) and `models.Scan.audit_entries` relationship. Task 3 (orchestrator) creates rows of this type; Task 9 (CLI) reads `scan.audit_entries`.

- [ ] **Step 1: Write the failing test**

Add to `backend/tests/test_models.py`:

```python
def test_audit_entry_persists_and_is_reachable_from_scan():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = models.Project(
            name="Audit Co", target="audit.example.com", scope_notes="ok", authorized=True
        )
        db.add(project)
        db.commit()

        scan = models.Scan(project_id=project.id, status="pending")
        db.add(scan)
        db.commit()

        entry = models.AuditEntry(
            scan_id=scan.id,
            module="crtsh",
            target="audit.example.com",
            url="https://crt.sh/",
            outcome="200",
        )
        db.add(entry)
        db.commit()

        reloaded_scan = db.get(models.Scan, scan.id)
        assert reloaded_scan.audit_entries[0].module == "crtsh"
        assert reloaded_scan.audit_entries[0].target == "audit.example.com"
        assert reloaded_scan.audit_entries[0].url == "https://crt.sh/"
        assert reloaded_scan.audit_entries[0].outcome == "200"
        assert reloaded_scan.audit_entries[0].requested_at is not None
    finally:
        db.close()


def test_audit_entry_url_is_optional():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = models.Project(
            name="Audit No URL Co", target="nourl.example.com", scope_notes="ok", authorized=True
        )
        db.add(project)
        db.commit()

        scan = models.Scan(project_id=project.id, status="pending")
        db.add(scan)
        db.commit()

        entry = models.AuditEntry(
            scan_id=scan.id, module="whois", target="nourl.example.com", outcome="success"
        )
        db.add(entry)
        db.commit()

        reloaded_scan = db.get(models.Scan, scan.id)
        assert reloaded_scan.audit_entries[0].url is None
    finally:
        db.close()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && python -m pytest tests/test_models.py -v`
Expected: FAIL with `AttributeError: module 'app.models' has no attribute 'AuditEntry'`

- [ ] **Step 3: Add the model**

In `backend/app/models.py`, add the `audit_entries` relationship to `Scan` (currently reads exactly):

```python
    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")
```

Change to:

```python
    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")
    audit_entries = relationship("AuditEntry", back_populates="scan")
```

Then add a new `AuditEntry` class at the end of the file, after `Finding`:

```python
class AuditEntry(Base):
    __tablename__ = "audit_entries"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    module = Column(String, nullable=False)
    target = Column(String, nullable=False)
    url = Column(String, nullable=True)
    outcome = Column(String, nullable=False)
    requested_at = Column(DateTime, default=utc_now)

    scan = relationship("Scan", back_populates="audit_entries")
```

No new imports needed — `Column, DateTime, ForeignKey, Integer, String` are already imported at the top of the file, and `utc_now` is already imported from `app.timeutil`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_models.py -v`
Expected: all PASS

- [ ] **Step 5: Run the full suite**

Run: `cd backend && python -m pytest -v`
Expected: all PASS (this is a new table; `ensure_schema()`'s `Base.metadata.create_all()` picks it up automatically, no migration helper changes needed)

- [ ] **Step 6: Commit**

```bash
git add backend/app/models.py backend/tests/test_models.py
git commit -m "feat(audit): add AuditEntry model and Scan.audit_entries relationship"
```

---

## Task 3: Orchestrator threads `context["audit"]`, persists per module, and records `out_of_scope` for discovery-filtered subdomains

**Files:**
- Modify: `backend/app/orchestrator.py`
- Modify: `backend/tests/test_orchestrator.py`

**Interfaces:**
- Consumes: `app.audit.AuditLog` (Task 1), `models.AuditEntry` (Task 2).
- Produces: `context["audit"]` (a real `AuditLog` instance) available to every module from here on — Task 4-8's modules read `context.get("audit")`, treating `None` as "no restriction" (only relevant when a module is unit-tested directly with a bare `{}` context), exactly like the existing `scope` contract in `backend/app/modules/base.py`.

- [ ] **Step 1: Write the failing tests**

Add to `backend/tests/test_orchestrator.py`:

```python
def test_run_scan_persists_audit_entries_recorded_by_a_module():
    class _AuditingModule(ReconModule):
        name = "_test_auditing_module"
        run_order = 20

        def run(self, target, context):
            context["audit"].record(module=self.name, target=target, outcome="200", url="https://example.com/")
            return []

    scan_id = _create_authorized_project_and_scan()
    try:
        register_module(_AuditingModule)
        with _mock_all_modules(exclude={_AuditingModule.name}):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_AuditingModule.name]

    db = SessionLocal()
    try:
        entries = db.query(models.AuditEntry).filter_by(scan_id=scan_id).all()
    finally:
        db.close()

    assert len(entries) == 1
    assert entries[0].module == "_test_auditing_module"
    assert entries[0].target == "example.com"
    assert entries[0].outcome == "200"
    assert entries[0].url == "https://example.com/"


def test_run_scan_persists_audit_entries_from_each_module_separately_without_duplication():
    class _FirstAuditingModule(ReconModule):
        name = "_test_first_auditing_module"
        run_order = 20

        def run(self, target, context):
            context["audit"].record(module=self.name, target=target, outcome="200")
            return []

    class _SecondAuditingModule(ReconModule):
        name = "_test_second_auditing_module"
        run_order = 30

        def run(self, target, context):
            context["audit"].record(module=self.name, target=target, outcome="404")
            return []

    scan_id = _create_authorized_project_and_scan()
    try:
        register_module(_FirstAuditingModule)
        register_module(_SecondAuditingModule)
        with _mock_all_modules(
            exclude={_FirstAuditingModule.name, _SecondAuditingModule.name}
        ):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_FirstAuditingModule.name]
        del MODULE_REGISTRY[_SecondAuditingModule.name]

    db = SessionLocal()
    try:
        entries = db.query(models.AuditEntry).filter_by(scan_id=scan_id).all()
    finally:
        db.close()

    assert len(entries) == 2
    by_module = {e.module: e.outcome for e in entries}
    assert by_module == {
        "_test_first_auditing_module": "200",
        "_test_second_auditing_module": "404",
    }


def test_run_scan_keeps_audit_entries_recorded_before_a_module_crashes():
    class _CrashingAuditingModule(ReconModule):
        name = "_test_crashing_auditing_module"
        run_order = 20

        def run(self, target, context):
            context["audit"].record(module=self.name, target=target, outcome="error: connection reset")
            raise RuntimeError("boom")

    scan_id = _create_authorized_project_and_scan()
    try:
        register_module(_CrashingAuditingModule)
        with _mock_all_modules(exclude={_CrashingAuditingModule.name}):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_CrashingAuditingModule.name]

    db = SessionLocal()
    try:
        entries = db.query(models.AuditEntry).filter_by(scan_id=scan_id).all()
        findings = db.query(models.Finding).filter_by(scan_id=scan_id).all()
    finally:
        db.close()

    assert len(entries) == 1
    assert entries[0].outcome == "error: connection reset"
    assert any(f.type == "module_error" and f.module == "_test_crashing_auditing_module" for f in findings)


def test_run_scan_records_out_of_scope_finding_for_discovery_filtered_subdomain():
    class _DiscoveryModule(ReconModule):
        name = "_test_discovery_module_for_audit"
        run_order = 10

        def run(self, target, context):
            return [Finding(type="subdomain", value="blocked.example.com")]

    db = SessionLocal()
    try:
        project = models.Project(
            name="Discovery Scope Co",
            target="example.com",
            scope_notes="only example.com",
            authorized=True,
            scope={"include": ["example.com"], "exclude": ["blocked.example.com"]},
        )
        db.add(project)
        db.commit()
        scan = models.Scan(project_id=project.id, status="pending")
        db.add(scan)
        db.commit()
        scan_id = scan.id
    finally:
        db.close()

    try:
        register_module(_DiscoveryModule)
        with _mock_all_modules(exclude={_DiscoveryModule.name}):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_DiscoveryModule.name]

    db = SessionLocal()
    try:
        findings = db.query(models.Finding).filter_by(scan_id=scan_id).all()
    finally:
        db.close()

    out_of_scope = [f for f in findings if f.type == "out_of_scope" and f.value == "blocked.example.com"]
    assert len(out_of_scope) == 1
    assert out_of_scope[0].module == "orchestrator"
    assert out_of_scope[0].data == {"module": "orchestrator"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && python -m pytest tests/test_orchestrator.py -k "audit or discovery_filtered" -v`
Expected: FAIL — `context["audit"]` doesn't exist yet (`KeyError`), and no `out_of_scope` Finding is recorded for the discovery-filtered subdomain

- [ ] **Step 3: Implement the orchestrator changes**

In `backend/app/orchestrator.py`, add the import:

```python
from app.audit import AuditLog
```

Change the context construction (currently):

```python
        target = scan.project.target
        context: dict = {
            "subdomains": set(),
            "technologies": [],
            "rate_limit": rate_limit,
            "circuit_breaker_threshold": circuit_breaker_threshold,
            "scope": scan.project.scope or {},
        }
```

to also carry `audit`:

```python
        target = scan.project.target
        context: dict = {
            "subdomains": set(),
            "technologies": [],
            "rate_limit": rate_limit,
            "circuit_breaker_threshold": circuit_breaker_threshold,
            "scope": scan.project.scope or {},
            "audit": AuditLog(),
        }
```

Change the per-module loop (currently):

```python
            module = module_cls()
            for finding in _run_module(db, scan_id, module, target, context):
                if finding.type == "subdomain":
                    if is_in_scope(finding.value, None, context["scope"]):
                        context["subdomains"].add(finding.value)
                elif finding.type == "technology":
                    context["technologies"].append(dict(finding.data))
```

to:

```python
            module = module_cls()
            module_findings = _run_module(db, scan_id, module, target, context)
            _persist_audit_entries(db, scan_id, context["audit"])
            for finding in module_findings:
                if finding.type == "subdomain":
                    if is_in_scope(finding.value, None, context["scope"]):
                        context["subdomains"].add(finding.value)
                    else:
                        _persist(
                            db,
                            scan_id,
                            "orchestrator",
                            Finding(
                                type="out_of_scope",
                                value=finding.value,
                                data={"module": "orchestrator"},
                            ),
                        )
                elif finding.type == "technology":
                    context["technologies"].append(dict(finding.data))
```

Then add a new `_persist_audit_entries` function, right after the existing `_persist` function at the bottom of the file:

```python
def _persist_audit_entries(db, scan_id: int, audit_log: AuditLog) -> None:
    for entry in audit_log.entries:
        db.add(
            models.AuditEntry(
                scan_id=scan_id,
                module=entry["module"],
                target=entry["target"],
                url=entry.get("url"),
                outcome=entry["outcome"],
                requested_at=entry["requested_at"],
            )
        )
    db.commit()
    audit_log.entries.clear()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_orchestrator.py -v`
Expected: all PASS

- [ ] **Step 5: Run the full suite**

Run: `cd backend && python -m pytest -v`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add backend/app/orchestrator.py backend/tests/test_orchestrator.py
git commit -m "feat(audit): thread AuditLog through orchestrator context, persist per module, record out_of_scope for discovery-filtered subdomains"
```

---

## Task 4: Instrument `crtsh` and `whois`

**Files:**
- Modify: `backend/app/modules/crtsh.py`
- Modify: `backend/app/modules/whois_module.py`
- Modify: `backend/tests/test_modules_crtsh.py`
- Modify: `backend/tests/test_modules_whois.py`

**Interfaces:**
- Consumes: `context.get("audit")` (Task 3), `AuditLog.record(...)` (Task 1).
- Produces: one `AuditEntry`-shaped dict per run in each module's `context["audit"]`, `outcome` being the HTTP status code (crtsh) or `"success"` (whois) on success, `"error: <message>"` on failure — recorded before the exception propagates, so the existing `module_error` Finding behavior in `_run_module` is unchanged.

- [ ] **Step 1: Write the failing tests**

`backend/tests/test_modules_crtsh.py` currently starts with:

```python
from unittest.mock import MagicMock, patch

from app.modules.crtsh import CrtShModule
```

Change it to:

```python
import pytest
from unittest.mock import MagicMock, patch

from app.audit import AuditLog
from app.modules.crtsh import CrtShModule
```

Then add these two tests to the end of the file:

```python
def test_records_a_successful_request_to_the_audit_log():
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = []
    response.raise_for_status = MagicMock()

    audit = AuditLog()
    with patch("app.modules.crtsh.requests.get", return_value=response):
        CrtShModule().run("example.com", {"audit": audit})

    assert len(audit.entries) == 1
    assert audit.entries[0]["module"] == "crtsh"
    assert audit.entries[0]["target"] == "example.com"
    assert audit.entries[0]["outcome"] == "200"
    assert audit.entries[0]["url"] == "https://crt.sh/"


def test_records_a_failed_request_to_the_audit_log_before_reraising():
    import requests as requests_lib

    audit = AuditLog()
    with patch(
        "app.modules.crtsh.requests.get",
        side_effect=requests_lib.RequestException("connection reset"),
    ):
        with pytest.raises(requests_lib.RequestException):
            CrtShModule().run("example.com", {"audit": audit})

    assert len(audit.entries) == 1
    assert audit.entries[0]["outcome"] == "error: connection reset"
```

`backend/tests/test_modules_whois.py` currently starts with:

```python
from unittest.mock import patch

from app.modules.whois_module import WhoisModule
```

Change it to:

```python
import pytest
from unittest.mock import MagicMock, patch

from app.audit import AuditLog
from app.modules.whois_module import WhoisModule
```

Then add these two tests to the end of the file:

```python
def test_records_a_successful_lookup_to_the_audit_log():
    audit = AuditLog()
    with patch("app.modules.whois_module.whois.whois", return_value=MagicMock(get=lambda *a: None)):
        WhoisModule().run("example.com", {"audit": audit})

    assert len(audit.entries) == 1
    assert audit.entries[0]["module"] == "whois"
    assert audit.entries[0]["target"] == "example.com"
    assert audit.entries[0]["outcome"] == "success"
    assert audit.entries[0]["url"] is None


def test_records_a_failed_lookup_to_the_audit_log_before_reraising():
    audit = AuditLog()
    with patch("app.modules.whois_module.whois.whois", side_effect=ConnectionError("timed out")):
        with pytest.raises(ConnectionError):
            WhoisModule().run("example.com", {"audit": audit})

    assert len(audit.entries) == 1
    assert audit.entries[0]["outcome"] == "error: timed out"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && python -m pytest tests/test_modules_crtsh.py tests/test_modules_whois.py -v`
Expected: FAIL — both modules ignore `context["audit"]` entirely, so `audit.entries` stays empty

- [ ] **Step 3: Implement the instrumentation in `crtsh.py`**

Replace the full contents of `backend/app/modules/crtsh.py` with:

```python
import requests

from app.modules.base import Finding, ReconModule, register_module
from app.scope import is_in_scope


@register_module
class CrtShModule(ReconModule):
    name = "crtsh"
    run_order = 10

    def run(self, target: str, context: dict) -> list[Finding]:
        scope = context.get("scope")
        if scope is not None and not is_in_scope(target, None, scope):
            return [Finding(type="out_of_scope", value=target, data={"module": self.name})]

        audit = context.get("audit")
        url = "https://crt.sh/"
        try:
            response = requests.get(
                url,
                params={"q": f"%.{target}", "output": "json"},
                timeout=30,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            if audit is not None:
                audit.record(module=self.name, target=target, outcome=f"error: {exc}", url=url)
            raise

        if audit is not None:
            audit.record(module=self.name, target=target, outcome=str(response.status_code), url=url)

        subdomains = set()
        for entry in response.json():
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().removeprefix("*.")
                if name == target or name.endswith("." + target):
                    subdomains.add(name)

        return [
            Finding(type="subdomain", value=s, data={"source": "crt.sh"})
            for s in sorted(subdomains)
        ]
```

- [ ] **Step 4: Implement the instrumentation in `whois_module.py`**

Replace the full contents of `backend/app/modules/whois_module.py` with:

```python
import whois

from app.modules.base import Finding, ReconModule, register_module
from app.scope import is_in_scope


@register_module
class WhoisModule(ReconModule):
    name = "whois"

    def run(self, target: str, context: dict) -> list[Finding]:
        scope = context.get("scope")
        if scope is not None and not is_in_scope(target, None, scope):
            return [Finding(type="out_of_scope", value=target, data={"module": self.name})]

        audit = context.get("audit")
        try:
            record = whois.whois(target)
        except Exception as exc:
            if audit is not None:
                audit.record(module=self.name, target=target, outcome=f"error: {exc}")
            raise

        if audit is not None:
            audit.record(module=self.name, target=target, outcome="success")

        data = {
            "registrar": record.get("registrar"),
            "creation_date": str(record.get("creation_date")),
            "expiration_date": str(record.get("expiration_date")),
            "name_servers": record.get("name_servers"),
        }
        return [Finding(type="whois", value=target, data=data)]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_modules_crtsh.py tests/test_modules_whois.py -v`
Expected: all PASS

- [ ] **Step 6: Run the full suite**

Run: `cd backend && python -m pytest -v`
Expected: all PASS

- [ ] **Step 7: Commit**

```bash
git add backend/app/modules/crtsh.py backend/app/modules/whois_module.py backend/tests/test_modules_crtsh.py backend/tests/test_modules_whois.py
git commit -m "feat(audit): instrument crtsh and whois with audit log entries"
```

---

## Task 5: Instrument `cloud_range`

**Files:**
- Modify: `backend/app/modules/cloud_range.py`
- Modify: `backend/tests/test_modules_cloud_range.py`

**Interfaces:**
- Consumes: `context.get("audit")` (Task 3), `AuditLog.record(...)` (Task 1).
- Produces: one audit entry per host's DNS resolution attempt — `outcome=f"resolved: {ip}"` on success, `outcome=f"error: {exc}"` on `OSError`. No `url` (DNS lookups have none).

- [ ] **Step 1: Write the failing tests**

Add to `backend/tests/test_modules_cloud_range.py`:

```python
def test_records_a_successful_resolution_to_the_audit_log():
    from app.audit import AuditLog

    audit = AuditLog()
    with patch("app.modules.cloud_range.socket.gethostbyname", return_value="3.5.140.1"):
        CloudRangeModule().run("example.com", {"audit": audit})

    assert len(audit.entries) == 1
    assert audit.entries[0]["module"] == "cloud_range"
    assert audit.entries[0]["target"] == "example.com"
    assert audit.entries[0]["outcome"] == "resolved: 3.5.140.1"
    assert audit.entries[0]["url"] is None


def test_records_a_failed_resolution_to_the_audit_log():
    from app.audit import AuditLog

    audit = AuditLog()
    with patch(
        "app.modules.cloud_range.socket.gethostbyname", side_effect=OSError("no dns")
    ):
        CloudRangeModule().run("example.com", {"audit": audit})

    assert len(audit.entries) == 1
    assert audit.entries[0]["outcome"] == "error: no dns"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && python -m pytest tests/test_modules_cloud_range.py -k audit_log -v`
Expected: FAIL — `audit.entries` stays empty, module never touches `context["audit"]`

- [ ] **Step 3: Implement the instrumentation**

In `backend/app/modules/cloud_range.py`, change the `run()` method (currently):

```python
    def run(self, target: str, context: dict) -> list[Finding]:
        hosts = sorted(context.get("subdomains", set()) | {target})
        scope = context.get("scope")
        limiter = RateLimiter(context.get("rate_limit", DEFAULT_RATE_LIMIT))
        breaker = CircuitBreaker(
            context.get("circuit_breaker_threshold", DEFAULT_CIRCUIT_BREAKER_THRESHOLD)
        )
        findings = []

        for index, host in enumerate(hosts):
            limiter.wait()
            try:
                ip = socket.gethostbyname(host)
            except OSError:
                if breaker.record_failure():
                    findings.append(
                        Finding(
                            type="circuit_breaker_tripped",
                            value=host,
                            data={"module": self.name, "skipped_hosts": len(hosts) - index - 1},
                        )
                    )
                    break
                continue

            breaker.record_success()

            if scope is not None and not is_in_scope(host, ip, scope):
                findings.append(
                    Finding(type="out_of_scope", value=host, data={"module": self.name})
                )
                continue

            provider = self._match_provider(ip)
            if provider is not None:
                findings.append(
                    Finding(type="cloud_asset", value=host, data={"ip": ip, "provider": provider})
                )

        return findings
```

to:

```python
    def run(self, target: str, context: dict) -> list[Finding]:
        hosts = sorted(context.get("subdomains", set()) | {target})
        scope = context.get("scope")
        audit = context.get("audit")
        limiter = RateLimiter(context.get("rate_limit", DEFAULT_RATE_LIMIT))
        breaker = CircuitBreaker(
            context.get("circuit_breaker_threshold", DEFAULT_CIRCUIT_BREAKER_THRESHOLD)
        )
        findings = []

        for index, host in enumerate(hosts):
            limiter.wait()
            try:
                ip = socket.gethostbyname(host)
            except OSError as exc:
                if audit is not None:
                    audit.record(module=self.name, target=host, outcome=f"error: {exc}")
                if breaker.record_failure():
                    findings.append(
                        Finding(
                            type="circuit_breaker_tripped",
                            value=host,
                            data={"module": self.name, "skipped_hosts": len(hosts) - index - 1},
                        )
                    )
                    break
                continue

            if audit is not None:
                audit.record(module=self.name, target=host, outcome=f"resolved: {ip}")
            breaker.record_success()

            if scope is not None and not is_in_scope(host, ip, scope):
                findings.append(
                    Finding(type="out_of_scope", value=host, data={"module": self.name})
                )
                continue

            provider = self._match_provider(ip)
            if provider is not None:
                findings.append(
                    Finding(type="cloud_asset", value=host, data={"ip": ip, "provider": provider})
                )

        return findings
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_modules_cloud_range.py -v`
Expected: all PASS

- [ ] **Step 5: Run the full suite**

Run: `cd backend && python -m pytest -v`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add backend/app/modules/cloud_range.py backend/tests/test_modules_cloud_range.py
git commit -m "feat(audit): instrument cloud_range DNS resolution with audit log entries"
```

---

## Task 6: Instrument `tech_fingerprint`

**Files:**
- Modify: `backend/app/modules/tech_fingerprint.py`
- Modify: `backend/tests/test_modules_tech_fingerprint.py`

**Interfaces:**
- Consumes: `context.get("audit")` (Task 3), `AuditLog.record(...)` (Task 1).
- Produces: one audit entry per real HTTP request — the main per-host GET, plus one more for each `path_probe` rule request that actually fires (today only the WordPress `/CHANGELOG.txt` rule). `outcome` is the response status code on success, `"error: <message>"` on failure. `url` is the exact URL requested.

- [ ] **Step 1: Write the failing tests**

Add to `backend/tests/test_modules_tech_fingerprint.py`:

```python
def test_records_the_main_request_to_the_audit_log():
    from app.audit import AuditLog

    base = _response(headers={"Server": "nginx/1.18.0"})
    probe_404 = _response(status_code=404)

    def fake_get(url, **kwargs):
        if url.endswith("/CHANGELOG.txt"):
            return probe_404
        return base

    audit = AuditLog()
    with patch("app.modules.tech_fingerprint.requests.get", side_effect=fake_get):
        TechFingerprintModule().run("example.com", {"audit": audit})

    main_entries = [e for e in audit.entries if e["url"] == "https://example.com/"]
    assert len(main_entries) == 1
    assert main_entries[0]["outcome"] == "200"
    assert main_entries[0]["target"] == "example.com"


def test_records_the_path_probe_request_to_the_audit_log_when_it_fires():
    from app.audit import AuditLog

    base = _response()
    changelog = _response(status_code=200, text="== Changelog ==\n\nVersion 6.4.2\n* fixed things")

    def fake_get(url, **kwargs):
        if url.endswith("/CHANGELOG.txt"):
            return changelog
        return base

    audit = AuditLog()
    with patch("app.modules.tech_fingerprint.requests.get", side_effect=fake_get):
        TechFingerprintModule().run("example.com", {"audit": audit})

    probe_entries = [e for e in audit.entries if e["url"] == "https://example.com/CHANGELOG.txt"]
    assert len(probe_entries) == 1
    assert probe_entries[0]["outcome"] == "200"


def test_records_a_failed_main_request_to_the_audit_log():
    import requests as requests_lib

    from app.audit import AuditLog

    audit = AuditLog()
    with patch(
        "app.modules.tech_fingerprint.requests.get",
        side_effect=requests_lib.RequestException("down"),
    ):
        TechFingerprintModule().run("example.com", {"audit": audit})

    assert len(audit.entries) == 1
    assert audit.entries[0]["outcome"] == "error: down"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && python -m pytest tests/test_modules_tech_fingerprint.py -k audit_log -v`
Expected: FAIL — `audit.entries` stays empty in all three cases

- [ ] **Step 3: Implement the instrumentation**

In `backend/app/modules/tech_fingerprint.py`, change the `run()` method's call to `_fingerprint_host` (currently):

```python
        findings: list[Finding] = []
        for index, host in enumerate(hosts):
            if scope is not None and not is_in_scope(host, None, scope):
                findings.append(
                    Finding(type="out_of_scope", value=host, data={"module": self.name})
                )
                continue

            limiter.wait()
            host_findings, reached_host = self._fingerprint_host(host, limiter)
            findings.extend(host_findings)
```

to:

```python
        audit = context.get("audit")
        findings: list[Finding] = []
        for index, host in enumerate(hosts):
            if scope is not None and not is_in_scope(host, None, scope):
                findings.append(
                    Finding(type="out_of_scope", value=host, data={"module": self.name})
                )
                continue

            limiter.wait()
            host_findings, reached_host = self._fingerprint_host(host, limiter, audit)
            findings.extend(host_findings)
```

(Place `audit = context.get("audit")` right after the existing `scope = context.get("scope")` line at the top of `run()`.)

Change `_fingerprint_host` (currently):

```python
    def _fingerprint_host(self, host: str, limiter: RateLimiter) -> tuple[list[Finding], bool]:
        try:
            response = requests.get(f"https://{host}/", timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            return [], False

        findings = []
        for rule in FINGERPRINT_RULES:
            finding = self._apply_rule(host, rule, response, limiter)
            if finding is not None:
                findings.append(finding)
        return findings, True
```

to:

```python
    def _fingerprint_host(self, host: str, limiter: RateLimiter, audit) -> tuple[list[Finding], bool]:
        url = f"https://{host}/"
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            if audit is not None:
                audit.record(module=self.name, target=host, outcome=f"error: {exc}", url=url)
            return [], False

        if audit is not None:
            audit.record(module=self.name, target=host, outcome=str(response.status_code), url=url)

        findings = []
        for rule in FINGERPRINT_RULES:
            finding = self._apply_rule(host, rule, response, limiter, audit)
            if finding is not None:
                findings.append(finding)
        return findings, True
```

Change `_apply_rule`'s signature and its `path_probe` branch (currently):

```python
    def _apply_rule(self, host: str, rule: dict, response, limiter: RateLimiter) -> Finding | None:
```

to:

```python
    def _apply_rule(self, host: str, rule: dict, response, limiter: RateLimiter, audit) -> Finding | None:
```

and the `path_probe` branch (currently):

```python
        if rule["match_type"] == "path_probe":
            limiter.wait()
            try:
                probe = requests.get(f"https://{host}{rule['path']}", timeout=REQUEST_TIMEOUT)
            except requests.RequestException:
                return None
            if probe.status_code != 200:
                return None
            match = re.search(rule["pattern"], probe.text, re.IGNORECASE)
            if not match:
                return None
            return self._finding(host, rule, match, source="path_probe")
```

to:

```python
        if rule["match_type"] == "path_probe":
            limiter.wait()
            probe_url = f"https://{host}{rule['path']}"
            try:
                probe = requests.get(probe_url, timeout=REQUEST_TIMEOUT)
            except requests.RequestException as exc:
                if audit is not None:
                    audit.record(module=self.name, target=host, outcome=f"error: {exc}", url=probe_url)
                return None
            if audit is not None:
                audit.record(module=self.name, target=host, outcome=str(probe.status_code), url=probe_url)
            if probe.status_code != 200:
                return None
            match = re.search(rule["pattern"], probe.text, re.IGNORECASE)
            if not match:
                return None
            return self._finding(host, rule, match, source="path_probe")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_modules_tech_fingerprint.py -v`
Expected: all PASS

- [ ] **Step 5: Run the full suite**

Run: `cd backend && python -m pytest -v`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add backend/app/modules/tech_fingerprint.py backend/tests/test_modules_tech_fingerprint.py
git commit -m "feat(audit): instrument tech_fingerprint's main and path_probe requests with audit log entries"
```

---

## Task 7: Instrument `cve_correlation`

**Files:**
- Modify: `backend/app/modules/cve_correlation.py`
- Modify: `backend/tests/test_modules_cve_correlation.py`

**Interfaces:**
- Consumes: `context.get("audit")` (Task 3), `AuditLog.record(...)` (Task 1).
- Produces: one audit entry per NVD query (one per technology with a known name+version), `target` being the technology name, `url` being `NVD_API_URL`, `outcome` the response status code or `"error: <message>"`.

- [ ] **Step 1: Write the failing tests**

Add to `backend/tests/test_modules_cve_correlation.py` (this file already has a `_mock_response` helper and imports `cve_correlation`/`CveCorrelationModule` — follow the existing pattern for `monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)`):

```python
def test_records_a_successful_nvd_query_to_the_audit_log(monkeypatch):
    from app.audit import AuditLog

    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)

    context = {"technologies": [{"name": "nginx", "version": "1.18.0"}]}
    payload = _nvd_response(_cve("CVE-2021-23017", [NGINX_RANGE_MATCH]))
    audit = AuditLog()
    context["audit"] = audit

    with patch(
        "app.modules.cve_correlation.requests.get", return_value=_mock_response(payload)
    ):
        CveCorrelationModule().run("example.com", context)

    assert len(audit.entries) == 1
    assert audit.entries[0]["module"] == "cve_correlation"
    assert audit.entries[0]["target"] == "nginx"
    assert audit.entries[0]["outcome"] == "200"
    assert audit.entries[0]["url"] == cve_correlation.NVD_API_URL


def test_records_a_failed_nvd_query_to_the_audit_log(monkeypatch):
    from app.audit import AuditLog

    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)

    context = {"technologies": [{"name": "nginx", "version": "1.18.0"}]}
    audit = AuditLog()
    context["audit"] = audit

    import requests as requests_lib

    with patch(
        "app.modules.cve_correlation.requests.get",
        side_effect=requests_lib.RequestException("nvd is down"),
    ):
        CveCorrelationModule().run("example.com", context)

    assert len(audit.entries) == 1
    assert audit.entries[0]["outcome"] == "error: nvd is down"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && python -m pytest tests/test_modules_cve_correlation.py -k audit_log -v`
Expected: FAIL — `audit.entries` stays empty, module never touches `context["audit"]`

- [ ] **Step 3: Implement the instrumentation**

In `backend/app/modules/cve_correlation.py`, change `run()`'s call to `_query_cves` (currently):

```python
        breaker = CircuitBreaker(
            context.get("circuit_breaker_threshold", DEFAULT_CIRCUIT_BREAKER_THRESHOLD)
        )
        findings: list[Finding] = []

        for index, tech in enumerate(technologies):
            name = tech.get("name")
            version = tech.get("version")
            if not name or not version:
                continue

            tech_findings, succeeded = self._query_cves(name, version)
```

to:

```python
        breaker = CircuitBreaker(
            context.get("circuit_breaker_threshold", DEFAULT_CIRCUIT_BREAKER_THRESHOLD)
        )
        audit = context.get("audit")
        findings: list[Finding] = []

        for index, tech in enumerate(technologies):
            name = tech.get("name")
            version = tech.get("version")
            if not name or not version:
                continue

            tech_findings, succeeded = self._query_cves(name, version, audit)
```

Change `_query_cves`'s signature and body (currently):

```python
    def _query_cves(self, name: str, version: str) -> tuple[list[Finding], bool]:
        # keywordSearch does a literal free-text match: searching "{name}
        # {version}" together returns almost nothing, since most CVE
        # descriptions don't quote the exact version. Search by name only,
        # then filter matches by the CPE version range NVD attaches to
        # each CVE -- that's the structured signal, not the prose.
        headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
        try:
            response = requests.get(
                NVD_API_URL,
                params={"keywordSearch": name},
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException:
            return [], False

        findings = []
        for vulnerability in payload.get("vulnerabilities", []):
            cve = vulnerability.get("cve", {})
            if _cve_matches_version(cve, name, version):
                findings.append(self._finding_from_cve(cve, name, version))
        return findings, True
```

to:

```python
    def _query_cves(self, name: str, version: str, audit) -> tuple[list[Finding], bool]:
        # keywordSearch does a literal free-text match: searching "{name}
        # {version}" together returns almost nothing, since most CVE
        # descriptions don't quote the exact version. Search by name only,
        # then filter matches by the CPE version range NVD attaches to
        # each CVE -- that's the structured signal, not the prose.
        headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
        try:
            response = requests.get(
                NVD_API_URL,
                params={"keywordSearch": name},
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as exc:
            if audit is not None:
                audit.record(module=self.name, target=name, outcome=f"error: {exc}", url=NVD_API_URL)
            return [], False

        if audit is not None:
            audit.record(module=self.name, target=name, outcome=str(response.status_code), url=NVD_API_URL)

        findings = []
        for vulnerability in payload.get("vulnerabilities", []):
            cve = vulnerability.get("cve", {})
            if _cve_matches_version(cve, name, version):
                findings.append(self._finding_from_cve(cve, name, version))
        return findings, True
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_modules_cve_correlation.py -v`
Expected: all PASS

- [ ] **Step 5: Run the full suite**

Run: `cd backend && python -m pytest -v`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add backend/app/modules/cve_correlation.py backend/tests/test_modules_cve_correlation.py
git commit -m "feat(audit): instrument cve_correlation NVD queries with audit log entries"
```

---

## Task 8: Instrument `subfinder` and `httpx_probe` (accepted per-invocation/per-host approximation)

**Files:**
- Modify: `backend/app/modules/subfinder.py`
- Modify: `backend/app/modules/httpx_probe.py`
- Modify: `backend/tests/test_modules_subfinder.py`
- Modify: `backend/tests/test_modules_httpx_probe.py`

**Interfaces:**
- Consumes: `context.get("audit")` (Task 3), `AuditLog.record(...)` (Task 1).
- Produces: `subfinder` gets one audit entry per invocation (`outcome=f"success ({N} found)"` or `f"error: {exc}"`). `httpx_probe` gets one entry per host in its (already scope-filtered) host list — `outcome` taken from that host's parsed JSON line (its status code) when present, `"no_response"` when the host never appears in `httpx`'s output, or `f"error: {exc}"` for every host if the subprocess itself fails. Both are documented as an accepted approximation (per the spec) since neither module can see the individual requests its external binary makes internally.

- [ ] **Step 1: Write the failing tests**

`backend/tests/test_modules_subfinder.py` currently starts with:

```python
from unittest.mock import MagicMock, patch

from app.modules.subfinder import SubfinderModule
```

Change it to:

```python
import subprocess
import pytest
from unittest.mock import MagicMock, patch

from app.audit import AuditLog
from app.modules.subfinder import SubfinderModule
```

Then add these two tests to the end of the file:

```python
def test_records_a_successful_invocation_to_the_audit_log():
    fake_result = MagicMock(stdout="a.example.com\nb.example.com\n")
    audit = AuditLog()
    with patch("app.modules.subfinder.subprocess.run", return_value=fake_result):
        SubfinderModule().run("example.com", {"audit": audit})

    assert len(audit.entries) == 1
    assert audit.entries[0]["module"] == "subfinder"
    assert audit.entries[0]["target"] == "example.com"
    assert audit.entries[0]["outcome"] == "success (2 found)"


def test_records_a_failed_invocation_to_the_audit_log_before_reraising():
    audit = AuditLog()
    with patch(
        "app.modules.subfinder.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "subfinder"),
    ):
        with pytest.raises(subprocess.CalledProcessError):
            SubfinderModule().run("example.com", {"audit": audit})

    assert len(audit.entries) == 1
    assert audit.entries[0]["outcome"].startswith("error:")
```

`backend/tests/test_modules_httpx_probe.py` currently starts with:

```python
from unittest.mock import MagicMock, patch

from app.modules.httpx_probe import HttpxProbeModule
```

Change it to:

```python
import subprocess
import pytest
from unittest.mock import MagicMock, patch

from app.audit import AuditLog
from app.modules.httpx_probe import HttpxProbeModule
```

Then add these two tests to the end of the file:

```python
def test_records_one_entry_per_host_from_parsed_output():
    fake_output = (
        '{"url": "https://a.example.com", "input": "a.example.com", "status_code": 200}\n'
    )
    fake_result = MagicMock(stdout=fake_output)
    audit = AuditLog()
    with patch("app.modules.httpx_probe.subprocess.run", return_value=fake_result):
        HttpxProbeModule().run("example.com", {"subdomains": {"a.example.com"}, "audit": audit})

    entries = {e["target"]: e["outcome"] for e in audit.entries}
    assert entries["a.example.com"] == "200"
    assert entries["example.com"] == "no_response"


def test_records_error_for_every_host_when_subprocess_fails():
    audit = AuditLog()
    with patch(
        "app.modules.httpx_probe.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "httpx"),
    ):
        with pytest.raises(subprocess.CalledProcessError):
            HttpxProbeModule().run(
                "example.com", {"subdomains": {"a.example.com"}, "audit": audit}
            )

    targets = {e["target"] for e in audit.entries}
    assert targets == {"example.com", "a.example.com"}
    assert all(e["outcome"].startswith("error:") for e in audit.entries)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && python -m pytest tests/test_modules_subfinder.py tests/test_modules_httpx_probe.py -k "audit or records" -v`
Expected: FAIL — neither module touches `context["audit"]` yet

- [ ] **Step 3: Implement the instrumentation in `subfinder.py`**

Replace the full contents of `backend/app/modules/subfinder.py` with:

```python
import subprocess

from app.modules.base import Finding, ReconModule, register_module


@register_module
class SubfinderModule(ReconModule):
    name = "subfinder"
    run_order = 10

    def run(self, target: str, context: dict) -> list[Finding]:
        audit = context.get("audit")
        try:
            result = subprocess.run(
                ["subfinder", "-d", target, "-silent"],
                capture_output=True,
                text=True,
                timeout=300,
                check=True,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            if audit is not None:
                audit.record(module=self.name, target=target, outcome=f"error: {exc}")
            raise

        subdomains = {line.strip() for line in result.stdout.splitlines() if line.strip()}
        if audit is not None:
            audit.record(module=self.name, target=target, outcome=f"success ({len(subdomains)} found)")
        return [Finding(type="subdomain", value=s) for s in sorted(subdomains)]
```

- [ ] **Step 4: Implement the instrumentation in `httpx_probe.py`**

Replace the full contents of `backend/app/modules/httpx_probe.py` with:

```python
import json
import subprocess

from app.modules.base import Finding, ReconModule, register_module
from app.scope import is_in_scope

DEFAULT_RATE_LIMIT = 5.0


@register_module
class HttpxProbeModule(ReconModule):
    name = "httpx_probe"
    is_active = True

    def run(self, target: str, context: dict) -> list[Finding]:
        hosts = context.get("subdomains", set()) | {target}
        scope = context.get("scope")
        audit = context.get("audit")
        findings: list[Finding] = []

        if scope is not None:
            in_scope_hosts = set()
            for host in hosts:
                if is_in_scope(host, None, scope):
                    in_scope_hosts.add(host)
                else:
                    findings.append(
                        Finding(type="out_of_scope", value=host, data={"module": self.name})
                    )
            hosts = in_scope_hosts

        rate_limit = context.get("rate_limit", DEFAULT_RATE_LIMIT)
        # httpx paces its own requests natively -- pass our limit through
        # instead of reimplementing pacing for a subprocess we don't
        # control the request loop of.
        command = [
            "httpx",
            "-silent",
            "-json",
            "-tech-detect",
            "-rate-limit",
            str(max(1, round(rate_limit))),
        ]
        try:
            result = subprocess.run(
                command,
                input="\n".join(sorted(hosts)),
                capture_output=True,
                text=True,
                timeout=300,
                check=True,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            if audit is not None:
                for host in hosts:
                    audit.record(module=self.name, target=host, outcome=f"error: {exc}")
            raise

        # httpx makes its own requests internally -- we can't see the
        # individual ones it made, only correlate its output back to the
        # hosts we sent it. A host missing from the output gets no_response.
        seen_hosts = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            host_target = record.get("input") or record.get("url", "")
            seen_hosts.add(host_target)
            if audit is not None:
                status = record.get("status_code")
                audit.record(
                    module=self.name,
                    target=host_target,
                    outcome=str(status) if status is not None else "no_response",
                    url=record.get("url"),
                )
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

        if audit is not None:
            for host in hosts - seen_hosts:
                audit.record(module=self.name, target=host, outcome="no_response")

        return findings
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_modules_subfinder.py tests/test_modules_httpx_probe.py -v`
Expected: all PASS

- [ ] **Step 6: Run the full suite**

Run: `cd backend && python -m pytest -v`
Expected: all PASS

- [ ] **Step 7: Commit**

```bash
git add backend/app/modules/subfinder.py backend/app/modules/httpx_probe.py backend/tests/test_modules_subfinder.py backend/tests/test_modules_httpx_probe.py
git commit -m "feat(audit): instrument subfinder and httpx_probe with a per-invocation/per-host approximation"
```

---

## Task 9: `recon audit <scan_id>` CLI command

**Files:**
- Modify: `backend/app/cli.py`
- Modify: `backend/app/i18n.py`
- Modify: `backend/tests/test_cli.py`

**Interfaces:**
- Consumes: `models.AuditEntry`, `Scan.audit_entries` (Task 2), `i18n.t(...)` (existing, Fase A).
- Produces: a new Typer command `audit`, exported separately from `report` per the spec ("exportável separadamente do relatório de achados").

- [ ] **Step 1: Add the new i18n keys**

In `backend/app/i18n.py`, add to the `"en"` dict (anywhere alongside the other `*_title`/`*_col_*` keys, e.g. near `other_findings_title`):

```python
        "audit_title": "Audit trail",
        "audit_col_module": "Module",
        "audit_col_target": "Target",
        "audit_col_url": "URL",
        "audit_col_outcome": "Outcome",
        "audit_col_requested_at": "Requested at",
```

And to the `"pt"` dict, at the same relative position:

```python
        "audit_title": "Trilha de auditoria",
        "audit_col_module": "Modulo",
        "audit_col_target": "Alvo",
        "audit_col_url": "URL",
        "audit_col_outcome": "Resultado",
        "audit_col_requested_at": "Requisitado em",
```

- [ ] **Step 2: Write the failing tests**

Add to `backend/tests/test_cli.py`:

```python
def test_audit_command_prints_table_with_recorded_entries():
    db = SessionLocal()
    try:
        project = models.Project(
            name="Audit Co", target="audit.example.com", scope_notes="ok", authorized=True
        )
        db.add(project)
        db.commit()
        scan_row = models.Scan(project_id=project.id, status="complete")
        db.add(scan_row)
        db.commit()
        db.add(
            models.AuditEntry(
                scan_id=scan_row.id,
                module="crtsh",
                target="audit.example.com",
                url="https://crt.sh/",
                outcome="200",
            )
        )
        db.commit()
        scan_id = scan_row.id
    finally:
        db.close()

    result = runner.invoke(app, ["audit", str(scan_id)])

    assert result.exit_code == 0
    assert "crtsh" in result.output
    assert "audit.example.com" in result.output


def test_audit_command_csv_format_outputs_csv_rows():
    db = SessionLocal()
    try:
        project = models.Project(
            name="Audit CSV Co", target="csv.example.com", scope_notes="ok", authorized=True
        )
        db.add(project)
        db.commit()
        scan_row = models.Scan(project_id=project.id, status="complete")
        db.add(scan_row)
        db.commit()
        db.add(
            models.AuditEntry(
                scan_id=scan_row.id, module="whois", target="csv.example.com", outcome="success"
            )
        )
        db.commit()
        scan_id = scan_row.id
    finally:
        db.close()

    result = runner.invoke(app, ["audit", str(scan_id), "--format", "csv"])

    assert result.exit_code == 0
    assert "module,target,url,outcome,requested_at" in result.output
    assert "whois,csv.example.com" in result.output


def test_audit_command_exits_with_error_for_unknown_scan_id():
    result = runner.invoke(app, ["audit", "999999"])

    assert result.exit_code == 1
    assert "999999" in result.output
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd backend && python -m pytest tests/test_cli.py -k audit_command -v`
Expected: FAIL — `audit` is not a recognized command (Typer/Click reports "No such command")

- [ ] **Step 4: Implement the CLI command**

In `backend/app/cli.py`, add `csv` to the import block at the top (currently `import ipaddress`, `import re`, `import sys`):

```python
import csv
import ipaddress
import re
import sys
```

Add the new command, right after the existing `report` command and before `_print_report`:

```python
@app.command()
def audit(
    scan_id: int = typer.Argument(..., help="ID of a previously run scan"),
    format: str = typer.Option("table", "--format", help="Output format: table (default) or csv"),
) -> None:
    db = SessionLocal()
    try:
        scan_row = db.get(models.Scan, scan_id)
        if scan_row is None:
            console.print(f"[red]{i18n.t('scan_not_found', scan_id=scan_id)}[/red]")
            raise typer.Exit(code=1)
        entries = list(scan_row.audit_entries)
    finally:
        db.close()

    if format == "csv":
        writer = csv.writer(sys.stdout)
        writer.writerow(["module", "target", "url", "outcome", "requested_at"])
        for entry in entries:
            writer.writerow(
                [entry.module, entry.target, entry.url or "", entry.outcome, entry.requested_at]
            )
        return

    table = Table(title=i18n.t("audit_title"))
    for key in (
        "audit_col_module",
        "audit_col_target",
        "audit_col_url",
        "audit_col_outcome",
        "audit_col_requested_at",
    ):
        table.add_column(i18n.t(key))
    for entry in entries:
        table.add_row(
            entry.module, entry.target, entry.url or "-", entry.outcome, str(entry.requested_at)
        )
    console.print(table)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_cli.py -v`
Expected: all PASS

- [ ] **Step 6: Run the full suite**

Run: `cd backend && python -m pytest -v`
Expected: all PASS

- [ ] **Step 7: Commit**

```bash
git add backend/app/cli.py backend/app/i18n.py backend/tests/test_cli.py
git commit -m "feat(audit): add recon audit <scan_id> CLI command (table/csv)"
```

---

## Task 10: Documentation and a live smoke test

**Files:**
- Modify: `README.md`
- Modify: `README.pt-BR.md`

**Interfaces:**
- Consumes: nothing (documentation only).
- Produces: nothing consumed by other tasks — this is the final task.

- [ ] **Step 1: Add an "Audit trail" section to `README.md`**

Add a new `## Audit trail` section after `## Data and persistence` (before `## Tests`), and add it to the table of contents near the top:

```markdown
## Audit trail

Every real network request the tool makes — against the target/
subdomains and against third-party services like the NVD — is recorded
as an `AuditEntry`: module, target, URL (when applicable), outcome, and
timestamp. This is separate from the findings report; it exists to
prove what the tool actually touched, independent of what turned into
a finding. `subfinder` and `httpx_probe` shell out to external Go
binaries and can't see the individual requests those binaries make
internally, so they get one entry per invocation/per-host respectively
— an accepted approximation, not literal per-socket-request fidelity.

```bash
python -m app.cli audit <scan_id> --format table
python -m app.cli audit <scan_id> --format csv > audit.csv
```
```

Also update the `Finding.type` list in `## Data and persistence` to mention the new `out_of_scope` attribution: it already lists `out_of_scope`, so no change needed there — the orchestrator-attributed variant uses the same `Finding.type` value, just a different `module` value (`"orchestrator"`), which doesn't need a new list entry.

- [ ] **Step 2: Mirror the same section in `README.pt-BR.md`**

```markdown
## Trilha de auditoria

Toda requisição de rede real que a ferramenta faz — contra o alvo/
subdomínios e contra serviços de terceiros como o NVD — fica registrada
como um `AuditEntry`: módulo, alvo, URL (quando aplicável), resultado e
timestamp. Isso é separado do relatório de achados; existe pra provar o
que a ferramenta realmente tocou, independente do que virou achado.
`subfinder` e `httpx_probe` chamam binários externos em Go e não
conseguem ver as requisições individuais que esses binários fazem por
dentro, então ganham uma entrada por invocação/por host respectivamente
— uma aproximação aceita, não fidelidade literal por requisição.

```bash
python -m app.cli audit <scan_id> --format table
python -m app.cli audit <scan_id> --format csv > audit.csv
```
```

Add it to the Portuguese table of contents at the same relative position, and add the section after `## Dados e persistência`, before `## Testes`.

- [ ] **Step 3: Update the test count badge in both READMEs**

Run `cd backend && python -m pytest --collect-only -q` to get the final test count, then update the `tests-NN%20passing` badge value and the prose test count sentence in both `README.md` and `README.pt-BR.md` to match (mirrors the pattern from every prior fase's README updates).

- [ ] **Step 4: Live smoke test**

Run against the safe test domain, confirming audit entries are visibly recorded and exportable:

```bash
cd backend
python -m app.cli scan example.com --scope "smoke test audit trail" --authorized --confirm-active
```

Note the `Scan #<id>` printed at the top of the report, then:

```bash
python -m app.cli audit <id>
python -m app.cli audit <id> --format csv
```

Expected: the table view shows multiple rows across different modules
(at minimum `crtsh`, `whois`, `cve_correlation` if any technology with a
known version was detected); the CSV view shows the same data as valid
CSV with a header row. Confirm at least one row's `outcome` is a
numeric-looking HTTP status code (proving the instrumentation is wired
to real requests, not just mocked tests).

- [ ] **Step 5: Run the full suite one final time**

Run: `cd backend && python -m pytest -v`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add README.md README.pt-BR.md
git commit -m "docs(readme): document the audit trail and the recon audit command"
```

- [ ] **Step 7: Push**

```bash
git push origin master
```
