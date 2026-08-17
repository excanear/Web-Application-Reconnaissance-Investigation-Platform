# Structured Scope Enforcement (Fase C) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `Project` a structured, enforced scope (include/exclude domain patterns and CIDR ranges, plus an optional UTC time window) so every module refuses to touch a host outside what the operator declared, instead of only trusting free-text `scope_notes`.

**Architecture:** A new `app/scope.py` holds pure matching logic (`is_in_scope`, `is_within_window`). `Project` gets a JSON `scope` column (with a hand-rolled add-column-if-missing migration helper, since this project has no Alembic and `create_all()` doesn't alter existing tables). The CLI's `scan` command resolves `--scope-include`/`--scope-exclude`/`--scope-window` into that JSON shape and rejects contradictory input before creating a project. The orchestrator threads `scope` through `context` and filters discovered subdomains by it; every module that touches a host checks scope in its own per-host loop before making a request, recording an `out_of_scope` Finding when it skips one.

**Tech Stack:** Python 3.13, SQLAlchemy (SQLite), Typer, pytest. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-08-17-structured-scope-enforcement-design.md`

## Global Constraints

- English is the primary CLI language, Portuguese is secondary via `--lang pt` (Fase A) — every new user-facing string needs both an `en` and `pt` entry in `app/i18n.py`.
- `crd/whois`-style single-request modules and the loop-based modules (`tech_fingerprint`, `cloud_range`) already carry `RateLimiter`/`CircuitBreaker` from Fase B — scope checks are a new, separate gate alongside those, not a replacement.
- Exclude always wins over include. Empty/missing `include` fails closed (nothing in scope) — this is a deliberate security default, not a bug.
- `cd backend && pytest -v` must be fully green before every commit.
- Every new module-level scope skip is recorded as a Finding of type `out_of_scope` (per-host skips) or `scope_window_closed` (a whole module skipped because the allowed time window is shut), both with `data={"module": <module_name>}`, mirroring the existing `circuit_breaker_tripped` shape from Fase B so the CLI's report table needs no changes to render either one.

---

## Task 1: Scope matching logic (`app/scope.py`)

**Files:**
- Create: `backend/app/scope.py`
- Test: `backend/tests/test_scope.py`

**Interfaces:**
- Produces: `is_in_scope(host: str, ip: str | None, scope: dict) -> bool`, `is_within_window(scope: dict, now: datetime | None = None) -> bool`. Every later task that enforces scope calls these two functions and nothing else from this module.

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/test_scope.py
from datetime import datetime

from app.scope import is_in_scope, is_within_window


def test_bare_domain_pattern_matches_apex_and_subdomains():
    scope = {"include": ["example.com"]}
    assert is_in_scope("example.com", None, scope) is True
    assert is_in_scope("a.example.com", None, scope) is True
    assert is_in_scope("a.b.example.com", None, scope) is True


def test_bare_domain_pattern_does_not_match_unrelated_domain():
    scope = {"include": ["example.com"]}
    assert is_in_scope("example.com.evil.com", None, scope) is False
    assert is_in_scope("notexample.com", None, scope) is False


def test_wildcard_pattern_matches_only_subdomains_not_apex():
    scope = {"include": ["*.example.com"]}
    assert is_in_scope("a.example.com", None, scope) is True
    assert is_in_scope("example.com", None, scope) is False


def test_cidr_entry_matches_ip_within_range():
    scope = {"include": ["10.0.0.0/8"]}
    assert is_in_scope("anything.example.com", "10.1.2.3", scope) is True


def test_cidr_entry_does_not_match_ip_outside_range():
    scope = {"include": ["10.0.0.0/8"]}
    assert is_in_scope("anything.example.com", "8.8.8.8", scope) is False


def test_cidr_entry_never_matches_when_ip_not_provided():
    scope = {"include": ["10.0.0.0/8"]}
    assert is_in_scope("anything.example.com", None, scope) is False


def test_exclude_wins_over_include():
    scope = {"include": ["example.com"], "exclude": ["internal.example.com"]}
    assert is_in_scope("internal.example.com", None, scope) is False
    assert is_in_scope("api.example.com", None, scope) is True


def test_empty_include_fails_closed():
    assert is_in_scope("example.com", None, {}) is False
    assert is_in_scope("example.com", None, {"include": []}) is False


def test_is_within_window_returns_true_when_no_window_configured():
    assert is_within_window({}) is True


def test_is_within_window_returns_true_inside_window():
    scope = {"allowed_window": {"start": "09:00", "end": "18:00"}}
    now = datetime(2026, 8, 17, 12, 0)
    assert is_within_window(scope, now=now) is True


def test_is_within_window_returns_false_outside_window():
    scope = {"allowed_window": {"start": "09:00", "end": "18:00"}}
    now = datetime(2026, 8, 17, 20, 0)
    assert is_within_window(scope, now=now) is False


def test_is_within_window_handles_window_crossing_midnight():
    scope = {"allowed_window": {"start": "22:00", "end": "06:00"}}
    late_night = datetime(2026, 8, 17, 23, 0)
    early_morning = datetime(2026, 8, 17, 3, 0)
    midday = datetime(2026, 8, 17, 12, 0)
    assert is_within_window(scope, now=late_night) is True
    assert is_within_window(scope, now=early_morning) is True
    assert is_within_window(scope, now=midday) is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && python -m pytest tests/test_scope.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.scope'`

- [ ] **Step 3: Write the implementation**

```python
# backend/app/scope.py
"""Pure scope-matching logic. Every module that touches a host calls
is_in_scope() before making a request; the orchestrator also calls it to
filter newly discovered subdomains before they reach later modules."""

import ipaddress
from datetime import datetime, time


def _parse_network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _domain_matches(host: str, pattern: str) -> bool:
    host = host.lower()
    pattern = pattern.lower()
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host != suffix and host.endswith("." + suffix)
    return host == pattern or host.endswith("." + pattern)


def _matches_entry(host: str, ip: str | None, entry: str) -> bool:
    network = _parse_network(entry)
    if network is not None:
        if ip is None:
            return False
        try:
            return ipaddress.ip_address(ip) in network
        except ValueError:
            return False
    return _domain_matches(host, entry)


def is_in_scope(host: str, ip: str | None, scope: dict) -> bool:
    exclude = scope.get("exclude", [])
    if any(_matches_entry(host, ip, entry) for entry in exclude):
        return False
    include = scope.get("include", [])
    return any(_matches_entry(host, ip, entry) for entry in include)


def _parse_hhmm(value: str) -> time:
    hour, minute = value.split(":")
    return time(int(hour), int(minute))


def is_within_window(scope: dict, now: datetime | None = None) -> bool:
    window = scope.get("allowed_window")
    if not window:
        return True
    now = now or datetime.utcnow()
    start = _parse_hhmm(window["start"])
    end = _parse_hhmm(window["end"])
    current = now.time()
    if start <= end:
        return start <= current <= end
    return current >= start or current <= end
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_scope.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/scope.py backend/tests/test_scope.py
git commit -m "feat(scope): add pure scope-matching logic (domain patterns, CIDR, time window)"
```

---

## Task 2: `Project.scope` column and migration helper

**Files:**
- Modify: `backend/app/models.py`
- Modify: `backend/app/db.py`
- Modify: `backend/tests/test_models.py`
- Create: `backend/tests/test_db_migration.py`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `models.Project.scope` (JSON column, Python-side default `dict` i.e. `{}`). `db.ensure_schema(bind=None) -> None` — later tasks call this instead of calling `Base.metadata.create_all(bind=engine)` directly wherever a fresh process boots (i.e. `cli.py`'s module-level setup).

- [ ] **Step 1: Write the failing test for the model column**

Add to `backend/tests/test_models.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && python -m pytest tests/test_models.py -v`
Expected: FAIL with `TypeError: 'scope' is an invalid keyword argument for Project` (or an `AttributeError` on `reloaded.scope`)

- [ ] **Step 3: Add the column to the model**

In `backend/app/models.py`, add the `scope` column to `Project` right after `scope_notes`:

```python
    scope_notes = Column(Text, nullable=False)
    scope = Column(JSON, nullable=False, default=dict)
```

(`JSON` is already imported at the top of the file alongside `Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text` — no new import needed.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_models.py -v`
Expected: all PASS

- [ ] **Step 5: Write the failing migration test**

```python
# backend/tests/test_db_migration.py
from sqlalchemy import create_engine, inspect, text

from app.db import ensure_schema


def test_ensure_schema_adds_missing_scope_column_to_existing_projects_table(tmp_path):
    db_path = tmp_path / "legacy.db"
    legacy_engine = create_engine(f"sqlite:///{db_path}")
    try:
        with legacy_engine.begin() as conn:
            conn.execute(
                text(
                    "CREATE TABLE projects ("
                    "id INTEGER PRIMARY KEY, name VARCHAR NOT NULL, target VARCHAR NOT NULL, "
                    "scope_notes TEXT NOT NULL, authorized BOOLEAN NOT NULL, "
                    "authorized_at DATETIME, created_at DATETIME)"
                )
            )

        ensure_schema(bind=legacy_engine)

        inspector = inspect(legacy_engine)
        columns = {col["name"] for col in inspector.get_columns("projects")}
        assert "scope" in columns
    finally:
        legacy_engine.dispose()


def test_ensure_schema_is_a_no_op_when_scope_column_already_exists(tmp_path):
    db_path = tmp_path / "current.db"
    current_engine = create_engine(f"sqlite:///{db_path}")
    try:
        ensure_schema(bind=current_engine)
        # calling it again must not raise (column already present)
        ensure_schema(bind=current_engine)

        inspector = inspect(current_engine)
        columns = {col["name"] for col in inspector.get_columns("projects")}
        assert "scope" in columns
    finally:
        current_engine.dispose()
```

- [ ] **Step 6: Run the migration test to verify it fails**

Run: `cd backend && python -m pytest tests/test_db_migration.py -v`
Expected: FAIL with `ImportError: cannot import name 'ensure_schema' from 'app.db'`

- [ ] **Step 7: Implement `ensure_schema` in `app/db.py`**

Replace the full contents of `backend/app/db.py` with:

```python
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

connect_args = (
    {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
)
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def ensure_schema(bind=None) -> None:
    """Creates any missing tables, then adds any columns the current
    models define that an existing table predates (SQLite's
    ALTER TABLE ... ADD COLUMN is sufficient here - no full migration
    framework needed for a single additive column)."""
    bind = bind or engine
    Base.metadata.create_all(bind=bind)

    inspector = inspect(bind)
    if "projects" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("projects")}
    if "scope" not in columns:
        with bind.begin() as conn:
            conn.execute(text("ALTER TABLE projects ADD COLUMN scope JSON"))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

Note: `Base.metadata.create_all(bind=bind)` must run *before* the model
import that defines `Project` (with its new `scope` column) is available
for SQLAlchemy to know about — this is already satisfied because
`app/models.py` imports `Base` from `app/db.py` at module load time, and
by the time any test or CLI code calls `ensure_schema()`, `app.models`
has already been imported (directly or transitively), so `Base.metadata`
already has `Project` registered.

- [ ] **Step 8: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_db_migration.py tests/test_models.py -v`
Expected: all PASS

- [ ] **Step 9: Switch `cli.py`'s schema setup to `ensure_schema()`**

In `backend/app/cli.py`, find:

```python
Base.metadata.create_all(bind=engine)
```

Replace with:

```python
from app.db import ensure_schema

ensure_schema()
```

(The existing import line is `from app.db import Base, SessionLocal, engine`. Both `Base` and `engine` were only used for the `Base.metadata.create_all(bind=engine)` call being replaced — after this change, grep `cli.py` for `Base` and `engine` to confirm neither is referenced anywhere else in the file, and if not, replace that import line with `from app.db import SessionLocal, ensure_schema`, dropping `Base` and `engine` entirely.)

- [ ] **Step 10: Run the full suite**

Run: `cd backend && python -m pytest -v`
Expected: all PASS

- [ ] **Step 11: Commit**

```bash
git add backend/app/models.py backend/app/db.py backend/app/cli.py backend/tests/test_models.py backend/tests/test_db_migration.py
git commit -m "feat(scope): add Project.scope column with an add-column-if-missing migration helper"
```

---

## Task 3: CLI scope flags (`--scope-include`, `--scope-exclude`, `--scope-window`)

**Files:**
- Modify: `backend/app/cli.py`
- Modify: `backend/app/i18n.py`
- Modify: `backend/tests/test_cli.py`

**Interfaces:**
- Consumes: `app.scope.is_in_scope` (Task 1), `models.Project.scope` (Task 2).
- Produces: `scan` command now creates `models.Project` with a populated `scope` dict shaped `{"include": [...], "exclude": [...], "allowed_window": {...} | absent}`. Later tasks (orchestrator, Task 4) read `scan.project.scope`.

- [ ] **Step 1: Add the new i18n keys**

In `backend/app/i18n.py`, add to the `"en"` dict (after `"active_modules_confirm_required"`):

```python
        "target_excluded_from_scope": (
            "the target itself falls outside the declared scope "
            "(--scope-include/--scope-exclude) - refusing to create a "
            "project with nothing left to test."
        ),
        "scope_window_invalid": (
            "--scope-window must be in the form HH:MM-HH:MM (e.g. 09:00-18:00)."
        ),
```

And to the `"pt"` dict, at the same relative position:

```python
        "target_excluded_from_scope": (
            "o proprio alvo cai fora do escopo declarado "
            "(--scope-include/--scope-exclude) - recusando criar um "
            "projeto sem nada pra testar."
        ),
        "scope_window_invalid": (
            "--scope-window deve estar no formato HH:MM-HH:MM (ex: 09:00-18:00)."
        ),
```

- [ ] **Step 2: Write the failing CLI tests**

Add to `backend/tests/test_cli.py`:

```python
def test_scan_defaults_scope_to_target_and_wildcard_subdomains():
    with patch("app.cli.run_scan"):
        result = runner.invoke(
            app,
            [
                "scan",
                "example.com",
                "--scope",
                "authorized test scope",
                "--authorized",
                "--confirm-active",
            ],
        )

    assert result.exit_code == 0, result.output
    db = SessionLocal()
    try:
        project = db.query(models.Project).filter_by(target="example.com").order_by(
            models.Project.id.desc()
        ).first()
        assert project.scope["include"] == ["example.com", "*.example.com"]
        assert project.scope["exclude"] == []
    finally:
        db.close()


def test_scan_persists_custom_scope_include_exclude_and_window():
    with patch("app.cli.run_scan"):
        result = runner.invoke(
            app,
            [
                "scan",
                "example.com",
                "--scope",
                "authorized test scope",
                "--authorized",
                "--confirm-active",
                "--scope-include",
                "example.com",
                "--scope-include",
                "*.example.com",
                "--scope-exclude",
                "internal.example.com",
                "--scope-window",
                "09:00-18:00",
            ],
        )

    assert result.exit_code == 0, result.output
    db = SessionLocal()
    try:
        project = db.query(models.Project).filter_by(target="example.com").order_by(
            models.Project.id.desc()
        ).first()
        assert project.scope["include"] == ["example.com", "*.example.com"]
        assert project.scope["exclude"] == ["internal.example.com"]
        assert project.scope["allowed_window"] == {"start": "09:00", "end": "18:00"}
    finally:
        db.close()


def test_scan_rejects_when_target_itself_is_excluded_from_scope():
    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--scope",
            "authorized test scope",
            "--authorized",
            "--confirm-active",
            "--scope-exclude",
            "example.com",
        ],
    )

    assert result.exit_code == 1
    assert "Error:" in result.output
    assert "scope" in result.output.lower()


def test_scan_rejects_malformed_scope_window():
    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--scope",
            "authorized test scope",
            "--authorized",
            "--confirm-active",
            "--scope-window",
            "not-a-window",
        ],
    )

    assert result.exit_code == 1
    assert "Error:" in result.output
    assert "scope-window" in result.output.lower()
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd backend && python -m pytest tests/test_cli.py -v`
Expected: FAIL — `--scope-include` etc. are unrecognized options (Typer/Click reports "No such option")

- [ ] **Step 4: Implement the CLI changes**

In `backend/app/cli.py`, add the import:

```python
from app.scope import is_in_scope
```

Add new options to the `scan` command signature (after `circuit_breaker_threshold`):

```python
    scope_include: list[str] = typer.Option(
        None, "--scope-include", help="Domain pattern or CIDR explicitly in scope (repeatable)"
    ),
    scope_exclude: list[str] = typer.Option(
        None, "--scope-exclude", help="Domain pattern or CIDR explicitly excluded (repeatable)"
    ),
    scope_window: str = typer.Option(
        None, "--scope-window", help="Allowed UTC time window, e.g. 09:00-18:00"
    ),
```

Right after the existing `has_active_modules`/`confirm_active` check
(before the `db = SessionLocal()` block), add scope resolution and
validation:

```python
    include = list(scope_include) if scope_include else [target, f"*.{target}"]
    exclude = list(scope_exclude) if scope_exclude else []

    allowed_window = None
    if scope_window:
        try:
            start_str, end_str = scope_window.split("-", 1)
            allowed_window = {"start": start_str.strip(), "end": end_str.strip()}
        except ValueError:
            console.print(f"[red]{i18n.t('error_prefix')}[/red] {i18n.t('scope_window_invalid')}")
            raise typer.Exit(code=1)

    scope_dict = {"include": include, "exclude": exclude}
    if allowed_window is not None:
        scope_dict["allowed_window"] = allowed_window

    if not is_in_scope(target, None, scope_dict):
        console.print(f"[red]{i18n.t('error_prefix')}[/red] {i18n.t('target_excluded_from_scope')}")
        raise typer.Exit(code=1)
```

Then update the `models.Project(...)` construction to pass `scope=scope_dict`:

```python
        project = models.Project(
            name=name or target,
            target=target,
            scope_notes=scope,
            scope=scope_dict,
            authorized=True,
            authorized_at=utc_now(),
        )
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
git commit -m "feat(scope): add --scope-include/--scope-exclude/--scope-window flags to scan"
```

---

## Task 4: Orchestrator threads scope through context, filters discovered subdomains, and skips modules outside the allowed window

**Files:**
- Modify: `backend/app/orchestrator.py`
- Modify: `backend/tests/test_orchestrator.py`

**Interfaces:**
- Consumes: `app.scope.is_in_scope`, `app.scope.is_within_window` (Task 1), `scan.project.scope` (Task 2/3).
- Produces: `context["scope"]` (the project's scope dict) available to every module from here on. Task 5-8 modules read `context.get("scope")`, treating `None` (key absent — only happens when a module is unit-tested directly with a bare `{}` context) as "no restriction," and a real dict as the fail-closed structured scope. Also produces the `scope_window_closed` Finding type (`data={"module": <module_name>}`) — recorded by the orchestrator itself, not by individual modules, since the window is checked once per module invocation before `module.run()` is ever called.

- [ ] **Step 1: Write the failing test**

Add to `backend/tests/test_orchestrator.py`:

```python
def test_run_scan_filters_out_of_scope_subdomains_before_later_modules_see_them():
    seen_subdomains = []

    class _DiscoveryModule(ReconModule):
        name = "_test_discovery_module"
        run_order = 10

        def run(self, target, context):
            return [
                Finding(type="subdomain", value="in-scope.example.com"),
                Finding(type="subdomain", value="out-of-scope.example.com"),
            ]

    class _LateContextCapturingModule(ReconModule):
        name = "_test_late_context_capturing_module"
        run_order = 90

        def run(self, target, context):
            seen_subdomains.append(set(context.get("subdomains", set())))
            return []

    db = SessionLocal()
    try:
        project = models.Project(
            name="Scope Filter Co",
            target="example.com",
            scope_notes="only in-scope.example.com",
            authorized=True,
            scope={"include": ["example.com", "in-scope.example.com"]},
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
        register_module(_LateContextCapturingModule)
        with _mock_all_modules(
            exclude={_DiscoveryModule.name, _LateContextCapturingModule.name}
        ):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_DiscoveryModule.name]
        del MODULE_REGISTRY[_LateContextCapturingModule.name]

    assert seen_subdomains == [{"in-scope.example.com"}]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/test_orchestrator.py -k filters_out_of_scope -v`
Expected: FAIL — `seen_subdomains` will contain both subdomains (no filtering yet)

- [ ] **Step 3: Implement the orchestrator change**

In `backend/app/orchestrator.py`, add the import:

```python
from app.scope import is_in_scope
```

Change the context construction (already carries `rate_limit`/`circuit_breaker_threshold` from Fase B) to also carry `scope`:

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

Change the finding-processing loop to filter subdomains by scope:

```python
        ordered_modules = sorted(MODULE_REGISTRY.values(), key=lambda cls: cls.run_order)
        for module_cls in ordered_modules:
            progress_callback(module_cls.name)
            module = module_cls()
            for finding in _run_module(db, scan_id, module, target, context):
                if finding.type == "subdomain":
                    if is_in_scope(finding.value, None, context["scope"]):
                        context["subdomains"].add(finding.value)
                elif finding.type == "technology":
                    context["technologies"].append(dict(finding.data))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && python -m pytest tests/test_orchestrator.py -k filters_out_of_scope -v`
Expected: PASS

- [ ] **Step 5: Write the failing test for the time window**

Add to `backend/tests/test_orchestrator.py`:

```python
def test_run_scan_skips_a_module_entirely_when_the_scope_window_is_closed():
    called = []

    class _WindowedModule(ReconModule):
        name = "_test_windowed_module"
        run_order = 20

        def run(self, target, context):
            called.append(self.name)
            return []

    db = SessionLocal()
    try:
        project = models.Project(
            name="Window Co",
            target="example.com",
            scope_notes="business hours only",
            authorized=True,
            scope={
                "include": ["example.com"],
                "allowed_window": {"start": "00:00", "end": "00:01"},
            },
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
        register_module(_WindowedModule)
        with _mock_all_modules(exclude={_WindowedModule.name}):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_WindowedModule.name]

    assert called == []

    db = SessionLocal()
    try:
        findings = db.query(models.Finding).filter_by(scan_id=scan_id).all()
    finally:
        db.close()
    window_closed = [f for f in findings if f.type == "scope_window_closed"]
    assert any(f.module == "_test_windowed_module" for f in window_closed)
```

This test relies on `00:00-00:01` almost never being the current UTC
minute, which makes it a rare, acceptable flake rather than a real
dependency on wall-clock time — that's consistent with how tightly
scoped the window feature is (see the spec's "Out of scope for this
pass" section: no mid-scan interruption logic is being built, so a
precise fake-clock injection isn't warranted here either).

- [ ] **Step 6: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/test_orchestrator.py -k window_is_closed -v`
Expected: FAIL — `_test_windowed_module` still runs regardless of the window

- [ ] **Step 7: Implement the time-window check**

In `backend/app/orchestrator.py`, extend the import from Task 4 Step 3:

```python
from app.scope import is_in_scope, is_within_window
```

Update the per-module loop to skip a module entirely when the window is
closed, recording a `scope_window_closed` Finding instead of calling
`module.run()`:

```python
        ordered_modules = sorted(MODULE_REGISTRY.values(), key=lambda cls: cls.run_order)
        for module_cls in ordered_modules:
            progress_callback(module_cls.name)

            if not is_within_window(context["scope"]):
                _persist(
                    db,
                    scan_id,
                    module_cls.name,
                    Finding(
                        type="scope_window_closed",
                        value=module_cls.name,
                        data={"module": module_cls.name},
                    ),
                )
                continue

            module = module_cls()
            for finding in _run_module(db, scan_id, module, target, context):
                if finding.type == "subdomain":
                    if is_in_scope(finding.value, None, context["scope"]):
                        context["subdomains"].add(finding.value)
                elif finding.type == "technology":
                    context["technologies"].append(dict(finding.data))
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_orchestrator.py -v`
Expected: all PASS

- [ ] **Step 9: Run the full suite**

Run: `cd backend && python -m pytest -v`
Expected: all PASS (existing orchestrator tests create projects without an explicit `scope`, which defaults to `{}` — `is_in_scope` fails closed on that, but those tests' assertions check persisted `Finding` rows, not `context["subdomains"]`, so subdomain filtering doesn't affect them; `is_within_window` returns `True` for `{}` since there's no `allowed_window` key, so none of those tests are affected by the window check either)

- [ ] **Step 10: Commit**

```bash
git add backend/app/orchestrator.py backend/tests/test_orchestrator.py
git commit -m "feat(scope): thread project scope through orchestrator context, filter discovered subdomains, skip modules outside the allowed window"
```

---

## Task 5: `tech_fingerprint` scope enforcement

**Files:**
- Modify: `backend/app/modules/tech_fingerprint.py`
- Modify: `backend/tests/test_modules_tech_fingerprint.py`

**Interfaces:**
- Consumes: `context.get("scope")` (Task 4), `app.scope.is_in_scope` (Task 1).
- Produces: an `out_of_scope` Finding (`data={"module": "tech_fingerprint"}`) per skipped host, same shape used by every other module in this plan.

- [ ] **Step 1: Write the failing test**

Add to `backend/tests/test_modules_tech_fingerprint.py`:

```python
def test_out_of_scope_hosts_are_skipped_and_recorded_without_requests():
    base = _response(headers={"Server": "nginx/1.18.0"})
    probe_404 = _response(status_code=404)

    def fake_get(url, **kwargs):
        assert "blocked.example.com" not in url
        if url.endswith("/CHANGELOG.txt"):
            return probe_404
        return base

    scope = {"include": ["example.com"], "exclude": ["blocked.example.com"]}

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=fake_get):
        findings = TechFingerprintModule().run(
            "example.com", {"subdomains": {"blocked.example.com"}, "scope": scope}
        )

    out_of_scope = [f for f in findings if f.type == "out_of_scope"]
    assert [f.value for f in out_of_scope] == ["blocked.example.com"]
    assert out_of_scope[0].data == {"module": "tech_fingerprint"}
    assert any(f.data.get("name") == "nginx" for f in findings if f.type == "technology")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/test_modules_tech_fingerprint.py -k out_of_scope -v`
Expected: FAIL — `blocked.example.com` gets requested (the `assert` inside `fake_get` fails) since there's no scope check yet

- [ ] **Step 3: Implement the scope check**

In `backend/app/modules/tech_fingerprint.py`, add the import:

```python
from app.scope import is_in_scope
```

In `run()`, read `scope` from context and check it first in the per-host loop, before the rate limiter wait:

```python
    def run(self, target: str, context: dict) -> list[Finding]:
        hosts = sorted(context.get("subdomains", set()) | {target})
        scope = context.get("scope")
        limiter = RateLimiter(context.get("rate_limit", DEFAULT_RATE_LIMIT))
        breaker = CircuitBreaker(
            context.get("circuit_breaker_threshold", DEFAULT_CIRCUIT_BREAKER_THRESHOLD)
        )

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

            if reached_host:
                breaker.record_success()
                continue

            if breaker.record_failure():
                findings.append(
                    Finding(
                        type="circuit_breaker_tripped",
                        value=host,
                        data={"module": self.name, "skipped_hosts": len(hosts) - index - 1},
                    )
                )
                break
        return findings
```

(Only the loop body changed — the `if scope is not None and not is_in_scope(...)` block is new and sits before the existing `limiter.wait()` line; everything else in `run()` and the rest of the file is unchanged.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_modules_tech_fingerprint.py -v`
Expected: all PASS

- [ ] **Step 5: Run the full suite**

Run: `cd backend && python -m pytest -v`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add backend/app/modules/tech_fingerprint.py backend/tests/test_modules_tech_fingerprint.py
git commit -m "feat(scope): enforce scope per-host in tech_fingerprint before probing"
```

---

## Task 6: `cloud_range` scope enforcement (resolve, then check with the resolved IP)

**Files:**
- Modify: `backend/app/modules/cloud_range.py`
- Modify: `backend/tests/test_modules_cloud_range.py`

**Interfaces:**
- Consumes: `context.get("scope")` (Task 4), `app.scope.is_in_scope` (Task 1).
- Produces: an `out_of_scope` Finding (`data={"module": "cloud_range"}`) per skipped host. `cloud_range` is the only module that checks scope *with* a resolved IP, since it's the only one that already resolves one — this lets CIDR-range scope entries work here specifically.

- [ ] **Step 1: Write the failing test**

Add to `backend/tests/test_modules_cloud_range.py`:

```python
def test_out_of_scope_hosts_are_skipped_after_resolution():
    scope = {"include": ["example.com"], "exclude": ["blocked.example.com"]}

    with patch(
        "app.modules.cloud_range.socket.gethostbyname", return_value="3.5.140.1"
    ):
        findings = CloudRangeModule().run(
            "example.com", {"subdomains": {"blocked.example.com"}, "scope": scope}
        )

    out_of_scope = [f for f in findings if f.type == "out_of_scope"]
    assert [f.value for f in out_of_scope] == ["blocked.example.com"]
    assert out_of_scope[0].data == {"module": "cloud_range"}
    cloud_assets = [f for f in findings if f.type == "cloud_asset"]
    assert [f.value for f in cloud_assets] == ["example.com"]


def test_cidr_scope_entry_matches_resolved_ip():
    scope = {"include": ["3.5.128.0/18"]}

    with patch(
        "app.modules.cloud_range.socket.gethostbyname", return_value="3.5.140.1"
    ):
        findings = CloudRangeModule().run("example.com", {"scope": scope})

    cloud_assets = [f for f in findings if f.type == "cloud_asset"]
    assert [f.value for f in cloud_assets] == ["example.com"]
    assert not any(f.type == "out_of_scope" for f in findings)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && python -m pytest tests/test_modules_cloud_range.py -k "out_of_scope or cidr_scope" -v`
Expected: FAIL — no scope enforcement yet, `blocked.example.com` still produces no `out_of_scope` finding

- [ ] **Step 3: Implement the scope check**

In `backend/app/modules/cloud_range.py`, add the import:

```python
from app.scope import is_in_scope
```

Update `run()` to check scope right after resolving each host's IP (before matching cloud provider ranges):

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

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_modules_cloud_range.py -v`
Expected: all PASS

- [ ] **Step 5: Run the full suite**

Run: `cd backend && python -m pytest -v`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add backend/app/modules/cloud_range.py backend/tests/test_modules_cloud_range.py
git commit -m "feat(scope): enforce scope in cloud_range using the already-resolved IP"
```

---

## Task 7: `httpx_probe` pre-filters out-of-scope hosts

**Files:**
- Modify: `backend/app/modules/httpx_probe.py`
- Modify: `backend/tests/test_modules_httpx_probe.py`

**Interfaces:**
- Consumes: `context.get("scope")` (Task 4), `app.scope.is_in_scope` (Task 1).
- Produces: the host list fed to the `httpx` subprocess never includes an out-of-scope host; one `out_of_scope` Finding per skipped host is returned alongside the parsed `live_host` findings.

- [ ] **Step 1: Write the failing test**

Add to `backend/tests/test_modules_httpx_probe.py`:

```python
def test_pre_filters_out_of_scope_hosts_before_invoking_httpx():
    fake_result = MagicMock(stdout="")
    scope = {"include": ["example.com"], "exclude": ["blocked.example.com"]}

    with patch("app.modules.httpx_probe.subprocess.run", return_value=fake_result) as mock_run:
        findings = HttpxProbeModule().run(
            "example.com", {"subdomains": {"blocked.example.com"}, "scope": scope}
        )

    called_input = mock_run.call_args.kwargs["input"]
    assert "blocked.example.com" not in called_input
    assert "example.com" in called_input

    out_of_scope = [f for f in findings if f.type == "out_of_scope"]
    assert [f.value for f in out_of_scope] == ["blocked.example.com"]
    assert out_of_scope[0].data == {"module": "httpx_probe"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/test_modules_httpx_probe.py -k pre_filters -v`
Expected: FAIL — `blocked.example.com` is still in `called_input`, and no `out_of_scope` finding is returned

- [ ] **Step 3: Implement the pre-filter**

In `backend/app/modules/httpx_probe.py`, add the import:

```python
from app.scope import is_in_scope
```

Update `run()`:

```python
    def run(self, target: str, context: dict) -> list[Finding]:
        hosts = context.get("subdomains", set()) | {target}
        scope = context.get("scope")
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
        result = subprocess.run(
            command,
            input="\n".join(sorted(hosts)),
            capture_output=True,
            text=True,
            timeout=300,
            check=True,
        )

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

(This restructures `run()` to build `findings` up front instead of only at
the end — the rest of the method body, from `rate_limit = ...` onward, is
unchanged from Fase B; only the `hosts` value it operates on may now be
narrower, and the return statement now returns the accumulated `findings`
list instead of building a fresh one.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_modules_httpx_probe.py -v`
Expected: all PASS

- [ ] **Step 5: Run the full suite**

Run: `cd backend && python -m pytest -v`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add backend/app/modules/httpx_probe.py backend/tests/test_modules_httpx_probe.py
git commit -m "feat(scope): pre-filter out-of-scope hosts before invoking httpx"
```

---

## Task 8: `crtsh` and `whois` check the target itself before their single request

**Files:**
- Modify: `backend/app/modules/crtsh.py`
- Modify: `backend/app/modules/whois_module.py`
- Modify: `backend/tests/test_modules_crtsh.py`
- Modify: `backend/tests/test_modules_whois.py`

**Interfaces:**
- Consumes: `context.get("scope")` (Task 4), `app.scope.is_in_scope` (Task 1).
- Produces: an `out_of_scope` Finding (`data={"module": "crtsh"}` or `data={"module": "whois"}`) when the target itself is excluded — a defense-in-depth path that should be unreachable in normal CLI usage (Task 3 already refuses to create a project whose target is excluded), but is directly exercisable when a module is unit-tested or driven outside the CLI.

- [ ] **Step 1: Write the failing tests**

Add to `backend/tests/test_modules_crtsh.py` (check the existing file's imports first — it currently imports `requests` mocking via `patch("app.modules.crtsh.requests.get", ...)`; follow that same pattern):

```python
def test_refuses_to_query_a_target_outside_declared_scope():
    from unittest.mock import patch

    from app.modules.crtsh import CrtShModule

    scope = {"include": ["other.com"]}

    with patch("app.modules.crtsh.requests.get") as mock_get:
        findings = CrtShModule().run("example.com", {"scope": scope})

    mock_get.assert_not_called()
    assert len(findings) == 1
    assert findings[0].type == "out_of_scope"
    assert findings[0].value == "example.com"
    assert findings[0].data == {"module": "crtsh"}
```

Add to `backend/tests/test_modules_whois.py` (check the existing file's
patch target first, e.g. `app.modules.whois_module.whois.whois`, and
follow that same pattern):

```python
def test_refuses_to_query_a_target_outside_declared_scope():
    from unittest.mock import patch

    from app.modules.whois_module import WhoisModule

    scope = {"include": ["other.com"]}

    with patch("app.modules.whois_module.whois.whois") as mock_whois:
        findings = WhoisModule().run("example.com", {"scope": scope})

    mock_whois.assert_not_called()
    assert len(findings) == 1
    assert findings[0].type == "out_of_scope"
    assert findings[0].value == "example.com"
    assert findings[0].data == {"module": "whois"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && python -m pytest tests/test_modules_crtsh.py tests/test_modules_whois.py -v`
Expected: FAIL — both modules still call their request functions unconditionally

- [ ] **Step 3: Implement the target-scope check in `crtsh.py`**

In `backend/app/modules/crtsh.py`, add the import and the check at the
top of `run()`:

```python
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

        response = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{target}", "output": "json"},
            timeout=30,
        )
        response.raise_for_status()

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

- [ ] **Step 4: Implement the target-scope check in `whois_module.py`**

In `backend/app/modules/whois_module.py`:

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

        record = whois.whois(target)
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
git commit -m "feat(scope): crtsh and whois refuse to query a target outside declared scope"
```

---

## Task 9: Update documentation and do a live smoke test

**Files:**
- Modify: `README.md`
- Modify: `README.pt-BR.md`

**Interfaces:**
- Consumes: nothing (documentation only).
- Produces: nothing consumed by other tasks — this is the final task.

- [ ] **Step 1: Update the command reference table in `README.md`**

In the `### Run a scan` section's flag table, add three rows after
`--circuit-breaker-threshold`:

```markdown
| `--scope-include` | no | Domain pattern or CIDR explicitly in scope (repeatable, defaults to `<target>` and `*.<target>`) |
| `--scope-exclude` | no | Domain pattern or CIDR explicitly excluded from scope (repeatable) |
| `--scope-window` | no | Allowed UTC time window, e.g. `09:00-18:00` (default: always allowed) |
```

Add a short paragraph after the existing rate-limiting paragraph in that
same section:

```markdown
Every module checks the declared scope before touching a host — an
out-of-scope host is skipped and recorded as an `out_of_scope` finding
instead of being probed. If narrowing scope with `--scope-include`
would exclude the target itself, `scan` refuses to create the project at
all.
```

- [ ] **Step 2: Update `Finding.type` list and known limitations in `README.md`**

In `## Data and persistence`, update the `Finding.type` sentence to add
`out_of_scope`:

```markdown
`Finding.type` currently includes: `subdomain`, `whois`, `live_host`,
`technology`, `cve`, `cloud_asset`, `module_error`,
`circuit_breaker_tripped`, `out_of_scope`, `scope_window_closed`.
`Finding.data` holds the type-specific payload (category/version/
confidence for technology; CVSS/severity/description for CVE, etc).
```

In `## Roadmap`, remove the (now-obsolete, if still present in any form)
scope-related bullet — check the current roadmap section for a
`structured scope` or similar entry from the professional-pentest
roadmap doc and remove it if present; if the roadmap section in
`README.md` doesn't mention scope explicitly, leave it as-is.

- [ ] **Step 3: Mirror the same changes in `README.pt-BR.md`**

Apply the equivalent additions in Portuguese: three new rows in the
`### Rodar um scan` flag table (`--scope-include`, `--scope-exclude`,
`--scope-window`, translated descriptions), the same short explanatory
paragraph translated, and `out_of_scope` added to the `Finding.type`
list in `## Dados e persistência`.

- [ ] **Step 4: Update the test count badge in both READMEs**

Run `cd backend && python -m pytest --collect-only -q` to get the final
test count, then update the `tests-NN%20passing` badge value and the
prose test count sentence in both `README.md` and `README.pt-BR.md` to
match (mirrors the pattern from Fase A/B's README updates).

- [ ] **Step 5: Live smoke test**

Run against the safe test domain, confirming scope enforcement is
visible in the report:

```bash
cd backend
python -m app.cli scan example.com --scope "smoke test scope enforcement" --authorized --confirm-active --scope-exclude "admin.example.com"
```

Expected: scan completes; if `subdomain_permutation` discovers
`admin.example.com` (it's in the module's static wordlist), the report's
"Other findings" table shows an `out_of_scope` row for it with module
`tech_fingerprint` and/or `cloud_range`/`httpx_probe`, and it never shows
up with a `technology`, `cloud_asset`, or `live_host` finding.

Also confirm the reject-on-excluded-target path live:

```bash
python -m app.cli scan example.com --scope "smoke test rejection" --authorized --confirm-active --scope-exclude "example.com"
```

Expected: exits with code 1 and the `target_excluded_from_scope` message,
no project created.

- [ ] **Step 6: Run the full suite one final time**

Run: `cd backend && python -m pytest -v`
Expected: all PASS

- [ ] **Step 7: Commit**

```bash
git add README.md README.pt-BR.md
git commit -m "docs(readme): document structured scope flags and out_of_scope findings"
```

- [ ] **Step 8: Push**

```bash
git push origin master
```
