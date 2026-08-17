# Design — Fase C: Structured & Enforced Scope

**Status:** approved, ready for implementation plan
**Roadmap:** `docs/superpowers/specs/2026-08-17-professional-pentest-roadmap.md` (Fase C)
**Depends on:** Fase A (i18n, done), Fase B (rate limiting/circuit breaker, done)

## Problem

Today `Project.scope_notes` is a free-text description of the authorized
scope — it's stored for audit purposes but never enforced. Nothing stops
a module from touching a discovered subdomain that's actually outside
what the operator was authorized to test. Before Fase E adds more
powerful active-validation modules, the tool needs to be able to
**refuse** to touch something out of scope, not just trust the operator's
word.

## Data model

Add a structured `scope` column to `Project` alongside the existing
free-text `scope_notes` (which stays as-is — the human-readable
description used in reports/audit):

```python
scope = Column(JSON, nullable=False, default=dict)
```

Shape:

```json
{
  "include": ["example.com", "*.example.com"],
  "exclude": ["internal.example.com"],
  "allowed_window": {"start": "09:00", "end": "18:00"}
}
```

- `include` / `exclude` entries: a domain pattern (`example.com`,
  `*.example.com`) or a CIDR/IP (`10.0.0.0/8`, `1.2.3.4`).
- `allowed_window`: optional, `HH:MM`-`HH:MM` in UTC, no day-of-week.
  Absent means always allowed.

### Migration

There's no Alembic in this project, and `Base.metadata.create_all()`
only creates missing tables — it does not add columns to a table that
already exists. Existing `dev.db` files from before this change would
break on first query against the new column.

Add a small startup helper in `app/db.py`, run right after
`create_all()`: inspect `projects`' existing columns via
`sqlalchemy.inspect(engine)`, and if `scope` is missing, run
`ALTER TABLE projects ADD COLUMN scope JSON`. SQLite supports
`ALTER TABLE ... ADD COLUMN` natively. This is a generic
"add column if missing" helper, not a full migration framework — it
pays for itself again in Fase D when the audit table needs a similar
column addition down the line, but nothing more elaborate than that is
being built now.

## CLI

`scan` gains three new options:

| Flag | Repeatable | Default |
|---|---|---|
| `--scope-include` | yes | `[target, "*.{target}"]` if never passed |
| `--scope-exclude` | yes | `[]` |
| `--scope-window` | no | none (always allowed) |

Default include preserves today's implicit behavior (target + all its
discovered subdomains are fair game) so existing invocations without
the new flags keep working unchanged.

**Reject-on-excluded-target:** if resolving `include`/`exclude` leaves
the target itself out of scope (a contradictory input — the project's
own target excluded from its own scan), `scan` fails immediately with a
translated error message (English primary, Portuguese via `--lang`,
per Fase A), before any project row is created. There's no point running
a scan whose every module would immediately no-op.

## Matching (`app/scope.py`)

```python
def is_in_scope(host: str, ip: str | None, scope: dict) -> bool
```

- Exclude always wins over include (deny-list takes priority — matches
  the tool's existing safety-first posture from Fase A/B).
- A domain pattern `example.com` matches itself and any subdomain
  (`a.example.com`, `a.b.example.com`) — mirrors `crtsh`'s existing
  suffix-matching logic (`app/modules/crtsh.py`).
- A domain pattern `*.example.com` matches only subdomains, not the
  apex `example.com` itself.
- A CIDR/IP entry is checked against `ip` (when the caller has resolved
  one); hosts are never matched against CIDR entries and IPs are never
  matched against domain patterns.
- If `include` is empty, nothing is in scope (fail closed, not open).

Time window is a separate, coarser check: `is_within_window(scope) ->
bool`, using `datetime.utcnow()`. Checked once per module invocation
(not per host) — if the window has closed, the module simply doesn't
run at all for the rest of that scan and records nothing. No mid-run
interruption logic for a scan that happens to cross the window boundary
mid-flight — that's an accepted simplification for this fase.

## Enforcement points

- **`tech_fingerprint`, `cloud_range`** — both already loop per-host
  (threaded with `RateLimiter`/`CircuitBreaker` in Fase B). Add one
  `is_in_scope()` check per host in the same loop; an out-of-scope host
  is skipped (no rate-limiter wait, no request) and recorded as an
  `out_of_scope` Finding instead.
- **`httpx_probe`** — pre-filters the host list before building the
  subprocess input, since there's no per-host hook inside the external
  `httpx` binary to enforce scope from within.
- **`crtsh`, `whois`** — check the target itself once before their
  single request. In practice this only fires for the contradictory
  case the CLI-level check is meant to catch first; kept as
  defense-in-depth per module, consistent with the roadmap's explicit
  "every module checks before touching a host."
- **`cve_correlation`** — untouched. It only operates on technologies
  already tied to hosts that passed scope upstream; it never makes a
  request against a host directly.
- **Orchestrator** — after each discovery module runs (`crtsh`,
  `subfinder`, `subdomain_permutation`), filters `context["subdomains"]`
  down to in-scope entries before later modules ever see them. This is
  belt-and-suspenders with the per-module checks: cheap (one filter
  call), and means a module author who forgets the per-host check still
  can't touch something that was never in `context["subdomains"]` to
  begin with.

All `out_of_scope` findings share the same shape as the existing
`circuit_breaker_tripped` findings from Fase B: `{"module": ...}` in
`data`, so the CLI's existing "Other findings" report table picks them
up with zero changes to `cli.py`'s report rendering.

## Testing

TDD, same shape as Fase A/B:

1. `app/scope.py` matching logic first — domain patterns (apex,
   subdomain, wildcard), CIDR/IP, exclude-wins-over-include, empty
   include fails closed, time window open/closed.
2. Per-module tests mirroring Fase B's circuit-breaker tests: an
   out-of-scope host is skipped and recorded, in-scope hosts proceed
   normally, mixed lists only skip the out-of-scope ones.
3. Orchestrator test: a discovered subdomain outside scope never reaches
   `context["subdomains"]` for later modules.
4. CLI tests: default scope preserves current behavior, custom
   `--scope-include`/`--scope-exclude` narrows it, contradictory input
   (target excluded) rejects before project creation, in both languages
   per Fase A's `--lang` convention.
5. Migration test: a `projects` table created without the `scope`
   column (simulating a pre-Fase-C `dev.db`) gets the column added on
   next startup without data loss.

Full suite (`cd backend && pytest -v`) green before each commit, same as
every prior fase.

## Out of scope for this pass

- Day-of-week windows (roadmap explicitly scoped this fase to
  `HH:MM-HH:MM` only).
- Mid-scan interruption when a window closes while a scan is running.
- A general migration framework (Alembic) — the add-column-if-missing
  helper is deliberately minimal and specific to this need.
