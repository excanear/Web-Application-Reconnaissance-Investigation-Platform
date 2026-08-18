# Design — Fase D: Full Audit Trail

**Status:** approved, ready for implementation plan
**Roadmap:** `docs/superpowers/specs/2026-08-17-professional-pentest-roadmap.md` (Fase D)
**Depends on:** Fase A (i18n, done), Fase B (rate limiting/circuit breaker, done), Fase C (structured scope, done)

## Problem

Today the only record of what the tool did during a scan is the `Finding`
rows it produced — technologies detected, CVEs correlated, hosts skipped
for being out of scope, etc. There's no record of the underlying network
activity itself: every request the tool actually made, against what,
and what happened. For a professional pentest engagement, "we only
touched what was authorized" needs to be provable independently of
what happened to turn into a finding — a request that came back empty
still needs to be in the record. Fase C also left one known gap: when
the orchestrator filters a discovered subdomain out of scope before any
module sees it, nothing records that this happened.

## Scope decisions (confirmed with the user)

- **Every network request the tool makes**, including third-party
  service calls (the NVD API in `cve_correlation`) — not just
  requests against the authorized target/subdomains. A single trail
  covering everything the tool touched is simpler to reason about and
  more complete than two separate logs.
- **Per-individual-request granularity** where the code makes the
  request directly (matches the roadmap's "toda requisição de rede").
  Two modules shell out to opaque external binaries (`subfinder`,
  `httpx_probe`) and can't achieve true per-request fidelity without
  visibility into what the binary itself does — this is called out
  explicitly below as an accepted approximation, not glossed over.

## Data model

New `AuditEntry` table in `app/models.py`, alongside `Project`/`Scan`/
`Finding`:

```python
class AuditEntry(Base):
    __tablename__ = "audit_entries"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    module = Column(String, nullable=False)
    target = Column(String, nullable=False)  # host, technology name, or service (e.g. "nvd.nist.gov")
    url = Column(String, nullable=True)       # None for DNS/whois lookups, which have no URL
    outcome = Column(String, nullable=False)  # short string: status code, "resolved: <ip>", "error: <msg>"
    requested_at = Column(DateTime, default=utc_now)

    scan = relationship("Scan", back_populates="audit_entries")
```

`Scan` gets a matching `audit_entries = relationship("AuditEntry",
back_populates="scan")` alongside its existing `findings` relationship.

Unlike Fase C's `Project.scope` column, `AuditEntry` is a **wholly new
table** — `Base.metadata.create_all()` (already called via
`ensure_schema()`) creates missing tables on any existing database
without needing the add-column-if-missing migration helper Fase C
built. No new migration work required here.

## `app/audit.py` — the recorder

A small class, same shape as Fase B's `RateLimiter`/`CircuitBreaker`:

```python
class AuditLog:
    def __init__(self):
        self.entries: list[dict] = []

    def record(self, module: str, target: str, outcome: str, url: str | None = None) -> None:
        self.entries.append({
            "module": module,
            "target": target,
            "url": url,
            "outcome": outcome,
            "requested_at": utc_now(),
        })
```

Pure in-memory accumulator — no DB access inside modules, keeping
SQLAlchemy session handling centralized in the orchestrator (the same
boundary `Finding` already respects: modules return/record data,
the orchestrator persists it).

## Threading through `context`

Same mechanism already used for `rate_limit`, `circuit_breaker_threshold`,
and `scope` (Fase B/C): the orchestrator creates one `AuditLog()` per
scan and puts it in `context["audit"]` before the module loop starts.
Every module that makes a network call reaches into
`context["audit"].record(...)` at each call site. This keeps the
`ReconModule.run(target, context) -> list[Finding]` interface completely
unchanged — a future module author still just writes a file and imports
it, per Fase A's extensibility promise.

## Instrumentation per module

| Module | Call site(s) | Entries per run |
|---|---|---|
| `crtsh` | the single `requests.get` to crt.sh | 1 |
| `whois` | the single `whois.whois(target)` call | 1 |
| `cloud_range` | `socket.gethostbyname(host)` | 1 per host |
| `tech_fingerprint` | main `requests.get` + optional path_probe `requests.get` | 1-2 per host |
| `cve_correlation` | `requests.get` to the NVD API | 1 per technology queried |
| `subfinder` | the `subfinder` subprocess invocation | 1 per run (see below) |
| `httpx_probe` | the `httpx` subprocess invocation | 1 per host in the filtered list (see below) |
| `subdomain_permutation` | none — pure candidate generation, no network calls | 0 |

**Accepted approximation for `subfinder` and `httpx_probe`:** both shell
out to an external Go binary that makes its own requests internally,
invisible to this process. `subfinder` gets one audit entry per
invocation (`target=<the scan target>`, `outcome="success (N found)"` or
`"error: ..."`). `httpx_probe` gets one entry per host in the
already-scope-filtered host list it sends to the subprocess, with
`outcome` taken from that host's line in the parsed JSON output
(status code) when present, or `"no_response"` when the host never
appears in `httpx`'s output. Neither is literally "the individual HTTP
request `httpx`/`subfinder` made" — it's the closest honest
approximation available without controlling the binary's own request
loop. This gets documented in the code as a known limitation, not
presented as exact.

Skipped hosts (out of scope, or past a tripped circuit breaker) get no
audit entry — no request was made, so there's nothing to log. A host
that *was* attempted and failed (e.g. a `RequestException` before the
circuit breaker trips) does get an entry, `outcome="error: <message>"`.

## Persistence timing

Right after each module's `run()` returns — the same point
`_run_module` in `app/orchestrator.py` already persists that module's
`Finding`s — the orchestrator reads `context["audit"].entries`,
persists every entry accumulated so far as an `AuditEntry` row tagged
with the current `scan_id`, and clears the list before the next module
runs. This means a module that crashes mid-run doesn't lose the audit
trail already recorded by earlier modules (mirrors `_run_module`'s
existing per-module failure isolation for `Finding`s).

## The Fase C follow-up: `out_of_scope` Finding for discovery-filtered subdomains

In the orchestrator's subdomain-filtering step (`if finding.type ==
"subdomain": ... is_in_scope(...) ...`), when a discovered subdomain is
dropped for being out of scope, the orchestrator now also persists an
`out_of_scope` `Finding` for it, `data={"module": "orchestrator"}` —
distinguishing it from a per-module check (which will never fire for
this host, since it never reaches `context["subdomains"]` for any
module to see). This is a `Finding`, not an `AuditEntry`: no network
request happened, so there's nothing to audit-log — this is purely "we
saw it discovered and declined to touch it," the same shape as the
existing per-module `out_of_scope` Findings from Fase C.

## CLI: `recon audit <scan_id>`

New command, separate from `report` (matches the roadmap's "exportável
separadamente do relatório de achados"):

```bash
python -m app.cli audit <scan_id> --format table|csv
```

- `table` (default): a Rich table, same visual style as `report`'s
  existing tables — columns Module, Target, URL, Outcome, Requested at.
- `csv`: writes RFC-4180 CSV directly to stdout (no `--output` flag —
  consistent with the project's existing stdout-first style; the user
  redirects with shell `>` if they want a file).

No PDF export here — that's explicitly Fase F's job for the findings
report, and the audit trail doesn't need to anticipate it early.

## Testing

TDD, same pattern as every prior fase:

1. `app/audit.py`'s `AuditLog` class tested in isolation first —
   `.record()` appends the right shape, multiple calls accumulate,
   `requested_at` is set automatically.
2. Per-module instrumentation tests, one per module in the table above
   (mirroring how Fase B/C added one test per module for rate
   limiting/circuit breaking/scope) — asserting the right number of
   entries with the right `module`/`target`/`outcome` shape land in
   `context["audit"].entries` after `run()`.
3. Orchestrator tests: per-module persist-and-clear timing (a module
   that raises still leaves earlier modules' audit entries persisted);
   the new `out_of_scope` Finding for a discovery-filtered subdomain.
4. CLI tests for `audit <scan_id>` in both `table` and `csv` formats,
   plus the existing `report`/`history`/`scan` command tests remaining
   green (no regressions from the new table/command).

Full suite (`cd backend && pytest -v`) green before each commit, same
as every prior fase.

## Out of scope for this pass

- PDF export for the audit trail (Fase F's concern, for the findings
  report specifically — not being front-loaded here).
- True per-request fidelity inside `subfinder`/`httpx_probe` — would
  require replacing those external binaries with in-process request
  loops, a much larger change than this fase's budget; the
  per-invocation/per-host approximation is accepted and documented.
- Retroactively backfilling audit entries for scans run before this
  fase shipped — old scans simply have no `AuditEntry` rows, which is
  fine (an empty `audit` table result for an old `scan_id` is expected,
  not a bug).
