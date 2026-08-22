# Fase H: Scaled Execution (Controlled Concurrency) — Design

## Context and goal

For large scopes (hundreds/thousands of subdomains), every module that
loops over hosts today does so **strictly sequentially**, one host at a
time, paced only by `RateLimiter.wait()`. A scan against a target with
1,000 discovered subdomains at the default 5 req/s takes on the order of
minutes just for `tech_fingerprint` alone, even though the actual
bottleneck (network I/O latency per request) leaves the process mostly
idle between requests.

Fase H's mandate, from the project roadmap
(`docs/superpowers/specs/2026-08-17-professional-pentest-roadmap.md`):
run modules with **limited parallelism inside the existing process** —
explicitly not reintroducing Celery/Redis, and explicitly still
respecting Fase B's rate limiting. This is local, bounded concurrency,
not distributed execution.

**Non-goal:** raising the effective request rate against a target.
`--max-requests-per-second` remains the hard ceiling on aggregate
request pace; concurrency only lets multiple in-flight requests share
that same paced budget instead of one request blocking the next
host's request from starting until it fully completes. The benefit is
wall-clock time (many slow/idle connections overlap), not more requests
per second.

## Current state

- `RateLimiter` (`backend/app/ratelimit.py`) paces calls via
  `time.monotonic()` + `time.sleep()`, mutating `self._last_call` with no
  lock — safe only because every module currently calls it from a single
  thread.
- `CircuitBreaker` (same file) tracks `_consecutive_failures` with no
  lock, same single-thread assumption.
- `AuditLog.record` (`backend/app/audit.py`) appends to a plain list, no
  lock.
- Two modules loop over hosts in Python, each host's work fully
  completing before the next host starts:
  - `tech_fingerprint.py`: `run()` iterates `hosts`, calling
    `_fingerprint_host()` (one GET to `https://{host}/` plus, for the
    fixed `PATH_PROBE_RULES` list, one more GET per rule) per host.
  - `cloud_range.py`: `run()` iterates `hosts`, calling
    `socket.gethostbyname(host)` per host.
- Two other host-touching modules are explicitly **out of scope** for
  this phase:
  - `httpx_probe.py` shells out once to the external `httpx` binary with
    every host piped to stdin — `httpx` already parallelizes internally
    and exposes its own `-rate-limit`, which this project already passes
    through. No Python-level loop to parallelize.
  - `cve_correlation.py` loops per `(technology name, version)` pair
    against the NVD API, not per host. NVD's own request cap (5/30s, or
    50/30s with an API key) is already the binding constraint — local
    concurrency wouldn't shorten a scan bound by an external rate limit
    the tool must not exceed regardless of local parallelism. Left
    sequential.
- `orchestrator.run_scan()` builds a `context` dict once per scan,
  passing `rate_limit`/`circuit_breaker_threshold` through from CLI
  flags (`--max-requests-per-second`, `--circuit-breaker-threshold`) —
  the same plumbing pattern this phase's new flag follows.

## Approach

Add one new CLI flag, `--max-workers` (default `1`), threaded through
`context["max_workers"]` exactly like `rate_limit` and
`circuit_breaker_threshold` are today. At the default, every module's
observable behavior — output, ordering, timing — is unchanged from
today: this phase is strictly opt-in.

`tech_fingerprint` and `cloud_range` process their `hosts` list in
**batches** of size `max_workers`, submitting each batch to a
`concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)` and
waiting for the whole batch to finish before deciding whether to submit
the next one. `max_workers=1` degrades to exactly one host processed at
a time — same code path as every value, no separate sequential branch
to keep in sync.

`RateLimiter`, `CircuitBreaker`, and `AuditLog` each gain an internal
`threading.Lock` guarding their mutable state, so the same shared
instance already threaded through `context` today can now be called
safely from multiple worker threads. This is a pure internal
implementation change — no public method signature changes.

### Why batches, not a single work queue

A single shared queue with workers pulling the next host as soon as
they're free would keep all `max_workers` slots busy continuously,
which is a real throughput win, but it also means the circuit breaker's
"stop probing this target" signal can't take effect until the queue
drains — with a large scope and a target that's down, that's exactly
the runaway-request scenario Fase B's circuit breaker exists to
prevent. Batching bounds the damage precisely: checking `breaker.is_open`
between batches means at most one extra batch (`max_workers - 1` hosts
beyond the one that tripped it) is ever in flight past the trip point,
a small and predictable cost in exchange for keeping the "stop
promptly" guarantee legible. This is the same trade-off class the
project already accepts elsewhere (e.g. `subfinder`/`httpx_probe`'s
one-audit-entry-per-invocation approximation) — documented, bounded,
not silent.

### Circuit breaker and audit-log semantics under concurrency

Today, `circuit_breaker_tripped`'s `skipped_hosts` count and the exact
host it fires on are both deterministic (strict sequential order).
Under concurrency:

- **Which host the trip fires on** becomes whichever host's failure
  is *recorded* last within the batch that pushes the failure count
  to the threshold — not necessarily the last host in sort order.
  `record_failure()` itself stays correct (it's now lock-guarded), but
  the *label* on the resulting `circuit_breaker_tripped` Finding's
  `value` is inherently a "some host in this batch" fact, not "the
  Nth host in the list" fact, once more than one host can fail
  concurrently.
- `skipped_hosts` is computed as `len(hosts) - hosts processed so far`,
  same formula as today, evaluated once after the batch that tripped
  the breaker finishes — still accurate, just counted per-batch instead
  of per-host.
- `AuditEntry` order for concurrent hosts is no longer guaranteed to
  match `hosts` sort order (entries from different threads can commit
  in either order) — the audit trail's existing guarantee is "every
  real request is recorded", not "recorded in request order", and nothing
  downstream (the `recon audit` CLI command, `report_data.py`) depends
  on entry order, only content. No behavior change to what's
  guaranteed, only documented as a real consequence of concurrency.
- `report_data.py`, `report_csv.py`, `report_pdf.py` are all
  **untouched** — they consume the already-persisted `Finding`/
  `AuditEntry` rows from the database, with no ordering assumption this
  phase would violate.

At `max_workers=1`, every one of the above stays byte-for-byte identical
to today (a "batch" of size 1 processed then checked is the existing
sequential loop).

### `_apply_path_probe_rule`'s nested `limiter.wait()` call

`tech_fingerprint`'s path-probe step calls `limiter.wait()` a second
time per host (for the WordPress `/CHANGELOG.txt` probe), inside
`_fingerprint_host()`. Under concurrency this becomes multiple threads
each making two paced calls into the same shared, now-lock-guarded
limiter — correct (the lock still serializes the actual pacing
decision across all callers, threads included), just worth naming
explicitly since it's the one module where a single "unit of work"
already means more than one `limiter.wait()` call.

## Global constraints

- `--max-requests-per-second` remains the true ceiling on aggregate
  request pace, enforced by the (now thread-safe) shared `RateLimiter`
  instance — concurrency never lets the tool exceed it, only lets
  multiple in-flight requests share the same paced budget.
- `--max-workers` defaults to `1`; omitting it produces byte-for-byte
  identical behavior to the tool before this phase.
- `httpx_probe.py` and `cve_correlation.py` are not touched by this
  phase (see Current state above for why).
- No new external dependency — `concurrent.futures` and `threading` are
  stdlib.
- No change to `Finding`/`AuditEntry` shape, no change to
  `report_data.py`/`report_csv.py`/`report_pdf.py`.
- `RateLimiter`/`CircuitBreaker`/`AuditLog` public method signatures are
  unchanged — only their internals gain locking.

## Testing approach

- `RateLimiter`/`CircuitBreaker`/`AuditLog`: new tests spinning up
  several real threads calling into one shared instance concurrently,
  asserting no lost updates (e.g. `AuditLog` ends up with exactly
  N entries after N concurrent `record()` calls from N threads;
  `CircuitBreaker` trips at exactly `threshold` recorded failures
  regardless of thread interleaving).
- `tech_fingerprint`/`cloud_range`: existing sequential-behavior tests
  keep passing unchanged (they don't pass `max_workers`, so default `1`
  applies). New tests pass `max_workers > 1` with a small synthetic host
  set and a mocked `requests.get`/`socket.gethostbyname`, asserting the
  same *set* of findings is produced (order not asserted for the
  concurrent case, per the semantics above) and that a circuit-breaker
  trip under concurrency still stops the module before all hosts are
  processed.
- No live/manual-validation network scan is strictly required by this
  phase's own logic (no new network behavior, no new external dataset,
  unlike Fase G) — but re-running the existing manual-validation target
  with `--max-workers 4` once, comparing wall-clock time and finding-set
  parity against a `--max-workers 1` run, is worth doing as a real-world
  sanity check before considering the phase done.
