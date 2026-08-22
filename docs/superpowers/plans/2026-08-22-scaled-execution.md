# Fase H: Scaled Execution (Controlled Concurrency) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `tech_fingerprint` and `cloud_range` process hosts with bounded, opt-in local concurrency (a new `--max-workers` flag, default `1`) instead of strictly one host at a time, while the shared `RateLimiter`/`CircuitBreaker`/`AuditLog` primitives they use stay correct under concurrent access.

**Architecture:** `RateLimiter`, `CircuitBreaker`, and `AuditLog` each gain an internal `threading.Lock` around their mutable state — pure internal change, no public signature change. `tech_fingerprint.run()` and `cloud_range.run()` are rewritten to process their `hosts` list in fixed-size batches (`max_workers` hosts per batch): each batch's per-host network work runs concurrently via a `ThreadPoolExecutor`, but the batch's *results* are then walked back in the original host-list order to build findings and drive the (now thread-safe) circuit breaker — so bookkeeping (which host trips the breaker, the `skipped_hosts` count, finding order) stays fully deterministic and, at `max_workers=1`, byte-for-byte identical to today's sequential code. `orchestrator.run_scan()` and `cli.py`'s `scan` command thread the new flag through exactly like `rate_limit`/`circuit_breaker_threshold` already are.

**Tech Stack:** Python stdlib only — `threading.Lock`, `concurrent.futures.ThreadPoolExecutor`. No new dependency.

**Spec:** `docs/superpowers/specs/2026-08-22-scaled-execution-design.md`

## Global Constraints

- `--max-requests-per-second` remains the true ceiling on aggregate request pace — concurrency only lets multiple in-flight requests share that paced budget, never exceeds it.
- `--max-workers` defaults to `1`; omitting it produces byte-for-byte identical behavior (same Finding order, same `skipped_hosts` formula, same circuit-breaker trip host) to the tool before this phase.
- `httpx_probe.py` and `cve_correlation.py` are not touched by this phase.
- No new external dependency.
- No change to `Finding`/`AuditEntry` shape, no change to `report_data.py`/`report_csv.py`/`report_pdf.py`.
- `RateLimiter.wait()`/`CircuitBreaker.record_success()`/`CircuitBreaker.record_failure()`/`AuditLog.record()` public signatures are unchanged — only their internals gain locking.

## Refinement over the spec (documented, not silent drift)

The spec's "Circuit breaker and audit-log semantics under concurrency"
section speculated that *which* host a circuit-breaker trip labels, and
the `skipped_hosts` count, would become non-deterministic under
concurrency. This plan's actual design avoids that: only the network
I/O for a batch runs concurrently (via `ThreadPoolExecutor.map`, which
returns results in submission order, not completion order) — every
piece of *bookkeeping* (appending Findings, calling
`breaker.record_success()`/`record_failure()`, computing `skipped_hosts`,
deciding whether to stop) still happens in a single, deterministic pass
over the batch's results in original host-list order, right after the
batch's futures resolve. The result: at `max_workers=1` (batch size 1),
every task's rewritten `run()` is byte-for-byte equivalent to the
current sequential loop — same formula, same order, same break
condition. Only `AuditEntry` commit order *within* a batch (multiple
threads calling `audit.record()` concurrently for different hosts) is
not guaranteed — exactly as the spec already says, and nothing
downstream depends on that order.

---

## File Structure

- **Modify** `backend/app/ratelimit.py` — `RateLimiter`/`CircuitBreaker` gain internal locks.
- **Modify** `backend/tests/test_ratelimit.py` — add concurrent-access tests.
- **Modify** `backend/app/audit.py` — `AuditLog` gains an internal lock.
- **Modify** `backend/tests/test_audit.py` — add a concurrent-access test.
- **Modify** `backend/app/modules/tech_fingerprint.py` — batch/concurrent host processing.
- **Modify** `backend/tests/test_modules_tech_fingerprint.py` — add `max_workers` tests.
- **Modify** `backend/app/modules/cloud_range.py` — batch/concurrent host processing.
- **Modify** `backend/tests/test_modules_cloud_range.py` — add `max_workers` tests.
- **Modify** `backend/app/orchestrator.py` — add `max_workers` parameter, thread into `context`.
- **Modify** `backend/tests/test_orchestrator.py` — assert `max_workers` reaches `context`.
- **Modify** `backend/app/cli.py` — add `--max-workers` option to `scan`.
- **Modify** `backend/tests/test_cli.py` — assert the flag forwards to `run_scan`.
- **Modify** `README.md`, `README.pt-BR.md` — document the new flag and its concurrency semantics.

---

### Task 1: Thread-safe `RateLimiter` and `CircuitBreaker`

**Files:**
- Modify: `backend/app/ratelimit.py`
- Test: `backend/tests/test_ratelimit.py`

**Interfaces:**
- No signature changes. `RateLimiter.wait() -> None`, `CircuitBreaker.record_success() -> None`, `CircuitBreaker.record_failure() -> bool` all keep their current behavior for single-threaded callers; this task only adds correctness under concurrent callers.

- [ ] **Step 1: Write the failing tests**

Append to `backend/tests/test_ratelimit.py`:

```python
import threading
from concurrent.futures import ThreadPoolExecutor


def test_rate_limiter_serializes_concurrent_waits_to_respect_the_pace():
    # 20 req/s -> min interval 0.05s. 5 threads all call wait() at once;
    # since the limiter must serialize them to respect the global pace,
    # completing all 5 takes at least 4 intervals (the first call never
    # waits, each of the other 4 waits ~0.05s behind the previous one).
    limiter = RateLimiter(20.0)
    start = None

    def call():
        nonlocal start
        limiter.wait()

    threads = [threading.Thread(target=call) for _ in range(5)]
    import time

    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - t0

    assert elapsed >= 0.05 * 4 * 0.8  # 20% slack for scheduling jitter


def test_circuit_breaker_loses_no_increments_under_concurrent_failures():
    # threshold high enough that it never trips -- this test is purely
    # about the internal counter surviving concurrent increments without
    # a lost update, not about trip behavior.
    breaker = CircuitBreaker(threshold=1000)

    with ThreadPoolExecutor(max_workers=20) as executor:
        list(executor.map(lambda _: breaker.record_failure(), range(200)))

    assert breaker._consecutive_failures == 200
    assert breaker.is_open is False


def test_circuit_breaker_trips_exactly_once_the_threshold_is_reached_concurrently():
    breaker = CircuitBreaker(threshold=50)

    with ThreadPoolExecutor(max_workers=20) as executor:
        list(executor.map(lambda _: breaker.record_failure(), range(50)))

    assert breaker._consecutive_failures == 50
    assert breaker.is_open is True
```

- [ ] **Step 2: Run tests to verify they fail or are flaky-by-design**

Run: `cd backend && pytest tests/test_ratelimit.py -v -k "concurrent or serializes"`
Expected: the counter tests (`loses_no_increments`, `trips_exactly_once`) FAIL or
intermittently fail today — `_consecutive_failures += 1` is not atomic
across threads without a lock, so some increments can be lost under
real concurrent execution. The pacing test may pass or fail
inconsistently depending on scheduling, since `_last_call` reads/writes
also race. All three become reliably correct only after Step 3.

- [ ] **Step 3: Add locking to `RateLimiter` and `CircuitBreaker`**

Replace the full contents of `backend/app/ratelimit.py`:

```python
"""Shared pacing and failure-isolation primitives for modules that make
real network requests against a target. Each module owns its own
RateLimiter/CircuitBreaker instance per run - state never persists across
scans. Both are safe to call from multiple threads concurrently (Fase H:
tech_fingerprint/cloud_range can now process several hosts' requests in
parallel, all sharing one RateLimiter/CircuitBreaker instance to keep the
pacing and failure-count guarantees global rather than per-thread)."""

import threading
import time


class RateLimiter:
    """Paces calls to at most `requests_per_second`, sleeping just enough
    since the previous call to respect that rate. The first call never
    sleeps - there's nothing to pace against yet. A lock serializes the
    read-decide-sleep-write sequence across threads, so the pace limit is
    enforced globally (across every caller sharing this instance), not
    per-thread."""

    def __init__(self, requests_per_second: float):
        self._min_interval = 1.0 / requests_per_second
        self._last_call: float | None = None
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            if self._last_call is not None:
                elapsed = now - self._last_call
                remaining = self._min_interval - elapsed
                if remaining > 0:
                    time.sleep(remaining)
                    now = self._last_call + self._min_interval
            self._last_call = now


class CircuitBreaker:
    """Tracks consecutive failures; trips (opens) once `threshold` failures
    happen in a row without an intervening success. A single success
    resets the streak. A lock guards the counter and `is_open` so
    concurrent record_success()/record_failure() calls from multiple
    threads never lose an update."""

    def __init__(self, threshold: int):
        self._threshold = threshold
        self._consecutive_failures = 0
        self.is_open = False
        self._lock = threading.Lock()

    def record_success(self) -> None:
        with self._lock:
            self._consecutive_failures = 0

    def record_failure(self) -> bool:
        with self._lock:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self._threshold:
                self.is_open = True
            return self.is_open
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_ratelimit.py -v`
Expected: PASS (all tests, including the 3 new ones, reliably — run it
2-3 times in a row to build confidence there's no residual flakiness).

- [ ] **Step 5: Commit**

```bash
git add backend/app/ratelimit.py backend/tests/test_ratelimit.py
git commit -m "feat(concurrency): make RateLimiter and CircuitBreaker thread-safe"
```

---

### Task 2: Thread-safe `AuditLog`

**Files:**
- Modify: `backend/app/audit.py`
- Test: `backend/tests/test_audit.py`

**Interfaces:**
- No signature changes. `AuditLog.record(module, target, outcome, url=None) -> None` keeps its current behavior for single-threaded callers.

- [ ] **Step 1: Write the failing test**

Append to `backend/tests/test_audit.py`:

```python
from concurrent.futures import ThreadPoolExecutor


def test_record_loses_no_entries_under_concurrent_calls():
    log = AuditLog()

    def do_record(i):
        log.record(module="tech_fingerprint", target=f"host{i}.example.com", outcome="200")

    with ThreadPoolExecutor(max_workers=20) as executor:
        list(executor.map(do_record, range(200)))

    assert len(log.entries) == 200
    assert {e["target"] for e in log.entries} == {f"host{i}.example.com" for i in range(200)}
```

- [ ] **Step 2: Run test to verify it's flaky-by-design today**

Run: `cd backend && pytest tests/test_audit.py -v -k concurrent`
Expected: `list.append` is CPython-GIL-protected for a single call, but
this test's real risk is subtler — without the task's own reasoning
being load-bearing here, this is a straightforward hardening step, not a
guaranteed-reproducible race. It should already pass most runs; the
point of this task is to make the code *provably* correct rather than
*accidentally* correct in the current CPython implementation, and to
leave a lock in place for any future entry-processing logic in
`record()` that would need one. Proceed to Step 3 regardless of this
run's outcome.

- [ ] **Step 3: Add a lock to `AuditLog`**

Replace the full contents of `backend/app/audit.py`:

```python
"""In-memory accumulator for network-request audit entries. Every
module that makes a real network call records into the shared instance
threaded through context["audit"]; the orchestrator persists .entries
to the AuditEntry table right after each module's run() returns, then
clears the list before the next module runs. Safe to call record() from
multiple threads concurrently (Fase H: tech_fingerprint/cloud_range can
process several hosts in parallel, all sharing one AuditLog instance)."""

import threading

from app.timeutil import utc_now


class AuditLog:
    def __init__(self):
        self.entries: list[dict] = []
        self._lock = threading.Lock()

    def record(self, module: str, target: str, outcome: str, url: str | None = None) -> None:
        entry = {
            "module": module,
            "target": target,
            "url": url,
            "outcome": outcome,
            "requested_at": utc_now(),
        }
        with self._lock:
            self.entries.append(entry)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_audit.py -v`
Expected: PASS (all tests).

- [ ] **Step 5: Commit**

```bash
git add backend/app/audit.py backend/tests/test_audit.py
git commit -m "feat(concurrency): make AuditLog thread-safe"
```

---

### Task 3: Batched/concurrent host processing in `tech_fingerprint`

**Files:**
- Modify: `backend/app/modules/tech_fingerprint.py`
- Modify: `backend/tests/test_modules_tech_fingerprint.py`

**Interfaces:**
- Consumes: `RateLimiter`/`CircuitBreaker` (Task 1, now thread-safe), `AuditLog.record` (Task 2, now thread-safe), `context.get("max_workers", DEFAULT_MAX_WORKERS)`.
- Produces: unchanged public behavior — `TechFingerprintModule.run(target, context) -> list[Finding]`. `context["max_workers"]` is a new, optional context key; absent or `1` means fully sequential (identical to pre-Fase-H behavior).

- [ ] **Step 1: Write the failing tests**

Append to `backend/tests/test_modules_tech_fingerprint.py` (this file
already has `NGINX_TECH`, `_response`, `_fake_get` helpers defined near
the top from Fase G — reuse them):

```python
def test_max_workers_default_is_fully_sequential_and_unchanged():
    # Same scenario/assertions as the pre-existing
    # test_circuit_breaker_trips_after_threshold_consecutive_failures_and_skips_remaining_hosts,
    # run with no max_workers in context at all -- proves the default path
    # is untouched by this task's changes.
    import requests

    subdomains = {f"host{i}.example.com" for i in range(5)}

    with patch(
        "app.modules.tech_fingerprint.requests.get",
        side_effect=requests.RequestException("down"),
    ):
        findings = TechFingerprintModule().run(
            "example.com",
            {"subdomains": subdomains, "circuit_breaker_threshold": 2, "wappalyzer_technologies": {}},
        )

    tripped = [f for f in findings if f.type == "circuit_breaker_tripped"]
    assert len(tripped) == 1
    assert tripped[0].data["skipped_hosts"] == 4


def test_max_workers_greater_than_one_still_detects_every_host():
    base = _response(headers={"Server": "nginx/1.18.0"})
    subdomains = {f"host{i}.example.com" for i in range(6)}

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=_fake_get(base)):
        findings = TechFingerprintModule().run(
            "example.com",
            {
                "subdomains": subdomains,
                "wappalyzer_technologies": NGINX_TECH,
                "max_workers": 3,
            },
        )

    hosts_detected = {f.value for f in findings if f.data.get("name") == "nginx"}
    assert hosts_detected == subdomains | {"example.com"}


def test_max_workers_circuit_breaker_trips_deterministically_on_batch_boundary():
    # 6 hosts total (sorted: example.com, host0..host4), max_workers=3 ->
    # two batches of 3. threshold=2 failures trips inside the first
    # batch (both requests in that batch fail) -- the trip must fire
    # using the same "last host whose failure crossed the threshold, in
    # host-list order" rule as the sequential (max_workers=1) case, and
    # the second batch must never be submitted.
    import requests

    subdomains = {f"host{i}.example.com" for i in range(5)}

    with patch(
        "app.modules.tech_fingerprint.requests.get",
        side_effect=requests.RequestException("down"),
    ):
        findings = TechFingerprintModule().run(
            "example.com",
            {
                "subdomains": subdomains,
                "circuit_breaker_threshold": 2,
                "wappalyzer_technologies": {},
                "max_workers": 3,
            },
        )

    tripped = [f for f in findings if f.type == "circuit_breaker_tripped"]
    assert len(tripped) == 1
    # sorted hosts: ["example.com", "host0.example.com", "host1.example.com",
    #                "host2.example.com", "host3.example.com", "host4.example.com"]
    # batch 1 = indices 0,1,2 -> failures at index 0 and 1 trip the breaker
    # (threshold=2) while processing batch-1 results in order; trip fires
    # on the host at index 1, matching what max_workers=1 would produce.
    assert tripped[0].value == "example.com" or tripped[0].value.startswith("host0")
    assert tripped[0].data["skipped_hosts"] == 4
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_modules_tech_fingerprint.py -v -k max_workers`
Expected: FAIL — `context.get("max_workers", ...)` isn't read yet, so
`max_workers=3` has no effect (all three tests actually run sequentially
today, so the first two may accidentally pass; the third's exact
`tripped[0].value` assertion is the one that pins down real batching
behavior — treat any of the three failing as expected-fail evidence,
and don't worry if 1-2 happen to already pass by coincidence of today's
sequential code path).

- [ ] **Step 3: Rewrite `tech_fingerprint.py`**

Replace the full contents of `backend/app/modules/tech_fingerprint.py`:

```python
# backend/app/modules/tech_fingerprint.py
import re
from concurrent.futures import ThreadPoolExecutor

import requests

from app import wappalyzer
from app.audit import AuditLog
from app.modules.base import Finding, ReconModule, register_module
from app.ratelimit import CircuitBreaker, RateLimiter
from app.scope import is_in_scope

DEFAULT_RATE_LIMIT = 5.0
DEFAULT_CIRCUIT_BREAKER_THRESHOLD = 5
DEFAULT_MAX_WORKERS = 1
REQUEST_TIMEOUT = 10

# Project-specific extension, not a native Wappalyzer check type: an
# active path probe for cases needing more precise version detection
# than a passive header/cookie/meta/html/scriptSrc check can offer.
PATH_PROBE_RULES = [
    {
        "category": "cms",
        "name": "WordPress",
        "path": "/CHANGELOG.txt",
        "pattern": r"Version\s+([\d.]+)",
    },
]


@register_module
class TechFingerprintModule(ReconModule):
    name = "tech_fingerprint"
    is_active = True

    def run(self, target: str, context: dict) -> list[Finding]:
        hosts = sorted(context.get("subdomains", set()) | {target})
        scope = context.get("scope")
        audit = context.get("audit")
        max_workers = context.get("max_workers", DEFAULT_MAX_WORKERS)
        limiter = RateLimiter(context.get("rate_limit", DEFAULT_RATE_LIMIT))
        breaker = CircuitBreaker(
            context.get("circuit_breaker_threshold", DEFAULT_CIRCUIT_BREAKER_THRESHOLD)
        )
        technologies = context.get("wappalyzer_technologies")
        if technologies is None:
            technologies = wappalyzer.load_technologies()

        findings: list[Finding] = []

        for batch_start in range(0, len(hosts), max_workers):
            batch = hosts[batch_start:batch_start + max_workers]
            in_scope_batch = [
                host for host in batch if scope is None or is_in_scope(host, None, scope)
            ]
            for host in batch:
                if host not in in_scope_batch:
                    findings.append(
                        Finding(type="out_of_scope", value=host, data={"module": self.name})
                    )

            if not in_scope_batch:
                continue

            with ThreadPoolExecutor(max_workers=len(in_scope_batch)) as executor:
                results = list(
                    executor.map(
                        lambda host: self._fingerprint_host(host, limiter, audit, technologies),
                        in_scope_batch,
                    )
                )

            breaker_tripped = False
            for offset, host in enumerate(batch):
                if host not in in_scope_batch:
                    continue
                index = batch_start + offset
                host_findings, reached_host = results[in_scope_batch.index(host)]
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
                    breaker_tripped = True
                    break

            if breaker_tripped:
                break
        return findings

    def _fingerprint_host(
        self, host: str, limiter: RateLimiter, audit: AuditLog | None, technologies: dict
    ) -> tuple[list[Finding], bool]:
        limiter.wait()
        url = f"https://{host}/"
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            if audit is not None:
                audit.record(module=self.name, target=host, outcome=f"error: {exc}", url=url)
            return [], False

        if audit is not None:
            audit.record(module=self.name, target=host, outcome=str(response.status_code), url=url)

        findings = wappalyzer.match_technologies(host, response, technologies=technologies)
        for rule in PATH_PROBE_RULES:
            finding = self._apply_path_probe_rule(host, rule, limiter, audit)
            if finding is not None:
                findings.append(finding)
        return findings, True

    def _apply_path_probe_rule(
        self, host: str, rule: dict, limiter: RateLimiter, audit: AuditLog | None
    ) -> Finding | None:
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
        version = match.group(1) if match.groups() else None
        return Finding(
            type="technology",
            value=host,
            data={
                "category": rule["category"],
                "name": rule["name"],
                "version": version,
                "confidence": "high" if version else "medium",
                "source": "path_probe",
            },
        )
```

Note on `limiter.wait()` moving inside `_fingerprint_host`: in the
pre-Fase-H code, `run()` called `limiter.wait()` once per host *before*
calling `_fingerprint_host`. Since hosts in a batch now run inside
separate threads, each host's worker must call `limiter.wait()` itself
right before its own request — the (now thread-safe, from Task 1)
shared `limiter` instance still serializes the pacing decision across
every caller, so the aggregate rate is still correctly capped; only the
call site moved. At `max_workers=1` this produces the exact same
sequence of `wait()` calls as before (one per host, right before that
host's request).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_modules_tech_fingerprint.py -v`
Expected: PASS (all tests — the full file, not just the `max_workers`
ones, since the rewrite touches every code path).

- [ ] **Step 5: Run the full suite to check for regressions**

Run: `cd backend && pytest -v`
Expected: PASS (all tests).

- [ ] **Step 6: Commit**

```bash
git add backend/app/modules/tech_fingerprint.py backend/tests/test_modules_tech_fingerprint.py
git commit -m "feat(concurrency): batch tech_fingerprint host processing behind --max-workers"
```

---

### Task 4: Batched/concurrent host processing in `cloud_range`

**Files:**
- Modify: `backend/app/modules/cloud_range.py`
- Modify: `backend/tests/test_modules_cloud_range.py`

**Interfaces:**
- Consumes: `RateLimiter`/`CircuitBreaker` (Task 1), `AuditLog.record` (Task 2), `context.get("max_workers", DEFAULT_MAX_WORKERS)`.
- Produces: unchanged public behavior — `CloudRangeModule.run(target, context) -> list[Finding]`.

- [ ] **Step 1: Read the existing test file first**

Read `backend/tests/test_modules_cloud_range.py` in full before writing
new tests — reuse its existing helpers/fixtures/mocking style for
`socket.gethostbyname` exactly (this plan doesn't reproduce them here
since they already exist and this task must not diverge from their
established pattern).

- [ ] **Step 2: Write the failing tests**

Append to `backend/tests/test_modules_cloud_range.py`, adapting the
existing file's own mocking pattern for `socket.gethostbyname` (e.g. if
the file mocks it via `patch("app.modules.cloud_range.socket.gethostbyname", ...)`,
follow that same import path):

```python
def test_max_workers_default_is_fully_sequential_and_unchanged():
    # Mirrors this file's existing circuit-breaker-trip test (same
    # subdomain count / threshold / all-failing setup) but asserted with
    # no max_workers key in context at all.
    with patch(
        "app.modules.cloud_range.socket.gethostbyname",
        side_effect=OSError("unknown host"),
    ):
        findings = CloudRangeModule().run(
            "example.com",
            {
                "subdomains": {f"host{i}.example.com" for i in range(5)},
                "circuit_breaker_threshold": 2,
            },
        )

    tripped = [f for f in findings if f.type == "circuit_breaker_tripped"]
    assert len(tripped) == 1
    assert tripped[0].data["skipped_hosts"] == 4


def test_max_workers_greater_than_one_still_resolves_every_host():
    with patch(
        "app.modules.cloud_range.socket.gethostbyname",
        return_value="52.1.2.3",  # inside the AWS CLOUD_RANGES sample
    ):
        findings = CloudRangeModule().run(
            "example.com",
            {
                "subdomains": {f"host{i}.example.com" for i in range(6)},
                "max_workers": 3,
            },
        )

    cloud_assets = {f.value for f in findings if f.type == "cloud_asset"}
    assert cloud_assets == {f"host{i}.example.com" for i in range(6)} | {"example.com"}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_modules_cloud_range.py -v -k max_workers`
Expected: FAIL — same reasoning as Task 3's Step 2 (max_workers isn't
read yet).

- [ ] **Step 4: Rewrite `cloud_range.py`**

Replace the full contents of `backend/app/modules/cloud_range.py`:

```python
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

from app.modules.base import Finding, ReconModule, register_module
from app.ratelimit import CircuitBreaker, RateLimiter
from app.scope import is_in_scope

DEFAULT_RATE_LIMIT = 5.0
DEFAULT_CIRCUIT_BREAKER_THRESHOLD = 5
DEFAULT_MAX_WORKERS = 1

# Small illustrative sample of public cloud ranges, not an authoritative or
# exhaustive list (each provider publishes machine-readable full lists that
# a future module could sync periodically instead).
CLOUD_RANGES = [
    ("aws", ipaddress.ip_network("3.5.128.0/18")),
    ("aws", ipaddress.ip_network("52.0.0.0/11")),
    ("gcp", ipaddress.ip_network("34.64.0.0/10")),
    ("gcp", ipaddress.ip_network("35.184.0.0/13")),
    ("azure", ipaddress.ip_network("20.0.0.0/8")),
    ("azure", ipaddress.ip_network("40.64.0.0/10")),
]


@register_module
class CloudRangeModule(ReconModule):
    name = "cloud_range"

    def run(self, target: str, context: dict) -> list[Finding]:
        hosts = sorted(context.get("subdomains", set()) | {target})
        scope = context.get("scope")
        audit = context.get("audit")
        max_workers = context.get("max_workers", DEFAULT_MAX_WORKERS)
        limiter = RateLimiter(context.get("rate_limit", DEFAULT_RATE_LIMIT))
        breaker = CircuitBreaker(
            context.get("circuit_breaker_threshold", DEFAULT_CIRCUIT_BREAKER_THRESHOLD)
        )
        findings = []

        for batch_start in range(0, len(hosts), max_workers):
            batch = hosts[batch_start:batch_start + max_workers]

            with ThreadPoolExecutor(max_workers=len(batch)) as executor:
                results = list(
                    executor.map(lambda host: self._resolve_host(host, limiter, audit), batch)
                )

            breaker_tripped = False
            for offset, (host, (ip, error)) in enumerate(zip(batch, results)):
                index = batch_start + offset

                if error is not None:
                    if breaker.record_failure():
                        findings.append(
                            Finding(
                                type="circuit_breaker_tripped",
                                value=host,
                                data={"module": self.name, "skipped_hosts": len(hosts) - index - 1},
                            )
                        )
                        breaker_tripped = True
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

            if breaker_tripped:
                break

        return findings

    def _resolve_host(
        self, host: str, limiter: RateLimiter, audit
    ) -> tuple[str | None, str | None]:
        limiter.wait()
        try:
            ip = socket.gethostbyname(host)
        except OSError as exc:
            if audit is not None:
                audit.record(module=self.name, target=host, outcome=f"error: {exc}")
            return None, str(exc)
        if audit is not None:
            audit.record(module=self.name, target=host, outcome=f"resolved: {ip}")
        return ip, None

    @staticmethod
    def _match_provider(ip: str) -> str | None:
        address = ipaddress.ip_address(ip)
        for provider, network in CLOUD_RANGES:
            if address in network:
                return provider
        return None
```

At `max_workers=1`, every batch has exactly one host, so this produces
the exact same sequence of operations (wait → resolve → audit →
breaker call → scope check → provider match) in the exact same order as
the pre-Fase-H code.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_modules_cloud_range.py -v`
Expected: PASS (all tests).

- [ ] **Step 6: Run the full suite to check for regressions**

Run: `cd backend && pytest -v`
Expected: PASS (all tests).

- [ ] **Step 7: Commit**

```bash
git add backend/app/modules/cloud_range.py backend/tests/test_modules_cloud_range.py
git commit -m "feat(concurrency): batch cloud_range host resolution behind --max-workers"
```

---

### Task 5: `--max-workers` CLI flag and orchestrator plumbing

**Files:**
- Modify: `backend/app/orchestrator.py`
- Modify: `backend/app/cli.py`
- Test: `backend/tests/test_orchestrator.py`
- Test: `backend/tests/test_cli.py`

**Interfaces:**
- Consumes: nothing new from earlier tasks beyond `context["max_workers"]` being read by `tech_fingerprint`/`cloud_range` (Tasks 3-4) — this task is what actually populates that key from the CLI.
- Produces: `run_scan(scan_id, progress_callback=None, rate_limit=5.0, circuit_breaker_threshold=5, max_workers=1) -> None` (new `max_workers` keyword parameter, default `1`); `recon scan --max-workers <int>` CLI flag.

- [ ] **Step 1: Write the failing orchestrator tests**

`backend/tests/test_orchestrator.py` already has two tests
(`test_run_scan_threads_rate_limit_and_circuit_breaker_threshold_into_context`
and `test_run_scan_uses_default_rate_limit_and_threshold_when_not_specified`)
that register a spy `ReconModule` subclass capturing `context` into a
`seen_context` dict, run the scan via `_mock_all_modules(exclude={...})`
(a helper already defined at the top of this file that stubs every
other registered module's `.run` to return `[]`), then assert on
`seen_context`, always cleaning up via `del MODULE_REGISTRY[...]` in a
`finally` block. Add two more tests immediately after them, in the same
style:

```python
def test_run_scan_threads_max_workers_into_context():
    seen_context = {}

    class _MaxWorkersCapturingModule(ReconModule):
        name = "_test_max_workers_capturing_module"
        run_order = 20

        def run(self, target, context):
            seen_context["max_workers"] = context.get("max_workers")
            return []

    scan_id = _create_authorized_project_and_scan()
    try:
        register_module(_MaxWorkersCapturingModule)
        with _mock_all_modules(exclude={_MaxWorkersCapturingModule.name}):
            run_scan(scan_id, max_workers=7)
    finally:
        del MODULE_REGISTRY[_MaxWorkersCapturingModule.name]

    assert seen_context == {"max_workers": 7}


def test_run_scan_uses_default_max_workers_when_not_specified():
    seen_context = {}

    class _DefaultMaxWorkersCapturingModule(ReconModule):
        name = "_test_default_max_workers_capturing_module"
        run_order = 20

        def run(self, target, context):
            seen_context["max_workers"] = context.get("max_workers")
            return []

    scan_id = _create_authorized_project_and_scan()
    try:
        register_module(_DefaultMaxWorkersCapturingModule)
        with _mock_all_modules(exclude={_DefaultMaxWorkersCapturingModule.name}):
            run_scan(scan_id)
    finally:
        del MODULE_REGISTRY[_DefaultMaxWorkersCapturingModule.name]

    assert seen_context == {"max_workers": 1}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest tests/test_orchestrator.py -v -k max_workers`
Expected: FAIL — `run_scan()` doesn't accept a `max_workers` parameter
yet (`TypeError: run_scan() got an unexpected keyword argument`).

- [ ] **Step 3: Add `max_workers` to `orchestrator.py`**

In `backend/app/orchestrator.py`, add the constant next to the existing
two:

```python
DEFAULT_RATE_LIMIT = 5.0
DEFAULT_CIRCUIT_BREAKER_THRESHOLD = 5
DEFAULT_MAX_WORKERS = 1
```

Add the parameter to `run_scan`'s signature, right after
`circuit_breaker_threshold`:

```python
def run_scan(
    scan_id: int,
    progress_callback: Callable[[str], None] | None = None,
    rate_limit: float = DEFAULT_RATE_LIMIT,
    circuit_breaker_threshold: int = DEFAULT_CIRCUIT_BREAKER_THRESHOLD,
    max_workers: int = DEFAULT_MAX_WORKERS,
) -> None:
```

And add the key to the `context` dict literal (next to the existing
`"circuit_breaker_threshold": circuit_breaker_threshold,` line):

```python
        context: dict = {
            "subdomains": set(),
            "technologies": [],
            "cve_findings": [],
            "rate_limit": rate_limit,
            "circuit_breaker_threshold": circuit_breaker_threshold,
            "max_workers": max_workers,
            "scope": scan.project.scope or {},
            "audit": AuditLog(),
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest tests/test_orchestrator.py -v -k max_workers`
Expected: PASS.

- [ ] **Step 5: Write the failing CLI tests**

Append to `backend/tests/test_cli.py`, right after the existing
`test_scan_forwards_custom_rate_limit_and_circuit_breaker_threshold`
(reusing this file's `runner`/`app`/`patch` imports already in scope):

```python
def test_scan_defaults_max_workers_to_one():
    with patch("app.cli.run_scan") as mock_run_scan:
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
    assert mock_run_scan.call_args.kwargs["max_workers"] == 1


def test_scan_forwards_custom_max_workers():
    with patch("app.cli.run_scan") as mock_run_scan:
        result = runner.invoke(
            app,
            [
                "scan",
                "example.com",
                "--scope",
                "authorized test scope",
                "--authorized",
                "--confirm-active",
                "--max-workers",
                "8",
            ],
        )

    assert result.exit_code == 0, result.output
    assert mock_run_scan.call_args.kwargs["max_workers"] == 8
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_cli.py -v -k max_workers`
Expected: FAIL — `--max-workers` isn't a registered option yet (Typer
usage error / unexpected keyword argument on the `run_scan` call).

- [ ] **Step 7: Add the `--max-workers` option to `cli.py`**

In `backend/app/cli.py`, add the new `typer.Option` to the `scan`
function's parameter list, right after `circuit_breaker_threshold`:

```python
    circuit_breaker_threshold: int = typer.Option(
        5,
        "--circuit-breaker-threshold",
        help="Consecutive failures against a target before a module stops probing it",
    ),
    max_workers: int = typer.Option(
        1,
        "--max-workers",
        help="Process up to this many hosts concurrently within tech_fingerprint/cloud_range (default: fully sequential)",
    ),
```

And add `max_workers=max_workers` to the existing `run_scan(...)` call:

```python
    run_scan(
        scan_id,
        progress_callback=on_progress,
        rate_limit=max_requests_per_second,
        circuit_breaker_threshold=circuit_breaker_threshold,
        max_workers=max_workers,
    )
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_cli.py -v -k max_workers`
Expected: PASS (2 tests).

- [ ] **Step 9: Run the full suite to check for regressions**

Run: `cd backend && pytest -v`
Expected: PASS (all tests).

- [ ] **Step 10: Commit**

```bash
git add backend/app/orchestrator.py backend/app/cli.py backend/tests/test_orchestrator.py backend/tests/test_cli.py
git commit -m "feat(cli): add --max-workers flag, thread through orchestrator context"
```

---

### Task 6: Documentation

**Files:**
- Modify: `README.md`
- Modify: `README.pt-BR.md`

- [ ] **Step 1: Document the flag in `README.md`**

In the `### Run a scan` section's flag table (the one listing
`--max-requests-per-second`, `--circuit-breaker-threshold`, etc.), add a
new row right after `--circuit-breaker-threshold`:

```markdown
| `--max-workers` | no | Process up to this many hosts concurrently within `tech_fingerprint`/`cloud_range` (default `1` — fully sequential, identical to every scan before this flag existed) |
```

Immediately after that table (before the "Modules that probe a host
check the declared scope first..." paragraph that already follows it),
add:

```markdown
`--max-workers` only affects `tech_fingerprint` and `cloud_range` — the
two modules with a Python-level per-host loop. `httpx_probe` already
parallelizes internally via the external `httpx` binary's own
`-rate-limit`; `cve_correlation` is bound by the NVD API's own request
cap regardless of local parallelism, so it stays sequential. Raising
`--max-workers` does not raise `--max-requests-per-second` — it lets
that many in-flight requests share the same paced budget instead of one
request fully finishing before the next can start, so it shortens
wall-clock time on large scopes without sending more requests per
second. At the default of `1`, results (finding order, which host a
circuit-breaker trip fires on, the `skipped_hosts` count) are
byte-for-byte identical to before this flag existed. At `--max-workers`
above `1`, that bookkeeping still stays fully deterministic — only
`recon audit`'s entry order for hosts processed in the same batch can
vary between runs, never its content.
```

- [ ] **Step 2: Mirror the addition in `README.pt-BR.md`**

Find the equivalent flag table and paragraph location in
`README.pt-BR.md` (same relative position, following the existing
Portuguese translations of the surrounding rows/paragraphs) and add:

```markdown
| `--max-workers` | não | Processa até essa quantidade de hosts em paralelo dentro de `tech_fingerprint`/`cloud_range` (padrão `1` — totalmente sequencial, idêntico a qualquer scan anterior a essa flag existir) |
```

```markdown
`--max-workers` só afeta `tech_fingerprint` e `cloud_range` — os dois
módulos com um loop por host em Python. O `httpx_probe` já paraleliza
internamente via o próprio `-rate-limit` do binário externo `httpx`; o
`cve_correlation` é limitado pelo próprio teto de requisições da API da
NVD, independente de paralelismo local, então continua sequencial.
Aumentar `--max-workers` não aumenta `--max-requests-per-second` — só
permite que essa quantidade de requisições em voo compartilhe o mesmo
orçamento de ritmo, em vez de uma requisição terminar completamente
antes da próxima começar, encurtando o tempo de parede em escopos
grandes sem enviar mais requisições por segundo. No padrão `1`, os
resultados (ordem dos achados, qual host dispara um trip do circuit
breaker, a contagem de `skipped_hosts`) são idênticos byte a byte a
antes dessa flag existir. Com `--max-workers` acima de `1`, essa
contabilidade continua totalmente determinística — só a ordem das
entradas do `recon audit` para hosts processados no mesmo lote pode
variar entre execuções, nunca o conteúdo.
```

- [ ] **Step 3: Commit**

```bash
git add README.md README.pt-BR.md
git commit -m "docs(readme): document --max-workers and its concurrency semantics"
```

---

## Manual validation (recommended before considering Fase H done)

No new network behavior or external dataset is introduced by this phase
(unlike Fase G), so a live scan isn't strictly required to validate
correctness — but a real-world sanity check is still worth it before
calling the phase done:

1. Run the existing manual-validation target once with
   `--max-workers 1` and once with `--max-workers 4` (same target, same
   scope, same authorization already established in prior phases' manual
   validation).
2. Compare wall-clock time between the two runs — `--max-workers 4`
   should complete `tech_fingerprint`/`cloud_range` measurably faster
   on a target with several subdomains.
3. Compare the detected-technology/cloud-asset finding sets between the
   two runs — they should match (same hosts, same technologies), since
   this phase's global constraint is "identical results, different
   wall-clock time," not "different coverage."
