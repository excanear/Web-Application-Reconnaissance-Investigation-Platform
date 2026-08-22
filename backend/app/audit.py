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
