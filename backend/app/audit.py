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
