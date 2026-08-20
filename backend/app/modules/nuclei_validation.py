# backend/app/modules/nuclei_validation.py
import json
import subprocess

from app import i18n
from app.audit import AuditLog
from app.modules.base import Finding, ReconModule, register_module
from app.ratelimit import CircuitBreaker
from app.scope import is_in_scope

DEFAULT_RATE_LIMIT = 5.0
DEFAULT_CIRCUIT_BREAKER_THRESHOLD = 5
# Hard-coded, never operator-configurable: dos/fuzz/intrusive-tagged
# templates are excluded from every invocation regardless of settings --
# this is a permanent safety boundary, the same tier as
# --authorized/--confirm-active, not a tunable rate limit.
EXCLUDED_TAGS = "dos,fuzz,intrusive"
REQUEST_TIMEOUT = 120


@register_module
class NucleiValidationModule(ReconModule):
    name = "nuclei_validation"
    run_order = 95
    is_active = True

    def run(self, target: str, context: dict) -> list[Finding]:
        cve_findings = context.get("cve_findings", [])
        scope = context.get("scope")
        audit = context.get("audit")
        rate_limit = context.get("rate_limit", DEFAULT_RATE_LIMIT)
        breaker = CircuitBreaker(
            context.get("circuit_breaker_threshold", DEFAULT_CIRCUIT_BREAKER_THRESHOLD)
        )
        findings: list[Finding] = []

        for index, entry in enumerate(cve_findings):
            cve_id = entry.get("cve_id")
            host = entry.get("host")
            if not cve_id or not host:
                continue

            if scope is not None and not is_in_scope(host, None, scope):
                findings.append(
                    Finding(type="out_of_scope", value=host, data={"module": self.name})
                )
                continue

            finding, succeeded = self._validate(cve_id, host, rate_limit, audit)
            if finding is not None:
                findings.append(finding)

            if succeeded:
                breaker.record_success()
            elif breaker.record_failure():
                findings.append(
                    Finding(
                        type="circuit_breaker_tripped",
                        value=target,
                        data={"module": self.name, "skipped_checks": len(cve_findings) - index - 1},
                    )
                )
                break

        return findings

    def _validate(
        self, cve_id: str, host: str, rate_limit: float, audit: AuditLog | None
    ) -> tuple[Finding | None, bool]:
        url = f"https://{host}/"
        target_label = f"{cve_id}@{host}"
        command = [
            "nuclei",
            "-u", url,
            "-id", cve_id,
            "-etags", EXCLUDED_TAGS,
            "-jsonl",
            "-silent",
            "-rate-limit", str(max(1, round(rate_limit))),
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=REQUEST_TIMEOUT,
                check=False,
            )
        except OSError as exc:
            # nuclei never even launched (e.g. the binary isn't installed) --
            # distinguish "never attempted" from "attempted and failed" so
            # the audit trail doesn't imply a request was made when none was.
            if audit is not None:
                audit.record(module=self.name, target=target_label, outcome=f"not_attempted: {exc}", url=url)
            raise
        except subprocess.TimeoutExpired as exc:
            if audit is not None:
                audit.record(module=self.name, target=target_label, outcome=f"error: {exc}", url=url)
            return None, False

        matches = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]

        if result.returncode != 0 and not matches:
            if audit is not None:
                audit.record(
                    module=self.name,
                    target=target_label,
                    outcome=f"error: nuclei exited {result.returncode}",
                    url=url,
                )
            return None, False

        if not matches:
            if audit is not None:
                audit.record(module=self.name, target=target_label, outcome="no_match", url=url)
            return None, True

        match = matches[0]
        template_id = match.get("template-id", cve_id)
        matched_at = match.get("matched-at", url)

        if audit is not None:
            audit.record(module=self.name, target=target_label, outcome="confirmed", url=url)

        return (
            Finding(
                type="cve_validation",
                value=cve_id,
                data={
                    "host": host,
                    "status": "confirmed",
                    "nuclei_template_id": template_id,
                    "matched_at": matched_at,
                    "confirmation_note_en": i18n.t(
                        "cve_confirmed_note", lang="en", template_id=template_id, matched_at=matched_at
                    ),
                    "confirmation_note_pt": i18n.t(
                        "cve_confirmed_note", lang="pt", template_id=template_id, matched_at=matched_at
                    ),
                },
            ),
            True,
        )
