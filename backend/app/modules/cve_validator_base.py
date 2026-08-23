# backend/app/modules/cve_validator_base.py
from abc import abstractmethod

from app.modules.base import Finding, ReconModule
from app.ratelimit import CircuitBreaker
from app.scope import is_in_scope

DEFAULT_CIRCUIT_BREAKER_THRESHOLD = 5


class ActiveCveValidatorModule(ReconModule):
    """Shared skeleton for every module that actively confirms a
    `suspected` CVE (from cve_correlation) against a live host --
    nuclei_validation, msf_validation, nmap_validation, tls_validation
    all just implement _validate() for their own tool. Handles the
    per-CVE loop, scope filtering, and circuit breaker identically so
    that behavior (out_of_scope, circuit_breaker_tripped semantics,
    skipped_checks accounting) stays consistent across every validator
    instead of being re-copied and risking drift between them.

    Subclasses only implement _validate(cve_id, host, context) ->
    (Finding | None, succeeded). `succeeded` must be False ONLY for a
    genuine tool-execution failure (binary crashed, timed out, produced
    unparseable output) -- "the tool ran fine and found nothing to
    confirm" (no match, no template, no applicable check) is always
    (None, True). Conflating the two was a real bug found twice in this
    project already (nuclei_validation and msf_validation both had to
    be fixed for exactly this): a routine "nothing found" outcome must
    never count against the circuit breaker, or a run of ordinary
    non-matches can silently abort validation for the rest of the scan."""

    run_order = 95
    is_active = True

    def run(self, target: str, context: dict) -> list[Finding]:
        cve_findings = context.get("cve_findings", [])
        scope = context.get("scope")
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

            finding, succeeded = self._validate(cve_id, host, context)
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

    @abstractmethod
    def _validate(self, cve_id: str, host: str, context: dict) -> tuple[Finding | None, bool]:
        ...
