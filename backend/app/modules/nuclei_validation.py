# backend/app/modules/nuclei_validation.py
import json
import subprocess

from app import i18n
from app.audit import AuditLog
from app.modules.base import Finding, register_module
from app.modules.cve_validator_base import ActiveCveValidatorModule

DEFAULT_RATE_LIMIT = 5.0
# Hard-coded, never operator-configurable: dos/fuzz/intrusive-tagged
# templates are excluded from every invocation regardless of settings --
# this is a permanent safety boundary, the same tier as
# --authorized/--confirm-active, not a tunable rate limit.
EXCLUDED_TAGS = "dos,fuzz,intrusive"
REQUEST_TIMEOUT = 120
# nuclei's own message (stderr, exit code 1) when `-id <cve>` matches no
# template in the community library -- verified live: most CVEs never
# get a nuclei template written for them (nuclei skews toward
# HTTP-detectable web-app vulns, not e.g. memory-safety bugs), so this
# is the routine, expected outcome for a large fraction of CVEs, not a
# tool failure. It must never count against the circuit breaker.
NO_TEMPLATE_MARKER = "no templates provided for scan"


@register_module
class NucleiValidationModule(ActiveCveValidatorModule):
    name = "nuclei_validation"
    run_order = 95

    def _validate(self, cve_id: str, host: str, context: dict) -> tuple[Finding | None, bool]:
        audit: AuditLog | None = context.get("audit")
        rate_limit = context.get("rate_limit", DEFAULT_RATE_LIMIT)

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

        try:
            matches = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        except json.JSONDecodeError as exc:
            # nuclei ran but emitted something we can't parse as its JSONL
            # output (e.g. a stray warning line slipping past -silent) --
            # this is a check failure, not a "binary missing" case, so it's
            # audited and counted against the circuit breaker rather than
            # raised.
            if audit is not None:
                audit.record(module=self.name, target=target_label, outcome=f"error: {exc}", url=url)
            return None, False

        if result.returncode != 0 and not matches:
            if NO_TEMPLATE_MARKER in result.stderr:
                if audit is not None:
                    audit.record(module=self.name, target=target_label, outcome="no_template", url=url)
                return None, True
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

        data = {
            "host": host,
            "status": "confirmed",
            "tool": "nuclei",
            "nuclei_template_id": template_id,
            "matched_at": matched_at,
            "confirmation_note_en": i18n.t(
                "cve_confirmed_note", lang="en", template_id=template_id, matched_at=matched_at
            ),
            "confirmation_note_pt": i18n.t(
                "cve_confirmed_note", lang="pt", template_id=template_id, matched_at=matched_at
            ),
        }
        remediation = match.get("info", {}).get("remediation")
        if remediation:
            data["remediation_en"] = remediation.strip()

        return Finding(type="cve_validation", value=cve_id, data=data), True
