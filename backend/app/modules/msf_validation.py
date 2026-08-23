# backend/app/modules/msf_validation.py
import re
import subprocess

from app import i18n
from app.audit import AuditLog
from app.modules.base import Finding, ReconModule, register_module
from app.ratelimit import CircuitBreaker
from app.scope import is_in_scope

DEFAULT_RATE_LIMIT = 5.0
DEFAULT_CIRCUIT_BREAKER_THRESHOLD = 5
SEARCH_TIMEOUT = 60
CHECK_TIMEOUT = 120

# msfconsole's `search` table has had a stable column layout for years:
# "   #  Name  Disclosure Date  Rank  Check  Description" -- module ref
# names never contain whitespace, so the second whitespace-separated
# token of the first numbered data row is always the top-ranked match.
_SEARCH_ROW_RE = re.compile(r"^\s*(\d+)\s+(\S+)", re.MULTILINE)

# Msf::Exploit::CheckCode's own report_check_result() has printed these
# exact "[+]/[-]/[*] ... - <message>" prefixes for over a decade -- this
# is the documented, stable contract msfconsole automation scrapes, not
# an internal implementation detail liable to change release to release.
_VULNERABLE_RE = re.compile(r"^\[\+\].*is vulnerable", re.IGNORECASE | re.MULTILINE)
_NOT_VULNERABLE_RE = re.compile(
    r"^\[-\].*(is not vulnerable|not exploitable|appears to be safe)", re.IGNORECASE | re.MULTILINE
)


@register_module
class MsfValidationModule(ReconModule):
    """Second active CVE-confirmation engine alongside nuclei_validation:
    finds a Metasploit module for a CVE via `search cve:<id>` and runs
    its non-destructive `check` action against the host. Only confirms
    CVEs whose matched module exposes an HTTP(S) service on port 443 --
    this tool only ever established host/scheme context for web assets,
    so RHOSTS/RPORT/SSL are set accordingly and modules targeting other
    services will simply report "could not validate" rather than a false
    confirmation."""

    name = "msf_validation"
    run_order = 96  # after nuclei_validation (95): independent, additive confirmation
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

            finding, succeeded = self._validate(cve_id, host, audit)
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

    def _validate(self, cve_id: str, host: str, audit: AuditLog | None) -> tuple[Finding | None, bool]:
        target_label = f"{cve_id}@{host}"

        module_path, succeeded = self._find_module(cve_id, host, audit)
        if not succeeded:
            return None, False
        if module_path is None:
            if audit is not None:
                audit.record(module=self.name, target=target_label, outcome="no_module", url=None)
            return None, True

        return self._check_module(cve_id, host, module_path, audit)

    def _find_module(
        self, cve_id: str, host: str, audit: AuditLog | None
    ) -> tuple[str | None, bool]:
        target_label = f"{cve_id}@{host}"
        numeric_id = cve_id.removeprefix("CVE-")
        command = [
            "msfconsole", "-q", "-x", f"search cve:{numeric_id}; exit",
        ]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=SEARCH_TIMEOUT, check=False,
            )
        except OSError as exc:
            if audit is not None:
                audit.record(
                    module=self.name, target=target_label, outcome=f"not_attempted: {exc}", url=None
                )
            raise
        except subprocess.TimeoutExpired as exc:
            if audit is not None:
                audit.record(module=self.name, target=target_label, outcome=f"error: {exc}", url=None)
            return None, False

        match = _SEARCH_ROW_RE.search(result.stdout)
        if match is None:
            return None, True
        return match.group(2), True

    def _check_module(
        self, cve_id: str, host: str, module_path: str, audit: AuditLog | None
    ) -> tuple[Finding | None, bool]:
        target_label = f"{cve_id}@{host}"
        script = (
            f"use {module_path}; "
            f"set RHOSTS {host}; set RPORT 443; set SSL true; "
            "check; exit"
        )
        command = ["msfconsole", "-q", "-x", script]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=CHECK_TIMEOUT, check=False,
            )
        except OSError as exc:
            if audit is not None:
                audit.record(
                    module=self.name, target=target_label, outcome=f"not_attempted: {exc}", url=None
                )
            raise
        except subprocess.TimeoutExpired as exc:
            if audit is not None:
                audit.record(module=self.name, target=target_label, outcome=f"error: {exc}", url=None)
            return None, False

        if _VULNERABLE_RE.search(result.stdout):
            if audit is not None:
                audit.record(module=self.name, target=target_label, outcome="confirmed", url=None)
            data = {
                "host": host,
                "status": "confirmed",
                "tool": "metasploit",
                "msf_module": module_path,
                "msf_confirmation_note_en": i18n.t(
                    "cve_confirmed_note_msf", lang="en", module=module_path
                ),
                "msf_confirmation_note_pt": i18n.t(
                    "cve_confirmed_note_msf", lang="pt", module=module_path
                ),
            }
            return Finding(type="cve_validation", value=cve_id, data=data), True

        if _NOT_VULNERABLE_RE.search(result.stdout):
            if audit is not None:
                audit.record(module=self.name, target=target_label, outcome="not_vulnerable", url=None)
            return None, True

        if audit is not None:
            audit.record(module=self.name, target=target_label, outcome="inconclusive", url=None)
        return None, True
