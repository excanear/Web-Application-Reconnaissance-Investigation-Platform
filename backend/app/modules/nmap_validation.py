# backend/app/modules/nmap_validation.py
import re
import subprocess

from app import i18n
from app.audit import AuditLog
from app.modules.base import Finding, register_module
from app.modules.cve_validator_base import ActiveCveValidatorModule

SCAN_TIMEOUT = 120

# Curated, deliberately small: only nmap's own built-in NSE scripts
# whose `categories` table (verified against nmap 7.98's vendored
# scripts) includes "safe" and excludes "intrusive"/"exploit" -- the
# same safety bar nuclei_validation already holds via its
# dos/fuzz/intrusive tag exclusion. nmap ships dozens of other
# CVE-named vuln scripts (Struts2, Drupal, PHP-CGI, Rails RCE, ...) that
# are legitimately tagged "intrusive"/"exploit" because a positive
# result requires actually triggering the bug -- those are excluded
# here on purpose, not an oversight. Every entry's port is hard-coded
# to what that specific script needs; unlike msf_validation, we set
# this correctly per CVE instead of always guessing 443, since these
# are individually curated rather than dynamically discovered.
CVE_TO_NMAP_SCRIPT: dict[str, dict] = {
    "CVE-2014-0160": {"script": "ssl-heartbleed", "port": 443},
    "CVE-2014-3566": {"script": "ssl-poodle", "port": 443},
    "CVE-2017-1001000": {"script": "http-vuln-cve2017-1001000", "port": 443},
    "CVE-2015-1635": {"script": "http-vuln-cve2015-1635", "port": 443},
    "CVE-2011-3192": {"script": "http-vuln-cve2011-3192", "port": 443},
    "CVE-2014-2126": {"script": "http-vuln-cve2014-2126", "port": 443},
    "CVE-2014-2127": {"script": "http-vuln-cve2014-2127", "port": 443},
    "CVE-2014-2128": {"script": "http-vuln-cve2014-2128", "port": 443},
    "CVE-2014-2129": {"script": "http-vuln-cve2014-2129", "port": 443},
}

# Every nmap "vuln"-category script prints through the shared vulns.lua
# report library, which -- verified live against nmap 7.98 with
# --script-args vulns.showall -- always emits an explicit
# "State: VULNERABLE" or "State: NOT VULNERABLE" line per script,
# instead of staying silent on a negative result. Without vulns.showall
# a negative result prints nothing at all for most scripts, which is
# indistinguishable from "script didn't run" -- showall is what makes
# a clean, positive "checked and safe" signal possible here.
_STATE_RE = re.compile(r"State:\s*(NOT VULNERABLE|VULNERABLE)", re.IGNORECASE)


@register_module
class NmapValidationModule(ActiveCveValidatorModule):
    """Third active CVE-confirmation engine: runs nmap's own built-in
    NSE vulnerability script for a curated set of well-known CVEs
    (see CVE_TO_NMAP_SCRIPT) against the host. Covers protocol/TLS-level
    checks nuclei and msf_validation don't reach well. A CVE with no
    curated script is skipped without attempting anything (not a
    failure -- there's simply no check to run), same posture as
    msf_validation's "no_module" outcome."""

    name = "nmap_validation"
    run_order = 97  # after nuclei_validation (95) and msf_validation (96)

    def _validate(self, cve_id: str, host: str, context: dict) -> tuple[Finding | None, bool]:
        audit: AuditLog | None = context.get("audit")
        target_label = f"{cve_id}@{host}"

        check = CVE_TO_NMAP_SCRIPT.get(cve_id)
        if check is None:
            if audit is not None:
                audit.record(module=self.name, target=target_label, outcome="no_script", url=None)
            return None, True

        command = [
            "nmap",
            "-Pn", "-sT",
            "-p", str(check["port"]),
            "--script", check["script"],
            "--script-args", "vulns.showall",
            host,
        ]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=SCAN_TIMEOUT, check=False,
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

        if result.returncode != 0:
            if audit is not None:
                audit.record(
                    module=self.name,
                    target=target_label,
                    outcome=f"error: nmap exited {result.returncode}",
                    url=None,
                )
            return None, False

        # Exactly one script runs per invocation here (--script takes a
        # single name), so any "State:" line found in stdout belongs to
        # it -- no need to isolate a per-script block first.
        state_match = _STATE_RE.search(result.stdout)
        if state_match is None:
            # The script never produced a state line at all -- e.g. the
            # port wasn't actually reachable, or a precondition (like
            # "must be WordPress") wasn't met. Nothing to confirm, but
            # nmap itself ran fine, so this isn't a circuit-breaker
            # failure.
            if audit is not None:
                audit.record(module=self.name, target=target_label, outcome="no_result", url=None)
            return None, True

        if state_match.group(1).upper() != "VULNERABLE":
            if audit is not None:
                audit.record(module=self.name, target=target_label, outcome="not_vulnerable", url=None)
            return None, True

        if audit is not None:
            audit.record(module=self.name, target=target_label, outcome="confirmed", url=None)

        data = {
            "host": host,
            "status": "confirmed",
            "tool": "nmap",
            "nmap_script": check["script"],
            "nmap_confirmation_note_en": i18n.t(
                "cve_confirmed_note_nmap", lang="en", script=check["script"]
            ),
            "nmap_confirmation_note_pt": i18n.t(
                "cve_confirmed_note_nmap", lang="pt", script=check["script"]
            ),
        }
        return Finding(type="cve_validation", value=cve_id, data=data), True
