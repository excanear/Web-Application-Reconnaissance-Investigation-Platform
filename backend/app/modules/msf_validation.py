# backend/app/modules/msf_validation.py
import re
import subprocess

from app import i18n
from app.audit import AuditLog
from app.modules.base import Finding, register_module
from app.modules.cve_validator_base import ActiveCveValidatorModule

SEARCH_TIMEOUT = 60
CHECK_TIMEOUT = 120

# msfconsole's `search` table has had a stable column layout for years:
# "   #  Full Name  Disclosure Date  Rank  Check  Name" -- module ref
# names never contain whitespace, so the second whitespace-separated
# token of the first numbered data row is always the top-ranked match.
# Verified against a real msfconsole 6.5.3 `search cve:2021-44228`.
_SEARCH_ROW_RE = re.compile(r"^\s*(\d+)\s+(\S+)", re.MULTILINE)

# msfconsole colorizes every [+]/[-]/[*] line with raw ANSI SGR escapes
# even when stdout isn't a tty (verified live: piping to a file still
# produced e.g. "\x1b[1m\x1b[34m[*]\x1b[0m ..." for a status line) -- the
# prefix is never the first literal character on the line, so it must be
# stripped before any "^\[...\]" match is attempted.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Msf::Exploit::CheckCode (lib/msf/core/exploit.rb) only ever prints
# print_good ("[+]") for the Vulnerable and Appears codes -- every other
# code (Safe/"not exploitable", Unknown/"cannot reliably check",
# Detected, Unsupported) goes through print_status ("[*]"), confirmed
# live against Metasploit 6.5.3. There is no "[-] ... not vulnerable"
# message to scrape -- "[-]" is reserved for genuine check failures
# (exceptions), which this module intentionally does not try to
# distinguish from an ordinary negative/inconclusive result.
_VULNERABLE_RE = re.compile(r"^\[\+\]\s*(.*vulnerable.*)$", re.IGNORECASE | re.MULTILINE)


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


@register_module
class MsfValidationModule(ActiveCveValidatorModule):
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

    def _validate(self, cve_id: str, host: str, context: dict) -> tuple[Finding | None, bool]:
        audit: AuditLog | None = context.get("audit")
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

        match = _SEARCH_ROW_RE.search(_strip_ansi(result.stdout))
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

        clean_stdout = _strip_ansi(result.stdout)
        vulnerable_match = _VULNERABLE_RE.search(clean_stdout)
        if vulnerable_match:
            if audit is not None:
                audit.record(module=self.name, target=target_label, outcome="confirmed", url=None)
            data = {
                "host": host,
                "status": "confirmed",
                "tool": "metasploit",
                "msf_module": module_path,
                "msf_check_message": vulnerable_match.group(1).strip(),
                "msf_confirmation_note_en": i18n.t(
                    "cve_confirmed_note_msf", lang="en", module=module_path
                ),
                "msf_confirmation_note_pt": i18n.t(
                    "cve_confirmed_note_msf", lang="pt", module=module_path
                ),
            }
            return Finding(type="cve_validation", value=cve_id, data=data), True

        if audit is not None:
            audit.record(module=self.name, target=target_label, outcome="not_vulnerable", url=None)
        return None, True
