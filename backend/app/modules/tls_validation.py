# backend/app/modules/tls_validation.py
import json
import os
import subprocess
import tempfile

from app import i18n
from app.audit import AuditLog
from app.modules.base import Finding, register_module
from app.modules.cve_validator_base import ActiveCveValidatorModule

SCAN_TIMEOUT = 180

# Curated from testssl.sh's own source (each check function's
# `jsonID`/`cve` locals, verified against a live clone of
# github.com/drwetter/testssl.sh) -- the well-known, famous TLS/SSL
# CVEs that each have a single dedicated CLI flag for a fast, targeted
# check instead of the full -U/--vulnerable sweep. A few multi-CVE
# checks (DROWN, SWEET32) map more than one CVE ID to the same flag/id.
CVE_TO_TESTSSL_CHECK: dict[str, dict] = {
    "CVE-2014-0160": {"flag": "--heartbleed", "id": "heartbleed"},
    "CVE-2014-0224": {"flag": "--ccs-injection", "id": "CCS"},
    "CVE-2012-4929": {"flag": "--compression", "id": "CRIME_TLS"},
    "CVE-2013-3587": {"flag": "--breach", "id": "BREACH"},
    "CVE-2016-2183": {"flag": "--sweet32", "id": "SWEET32"},
    "CVE-2016-6329": {"flag": "--sweet32", "id": "SWEET32"},
    "CVE-2014-3566": {"flag": "--poodle", "id": "POODLE_SSL"},
    "CVE-2015-0204": {"flag": "--freak", "id": "FREAK"},
    "CVE-2015-4000": {"flag": "--logjam", "id": "LOGJAM"},
    "CVE-2016-0800": {"flag": "--drown", "id": "DROWN"},
    "CVE-2016-0703": {"flag": "--drown", "id": "DROWN"},
    "CVE-2011-3389": {"flag": "--beast", "id": "BEAST"},
}


@register_module
class TlsValidationModule(ActiveCveValidatorModule):
    """Fourth active CVE-confirmation engine: runs testssl.sh for a
    curated set of well-known TLS/SSL CVEs (Heartbleed, POODLE, DROWN,
    FREAK, LOGJAM, CRIME, BREACH, SWEET32, BEAST, CCS injection) against
    the host's HTTPS port. This is a category none of nuclei/msf/nmap
    validation cover -- protocol-level TLS weaknesses rather than an
    HTTP application bug or a network-service exploit. A CVE with no
    curated check is skipped without attempting anything (not a
    failure), same posture as msf_validation's "no_module" outcome."""

    name = "tls_validation"
    run_order = 98  # after nuclei/msf/nmap validation (95/96/97)

    def _validate(self, cve_id: str, host: str, context: dict) -> tuple[Finding | None, bool]:
        audit: AuditLog | None = context.get("audit")
        target_label = f"{cve_id}@{host}"

        check = CVE_TO_TESTSSL_CHECK.get(cve_id)
        if check is None:
            if audit is not None:
                audit.record(module=self.name, target=target_label, outcome="no_check", url=None)
            return None, True

        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = os.path.join(tmpdir, "testssl.json")
            command = [
                "testssl.sh",
                check["flag"],
                "--jsonfile", json_path,
                "--quiet",
                host,
            ]
            try:
                subprocess.run(
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

            try:
                with open(json_path, encoding="utf-8") as f:
                    entries = json.load(f)
            except (OSError, json.JSONDecodeError) as exc:
                # testssl.sh writes its own JSON file rather than
                # printing it to stdout -- if the process died before
                # ever producing a valid file (crash, killed), that's a
                # genuine execution failure, not a benign non-match.
                if audit is not None:
                    audit.record(module=self.name, target=target_label, outcome=f"error: {exc}", url=None)
                return None, False

        fatal = next((e for e in entries if e.get("severity") == "FATAL"), None)
        if fatal is not None:
            if audit is not None:
                audit.record(
                    module=self.name, target=target_label,
                    outcome=f"error: {fatal.get('finding', 'scan failed')}", url=None,
                )
            return None, False

        entry = next((e for e in entries if e.get("id") == check["id"]), None)
        if entry is None:
            # testssl ran and produced a normal JSON report, but this
            # specific check's entry never appeared -- e.g. the port
            # never established a TLS session at all. Nothing to
            # confirm, but not a tool crash either.
            if audit is not None:
                audit.record(module=self.name, target=target_label, outcome="no_result", url=None)
            return None, True

        # testssl.sh's own convention (verified in its source across
        # every vuln-check function): the `finding` text is "VULNERABLE"
        # (uppercase) for a positive result and "not vulnerable"
        # (lowercase) otherwise -- always this exact casing distinction.
        finding_text = entry.get("finding", "")
        if "VULNERABLE" not in finding_text:
            if audit is not None:
                audit.record(module=self.name, target=target_label, outcome="not_vulnerable", url=None)
            return None, True

        if audit is not None:
            audit.record(module=self.name, target=target_label, outcome="confirmed", url=None)

        data = {
            "host": host,
            "status": "confirmed",
            "tool": "testssl",
            "testssl_check": check["id"],
            "tls_confirmation_note_en": i18n.t(
                "cve_confirmed_note_tls", lang="en", check=check["id"]
            ),
            "tls_confirmation_note_pt": i18n.t(
                "cve_confirmed_note_tls", lang="pt", check=check["id"]
            ),
        }
        return Finding(type="cve_validation", value=cve_id, data=data), True
