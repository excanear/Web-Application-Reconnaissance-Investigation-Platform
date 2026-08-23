import subprocess
import pytest
from unittest.mock import MagicMock, patch

from app.audit import AuditLog
from app.modules.msf_validation import MsfValidationModule


def _fake_result(stdout="", returncode=0):
    return MagicMock(stdout=stdout, returncode=returncode)


SEARCH_TABLE = """Matching Modules
================

   #  Name                                    Disclosure Date  Rank       Check  Description
   -  ----                                    ----------------  ----       -----  -----------
   0  exploit/multi/http/example_rce           2021-01-26        excellent  Yes    Example RCE
"""

VULNERABLE_CHECK = "[+] 10.0.0.1:443 - The target is vulnerable.\n"
NOT_VULNERABLE_CHECK = "[-] 10.0.0.1:443 - The target is not vulnerable.\n"
INCONCLUSIVE_CHECK = "[*] 10.0.0.1:443 - The service is running, but could not be validated.\n"


def test_confirms_a_cve_when_msf_check_reports_vulnerable():
    context = {"cve_findings": [{"cve_id": "CVE-2021-23017", "host": "tech.example.com"}]}

    with patch(
        "app.modules.msf_validation.subprocess.run",
        side_effect=[_fake_result(stdout=SEARCH_TABLE), _fake_result(stdout=VULNERABLE_CHECK)],
    ) as mock_run:
        findings = MsfValidationModule().run("example.com", context)

    search_call, check_call = mock_run.call_args_list
    assert search_call.args[0] == ["msfconsole", "-q", "-x", "search cve:2021-23017; exit"]
    assert check_call.args[0] == [
        "msfconsole", "-q", "-x",
        "use exploit/multi/http/example_rce; set RHOSTS tech.example.com; "
        "set RPORT 443; set SSL true; check; exit",
    ]

    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "cve_validation"
    assert finding.value == "CVE-2021-23017"
    assert finding.data["status"] == "confirmed"
    assert finding.data["tool"] == "metasploit"
    assert finding.data["host"] == "tech.example.com"
    assert finding.data["msf_module"] == "exploit/multi/http/example_rce"
    assert "exploit/multi/http/example_rce" in finding.data["msf_confirmation_note_en"]
    assert "Metasploit" in finding.data["msf_confirmation_note_pt"]


def test_stays_unconfirmed_when_msf_check_reports_not_vulnerable():
    context = {"cve_findings": [{"cve_id": "CVE-2021-23017", "host": "tech.example.com"}]}
    audit = AuditLog()
    context["audit"] = audit

    with patch(
        "app.modules.msf_validation.subprocess.run",
        side_effect=[_fake_result(stdout=SEARCH_TABLE), _fake_result(stdout=NOT_VULNERABLE_CHECK)],
    ):
        findings = MsfValidationModule().run("example.com", context)

    assert findings == []
    assert audit.entries[-1]["outcome"] == "not_vulnerable"


def test_stays_unconfirmed_and_records_inconclusive_when_check_cannot_decide():
    context = {"cve_findings": [{"cve_id": "CVE-2021-23017", "host": "tech.example.com"}]}
    audit = AuditLog()
    context["audit"] = audit

    with patch(
        "app.modules.msf_validation.subprocess.run",
        side_effect=[_fake_result(stdout=SEARCH_TABLE), _fake_result(stdout=INCONCLUSIVE_CHECK)],
    ):
        findings = MsfValidationModule().run("example.com", context)

    assert findings == []
    assert audit.entries[-1]["outcome"] == "inconclusive"


def test_no_finding_and_no_check_call_when_search_finds_no_module():
    context = {"cve_findings": [{"cve_id": "CVE-9999-00001", "host": "tech.example.com"}]}
    audit = AuditLog()
    context["audit"] = audit

    with patch(
        "app.modules.msf_validation.subprocess.run",
        return_value=_fake_result(stdout="Matching Modules\n================\n\n"),
    ) as mock_run:
        findings = MsfValidationModule().run("example.com", context)

    assert findings == []
    assert mock_run.call_count == 1  # search only, check never attempted
    assert audit.entries[-1]["outcome"] == "no_module"


def test_records_not_attempted_and_reraises_when_the_binary_is_missing():
    context = {"cve_findings": [{"cve_id": "CVE-2021-23017", "host": "tech.example.com"}]}
    audit = AuditLog()
    context["audit"] = audit

    with patch(
        "app.modules.msf_validation.subprocess.run",
        side_effect=OSError("msfconsole not found"),
    ):
        with pytest.raises(OSError):
            MsfValidationModule().run("example.com", context)

    assert len(audit.entries) == 1
    assert audit.entries[0]["outcome"].startswith("not_attempted:")


def test_skips_an_out_of_scope_host():
    context = {
        "cve_findings": [{"cve_id": "CVE-2021-23017", "host": "blocked.example.com"}],
        "scope": {"include": ["example.com"], "exclude": ["blocked.example.com"]},
    }

    with patch("app.modules.msf_validation.subprocess.run") as mock_run:
        findings = MsfValidationModule().run("example.com", context)

    mock_run.assert_not_called()
    assert len(findings) == 1
    assert findings[0].type == "out_of_scope"
    assert findings[0].value == "blocked.example.com"


def test_circuit_breaker_trips_after_threshold_consecutive_search_timeouts():
    context = {
        "cve_findings": [
            {"cve_id": f"CVE-2021-{i}", "host": "tech.example.com"} for i in range(5)
        ],
        "circuit_breaker_threshold": 2,
    }

    with patch(
        "app.modules.msf_validation.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="msfconsole", timeout=60),
    ):
        findings = MsfValidationModule().run("example.com", context)

    tripped = [f for f in findings if f.type == "circuit_breaker_tripped"]
    assert len(tripped) == 1
    assert tripped[0].data["module"] == "msf_validation"
    assert tripped[0].data["skipped_checks"] == 3
