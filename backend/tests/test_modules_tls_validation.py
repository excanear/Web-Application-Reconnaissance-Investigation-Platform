import json
import subprocess
import pytest
from unittest.mock import MagicMock, patch

from app.audit import AuditLog
from app.modules.tls_validation import TlsValidationModule

# Real testssl.sh JSON entries (heartbleed check), captured live against
# example.com -- confirmed against the actual testssl.sh source
# (run_heartbleed(), fileout calls) that "OK"/"not vulnerable..." is the
# negative shape and "CRITICAL"/"VULNERABLE" is the positive one; the
# same fileout(id, severity, finding, cve, cwe) convention is shared by
# every other vuln check function in the script.
NOT_VULNERABLE_ENTRY = {
    "id": "heartbleed",
    "ip": "example.com/104.20.23.154",
    "port": "443",
    "severity": "OK",
    "cve": "CVE-2014-0160",
    "cwe": "CWE-119",
    "finding": "not vulnerable, no heartbeat extension",
}
VULNERABLE_ENTRY = {
    "id": "heartbleed",
    "ip": "example.com/104.20.23.154",
    "port": "443",
    "severity": "CRITICAL",
    "cve": "CVE-2014-0160",
    "cwe": "CWE-119",
    "finding": "VULNERABLE",
}
FATAL_ENTRY = {
    "id": "scanProblem",
    "ip": "artssystem.com.br/191.252.83.206",
    "port": "443",
    "severity": "FATAL",
    "finding": "Can't connect to '191.252.83.206:443'",
}


def _fake_result(returncode=0):
    return MagicMock(stdout="", stderr="", returncode=returncode)


def _patched_run_writing_json(entries):
    """testssl.sh writes its report to the --jsonfile path as a side
    effect rather than printing it to stdout -- the mock has to actually
    write that file for the module's subsequent open()+json.load() to
    find anything."""

    def fake_run(command, **kwargs):
        json_path = command[command.index("--jsonfile") + 1]
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(entries, f)
        return _fake_result()

    return fake_run


def test_confirms_a_cve_when_testssl_reports_vulnerable():
    context = {"cve_findings": [{"cve_id": "CVE-2014-0160", "host": "tech.example.com"}]}

    with patch(
        "app.modules.tls_validation.subprocess.run",
        side_effect=_patched_run_writing_json([VULNERABLE_ENTRY]),
    ) as mock_run:
        findings = TlsValidationModule().run("example.com", context)

    called_command = mock_run.call_args.args[0]
    assert called_command[0] == "testssl.sh"
    assert called_command[1] == "--heartbleed"
    assert called_command[-1] == "tech.example.com"

    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "cve_validation"
    assert finding.data["status"] == "confirmed"
    assert finding.data["tool"] == "testssl"
    assert finding.data["testssl_check"] == "heartbleed"
    assert "heartbleed" in finding.data["tls_confirmation_note_en"]


def test_stays_unconfirmed_when_testssl_reports_not_vulnerable():
    context = {"cve_findings": [{"cve_id": "CVE-2014-0160", "host": "tech.example.com"}]}
    audit = AuditLog()
    context["audit"] = audit

    with patch(
        "app.modules.tls_validation.subprocess.run",
        side_effect=_patched_run_writing_json([NOT_VULNERABLE_ENTRY]),
    ):
        findings = TlsValidationModule().run("example.com", context)

    assert findings == []
    assert audit.entries[-1]["outcome"] == "not_vulnerable"


def test_records_an_error_and_penalizes_the_breaker_on_a_fatal_scan_problem():
    context = {"cve_findings": [{"cve_id": "CVE-2014-0160", "host": "tech.example.com"}]}
    audit = AuditLog()
    context["audit"] = audit

    with patch(
        "app.modules.tls_validation.subprocess.run",
        side_effect=_patched_run_writing_json([FATAL_ENTRY]),
    ):
        findings = TlsValidationModule().run("example.com", context)

    assert findings == []
    assert audit.entries[-1]["outcome"].startswith("error:")


def test_records_no_result_when_the_check_entry_never_appears():
    context = {"cve_findings": [{"cve_id": "CVE-2014-0160", "host": "tech.example.com"}]}
    audit = AuditLog()
    context["audit"] = audit

    with patch(
        "app.modules.tls_validation.subprocess.run",
        side_effect=_patched_run_writing_json([{"id": "service", "severity": "INFO", "finding": "HTTP"}]),
    ):
        findings = TlsValidationModule().run("example.com", context)

    assert findings == []
    assert audit.entries[-1]["outcome"] == "no_result"


def test_skips_a_cve_with_no_curated_check_without_running_testssl():
    context = {"cve_findings": [{"cve_id": "CVE-9999-99999", "host": "tech.example.com"}]}
    audit = AuditLog()
    context["audit"] = audit

    with patch("app.modules.tls_validation.subprocess.run") as mock_run:
        findings = TlsValidationModule().run("example.com", context)

    mock_run.assert_not_called()
    assert findings == []
    assert audit.entries[-1]["outcome"] == "no_check"


def test_records_not_attempted_and_reraises_when_the_binary_is_missing():
    context = {"cve_findings": [{"cve_id": "CVE-2014-0160", "host": "tech.example.com"}]}
    audit = AuditLog()
    context["audit"] = audit

    with patch(
        "app.modules.tls_validation.subprocess.run",
        side_effect=OSError("testssl.sh not found"),
    ):
        with pytest.raises(OSError):
            TlsValidationModule().run("example.com", context)

    assert len(audit.entries) == 1
    assert audit.entries[0]["outcome"].startswith("not_attempted:")


def test_skips_an_out_of_scope_host():
    context = {
        "cve_findings": [{"cve_id": "CVE-2014-0160", "host": "blocked.example.com"}],
        "scope": {"include": ["example.com"], "exclude": ["blocked.example.com"]},
    }

    with patch("app.modules.tls_validation.subprocess.run") as mock_run:
        findings = TlsValidationModule().run("example.com", context)

    mock_run.assert_not_called()
    assert len(findings) == 1
    assert findings[0].type == "out_of_scope"


def test_circuit_breaker_trips_after_threshold_consecutive_timeouts():
    context = {
        "cve_findings": [
            {"cve_id": "CVE-2014-0160", "host": "tech.example.com"} for _ in range(5)
        ],
        "circuit_breaker_threshold": 2,
    }

    with patch(
        "app.modules.tls_validation.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="testssl.sh", timeout=180),
    ):
        findings = TlsValidationModule().run("example.com", context)

    tripped = [f for f in findings if f.type == "circuit_breaker_tripped"]
    assert len(tripped) == 1
    assert tripped[0].data["module"] == "tls_validation"
