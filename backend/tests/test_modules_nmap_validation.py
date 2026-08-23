import subprocess
import pytest
from unittest.mock import MagicMock, patch

from app.audit import AuditLog
from app.modules.nmap_validation import NmapValidationModule

# Real nmap 7.98 output, captured live against artssystem.com.br with
# `--script-args vulns.showall` (which forces an explicit State: line
# even on a negative result -- without it most scripts print nothing at
# all when safe).
REAL_NOT_VULNERABLE_OUTPUT = """Starting Nmap 7.98 ( https://nmap.org )
Nmap scan report for artssystem.com.br (191.252.83.206)
Host is up (0.00086s latency).

PORT    STATE SERVICE
443/tcp open  https
| ssl-heartbleed:
|   NOT VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability.
|     State: NOT VULNERABLE
|     References:
|       http://www.openssl.org/news/secadv_20140407.txt
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160

Nmap done: 1 IP address (1 host up) scanned in 1.85 seconds
"""

REAL_VULNERABLE_STYLE_OUTPUT = """Starting Nmap 7.98 ( https://nmap.org )
Nmap scan report for example.com
PORT    STATE SERVICE
443/tcp open  https
| ssl-heartbleed:
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability.
|     State: VULNERABLE
|     Risk factor: High
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160

Nmap done: 1 IP address (1 host up) scanned in 1.85 seconds
"""

NO_RESULT_OUTPUT = """Starting Nmap 7.98 ( https://nmap.org )
Nmap scan report for example.com
PORT    STATE    SERVICE
443/tcp filtered https

Nmap done: 1 IP address (1 host up) scanned in 1.56 seconds
"""


def _fake_result(stdout="", returncode=0):
    return MagicMock(stdout=stdout, returncode=returncode)


def test_confirms_a_cve_when_nmap_reports_vulnerable():
    context = {"cve_findings": [{"cve_id": "CVE-2014-0160", "host": "tech.example.com"}]}

    with patch(
        "app.modules.nmap_validation.subprocess.run",
        return_value=_fake_result(stdout=REAL_VULNERABLE_STYLE_OUTPUT),
    ) as mock_run:
        findings = NmapValidationModule().run("example.com", context)

    assert mock_run.call_args.args[0] == [
        "nmap", "-Pn", "-sT", "-p", "443",
        "--script", "ssl-heartbleed", "--script-args", "vulns.showall",
        "tech.example.com",
    ]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "cve_validation"
    assert finding.data["status"] == "confirmed"
    assert finding.data["tool"] == "nmap"
    assert finding.data["nmap_script"] == "ssl-heartbleed"
    assert "ssl-heartbleed" in finding.data["nmap_confirmation_note_en"]


def test_stays_unconfirmed_when_nmap_reports_not_vulnerable():
    context = {"cve_findings": [{"cve_id": "CVE-2014-0160", "host": "tech.example.com"}]}
    audit = AuditLog()
    context["audit"] = audit

    with patch(
        "app.modules.nmap_validation.subprocess.run",
        return_value=_fake_result(stdout=REAL_NOT_VULNERABLE_OUTPUT),
    ):
        findings = NmapValidationModule().run("example.com", context)

    assert findings == []
    assert audit.entries[-1]["outcome"] == "not_vulnerable"


def test_records_no_result_when_the_script_never_produced_a_state_line():
    context = {"cve_findings": [{"cve_id": "CVE-2014-0160", "host": "tech.example.com"}]}
    audit = AuditLog()
    context["audit"] = audit

    with patch(
        "app.modules.nmap_validation.subprocess.run",
        return_value=_fake_result(stdout=NO_RESULT_OUTPUT),
    ):
        findings = NmapValidationModule().run("example.com", context)

    assert findings == []
    assert audit.entries[-1]["outcome"] == "no_result"


def test_skips_a_cve_with_no_curated_script_without_running_nmap():
    context = {"cve_findings": [{"cve_id": "CVE-9999-99999", "host": "tech.example.com"}]}
    audit = AuditLog()
    context["audit"] = audit

    with patch("app.modules.nmap_validation.subprocess.run") as mock_run:
        findings = NmapValidationModule().run("example.com", context)

    mock_run.assert_not_called()
    assert findings == []
    assert audit.entries[-1]["outcome"] == "no_script"


def test_records_not_attempted_and_reraises_when_the_binary_is_missing():
    context = {"cve_findings": [{"cve_id": "CVE-2014-0160", "host": "tech.example.com"}]}
    audit = AuditLog()
    context["audit"] = audit

    with patch(
        "app.modules.nmap_validation.subprocess.run",
        side_effect=OSError("nmap not found"),
    ):
        with pytest.raises(OSError):
            NmapValidationModule().run("example.com", context)

    assert len(audit.entries) == 1
    assert audit.entries[0]["outcome"].startswith("not_attempted:")


def test_skips_an_out_of_scope_host():
    context = {
        "cve_findings": [{"cve_id": "CVE-2014-0160", "host": "blocked.example.com"}],
        "scope": {"include": ["example.com"], "exclude": ["blocked.example.com"]},
    }

    with patch("app.modules.nmap_validation.subprocess.run") as mock_run:
        findings = NmapValidationModule().run("example.com", context)

    mock_run.assert_not_called()
    assert len(findings) == 1
    assert findings[0].type == "out_of_scope"


def test_circuit_breaker_trips_after_threshold_consecutive_search_timeouts():
    context = {
        "cve_findings": [
            {"cve_id": "CVE-2014-0160", "host": "tech.example.com"} for _ in range(5)
        ],
        "circuit_breaker_threshold": 2,
    }

    with patch(
        "app.modules.nmap_validation.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=120),
    ):
        findings = NmapValidationModule().run("example.com", context)

    tripped = [f for f in findings if f.type == "circuit_breaker_tripped"]
    assert len(tripped) == 1
    assert tripped[0].data["module"] == "nmap_validation"


def test_many_uncurated_cves_never_trip_the_circuit_breaker():
    context = {
        "cve_findings": [
            {"cve_id": f"CVE-9999-{i}", "host": "tech.example.com"} for i in range(10)
        ],
        "circuit_breaker_threshold": 2,
    }

    with patch("app.modules.nmap_validation.subprocess.run") as mock_run:
        findings = NmapValidationModule().run("example.com", context)

    mock_run.assert_not_called()
    assert findings == []
