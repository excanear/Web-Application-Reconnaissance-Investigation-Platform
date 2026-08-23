import subprocess
import pytest
from unittest.mock import MagicMock, patch

from app.audit import AuditLog
from app.modules.msf_validation import MsfValidationModule

# Real msfconsole 6.5.3 output, captured live against `search cve:2021-44228`
# and `use exploit/multi/http/vmware_vcenter_log4shell; ...; check` against a
# real (non-vulnerable) target -- including msfconsole's raw ANSI escapes,
# which it emits unconditionally even when stdout isn't a tty. These are
# fixtures, not string constants the module ever inspects directly.
REAL_SEARCH_OUTPUT = (
    "\x1b[0m\nMatching Modules\n================\n\n"
    "   #   Full Name                                      Disclosure Date  Rank       Check  Name\n"
    "   -   ---------                                      ---------------  ----       -----  ----\n"
    "   0   exploit/multi/http/log4shell_header_injection  2021-12-09       \x1b[32mexcellent\x1b[0m  Yes    Log4Shell HTTP Header Injection\n"
    "   1     \\_ target: Automatic                         .                .          .      .\n"
    "   6   auxiliary/scanner/http/log4shell_scanner       2021-12-09       normal     No     Log4Shell HTTP Scanner\n\n"
    "Interact with a module by name or index. For example \x1b[32minfo 22\x1b[0m, \x1b[32muse 22\x1b[0m\n\n\x1b[0m"
)

REAL_UNCONFIRMED_CHECK_OUTPUT = (
    "\x1b[0m\x1b[1m\x1b[34m[*]\x1b[0m No payload configured, defaulting to cmd/windows/ftp/x64/meterpreter/reverse_tcp\n"
    "\x1b[0mRHOSTS => example.com\n\x1b[0mRPORT => 443\n\x1b[0mSSL => true\n"
    "\x1b[0m\x1b[1m\x1b[34m[*]\x1b[0m 104.20.23.154:443 - Cannot reliably check exploitability. "
    "Could not determine tenant from the target; the target may have returned an unexpected redirect\n\x1b[0m"
)

# Constructed from the exact same ANSI convention observed live for [*]/[-]
# (Msf::Ui::Text's bold + color-code wrapping around the bracketed prefix)
# and the canonical CheckCode messages from
# lib/msf/core/exploit.rb ('The target is vulnerable.' / '... appears to
# be vulnerable.') -- print_good uses color 32 (green), the same code
# already seen wrapping "excellent"/"info"/"use" in REAL_SEARCH_OUTPUT.
REAL_STYLE_VULNERABLE_CHECK_OUTPUT = (
    "\x1b[0m\x1b[1m\x1b[32m[+]\x1b[0m 10.0.0.1:443 - The target is vulnerable.\n\x1b[0m"
)


def _fake_result(stdout="", returncode=0):
    return MagicMock(stdout=stdout, returncode=returncode)


def test_confirms_a_cve_when_msf_check_reports_vulnerable_through_real_ansi_output():
    context = {"cve_findings": [{"cve_id": "CVE-2021-44228", "host": "tech.example.com"}]}

    with patch(
        "app.modules.msf_validation.subprocess.run",
        side_effect=[
            _fake_result(stdout=REAL_SEARCH_OUTPUT),
            _fake_result(stdout=REAL_STYLE_VULNERABLE_CHECK_OUTPUT),
        ],
    ) as mock_run:
        findings = MsfValidationModule().run("example.com", context)

    search_call, check_call = mock_run.call_args_list
    assert search_call.args[0] == ["msfconsole", "-q", "-x", "search cve:2021-44228; exit"]
    assert check_call.args[0] == [
        "msfconsole", "-q", "-x",
        "use exploit/multi/http/log4shell_header_injection; set RHOSTS tech.example.com; "
        "set RPORT 443; set SSL true; check; exit",
    ]

    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "cve_validation"
    assert finding.value == "CVE-2021-44228"
    assert finding.data["status"] == "confirmed"
    assert finding.data["tool"] == "metasploit"
    assert finding.data["host"] == "tech.example.com"
    assert finding.data["msf_module"] == "exploit/multi/http/log4shell_header_injection"
    assert finding.data["msf_check_message"] == "10.0.0.1:443 - The target is vulnerable."
    assert "log4shell_header_injection" in finding.data["msf_confirmation_note_en"]
    assert "Metasploit" in finding.data["msf_confirmation_note_pt"]


def test_confirms_on_the_lower_confidence_appears_to_be_vulnerable_checkcode():
    # Msf::Exploit::CheckCode::Appears ("The target appears to be
    # vulnerable.") is also reported via print_good/"[+]" -- only
    # CheckCode::Vulnerable ("is vulnerable.") is hard evidence, but both
    # print through the same "[+]...vulnerable" convention this module
    # scrapes, so both must be recognized.
    context = {"cve_findings": [{"cve_id": "CVE-2021-44228", "host": "tech.example.com"}]}
    appears_output = "\x1b[1m\x1b[32m[+]\x1b[0m 10.0.0.1:443 - The target appears to be vulnerable.\n"

    with patch(
        "app.modules.msf_validation.subprocess.run",
        side_effect=[_fake_result(stdout=REAL_SEARCH_OUTPUT), _fake_result(stdout=appears_output)],
    ):
        findings = MsfValidationModule().run("example.com", context)

    assert len(findings) == 1
    assert findings[0].data["status"] == "confirmed"


def test_stays_unconfirmed_when_msf_check_cannot_reliably_validate():
    # Verified live: Metasploit's "Safe"/"Unknown"/"Detected" CheckCodes
    # all print through print_status ("[*]"), never "[-]" -- there is no
    # "[-] ... not vulnerable" message to scrape.
    context = {"cve_findings": [{"cve_id": "CVE-2021-44228", "host": "tech.example.com"}]}
    audit = AuditLog()
    context["audit"] = audit

    with patch(
        "app.modules.msf_validation.subprocess.run",
        side_effect=[
            _fake_result(stdout=REAL_SEARCH_OUTPUT),
            _fake_result(stdout=REAL_UNCONFIRMED_CHECK_OUTPUT),
        ],
    ):
        findings = MsfValidationModule().run("example.com", context)

    assert findings == []
    assert audit.entries[-1]["outcome"] == "not_vulnerable"


def test_no_finding_and_no_check_call_when_search_finds_no_module():
    context = {"cve_findings": [{"cve_id": "CVE-9999-00001", "host": "tech.example.com"}]}
    audit = AuditLog()
    context["audit"] = audit

    with patch(
        "app.modules.msf_validation.subprocess.run",
        return_value=_fake_result(stdout="\x1b[0m\nMatching Modules\n================\n\n\x1b[0m"),
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
