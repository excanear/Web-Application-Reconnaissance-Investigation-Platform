import subprocess
import pytest
from unittest.mock import MagicMock, patch

from app.audit import AuditLog
from app.modules.nuclei_validation import NucleiValidationModule


def _fake_result(stdout="", returncode=0, stderr=""):
    return MagicMock(stdout=stdout, returncode=returncode, stderr=stderr)


# Real stderr text from nuclei 3.11.1 (verified live) when `-id <cve>`
# matches no template in the community library -- happens for both a
# real, well-known CVE with no nuclei template (CVE-2021-23017) and a
# fully made-up CVE ID; the message and exit code (1) are identical
# either way.
NO_TEMPLATE_STDERR = "[FTL] Could not run nuclei: no templates provided for scan\n"


def test_confirms_a_cve_when_nuclei_reports_a_match():
    match_line = '{"template-id": "CVE-2021-23017", "matched-at": "https://tech.example.com/"}\n'
    context = {"cve_findings": [{"cve_id": "CVE-2021-23017", "host": "tech.example.com"}]}

    with patch(
        "app.modules.nuclei_validation.subprocess.run",
        return_value=_fake_result(stdout=match_line),
    ) as mock_run:
        findings = NucleiValidationModule().run("example.com", context)

    assert mock_run.call_args.args[0] == [
        "nuclei",
        "-u", "https://tech.example.com/",
        "-id", "CVE-2021-23017",
        "-etags", "dos,fuzz,intrusive",
        "-jsonl",
        "-silent",
        "-rate-limit", "5",
    ]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "cve_validation"
    assert finding.value == "CVE-2021-23017"
    assert finding.data["status"] == "confirmed"
    assert finding.data["host"] == "tech.example.com"
    assert finding.data["nuclei_template_id"] == "CVE-2021-23017"
    assert finding.data["matched_at"] == "https://tech.example.com/"
    assert "CVE-2021-23017" in finding.data["confirmation_note_en"]
    assert "template nuclei" in finding.data["confirmation_note_pt"]


def test_stays_suspected_when_nuclei_reports_no_match():
    context = {"cve_findings": [{"cve_id": "CVE-2021-23017", "host": "tech.example.com"}]}

    with patch(
        "app.modules.nuclei_validation.subprocess.run",
        return_value=_fake_result(stdout=""),
    ):
        findings = NucleiValidationModule().run("example.com", context)

    assert findings == []


def test_records_not_attempted_and_reraises_when_the_binary_is_missing():
    context = {"cve_findings": [{"cve_id": "CVE-2021-23017", "host": "tech.example.com"}]}
    audit = AuditLog()
    context["audit"] = audit

    with patch(
        "app.modules.nuclei_validation.subprocess.run",
        side_effect=OSError("nuclei not found"),
    ):
        with pytest.raises(OSError):
            NucleiValidationModule().run("example.com", context)

    assert len(audit.entries) == 1
    assert audit.entries[0]["outcome"].startswith("not_attempted:")


def test_records_a_confirmed_check_to_the_audit_log():
    match_line = '{"template-id": "CVE-2021-23017", "matched-at": "https://tech.example.com/"}\n'
    context = {"cve_findings": [{"cve_id": "CVE-2021-23017", "host": "tech.example.com"}]}
    audit = AuditLog()
    context["audit"] = audit

    with patch(
        "app.modules.nuclei_validation.subprocess.run",
        return_value=_fake_result(stdout=match_line),
    ):
        NucleiValidationModule().run("example.com", context)

    assert len(audit.entries) == 1
    assert audit.entries[0]["outcome"] == "confirmed"
    assert audit.entries[0]["target"] == "CVE-2021-23017@tech.example.com"


def test_records_no_match_to_the_audit_log_without_emitting_a_finding():
    context = {"cve_findings": [{"cve_id": "CVE-2021-23017", "host": "tech.example.com"}]}
    audit = AuditLog()
    context["audit"] = audit

    with patch(
        "app.modules.nuclei_validation.subprocess.run",
        return_value=_fake_result(stdout=""),
    ):
        findings = NucleiValidationModule().run("example.com", context)

    assert findings == []
    assert audit.entries[0]["outcome"] == "no_match"


def test_skips_an_out_of_scope_host():
    context = {
        "cve_findings": [{"cve_id": "CVE-2021-23017", "host": "blocked.example.com"}],
        "scope": {"include": ["example.com"], "exclude": ["blocked.example.com"]},
    }

    with patch("app.modules.nuclei_validation.subprocess.run") as mock_run:
        findings = NucleiValidationModule().run("example.com", context)

    mock_run.assert_not_called()
    assert len(findings) == 1
    assert findings[0].type == "out_of_scope"
    assert findings[0].value == "blocked.example.com"


def test_records_an_error_to_the_audit_log_and_does_not_crash_on_unparseable_stdout():
    context = {"cve_findings": [{"cve_id": "CVE-2021-23017", "host": "tech.example.com"}]}
    audit = AuditLog()
    context["audit"] = audit

    with patch(
        "app.modules.nuclei_validation.subprocess.run",
        return_value=_fake_result(stdout="[WRN] some warning banner, not JSON\n"),
    ):
        findings = NucleiValidationModule().run("example.com", context)

    assert findings == []
    assert audit.entries[0]["outcome"].startswith("error:")


def test_stays_suspected_without_penalizing_the_circuit_breaker_when_no_template_exists():
    # The real bug: nuclei exits 1 (a "failure" exit code) for the
    # routine, expected case of a CVE with no matching community
    # template -- most CVEs never get one written. Treating that as a
    # circuit-breaker failure meant a run of un-templated CVEs could
    # exhaust the breaker before ever reaching one nuclei could actually
    # check, silently killing validation for a whole scan.
    context = {"cve_findings": [{"cve_id": "CVE-2021-23017", "host": "tech.example.com"}]}
    audit = AuditLog()
    context["audit"] = audit

    with patch(
        "app.modules.nuclei_validation.subprocess.run",
        return_value=_fake_result(returncode=1, stderr=NO_TEMPLATE_STDERR),
    ):
        findings = NucleiValidationModule().run("example.com", context)

    assert findings == []
    assert audit.entries[0]["outcome"] == "no_template"


def test_many_untemplated_cves_never_trip_the_circuit_breaker():
    context = {
        "cve_findings": [
            {"cve_id": f"CVE-2021-{i}", "host": "tech.example.com"} for i in range(10)
        ],
        "circuit_breaker_threshold": 2,
    }

    with patch(
        "app.modules.nuclei_validation.subprocess.run",
        return_value=_fake_result(returncode=1, stderr=NO_TEMPLATE_STDERR),
    ):
        findings = NucleiValidationModule().run("example.com", context)

    assert findings == []  # all 10 attempted, none tripped the breaker


def test_a_genuine_nuclei_error_still_counts_against_the_circuit_breaker():
    # Only the specific "no templates provided for scan" message is
    # exempted -- a real execution failure (bad flags, crashed template,
    # unexpected exit) must still protect the rest of the scan.
    context = {
        "cve_findings": [
            {"cve_id": f"CVE-2021-{i}", "host": "tech.example.com"} for i in range(5)
        ],
        "circuit_breaker_threshold": 2,
    }

    with patch(
        "app.modules.nuclei_validation.subprocess.run",
        return_value=_fake_result(returncode=1, stderr="[FTL] some other fatal error\n"),
    ):
        findings = NucleiValidationModule().run("example.com", context)

    tripped = [f for f in findings if f.type == "circuit_breaker_tripped"]
    assert len(tripped) == 1


def test_circuit_breaker_trips_after_threshold_consecutive_check_failures():
    context = {
        "cve_findings": [
            {"cve_id": f"CVE-2021-{i}", "host": "tech.example.com"} for i in range(5)
        ],
        "circuit_breaker_threshold": 2,
    }

    with patch(
        "app.modules.nuclei_validation.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="nuclei", timeout=120),
    ):
        findings = NucleiValidationModule().run("example.com", context)

    tripped = [f for f in findings if f.type == "circuit_breaker_tripped"]
    assert len(tripped) == 1
    assert tripped[0].data["module"] == "nuclei_validation"
    assert tripped[0].data["skipped_checks"] == 3


def test_confirmed_finding_includes_remediation_when_the_template_provides_it():
    match_line = (
        '{"template-id": "CVE-2021-23017", "matched-at": "https://tech.example.com/", '
        '"info": {"remediation": "Upgrade to version 2.0 or later.\\n"}}\n'
    )
    context = {"cve_findings": [{"cve_id": "CVE-2021-23017", "host": "tech.example.com"}]}

    with patch(
        "app.modules.nuclei_validation.subprocess.run",
        return_value=_fake_result(stdout=match_line),
    ):
        findings = NucleiValidationModule().run("example.com", context)

    assert findings[0].data["remediation_en"] == "Upgrade to version 2.0 or later."


def test_confirmed_finding_omits_remediation_when_the_template_has_none():
    match_line = '{"template-id": "CVE-2021-23017", "matched-at": "https://tech.example.com/"}\n'
    context = {"cve_findings": [{"cve_id": "CVE-2021-23017", "host": "tech.example.com"}]}

    with patch(
        "app.modules.nuclei_validation.subprocess.run",
        return_value=_fake_result(stdout=match_line),
    ):
        findings = NucleiValidationModule().run("example.com", context)

    assert "remediation_en" not in findings[0].data
