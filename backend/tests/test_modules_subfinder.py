import subprocess
import pytest
from unittest.mock import MagicMock, patch

from app.audit import AuditLog
from app.modules.subfinder import SubfinderModule


def test_subfinder_parses_stdout_into_subdomain_findings():
    fake_result = MagicMock(stdout="b.example.com\na.example.com\na.example.com\n")
    with patch("app.modules.subfinder.subprocess.run", return_value=fake_result) as mock_run:
        findings = SubfinderModule().run("example.com", {})

    mock_run.assert_called_once_with(
        ["subfinder", "-d", "example.com", "-silent"],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )
    assert [f.value for f in findings] == ["a.example.com", "b.example.com"]
    assert all(f.type == "subdomain" for f in findings)


def test_records_a_successful_invocation_to_the_audit_log():
    fake_result = MagicMock(stdout="a.example.com\nb.example.com\n")
    audit = AuditLog()
    with patch("app.modules.subfinder.subprocess.run", return_value=fake_result):
        SubfinderModule().run("example.com", {"audit": audit})

    assert len(audit.entries) == 1
    assert audit.entries[0]["module"] == "subfinder"
    assert audit.entries[0]["target"] == "example.com"
    assert audit.entries[0]["outcome"] == "success (2 found)"


def test_records_a_failed_invocation_to_the_audit_log_before_reraising():
    audit = AuditLog()
    with patch(
        "app.modules.subfinder.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "subfinder"),
    ):
        with pytest.raises(subprocess.CalledProcessError):
            SubfinderModule().run("example.com", {"audit": audit})

    assert len(audit.entries) == 1
    assert audit.entries[0]["outcome"].startswith("error:")


def test_records_not_attempted_when_the_binary_is_missing():
    audit = AuditLog()
    with patch(
        "app.modules.subfinder.subprocess.run",
        side_effect=OSError("subfinder not found"),
    ):
        with pytest.raises(OSError):
            SubfinderModule().run("example.com", {"audit": audit})

    assert len(audit.entries) == 1
    assert audit.entries[0]["outcome"].startswith("not_attempted:")
