import pytest
from unittest.mock import MagicMock, patch

from app.audit import AuditLog
from app.modules.whois_module import WhoisModule


def test_whois_returns_single_finding_with_registration_data():
    fake_record = {
        "registrar": "Example Registrar",
        "creation_date": "2010-01-01",
        "expiration_date": "2030-01-01",
        "name_servers": ["ns1.example.com", "ns2.example.com"],
    }
    with patch("app.modules.whois_module.whois.whois", return_value=fake_record):
        findings = WhoisModule().run("example.com", {})

    assert len(findings) == 1
    assert findings[0].type == "whois"
    assert findings[0].value == "example.com"
    assert findings[0].data["registrar"] == "Example Registrar"
    assert findings[0].data["name_servers"] == ["ns1.example.com", "ns2.example.com"]


def test_refuses_to_query_a_target_outside_declared_scope():
    from unittest.mock import patch

    from app.modules.whois_module import WhoisModule

    scope = {"include": ["other.com"]}

    with patch("app.modules.whois_module.whois.whois") as mock_whois:
        findings = WhoisModule().run("example.com", {"scope": scope})

    mock_whois.assert_not_called()
    assert len(findings) == 1
    assert findings[0].type == "out_of_scope"
    assert findings[0].value == "example.com"
    assert findings[0].data == {"module": "whois"}


def test_records_a_successful_lookup_to_the_audit_log():
    audit = AuditLog()
    with patch("app.modules.whois_module.whois.whois", return_value=MagicMock(get=lambda *a: None)):
        WhoisModule().run("example.com", {"audit": audit})

    assert len(audit.entries) == 1
    assert audit.entries[0]["module"] == "whois"
    assert audit.entries[0]["target"] == "example.com"
    assert audit.entries[0]["outcome"] == "success"
    assert audit.entries[0]["url"] is None


def test_records_a_failed_lookup_to_the_audit_log_before_reraising():
    audit = AuditLog()
    with patch("app.modules.whois_module.whois.whois", side_effect=ConnectionError("timed out")):
        with pytest.raises(ConnectionError):
            WhoisModule().run("example.com", {"audit": audit})

    assert len(audit.entries) == 1
    assert audit.entries[0]["outcome"] == "error: timed out"
