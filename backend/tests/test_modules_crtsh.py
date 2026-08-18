import pytest
from unittest.mock import MagicMock, patch

from app.audit import AuditLog
from app.modules.crtsh import CrtShModule


def test_crtsh_extracts_unique_subdomains_from_certificate_entries():
    fake_response = MagicMock()
    fake_response.raise_for_status.return_value = None
    fake_response.json.return_value = [
        {"name_value": "a.example.com\n*.a.example.com"},
        {"name_value": "b.example.com"},
        {"name_value": "unrelated.org"},
        {"name_value": "evilexample.com"},
    ]
    with patch("app.modules.crtsh.requests.get", return_value=fake_response) as mock_get:
        findings = CrtShModule().run("example.com", {})

    mock_get.assert_called_once_with(
        "https://crt.sh/",
        params={"q": "%.example.com", "output": "json"},
        timeout=30,
    )
    assert [f.value for f in findings] == ["a.example.com", "b.example.com"]
    assert all(f.data["source"] == "crt.sh" for f in findings)


def test_refuses_to_query_a_target_outside_declared_scope():
    from unittest.mock import patch

    from app.modules.crtsh import CrtShModule

    scope = {"include": ["other.com"]}

    with patch("app.modules.crtsh.requests.get") as mock_get:
        findings = CrtShModule().run("example.com", {"scope": scope})

    mock_get.assert_not_called()
    assert len(findings) == 1
    assert findings[0].type == "out_of_scope"
    assert findings[0].value == "example.com"
    assert findings[0].data == {"module": "crtsh"}


def test_records_a_successful_request_to_the_audit_log():
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = []
    response.raise_for_status = MagicMock()

    audit = AuditLog()
    with patch("app.modules.crtsh.requests.get", return_value=response):
        CrtShModule().run("example.com", {"audit": audit})

    assert len(audit.entries) == 1
    assert audit.entries[0]["module"] == "crtsh"
    assert audit.entries[0]["target"] == "example.com"
    assert audit.entries[0]["outcome"] == "200"
    assert audit.entries[0]["url"] == "https://crt.sh/"


def test_records_a_failed_request_to_the_audit_log_before_reraising():
    import requests as requests_lib

    audit = AuditLog()
    with patch(
        "app.modules.crtsh.requests.get",
        side_effect=requests_lib.RequestException("connection reset"),
    ):
        with pytest.raises(requests_lib.RequestException):
            CrtShModule().run("example.com", {"audit": audit})

    assert len(audit.entries) == 1
    assert audit.entries[0]["outcome"] == "error: connection reset"
