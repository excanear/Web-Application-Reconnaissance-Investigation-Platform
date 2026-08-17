from unittest.mock import patch

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
