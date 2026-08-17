from unittest.mock import MagicMock, patch

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
